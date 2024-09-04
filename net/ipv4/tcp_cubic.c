// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8	// 只会使用每一轮开始的几个 报文计算的 rtt
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
// 注意此处的 beta 和 cubic 原始论文里的 beta 是不一样的，那个 \beta = 1 - (beta / 1024)
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41; // 和 cubic 论文里的 C 有关
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta_us __read_mostly = 2000;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta_us, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");

/* BIC TCP Parameters */
// cubic 函数: W(t) = C(t-K)^3 + W_{max}
// - t 的单位是s
// - 这个三次函数的中心对称点是 (K, W_{max})			// 即时间 K 的时候会 cwnd 会增长到 W_{max}
struct bictcp {
	// CUBIC 计算出 目标的 W(t) 后，会在一个 RTT 内增长到 W(t) 的, 即按照 cnt 来增长
	u32	cnt;		/* increase cwnd by 1 after ACKs */ // 每收到一个 ack 需要增加多少 cwnd, 表示 百分比。需要增加的量是 1 / cnt。即每被 ack 了 cnt 的数据，cwnd 就增长1.
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */	// 就是 W_{max}
	u32	bic_K;		/* time to origin point			// 就是 K
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (usec) */	// 该连接最小的 RTT 采样值, 在连接开始以及进入 Loss 的时候会重置的
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */	// 在此期间被 ack 的数目
	u32	tcp_cwnd;	/* estimated tcp cwnd */ // 评估的标准 tcp 的窗口
	u16	unused;
	u8	sample_cnt;	/* number of samples to decide curr_rtt */ // 用于采样 RTT 的样本数量
	u8	found;		/* the exit point is found? */ // 即 hystart 的 safe exit point，即找到了一个合适的 ssthresh 了
	u32	round_start;	/* beginning of each round */ // 一个 rtt round 的开始
	u32	end_seq;	/* end_seq of the round */	// 一个 rtt round 结束时的 seq
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */ // 这一轮的最小 rtt
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

static inline u32 bictcp_clock_us(const struct sock *sk)
{
	return tcp_sk(sk)->tcp_mstamp;
}

// 每个 rtt round 开始的时候会执行的
static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock_us(sk);
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = ~0U;
	ca->sample_cnt = 0;
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);

	if (hystart)
		bictcp_hystart_reset(sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

static void bictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 *
 * W(T) = C(T-K)^3 + W_{max}
 *
 * @cwnd: 当前 tcp_sock 中记录的 cwnd，也就是需要更新的 cwnd
 * @acked: 当前正在处理的这个 ack 报文 ack/sack 了多少数据
 *
 * 关于 cubic 窗口增长函数的说明:
 *
 * # 原始定义
 *  - W(T) = C(T - K)^3 + W_{max}
 *       - T:          是真实物理时间，单位是 s
 *       - W_{max}:    是发生快速重传前的 cwnd 值
 *       - C:          是常数, 默认 0.4
 *       - \beta:      是乘性减少因子，即发生快速重传的时候，cwnd 应该更新为之前的 (1 - \beta)W_{max}		__重点__
 *		- 此处记做 W_{min}
 *       - K = sqrt[3]{\beta * W_{max} / C}
 *          - 该函数起点为 (0, (1-\beta)W_{max})
 *          - 中心对称点为 (K, W_{max})
 *          - 注意：K 表示的是从开始 cubic 算法到 cwnd 到达 W_{max} 的时间，即之前的 max cwnd。而 cwnd 表示了 bdp。所以 bdp 越大，K 越大。那么一旦发生重传想要重新到达 W_{max} 的时间就越久。
 *
 *
 * # 注意，当快速恢复结束的时候，第一次进入该函数，执行拥塞避免的时候, 传入的 cwnd 就是运行 prr 算法得到的 cwnd 其值就应该是 (1 - \beta) W_{max}, 将其记做 W_{min}
 *
 *
 * # 在此基础上考虑该函数的计算:
 * - cube_factor = 2^40 / 410 // 决定了 C
 * - bic_K = sqrt[3]{ cube_factor * (W_{max} - W_{min}) }
 * - bic_t = T * 1024					// 即真实的物理时间(T s) * 1024
 * - delta = (410 * (bic_t - bic_K)^3) / 2^40
 *   
 * - bic_target = delta + W_{max}			// 就是 W(T) , 注意，代码里做了正负的处理
 *
 * bic_target = delta + W_{max}
 *            = ((410 * (bic_t - bic_K)^3) / 2^40) + W_{max}
 *            = ((410 * (1024 * T - bic_K)^3) / 2^40) + W_{max}
 *            = (sqrt[3]{410 / 1024} * T - sqrt[3]{W_{max} - W_{min}})^3 + W_{max}
 *            ~= (0.737 T - sqrt[3]{W_{max} - (1-\beta)W_{max}})^3 + W_{max}
 *            = (0.737T - sqrt[3]{\beta * W_{max}}) + W_{max}
 *            = 0.4(T - sqrt[3]{\beta * W{max} / 0.4)
 *            = C(T - sqrt[3]{\beta * W{max} / C)			// 令 C = 0.4
 *            = W(T)							// W(t) 的原始定义
 *
 * 故 K 也可以写作 sqrt[3]{(W_{max} - W_{min}) / C} = sqrt[3]{(last_cwnd - cwnd) / C}
 *
 */

/* 第一次进入这里的时候，是 prr 算法结束，已经完成 快速恢复了
 *     - 理解这里的 cwnd 就是 (1 - \beta) W_{max}
 *
 * - C = 0.4 = 410 / 1024
 * - K = sqrt[3]((last_cwnd - cwnd) / 0.4) = sqrt[3](\beta * last_cwnd)	// 而 \beta 具体是多少，则是取决于 prr 算法在快速恢复结束后，将 cwnd 减少了多少, refer to: tcp_init_cwnd_reduction() 里 ssthresh 的更新, prr 结束的时候，cwnd 会到达 ssthresh 了
 *
 * tcp_init_cwnd_reduction() 又调用的是 bictcp_recalc_ssthresh, 可以看到 \beta 是 1 - 717 / 1024 = 0.3
 *
 * 综上：linux 默认情况下
 *
 * 
 * W(T) = C(T-K)^3 + W_{max} = 0.4(T - sqrt[3]{0.3 * W_{max} / 0.4})^3 + W_{max}
 *
 * 计算的 snd_cnt 的目的是为了在下一个 RTT 的时间内，让 cwnd 增长到 bic_target
 */

static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked) // __极其重要__
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */ // cubic 一次 epoch 被 ack 的 segs 数目

	if (ca->last_cwnd == cwnd && // cwnd 没有增长过，且上次进入的时间小于 1/32 s
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32) // 距离上一次更新小于 1/32s(31ms), 且 cwnd 没有变化
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.	// 一个 jiffies 最多更新一次
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)	// CUBIC 最多 1 BICTCP HZ 运行一次, 如果进来很频繁的话，直接去 tcp friendliness
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) { // 经历了一次 窗口减小事件后，第一次进入 拥塞避免。即 prr 算法刚结束，完成快速恢复
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */ // 这里的 cwnd 应该是 prr 算法结束时更新的，应该就是 ssthresh

		if (ca->last_max_cwnd <= cwnd) { // 注意这里, hystart 第一次结束的时候，此时没有发生过任何丢包，然后开始拥塞避免就会进入这里. 第一从 slow-start 进入 cubic 的时候, 是直接进入其右半部分的凹函数的
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd; // 原点，即 W_{max}, 这种情况下，直接将 cwnd 作为 W_{max} 进入窗口探测阶段
		} else { // 常态是这里
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 *
			 *
			 * - K 值表示 三次曲线的起点 W(0) 增长到 W_{max} 需要的时间
			 * - K 值需要根据第一次进入 cubic 时的 cwnd 来计算。这个 cwnd 是 prr 算法结束时更新的。
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd)); // 计算 K 值
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ				// 这里的 除法是为了防止溢出 // W(t) = C(t-K)^3 + W_{max}
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - ca->epoch_start); // 第一次进来的时候，这里 t 就是 0
	t += usecs_to_jiffies(ca->delay_min); // 这里会加一个 最小的 RTT, 那么这里的 t 至少是 2*RTT
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ); // t 表示的是 HZ 数目，不过将 t 从 HZ 转换为了 bictcp_HZ (1/1024 s), 这里的 t 的值 = 物理时间(s) * 1024

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	// W(t) = C(t-K)^3 + W_{max}
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);	// 这里修正为正数了
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;			// bic_target 就是 W(t)
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* bic_target 就是 W(t), 得到了 W(t) 就是希望在当前的 cwnd 内的报文都接收到的时候，cwnd 可以增长到 bic_target
	 * 所以需要计算每被 ack 一个 seg 的时候，cwnd 能够增长多少。
	 *
	 * 每收一个 ack cwnd 应该增长 (bic_target - cwnd) / cwnd 即  (1 / ca->cnt)
	 * */
	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);			// 这里是关键，ca->cnt 就是后续用来计算 cwnd 的关键
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/	// 表示每个 ack 增加 1 / (100 * cwnd)。即每 ack 一个 cwnd 的数据量会增长 1%。因为此时 cwnd 已经超过了 cubic 的target 了，保持最小的增长来探测链路
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness: // 按照 标准 tcp 的方式来计算 cwnd, 如果窗口特别小的话，CUBIC 相对于 标准tcp 性能太差，这里要修正
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale; // 默认情况下是 15

		delta = (cwnd * scale) >> 3; // 窗口太小的时候，cubic 相对于标准 tcp 比较吃亏，所以要修正, 默认情况是 1.89 cwnd, delta 是整数，所以这里就是 cwnd。就看 ack_cnt 是当前的几倍 cwnd, 是几倍就加几，符合 拥塞避免阶段的线性增长
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */ // 计算出一个 tcp_cwnd 来表示标准 tcp 的 cwnd
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++; // 这个算出来的是，标准 TCP 的 cwnd 窗口数目
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */ // 比较标准 TCP 的 cwnd 和 cubic 的 cwnd，谁大，用谁。
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U); // 最大不超过 2。即最多每个 RTT 增加 1.5 倍
}

/* @acked: 这一次收到的 ack 报文，acked 或 sacked 的数目
 * @ack: 这个报文 ack 的序号
 * */

// 执行时机: cwnd > ssthresh
//一旦发生重传，那么 CUBIC 算法立即结束，执行 prr 算法/或 slowstart。当复 cwnd > ssthresh 后又会开始 cubic
// 
// 注意：这个函数不仅实现了拥塞避免，也实现了 hystart 的 slow start 算法
static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		if (hystart && after(ack, ca->end_seq)) // 表示 慢启动阶段 开启了一个新的 RTT round
			bictcp_hystart_reset(sk);
		acked = tcp_slow_start(tp, acked);
		if (!acked) // 如果是完全在慢启动阶段(即 cwnd 离 ssthresh 还是比较远的, 没有穿越 ssthresh 的风险)，这里返回值是0，就直接退出了
			return;
	}
	bictcp_update(ca, tp->snd_cwnd, acked);
	tcp_cong_avoid_ai(tp, ca->cnt, acked); // 利用 ca->cnt, acked 来更新 cwnd
}

// 只要丢包就会更新 ssthresh, 不管是重传丢包还是timeout
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */ // 一次 cubic 三次算法运行的开始

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta)) // (1024 + 717) / (2 * 1024) 缩小系数 0.85
			/ (2 * BICTCP_BETA_SCALE);	// last_max 用于 cubic 算法的。 如果持续的重传，每次重传 snd_cwnd 都没有超过之前的 last_max_cwnd, 那么将 last_max_cwnd 减小的更快一点。前提是开启了 fast_convergence
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U); // 减少为 之前的 0.7，故减小系数是 0.3
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk);
	}
}

/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
static u32 hystart_ack_delay(struct sock *sk)
{
	unsigned long rate;

	rate = READ_ONCE(sk->sk_pacing_rate);
	if (!rate)
		return 0;
	return min_t(u64, USEC_PER_MSEC,
		     div64_ul((u64)GSO_MAX_SIZE * 4 * USEC_PER_SEC, rate));
}

// hystart 算法仅仅是用来寻找 ssthresh 的，cwnd 的更新其不参与
static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 threshold;

	if (hystart_detect & HYSTART_ACK_TRAIN) { // hystart 算法退出只要满足两个条件之一就可以了, 这里是第一个
		u32 now = bictcp_clock_us(sk);

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta_us) {
			ca->last_ack = now;

			threshold = ca->delay_min + hystart_ack_delay(sk);	// 就是最小的 RTT_{min} + 一个 对于 TSO/GRO 的修正值

			/* Hystart ack train triggers if we get ack past
			 * ca->delay_min/2.
			 * Pacing might have delayed packets up to RTT/2
			 * during slow start. // 如果开启了 pacing 机制，即不进入下面的 if。其会导致 dealy_min 增长 RTT/2, 所以 threshold 也要增长 RTT/2。即不进入下面的 if 语句
			 */
			if (sk->sk_pacing_status == SK_PACING_NONE) // 常态, 原始论文里就是需要除以 2 的。
				threshold >>= 1;

			if ((s32)(now - ca->round_start) > threshold) {	// 这一轮中，和第一个包之间的 T 已经超过 threshold 了，可以退出了
				ca->found = 1;
				pr_debug("hystart_ack_train (%u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
					 now - ca->round_start, threshold,
					 ca->delay_min, hystart_ack_delay(sk), tp->snd_cwnd);
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) { // hystart 算法退出只要满足两个条件之一就可以了, 这里是第二个。这里和 原始论文差别较大
		/* obtain the minimum delay of more than sampling packets */
		if (ca->curr_rtt > delay)
			ca->curr_rtt = delay;	// 这一轮采样的 最小 rtt
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) { // 计算这一轮 curr_rtt 采样了多少次, 超过 HYSTART_MIN_SAPLES 后就可以将其与 delay_min 比较，来判断是否退出了
			ca->sample_cnt++;
		} else { // delay_min 是链路上总的最小的 rtt
			if (ca->curr_rtt > ca->delay_min +		// 这一轮采样的最小 rtt 比整个连接的最小 rtt 要大不少，那么就退出了。慢启动阶段 RTT 会持续上升，这里不是很容易满足么？ 注意：这里加了一个 offset，这个 offset 至少是 4ms。换句话说，delay 至少增大了 4ms采集从这条路径退出
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found = 1;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}
}

static void bictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	// 至少 1HZ 才会进来一次的
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;

	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)	// 这条链接上的最小的 rtt
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (!ca->found && tcp_in_slow_start(tp) && hystart &&	// 还没有找到 ssthresh && 还在慢启动阶段 && 开启了 hystart  && cwnd 要足够大才会启动 hystart 算法, 因为 hystart 算法要采样一些数据，所以拥塞窗口至少要有 16 确保有足够的数据包提供信息
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= bictcp_cwnd_event,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "cubic",
};

static int __init cubictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */ // (1/10 s)
	do_div(cube_factor, bic_scale * 10);

	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CUBIC TCP");
MODULE_VERSION("2.3");
