/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 *
 * 关于 softroce 的 lock
 *
 * - global atomic lock: atomic_ops_lock
 *
 * - rxe_dev.usdev_lock. 目前仅仅用在 rxe_query_port() 上, port 是 device 的资
 *   源, 保护该资源.
 *
 * - rxe_port.port_lock: 目前是用来保护一些 counter 计数的
 *
 * - qp lock:
 *   - ~rxe_qp.grp_lock~
 *   - ~rxe_qp.state_lock~ requester 和 completer 会修改 qp state. 当 req 处于
 *   QP_STATE_DRAIN 状态的时候, 二者之一会去 drain 这个 qp. 这时候就用这个来协调
 *
 *
 * - sq lock: ~rxe_sq.sq_lock~, sq 访问者
 *   - 多个上层 verbs 调用: post_one_send()
 *
 *
 * - rq lock
 *   - ~rxe_sq.producer_lock~, 访问者, 多个上层 verbs 调用: rxe_post_recv()
 *   - ~rxe_sq.consumer_lock~, 没有用. 仅仅在 srq 的时候使用
 *
 *
 * - cq lock ~rxe_cq.cq_lock~ cq 的访问者
 *   - 底层访问者:
 *	- rxe_cq_post()       // 填充 cq
 *	- rxe_send_complete() // 通知用户
 *   - 上层 verbs:
 *	- rxe_poll_cq()
 *	- rxe_req_notify_cq()
 *	- rxe_cq_resize_queue()
 *	- rxe_cq_disable()
 *
 *
 * - srq lock
 *   - srq->rq.producer_lock, 访问者, 多个上层 verbs 调用: rxe_post_srq_recv()
 *   - srq->rq.consumer_lock, 访问者, 多个底层 qp 的 responder: get_srq_wqe()
 *
 */

#ifndef RXE_VERBS_H
#define RXE_VERBS_H

#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <rdma/rdma_user_rxe.h>
#include "rxe_pool.h"
#include "rxe_task.h"
#include "rxe_hw_counters.h"

static inline int pkey_match(u16 key1, u16 key2)
{
	return (((key1 & 0x7fff) != 0) &&
		((key1 & 0x7fff) == (key2 & 0x7fff)) &&
		((key1 & 0x8000) || (key2 & 0x8000))) ? 1 : 0;
}

/* Return >0 if psn_a > psn_b
 *	   0 if psn_a == psn_b
 *	  <0 if psn_a < psn_b
 *
 * psn_a 其实是在这个范围的, 小于 psn_b 就是 dup, 大于 psn_b 其实就是非法的.
 *   (psn_b - 2^23 + 1) ... psn_b ... (psn_b + 2^23)
 *
 *
 * XXX: Reponsder PSN 空间的划分:
 *
 *   ePSN-(2^23-1), ..., ePSN,  ..., ePSN+2^23
 *
 * - *valid psn*: [ePSN-(2^23-1), ePSN]
 *   - *dup psn*: [ePSN-(2^23-1), ePSN-1]
 * - *invalid psn*: [ePSN + 1, ePSN+2^23]
 *
 *
 * 故: 如果 psn_b 是 ePSN 的话, 那么
 * - diff < 0  即 dup psn
 * - diff == 0 即 ePSN
 * - diff > 0  即 invalid psn
 *
 *
 * XXX: requester 收到 response 的 PSN 空间划分
 */
static inline int psn_compare(u32 psn_a, u32 psn_b)
{
	s32 diff;

	/* psn 只有 24b 的, 所以 32b 在这里足够处理回绕. */
	/* - psn_a \in [psn_b-(2^23-1), psn_b) => diff < 0
	 * - psn_a = psn_b                     => diff = 0
	 * - psn_a \in (psn_b, psn_b+2^23]     => diff > 0
	 * */
	diff = (psn_a - psn_b) << 8;
	return diff;
}

struct rxe_ucontext {
	struct ib_ucontext ibuc;
	struct rxe_pool_entry	pelem;
};

// 就是 ib_pd 结构, 不过增加了一个 pelem, 方便将其添加到 pool 来管理
struct rxe_pd {
	struct ib_pd            ibpd;
	struct rxe_pool_entry	pelem;
};

struct rxe_ah {
	struct ib_ah		ibah;
	struct rxe_pool_entry	pelem;
	struct rxe_pd		*pd;
	struct rxe_av		av;
};

struct rxe_cqe {
	union {
		struct ib_wc		ibwc;
		struct ib_uverbs_wc	uibwc;
	};
};

struct rxe_cq {
	struct ib_cq		ibcq;
	struct rxe_pool_entry	pelem;
	struct rxe_queue	*queue;
	spinlock_t		cq_lock; // 协调 cq 的访问者, cq 是 shared 的
	u8			notify;  // 根据这个字段来判断, 填充 cq 的时候是否需要通知用户. ref: %IB_CQ_NEXT_COMP, ref: rxe_req_notify_cq()
	bool			is_dying; // ref: %rxe_cq_disable()
	int			is_user; // 来自用户态的创建 cq 的请求创建的
	struct tasklet_struct	comp_task; // completion tasklet, %rxe_send_complete. post_cq 后调度这个 tasklet 来通知用户, ref: rxe_cq_post()
};

// ref: update_wqe_state
enum wqe_state {
	wqe_state_posted,     // 刚被 post 完, 等待被处理
	wqe_state_processing, // 多 pkt 的 req 正在处理
	wqe_state_pending,    // rc 里 wqe 处理完了还要等待回复的
	wqe_state_done,
	wqe_state_error,
};

struct rxe_sq {
	int			max_wr;
	int			max_sge;  // 一个 wqe 里可以存储的最大的 sge 数量. ref: rxe_send_wqe.dma.sge
	int			max_inline; // 一个 wqe 里可以存储的最大的 sge 数量. ref: rxe_send_wqe.dma.inline_dat
	spinlock_t		sq_lock; /* guard queue 协调多个上层调用者 */
	struct rxe_queue	*queue;
};

struct rxe_rq {
	int			max_wr;
	int			max_sge;  // rxq 单个 wqe 里可以存储的最大的 sge 数量, ref: rxe_recv_wqe.dma.sge
	spinlock_t		producer_lock; /* guard queue producer, 同 sq, 多个上层调用者并发 post  */
	spinlock_t		consumer_lock; /* guard queue consumer, srq 里有用, 可能有多个底层 qp 并发从里面取 wqe */
	struct rxe_queue	*queue;
};

struct rxe_srq {
	struct ib_srq		ibsrq;
	struct rxe_pool_entry	pelem;
	struct rxe_pd		*pd;
	struct rxe_rq		rq;	// 底层还是通过一个 rq 来实现的
	u32			srq_num; // srq num (id ???)

	int			limit;  // 当 srq 中的 wqe 数量小于 limit 的时候, 会通知用户. 通知的时机是 get_srq_wqe()
	int			error;  // 标识 srq 进入了 error 状态, softroce 的实现里, srq好像不会进入 error 状态.
};

// 内部实现的状态
// qp 的 req / resp 端是单独维护的(可以简单的理解为 SQ/RQ 是单独维护的状态)
enum rxe_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */ // ref: rxe_qp_drain, 对应到上层就是 IB 的 SQD 状态: 允许已经 post 的 WQE 发完, 但是不允许 post 新的了. 表示 SQ 需要 DRAIN 了. 由 rxe_requester() / rxe_completer() 来排空
	QP_STATE_DRAINED,	/* req only */ // ref: complete_ack(), 排空后进入这个状态
	QP_STATE_ERROR
};

struct rxe_req_info {
	enum rxe_qp_state	state;          //  requester, resoonder 的状态是分开维护的, 可以对应到 spec 里的 sq/rq 状态是分开维护的
	int			wqe_index;	// 下一个要处理的 sq 的 wqe index, ref: rxe_requester() -> next_index()
	u32			psn;            // 下一个用来填充 req 的 psn, ref: update_wqe_psn()
	int			opcode;         // 记录了前一个 opcode, 在 next_opcode() 的时候要根据wqe 和这个来计算的
	/* rdma 中有两个参数:
	 * - max_rd_atomic (init depth), 本端最多可以发的 read/atomic 数目
         * - max_dest_rd_atomic(responder depth), 表示我最多可以同时处理的 read/atomic 数目
	 * */
	atomic_t		rd_atomic;      // 剩余的可用的 reawd/atomic 数量, ref: rxe_qp_from_attr(). 用户创建 qp 的时候提供的 rd_atomic 应该参考对端的情况
	int			wait_fence;     // ref: req_next_wqe, post fence 的时候, 设置这个标记. 这时候该 sq 上要等待前面的 wr 完成
	int			need_rd_atomic; // 有 requester 想要 post read/atomic, 但是由于 outstanding read/atomic 太多了, 所以要设置这个标志, 让其等待. 当 comp 腾出 read/atomic 资源的时候, 要根据这个 flag 来判断是不是要调度下 req 的.
	int			wait_psn;       // ref: rxe_requester, outstanding pkt 太多的时候就会设置这个 flag 来 block 住. 同样的 comp 腾出 psn 资源的时候, 如果发现 req 在等待, 要调度一下的
	int			need_retry;	// 收到 nak 后, 可能要 retry, 在这里标记下, 后面有机会的时候根据这个标记做 retry, 通过调度 requester 来实现的 ref: rxe_completer.
	int			noack_pkts;     // 记录我发出的没有设置 ack_req 的 last pkt 数量, 到达一定数量后, 就设置 ack_req bit, ref: init_req_packet(). 目前这个阈值是写死的 64
	struct rxe_task		task; // rxe_requester
};

struct rxe_comp_info {
	u32			psn;     // 最大的被 ack 的 psn + 1, 对于 req 接收responder 来说, 也就是 expect psn. 其实就是 snd_una
	int			opcode;  // 记录 completer 前一个处理的 opcode(responder pkt 里的), 检验下一个 pkt 的时候可能会用上. ref: check_ack(). 特别的, 当值为 -1 的时候, 表示被 reset 了
	int			timeout; // ref: rxe_completer, 表示 completer 是 retransmit timer 触发的, ref: retransmit_timer()
	int			timeout_retry; // 表示当前正是 timeout_retry 处理过程中
	int			started_retry; // 已经处于 retry(非 timeout retry) 状态了 
	u32			retry_cnt; // retry 次数记录.  ref: ib spec, 其值为 7 表示无限制
	u32			rnr_retry; // rnr retry 次数记录.  ref: ib spec, 其值为 7 表示无限制
	struct rxe_task		task;     // rxe_completer
};

// 处理 read 重传的时候, 记录是重传 first/middle/last 包 ?
enum rdatm_res_state {
	rdatm_res_state_next,
	rdatm_res_state_new,
	rdatm_res_state_replay,
};

struct resp_res {
	int			type;
	int			replay;
	u32			first_psn;
	u32			last_psn;
	u32			cur_psn;
	enum rdatm_res_state	state;

	union {
		struct {
			struct sk_buff	*skb;
		} atomic;
		struct {
			struct rxe_mem	*mr;
			u64		va_org;
			u32		rkey;
			u32		length;
			u64		va;
			u32		resid;
		} read;
	};
};

struct rxe_resp_info {
	enum rxe_qp_state	state;        //  requester, resoonder 的状态是分开维护的, 可以对应到 spec 里的 sq/rq 状态是分开维护的
	u32			msn;          // 从 0 开始, 执行了一个 valid req 就 ++, ref: execute(), 回复 ack 包的时候会使用的. 注意 read response 里是没有 msn 的.
	u32			psn;          // expected psn. ref: rxe_resp:execute()
	u32			ack_psn;      // ref: b97db58557f4aa6d9903f8e1deea6b3d1ed0ba43, ref: comments on duplicate_request()
	int			opcode;       // 保存刚才收到的 opcode, 用于校验后续的 opcode, ref: check_op_seq()
	int			drop_msg;     // RC 用不上, 用来支持 UC/UD 的错误处理的
	int			goto_error;   // 表示 qp 要进入错误状态
	int			sent_psn_nak; // 发送过了 nak:seq-err. 记录自己处于 nak:psn-err 状态. 这个状态下, 如果又来了invalid pkt, 那么不响应了. 这个 NAK 需要特殊处理的: ref: C9-80 C9-114
	
	// 暂存一些信息, 在后续产生 CQE, 回复 ACK 的时候会用上
	enum ib_wc_status	status;
	u8			aeth_syndrome;

	/* Receive only */
	struct rxe_recv_wqe	*wqe;         // 取出来正在用的 wqe, 可能来自 rq, 或者 srq, ref: get_srq_wqe()

	/* RDMA read / atomic only */         // 处理 response pkt 的时候暂存的一些信息, ref: writ_data_in()
	u64			va;
	struct rxe_mem		*mr; // 记录下当前正要被用的 mr, ref: check_rkey
	u32			resid; // ref: check_rkey(), 剩下的需要处理的数据长度
	u32			rkey;
	u32			length;
	u64			atomic_orig; // 存储原始值, 回复 atomic response 的时候需要

	/* SRQ only */
	struct {
		struct rxe_recv_wqe	wqe;
		struct ib_sge		sge[RXE_MAX_SGE];
	} srq_wqe; // 暂存从 srq 里取出来的东西

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 *
	 * 用来处理 read/atomic 的, 保存相关信息
	 */
	struct resp_res		*resources; // ref: find_resource()
	unsigned int		res_head;
	unsigned int		res_tail;
	struct resp_res		*res;
	struct rxe_task		task;  // rxe_responder
};

// ref: rxe_qp_from_attr
// 大部分属性来自 modify_qp, 而不是 creaet_qp()
// 有不少信息是对方的信息, rxe_resp_info() 这要在连接建立后才能拿到
struct rxe_qp {
	struct rxe_pool_entry	pelem;	// 挂到 pool 里管理
	struct ib_qp		ibqp;   // 上层 qp 结构
	struct ib_qp_attr	attr;   // 上层 qp 属性
	unsigned int		valid;  // destroy 后设置为 0, qp 可用的总开关
	unsigned int		mtu;
	int			is_user; // 是不是用户态调用过来要创建这个 qp

	struct rxe_pd		*pd;
	struct rxe_srq		*srq;
	struct rxe_cq		*scq;
	struct rxe_cq		*rcq;

	enum ib_sig_type	sq_sig_type; // 是不是所有的 wqe 都需要通知

	struct rxe_sq		sq;
	struct rxe_rq		rq;

	struct socket		*sk;         // 方便对接到 ip 层, 来收发报文
	u32			dst_cookie;  // 保存的出口信息
	u16			src_port;    // rocev2 外层 udp 报文的 sport

	struct rxe_av		pri_av;      // 路由信息
	struct rxe_av		alt_av;

	/* list of mcast groups qp has joined (for cleanup) */
	struct list_head	grp_list;
	spinlock_t		grp_lock; /* guard grp_list */

	struct sk_buff_head	req_pkts; // ref: rxe_resp_queue_pkt, 暂存收到的 req pkt
	struct sk_buff_head	resp_pkts; // 暂存收到的 response pkt
	struct sk_buff_head	send_pkts; // 没啥用

	struct rxe_req_info	req;  // 处理 wqe, 发送 req pkt
	struct rxe_comp_info	comp; // 产生 cqe(sq/rq)
	struct rxe_resp_info	resp; // 收到 req, 产生 response

	atomic_t		ssn; // 初始值是 0, send sequence number, 和 msn 是一对一的, ref: rxe_qp_init_misc(), post_sq_wqe 的时候 atomic_inc
	atomic_t		skb_out; // outstanding pkts
	int			need_req_skb; // 表示 outstanding pkts 太多了, 当前不能向外发送了, 需要给等 req skb credit 空出来

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct timer_list retrans_timer; // ref: rxe_qp_init_req, update_state
	u64 qp_timeout_jiffies; // 来自 qp_attr, retrans timeout, ref: rxe_qp_from_attr()

	/* Timer for handling RNR NAKS. */
	struct timer_list rnr_nak_timer; // ref: rxe_qp_init_req, rxe_completer() 负责调度, 其延迟应该是从 RNR NAK pkt 里提取的.

	spinlock_t		state_lock; /* guard requester and completer, 排空 SQ 的时候用来协调 requester 和 completer 的 */

	struct execute_work	cleanup_work; // 没啥大作用, 就是用 container_of 能找到 qp 这个结构, 用来挂一个 clean work 的
};

enum rxe_mem_state {
	RXE_MEM_STATE_ZOMBIE,
	RXE_MEM_STATE_INVALID,
	RXE_MEM_STATE_FREE,
	RXE_MEM_STATE_VALID,
};

enum rxe_mem_type {
	RXE_MEM_TYPE_NONE,
	RXE_MEM_TYPE_DMA,
	RXE_MEM_TYPE_MR,
	RXE_MEM_TYPE_FMR,
	RXE_MEM_TYPE_MW,
};

// 每个 page 可以存储的 rxe_phys_buf 的数量
#define RXE_BUF_PER_MAP		(PAGE_SIZE / sizeof(struct rxe_phys_buf))

// 表示一段连续的 phy buf
struct rxe_phys_buf {
	u64      addr;
	u64      size;
};

// 这个结构不超过一个 page
struct rxe_map {
	struct rxe_phys_buf	buf[RXE_BUF_PER_MAP];
};

// ref: rxe_alloc_mr()
struct rxe_mem {
	struct rxe_pool_entry	pelem;
	union {
		struct ib_mr		ibmr;
		struct ib_mw		ibmw;
	};

	struct ib_umem		*umem;

	enum rxe_mem_state	state;
	enum rxe_mem_type	type;
	u64			va;
	u64			iova;
	size_t			length;
	u32			offset;
	int			access;

	int			page_shift;
	int			page_mask;
	int			map_shift;
	int			map_mask;

	u32			num_buf;
	u32			nbuf;

	u32			max_buf; // 这个 mr 最大的 sge 数量
	u32			num_map;

	struct rxe_map		**map;
};

struct rxe_mc_grp {
	struct rxe_pool_entry	pelem;
	spinlock_t		mcg_lock; /* guard group */
	struct rxe_dev		*rxe;
	struct list_head	qp_list;
	union ib_gid		mgid;
	int			num_qp;
	u32			qkey;
	u16			pkey;
};

struct rxe_mc_elem {
	struct rxe_pool_entry	pelem;
	struct list_head	qp_list;
	struct list_head	grp_list;
	struct rxe_qp		*qp;
	struct rxe_mc_grp	*grp;
};

struct rxe_port {
	struct ib_port_attr	attr;
	__be64			port_guid;  // guid 的生成: rxe_init_ports
	__be64			subnet_prefix;
	spinlock_t		port_lock; /* guard port */
	unsigned int		mtu_cap;
	/* special QPs */
	u32			qp_smi_index;
	u32			qp_gsi_index;
};

// ref: rxe_init()
struct rxe_dev {
	struct ib_device	ib_dev;	// ref: rxe_register_device()
	struct ib_device_attr	attr;
	struct device_dma_parameters dma_parms; // ref: rxe_register_device() -> dma_set_max_seg_size() / dma_coerce_mask_and_coherent
	int			max_ucontext;
	int			max_inline_data;
	struct mutex	usdev_lock;

	struct net_device	*ndev;

	int			xmit_errors;

	// 一堆 pool 维护 per-device 的资源
	struct rxe_pool		uc_pool;
	struct rxe_pool		pd_pool;
	struct rxe_pool		ah_pool;
	struct rxe_pool		srq_pool;
	struct rxe_pool		qp_pool;
	struct rxe_pool		cq_pool;
	struct rxe_pool		mr_pool;
	struct rxe_pool		mw_pool;
	struct rxe_pool		mc_grp_pool;
	struct rxe_pool		mc_elem_pool;

	spinlock_t		pending_lock; /* guard pending_mmaps */
	struct list_head	pending_mmaps; // ref: rxe_mmap_info

	spinlock_t		mmap_offset_lock; /* guard mmap_offset */
	u64			mmap_offset;

	atomic64_t		stats_counters[RXE_NUM_OF_COUNTERS];

	struct rxe_port		port;
	struct crypto_shash	*tfm; // 用于 crc 计算
};

static inline void rxe_counter_inc(struct rxe_dev *rxe, enum rxe_counters index)
{
	atomic64_inc(&rxe->stats_counters[index]);
}

static inline struct rxe_dev *to_rdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct rxe_dev, ib_dev) : NULL;
}

static inline struct rxe_ucontext *to_ruc(struct ib_ucontext *uc)
{
	return uc ? container_of(uc, struct rxe_ucontext, ibuc) : NULL;
}

static inline struct rxe_pd *to_rpd(struct ib_pd *pd)
{
	return pd ? container_of(pd, struct rxe_pd, ibpd) : NULL;
}

static inline struct rxe_ah *to_rah(struct ib_ah *ah)
{
	return ah ? container_of(ah, struct rxe_ah, ibah) : NULL;
}

static inline struct rxe_srq *to_rsrq(struct ib_srq *srq)
{
	return srq ? container_of(srq, struct rxe_srq, ibsrq) : NULL;
}

static inline struct rxe_qp *to_rqp(struct ib_qp *qp)
{
	return qp ? container_of(qp, struct rxe_qp, ibqp) : NULL;
}

static inline struct rxe_cq *to_rcq(struct ib_cq *cq)
{
	return cq ? container_of(cq, struct rxe_cq, ibcq) : NULL;
}

static inline struct rxe_mem *to_rmr(struct ib_mr *mr)
{
	return mr ? container_of(mr, struct rxe_mem, ibmr) : NULL;
}

static inline struct rxe_mem *to_rmw(struct ib_mw *mw)
{
	return mw ? container_of(mw, struct rxe_mem, ibmw) : NULL;
}

static inline struct rxe_pd *mr_pd(struct rxe_mem *mr)
{
	return to_rpd(mr->ibmr.pd);
}

static inline u32 mr_lkey(struct rxe_mem *mr)
{
	return mr->ibmr.lkey;
}

static inline u32 mr_rkey(struct rxe_mem *mr)
{
	return mr->ibmr.rkey;
}

int rxe_register_device(struct rxe_dev *rxe, const char *ibdev_name);

void rxe_mc_cleanup(struct rxe_pool_entry *arg);

#endif /* RXE_VERBS_H */
