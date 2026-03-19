// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"
#include "rxe_task.h"

enum comp_state {
	COMPST_GET_ACK,
	COMPST_GET_WQE,
	COMPST_COMP_WQE,
	COMPST_COMP_ACK,
	COMPST_CHECK_PSN,
	COMPST_CHECK_ACK,
	COMPST_READ,
	COMPST_ATOMIC,
	COMPST_WRITE_SEND,
	COMPST_UPDATE_COMP,
	COMPST_ERROR_RETRY,
	COMPST_RNR_RETRY,
	COMPST_ERROR,
	COMPST_EXIT, /* We have an issue, and we want to rerun the completer */
	COMPST_DONE, /* The completer finished successflly */
};

static char *comp_state_name[] =  {
	[COMPST_GET_ACK]		= "GET ACK",
	[COMPST_GET_WQE]		= "GET WQE",
	[COMPST_COMP_WQE]		= "COMP WQE",
	[COMPST_COMP_ACK]		= "COMP ACK",
	[COMPST_CHECK_PSN]		= "CHECK PSN",
	[COMPST_CHECK_ACK]		= "CHECK ACK",
	[COMPST_READ]			= "READ",
	[COMPST_ATOMIC]			= "ATOMIC",
	[COMPST_WRITE_SEND]		= "WRITE/SEND",
	[COMPST_UPDATE_COMP]		= "UPDATE COMP",
	[COMPST_ERROR_RETRY]		= "ERROR RETRY",
	[COMPST_RNR_RETRY]		= "RNR RETRY",
	[COMPST_ERROR]			= "ERROR",
	[COMPST_EXIT]			= "EXIT",
	[COMPST_DONE]			= "DONE",
};

static unsigned long rnrnak_usec[32] = {
	[IB_RNR_TIMER_655_36] = 655360,
	[IB_RNR_TIMER_000_01] = 10,
	[IB_RNR_TIMER_000_02] = 20,
	[IB_RNR_TIMER_000_03] = 30,
	[IB_RNR_TIMER_000_04] = 40,
	[IB_RNR_TIMER_000_06] = 60,
	[IB_RNR_TIMER_000_08] = 80,
	[IB_RNR_TIMER_000_12] = 120,
	[IB_RNR_TIMER_000_16] = 160,
	[IB_RNR_TIMER_000_24] = 240,
	[IB_RNR_TIMER_000_32] = 320,
	[IB_RNR_TIMER_000_48] = 480,
	[IB_RNR_TIMER_000_64] = 640,
	[IB_RNR_TIMER_000_96] = 960,
	[IB_RNR_TIMER_001_28] = 1280,
	[IB_RNR_TIMER_001_92] = 1920,
	[IB_RNR_TIMER_002_56] = 2560,
	[IB_RNR_TIMER_003_84] = 3840,
	[IB_RNR_TIMER_005_12] = 5120,
	[IB_RNR_TIMER_007_68] = 7680,
	[IB_RNR_TIMER_010_24] = 10240,
	[IB_RNR_TIMER_015_36] = 15360,
	[IB_RNR_TIMER_020_48] = 20480,
	[IB_RNR_TIMER_030_72] = 30720,
	[IB_RNR_TIMER_040_96] = 40960,
	[IB_RNR_TIMER_061_44] = 61410,
	[IB_RNR_TIMER_081_92] = 81920,
	[IB_RNR_TIMER_122_88] = 122880,
	[IB_RNR_TIMER_163_84] = 163840,
	[IB_RNR_TIMER_245_76] = 245760,
	[IB_RNR_TIMER_327_68] = 327680,
	[IB_RNR_TIMER_491_52] = 491520,
};

static inline unsigned long rnrnak_jiffies(u8 timeout)
{
	return max_t(unsigned long,
		usecs_to_jiffies(rnrnak_usec[timeout]), 1);
}

static enum ib_wc_opcode wr_to_wc_opcode(enum ib_wr_opcode opcode)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:			return IB_WC_RDMA_WRITE;
	case IB_WR_RDMA_WRITE_WITH_IMM:		return IB_WC_RDMA_WRITE;
	case IB_WR_SEND:			return IB_WC_SEND;
	case IB_WR_SEND_WITH_IMM:		return IB_WC_SEND;
	case IB_WR_RDMA_READ:			return IB_WC_RDMA_READ;
	case IB_WR_ATOMIC_CMP_AND_SWP:		return IB_WC_COMP_SWAP;
	case IB_WR_ATOMIC_FETCH_AND_ADD:	return IB_WC_FETCH_ADD;
	case IB_WR_LSO:				return IB_WC_LSO;
	case IB_WR_SEND_WITH_INV:		return IB_WC_SEND;
	case IB_WR_RDMA_READ_WITH_INV:		return IB_WC_RDMA_READ;
	case IB_WR_LOCAL_INV:			return IB_WC_LOCAL_INV;
	case IB_WR_REG_MR:			return IB_WC_REG_MR;

	default:
		return 0xff;
	}
}

// run completer 就是了
void retransmit_timer(struct timer_list *t)
{
	struct rxe_qp *qp = from_timer(qp, t, retrans_timer);

	if (qp->valid) {
		qp->comp.timeout = 1;
		rxe_run_task(&qp->comp.task, 1);
	}
}

void rxe_comp_queue_pkt(struct rxe_qp *qp, struct sk_buff *skb)
{
	int must_sched;

	skb_queue_tail(&qp->resp_pkts, skb);

	must_sched = skb_queue_len(&qp->resp_pkts) > 1;
	if (must_sched != 0)
		rxe_counter_inc(SKB_TO_PKT(skb)->rxe, RXE_CNT_COMPLETER_SCHED);

	// rxe_completer
	rxe_run_task(&qp->comp.task, must_sched);
}

// 这里说明 response 和 wqe 是要按照顺序一一对应的.
// 因为这里就是取开头的 wqe, 没有进一步匹配查找
static inline enum comp_state get_wqe(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt,
				      struct rxe_send_wqe **wqe_p)
{
	struct rxe_send_wqe *wqe;

	/* we come here whether or not we found a response packet to see if
	 * there are any posted WQEs
	 */
	wqe = queue_head(qp->sq.queue);
	*wqe_p = wqe;

	/* no WQE or requester has not started it yet */
	if (!wqe || wqe->state == wqe_state_posted)
		return pkt ? COMPST_DONE : COMPST_EXIT;

	/* WQE does not require an ack */
	if (wqe->state == wqe_state_done)
		return COMPST_COMP_WQE;

	/* WQE caused an error */
	if (wqe->state == wqe_state_error)
		return COMPST_ERROR;

	/* we have a WQE, if we also have an ack check its PSN */
	return pkt ? COMPST_CHECK_PSN : COMPST_EXIT;
}

static inline void reset_retry_counters(struct rxe_qp *qp)
{
	qp->comp.retry_cnt = qp->attr.retry_cnt;
	qp->comp.rnr_retry = qp->attr.rnr_retry;
	qp->comp.started_retry = 0;
}

/* 关于几个 psn:
 * - pkt.psn: response ack 的 psn
 * - comp.psn: expected psn, 也就是最大的被 ack 的 psn + 1
 * - wqe.last_psn: 即当前 wqe 的 last psn(read req 中才实际有意义)
 *
 *
 * 累积确认(与 TCP 有不同)参考下述规则, 
 * - *Rule 0 隐含 NAK*:  如果收到 response 的 BTH:PSN 大于 没有完成的
 *   READ/ATOMIC 操作的 PSN, 那么这个 ACK 本质是对前面的 READ/ATOMIC 的 NAK.
 *   换句话说, *read/atomic 是不支持累积 ack 的*.
 * - *Rule 1 传统累积 ACK*: SEND/WRITE 遵循传统的累积 ack 行为
 * - *Rule 2 隐含 ACK*: READ response 的第一个 pkt, 累积 ack 前面的 request.
 *   这是为了确保 SEND/WRITE 的累积 ack.
 * - *Rule 3 READ ack*: READ response 的最后的 pkt, ack 了当前的 read request.
 *   由于 READ 不支持 累积 ACK, 所以必须自己用最后一个 pkt 来 ack.
 * - *<<Rule-4>>* NAK BTH:PSN 是 responder 的 ePSN. 所以 NAK pkt 隐式的 ack 了
 *    其前面的 pkt. 当然 NAK 是无法隐式 ack 前面的 read req 的. read req 必须被
 *    显示的 response 来 ack. rule-4 本质是 rule-0 和 rule-1 的在 NAK pkt 上的
 *    推广.
 *
 *    XXX: 根据 rule4, NAK 包 也会来先 check_psn 然后 comp 一些 wqe 的, 非常关键
 *
 *
 *
 * 关于 response 回复的 pkt 里的的 BTH:PSN
 * - pure-ack: 使用个最新的 req 的 psn.[[C9-95]]
 * - read/atomic response psn: 用 req 的 psn.  [[C9-96]] [[o9-58]] 
 * - nak 的 psn:
 *   - for non-read req response 用 ePSN, [[C9-111]] [[C9-112]] [[C9-113]]
 *   - read req response, NAK BTH:PSN 用正准备 NAK 的 PSN
 *   - RNR NAK, NAK BTH:PSN 用正准备 NAK 的 PSN
 *
 * */
static inline enum comp_state check_psn(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					struct rxe_send_wqe *wqe)
{
	s32 diff;

	/* check to see if response is past the oldest WQE. if it is, complete
	 * send/write or error read/atomic
	 */
	// pkt:psn 完全覆盖的 wqe
	// 1. 如果是 send/write req, 说明这个 wqe 被累积 ack 了
	// 2. 如果是 read/atomic req, 那么必须要严格对应 psn 的, 那么说明这个 wqe 被隐式 NAK 了
	// 3. 如果是 NAK 包: 根据情况不同会影响和当前 pkt->psn 匹配的 wqe 的处理. 但是前面的 wqe 都是一样的:
	//    - send/write 被隐式 ack
	//    - read/atomic 被隐式 NAK
	diff = psn_compare(pkt->psn, wqe->last_psn);
	if (diff > 0) { /* response.psn > wqe */
		if (wqe->state == wqe_state_pending) { 
			if (wqe->mask & WR_ATOMIC_OR_READ_MASK) //  Rule 0
				return COMPST_ERROR_RETRY;

			reset_retry_counters(qp); // Rule 1, Rule 2
			return COMPST_COMP_WQE;
		} else { /* invalid pkt ? without valid wqe to match it */
			return COMPST_DONE;
		}
	}
	

	/* compare response packet to expected response(准确的说是 snd_una) */
	/*  到这里的时候有: 
	 *  - wqe->first_psn <= pkt->psn <= wqe->last_psn
	 *  - wqe->first_psn <= snd_una <= wqe->last_psn (???)
	 *
	 *  特别的对于 single pkt req(atomic 必然走这里), wqe->first_psn == wqe->last_psn == pkt->psn == snd_una
	 *  故对于 single pkt req, 这里必然走到 case 3. 即该 wqe 正好和 ack 关联. 那么通通到 COMPST_CHECK_ACK 处理.
	 *
	 *
	 * 对于 multi pkt req:
	 * - pure-ack: send/write response
	 *   - case 1(dup pkt): wqe->first_psn <= pkt->psn < snd_una <= wqe->last_psn
	 *     - case 1.1: (???)
	 *     - case 1.2: wqe->first_psn <= pkt->psn < snd_una < wqe->last_psn
	 *       - dup pkt, drop silently
	 *   - case 3(good ack): wqe->first_psn <= snd_una <= pkt->psn <= wqe->last_psn
	 *     - 顺利推进了 snd_una, 进一步处理
	 *
	 * - read response (atomic 不可能是 multi req 的)
	 *   - case 1(dup pkt): wqe->first_psn <= pkt->psn < snd_una <= wqe->last_psn
	 *     - case 1.1: (???)
	 *       - 也是 dup 哦, 但是这个 wqe 是这个 SQ 上最后的一个 wqe (???)
	 *     - case 1.2: wqe->first_psn <= pkt->psn < snd_una < wqe->last_psn                           
	 *       - dup pkt, drop silently
	 *   - case 2: wqe->first_psn <= snd_una < pkt->psn <= wqe->last_psn
	 *     - 对于 read 来说, 必须要按照顺序来接收 psn response, 这里 reorder 了, drop silently
	 *   - case 3(good ack): wqe->first_psn <= snd_una = pkt->psn <= wqe->last_psn
	 *     - 对于 read 来说, good ack 必须是正好和 psn 对应的, 进一步处理
	 *
	 *
	 * - nak response
	 *   - case 1(dup pkt): wqe->first_psn <= pkt->psn < snd_una <= wqe->last_psn
	 *     - case 1.1: (???)
	 *     - case 1.2: wqe->first_psn <= pkt->psn < snd_una < wqe->last_psn
	 *   - case 2(nak read req): wqe->first_psn <= snd_una < pkt->psn <= wqe->last_psn
	 *     - 对于 read 来说, 就算是 NAK 也是如此 ???
	 *   - case 3(nak): 
	 *     - non-read nak: 
	 *       - wqe->first_psn <= snd_una <= pkt->psn <= wqe->last_psn
	 *       - pkt->psn == resp.ePSN
	 *     - read nak:
	 *       - wqe->first_psn <= snd_una == pkt->psn <= wqe->last_psn
	 *       - pkt->psn == resp.curr.psn
	 *     - others:
	 *       - wqe->first_psn <= snd_una <= pkt->psn <= wqe->last_psn
	 *       - pkt->psn == resp.curr.psn
	 *
	 *
	 * COMPST_CHECK_ACK: ack 和当前的 wqe 对应, 但是需要进一步检查
	 * COMPST_COMP_ACK: 这个 ack 确认了当前的 wqe(至少部分), 且该 wqe 是该 ack 可以确认的最后一个 wqe
	 * COMPST_DONE: drop silently
	 *
	 * */

	/* 小结: 当前的 wqe 是这个 ack 可以关联的最后一个 wqe 了, 分两种情况
	 * - 无法通过检查: drop silently
	 *   - 这里有一个优化 case 1.1 (???)
	 * - default case: COMPST_CHECK_ACK 里做进一步处理
	 *
	 * */ 
	diff = psn_compare(pkt->psn, qp->comp.psn);
	if (diff < 0) { //  case1: dup ack, drop silently
		/* response is most likely a retried packet if it matches an
		 * uncompleted WQE go complete it else ignore it.
		*/
		// 这里不可能(???) pkt->psn < snd_una && pkt->psn == wqe->last_psn 的
		if (pkt->psn == wqe->last_psn) // case 1.1
			return COMPST_COMP_ACK;
		else // case 1.2
			return COMPST_DONE; // drop silently
	} else if ((diff > 0) && (wqe->mask & WR_ATOMIC_OR_READ_MASK)) {  // spefical case for read: bad ack
		return COMPST_DONE;
	} else { // case 3: default case, 进一步处理
		return COMPST_CHECK_ACK;
	}
}

// 检查 ack 包
static inline enum comp_state check_ack(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					struct rxe_send_wqe *wqe)
{
	unsigned int mask = pkt->mask;
	u8 syn;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	/* Check the sequence only */
	switch (qp->comp.opcode) { // 前一个 response pkt 里提取出来的 opcode
	case -1:
		/* Will catch all *_ONLY cases. */
		if (!(mask & RXE_START_MASK)) // 所以这里必须要有 RXE_START_MASK, 得是一个新的
			return COMPST_ERROR;

		break;

	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		if (pkt->opcode != IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE &&
		    pkt->opcode != IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST) { // 可能重传了
			/* read retries of partial data may restart from
			 * read response first or response only.
			 */
			if ((pkt->psn == wqe->first_psn &&
			     pkt->opcode ==
			     IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST) ||
			    (wqe->first_psn == wqe->last_psn &&
			     pkt->opcode ==
			     IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY))
				break;

			return COMPST_ERROR;
		}
		break;
	default:
		WARN_ON_ONCE(1);
	}

	/* Check operation validity. */
	switch (pkt->opcode) {
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
		syn = aeth_syn(pkt); // 这几个 read pkt 要携带 aeth 的

		if ((syn & AETH_TYPE_MASK) != AETH_ACK)
			return COMPST_ERROR;

		fallthrough;
		/* (IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE doesn't have an AETH)
		 */
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE: // 当前 wqe 必须是 READ 相关的,  READ_FIRST/READ_LAST/READ_ONLY 会 fallthrough 到这里的
		if (wqe->wr.opcode != IB_WR_RDMA_READ &&
		    wqe->wr.opcode != IB_WR_RDMA_READ_WITH_INV) {
			wqe->status = IB_WC_FATAL_ERR;
			return COMPST_ERROR;
		}
		reset_retry_counters(qp);
		return COMPST_READ;

	case IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE:
		syn = aeth_syn(pkt);

		if ((syn & AETH_TYPE_MASK) != AETH_ACK)
			return COMPST_ERROR;

		if (wqe->wr.opcode != IB_WR_ATOMIC_CMP_AND_SWP &&
		    wqe->wr.opcode != IB_WR_ATOMIC_FETCH_AND_ADD)
			return COMPST_ERROR;
		reset_retry_counters(qp);
		return COMPST_ATOMIC;

	case IB_OPCODE_RC_ACKNOWLEDGE: // pure ack 包处理, nak 也是这里
		syn = aeth_syn(pkt);
		switch (syn & AETH_TYPE_MASK) {
		case AETH_ACK: // 这里可以看到没有用 credit count 机制的
			reset_retry_counters(qp);
			return COMPST_WRITE_SEND;

		case AETH_RNR_NAK:
			rxe_counter_inc(rxe, RXE_CNT_RCV_RNR);
			return COMPST_RNR_RETRY;

		case AETH_NAK:
			switch (syn) {
			case AETH_NAK_PSN_SEQ_ERROR:
				/* a nak implicitly acks all packets with psns
				 * before
				 */
				if (psn_compare(pkt->psn, qp->comp.psn) > 0) {
					rxe_counter_inc(rxe,
							RXE_CNT_RCV_SEQ_ERR);
					// NAK pkt 间接 ACK 了前面的 pkt, 所以 retry 的时候从 NAK 这个 PSN 开始就可以了
					// snd_una 前进了很多, nak 隐式前进了很多, nak 前的那些 wqe 如何处理呢?
					qp->comp.psn = pkt->psn; // NAK BTH:PSN 是 responder 的 ePSN, 即小于 NAK PSN 的都被 ack 了.
					if (qp->req.wait_psn) {
						qp->req.wait_psn = 0;
						rxe_run_task(&qp->req.task, 0);
					}
				}
				return COMPST_ERROR_RETRY;

			case AETH_NAK_INVALID_REQ:
				wqe->status = IB_WC_REM_INV_REQ_ERR;
				return COMPST_ERROR;

			case AETH_NAK_REM_ACC_ERR:
				wqe->status = IB_WC_REM_ACCESS_ERR;
				return COMPST_ERROR;

			case AETH_NAK_REM_OP_ERR:
				wqe->status = IB_WC_REM_OP_ERR;
				return COMPST_ERROR;

			default:
				pr_warn("unexpected nak %x\n", syn);
				wqe->status = IB_WC_REM_OP_ERR;
				return COMPST_ERROR;
			}

		default:
			return COMPST_ERROR;
		}
		break;

	default:
		pr_warn("unexpected opcode\n");
	}

	return COMPST_ERROR;
}

// 将 read 回来的包 copy 上去
static inline enum comp_state do_read(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt,
				      struct rxe_send_wqe *wqe)
{
	int ret;

	ret = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE,
			&wqe->dma, payload_addr(pkt),
			payload_size(pkt), to_mem_obj, NULL);
	if (ret)
		return COMPST_ERROR;

	// 全部 copy 结束了
	if (wqe->dma.resid == 0 && (pkt->mask & RXE_END_MASK))
		return COMPST_COMP_ACK;
	else
		return COMPST_UPDATE_COMP;
}

static inline enum comp_state do_atomic(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					struct rxe_send_wqe *wqe)
{
	int ret;

	u64 atomic_orig = atmack_orig(pkt);

	// atomic 的数据也要copy 到 wqe 的 dma 里么?
	ret = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE,
			&wqe->dma, &atomic_orig,
			sizeof(u64), to_mem_obj, NULL);
	if (ret)
		return COMPST_ERROR;
	else
		return COMPST_COMP_ACK;
}

static void make_send_cqe(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
			  struct rxe_cqe *cqe)
{
	memset(cqe, 0, sizeof(*cqe));

	if (!qp->is_user) {
		struct ib_wc		*wc	= &cqe->ibwc;

		wc->wr_id		= wqe->wr.wr_id;
		wc->status		= wqe->status;
		wc->opcode		= wr_to_wc_opcode(wqe->wr.opcode);
		if (wqe->wr.opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
		    wqe->wr.opcode == IB_WR_SEND_WITH_IMM)
			wc->wc_flags = IB_WC_WITH_IMM;
		wc->byte_len		= wqe->dma.length;
		wc->qp			= &qp->ibqp;
	} else {
		struct ib_uverbs_wc	*uwc	= &cqe->uibwc;

		uwc->wr_id		= wqe->wr.wr_id;
		uwc->status		= wqe->status;
		uwc->opcode		= wr_to_wc_opcode(wqe->wr.opcode);
		if (wqe->wr.opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
		    wqe->wr.opcode == IB_WR_SEND_WITH_IMM)
			uwc->wc_flags = IB_WC_WITH_IMM;
		uwc->byte_len		= wqe->dma.length;
		uwc->qp_num		= qp->ibqp.qp_num;
	}
}

/*
 * IBA Spec. Section 10.7.3.1 SIGNALED COMPLETIONS
 * ---------8<---------8<-------------
 * ...Note that if a completion error occurs, a Work Completion
 * will always be generated, even if the signaling
 * indicator requests an Unsignaled Completion.
 * ---------8<---------8<-------------
 *
 *  send queue 的 cqe 生成
 */
static void do_complete(struct rxe_qp *qp, struct rxe_send_wqe *wqe)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_cqe cqe;

	if ((qp->sq_sig_type == IB_SIGNAL_ALL_WR) ||
	    (wqe->wr.send_flags & IB_SEND_SIGNALED) ||
	    wqe->status != IB_WC_SUCCESS) {
		make_send_cqe(qp, wqe, &cqe);
		advance_consumer(qp->sq.queue);
		rxe_cq_post(qp->scq, &cqe, 0);
	} else {
		advance_consumer(qp->sq.queue);
	}

	if (wqe->wr.opcode == IB_WR_SEND ||
	    wqe->wr.opcode == IB_WR_SEND_WITH_IMM ||
	    wqe->wr.opcode == IB_WR_SEND_WITH_INV)
		rxe_counter_inc(rxe, RXE_CNT_RDMA_SEND);

	/*
	 * we completed something so let req run again
	 * if it is trying to fence
	 */
	if (qp->req.wait_fence) { // 这里调度让其试一试, 如果还要等待, 会继续 wait_fence 的, ref: req_next_wqe
		qp->req.wait_fence = 0;
		rxe_run_task(&qp->req.task, 0);
	}
}

// ack 了 该 wqe, 且该 wqe 是该 ack 的最后一个 wqe
static inline enum comp_state complete_ack(struct rxe_qp *qp,
					   struct rxe_pkt_info *pkt,
					   struct rxe_send_wqe *wqe)
{
	unsigned long flags;

	if (wqe->has_rd_atomic) {
		wqe->has_rd_atomic = 0;
		atomic_inc(&qp->req.rd_atomic);
		if (qp->req.need_rd_atomic) {
			qp->comp.timeout_retry = 0;
			qp->req.need_rd_atomic = 0;
			rxe_run_task(&qp->req.task, 0);
		}
	}

	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
		/* state_lock used by requester & completer */
		spin_lock_irqsave(&qp->state_lock, flags);
		if ((qp->req.state == QP_STATE_DRAIN) &&
		    (qp->comp.psn == qp->req.psn)) {
			qp->req.state = QP_STATE_DRAINED;
			spin_unlock_irqrestore(&qp->state_lock, flags);

			if (qp->ibqp.event_handler) {
				struct ib_event ev;

				ev.device = qp->ibqp.device;
				ev.element.qp = &qp->ibqp;
				ev.event = IB_EVENT_SQ_DRAINED;
				qp->ibqp.event_handler(&ev,
					qp->ibqp.qp_context);
			}
		} else {
			spin_unlock_irqrestore(&qp->state_lock, flags);
		}
	}

	do_complete(qp, wqe);

	if (psn_compare(pkt->psn, qp->comp.psn) >= 0)
		return COMPST_UPDATE_COMP;
	else
		return COMPST_DONE;
}

// ack 了 该 wqe, 但是该 wqe 不是该 ack 的最后一个 wqe, 即这个 ack 里还有信息可能可以继续去 ack 后面的 wqe 的
static inline enum comp_state complete_wqe(struct rxe_qp *qp,
					   struct rxe_pkt_info *pkt,
					   struct rxe_send_wqe *wqe)
{
	if (pkt && wqe->state == wqe_state_pending) {
		if (psn_compare(wqe->last_psn, qp->comp.psn) >= 0) {
			// sq snd_una 前进
			qp->comp.psn = (wqe->last_psn + 1) & BTH_PSN_MASK; // 更新 expect psn, 故 expectPSN 应该是下一个 wqe 的 first_psn
			qp->comp.opcode = -1;
		}

		if (qp->req.wait_psn) {
			qp->req.wait_psn = 0;
			rxe_run_task(&qp->req.task, 1);
		}
	}

	do_complete(qp, wqe);

	return COMPST_GET_WQE; // 一个 pkt 可能累积确认多个 WQE 的, 所以继续用这个 pkt 去处理下一个 WQE
}

static void rxe_drain_resp_pkts(struct rxe_qp *qp, bool notify)
{
	struct sk_buff *skb;
	struct rxe_send_wqe *wqe;

	// resp pkt 全部 drop 掉
	while ((skb = skb_dequeue(&qp->resp_pkts))) {
		rxe_drop_ref(qp);
		kfree_skb(skb);
	}

	// sq 里的 wqe 全部消耗掉
	while ((wqe = queue_head(qp->sq.queue))) {
		if (notify) {
			wqe->status = IB_WC_WR_FLUSH_ERR;
			do_complete(qp, wqe);
		} else {
			advance_consumer(qp->sq.queue);
		}
	}
}

// sq 上的任务完成或者出错了要返回 Work Completion 了
// 调度时机:
// - 收到 response pkt 的时候: rxe_comp_queue_pkt
// - retransmit_timer 触发的时候: retransmit_timer
// - 非 RC: rxe_xmit_packet 的时候
// - rxe_qp_drain()
// - rxe_qp_error()
// - 有些 local 操作处理完需要返回 wc
// - post_send 的时候出错了: rxe_post_send_kernel
//
// ref: 1.4 vol1 Ch9.7.6.1
int rxe_completer(void *arg)
{
	struct rxe_qp *qp = (struct rxe_qp *)arg;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_send_wqe *wqe = NULL;
	struct sk_buff *skb = NULL;
	struct rxe_pkt_info *pkt = NULL;
	enum comp_state state;

	rxe_add_ref(qp);

	if (!qp->valid || qp->req.state == QP_STATE_ERROR ||
	    qp->req.state == QP_STATE_RESET) {
		rxe_drain_resp_pkts(qp, qp->valid &&
				    qp->req.state == QP_STATE_ERROR);
		goto exit;
	}

	if (qp->comp.timeout) { // completer 是被 retransmit_timer 触发的
		qp->comp.timeout_retry = 1;
		qp->comp.timeout = 0;
	} else {
		qp->comp.timeout_retry = 0;
	}

	// 已经处于 retry 状态, 不处理了. 等 rxe_retry 被调度了才处理
	if (qp->req.need_retry)
		goto exit;

	state = COMPST_GET_ACK;

	while (1) {
		pr_debug("qp#%d state = %s\n", qp_num(qp),
			 comp_state_name[state]);
		switch (state) {
		case COMPST_GET_ACK: // 开始, 收到了 response 包
			skb = skb_dequeue(&qp->resp_pkts);
			if (skb) {
				pkt = SKB_TO_PKT(skb); // ref: rxe_rcv, 里提取了这些信息
				qp->comp.timeout_retry = 0;
			}
			state = COMPST_GET_WQE;	// 有些场景 rxe_completer 的调度不是 response 包引起的, 比如: local 操作, 出错处理
			break;

		case COMPST_GET_WQE:
			state = get_wqe(qp, pkt, &wqe); // 去 sq 拿 wqe
			break;

		case COMPST_CHECK_PSN:
			state = check_psn(qp, pkt, wqe);
			break;

		case COMPST_CHECK_ACK: // ack 正好对应了该 wqe 的 last_psn 么
			state = check_ack(qp, pkt, wqe);
			break;

		case COMPST_READ:
			state = do_read(qp, pkt, wqe);
			break;

		case COMPST_ATOMIC:
			state = do_atomic(qp, pkt, wqe);
			break;

		case COMPST_WRITE_SEND:
			if (wqe->state == wqe_state_pending &&
			    wqe->last_psn == pkt->psn)
				state = COMPST_COMP_ACK; // 正好是对应的 ack
			else
				state = COMPST_UPDATE_COMP;
			break;

		case COMPST_COMP_ACK: // ack 确认了部分 wqe, 这个 pkt 的 ack 已经被榨干了
			state = complete_ack(qp, pkt, wqe);
			break;

		case COMPST_COMP_WQE: // 累积确认走这里, pkt 确认了一个完整的 wqe
			state = complete_wqe(qp, pkt, wqe);
			break;

		case COMPST_UPDATE_COMP: // 更新 comp 信息, 比如 expected psn, 一个 pkt 的 ack 能处理的 wqe 结束后, 利用其信息更新下 comp 的信息. 有些 pkt 太老了, 可能直接跳过这部分, 直接去 COMPST_DONE 了.
			if (pkt->mask & RXE_END_MASK)
				qp->comp.opcode = -1;
			else
				qp->comp.opcode = pkt->opcode; // 记录下前一个 opcode 咯, 后面校验可能要用

			if (psn_compare(pkt->psn, qp->comp.psn) >= 0) // read response 的 middle 有 pkt psn, 但是还没有消耗一个完整的 wqe
				qp->comp.psn = (pkt->psn + 1) & BTH_PSN_MASK; // 需要更新 expected psn 了. 准确的说是 snd_una

			if (qp->req.wait_psn) { // post send 的时候由于 outstanding 限制, 导致当时 pause 了, 现在调度起来, ref: rxe_requester
				qp->req.wait_psn = 0;
				rxe_run_task(&qp->req.task, 1);
			}

			state = COMPST_DONE;
			break;

		case COMPST_DONE: // 这个 pkt 能处理的 wqe 已经结束了, skb 释放掉了. 如果需要 drop silently 也可以直接跳到这里
			if (pkt) {
				rxe_drop_ref(pkt->qp);
				kfree_skb(skb);
				skb = NULL;
			}
			goto done;

		case COMPST_EXIT: // 出问题了, 退出吧
			if (qp->comp.timeout_retry && wqe) {
				state = COMPST_ERROR_RETRY; // retry timer 触发的
				break;
			}

			/* re reset the timeout counter if
			 * (1) QP is type RC
			 * (2) the QP is alive
			 * (3) there is a packet sent by the requester that
			 *     might be acked (we still might get spurious
			 *     timeouts but try to keep them as few as possible)
			 * (4) the timeout parameter is set
			 */
			if ((qp_type(qp) == IB_QPT_RC) &&
			    (qp->req.state == QP_STATE_READY) &&
			    (psn_compare(qp->req.psn, qp->comp.psn) > 0) &&
			    qp->qp_timeout_jiffies)
				mod_timer(&qp->retrans_timer,
					  jiffies + qp->qp_timeout_jiffies);
			goto exit;

		case COMPST_ERROR_RETRY:
			/* we come here if the retry timer fired and we did
			 * not receive a response packet. try to retry the send
			 * queue if that makes sense and the limits have not
			 * been exceeded. remember that some timeouts are
			 * spurious since we do not reset the timer but kick
			 * it down the road or let it expire
			 */

			/* there is nothing to retry in this case */
			if (!wqe || (wqe->state == wqe_state_posted))
				goto exit;

			/* if we've started a retry, don't start another
			 * retry sequence, unless this is a timeout.
			 */
			if (qp->comp.started_retry &&
			    !qp->comp.timeout_retry) {
				if (pkt) {
					rxe_drop_ref(pkt->qp);
					kfree_skb(skb);
					skb = NULL;
				}

				goto done;
			}

			if (qp->comp.retry_cnt > 0) {
				if (qp->comp.retry_cnt != 7)
					qp->comp.retry_cnt--;

				/* no point in retrying if we have already
				 * seen the last ack that the requester could
				 * have caused
				 */
				if (psn_compare(qp->req.psn,
						qp->comp.psn) > 0) {
					/* tell the requester to retry the
					 * send queue next time around
					 */
					rxe_counter_inc(rxe,
							RXE_CNT_COMP_RETRY);
					qp->req.need_retry = 1;
					qp->comp.started_retry = 1;
					rxe_run_task(&qp->req.task, 0);
				}

				if (pkt) {
					rxe_drop_ref(pkt->qp);
					kfree_skb(skb);
					skb = NULL;
				}

				goto done;

			} else {
				rxe_counter_inc(rxe, RXE_CNT_RETRY_EXCEEDED);
				wqe->status = IB_WC_RETRY_EXC_ERR;
				state = COMPST_ERROR;
			}
			break;

		case COMPST_RNR_RETRY:
			if (qp->comp.rnr_retry > 0) {
				if (qp->comp.rnr_retry != 7)
					qp->comp.rnr_retry--;

				qp->req.need_retry = 1;
				pr_debug("qp#%d set rnr nak timer\n",
					 qp_num(qp));
				mod_timer(&qp->rnr_nak_timer,
					  jiffies + rnrnak_jiffies(aeth_syn(pkt)
						& ~AETH_TYPE_MASK));
				rxe_drop_ref(pkt->qp);
				kfree_skb(skb);
				skb = NULL;
				goto exit;
			} else {
				rxe_counter_inc(rxe,
						RXE_CNT_RNR_RETRY_EXCEEDED);
				wqe->status = IB_WC_RNR_RETRY_EXC_ERR;
				state = COMPST_ERROR;
			}
			break;

		case COMPST_ERROR: // 需要向上报告错误的
			WARN_ON_ONCE(wqe->status == IB_WC_SUCCESS);
			do_complete(qp, wqe);
			rxe_qp_error(qp);

			if (pkt) {
				rxe_drop_ref(pkt->qp);
				kfree_skb(skb);
				skb = NULL;
			}

			goto exit;
		}
	}

exit:
	/* we come here if we are done with processing and want the task to
	 * exit from the loop calling us
	 */
	WARN_ON_ONCE(skb);
	rxe_drop_ref(qp);
	return -EAGAIN;

done:
	/* we come here if we have processed a packet we want the task to call
	 * us again to see if there is anything else to do
	 */
	WARN_ON_ONCE(skb);
	rxe_drop_ref(qp);
	return 0;
}
