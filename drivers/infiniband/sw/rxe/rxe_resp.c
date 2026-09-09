// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"

enum resp_states {
	RESPST_NONE,
	RESPST_GET_REQ,
	RESPST_CHK_PSN,
	RESPST_CHK_OP_SEQ,
	RESPST_CHK_OP_VALID,
	RESPST_CHK_RESOURCE,
	RESPST_CHK_LENGTH,
	RESPST_CHK_RKEY,
	RESPST_EXECUTE,
	RESPST_READ_REPLY,
	RESPST_COMPLETE,
	RESPST_ACKNOWLEDGE,
	RESPST_CLEANUP,
	RESPST_DUPLICATE_REQUEST,
	RESPST_ERR_MALFORMED_WQE,
	RESPST_ERR_UNSUPPORTED_OPCODE,
	RESPST_ERR_MISALIGNED_ATOMIC,
	RESPST_ERR_PSN_OUT_OF_SEQ,
	RESPST_ERR_MISSING_OPCODE_FIRST,
	RESPST_ERR_MISSING_OPCODE_LAST_C,
	RESPST_ERR_MISSING_OPCODE_LAST_D1E,
	RESPST_ERR_TOO_MANY_RDMA_ATM_REQ, // 对端发过来的 outstanding atomic/read 太多了
	RESPST_ERR_RNR,                   // receive not ready
	RESPST_ERR_RKEY_VIOLATION,
	RESPST_ERR_LENGTH,
	RESPST_ERR_CQ_OVERFLOW,
	RESPST_ERROR,
	RESPST_RESET,
	RESPST_DONE,
	RESPST_EXIT,
};

static char *resp_state_name[] = {
	[RESPST_NONE]				= "NONE",
	[RESPST_GET_REQ]			= "GET_REQ",
	[RESPST_CHK_PSN]			= "CHK_PSN",
	[RESPST_CHK_OP_SEQ]			= "CHK_OP_SEQ",
	[RESPST_CHK_OP_VALID]			= "CHK_OP_VALID",
	[RESPST_CHK_RESOURCE]			= "CHK_RESOURCE",
	[RESPST_CHK_LENGTH]			= "CHK_LENGTH",
	[RESPST_CHK_RKEY]			= "CHK_RKEY",
	[RESPST_EXECUTE]			= "EXECUTE",
	[RESPST_READ_REPLY]			= "READ_REPLY",
	[RESPST_COMPLETE]			= "COMPLETE",
	[RESPST_ACKNOWLEDGE]			= "ACKNOWLEDGE",
	[RESPST_CLEANUP]			= "CLEANUP",
	[RESPST_DUPLICATE_REQUEST]		= "DUPLICATE_REQUEST",
	[RESPST_ERR_MALFORMED_WQE]		= "ERR_MALFORMED_WQE",
	[RESPST_ERR_UNSUPPORTED_OPCODE]		= "ERR_UNSUPPORTED_OPCODE",
	[RESPST_ERR_MISALIGNED_ATOMIC]		= "ERR_MISALIGNED_ATOMIC",
	[RESPST_ERR_PSN_OUT_OF_SEQ]		= "ERR_PSN_OUT_OF_SEQ",
	[RESPST_ERR_MISSING_OPCODE_FIRST]	= "ERR_MISSING_OPCODE_FIRST",
	[RESPST_ERR_MISSING_OPCODE_LAST_C]	= "ERR_MISSING_OPCODE_LAST_C",
	[RESPST_ERR_MISSING_OPCODE_LAST_D1E]	= "ERR_MISSING_OPCODE_LAST_D1E",
	[RESPST_ERR_TOO_MANY_RDMA_ATM_REQ]	= "ERR_TOO_MANY_RDMA_ATM_REQ",
	[RESPST_ERR_RNR]			= "ERR_RNR",
	[RESPST_ERR_RKEY_VIOLATION]		= "ERR_RKEY_VIOLATION",
	[RESPST_ERR_LENGTH]			= "ERR_LENGTH",
	[RESPST_ERR_CQ_OVERFLOW]		= "ERR_CQ_OVERFLOW",
	[RESPST_ERROR]				= "ERROR",
	[RESPST_RESET]				= "RESET",
	[RESPST_DONE]				= "DONE",
	[RESPST_EXIT]				= "EXIT",
};

/* rxe_recv calls here to add a request packet to the input queue */
void rxe_resp_queue_pkt(struct rxe_qp *qp, struct sk_buff *skb)
{
	int must_sched;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);

	// skb 挂到 req_pkts 里等待 rxe_responder 处理
	skb_queue_tail(&qp->req_pkts, skb);

	// XXX: 这种情况下工作量大, 所以要让 tasklet 去调度来处理, 而不是直接处理 (???)
	must_sched = (pkt->opcode == IB_OPCODE_RC_RDMA_READ_REQUEST) ||
			(skb_queue_len(&qp->req_pkts) > 1);

	// rxe_responder
	rxe_run_task(&qp->resp.task, must_sched);
}

static inline enum resp_states get_req(struct rxe_qp *qp,
				       struct rxe_pkt_info **pkt_p)
{
	struct sk_buff *skb;

	// 检查 qp 状态
	if (qp->resp.state == QP_STATE_ERROR) { // ref: rxe_qp_error()
		while ((skb = skb_dequeue(&qp->req_pkts))) {
			rxe_drop_ref(qp);
			kfree_skb(skb);
		}

		/* go drain recv wr queue */
		return RESPST_CHK_RESOURCE;
	}

	// 取报文下来 和 rxe_pkt_info 信息
	// 这里仅仅是 peek, 并没有取下来
	skb = skb_peek(&qp->req_pkts);
	if (!skb) // 会一直处理, 知道 req_pkts 被处理完
		return RESPST_EXIT;

	// rxe_rcv 的时候提取的
	*pkt_p = SKB_TO_PKT(skb);

	// 空是常态. 
	// 否则应该是 replay the rdma read reply 情况, ref: duplicate_request
	// ref: read_reply() 处理 multi-pkt read req 的时候, read_reply() 发一
	// 个 pkt 后就退出了, 但是会设置 resp.res 的
	return (qp->resp.res) ? RESPST_READ_REPLY : RESPST_CHK_PSN;
}

/* responder 看来 psn 分成三部分
 * - *dup*: [ ePSN-(2^23-1), ePSN )
 *   - send/write 的 dup 要调度一个 ack pkt
 *   - read 的 dup 要重新执行
 *   - atomic 的 dup 回复 ack, 但是不能重新执行
 *
 * - *expectPSN*
 *   - 进一步校验 opcode
 *
 * - *invalid*: ( ePSN, ePSN+2^23 ]
 *   - 回复: NAK:seq-error
 */
static enum resp_states check_psn(struct rxe_qp *qp,
				  struct rxe_pkt_info *pkt)
{
	int diff = psn_compare(pkt->psn, qp->resp.psn);
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (diff > 0) { // psn > ePSN, invalid pkt
			if (qp->resp.sent_psn_nak) // 已经发送过了 psn nak
				return RESPST_CLEANUP;

			qp->resp.sent_psn_nak = 1;
			rxe_counter_inc(rxe, RXE_CNT_OUT_OF_SEQ_REQ);
			return RESPST_ERR_PSN_OUT_OF_SEQ;

		} else if (diff < 0) { // dup req
			rxe_counter_inc(rxe, RXE_CNT_DUP_REQ);
			return RESPST_DUPLICATE_REQUEST;
		}

		// 正好是 ePSN, 可以退出一些异常状态了
		if (qp->resp.sent_psn_nak)
			qp->resp.sent_psn_nak = 0;

		break;

	case IB_QPT_UC:
		if (qp->resp.drop_msg || diff != 0) {
			if (pkt->mask & RXE_START_MASK) {
				qp->resp.drop_msg = 0;
				return RESPST_CHK_OP_SEQ;
			}

			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}
		break;
	default:
		break;
	}

	return RESPST_CHK_OP_SEQ;
}

// 检查 opcode 合法性
/* 两种错误:
 * - RESPST_ERR_MISSING_OPCODE_LAST_C, 缺尾
 * - RESPST_ERR_MISSING_OPCODE_FIRST,  缺头
 * */
static enum resp_states check_op_seq(struct rxe_qp *qp,
				     struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
		switch (qp->resp.opcode) {
		case IB_OPCODE_RC_SEND_FIRST:
		case IB_OPCODE_RC_SEND_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_SEND_MIDDLE:
			case IB_OPCODE_RC_SEND_LAST:
			case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_C;
			}

		case IB_OPCODE_RC_RDMA_WRITE_FIRST:
		case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_RC_RDMA_WRITE_LAST:
			case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_C;
			}

		default:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_SEND_MIDDLE:
			case IB_OPCODE_RC_SEND_LAST:
			case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
			case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_RC_RDMA_WRITE_LAST:
			case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_ERR_MISSING_OPCODE_FIRST;
			default:
				return RESPST_CHK_OP_VALID;
			}
		}
		break;

	case IB_QPT_UC:
		switch (qp->resp.opcode) {
		case IB_OPCODE_UC_SEND_FIRST:
		case IB_OPCODE_UC_SEND_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_SEND_MIDDLE:
			case IB_OPCODE_UC_SEND_LAST:
			case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
			}

		case IB_OPCODE_UC_RDMA_WRITE_FIRST:
		case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_UC_RDMA_WRITE_LAST:
			case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
			}

		default:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_SEND_MIDDLE:
			case IB_OPCODE_UC_SEND_LAST:
			case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_UC_RDMA_WRITE_LAST:
			case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				qp->resp.drop_msg = 1;
				return RESPST_CLEANUP;
			default:
				return RESPST_CHK_OP_VALID;
			}
		}
		break;

	default:
		return RESPST_CHK_OP_VALID;
	}
}

// 检查 opcode 合法性, 主要看看qp 是否支持对应的操作
static enum resp_states check_op_valid(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (((pkt->mask & RXE_READ_MASK) &&
		     !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_READ)) ||
		    ((pkt->mask & RXE_WRITE_MASK) &&
		     !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_WRITE)) ||
		    ((pkt->mask & RXE_ATOMIC_MASK) &&
		     !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_ATOMIC))) {
			return RESPST_ERR_UNSUPPORTED_OPCODE;
		}

		break;

	case IB_QPT_UC:
		if ((pkt->mask & RXE_WRITE_MASK) &&
		    !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_WRITE)) {
			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}

		break;

	case IB_QPT_UD:
	case IB_QPT_SMI:
	case IB_QPT_GSI:
		break;

	default:
		WARN_ON_ONCE(1);
		break;
	}

	return RESPST_CHK_RESOURCE;
}

static enum resp_states get_srq_wqe(struct rxe_qp *qp)
{
	struct rxe_srq *srq = qp->srq;
	struct rxe_queue *q = srq->rq.queue;
	struct rxe_recv_wqe *wqe;
	struct ib_event ev;

	if (srq->error)
		return RESPST_ERR_RNR;

	spin_lock_bh(&srq->rq.consumer_lock);

	wqe = queue_head(q);
	if (!wqe) {
		spin_unlock_bh(&srq->rq.consumer_lock);
		return RESPST_ERR_RNR;
	}

	/* note kernel and user space recv wqes have same size */
	memcpy(&qp->resp.srq_wqe, wqe, sizeof(qp->resp.srq_wqe));

	qp->resp.wqe = &qp->resp.srq_wqe.wqe;
	advance_consumer(q);

	if (srq->limit && srq->ibsrq.event_handler &&
	    (queue_count(q) < srq->limit)) { // rq 里的 wqe 数量小于 limit 了, 需要通知用户空间了, 设置为 0 避免重复通知
		srq->limit = 0;
		goto event;
	}

	spin_unlock_bh(&srq->rq.consumer_lock);
	return RESPST_CHK_LENGTH;

event:
	spin_unlock_bh(&srq->rq.consumer_lock);
	ev.device = qp->ibqp.device;
	ev.element.srq = qp->ibqp.srq;
	ev.event = IB_EVENT_SRQ_LIMIT_REACHED;
	srq->ibsrq.event_handler(&ev, srq->ibsrq.srq_context);
	return RESPST_CHK_LENGTH;
}

// 检测资源是否可用: 
// - qp 状态是否正确
// - 如果是 read/atomic req, 是否没有超量
// - send: rq wqe 有没有, 若没有 -> RNR
static enum resp_states check_resource(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	struct rxe_srq *srq = qp->srq;

	if (qp->resp.state == QP_STATE_ERROR) { // 已经是错误状态了, 这里顺便做错误处理
		if (qp->resp.wqe) { // 有正在处理的 rq 的 wqe, 说明还可以通过 wqe 来上报错误
			qp->resp.status = IB_WC_WR_FLUSH_ERR;
			return RESPST_COMPLETE;
		} else if (!srq) {  // 尝试否则取一个 wqe 来上报错误
			qp->resp.wqe = queue_head(qp->rq.queue);
			if (qp->resp.wqe) {
				qp->resp.status = IB_WC_WR_FLUSH_ERR;
				return RESPST_COMPLETE;
			} else { // 没有 wqe 可以上报错误了
				return RESPST_EXIT;
			}
		} else {
			return RESPST_EXIT;  // 是 srq 的话, 资源不再 qp 这里, 直接退出, 让 srq 去处理
		}
	}

	if (pkt->mask & RXE_READ_OR_ATOMIC) {
		/* it is the requesters job to not send
		 * too many read/atomic ops, we just
		 * recycle the responder resource queue
		 *
		 * XXX: 硬件实现的时候不能这么干的.
		 */
		if (likely(qp->attr.max_dest_rd_atomic > 0))
			return RESPST_CHK_LENGTH;
		else
			return RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
	}

	if (pkt->mask & RXE_RWR_MASK) { // 普通 send
		if (srq)
			return get_srq_wqe(qp); // 从 srq 里取 wqe, srq 是不一样的, 会直接 advance 的

		// 这里仅仅拿了位置, 还没有 advance_consumer, ref: do_complete()
		qp->resp.wqe = queue_head(qp->rq.queue);
		return (qp->resp.wqe) ? RESPST_CHK_LENGTH : RESPST_ERR_RNR;
	}

	return RESPST_CHK_LENGTH;
}

// dummy func, 还没有实现
// - 对于 send req, recv 的 wqe 可以存放下去
// - 对于 write 操作, 要 dma 的范围要合法
// - 另外还要根据 opcode 检查 payload 和 pmtu 的关系
static enum resp_states check_length(struct rxe_qp *qp,
				     struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
		return RESPST_CHK_RKEY;

	case IB_QPT_UC:
		return RESPST_CHK_RKEY;

	default:
		return RESPST_CHK_RKEY;
	}
}

// 检查 rkey 了, read/write/atomic 操作需要
static enum resp_states check_rkey(struct rxe_qp *qp,
				   struct rxe_pkt_info *pkt)
{
	struct rxe_mem *mem = NULL;
	u64 va;
	u32 rkey;
	u32 resid;
	u32 pktlen;
	int mtu = qp->mtu;
	enum resp_states state;
	int access;

	if (pkt->mask & (RXE_READ_MASK | RXE_WRITE_MASK)) {
		if (pkt->mask & RXE_RETH_MASK) {
			qp->resp.va = reth_va(pkt); // 从 pkt 里提取: va/rkey,length 信息
			qp->resp.rkey = reth_rkey(pkt);
			qp->resp.resid = reth_len(pkt);
			qp->resp.length = reth_len(pkt);
		}
		access = (pkt->mask & RXE_READ_MASK) ? IB_ACCESS_REMOTE_READ
						     : IB_ACCESS_REMOTE_WRITE;
	} else if (pkt->mask & RXE_ATOMIC_MASK) {
		qp->resp.va = atmeth_va(pkt);
		qp->resp.rkey = atmeth_rkey(pkt);
		qp->resp.resid = sizeof(u64);
		access = IB_ACCESS_REMOTE_ATOMIC;
	} else {
		return RESPST_EXECUTE;
	}

	/* A zero-byte op is not required to set an addr or rkey. */
	// 长度为 0 的 read/write/send 请求被看作 nop 指令
	// ref: rdma spec c9-88
	if ((pkt->mask & (RXE_READ_MASK | RXE_WRITE_OR_SEND)) &&
	    (pkt->mask & RXE_RETH_MASK) &&
	    reth_len(pkt) == 0) {
		return RESPST_EXECUTE;
	}

	//
	// 利用提取的信息查找 mr, 并检查权限
	va	= qp->resp.va;
	rkey	= qp->resp.rkey;
	resid	= qp->resp.resid;
	pktlen	= payload_size(pkt);

	// 去注册的 mr 里寻找: pd + rkey 信息
	// lookup 里已经增加了 mem 的引用计数了
	mem = lookup_mem(qp->pd, access, rkey, lookup_remote);
	if (!mem) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

	if (unlikely(mem->state == RXE_MEM_STATE_FREE)) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

	if (mem_check_range(mem, va, resid)) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

	// write 操作, 每个 包的 pkt 长度和 mtu 要做比较的
	if (pkt->mask & RXE_WRITE_MASK)	 {
		if (resid > mtu) {
			if (pktlen != mtu || bth_pad(pkt)) {
				state = RESPST_ERR_LENGTH;
				goto err;
			}
		} else {
			if (pktlen != resid) {
				state = RESPST_ERR_LENGTH;
				goto err;
			}
			if ((bth_pad(pkt) != (0x3 & (-resid)))) {
				/* This case may not be exactly that
				 * but nothing else fits.
				 */
				state = RESPST_ERR_LENGTH;
				goto err;
			}
		}
	}

	WARN_ON_ONCE(qp->resp.mr);

	// 记录下当前正要被用的 mr
	// lookup 里已经增加了 mem 的引用计数了
	qp->resp.mr = mem;
	return RESPST_EXECUTE;

err:
	if (mem)
		rxe_drop_ref(mem);
	return state;
}

static enum resp_states send_data_in(struct rxe_qp *qp, void *data_addr,
				     int data_len)
{
	int err;

	// data_addr -> dma sge
	err = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE, &qp->resp.wqe->dma,
			data_addr, data_len, to_mem_obj, NULL);
	if (unlikely(err))
		return (err == -ENOSPC) ? RESPST_ERR_LENGTH
					: RESPST_ERR_MALFORMED_WQE;

	return RESPST_NONE;
}

static enum resp_states write_data_in(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt)
{
	enum resp_states rc = RESPST_NONE;
	int	err;
	int data_len = payload_size(pkt);

	err = rxe_mem_copy(qp->resp.mr, qp->resp.va, payload_addr(pkt),
			   data_len, to_mem_obj, NULL);
	if (err) {
		rc = RESPST_ERR_RKEY_VIOLATION;
		goto out;
	}

	qp->resp.va += data_len;
	qp->resp.resid -= data_len;

out:
	return rc;
}

/* Guarantee atomicity of atomic operations at the machine level. */
// 全局锁实现 softroce global 粒度的原子操作
static DEFINE_SPINLOCK(atomic_ops_lock);

static enum resp_states process_atomic(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	u64 iova = atmeth_va(pkt);
	u64 *vaddr;
	enum resp_states ret;
	struct rxe_mem *mr = qp->resp.mr;

	if (mr->state != RXE_MEM_STATE_VALID) {
		ret = RESPST_ERR_RKEY_VIOLATION;
		goto out;
	}

	vaddr = iova_to_vaddr(mr, iova, sizeof(u64));

	/* check vaddr is 8 bytes aligned. */
	if (!vaddr || (uintptr_t)vaddr & 7) {
		ret = RESPST_ERR_MISALIGNED_ATOMIC;
		goto out;
	}

	spin_lock_bh(&atomic_ops_lock);

	qp->resp.atomic_orig = *vaddr;

	if (pkt->opcode == IB_OPCODE_RC_COMPARE_SWAP ||
	    pkt->opcode == IB_OPCODE_RD_COMPARE_SWAP) {
		if (*vaddr == atmeth_comp(pkt))
			*vaddr = atmeth_swap_add(pkt);
	} else {
		*vaddr += atmeth_swap_add(pkt);
	}

	spin_unlock_bh(&atomic_ops_lock);

	ret = RESPST_NONE;
out:
	return ret;
}

static struct sk_buff *prepare_ack_packet(struct rxe_qp *qp,
					  struct rxe_pkt_info *pkt,
					  struct rxe_pkt_info *ack,
					  int opcode,
					  int payload,
					  u32 psn,
					  u8 syndrome,
					  u32 *crcp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct sk_buff *skb;
	u32 crc = 0;
	u32 *p;
	int paylen;
	int pad;
	int err;

	/*
	 * allocate packet
	 */
	pad = (-payload) & 0x3; // 补齐到 4B
	paylen = rxe_opcode[opcode].length + payload + pad + RXE_ICRC_SIZE;

	skb = rxe_init_packet(rxe, &qp->pri_av, paylen, ack);
	if (!skb)
		return NULL;

	ack->qp = qp;
	ack->opcode = opcode;
	ack->mask = rxe_opcode[opcode].mask;
	ack->offset = pkt->offset;
	ack->paylen = paylen;

	/* fill in bth using the request packet headers */
	memcpy(ack->hdr, pkt->hdr, pkt->offset + RXE_BTH_BYTES);

	bth_set_opcode(ack, opcode);
	bth_set_qpn(ack, qp->attr.dest_qp_num);
	bth_set_pad(ack, pad);
	bth_set_se(ack, 0);
	bth_set_psn(ack, psn);
	bth_set_ack(ack, 0);
	ack->psn = psn;

	if (ack->mask & RXE_AETH_MASK) {
		aeth_set_syn(ack, syndrome);
		aeth_set_msn(ack, qp->resp.msn);
	}

	if (ack->mask & RXE_ATMACK_MASK)
		atmack_set_orig(ack, qp->resp.atomic_orig);

	err = rxe_prepare(ack, skb, &crc);
	if (err) {
		kfree_skb(skb);
		return NULL;
	}

	if (crcp) {
		/* CRC computation will be continued by the caller */
		*crcp = crc;
	} else {
		p = payload_addr(ack) + payload + bth_pad(ack);
		*p = ~crc;
	}

	return skb;
}

/* RDMA read response. If res is not NULL, then we have a current RDMA request
 * being processed or replayed.
 *
 * 读数据, 发送 read response 包.
 *
 * read 的 retry 也是走这里去回复 reply 的. ref: duplicate_request
 */
static enum resp_states read_reply(struct rxe_qp *qp,
				   struct rxe_pkt_info *req_pkt)
{
	struct rxe_pkt_info ack_pkt;
	struct sk_buff *skb;
	int mtu = qp->mtu;
	enum resp_states state;
	int payload;
	int opcode;
	int err;
	struct resp_res *res = qp->resp.res;
	u32 icrc;
	u32 *p;

	if (!res) { // ref: duplicate_request() 说明这不是 read 的重传, 也不是一个正在处理的 read 请求
		/* This is the first time we process that request. Get a
		 * resource
		 */
		// 分配一个空闲的 resource 来保存 read 的一些信息, 以应付 retry. 这里是循环覆盖的
		// ref: find_resource()
		res = &qp->resp.resources[qp->resp.res_head];

		// 要覆盖这个 resource 了, 将一些老的关联的资源释放掉
		free_rd_atomic_resource(qp, res);
		rxe_advance_resp_resource(qp);

		res->type		= RXE_READ_MASK;
		res->replay		= 0;

		// 记录下 va 信息
		res->read.va		= qp->resp.va; // 在构造报文的时候会向前移动的
		res->read.va_org	= qp->resp.va; // va original

		res->first_psn		= req_pkt->psn; // read 的 psn 必须和 req 一一对应的

		if (reth_len(req_pkt)) {
			res->last_psn	= (req_pkt->psn +
					   (reth_len(req_pkt) + mtu - 1) /
					   mtu - 1) & BTH_PSN_MASK;
		} else { // 0 长度 read 的处理
			res->last_psn	= res->first_psn;
		}
		res->cur_psn		= req_pkt->psn;

		res->read.resid		= qp->resp.resid;
		res->read.length	= qp->resp.resid;
		res->read.rkey		= qp->resp.rkey;

		/* note res inherits the reference to mr from qp 
		 * 因为是从 resp.mr 里直接拿过来的, 所以不需要增加引用计数
		 * */
		res->read.mr		= qp->resp.mr;
		qp->resp.mr		= NULL;

		qp->resp.res		= res;
		res->state		= rdatm_res_state_new;
	}

	if (res->state == rdatm_res_state_new) {
		if (res->read.resid <= mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
	} else { // 这条路径怎么进来的 ?
		if (res->read.resid > mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST;
	}

	res->state = rdatm_res_state_next;

	payload = min_t(int, res->read.resid, mtu);

	skb = prepare_ack_packet(qp, req_pkt, &ack_pkt, opcode, payload,
				 res->cur_psn, AETH_ACK_UNLIMITED, &icrc);
	if (!skb)
		return RESPST_ERR_RNR;

	// mem -> payload 里
	err = rxe_mem_copy(res->read.mr, res->read.va, payload_addr(&ack_pkt),
			   payload, from_mem_obj, &icrc);
	if (err)
		pr_err("Failed copying memory\n");

	if (bth_pad(&ack_pkt)) {
		struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
		u8 *pad = payload_addr(&ack_pkt) + payload;

		memset(pad, 0, bth_pad(&ack_pkt));
		icrc = rxe_crc32(rxe, icrc, pad, bth_pad(&ack_pkt));
	}
	p = payload_addr(&ack_pkt) + payload + bth_pad(&ack_pkt);
	*p = ~icrc;

	err = rxe_xmit_packet(qp, &ack_pkt, skb);
	if (err) {
		pr_err("Failed sending RDMA reply.\n");
		return RESPST_ERR_RNR;
	}

	res->read.va += payload;
	res->read.resid -= payload;
	res->cur_psn = (res->cur_psn + 1) & BTH_PSN_MASK;

	if (res->read.resid > 0) { // read req 需要的 reply 还没有发完, 为什么不继续发了? 还有什么路径会调度过来么? 会的, ref: comments on rxe_do_task()
		state = RESPST_DONE;
	} else { // 说明发完了
		qp->resp.res = NULL;
		/* 如果是 read 的重传, 这里不能 reset opcode 的
		 * 考虑下述 case:
		 * - 首先 resp 收到: read req psn: 20, 21, 22, write req psn: 23
		 *   - resp.psn = 24
		 *   - resp.opcode = wirte first
		 *
		 * - 然后 req 重传 read req psn: 20, 21, 22
		 *
		 * - resp 收到 dup read req, 然后重传
		 *   - resp.psn = 24
		 *   - resp.opcode = -1. 如果这里无条件设置的话
		 *
		 *
		 * 那么后续的 write seq 到来的时候, 使用这个 opcode 去判断合法性就会出问题的
		 * */
		if (!res->replay) 
			qp->resp.opcode = -1;
		if (psn_compare(res->cur_psn, qp->resp.psn) >= 0)
			qp->resp.psn = res->cur_psn; // 更新 ePSN 了
		state = RESPST_CLEANUP;
	}

	return state;
}

static void build_rdma_network_hdr(union rdma_network_hdr *hdr,
				   struct rxe_pkt_info *pkt)
{
	struct sk_buff *skb = PKT_TO_SKB(pkt);

	memset(hdr, 0, sizeof(*hdr));
	if (skb->protocol == htons(ETH_P_IP))
		memcpy(&hdr->roce4grh, ip_hdr(skb), sizeof(hdr->roce4grh));
	else if (skb->protocol == htons(ETH_P_IPV6))
		memcpy(&hdr->ibgrh, ipv6_hdr(skb), sizeof(hdr->ibgrh));
}

/* Executes a new request. A retried request never reach that function (send
 * and writes are discarded, and reads and atomics are retried elsewhere.
 *
 * 执行外部请求. 当然 read 其实不是在这里执行的. rdma 里 read 是 relaxed order 的
 */
static enum resp_states execute(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	enum resp_states err;

	// 执行
	if (pkt->mask & RXE_SEND_MASK) {
		if (qp_type(qp) == IB_QPT_UD ||
		    qp_type(qp) == IB_QPT_SMI ||
		    qp_type(qp) == IB_QPT_GSI) {
			union rdma_network_hdr hdr;

			// UD 其 buffer 里要保存网络头信息的, 提取地址信息, ref: 1.4 vol1 ch11.4.1.2
			build_rdma_network_hdr(&hdr, pkt);

			err = send_data_in(qp, &hdr, sizeof(hdr));
			if (err)
				return err;
		}
		// 再把 payload dma 到 rq wqe 的 buffer 里
		err = send_data_in(qp, payload_addr(pkt), payload_size(pkt));
		if (err)
			return err;
	} else if (pkt->mask & RXE_WRITE_MASK) {
		err = write_data_in(qp, pkt);
		if (err)
			return err;
	} else if (pkt->mask & RXE_READ_MASK) { // read 操作可以直接增加 msn 了
		/* For RDMA Read we can increment the msn now. See C9-148. */
		qp->resp.msn++;
		return RESPST_READ_REPLY; // read 直接从这里出去了
	} else if (pkt->mask & RXE_ATOMIC_MASK) {
		err = process_atomic(qp, pkt);
		if (err)
			return err;
	} else {
		/* Unreachable */
		WARN_ON_ONCE(1);
	}

	// 执行后更新 resp 等信息
	// read req 的处理走不到这里的, 其他 req 的 resp 都是单个包的
	/* next expected psn, read handles this separately */
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn; // 注意前面一行 ++ 了

	qp->resp.opcode = pkt->opcode;
	qp->resp.status = IB_WC_SUCCESS;

	// send_last, send_only, write_last_with_imm, write_only_with_imm
	if (pkt->mask & RXE_COMP_MASK) {
		/* We successfully processed this new request. See C9-148 */
		qp->resp.msn++;
		return RESPST_COMPLETE; // 需要产生 completion 的
	} else if (qp_type(qp) == IB_QPT_RC)
		return RESPST_ACKNOWLEDGE; // 暂时还不需要产生 completion, 但是可能需要回复 ack 包. 
	else
		return RESPST_CLEANUP;
}

// 利用已有的信息回复 completion 了, 当然可能还要通知用户
// send,write_with_imm 可能要产生 completion
//
// 出错后产生的 completion 也是走这里的, ref: do_class_ac_error()
static enum resp_states do_complete(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt)
{
	struct rxe_cqe cqe;
	struct ib_wc *wc = &cqe.ibwc;
	struct ib_uverbs_wc *uwc = &cqe.uibwc;
	struct rxe_recv_wqe *wqe = qp->resp.wqe; // 为这个 wqe 回复 completion, 从 rq 或者 srq 里取出来的
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	if (unlikely(!wqe))
		return RESPST_CLEANUP;

	memset(&cqe, 0, sizeof(cqe));

	if (qp->rcq->is_user) {
		uwc->status             = qp->resp.status;
		uwc->qp_num             = qp->ibqp.qp_num;
		uwc->wr_id              = wqe->wr_id;
	} else {
		wc->status              = qp->resp.status;
		wc->qp                  = &qp->ibqp;
		wc->wr_id               = wqe->wr_id;
	}

	if (wc->status == IB_WC_SUCCESS) {
		rxe_counter_inc(rxe, RXE_CNT_RDMA_RECV);
		wc->opcode = (pkt->mask & RXE_IMMDT_MASK &&
				pkt->mask & RXE_WRITE_MASK) ?
					IB_WC_RECV_RDMA_WITH_IMM : IB_WC_RECV;
		wc->vendor_err = 0;
		wc->byte_len = (pkt->mask & RXE_IMMDT_MASK &&
				pkt->mask & RXE_WRITE_MASK) ?
					qp->resp.length : wqe->dma.length - wqe->dma.resid;

		/* fields after byte_len are different between kernel and user
		 * space
		 */
		if (qp->rcq->is_user) {
			uwc->wc_flags = IB_WC_GRH;

			if (pkt->mask & RXE_IMMDT_MASK) {
				uwc->wc_flags |= IB_WC_WITH_IMM;
				uwc->ex.imm_data = immdt_imm(pkt);
			}

			if (pkt->mask & RXE_IETH_MASK) {
				uwc->wc_flags |= IB_WC_WITH_INVALIDATE;
				uwc->ex.invalidate_rkey = ieth_rkey(pkt);
			}

			uwc->qp_num		= qp->ibqp.qp_num;

			if (pkt->mask & RXE_DETH_MASK)
				uwc->src_qp = deth_sqp(pkt);

			uwc->port_num		= qp->attr.port_num;
		} else {
			struct sk_buff *skb = PKT_TO_SKB(pkt);

			wc->wc_flags = IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE;
			if (skb->protocol == htons(ETH_P_IP))
				wc->network_hdr_type = RDMA_NETWORK_IPV4;
			else
				wc->network_hdr_type = RDMA_NETWORK_IPV6;

			if (is_vlan_dev(skb->dev)) { // 提取 vlan id
				wc->wc_flags |= IB_WC_WITH_VLAN;
				wc->vlan_id = vlan_dev_vlan_id(skb->dev);
			}

			if (pkt->mask & RXE_IMMDT_MASK) { // 提取 immData
				wc->wc_flags |= IB_WC_WITH_IMM;
				wc->ex.imm_data = immdt_imm(pkt);
			}

			if (pkt->mask & RXE_IETH_MASK) { // 说明带有 invalidate 的
				struct rxe_mem *rmr;

				wc->wc_flags |= IB_WC_WITH_INVALIDATE;
				wc->ex.invalidate_rkey = ieth_rkey(pkt);

				rmr = rxe_pool_get_index(&rxe->mr_pool,
							 wc->ex.invalidate_rkey >> 8);
				if (unlikely(!rmr)) {
					pr_err("Bad rkey %#x invalidation\n",
					       wc->ex.invalidate_rkey);
					return RESPST_ERROR;
				}
				rmr->state = RXE_MEM_STATE_FREE;
				rxe_drop_ref(rmr);
			}

			wc->qp			= &qp->ibqp;

			if (pkt->mask & RXE_DETH_MASK)
				wc->src_qp = deth_sqp(pkt);

			wc->port_num		= qp->attr.port_num;
		}
	}

	/* have copy for srq and reference for !srq */
	if (!qp->srq)
		advance_consumer(qp->rq.queue); // ref: check_resource()

	// 这个 wqe 被用掉了, 如果前面出错直接返回了, 这个 wqe 就不会被用掉
	qp->resp.wqe = NULL;

	// XXX: cq 是反过来的, 硬件 post, app 消费
	if (rxe_cq_post(qp->rcq, &cqe, pkt ? bth_se(pkt) : 1)) // cq_post 里已经将 cq overflow 直接通知到上层了
		return RESPST_ERR_CQ_OVERFLOW;

	// 说明产生 completion 的时候出错了, 但是已经 post cqe 咯
	// (为什么又去 check 一把??? 主要让其去做错误处理, 释放资源)
	if (qp->resp.state == QP_STATE_ERROR)
		return RESPST_CHK_RESOURCE;

	if (!pkt)
		return RESPST_DONE;
	else if (qp_type(qp) == IB_QPT_RC)
		return RESPST_ACKNOWLEDGE; // 没有问题,  completion 产生了, 回复 ack 包去
	else
		return RESPST_CLEANUP;
}

/* 关于 response 回复的 pkt 里的的 BTH:PSN
 * 1. ref: acknowledge
 *   - 大部分 nak 使用触发 nak 的 pkt:psn 来回复
 *   - pure ack 使用最新的 psn 来回复
 *
 * 2. ref: rxe_responder()::case RESPST_ERR_PSN_OUT_OF_SEQ:
 *   - NAK:sequence-error 的 NAK 是 ePSN 来回复的
 *
 * 3. ref: rxe_responder()::case RESPST_ERR_RNR:
 *   - 也用的是当前 pkt 的 psn
 *
 * 在 softroce 的实现里, 针对 NAK:Seq-Err 统一用 ePSN.
 * 其他的都用对应的 pkt->psn. ref: acknowledge()
 *
 *
 * 考虑到 NAK:Seq-err 是最先检测的. 所以如果返回的是其他 NAK:Code, 也就说明触发
 * 该 NAK 的 pkt 其 psn 不是 dup pkt, 也不是 invalid pkt. 那么该 pkt 就是 ePSN
 * 了. 换句话说, 所有的 NAK pkt 的 BTH:PSN 都可以认为是 ePSN
 * */
static int send_ack(struct rxe_qp *qp, struct rxe_pkt_info *pkt,
		    u8 syndrome, u32 psn)
{
	int err = 0;
	struct rxe_pkt_info ack_pkt;
	struct sk_buff *skb;

	skb = prepare_ack_packet(qp, pkt, &ack_pkt, IB_OPCODE_RC_ACKNOWLEDGE,
				 0, psn, syndrome, NULL);
	if (!skb) {
		err = -ENOMEM;
		goto err1;
	}

	err = rxe_xmit_packet(qp, &ack_pkt, skb);
	if (err)
		pr_err_ratelimited("Failed sending ack\n");

err1:
	return err;
}

static int send_atomic_ack(struct rxe_qp *qp, struct rxe_pkt_info *pkt,
			   u8 syndrome)
{
	int rc = 0;
	struct rxe_pkt_info ack_pkt;
	struct sk_buff *skb;
	struct resp_res *res;

	skb = prepare_ack_packet(qp, pkt, &ack_pkt,
				 IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE, 0, pkt->psn,
				 syndrome, NULL);
	if (!skb) {
		rc = -ENOMEM;
		goto out;
	}

	rxe_add_ref(qp);

	res = &qp->resp.resources[qp->resp.res_head]; // 这里要复用资源的, 所以之前 resource 关联的 skb 要释放掉
	free_rd_atomic_resource(qp, res);
	rxe_advance_resp_resource(qp);

	memcpy(SKB_TO_PKT(skb), &ack_pkt, sizeof(ack_pkt));
	memset((unsigned char *)SKB_TO_PKT(skb) + sizeof(ack_pkt), 0,
	       sizeof(skb->cb) - sizeof(ack_pkt));

	skb_get(skb);
	res->type = RXE_ATOMIC_MASK;
	res->atomic.skb = skb;
	res->first_psn = ack_pkt.psn;
	res->last_psn  = ack_pkt.psn;
	res->cur_psn   = ack_pkt.psn;

	rc = rxe_xmit_packet(qp, &ack_pkt, skb);
	if (rc) {
		pr_err_ratelimited("Failed sending ack\n");
		rxe_drop_ref(qp); // 和前面的 rxe_add_ref 配对, 发送失败立即释放
	}
out:
	return rc; // 发送成功和 free_rd_atomic_resource 配对.
}

/* ack / nak / atomic response 走这里
 * read response 走 read_reply()
 * */
static enum resp_states acknowledge(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt)
{
	if (qp_type(qp) != IB_QPT_RC)
		return RESPST_CLEANUP;

	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED) // 说明有 nak 要回复
		send_ack(qp, pkt, qp->resp.aeth_syndrome, pkt->psn); // ref: send_ack()
	else if (pkt->mask & RXE_ATOMIC_MASK)
		send_atomic_ack(qp, pkt, AETH_ACK_UNLIMITED);
	else if (bth_ack(pkt)) // 必须对方有请求 ack 我们才回复的
		send_ack(qp, pkt, AETH_ACK_UNLIMITED, pkt->psn);      // 这个包要求我们回 ack, 当然现在最新的 psn 就是这个 pkt 的 psn 了

	return RESPST_CLEANUP;
}

// 释放必要的引用计数咯, 这里是 drop silently 么
// 这个 pkt 已经被榨干了
static enum resp_states cleanup(struct rxe_qp *qp,
				struct rxe_pkt_info *pkt)
{
	struct sk_buff *skb;

	if (pkt) {
		skb = skb_dequeue(&qp->req_pkts);
		rxe_drop_ref(qp);
		kfree_skb(skb);
	}

	// 将当前引用的 mr 释放掉
	if (qp->resp.mr) {
		rxe_drop_ref(qp->resp.mr);
		qp->resp.mr = NULL;
	}

	return RESPST_DONE;
}

static struct resp_res *find_resource(struct rxe_qp *qp, u32 psn)
{
	int i;

	// 从 responder 的角度来说, 需要根据 qp 支持的 max read atomic 来保留一些信息
	// 应付 atomic / read 的重传. 特别是 atomic 这种不能重新执行的
	for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
		struct resp_res *res = &qp->resp.resources[i];

		if (res->type == 0)
			continue;

		if (psn_compare(psn, res->first_psn) >= 0 &&
		    psn_compare(psn, res->last_psn) <= 0) {
			return res;
		}
	}

	return NULL;
}

// 只要看到 duplicate 了, 就认为发生了丢包, 无条件重做最早没有被 ack 的 pkt
// 没有选择重传的
static enum resp_states duplicate_request(struct rxe_qp *qp,
					  struct rxe_pkt_info *pkt)
{
	enum resp_states rc;
	/* XXX:
	 *
	 * ref: execute() read_reply() ack_psn 不一定是 ePSN 的, ref: execute()
	 * 对于 read 操作的处理的时候 ePSN 在增长, 但是 ack_psn 没有增长的, 这
	 * 里为 read/write 回复 dup req 的时候, 不能用 ePSN - 1. 考虑下述
	 * corner case:
         *  - resp 收到: write-req(30), 然后发送 ack(30)
         *    - ePSN = 31
         *  - resp 收到: read-req(31)
         *    - ePSN = 32
         *  - resp 收到了 req 重传的 write-req(30)
         *    - 此时如果用 ePSN-1 来回复, 就会回复 write-req(31). 就出错了, 因为 PSN 31
         *      对应的是一个 read request, 表示这是一个 read response 了.
	 *
	 * ref: b97db58557f4aa6d9903f8e1deea6b3d1ed0ba43
	 *  +----------+                   +----------+
         *  |requester |                   |responder |
         *  |          |                   |          |
         *  +----------+                   +----------+
         *        |                             |     
         *        |-----write(MSN:1,PSN:1)----->|     
         *        |                             |     
         *        |-----read(MSN:2,PSN:2,3)---->|    
         *        |                             |     
         *        |                             |     
         *        |     X--ack(MSN:1,PSN:1)-----|     
         *        |                             |     
         *        |                             |     
         *        |         RETRY               |     
         *        |-----write(MSN:1,PSN:1)----->|     
         *        |                             |     
         *        |                             |     
         *        |     ?---ack(MSN:?,PSN:?)----|     
         *        |                             |     
         *        |                             |     
         *        |                             |     
	 * */
	u32 prev_psn = (qp->resp.ack_psn - 1) & BTH_PSN_MASK;

	if (pkt->mask & RXE_SEND_MASK ||
	    pkt->mask & RXE_WRITE_MASK) {
		/* SEND. Ack again and cleanup. C9-105. */
		if (bth_ack(pkt))
			send_ack(qp, pkt, AETH_ACK_UNLIMITED, prev_psn);	// 注意, 这里用来 ack 的 PSN 不是从 pkt 里提取出来的. 也不是 ePSN, 而是保存的一个特殊值.
		rc = RESPST_CLEANUP;
		goto out;
	} else if (pkt->mask & RXE_READ_MASK) { // go back n 了 ???
		struct resp_res *res;

		res = find_resource(qp, pkt->psn);
		if (!res) {
			/* Resource not found. Class D error.  Drop the
			 * request.
			 */
			rc = RESPST_CLEANUP;
			goto out;
		} else {
			/* Ensure this new request is the same as the previous
			 * one or a subset of it. IB Spec 要求的
			 *
			 * 可能重新请求新的 va 的, 这里不能盲目执行的. 要从 pkt 里提取一些信息的
			 */
			u64 iova = reth_va(pkt);
			u32 resid = reth_len(pkt);

			if (iova < res->read.va_org ||
			    resid > res->read.length ||
			    (iova + resid) > (res->read.va_org +
					      res->read.length)) {
				rc = RESPST_CLEANUP;
				goto out;
			}

			if (reth_rkey(pkt) != res->read.rkey) {
				rc = RESPST_CLEANUP;
				goto out;
			}

			res->cur_psn = pkt->psn;
			res->state = (pkt->psn == res->first_psn) ?
					rdatm_res_state_new :
					rdatm_res_state_replay;
			res->replay = 1;

			/* Reset the resource, except length. */
			res->read.va_org = iova;
			res->read.va = iova;
			res->read.resid = resid;

			/* Replay the RDMA read reply. */
			qp->resp.res = res;
			rc = RESPST_READ_REPLY; // 去 read_reply() 回复 reply 咯
			goto out;
		}
	} else { // atomic 操作, 注意不要重做 atomic 操作, 仅仅重发包就可以了
		struct resp_res *res;

		/* Find the operation in our list of responder resources. */
		res = find_resource(qp, pkt->psn);
		if (res) {
			skb_get(res->atomic.skb); // 之前的 skb 捞出来, 直接重新发就可以了
			/* Resend the result. */
			rc = rxe_xmit_packet(qp, pkt, res->atomic.skb);
			if (rc) {
				pr_err("Failed resending result. This flow is not handled - skb ignored\n");
				rc = RESPST_CLEANUP;
				goto out;
			}
		}

		/* Resource not found. Class D error. Drop the request. */
		rc = RESPST_CLEANUP;
		goto out;
	}
out:
	return rc;
}

/* Process a class A or C. Both are treated the same in this implementation. 
 *
 * class a/c 的行为是一样的, 都需要向上和向 requester 报告.
 *
 * 这里设置状态就可以了, 从这个函数返回的时候将 state 设置为 RESPST_COMPLETE 就可以了, 
 * - do_complete() 会根据 status 产生错误的 cqe 的
 * - 然后会走到 acknowledge() 去回复 nak 包的
 * - 最后 goto_error, 将 qp 设置为 error 状态, 然后调度 completer 将后续的 wqe 标记为 flush_err 的
 * */
static void do_class_ac_error(struct rxe_qp *qp, u8 syndrome,
			      enum ib_wc_status status)
{
	qp->resp.aeth_syndrome	= syndrome;
	qp->resp.status		= status;

	/* indicate that we should go through the ERROR state */
	qp->resp.goto_error	= 1;
}

static enum resp_states do_class_d1e_error(struct rxe_qp *qp)
{
	/* UC */
	if (qp->srq) {
		/* Class E */
		qp->resp.drop_msg = 1;
		if (qp->resp.wqe) {
			qp->resp.status = IB_WC_REM_INV_REQ_ERR;
			return RESPST_COMPLETE;
		} else {
			return RESPST_CLEANUP;
		}
	} else {
		/* Class D1. This packet may be the start of a
		 * new message and could be valid. The previous
		 * message is invalid and ignored. reset the
		 * recv wr to its original state
		 */
		if (qp->resp.wqe) {
			qp->resp.wqe->dma.resid = qp->resp.wqe->dma.length;
			qp->resp.wqe->dma.cur_sge = 0;
			qp->resp.wqe->dma.sge_offset = 0;
			qp->resp.opcode = -1;
		}

		if (qp->resp.mr) {
			rxe_drop_ref(qp->resp.mr);
			qp->resp.mr = NULL;
		}

		return RESPST_CLEANUP;
	}
}

static void rxe_drain_req_pkts(struct rxe_qp *qp, bool notify)
{
	struct sk_buff *skb;

	// 收到的 req 全部 drop 掉
	while ((skb = skb_dequeue(&qp->req_pkts))) {
		rxe_drop_ref(qp);
		kfree_skb(skb);
	}

	if (notify)
		return;

	// rq 全部消耗掉
	while (!qp->srq && qp->rq.queue && queue_head(qp->rq.queue))
		advance_consumer(qp->rq.queue);
}

// 处理外部 rdma 请求包, 会一直处理, 知道 req_pkts 被处理完
// 调度时机:
// - rxe_qp_error() 的时候 drain work and pkt queues
// - 收到 request pkt 的时候: rxe_resp_queue_pkt

/* topic:
 * 0. 本地 qp 状态校验
 * 1. inbound pkt validation: 1.4 vol1 figure 90
 * 2. generating PSN
 * 3. read response
 * 4. dup req 处理
 * 5. generating nak
 * 6. 回复 ack 的时机
 * */

/* RC 错误类型
 * | Error(有 NAK)          | Desc                                   | Syndrome                     | Fault Behavior Class |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | Malformed WQE          | wqe 有问题                             | NAK:Remote-Operational-Error | Class A              |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | Local QP Error         | Responder 执行 request 的              | NAK:Remote-Operational-Error | Class A              |
 * |                        | 时候发现和locla QP 相关的              |                              |                      |
 * |                        | error,包括: SRQ 上的 error             |                              |                      |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | Resources Not Ready    | WQE 或者其他资源不可用                 | NAK:RNR                      | Class B              |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | OOO psn                | psn 乱了                               | NAk:sequence-err             | Class B              |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | unsupported or         | opcode 非法                            | NAk:Invalid-Req              | Class C              |
 * | rsvd opcode            |                                        |                              |                      |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | OOO opcode             | opcode 的顺序非法                      | NAK:invalid-Req              | Class C              |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | misaligned atomic      | atomic 的 va 不对齐                    | NAK:invalid-Req              | Class C              |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | too many rd/atomic req | req 发送的 rd/atomic 太多              | NAK:invalid-Req              | Class C              |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | length errors          | 1. send req message 超过了 recv buffer | NAK-Invalid Req              | Class C              |
 * |                        | 2. write pkt 的数据和 dma len 不匹配   |                              |                      |
 * |                        | 3. pkt payload 和 PMTU 长度不匹配      |                              |                      |
 * |                        | 4. message 最大长度超过 CA 限制        |                              |                      |
 * |------------------------+----------------------------------------+------------------------------+----------------------|
 * | R_Key Violation        | R_key 非法                             | NAK:Remote-Access-Violation  | Class C              |
 *
 *
 * | Error(无 NAK)           | Desc                                   | Syndrome | Fault Behavior Class |
 * |-------------------------+----------------------------------------+----------+----------------------|
 * | Pkt Hdr Violation       | Pkt Hdr 非法                           | none     | Class D              |
 * |-------------------------+----------------------------------------+----------+----------------------|
 * | Invalid dup ATOMIC Req  | 收到重复的 atomic req pkt, 但是 PSN 和 | none     | Class D              |
 * |                         | 保存的 ATOMIC Req 不匹配               |          |                      |
 * |-------------------------+----------------------------------------+----------+----------------------|
 * | CQ overflow             | CQ 满了                                | none     | Class G              |
 * |-------------------------+----------------------------------------+----------+----------------------|
 * | Remote Invalidate Error | send-with-invalidate 的 R_key 非法     | NA       | Class J              |
 *
 *
 *
 *
 * RC 错误处理
 * | Fault Behavior | desc                        | NAK Codes Returned          | Curr Receive WQE   | Sub Recv WQE | Final RQ State |
 * | Class          |                             |                             |                    |              |                |
 * |----------------+-----------------------------+-----------------------------+--------------------+--------------+----------------|
 * | Class A        | response 自己有问题         | 1. Remote Operational Error | completed in err   | flushed      | error          |
 * |                |                             |                             |                    |              |                |
 * |                | 向上报告                    |                             |                    |              |                |
 * |----------------+-----------------------------+-----------------------------+--------------------+--------------+----------------|
 * | Class B        | requester 提供的有问题      | 1. Seq error                | no WQE consmed     | no impact    | no change      |
 * |                |                             | 2. RNR                      |                    |              |                |
 * |                | 报告给 requester            |                             |                    |              |                |
 * |                | 不向上报告                  |                             |                    |              |                |
 * |----------------+-----------------------------+-----------------------------+--------------------+--------------+----------------|
 * | Class C        | requester 提供的有问题      | 1. Invalid Req              |                    |              |                |
 * |                |                             | 2. Remote Access Violation  |                    |              |                |
 * |                | 报告给 requester            |                             | completed in error | flushed      | error          |
 * |                | 也向上报告                  |                             |                    |              |                |
 * |----------------+-----------------------------+-----------------------------+--------------------+--------------+----------------|
 * | Class D        | inbound pkt 导致的          | none                        | no WQE consumed    | no impact    | no change      |
 * |                | drop silently               |                             |                    |              |                |
 * |----------------+-----------------------------+-----------------------------+--------------------+--------------+----------------|
 * | Class G        | CQ 有问题                   | none                        | unknown            | unknown      | error          |
 * |----------------+-----------------------------+-----------------------------+--------------------+--------------+----------------|
 * | Class J        | send-with-invalidate 有问题 | none                        | completed in error | flushed      | error          |
 * */
int rxe_responder(void *arg)
{
	struct rxe_qp *qp = (struct rxe_qp *)arg; // per-qp 的, 不能并发的
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	enum resp_states state;
	struct rxe_pkt_info *pkt = NULL;
	int ret = 0;

	rxe_add_ref(qp);

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;

	if (!qp->valid) {
		ret = -EINVAL;
		goto done;
	}

	switch (qp->resp.state) {
	case QP_STATE_RESET:
		state = RESPST_RESET; // 用户主动来 reset 恢复 cq 么?
		break;

	default:
		state = RESPST_GET_REQ;
		break;
	}

	// 正常路径: get_req -> RESPST_CHK_PSN -> RESPST_CHK_OP_SEQ -> RESPST_CHK_OP_VALID -> RESPST_CHK_RESOURCE
	while (1) {
		pr_debug("qp#%d state = %s\n", qp_num(qp),
			 resp_state_name[state]);
		switch (state) {
		case RESPST_GET_REQ: // 收到一个 req 了, 后面的 case 通过 while 进入的
			state = get_req(qp, &pkt); // pkt 用来存储原始的 req pkt
			break;
		case RESPST_CHK_PSN:
			state = check_psn(qp, pkt);
			break;
		case RESPST_CHK_OP_SEQ:
			state = check_op_seq(qp, pkt);
			break;
		case RESPST_CHK_OP_VALID:
			state = check_op_valid(qp, pkt);
			break;
		case RESPST_CHK_RESOURCE:
			state = check_resource(qp, pkt);
			break;
		case RESPST_CHK_LENGTH:
			state = check_length(qp, pkt);
			break;
		case RESPST_CHK_RKEY:
			state = check_rkey(qp, pkt);
			break;
		case RESPST_EXECUTE: // 检查结束, 需要执行了
			state = execute(qp, pkt);
			break;
		case RESPST_COMPLETE: // 需要生成 completion 了
			state = do_complete(qp, pkt);
			break;
		case RESPST_READ_REPLY: // 需要回 read reply. read req 的主要的执行行为在这里
			state = read_reply(qp, pkt);
			break;
		case RESPST_ACKNOWLEDGE: // 需要回 ack pkt
			state = acknowledge(qp, pkt);
			break;
		case RESPST_CLEANUP:
			state = cleanup(qp, pkt);
			break;
		case RESPST_DUPLICATE_REQUEST: // dup req 处理
			state = duplicate_request(qp, pkt);
			break;
		case RESPST_ERR_PSN_OUT_OF_SEQ: // class b: nak:sequence-error
			/* RC only - Class B. Drop packet. class b 只需要回复 nak 就可以了 */
			/* XXX: 就这里的 ack 特殊, psn 用的是 ePSN */
			send_ack(qp, pkt, AETH_NAK_PSN_SEQ_ERROR, qp->resp.psn);
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_TOO_MANY_RDMA_ATM_REQ: // class c: nak:invalid-request
		case RESPST_ERR_MISSING_OPCODE_FIRST:  // class c: nak:invalid-request
		case RESPST_ERR_MISSING_OPCODE_LAST_C: // class c: nak:invalid-request
		case RESPST_ERR_UNSUPPORTED_OPCODE:    // class c: nak:invalid-request
		case RESPST_ERR_MISALIGNED_ATOMIC:     // class c: nak:invalid-request
			/* RC Only - Class C. 本地就处理了额
			 * class a/c 的行为是一样的, 都需要向上和向 requester 报告.
			 * */
			do_class_ac_error(qp, AETH_NAK_INVALID_REQ,
					  IB_WC_REM_INV_REQ_ERR);
			// class a/c 的处理需要向上层报告, 所以去 complete 处理,
			// complete 处理后还要去 RESPST_ACKNOWLEDGE 去回复 nak
			// 最后 goto error 去 error 状态
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_MISSING_OPCODE_LAST_D1E: // UC Only
			state = do_class_d1e_error(qp);
			break;
		case RESPST_ERR_RNR:
			if (qp_type(qp) == IB_QPT_RC) {
				rxe_counter_inc(rxe, RXE_CNT_SND_RNR);
				/* RC - class B, 不需要向上报告, 回复 NAK 就可以了 */
				send_ack(qp, pkt, AETH_RNR_NAK |
					 (~AETH_TYPE_MASK &
					 qp->attr.min_rnr_timer),
					 pkt->psn);
			} else {
				/* UD/UC - class D */
				qp->resp.drop_msg = 1;
			}
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_RKEY_VIOLATION:
			if (qp_type(qp) == IB_QPT_RC) { // class c: nak:remote-access-violation
				do_class_ac_error(qp, AETH_NAK_REM_ACC_ERR,
						  IB_WC_REM_ACCESS_ERR);
				state = RESPST_COMPLETE;
			} else {
				qp->resp.drop_msg = 1;
				if (qp->srq) {
					/* UC/SRQ Class D */
					qp->resp.status = IB_WC_REM_ACCESS_ERR;
					state = RESPST_COMPLETE;
				} else {
					/* UC/non-SRQ Class E. */
					state = RESPST_CLEANUP;
				}
			}
			break;

		case RESPST_ERR_LENGTH:
			if (qp_type(qp) == IB_QPT_RC) { // class c: nak:invalid-request
				/* Class C */
				do_class_ac_error(qp, AETH_NAK_INVALID_REQ,
						  IB_WC_REM_INV_REQ_ERR);
				state = RESPST_COMPLETE;
			} else if (qp->srq) { // uc with srq: class E
				/* UC/UD - class E */
				qp->resp.status = IB_WC_REM_INV_REQ_ERR;
				state = RESPST_COMPLETE;
			} else {
				/* UC/UD - class D */
				qp->resp.drop_msg = 1;
				state = RESPST_CLEANUP;
			}
			break;

		case RESPST_ERR_MALFORMED_WQE: // class a: nak:remote-operation-error
			/* All, Class A. */
			do_class_ac_error(qp, AETH_NAK_REM_OP_ERR,
					  IB_WC_LOC_QP_OP_ERR);
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_CQ_OVERFLOW: // class G
			/* All - Class G */
			state = RESPST_ERROR; // 无条件直接进入 error 状态咯
			break;

		case RESPST_DONE:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			goto done;

		case RESPST_EXIT:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			goto exit;

		case RESPST_RESET:
			rxe_drain_req_pkts(qp, false);
			qp->resp.wqe = NULL;
			goto exit;

		case RESPST_ERROR:
			qp->resp.goto_error = 0;
			pr_warn("qp#%d moved to error state\n", qp_num(qp));
			rxe_qp_error(qp); // 出错了, 通知 userspace
			goto exit;

		default:
			WARN_ON_ONCE(1);
		}
	}

	/* A non-zero return value will cause rxe_do_task to
	 * exit its loop and end the work item. A zero return
	 * will continue looping and return to rxe_responder
	 *
	 * ref: rxe_do_task
	 */
exit:
	ret = -EAGAIN; // 从这里走, 就只能等待下次调度了
done: // 从 done 这里走函数可能还会回来
	rxe_drop_ref(qp);
	return ret;
}
