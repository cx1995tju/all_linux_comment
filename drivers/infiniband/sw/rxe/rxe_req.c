// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>
#include <crypto/hash.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"

static int next_opcode(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
		       u32 opcode);


// 这里的 npsn 个 pkt 不需要真的发送到 wire 上
static inline void retry_first_write_send(struct rxe_qp *qp,
					  struct rxe_send_wqe *wqe,
					  unsigned int mask, int npsn)
{
	int i;

	for (i = 0; i < npsn; i++) {
		int to_send = (wqe->dma.resid > qp->mtu) ?
				qp->mtu : wqe->dma.resid;

		qp->req.opcode = next_opcode(qp, wqe,
					     wqe->wr.opcode);

		if (wqe->wr.send_flags & IB_SEND_INLINE) {
			wqe->dma.resid -= to_send;
			wqe->dma.sge_offset += to_send;
		} else {
			advance_dma_data(&wqe->dma, to_send);
		}
		if (mask & WR_WRITE_MASK)
			wqe->iova += qp->mtu;
	}
}

// 标记 wqe 来完成回退, 这里仅仅做标记
static void req_retry(struct rxe_qp *qp)
{
	struct rxe_send_wqe *wqe;
	unsigned int wqe_index;
	unsigned int mask;
	int npsn;
	int first = 1;

	// GBN: 从最早的 wqe 开始, 全部 retry
	qp->req.wqe_index	= consumer_index(qp->sq.queue);
	qp->req.psn		= qp->comp.psn; // go back n, snd_una 来处理
	qp->req.opcode		= -1;

	for (wqe_index = consumer_index(qp->sq.queue);
		wqe_index != producer_index(qp->sq.queue);
		wqe_index = next_index(qp->sq.queue, wqe_index)) {
		wqe = addr_from_index(qp->sq.queue, wqe_index);
		mask = wr_opcode_mask(wqe->wr.opcode, qp);

		// 从这个 wqe 开始的都还没有被 requester 处理, 不需要 retry 了
		if (wqe->state == wqe_state_posted)
			break;

		// 这些 wqe 的 response 都收到了, 不需要管了
		if (wqe->state == wqe_state_done)
			continue;

		wqe->iova = (mask & WR_ATOMIC_MASK) ?
			     wqe->wr.wr.atomic.remote_addr :
			     (mask & WR_READ_OR_WRITE_MASK) ?
			     wqe->wr.wr.rdma.remote_addr :
			     0;

		if (!first || (mask & WR_READ_MASK) == 0) { // 因为 READ req 肯定是单个 pkt 的
			wqe->dma.resid = wqe->dma.length;
			wqe->dma.cur_sge = 0;
			wqe->dma.sge_offset = 0;
		}

		if (first) { // 第一个要特殊处理, write/send 可能只需要 retry 部分 pkt. read 也可能只需要请求部分 pkt
			first = 0;

			if (mask & WR_WRITE_OR_SEND_MASK) { // write, send 可能是多包, 但是只有部分需要重传
							    // qp->comp.psn 是 snd_una, 在 snd_una 之前的不需要 retry 了
				npsn = (qp->comp.psn - wqe->first_psn) &
					BTH_PSN_MASK;
				// 这里的 npsn 个 pkt 不需要真的发送到 wire 上
				retry_first_write_send(qp, wqe, mask, npsn);
			}

			if (mask & WR_READ_MASK) {
				npsn = (wqe->dma.length - wqe->dma.resid) /
					qp->mtu;
				wqe->iova += npsn * qp->mtu;
			}
		}

		// XXX: 这里是关键, 回退 wqe 状态
		wqe->state = wqe_state_posted;
	}
}

// run requester
void rnr_nak_timer(struct timer_list *t)
{
	struct rxe_qp *qp = from_timer(qp, t, rnr_nak_timer);

	pr_debug("qp#%d rnr nak timer fired\n", qp_num(qp));
	rxe_run_task(&qp->req.task, 1);
}

/* 取一个 wqe 来处理, 另外有一些特殊情况:
 * - SQ 处于 DRAIN 状态, 不允许 处理
 * - SQ 在 wait fence, 也不允许处理
 *
 * */
static struct rxe_send_wqe *req_next_wqe(struct rxe_qp *qp)
{
	struct rxe_send_wqe *wqe = queue_head(qp->sq.queue);
	unsigned long flags;

	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
		/* check to see if we are drained; 这里仅仅是检查是否 DRAINED 了.
		 * state_lock used by requester and completer
		 */
		spin_lock_irqsave(&qp->state_lock, flags);
		do {
			if (qp->req.state != QP_STATE_DRAIN) {
				/* comp just finished */
				spin_unlock_irqrestore(&qp->state_lock,
						       flags);
				break;
			}

			if (wqe && ((qp->req.wqe_index !=
				consumer_index(qp->sq.queue)) ||
				(wqe->state != wqe_state_posted))) {
				/* comp not done yet */
				spin_unlock_irqrestore(&qp->state_lock,
						       flags);
				break;
			}

			// 等待所有的 wqe 被完成
			qp->req.state = QP_STATE_DRAINED;
			spin_unlock_irqrestore(&qp->state_lock, flags);

			if (qp->ibqp.event_handler) {
				struct ib_event ev;

				ev.device = qp->ibqp.device;
				ev.element.qp = &qp->ibqp;
				ev.event = IB_EVENT_SQ_DRAINED;
				// XXX: 排空了会在这里触发 event 的
				qp->ibqp.event_handler(&ev,
					qp->ibqp.qp_context);
			}
		} while (0);
	}

	// 没有新的 wqe 可以用来发送了
	if (qp->req.wqe_index == producer_index(qp->sq.queue))
		return NULL;

	// 取出一个 wqe
	wqe = addr_from_index(qp->sq.queue, qp->req.wqe_index);

	// 除非这个 wqe 处理了一半, 那么在 DRAIN 状态, 还让 requester 继续处理.
	// 否则 verbs 层我们还是允许用户 post. 但是底层不允许其处理 wqe 了.
	// 等到我们排空后, 切换到 DRAINED 状态, 通知用户后, 用户自己再看着办.
	// 比如: 可以切换到 error 状态, 可以切换到 RTS 状态. 然后切换回 reset 状态.
	if (unlikely((qp->req.state == QP_STATE_DRAIN ||
		      qp->req.state == QP_STATE_DRAINED) &&
		     (wqe->state != wqe_state_processing)))
		return NULL;

	// fence 的处理
	if (unlikely((wqe->wr.send_flags & IB_SEND_FENCE) &&
		     (qp->req.wqe_index != consumer_index(qp->sq.queue)))) {
		qp->req.wait_fence = 1;
		return NULL;
	}

	wqe->mask = wr_opcode_mask(wqe->wr.opcode, qp);
	return wqe;
}

static int next_opcode_rc(struct rxe_qp *qp, u32 opcode, int fits)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_LAST :
				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_ONLY :
				IB_OPCODE_RC_RDMA_WRITE_FIRST;

	case IB_WR_RDMA_WRITE_WITH_IMM: // immdata 携带在最后一个 pkt 里
		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_RC_RDMA_WRITE_FIRST;

	case IB_WR_SEND:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_RC_SEND_LAST :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_SEND_ONLY :
				IB_OPCODE_RC_SEND_FIRST;

	case IB_WR_SEND_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_RC_SEND_FIRST;

	case IB_WR_RDMA_READ:
		return IB_OPCODE_RC_RDMA_READ_REQUEST;

	case IB_WR_ATOMIC_CMP_AND_SWP:
		return IB_OPCODE_RC_COMPARE_SWAP;

	case IB_WR_ATOMIC_FETCH_AND_ADD:
		return IB_OPCODE_RC_FETCH_ADD;

	case IB_WR_SEND_WITH_INV:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ? IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ? IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE :
				IB_OPCODE_RC_SEND_FIRST;
	case IB_WR_REG_MR:
	case IB_WR_LOCAL_INV:
		return opcode;
	}

	return -EINVAL;
}

static int next_opcode_uc(struct rxe_qp *qp, u32 opcode, int fits)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_LAST :
				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_ONLY :
				IB_OPCODE_UC_RDMA_WRITE_FIRST;

	case IB_WR_RDMA_WRITE_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_UC_RDMA_WRITE_FIRST;

	case IB_WR_SEND:
		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_UC_SEND_LAST :
				IB_OPCODE_UC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_SEND_ONLY :
				IB_OPCODE_UC_SEND_FIRST;

	case IB_WR_SEND_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE :
				IB_OPCODE_UC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_UC_SEND_FIRST;
	}

	return -EINVAL;
}

// opcode: wqe 的 opcode
static int next_opcode(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
		       u32 opcode)
{
	int fits = (wqe->dma.resid <= qp->mtu); // 遗留的数据长度 < mtu 了

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		return next_opcode_rc(qp, opcode, fits);

	case IB_QPT_UC:
		return next_opcode_uc(qp, opcode, fits);

	case IB_QPT_SMI:
	case IB_QPT_UD:
	case IB_QPT_GSI:
		switch (opcode) {
		case IB_WR_SEND:
			return IB_OPCODE_UD_SEND_ONLY;

		case IB_WR_SEND_WITH_IMM:
			return IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		}
		break;

	default:
		break;
	}

	return -EINVAL;
}

static inline int check_init_depth(struct rxe_qp *qp, struct rxe_send_wqe *wqe)
{
	int depth;

	if (wqe->has_rd_atomic)
		return 0;

	qp->req.need_rd_atomic = 1;
	depth = atomic_dec_return(&qp->req.rd_atomic);

	if (depth >= 0) {
		qp->req.need_rd_atomic = 0;
		wqe->has_rd_atomic = 1;
		return 0;
	}

	atomic_inc(&qp->req.rd_atomic);
	return -EAGAIN;
}

static inline int get_mtu(struct rxe_qp *qp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	if ((qp_type(qp) == IB_QPT_RC) || (qp_type(qp) == IB_QPT_UC))
		return qp->mtu;

	return rxe->port.mtu_cap;
}

// 会把报文头都准备好
// @pkt 存储的 metadata, 还不是送到 fabric 的 wire data
static struct sk_buff *init_req_packet(struct rxe_qp *qp,
				       struct rxe_send_wqe *wqe,
				       int opcode, int payload,
				       struct rxe_pkt_info *pkt)
{
	struct rxe_dev		*rxe = to_rdev(qp->ibqp.device);
	struct sk_buff		*skb;
	struct rxe_send_wr	*ibwr = &wqe->wr;
	struct rxe_av		*av;
	int			pad = (-payload) & 0x3;
	int			paylen;
	int			solicited;
	u16			pkey;
	u32			qp_num;
	int			ack_req;

	/* length from start of bth to end of icrc */
	paylen = rxe_opcode[opcode].length + payload + pad + RXE_ICRC_SIZE;

	/* pkt->hdr, rxe, port_num and mask are initialized in ifc
	 * layer
	 */
	pkt->opcode	= opcode;
	pkt->qp		= qp;
	pkt->psn	= qp->req.psn; // psn 就使用 qp->req.psn 里维护的就可以了, 这里用了但是不更新 psn 么?
	pkt->mask	= rxe_opcode[opcode].mask;
	pkt->paylen	= paylen;
	pkt->offset	= 0;
	pkt->wqe	= wqe;

	/* init skb */
	// 找到 av 结构指针, 查路由咯. connection 去对应 qp 找, 否则去对应的 wqe 里提取
	av = rxe_get_av(pkt);
	skb = rxe_init_packet(rxe, av, paylen, pkt);
	if (unlikely(!skb))
		return NULL;

	/* init bth */
	/* 什么情况要求在 responder 端产生 cqe? 同时满足下述 3 个条件
	 * - 用户要求: IB_SEND_SOLICITED
	 * - 是一个 end pkt
	 * - opcode 符合要求:
	 *   - send
	 *   - 或者 write with immData
	 * */
	solicited = (ibwr->send_flags & IB_SEND_SOLICITED) &&
			(pkt->mask & RXE_END_MASK) &&
			((pkt->mask & (RXE_SEND_MASK)) ||
			(pkt->mask & (RXE_WRITE_MASK | RXE_IMMDT_MASK)) ==
			(RXE_WRITE_MASK | RXE_IMMDT_MASK));

	// 可以看出 pkey 在 rocev2 里没什么作用的
	pkey = IB_DEFAULT_PKEY_FULL;

	qp_num = (pkt->mask & RXE_DETH_MASK) ? ibwr->wr.ud.remote_qpn :
					 qp->attr.dest_qp_num;

	/* 什么情况要求对方回 ack ? 
	 * - 要么这是 end pkt
	 * - 要么太长时间没有回 ack 给我了
	 * */
	ack_req = ((pkt->mask & RXE_END_MASK) ||
		(qp->req.noack_pkts++ > RXE_MAX_PKT_PER_ACK));
	if (ack_req)
		qp->req.noack_pkts = 0;

	// 下面可以看出不同的 hdr 之间的顺序
	bth_init(pkt, pkt->opcode, solicited, 0, pad, pkey, qp_num,
		 ack_req, pkt->psn);

	/* init optional headers */
	if (pkt->mask & RXE_RETH_MASK) { // rdma 操作需要的 header
		reth_set_rkey(pkt, ibwr->wr.rdma.rkey);
		reth_set_va(pkt, wqe->iova);
		reth_set_len(pkt, wqe->dma.resid);
	}

	if (pkt->mask & RXE_IMMDT_MASK)
		immdt_set_imm(pkt, ibwr->ex.imm_data);

	if (pkt->mask & RXE_IETH_MASK)
		ieth_set_rkey(pkt, ibwr->ex.invalidate_rkey);

	if (pkt->mask & RXE_ATMETH_MASK) {
		atmeth_set_va(pkt, wqe->iova);
		if (opcode == IB_OPCODE_RC_COMPARE_SWAP ||
		    opcode == IB_OPCODE_RD_COMPARE_SWAP) {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.swap);
			atmeth_set_comp(pkt, ibwr->wr.atomic.compare_add);
		} else {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.compare_add);
		}
		atmeth_set_rkey(pkt, ibwr->wr.atomic.rkey);
	}

	if (pkt->mask & RXE_DETH_MASK) {
		if (qp->ibqp.qp_num == 1)
			deth_set_qkey(pkt, GSI_QKEY); // qp1 
		else
			deth_set_qkey(pkt, ibwr->wr.ud.remote_qkey);
		deth_set_sqp(pkt, qp->ibqp.qp_num);
	}


	return skb;
}

// copy payload, 计算 crc
// 更新下 wqe 里维护的一些信息
static int fill_packet(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
		       struct rxe_pkt_info *pkt, struct sk_buff *skb,
		       int paylen)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	u32 crc = 0;
	u32 *p;
	int err;

	err = rxe_prepare(pkt, skb, &crc);
	if (err)
		return err;

	// write/send 带有 payload 的, copy data
	if (pkt->mask & RXE_WRITE_OR_SEND) {
		if (wqe->wr.send_flags & IB_SEND_INLINE) { // 如果是 send inline, 数据在 wr 里, 否则在 buf 里
			u8 *tmp = &wqe->dma.inline_data[wqe->dma.sge_offset];

			crc = rxe_crc32(rxe, crc, tmp, paylen);
			memcpy(payload_addr(pkt), tmp, paylen);

			wqe->dma.resid -= paylen;
			wqe->dma.sge_offset += paylen;
		} else {
			err = copy_data(qp->pd, 0, &wqe->dma,
					payload_addr(pkt), paylen,
					from_mem_obj,
					&crc);
			if (err)
				return err;
		}
		if (bth_pad(pkt)) {
			u8 *pad = payload_addr(pkt) + paylen;

			memset(pad, 0, bth_pad(pkt));
			crc = rxe_crc32(rxe, crc, pad, bth_pad(pkt));
		}
	}
	p = payload_addr(pkt) + paylen + bth_pad(pkt);

	*p = ~crc;

	return 0;
}

static void update_wqe_state(struct rxe_qp *qp,
		struct rxe_send_wqe *wqe,
		struct rxe_pkt_info *pkt)
{
	if (pkt->mask & RXE_END_MASK) {
		if (qp_type(qp) == IB_QPT_RC)
			wqe->state = wqe_state_pending;
	} else {
		wqe->state = wqe_state_processing;
	}
}

// psn 更新逻辑
static void update_wqe_psn(struct rxe_qp *qp,
			   struct rxe_send_wqe *wqe,
			   struct rxe_pkt_info *pkt,
			   int payload)
{
	/* number of packets left to send including current one */
	int num_pkt = (wqe->dma.resid + payload + qp->mtu - 1) / qp->mtu;

	/* handle zero length packet case */
	if (num_pkt == 0)
		num_pkt = 1;

	if (pkt->mask & RXE_START_MASK) {
		wqe->first_psn = qp->req.psn;
		wqe->last_psn = (qp->req.psn + num_pkt - 1) & BTH_PSN_MASK;
	}

	if (pkt->mask & RXE_READ_MASK)
		qp->req.psn = (wqe->first_psn + num_pkt) & BTH_PSN_MASK;
	else
		qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
}

static void save_state(struct rxe_send_wqe *wqe,
		       struct rxe_qp *qp,
		       struct rxe_send_wqe *rollback_wqe,
		       u32 *rollback_psn)
{
	rollback_wqe->state     = wqe->state;
	rollback_wqe->first_psn = wqe->first_psn;
	rollback_wqe->last_psn  = wqe->last_psn;
	*rollback_psn		= qp->req.psn;
}

static void rollback_state(struct rxe_send_wqe *wqe,
			   struct rxe_qp *qp,
			   struct rxe_send_wqe *rollback_wqe,
			   u32 rollback_psn)
{
	wqe->state     = rollback_wqe->state;
	wqe->first_psn = rollback_wqe->first_psn;
	wqe->last_psn  = rollback_wqe->last_psn;
	qp->req.psn    = rollback_psn;
}

static void update_state(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
			 struct rxe_pkt_info *pkt, int payload)
{
	qp->req.opcode = pkt->opcode;

	if (pkt->mask & RXE_END_MASK)
		qp->req.wqe_index = next_index(qp->sq.queue, qp->req.wqe_index);

	qp->need_req_skb = 0;

	// 这个 timer 很粗暴, 就是发送的时候就调度一下
	if (qp->qp_timeout_jiffies && !timer_pending(&qp->retrans_timer))
		mod_timer(&qp->retrans_timer,
			  jiffies + qp->qp_timeout_jiffies);
}

// 取出 wqe 进行处理
// 这个版本有些 local 操作的支持还不全面, 比如: bind mw 等
// 不用上锁的, rxe_requester 是 tasklet 不允许并发的, 每个 qp 启动一个该 tasklet
int rxe_requester(void *arg)
{
	struct rxe_qp *qp = (struct rxe_qp *)arg;
	struct rxe_pkt_info pkt;
	struct sk_buff *skb;
	struct rxe_send_wqe *wqe;
	enum rxe_hdr_mask mask;
	int payload;
	int mtu;
	int opcode;
	int ret;
	struct rxe_send_wqe rollback_wqe;
	u32 rollback_psn;

	// 注意引用计数的增加
	rxe_add_ref(qp);

next_wqe:
	if (unlikely(!qp->valid || qp->req.state == QP_STATE_ERROR))
		goto exit;

	// req 端还没有准备好
	if (unlikely(qp->req.state == QP_STATE_RESET)) {
		qp->req.wqe_index = consumer_index(qp->sq.queue);
		qp->req.opcode = -1;
		qp->req.need_rd_atomic = 0;
		qp->req.wait_psn = 0;
		qp->req.need_retry = 0;
		goto exit;
	}

	// req 端处于 retry 状态, 先做下 retry 然后继续
	if (unlikely(qp->req.need_retry)) {
		req_retry(qp);
		qp->req.need_retry = 0;	// 完成回退, retry 也就完成了
	}

	wqe = req_next_wqe(qp);
	if (unlikely(!wqe))
		goto exit;

	if (wqe->mask & WR_REG_MASK) { // 1. IB_WR_REG_MR 和 IB_WR_LOCAL_INV 这两种特殊的 wqe, 走这里
		if (wqe->wr.opcode == IB_WR_LOCAL_INV) { // local 操作直接就执行了, 没有考虑前面可能没有完成的 remote 操作 ???
			struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
			struct rxe_mem *rmr;

			rmr = rxe_pool_get_index(&rxe->mr_pool,
						 wqe->wr.ex.invalidate_rkey >> 8); // rkey 高 24b 是 index
			if (!rmr) {
				pr_err("No mr for key %#x\n",
				       wqe->wr.ex.invalidate_rkey);
				wqe->state = wqe_state_error;
				wqe->status = IB_WC_MW_BIND_ERR;
				goto exit;
			}
			rmr->state = RXE_MEM_STATE_FREE;
			rxe_drop_ref(rmr);
			wqe->state = wqe_state_done;
			wqe->status = IB_WC_SUCCESS;
		} else if (wqe->wr.opcode == IB_WR_REG_MR) {
			struct rxe_mem *rmr = to_rmr(wqe->wr.wr.reg.mr);

			rmr->state = RXE_MEM_STATE_VALID;
			rmr->access = wqe->wr.wr.reg.access;
			/* mr 上原本的 key 怎么办 ??? key 也不检查么 这就是
			 * fast reg mr 的作用. 这里的 key 用户也不能随便给吧.
			 * 高 24b 的 index 必须是 ca 分配的, 低 8b 可以用户提供.
			 *
			 * 这里对 key 不做任何检查么???? 访问的时候再检查???
			 * */
			rmr->ibmr.lkey = wqe->wr.wr.reg.key;
			rmr->ibmr.rkey = wqe->wr.wr.reg.key;
			rmr->iova = wqe->wr.wr.reg.mr->iova;
			wqe->state = wqe_state_done;
			wqe->status = IB_WC_SUCCESS;
		} else {
			goto exit;
		}
		// 只有 local 操作才会走到这里的
		if ((wqe->wr.send_flags & IB_SEND_SIGNALED) ||
		    qp->sq_sig_type == IB_SIGNAL_ALL_WR)
			rxe_run_task(&qp->comp.task, 1); // 需要 signal 那么就调度一个 completer
		qp->req.wqe_index = next_index(qp->sq.queue,
						qp->req.wqe_index);
		goto next_wqe;
	}

	// 限制出去的最多的 outstanding pkt 数目
	if (unlikely(qp_type(qp) == IB_QPT_RC &&
		     qp->req.psn > (qp->comp.psn + RXE_MAX_UNACKED_PSNS))) {
		qp->req.wait_psn = 1;
		goto exit;
	}

	// skb 也做限制
	/* Limit the number of inflight SKBs per QP */
	if (unlikely(atomic_read(&qp->skb_out) >
		     RXE_INFLIGHT_SKBS_PER_QP_HIGH)) {
		qp->need_req_skb = 1;
		goto exit;
	}

	// generating opcode
	opcode = next_opcode(qp, wqe, wqe->wr.opcode);
	if (unlikely(opcode < 0)) {
		wqe->status = IB_WC_LOC_QP_OP_ERR;
		goto exit;
	}

	mask = rxe_opcode[opcode].mask;
	if (unlikely(mask & RXE_READ_OR_ATOMIC)) {
		if (check_init_depth(qp, wqe)) // outstaind read/atomic 的数量都是有限制的
			goto exit;
	}

	// generating payload
	mtu = get_mtu(qp);
	// requester 侧, 只有 write/send 需要 payload 的
	payload = (mask & RXE_WRITE_OR_SEND) ? wqe->dma.resid : 0;
	if (payload > mtu) {
		if (qp_type(qp) == IB_QPT_UD) {
			/* C10-93.1.1: If the total sum of all the buffer lengths specified for a
			 * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
			 * shall not emit any packets for this message. Further, the CI shall not
			 * generate an error due to this condition.
			 *
			 * UD 的 payload 不能超过 MTU 的
			 */

			/* fake a successful UD send */
			wqe->first_psn = qp->req.psn;
			wqe->last_psn = qp->req.psn;
			qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
			qp->req.opcode = IB_OPCODE_UD_SEND_ONLY;
			qp->req.wqe_index = next_index(qp->sq.queue,
						       qp->req.wqe_index);
			wqe->state = wqe_state_done;	// completer 处理好 ack 后, 回调度 requester 来设置 wqe 的状态
			wqe->status = IB_WC_SUCCESS;
			__rxe_do_task(&qp->comp.task);
			rxe_drop_ref(qp);
			return 0;
		}
		payload = mtu;
	}

	skb = init_req_packet(qp, wqe, opcode, payload, &pkt);
	if (unlikely(!skb)) {
		pr_err("qp#%d Failed allocating skb\n", qp_num(qp));
		goto err;
	}

	if (fill_packet(qp, wqe, &pkt, skb, payload)) {
		pr_debug("qp#%d Error during fill packet\n", qp_num(qp));
		kfree_skb(skb);
		goto err;
	}

	/*
	 * To prevent a race on wqe access between requester and completer,
	 * wqe members state and psn need to be set before calling
	 * rxe_xmit_packet().
	 * Otherwise, completer might initiate an unjustified retry flow.
	 *
	 * 否则: req 发出了包, resp 很快就回复触发了 completer, 其一看 wqe 的状态不对, 可能就 retry 了.
	 */
	// 保存 wqe 的信息, 用于回滚, 因为 send 的时候还可能出错的
	save_state(wqe, qp, &rollback_wqe, &rollback_psn);
	update_wqe_state(qp, wqe, &pkt);

	// 这里要更新很多信息
	update_wqe_psn(qp, wqe, &pkt, payload);
	ret = rxe_xmit_packet(qp, &pkt, skb);
	if (ret) {
		qp->need_req_skb = 1;

		rollback_state(wqe, qp, &rollback_wqe, rollback_psn);

		if (ret == -EAGAIN) {
			rxe_run_task(&qp->req.task, 1); // 重试咯
			goto exit;
		}

		goto err;
	}

	// 更新 wqe
	update_state(qp, wqe, &pkt, payload);

	goto next_wqe;

err:
	wqe->status = IB_WC_LOC_PROT_ERR;
	wqe->state = wqe_state_error;
	__rxe_do_task(&qp->comp.task);

exit:
	rxe_drop_ref(qp);
	return -EAGAIN;
}
