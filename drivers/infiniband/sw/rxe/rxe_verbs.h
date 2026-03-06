/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
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
	spinlock_t		cq_lock;
	u8			notify;
	bool			is_dying;
	int			is_user;
	struct tasklet_struct	comp_task; // completion tasklet, %rxe_send_complete
};

// ref: update_wqe_state
enum wqe_state {
	wqe_state_posted,
	wqe_state_processing, // 多 pkt 的 req 正在处理
	wqe_state_pending, // rc 服务中, req 的最后一个 pkt 发出去后, 是要等待对方回复的. 所以此时 wqe 还没有处理完
	wqe_state_done,
	wqe_state_error,
};

struct rxe_sq {
	int			max_wr;
	int			max_sge;
	int			max_inline;
	spinlock_t		sq_lock; /* guard queue */
	struct rxe_queue	*queue;
};

struct rxe_rq {
	int			max_wr;
	int			max_sge;
	spinlock_t		producer_lock; /* guard queue producer */
	spinlock_t		consumer_lock; /* guard queue consumer */
	struct rxe_queue	*queue;
};

struct rxe_srq {
	struct ib_srq		ibsrq;
	struct rxe_pool_entry	pelem;
	struct rxe_pd		*pd;
	struct rxe_rq		rq;
	u32			srq_num;

	int			limit;
	int			error;
};

// 内部实现的状态
// qp 的 req / resp 段是单独维护的
enum rxe_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */ // ref: rxe_qp_drain, 对应到上层就是 IB 的 SQD 状态: 允许已经 post 的 WQE 发完, 但是不允许 post 新的了
	QP_STATE_DRAINED,	/* req only */ // ref: complete_ack(), 排空后进入这个状态
	QP_STATE_ERROR
};

struct rxe_req_info {
	enum rxe_qp_state	state;
	int			wqe_index;	// 下一个要处理的 sq 的 wqe index, ref: rxe_requester() -> next_index()
	u32			psn;            // 最大的被 req 的 psn
	int			opcode;
	/* rdma 中有两个参数:
	 * - max_rd_atomic (init depth), 本端最多可以发的 read/atomic 数目
         * - max_dest_rd_atomic(responder depth), 表示我最多可以同时处理的 read/atomic 数目
	 * */
	atomic_t		rd_atomic;      // 剩余的可用的 reawd/atomic 数量, ref: rxe_qp_from_attr(). 用户创建 qp 的时候提供的 rd_atomic 应该参考对端的情况
	int			wait_fence;     // ref: req_next_wqe, post fence 的时候, 设置这个标记. 这时候该 sq 上要等待前面的 wr 完成
	int			need_rd_atomic;
	int			wait_psn;
	int			need_retry;	// 收到 nak 后, 可能要 retry, 在这里标记下, 后面有机会的时候根据这个标记做 retry, ref: rxe_completer
	int			noack_pkts; // 记录我发出的没有设置 ack_req 的 last pkt 数量, 到达一定数量后, 就设置 ack_req bit, ref: init_req_packet()
	struct rxe_task		task; // rxe_requester
};

struct rxe_comp_info {
	u32			psn; // 最大的被 ack 的 psn + 1, 对于 req 接收responder 来说, 也就是 expect psn
	int			opcode;
	int			timeout; // ref: rxe_completer
	int			timeout_retry;
	int			started_retry;
	u32			retry_cnt;
	u32			rnr_retry;
	struct rxe_task		task; // rxe_completer
};

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
	enum rxe_qp_state	state;
	u32			msn;
	u32			psn; // expected psn. ref: rxe_resp:execute()
	u32			ack_psn; // 用来做 ack 的 psn, 即我如果回复 ack 包, 用这个做 psn. ref: rxe_resp:execute()
	int			opcode; // 保存刚才收到的 opcode, 用于校验后续的 opcode, ref: check_op_seq()
	int			drop_msg;
	int			goto_error;
	int			sent_psn_nak;
	enum ib_wc_status	status;
	u8			aeth_syndrome;

	/* Receive only */
	struct rxe_recv_wqe	*wqe; // 取出来正在用的 wqe, 可能来自 rq, 或者 srq, ref: get_srq_wqe()

	/* RDMA read / atomic only */ // 处理 response pkt 的时候暂存的一些信息
	u64			va;
	struct rxe_mem		*mr;
	u32			resid;
	u32			rkey;
	u32			length;
	u64			atomic_orig;

	/* SRQ only */
	struct {
		struct rxe_recv_wqe	wqe;
		struct ib_sge		sge[RXE_MAX_SGE];
	} srq_wqe;

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 */
	struct resp_res		*resources;
	unsigned int		res_head;
	unsigned int		res_tail;
	struct resp_res		*res;
	struct rxe_task		task;  // rxe_responder
};

// ref: rxe_qp_from_attr
// 大部分属性来自 modify_qp, 而不是 creaet_qp()
// 有不少信息是对方的信息, rxe_resp_info() 这要在连接建立后才能拿到
struct rxe_qp {
	struct rxe_pool_entry	pelem;
	struct ib_qp		ibqp;
	struct ib_qp_attr	attr;
	unsigned int		valid;
	unsigned int		mtu;
	int			is_user;

	struct rxe_pd		*pd;
	struct rxe_srq		*srq;
	struct rxe_cq		*scq;
	struct rxe_cq		*rcq;

	enum ib_sig_type	sq_sig_type;

	struct rxe_sq		sq;
	struct rxe_rq		rq;

	struct socket		*sk;
	u32			dst_cookie;
	u16			src_port;

	struct rxe_av		pri_av;
	struct rxe_av		alt_av;

	/* list of mcast groups qp has joined (for cleanup) */
	struct list_head	grp_list;
	spinlock_t		grp_lock; /* guard grp_list */

	struct sk_buff_head	req_pkts; // ref: rxe_resp_queue_pkt
	struct sk_buff_head	resp_pkts;
	struct sk_buff_head	send_pkts;

	struct rxe_req_info	req;
	struct rxe_comp_info	comp;
	struct rxe_resp_info	resp;

	atomic_t		ssn; // 初始值是 0, send sequence number, 和 msn 是一对一的, ref: rxe_qp_init_misc()
	atomic_t		skb_out;
	int			need_req_skb;

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct timer_list retrans_timer; // ref: rxe_qp_init_req, update_state
	u64 qp_timeout_jiffies; // 来自 qp_attr, retrans timeout, ref: rxe_qp_from_attr()

	/* Timer for handling RNR NAKS. */
	struct timer_list rnr_nak_timer; // ref: rxe_qp_init_req, rxe_completer() 负责调度

	spinlock_t		state_lock; /* guard requester and completer */

	struct execute_work	cleanup_work;
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
