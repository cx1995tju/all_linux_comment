/* 注: ib 和 roce 在 transport 层是一样的, 所以这里很多 ib 和 roce 的代码是统一到一起的
 *
 * 1. module_init/exit 函数
 * 2. 核心全局变量的增删改查
 *        - dev_list
 *        - listen_any_list
 *        - cma_wq
 *        - cma_pernet()->tcp_ps
 * 3. 外部接口: 给内核其他模块提供 rdma cm 能力, 以及通过 rdma_ucm.ko 提供 rdma cm 能力给 userspace
 *      // socket-like 接口, 不过与 tcp-socket 有一些不同的点, ref: comment on rdma_accept()
 *	EXPORT_SYMBOL(__rdma_create_kernel_id);
 *	EXPORT_SYMBOL(rdma_create_user_id);
 *	EXPORT_SYMBOL(rdma_destroy_id);
 *	EXPORT_SYMBOL(rdma_resolve_route);
 *	EXPORT_SYMBOL(rdma_resolve_addr);
 *	EXPORT_SYMBOL(rdma_listen);
 *	EXPORT_SYMBOL(rdma_bind_addr);
 *	EXPORT_SYMBOL(rdma_connect_locked);
 *	EXPORT_SYMBOL(rdma_connect);
 *	EXPORT_SYMBOL(rdma_connect_ece);
 *	EXPORT_SYMBOL(rdma_accept);
 *	EXPORT_SYMBOL(rdma_accept_ece);
 *	EXPORT_SYMBOL(rdma_disconnect);
 *	EXPORT_SYMBOL(rdma_reject); // 与 tcp socket 不同的点, 作为 user-space 或者其他模块, 知道连接来了后, 可以主动拒绝的
 *	EXPORT_SYMBOL(rdma_notify); // 其他模块/user-space 通知发生了什么事件, 一般都是数据通路有什么事情发生了, 因为数据通路 bypass 了
 *
 *
 *	EXPORT_SYMBOL(rdma_create_qp);
 *	EXPORT_SYMBOL(rdma_destroy_qp);
 *	EXPORT_SYMBOL(rdma_init_qp_attr);
 *
 *	// 基于 id_priv->handler_mutex 类似于 lock_sock() 同步三个角色的行为:
 *	- 上层 user-space 通过 rdma_ucm.ko 进入
 *	- cma_wq 里的 work
 *	- 下层 rdma 设备层之间的事件, 比如: cma_ib_listen() -> ib_cm_insert_listen() 注册的 cma_ib_req_handler
 *	EXPORT_SYMBOL(rdma_lock_handler);
 *	EXPORT_SYMBOL(rdma_unlock_handler);
 *
 *
 *
 *
 *      // 一些参数的设置读取
 *	EXPORT_SYMBOL(rdma_get_service_id);
 *	EXPORT_SYMBOL(rdma_read_gids);
 *	EXPORT_SYMBOL(rdma_set_service_type);
 *	EXPORT_SYMBOL(rdma_set_ack_timeout);
 *	EXPORT_SYMBOL(rdma_set_ib_path);
 *	EXPORT_SYMBOL(rdma_set_reuseaddr);
 *	EXPORT_SYMBOL(rdma_set_afonly);
 *
 *      // helper
 *	EXPORT_SYMBOL(rdma_iw_cm_id);
 *	EXPORT_SYMBOL(rdma_res_to_id);
 *	EXPORT_SYMBOL(rdma_event_msg);
 *	EXPORT_SYMBOL(rdma_reject_msg);
 *	EXPORT_SYMBOL(rdma_consumer_reject_data);
 *
 *
 *      // 多播相关
 *	EXPORT_SYMBOL(rdma_join_multicast);
 *	EXPORT_SYMBOL(rdma_leave_multicast);
 * 4. 外部接口: 各种 handler(callback): 构建了 rdma_cm.ko 的上层模块(比如: rdma_ucm.ko)和下层模块的 ib_core.ko 之间的关系 
 *      - type 1: create id 时上层模块传入的 handler, rdma_cm.ko 通过这个 handler 将事件分发过去
 *              cma_listen_handler
 *
 *	- type 2: rdma_cm.ko 模块的事件分发到上层模块			__核心__
 *              cma_cm_event_handler
 *
 *      - type 3: create id 时 rdma_cm.ko 传入到底层 ib_core.ko 的 handler, 底层连接报文的处理就是这些 handler callback 到 rdma_cm.ko 层的
 *              cma_sidr_rep_handler
 *              cma_ib_handler
 *              cma_ib_req_handler
 *              cma_iw_handler // iwarp
 *              iw_conn_req_handler // iwarp
 *
 *      - type 4: 其他注册到底层的 handler
 *              cma_query_handler
 *              cma_ib_mc_handler
 *
 *      - type 5: cma_wq 里使用的 handler
 *              cma_work_handler
 *              addr_handler
 *
 * 5. bind 机制的实现
 *	- 核心结构: rdma_bind_list
 *	- 相关函数:
 *          - 创建: cma_alloc_port() -> cma_ps_alloc()
 *          - 销毁: cma_release_port() -> cma_ps_remove()
 *          - 查找: cma_ps_find()
 *          - 增 node: cma_bind_port()
 *          - 减 node: cma_release_port() -> cma_ps_remove()
 * */
// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 * Copyright (c) 1999-2019, Mellanox Technologies, Inc. All rights reserved.
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
 */

#include "linux/list.h"
#include <linux/completion.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/igmp.h>
#include <linux/xarray.h>
#include <linux/inetdevice.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <net/route.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/ip_fib.h>
#include <net/ip6_route.h>

#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/rdma_netlink.h>
#include <rdma/ib.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_sa.h>
#include <rdma/iw_cm.h>

#include "core_priv.h"
#include "cma_priv.h"
#include "cma_trace.h"

MODULE_AUTHOR("Sean Hefty");
MODULE_DESCRIPTION("Generic RDMA CM Agent");
MODULE_LICENSE("Dual BSD/GPL");

#define CMA_CM_RESPONSE_TIMEOUT 20
#define CMA_QUERY_CLASSPORT_INFO_TIMEOUT 3000
#define CMA_MAX_CM_RETRIES 15
#define CMA_CM_MRA_SETTING (IB_CM_MRA_FLAG_DELAY | 24)
#define CMA_IBOE_PACKET_LIFETIME 18
#define CMA_PREFERRED_ROCE_GID_TYPE IB_GID_TYPE_ROCE_UDP_ENCAP

static const char * const cma_events[] = {
	[RDMA_CM_EVENT_ADDR_RESOLVED]	 = "address resolved",
	[RDMA_CM_EVENT_ADDR_ERROR]	 = "address error",
	[RDMA_CM_EVENT_ROUTE_RESOLVED]	 = "route resolved ",
	[RDMA_CM_EVENT_ROUTE_ERROR]	 = "route error",
	[RDMA_CM_EVENT_CONNECT_REQUEST]	 = "connect request",
	[RDMA_CM_EVENT_CONNECT_RESPONSE] = "connect response",
	[RDMA_CM_EVENT_CONNECT_ERROR]	 = "connect error",
	[RDMA_CM_EVENT_UNREACHABLE]	 = "unreachable",
	[RDMA_CM_EVENT_REJECTED]	 = "rejected",
	[RDMA_CM_EVENT_ESTABLISHED]	 = "established",
	[RDMA_CM_EVENT_DISCONNECTED]	 = "disconnected",
	[RDMA_CM_EVENT_DEVICE_REMOVAL]	 = "device removal",
	[RDMA_CM_EVENT_MULTICAST_JOIN]	 = "multicast join",
	[RDMA_CM_EVENT_MULTICAST_ERROR]	 = "multicast error",
	[RDMA_CM_EVENT_ADDR_CHANGE]	 = "address change",
	[RDMA_CM_EVENT_TIMEWAIT_EXIT]	 = "timewait exit",
};

static void cma_set_mgid(struct rdma_id_private *id_priv, struct sockaddr *addr,
			 union ib_gid *mgid);

const char *__attribute_const__ rdma_event_msg(enum rdma_cm_event_type event)
{
	size_t index = event;

	return (index < ARRAY_SIZE(cma_events) && cma_events[index]) ?
			cma_events[index] : "unrecognized event";
}
EXPORT_SYMBOL(rdma_event_msg);

const char *__attribute_const__ rdma_reject_msg(struct rdma_cm_id *id,
						int reason)
{
	if (rdma_ib_or_roce(id->device, id->port_num))
		return ibcm_reject_msg(reason);

	if (rdma_protocol_iwarp(id->device, id->port_num))
		return iwcm_reject_msg(reason);

	WARN_ON_ONCE(1);
	return "unrecognized transport";
}
EXPORT_SYMBOL(rdma_reject_msg);

/**
 * rdma_is_consumer_reject - return true if the consumer rejected the connect
 *                           request.
 * @id: Communication identifier that received the REJECT event.
 * @reason: Value returned in the REJECT event status field.
 */
static bool rdma_is_consumer_reject(struct rdma_cm_id *id, int reason)
{
	if (rdma_ib_or_roce(id->device, id->port_num))
		return reason == IB_CM_REJ_CONSUMER_DEFINED;

	if (rdma_protocol_iwarp(id->device, id->port_num))
		return reason == -ECONNREFUSED;

	WARN_ON_ONCE(1);
	return false;
}

// helper 提取 private data
// 谁调用这个函数的? 得到 private data 后如何处理的?
//
// 作用不大, 上层协议发现连接被 reject 后, 提取下 private data , 看看 reject 的理由.
// private data 也是由上层协议定义的
const void *rdma_consumer_reject_data(struct rdma_cm_id *id,
				      struct rdma_cm_event *ev, u8 *data_len)
{
	const void *p;

	if (rdma_is_consumer_reject(id, ev->status)) {
		*data_len = ev->param.conn.private_data_len;
		p = ev->param.conn.private_data;
	} else {
		*data_len = 0;
		p = NULL;
	}
	return p;
}
EXPORT_SYMBOL(rdma_consumer_reject_data);

/**
 * rdma_iw_cm_id() - return the iw_cm_id pointer for this cm_id.
 * @id: Communication Identifier
 */
struct iw_cm_id *rdma_iw_cm_id(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (id->device->node_type == RDMA_NODE_RNIC)
		return id_priv->cm_id.iw;
	return NULL;
}
EXPORT_SYMBOL(rdma_iw_cm_id);

/**
 * rdma_res_to_id() - return the rdma_cm_id pointer for this restrack.
 * @res: rdma resource tracking entry pointer
 */
struct rdma_cm_id *rdma_res_to_id(struct rdma_restrack_entry *res)
{
	struct rdma_id_private *id_priv =
		container_of(res, struct rdma_id_private, res);

	return &id_priv->id;
}
EXPORT_SYMBOL(rdma_res_to_id);

static int cma_add_one(struct ib_device *device);
static void cma_remove_one(struct ib_device *device, void *client_data);

// 将其注册到 ib 核心模块里, 这样 底层的 ib 发生了什么事件就可以去处理了
static struct ib_client cma_client = {
	.name   = "cma",
	.add    = cma_add_one,
	.remove = cma_remove_one
};

static struct ib_sa_client sa_client;

// 对于 rdma 设备通过向 ib_core 模块注册一个 `cma_client`, 每次底层有 ib 设备添加的时候, 都会通过 cma_add_one cb 挂一个设备到 dev_list 上
// dev_list 挂载的结构 cma_device 是和底层的设备一一对应的, ref: ib_register_device() ->* add_client_context()
static LIST_HEAD(dev_list); // XXX ref: struct cma_device
static LIST_HEAD(listen_any_list); // 有些用户态应用会 listen any 的
static DEFINE_MUTEX(lock);
static struct workqueue_struct *cma_wq;
static unsigned int cma_pernet_id; // 用于索引 per_net 的 cma_pernet 结构

// 从 cma_init() 里可以看出来, 这个结构是一个 pernet 的核心结构
// 下面 xarray 的 index 都是 host 字节序的 sport, 即相同 sport 的不同 id 都挂在同一个 entry(即 bind_list) 下
// 注意: bind_list 以 sport 为 index, 是因为收报文的时候, 就是 dport 了
struct cma_pernet {
	struct xarray tcp_ps; // rdma cm 协议用了
	struct xarray udp_ps; // rdma cm 协议用了
	struct xarray ipoib_ps; // ipoib 协议用了
	struct xarray ib_ps;
};

static struct cma_pernet *cma_pernet(struct net *net)
{
	return net_generic(net, cma_pernet_id); // 在每个 net 结构的 cma_pernet_id 位置存储了一个指针, 指针的空间大小是 cma_pernet_operations->size
}

static
struct xarray *cma_pernet_xa(struct net *net, enum rdma_ucm_port_space ps)
{
	struct cma_pernet *pernet = cma_pernet(net);

	switch (ps) {
	case RDMA_PS_TCP:
		return &pernet->tcp_ps;
	case RDMA_PS_UDP:
		return &pernet->udp_ps;
	case RDMA_PS_IPOIB:
		return &pernet->ipoib_ps;
	case RDMA_PS_IB:
		return &pernet->ib_ps;
	default:
		return NULL;
	}
}

// cma 作为 ib driver 的上层使用者, 为每个 device 创建一个抽象
struct cma_device {
	struct list_head	list;
	struct ib_device	*device;
	struct completion	comp;
	refcount_t refcount;
	struct list_head	id_list;
	enum ib_gid_type	*default_gid_type; // 一个设备有很多 port, 记录所有 port 的 gid
	u8			*default_roce_tos; // 数组, 每个 port 一个元素
};

// bind 机制的实现
//    创建: cma_alloc_port() -> cma_ps_alloc()
//    销毁: cma_release_port() -> cma_ps_remove() // owners 上的 node 减光了就自动 remove 咯
//    查找: cma_ps_find()
//    增 node: cma_bind_port()
//    减 node: cma_release_port() -> cma_ps_remove()
//
// convention: bind_list
struct rdma_bind_list {
	enum rdma_ucm_port_space ps;
	struct hlist_head	owners;  // node 是 struct rdma_id_private *id_priv->node 
	unsigned short		port;
};

// 代码里都没有用这个结构
// drivers/infiniband/core/cma.c
struct class_port_info_context {
	struct ib_class_port_info	*class_port_info;
	struct ib_device		*device;
	struct completion		done;
	struct ib_sa_query		*sa_query;
	u8				port_num;
};

// 在指定的 port space 里分配 port
static int cma_ps_alloc(struct net *net, enum rdma_ucm_port_space ps,
			struct rdma_bind_list *bind_list, int snum)
{
	struct xarray *xa = cma_pernet_xa(net, ps);

	return xa_insert(xa, snum, bind_list, GFP_KERNEL);
}

static struct rdma_bind_list *cma_ps_find(struct net *net,
					  enum rdma_ucm_port_space ps, int snum)
{
	struct xarray *xa = cma_pernet_xa(net, ps);

	return xa_load(xa, snum);
}

static void cma_ps_remove(struct net *net, enum rdma_ucm_port_space ps,
			  int snum)
{
	struct xarray *xa = cma_pernet_xa(net, ps);

	xa_erase(xa, snum);
}

enum {
	CMA_OPTION_AFONLY, // 只能用 id_priv->afonly 指定的 af 咯 ???
};

void cma_dev_get(struct cma_device *cma_dev)
{
	refcount_inc(&cma_dev->refcount);
}

void cma_dev_put(struct cma_device *cma_dev)
{
	if (refcount_dec_and_test(&cma_dev->refcount))
		complete(&cma_dev->comp);	// 注意这里, 唤醒了 cma_dev 上等待的一个实体, 因为 put 的时候如果能进来, 说明当前 做 put 的 thread 是最后一个持有 dev ref 的, 所以其要承担下唤醒的责任
}

// helper
struct cma_device *cma_enum_devices_by_ibdev(cma_device_filter	filter,
					     void		*cookie)
{
	struct cma_device *cma_dev;
	struct cma_device *found_cma_dev = NULL;

	mutex_lock(&lock);

	// 遍历 dev_list , 根据 filter 函数找到一个符合条件的设备, 返回回去
	list_for_each_entry(cma_dev, &dev_list, list)
		if (filter(cma_dev->device, cookie)) {
			found_cma_dev = cma_dev;
			break;
		}

	if (found_cma_dev)
		cma_dev_get(found_cma_dev);
	mutex_unlock(&lock);
	return found_cma_dev;
}

// 通过 configfs 可以设置设备的 default gid type / tos
int cma_get_default_gid_type(struct cma_device *cma_dev,
			     unsigned int port)
{
	if (!rdma_is_port_valid(cma_dev->device, port))
		return -EINVAL;

	return cma_dev->default_gid_type[port - rdma_start_port(cma_dev->device)];
}

int cma_set_default_gid_type(struct cma_device *cma_dev,
			     unsigned int port,
			     enum ib_gid_type default_gid_type)
{
	unsigned long supported_gids;

	if (!rdma_is_port_valid(cma_dev->device, port))
		return -EINVAL;

	if (default_gid_type == IB_GID_TYPE_IB && /* 不是想改成 IB 就改成 IB 的 */
	    rdma_protocol_roce_eth_encap(cma_dev->device, port))
		default_gid_type = IB_GID_TYPE_ROCE;

	supported_gids = roce_gid_type_mask_support(cma_dev->device, port);

	if (!(supported_gids & 1 << default_gid_type))
		return -EINVAL;

	cma_dev->default_gid_type[port - rdma_start_port(cma_dev->device)] =
		default_gid_type;

	return 0;
}

int cma_get_default_roce_tos(struct cma_device *cma_dev, unsigned int port)
{
	if (!rdma_is_port_valid(cma_dev->device, port))
		return -EINVAL;

	return cma_dev->default_roce_tos[port - rdma_start_port(cma_dev->device)];
}

int cma_set_default_roce_tos(struct cma_device *cma_dev, unsigned int port,
			     u8 default_roce_tos)
{
	if (!rdma_is_port_valid(cma_dev->device, port))
		return -EINVAL;

	cma_dev->default_roce_tos[port - rdma_start_port(cma_dev->device)] =
		 default_roce_tos;

	return 0;
}
struct ib_device *cma_get_ib_dev(struct cma_device *cma_dev)
{
	return cma_dev->device;
}

/*
 * Device removal can occur at anytime, so we need extra handling to
 * serialize notifying the user of device removal with other callbacks.
 * We do this by disabling removal notification while a callback is in process,
 * and reporting it after the callback completes.
 */

struct cma_multicast {
	struct rdma_id_private *id_priv;
	struct ib_sa_multicast *sa_mc;
	struct list_head	list;
	void			*context;
	struct sockaddr_storage	addr;
	u8			join_state;
};

struct cma_work {
	struct work_struct	work; // first-member inherit, work 机
	struct rdma_id_private	*id;
	enum rdma_cm_state	old_state;
	enum rdma_cm_state	new_state;
	struct rdma_cm_event	event;
};

union cma_ip_addr {
	struct in6_addr ip6;
	struct {
		__be32 pad[3];
		__be32 addr;
	} ip4;
};

// ref: IB Spec Vol1 A11.4
// 在 MAD REQ 报文的 private data 里携带的
struct cma_hdr {
	u8 cma_version;
	u8 ip_version;	/* IP version: 7:4 */
	__be16 port;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

#define CMA_VERSION 0x00

struct cma_req_info {
	struct sockaddr_storage listen_addr_storage;
	struct sockaddr_storage src_addr_storage;
	struct ib_device *device;
	union ib_gid local_gid;
	__be64 service_id;
	int port;
	bool has_gid;
	u16 pkey;
};

// return 1 标识当前状态是 comp
//
// id_priv 的状态是 comp 的话就切换 exch
static int cma_comp_exch(struct rdma_id_private *id_priv,
			 enum rdma_cm_state comp, enum rdma_cm_state exch)
{
	unsigned long flags;
	int ret;

	/*
	 * The FSM uses a funny double locking where state is protected by both
	 * the handler_mutex and the spinlock. State is not allowed to change
	 * to/from a handler_mutex protected value without also holding
	 * handler_mutex.
	 */
	if (comp == RDMA_CM_CONNECT || exch == RDMA_CM_CONNECT)
		lockdep_assert_held(&id_priv->handler_mutex);

	spin_lock_irqsave(&id_priv->lock, flags);
	if ((ret = (id_priv->state == comp)))
		id_priv->state = exch;
	spin_unlock_irqrestore(&id_priv->lock, flags);
	return ret;
}

static inline u8 cma_get_ip_ver(const struct cma_hdr *hdr)
{
	return hdr->ip_version >> 4;
}

static inline void cma_set_ip_ver(struct cma_hdr *hdr, u8 ip_ver)
{
	hdr->ip_version = (ip_ver << 4) | (hdr->ip_version & 0xF);
}

// 组播相关, igmp
static int cma_igmp_send(struct net_device *ndev, union ib_gid *mgid, bool join)
{
	struct in_device *in_dev = NULL;

	if (ndev) {
		rtnl_lock();
		in_dev = __in_dev_get_rtnl(ndev);
		if (in_dev) {
			if (join)
				ip_mc_inc_group(in_dev,
						*(__be32 *)(mgid->raw + 12));
			else
				ip_mc_dec_group(in_dev,
						*(__be32 *)(mgid->raw + 12));
		}
		rtnl_unlock();
	}
	return (in_dev) ? 0 : -ENODEV;
}

// helper: 为 id_priv 查找路由后可以得到 出口 cma_dev, 将其 attach 到 id 上
static void _cma_attach_to_dev(struct rdma_id_private *id_priv,
			       struct cma_device *cma_dev)
{
	cma_dev_get(cma_dev);
	id_priv->cma_dev = cma_dev;
	id_priv->id.device = cma_dev->device;
	id_priv->id.route.addr.dev_addr.transport =
		rdma_node_get_transport(cma_dev->device->node_type);
	list_add_tail(&id_priv->list, &cma_dev->id_list);
	rdma_restrack_add(&id_priv->res);

	trace_cm_id_attach(id_priv, cma_dev->device);
}

static void cma_attach_to_dev(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev)
{
	_cma_attach_to_dev(id_priv, cma_dev);
	id_priv->gid_type =
		cma_dev->default_gid_type[id_priv->id.port_num -
					  rdma_start_port(cma_dev->device)];
}

static void cma_release_dev(struct rdma_id_private *id_priv)
{
	mutex_lock(&lock);
	list_del(&id_priv->list);
	cma_dev_put(id_priv->cma_dev);
	id_priv->cma_dev = NULL;
	mutex_unlock(&lock);
}

static inline struct sockaddr *cma_src_addr(struct rdma_id_private *id_priv)
{
	return (struct sockaddr *) &id_priv->id.route.addr.src_addr;
}

static inline struct sockaddr *cma_dst_addr(struct rdma_id_private *id_priv)
{
	return (struct sockaddr *) &id_priv->id.route.addr.dst_addr;
}

static inline unsigned short cma_family(struct rdma_id_private *id_priv)
{
	return id_priv->id.route.addr.src_addr.ss_family;
}

// helper
// UD 服务需要的
static int cma_set_qkey(struct rdma_id_private *id_priv, u32 qkey)
{
	struct ib_sa_mcmember_rec rec;
	int ret = 0;

	if (id_priv->qkey) {
		if (qkey && id_priv->qkey != qkey)
			return -EINVAL;
		return 0;
	}

	if (qkey) {
		id_priv->qkey = qkey;
		return 0;
	}

	// qkey 为 0 就走下来
	switch (id_priv->id.ps) {
	case RDMA_PS_UDP:
	case RDMA_PS_IB:
		id_priv->qkey = RDMA_UDP_QKEY;
		break;
	case RDMA_PS_IPOIB:
		ib_addr_get_mgid(&id_priv->id.route.addr.dev_addr, &rec.mgid);
		ret = ib_sa_get_mcmember_rec(id_priv->id.device,
					     id_priv->id.port_num, &rec.mgid,
					     &rec);
		if (!ret)
			id_priv->qkey = be32_to_cpu(rec.qkey);
		break;
	default:
		break;
	}
	return ret;
}

// helper:
// sib -> dev_addr
static void cma_translate_ib(struct sockaddr_ib *sib, struct rdma_dev_addr *dev_addr)
{
	dev_addr->dev_type = ARPHRD_INFINIBAND; // 地址类型
	rdma_addr_set_sgid(dev_addr, (union ib_gid *) &sib->sib_addr); // 地址 sgid
	ib_addr_set_pkey(dev_addr, ntohs(sib->sib_pkey)); // pkey
}

// 将 addr -> dev_addr
static int cma_translate_addr(struct sockaddr *addr, struct rdma_dev_addr *dev_addr)
{
	int ret;

	if (addr->sa_family != AF_IB) {
		ret = rdma_translate_ip(addr, dev_addr); // 用 addr 里的 ip 地址找到一个设备, 然后根据设备上的信息来设置 dev_addr
	} else { // userspace 可以直接指定 AF_IB, 然后传入 gid 的
		cma_translate_ib((struct sockaddr_ib *) addr, dev_addr);
		ret = 0;
	}

	return ret;
}

// device 的 port 是否符合条件
// - namespace 符合 id_priv 的 namespace
// - dev_type 匹配
// - gid_type 匹配
//
// 如果都匹配的话, 将 sgid 的信息 sgid_attr 返回
static const struct ib_gid_attr *
cma_validate_port(struct ib_device *device, u8 port,
		  enum ib_gid_type gid_type,
		  union ib_gid *gid,
		  struct rdma_id_private *id_priv)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	int bound_if_index = dev_addr->bound_dev_if;
	const struct ib_gid_attr *sgid_attr;
	int dev_type = dev_addr->dev_type;
	struct net_device *ndev = NULL;

	// dev_addr 的 net 是否可以访问这个 ib_device
	if (!rdma_dev_access_netns(device, id_priv->id.route.addr.dev_addr.net))
		return ERR_PTR(-ENODEV);

	if ((dev_type == ARPHRD_INFINIBAND) && !rdma_protocol_ib(device, port))
		return ERR_PTR(-ENODEV);

	if ((dev_type != ARPHRD_INFINIBAND) && rdma_protocol_ib(device, port))
		return ERR_PTR(-ENODEV);

	// id_priv 里的 dev_addr 是 Ether, 然后 ib_device 是 roce
	if (dev_type == ARPHRD_ETHER && rdma_protocol_roce(device, port)) { // HERE
		ndev = dev_get_by_index(dev_addr->net, bound_if_index);
		if (!ndev)
			return ERR_PTR(-ENODEV);
	} else {
		gid_type = IB_GID_TYPE_IB;
	}

	sgid_attr = rdma_find_gid_by_port(device, gid, gid_type, port, ndev);
	if (ndev)
		dev_put(ndev);
	return sgid_attr;
}

// helper
// 设置 sgid_attr
static void cma_bind_sgid_attr(struct rdma_id_private *id_priv,
			       const struct ib_gid_attr *sgid_attr)
{
	WARN_ON(id_priv->id.route.addr.dev_addr.sgid_attr);
	id_priv->id.route.addr.dev_addr.sgid_attr = sgid_attr;
}

/**
 * cma_acquire_dev_by_src_ip - Acquire cma device, port, gid attribute
 * based on source ip address.
 * @id_priv:	cm_id which should be bound to cma device
 *
 * cma_acquire_dev_by_src_ip() binds cm id to cma device, port and GID attribute
 * based on source IP address. It returns 0 on success or error code otherwise.
 * It is applicable to active and passive side cm_id.
 *
 * 根据 src ip 找到一个 cma_dev 保存到 id_priv 里
 */
static int cma_acquire_dev_by_src_ip(struct rdma_id_private *id_priv)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	const struct ib_gid_attr *sgid_attr;
	union ib_gid gid, iboe_gid, *gidp;
	struct cma_device *cma_dev;
	enum ib_gid_type gid_type;
	int ret = -ENODEV;
	unsigned int port;

	if (dev_addr->dev_type != ARPHRD_INFINIBAND &&
	    id_priv->id.ps == RDMA_PS_IPOIB)
		return -EINVAL;

	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.src_addr,
		    &iboe_gid);

	memcpy(&gid, dev_addr->src_dev_addr +
	       rdma_addr_gid_offset(dev_addr), sizeof(gid));

	mutex_lock(&lock);
	list_for_each_entry(cma_dev, &dev_list, list) { // 遍历所有的 cma_dev 的 所有 port, 找到其中一个 port 其和 id_priv 的 dev_addr 可以匹配上, 然后设置 id_priv -> cma_dev 的关系
		rdma_for_each_port (cma_dev->device, port) {
			gidp = rdma_protocol_roce(cma_dev->device, port) ?
			       &iboe_gid : &gid; // iboe_gid 是根据 src_addr 得到的, gid 也是根据 src_dev_addr 得到的
			gid_type = cma_dev->default_gid_type[port - 1]; // port - 1: ref cma_set_default_gid_type
			sgid_attr = cma_validate_port(cma_dev->device, port,
						      gid_type, gidp, id_priv); // 判断当前 遍历的这个 port 是不是和 id_priv dev_addr 匹配的
			if (!IS_ERR(sgid_attr)) {
				id_priv->id.port_num = port; // 为什么将 这个 port 绑定到这个 id 上
				cma_bind_sgid_attr(id_priv, sgid_attr);
				cma_attach_to_dev(id_priv, cma_dev);
				ret = 0;
				goto out;
			}
		}
	}
out:
	mutex_unlock(&lock);
	return ret;
}

/**
 * cma_ib_acquire_dev - Acquire cma device, port and SGID attribute
 * @id_priv:		cm id to bind to cma device
 * @listen_id_priv:	listener cm id to match against
 * @req:		Pointer to req structure containaining incoming
 *			request information
 * cma_ib_acquire_dev() acquires cma device, port and SGID attribute when
 * rdma device matches for listen_id and incoming request. It also verifies
 * that a GID table entry is present for the source address.
 * Returns 0 on success, or returns error code otherwise.
 */
// id_priv 是 listen_id 到来的 new conn 的 id
//
// 现在根据 listn_id 以及 req 里的信息, 为这个 id 绑定 出口设备 以及 sgid_attr
static int cma_ib_acquire_dev(struct rdma_id_private *id_priv,
			      const struct rdma_id_private *listen_id_priv,
			      struct cma_req_info *req)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	const struct ib_gid_attr *sgid_attr;
	enum ib_gid_type gid_type;
	union ib_gid gid;

	if (dev_addr->dev_type != ARPHRD_INFINIBAND &&
	    id_priv->id.ps == RDMA_PS_IPOIB)
		return -EINVAL;

	if (rdma_protocol_roce(req->device, req->port))
		rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.src_addr, // roce 协议的 gid 就是 ip地址转换过来的
			    &gid);
	else
		memcpy(&gid, dev_addr->src_dev_addr +
		       rdma_addr_gid_offset(dev_addr), sizeof(gid));

	/* ah! magic num ???? */
	gid_type = listen_id_priv->cma_dev->default_gid_type[req->port - 1]; // port - 1: ref cma_set_default_gid_type.

	sgid_attr = cma_validate_port(req->device, req->port,
				      gid_type, &gid, id_priv);
	if (IS_ERR(sgid_attr))
		return PTR_ERR(sgid_attr);

	id_priv->id.port_num = req->port;
	cma_bind_sgid_attr(id_priv, sgid_attr);
	/* Need to acquire lock to protect against reader
	 * of cma_dev->id_list such as cma_netdev_callback() and
	 * cma_process_remove().
	 */
	mutex_lock(&lock);
	cma_attach_to_dev(id_priv, listen_id_priv->cma_dev);
	mutex_unlock(&lock);
	return 0;
}

// iwarp 相关
static int cma_iw_acquire_dev(struct rdma_id_private *id_priv,
			      const struct rdma_id_private *listen_id_priv)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	const struct ib_gid_attr *sgid_attr;
	struct cma_device *cma_dev;
	enum ib_gid_type gid_type;
	int ret = -ENODEV;
	unsigned int port;
	union ib_gid gid;

	if (dev_addr->dev_type != ARPHRD_INFINIBAND &&
	    id_priv->id.ps == RDMA_PS_IPOIB)
		return -EINVAL;

	memcpy(&gid, dev_addr->src_dev_addr +
	       rdma_addr_gid_offset(dev_addr), sizeof(gid));

	mutex_lock(&lock);

	cma_dev = listen_id_priv->cma_dev;
	port = listen_id_priv->id.port_num;
	gid_type = listen_id_priv->gid_type;
	sgid_attr = cma_validate_port(cma_dev->device, port,
				      gid_type, &gid, id_priv);
	if (!IS_ERR(sgid_attr)) {
		id_priv->id.port_num = port;
		cma_bind_sgid_attr(id_priv, sgid_attr);
		ret = 0;
		goto out;
	}

	list_for_each_entry(cma_dev, &dev_list, list) {
		rdma_for_each_port (cma_dev->device, port) {
			if (listen_id_priv->cma_dev == cma_dev &&
			    listen_id_priv->id.port_num == port)
				continue;

			gid_type = cma_dev->default_gid_type[port - 1];
			sgid_attr = cma_validate_port(cma_dev->device, port,
						      gid_type, &gid, id_priv);
			if (!IS_ERR(sgid_attr)) {
				id_priv->id.port_num = port;
				cma_bind_sgid_attr(id_priv, sgid_attr);
				ret = 0;
				goto out;
			}
		}
	}

out:
	if (!ret)
		cma_attach_to_dev(id_priv, cma_dev);

	mutex_unlock(&lock);
	return ret;
}

/*
 * Select the source IB device and address to reach the destination IB address.
 */
// __重要__ 为 id_priv 选择出口设备, 出口地址
//
// roce 不用这个函数
static int cma_resolve_ib_dev(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev, *cur_dev;
	struct sockaddr_ib *addr; // 目的地址
	union ib_gid gid, sgid, *dgid; // 目的 gid
	unsigned int p;
	u16 pkey, index;
	enum ib_port_state port_state;
	int i;

	cma_dev = NULL;
	addr = (struct sockaddr_ib *) cma_dst_addr(id_priv);
	dgid = (union ib_gid *) &addr->sib_addr;
	pkey = ntohs(addr->sib_pkey);

	mutex_lock(&lock);
	list_for_each_entry(cur_dev, &dev_list, list) {
		rdma_for_each_port (cur_dev->device, p) { // 检查 dev_list 中每个设备的每个 port
			if (!rdma_cap_af_ib(cur_dev->device, p)) // roce 可以通过这个检查
				continue;

			// device 这个设备的 p 这个 port 可以和 pkey 匹配上就返回 0
			if (ib_find_cached_pkey(cur_dev->device, p, pkey, &index))
				continue;

			if (ib_get_cached_port_state(cur_dev->device, p, &port_state))
				continue;
			for (i = 0; !rdma_query_gid(cur_dev->device,
						    p, i, &gid); // 获取到对应的 gid
			     i++) {
				if (!memcmp(&gid, dgid, sizeof(gid))) { // 设备的 gid  和 dgid 匹配, 说明是 loopback 么么 ???
					cma_dev = cur_dev;
					sgid = gid;
					id_priv->id.port_num = p;
					goto found;
				}

				if (!cma_dev && (gid.global.subnet_prefix ==	// 说明 dgid 和这个设备的 gid 是在同一个 subnet 里, 那么可以通过这个设备出去
				    dgid->global.subnet_prefix) &&
				    port_state == IB_PORT_ACTIVE) {
					cma_dev = cur_dev;
					sgid = gid;
					id_priv->id.port_num = p;
					goto found;
				}
			}
		}
	}
	mutex_unlock(&lock);
	return -ENODEV;

found:
	cma_attach_to_dev(id_priv, cma_dev);
	mutex_unlock(&lock);
	addr = (struct sockaddr_ib *)cma_src_addr(id_priv);
	memcpy(&addr->sib_addr, &sgid, sizeof(sgid));
	cma_translate_ib(addr, &id_priv->id.route.addr.dev_addr);
	return 0;
}

static void cma_id_get(struct rdma_id_private *id_priv)
{
	refcount_inc(&id_priv->refcount);
}

static void cma_id_put(struct rdma_id_private *id_priv)
{
	if (refcount_dec_and_test(&id_priv->refcount))
		complete(&id_priv->comp); // 如果我是持有这个 id 的最后一个 thread, 我要负责唤醒其上的调度实体的
}

// event_handler 的调用: cma_cm_event_handler
// 关注传入的参数
//     - event_handler: 通知上层的 callback
//     - 一个 id 的关键参数: ps, qp_type
//     - listen_id 是 new conn id 的 parent
static struct rdma_id_private *
__rdma_create_id(struct net *net, rdma_cm_event_handler event_handler,
		 void *context, enum rdma_ucm_port_space ps,
		 enum ib_qp_type qp_type, const struct rdma_id_private *parent)
{
	struct rdma_id_private *id_priv;

	id_priv = kzalloc(sizeof *id_priv, GFP_KERNEL);
	if (!id_priv)
		return ERR_PTR(-ENOMEM);

	id_priv->state = RDMA_CM_IDLE;
	id_priv->id.context = context;	// rdma_cm 层 opaque 的, 上层知道是什么
	id_priv->id.event_handler = event_handler; // 参数是 id_priv->id
	id_priv->id.ps = ps;
	id_priv->id.qp_type = qp_type;
	id_priv->tos_set = false;
	id_priv->timeout_set = false;
	id_priv->gid_type = IB_GID_TYPE_IB; // 默认值, 没有什么意义, 之后还会改的
	spin_lock_init(&id_priv->lock);
	mutex_init(&id_priv->qp_mutex);
	init_completion(&id_priv->comp);
	refcount_set(&id_priv->refcount, 1);
	mutex_init(&id_priv->handler_mutex);
	INIT_LIST_HEAD(&id_priv->listen_list);
	INIT_LIST_HEAD(&id_priv->mc_list);
	get_random_bytes(&id_priv->seq_num, sizeof id_priv->seq_num);
	id_priv->id.route.addr.dev_addr.net = get_net(net);
	id_priv->seq_num &= 0x00ffffff;

	rdma_restrack_new(&id_priv->res, RDMA_RESTRACK_CM_ID);
	if (parent)
		rdma_restrack_parent_name(&id_priv->res, &parent->res);

	return id_priv;
}

// 内核使用 rdmacm 功能调用这个函数
struct rdma_cm_id *
__rdma_create_kernel_id(struct net *net, rdma_cm_event_handler event_handler,
			void *context, enum rdma_ucm_port_space ps,
			enum ib_qp_type qp_type, const char *caller)
{
	struct rdma_id_private *ret;

	ret = __rdma_create_id(net, event_handler, context, ps, qp_type, NULL);
	if (IS_ERR(ret))
		return ERR_CAST(ret);

	rdma_restrack_set_name(&ret->res, caller);
	return &ret->id;
}
EXPORT_SYMBOL(__rdma_create_kernel_id);

// 用户态使用 rdmacm 功能调用这个函数
struct rdma_cm_id *rdma_create_user_id(rdma_cm_event_handler event_handler,
				       void *context,
				       enum rdma_ucm_port_space ps,
				       enum ib_qp_type qp_type)
{
	struct rdma_id_private *ret;

	ret = __rdma_create_id(current->nsproxy->net_ns, event_handler, context,
			       ps, qp_type, NULL);
	if (IS_ERR(ret))
		return ERR_CAST(ret);

	rdma_restrack_set_name(&ret->res, NULL);
	return &ret->id;
}
EXPORT_SYMBOL(rdma_create_user_id);

static int cma_init_ud_qp(struct rdma_id_private *id_priv, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	// 标准 verbs 接口咯, 要一路下去到 设备层的
	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret)
		return ret;

	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_modify_qp(qp, &qp_attr, IB_QP_STATE);
	if (ret)
		return ret;

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	ret = ib_modify_qp(qp, &qp_attr, IB_QP_STATE | IB_QP_SQ_PSN);

	return ret;
}

// 利用 verbs 接口, 修改 qp 状态咯
static int cma_init_conn_qp(struct rdma_id_private *id_priv, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	return ib_modify_qp(qp, &qp_attr, qp_attr_mask);
}

// 底层接口的简单调用
int rdma_create_qp(struct rdma_cm_id *id, struct ib_pd *pd,
		   struct ib_qp_init_attr *qp_init_attr)
{
	struct rdma_id_private *id_priv;
	struct ib_qp *qp;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (id->device != pd->device) {
		ret = -EINVAL;
		goto out_err;
	}

	qp_init_attr->port_num = id->port_num;
	qp = ib_create_qp(pd, qp_init_attr);
	if (IS_ERR(qp)) {
		ret = PTR_ERR(qp);
		goto out_err;
	}

	if (id->qp_type == IB_QPT_UD)
		ret = cma_init_ud_qp(id_priv, qp);
	else
		ret = cma_init_conn_qp(id_priv, qp);
	if (ret)
		goto out_destroy;

	id->qp = qp;
	id_priv->qp_num = qp->qp_num;
	id_priv->srq = (qp->srq != NULL);
	trace_cm_qp_create(id_priv, pd, qp_init_attr, 0);
	return 0;
out_destroy:
	ib_destroy_qp(qp);
out_err:
	trace_cm_qp_create(id_priv, pd, qp_init_attr, ret);
	return ret;
}
EXPORT_SYMBOL(rdma_create_qp);

void rdma_destroy_qp(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;

	id_priv = container_of(id, struct rdma_id_private, id);
	trace_cm_qp_destroy(id_priv);
	mutex_lock(&id_priv->qp_mutex);
	ib_destroy_qp(id_priv->id.qp);
	id_priv->id.qp = NULL;
	mutex_unlock(&id_priv->qp_mutex);
}
EXPORT_SYMBOL(rdma_destroy_qp);

// 底层接口简单封装
static int cma_modify_qp_rtr(struct rdma_id_private *id_priv,
			     struct rdma_conn_param *conn_param)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	mutex_lock(&id_priv->qp_mutex);
	if (!id_priv->id.qp) {
		ret = 0;
		goto out;
	}

	/* Need to update QP attributes from default values. */
	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	if (ret)
		goto out;

	ret = ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
	if (ret)
		goto out;

	qp_attr.qp_state = IB_QPS_RTR;
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	if (ret)
		goto out;

	BUG_ON(id_priv->cma_dev->device != id_priv->id.device);

	if (conn_param)
		qp_attr.max_dest_rd_atomic = conn_param->responder_resources;
	ret = ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
out:
	mutex_unlock(&id_priv->qp_mutex);
	return ret;
}

// 底层接口简单封装
static int cma_modify_qp_rts(struct rdma_id_private *id_priv,
			     struct rdma_conn_param *conn_param)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	mutex_lock(&id_priv->qp_mutex);
	if (!id_priv->id.qp) {
		ret = 0;
		goto out;
	}

	qp_attr.qp_state = IB_QPS_RTS;
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	if (ret)
		goto out;

	if (conn_param)
		qp_attr.max_rd_atomic = conn_param->initiator_depth;
	ret = ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
out:
	mutex_unlock(&id_priv->qp_mutex);
	return ret;
}

// 底层接口简单封装
static int cma_modify_qp_err(struct rdma_id_private *id_priv)
{
	struct ib_qp_attr qp_attr;
	int ret;

	mutex_lock(&id_priv->qp_mutex);
	if (!id_priv->id.qp) {
		ret = 0;
		goto out;
	}

	qp_attr.qp_state = IB_QPS_ERR;
	ret = ib_modify_qp(id_priv->id.qp, &qp_attr, IB_QP_STATE);
out:
	mutex_unlock(&id_priv->qp_mutex);
	return ret;
}

static int cma_ib_init_qp_attr(struct rdma_id_private *id_priv,
			       struct ib_qp_attr *qp_attr, int *qp_attr_mask)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	int ret;
	u16 pkey;

	if (rdma_cap_eth_ah(id_priv->id.device, id_priv->id.port_num))
		pkey = 0xffff; // IB Spec vol1 ch10.9.1.2, 所以 roce 场景 pkey 没有什么用
	else
		pkey = ib_addr_get_pkey(dev_addr);

	ret = ib_find_cached_pkey(id_priv->id.device, id_priv->id.port_num,
				  pkey, &qp_attr->pkey_index);
	if (ret)
		return ret;

	qp_attr->port_num = id_priv->id.port_num;
	*qp_attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT;

	if (id_priv->id.qp_type == IB_QPT_UD) {
		ret = cma_set_qkey(id_priv, 0);
		if (ret)
			return ret;

		qp_attr->qkey = id_priv->qkey;
		*qp_attr_mask |= IB_QP_QKEY;
	} else {
		qp_attr->qp_access_flags = 0;
		*qp_attr_mask |= IB_QP_ACCESS_FLAGS;
	}
	return 0;
}

int rdma_init_qp_attr(struct rdma_cm_id *id, struct ib_qp_attr *qp_attr,
		       int *qp_attr_mask)
{
	struct rdma_id_private *id_priv;
	int ret = 0;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (rdma_cap_ib_cm(id->device, id->port_num)) { // roce 走这里
		if (!id_priv->cm_id.ib || (id_priv->id.qp_type == IB_QPT_UD))
			ret = cma_ib_init_qp_attr(id_priv, qp_attr, qp_attr_mask);
		else
			ret = ib_cm_init_qp_attr(id_priv->cm_id.ib, qp_attr,
						 qp_attr_mask);

		if (qp_attr->qp_state == IB_QPS_RTR)
			qp_attr->rq_psn = id_priv->seq_num;
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) {
		if (!id_priv->cm_id.iw) {
			qp_attr->qp_access_flags = 0;
			*qp_attr_mask = IB_QP_STATE | IB_QP_ACCESS_FLAGS;
		} else
			ret = iw_cm_init_qp_attr(id_priv->cm_id.iw, qp_attr,
						 qp_attr_mask);
		qp_attr->port_num = id_priv->id.port_num;
		*qp_attr_mask |= IB_QP_PORT;
	} else
		ret = -ENOSYS;

	if ((*qp_attr_mask & IB_QP_TIMEOUT) && id_priv->timeout_set)
		qp_attr->timeout = id_priv->timeout;

	return ret;
}
EXPORT_SYMBOL(rdma_init_qp_attr);

static inline bool cma_zero_addr(const struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return ipv4_is_zeronet(((struct sockaddr_in *)addr)->sin_addr.s_addr);
	case AF_INET6:
		return ipv6_addr_any(&((struct sockaddr_in6 *)addr)->sin6_addr);
	case AF_IB:
		return ib_addr_any(&((struct sockaddr_ib *)addr)->sib_addr);
	default:
		return false;
	}
}

static inline bool cma_loopback_addr(const struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return ipv4_is_loopback(
			((struct sockaddr_in *)addr)->sin_addr.s_addr);
	case AF_INET6:
		return ipv6_addr_loopback(
			&((struct sockaddr_in6 *)addr)->sin6_addr);
	case AF_IB:
		return ib_addr_loopback(
			&((struct sockaddr_ib *)addr)->sib_addr);
	default:
		return false;
	}
}

static inline bool cma_any_addr(const struct sockaddr *addr)
{
	return cma_zero_addr(addr) || cma_loopback_addr(addr);
}

// 不等 返回 true (1), 相等返回 false (0)
static int cma_addr_cmp(const struct sockaddr *src, const struct sockaddr *dst)
{
	if (src->sa_family != dst->sa_family)
		return -1;

	switch (src->sa_family) {
	case AF_INET:
		return ((struct sockaddr_in *)src)->sin_addr.s_addr !=
		       ((struct sockaddr_in *)dst)->sin_addr.s_addr;
	case AF_INET6: {
		struct sockaddr_in6 *src_addr6 = (struct sockaddr_in6 *)src;
		struct sockaddr_in6 *dst_addr6 = (struct sockaddr_in6 *)dst;
		bool link_local;

		if (ipv6_addr_cmp(&src_addr6->sin6_addr,
					  &dst_addr6->sin6_addr))
			return 1;
		link_local = ipv6_addr_type(&dst_addr6->sin6_addr) &
			     IPV6_ADDR_LINKLOCAL;
		/* Link local must match their scope_ids */
		return link_local ? (src_addr6->sin6_scope_id !=
				     dst_addr6->sin6_scope_id) :
				    0;
	}

	default:
		return ib_addr_cmp(&((struct sockaddr_ib *) src)->sib_addr,
				   &((struct sockaddr_ib *) dst)->sib_addr);
	}
}

static __be16 cma_port(const struct sockaddr *addr)
{
	struct sockaddr_ib *sib;

	switch (addr->sa_family) {
	case AF_INET:
		return ((struct sockaddr_in *) addr)->sin_port;
	case AF_INET6:
		return ((struct sockaddr_in6 *) addr)->sin6_port;
	case AF_IB:
		sib = (struct sockaddr_ib *) addr;
		return htons((u16) (be64_to_cpu(sib->sib_sid) &
				    be64_to_cpu(sib->sib_sid_mask))); // 这里也可以看出 sib_sid 被 mask 后的 低 16 b 里编码了 port
	default:
		return 0;
	}
}

static inline int cma_any_port(const struct sockaddr *addr)
{
	return !cma_port(addr);
}

// ib 会用, roce 不会用
static void cma_save_ib_info(struct sockaddr *src_addr,
			     struct sockaddr *dst_addr,
			     const struct rdma_cm_id *listen_id,
			     const struct sa_path_rec *path)
{
	struct sockaddr_ib *listen_ib, *ib;

	listen_ib = (struct sockaddr_ib *) &listen_id->route.addr.src_addr;
	if (src_addr) {
		ib = (struct sockaddr_ib *)src_addr;
		ib->sib_family = AF_IB;
		if (path) {
			ib->sib_pkey = path->pkey;
			ib->sib_flowinfo = path->flow_label;
			memcpy(&ib->sib_addr, &path->sgid, 16);
			ib->sib_sid = path->service_id;
			ib->sib_scope_id = 0;
		} else {
			ib->sib_pkey = listen_ib->sib_pkey;
			ib->sib_flowinfo = listen_ib->sib_flowinfo;
			ib->sib_addr = listen_ib->sib_addr;
			ib->sib_sid = listen_ib->sib_sid;
			ib->sib_scope_id = listen_ib->sib_scope_id;
		}
		ib->sib_sid_mask = cpu_to_be64(0xffffffffffffffffULL);
	}
	if (dst_addr) {
		ib = (struct sockaddr_ib *)dst_addr;
		ib->sib_family = AF_IB;
		if (path) {
			ib->sib_pkey = path->pkey;
			ib->sib_flowinfo = path->flow_label;
			memcpy(&ib->sib_addr, &path->dgid, 16);
		}
	}
}

// 从 cma_hdr 里提取出信息保存到 src_addr / dst_addr
static void cma_save_ip4_info(struct sockaddr_in *src_addr,
			      struct sockaddr_in *dst_addr,
			      struct cma_hdr *hdr,
			      __be16 local_port)
{
	if (src_addr) {
		*src_addr = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr.s_addr = hdr->dst_addr.ip4.addr,
			.sin_port = local_port,
		};
	}

	if (dst_addr) {
		*dst_addr = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr.s_addr = hdr->src_addr.ip4.addr,
			.sin_port = hdr->port,
		};
	}
}

static void cma_save_ip6_info(struct sockaddr_in6 *src_addr,
			      struct sockaddr_in6 *dst_addr,
			      struct cma_hdr *hdr,
			      __be16 local_port)
{
	if (src_addr) {
		*src_addr = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_addr = hdr->dst_addr.ip6,
			.sin6_port = local_port,
		};
	}

	if (dst_addr) {
		*dst_addr = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_addr = hdr->src_addr.ip6,
			.sin6_port = hdr->port,
		};
	}
}

// service_id 的 低 16b 编码了 port
// ref: rdma_get_service_id 
static u16 cma_port_from_service_id(__be64 service_id)
{
	return (u16)be64_to_cpu(service_id);
}

static int cma_save_ip_info(struct sockaddr *src_addr,
			    struct sockaddr *dst_addr,
			    const struct ib_cm_event *ib_event,
			    __be64 service_id)
{
	struct cma_hdr *hdr;
	__be16 port;

	hdr = ib_event->private_data;
	if (hdr->cma_version != CMA_VERSION)
		return -EINVAL;

	port = htons(cma_port_from_service_id(service_id));

	switch (cma_get_ip_ver(hdr)) {
	case 4:
		cma_save_ip4_info((struct sockaddr_in *)src_addr,
				  (struct sockaddr_in *)dst_addr, hdr, port);
		break;
	case 6:
		cma_save_ip6_info((struct sockaddr_in6 *)src_addr,
				  (struct sockaddr_in6 *)dst_addr, hdr, port);
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

static int cma_save_net_info(struct sockaddr *src_addr,
			     struct sockaddr *dst_addr,
			     const struct rdma_cm_id *listen_id,
			     const struct ib_cm_event *ib_event,
			     sa_family_t sa_family, __be64 service_id)
{
	if (sa_family == AF_IB) {
		if (ib_event->event == IB_CM_REQ_RECEIVED)
			cma_save_ib_info(src_addr, dst_addr, listen_id,
					 ib_event->param.req_rcvd.primary_path);
		else if (ib_event->event == IB_CM_SIDR_REQ_RECEIVED)
			cma_save_ib_info(src_addr, dst_addr, listen_id, NULL);
		return 0;
	}

	return cma_save_ip_info(src_addr, dst_addr, ib_event, service_id);
}

// ib_event 中的信息保存到 req 里
// ib_event 是底层接收了报文解析后构造出来的
static int cma_save_req_info(const struct ib_cm_event *ib_event,
			     struct cma_req_info *req)
{
	const struct ib_cm_req_event_param *req_param =
		&ib_event->param.req_rcvd;
	const struct ib_cm_sidr_req_event_param *sidr_param =
		&ib_event->param.sidr_req_rcvd;

	switch (ib_event->event) {
	case IB_CM_REQ_RECEIVED: // 接收到了连接请求
		req->device	= req_param->listen_id->device;
		req->port	= req_param->port;
		memcpy(&req->local_gid, &req_param->primary_path->sgid,
		       sizeof(req->local_gid));
		req->has_gid	= true;
		req->service_id = req_param->primary_path->service_id;
		req->pkey	= be16_to_cpu(req_param->primary_path->pkey);
		if (req->pkey != req_param->bth_pkey)
			pr_warn_ratelimited("RDMA CMA: got different BTH P_Key (0x%x) and primary path P_Key (0x%x)\n"
					    "RDMA CMA: in the future this may cause the request to be dropped\n",
					    req_param->bth_pkey, req->pkey);
		break;
	case IB_CM_SIDR_REQ_RECEIVED: // 接收到了 SIDR_REQ 报文
		req->device	= sidr_param->listen_id->device;
		req->port	= sidr_param->port;
		req->has_gid	= false;
		req->service_id	= sidr_param->service_id;
		req->pkey	= sidr_param->pkey;
		if (req->pkey != sidr_param->bth_pkey)
			pr_warn_ratelimited("RDMA CMA: got different BTH P_Key (0x%x) and SIDR request payload P_Key (0x%x)\n"
					    "RDMA CMA: in the future this may cause the request to be dropped\n",
					    sidr_param->bth_pkey, req->pkey);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

// 检查下 src / dst 地址, 然后用地址去查一下路由, 看看能不能查成功
static bool validate_ipv4_net_dev(struct net_device *net_dev,
				  const struct sockaddr_in *dst_addr,
				  const struct sockaddr_in *src_addr)
{
	__be32 daddr = dst_addr->sin_addr.s_addr,
	       saddr = src_addr->sin_addr.s_addr;
	struct fib_result res;
	struct flowi4 fl4;
	int err;
	bool ret;

	if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr) ||
	    ipv4_is_lbcast(daddr) || ipv4_is_zeronet(saddr) ||
	    ipv4_is_zeronet(daddr) || ipv4_is_loopback(daddr) ||
	    ipv4_is_loopback(saddr))
		return false;

	memset(&fl4, 0, sizeof(fl4));
	fl4.flowi4_iif = net_dev->ifindex;
	fl4.daddr = daddr;
	fl4.saddr = saddr;

	rcu_read_lock();
	err = fib_lookup(dev_net(net_dev), &fl4, &res, 0);
	ret = err == 0 && FIB_RES_DEV(res) == net_dev;
	rcu_read_unlock();

	return ret;
}

static bool validate_ipv6_net_dev(struct net_device *net_dev,
				  const struct sockaddr_in6 *dst_addr,
				  const struct sockaddr_in6 *src_addr)
{
#if IS_ENABLED(CONFIG_IPV6)
	const int strict = ipv6_addr_type(&dst_addr->sin6_addr) &
			   IPV6_ADDR_LINKLOCAL;
	struct rt6_info *rt = rt6_lookup(dev_net(net_dev), &dst_addr->sin6_addr,
					 &src_addr->sin6_addr, net_dev->ifindex,
					 NULL, strict);
	bool ret;

	if (!rt)
		return false;

	ret = rt->rt6i_idev->dev == net_dev;
	ip6_rt_put(rt);

	return ret;
#else
	return false;
#endif
}

static bool validate_net_dev(struct net_device *net_dev,
			     const struct sockaddr *daddr,
			     const struct sockaddr *saddr)
{
	const struct sockaddr_in *daddr4 = (const struct sockaddr_in *)daddr;
	const struct sockaddr_in *saddr4 = (const struct sockaddr_in *)saddr;
	const struct sockaddr_in6 *daddr6 = (const struct sockaddr_in6 *)daddr;
	const struct sockaddr_in6 *saddr6 = (const struct sockaddr_in6 *)saddr;

	switch (daddr->sa_family) {
	case AF_INET:
		return saddr->sa_family == AF_INET &&
		       validate_ipv4_net_dev(net_dev, daddr4, saddr4);

	case AF_INET6:
		return saddr->sa_family == AF_INET6 &&
		       validate_ipv6_net_dev(net_dev, daddr6, saddr6);

	default:
		return false;
	}
}

static struct net_device *
roce_get_net_dev_by_cm_event(const struct ib_cm_event *ib_event)
{
	const struct ib_gid_attr *sgid_attr = NULL;
	struct net_device *ndev;

	if (ib_event->event == IB_CM_REQ_RECEIVED)
		sgid_attr = ib_event->param.req_rcvd.ppath_sgid_attr;
	else if (ib_event->event == IB_CM_SIDR_REQ_RECEIVED)
		sgid_attr = ib_event->param.sidr_req_rcvd.sgid_attr;

	if (!sgid_attr)
		return NULL;

	rcu_read_lock();
	// 从 sgid_attr 里将 ndev 提取出来
	ndev = rdma_read_gid_attr_ndev_rcu(sgid_attr);
	if (IS_ERR(ndev))
		ndev = NULL;
	else
		dev_hold(ndev);
	rcu_read_unlock();
	return ndev;
}

static struct net_device *cma_get_net_dev(const struct ib_cm_event *ib_event,
					  struct cma_req_info *req)
{
	struct sockaddr *listen_addr =
			(struct sockaddr *)&req->listen_addr_storage;
	struct sockaddr *src_addr = (struct sockaddr *)&req->src_addr_storage;
	struct net_device *net_dev;
	const union ib_gid *gid = req->has_gid ? &req->local_gid : NULL;
	int err;

	// ib_event 保存了底层报文里提取的信息, 其中包含一些地址信息 ref: IB Spec Vol1 A11.4
	// 填充 listen_addr, src_addr (这里的 src_addr 是 peer addr;  listen addr 才是自己的 addr)
	err = cma_save_ip_info(listen_addr, src_addr, ib_event,
			       req->service_id);
	if (err)
		return ERR_PTR(err);

	if (rdma_protocol_roce(req->device, req->port)) // roce 在这里
		net_dev = roce_get_net_dev_by_cm_event(ib_event);
	else
		net_dev = ib_get_net_dev_by_params(req->device, req->port,
						   req->pkey,
						   gid, listen_addr);
	if (!net_dev)
		return ERR_PTR(-ENODEV);

	return net_dev;
}

// 可以看到 service id 的 低 [16:31]b 编码了 port space 号
static enum rdma_ucm_port_space rdma_ps_from_service_id(__be64 service_id)
{
	return (be64_to_cpu(service_id) >> 16) & 0xffff;
}

// roce 建立连接的是 mad 报文里会携带一些 private date 就是这个 cma_hdr 其中包含了一些地址信息
// 现在比较下这些地址信息和本地的 id_priv 中携带的地址信息是否匹配
static bool cma_match_private_data(struct rdma_id_private *id_priv,
				   const struct cma_hdr *hdr)
{
	struct sockaddr *addr = cma_src_addr(id_priv);
	__be32 ip4_addr;
	struct in6_addr ip6_addr;

	if (cma_any_addr(addr) && !id_priv->afonly)
		return true;

	switch (addr->sa_family) {
	case AF_INET:
		ip4_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
		if (cma_get_ip_ver(hdr) != 4)
			return false;
		if (!cma_any_addr(addr) &&
		    hdr->dst_addr.ip4.addr != ip4_addr)
			return false;
		break;
	case AF_INET6:
		ip6_addr = ((struct sockaddr_in6 *)addr)->sin6_addr;
		if (cma_get_ip_ver(hdr) != 6)
			return false;
		if (!cma_any_addr(addr) &&
		    memcmp(&hdr->dst_addr.ip6, &ip6_addr, sizeof(ip6_addr)))
			return false;
		break;
	case AF_IB:
		return true;
	default:
		return false;
	}

	return true;
}

// rocev1 rocev2
static bool cma_protocol_roce(const struct rdma_cm_id *id)
{
	struct ib_device *device = id->device;
	const int port_num = id->port_num ?: rdma_start_port(device);

	return rdma_protocol_roce(device, port_num);
}

// ipv6 link local 的请求
static bool cma_is_req_ipv6_ll(const struct cma_req_info *req)
{
	const struct sockaddr *daddr =
			(const struct sockaddr *)&req->listen_addr_storage;
	const struct sockaddr_in6 *daddr6 = (const struct sockaddr_in6 *)daddr;

	/* Returns true if the req is for IPv6 link local */
	return (daddr->sa_family == AF_INET6 &&
		(ipv6_addr_type(&daddr6->sin6_addr) & IPV6_ADDR_LINKLOCAL));
}

// 判断 netdev 和 id 里携带的 addr 是否匹配
static bool cma_match_net_dev(const struct rdma_cm_id *id,
			      const struct net_device *net_dev,
			      const struct cma_req_info *req)
{
	const struct rdma_addr *addr = &id->route.addr;

	// AF_IB 请求没有对应的 net device 的
	if (!net_dev)
		/* This request is an AF_IB request */
		return (!id->port_num || id->port_num == req->port) &&
		       (addr->src_addr.ss_family == AF_IB);

	/*
	 * If the request is not for IPv6 link local, allow matching
	 * request to any netdevice of the one or multiport rdma device.
	 */
	if (!cma_is_req_ipv6_ll(req))
		return true;
	/*
	 * Net namespaces must match, and if the listner is listening
	 * on a specific netdevice than netdevice must match as well.
	 */
	if (net_eq(dev_net(net_dev), addr->dev_addr.net) &&
	    (!!addr->dev_addr.bound_dev_if == // 如果 addr 上携带了 bound_dev_if 那么 就要和 net_dev->ifindex 匹配
	     (addr->dev_addr.bound_dev_if == net_dev->ifindex)))
		return true;
	else
		return false;
}

// 利用 cm_id, ib_event, req, net_dev
// 在 bind_list 里找到一个 匹配的 listen id
// - 可能在 bind_list 里找到的
// - 也可能在 listen id 的 listen_list 上找到, 当 listen_id listen 多个 dev 的时候
//
//
// listen 的是分两种情况:
// - 首先在 listen 之前肯定是 先 bind 的, 这是 listen id 会被挂到一个 bind_list 上, ref: rdma_listen() -> rdma_bind_addr() -> cma_get_port()
// - 如果是 listen 的某个设备, 后续收到 req 报文的时候, 直接在 bind_list 里就找到 listen_id 就可以了
// - 如果是 listen all device, 那么其实会为每个 device 再重新创建一个 id (ref: cma_listen_on_all() -> cma_listen_on_dev()), 这些 创建的 id 会被挂载到最初的 listen id 的 listen list 上, 所以这时候就是在 bind_list 中找到的 listen id的 listen list 上来找最终的 listen id
// 注: 如果是 listen all device 的话 原始的 listen id 还会被 挂到 global的 listen_any_list 上, 如果是 listen on dev 的话, 那么 id 就会被挂到 cma_device.list  ref: _cma_attach_to_dev
static struct rdma_id_private *cma_find_listener(
		const struct rdma_bind_list *bind_list,
		const struct ib_cm_id *cm_id,
		const struct ib_cm_event *ib_event,
		const struct cma_req_info *req,
		const struct net_device *net_dev)
{
	struct rdma_id_private *id_priv, *id_priv_dev;

	lockdep_assert_held(&lock);

	if (!bind_list)
		return ERR_PTR(-EINVAL);

	hlist_for_each_entry(id_priv, &bind_list->owners, node) {
		if (cma_match_private_data(id_priv, ib_event->private_data)) { // 首先 private data 要匹配
			if (id_priv->id.device == cm_id->device &&
			    cma_match_net_dev(&id_priv->id, net_dev, req)) // net_dev 和 id  里携带的 net_dev 也要匹配
				return id_priv;
			list_for_each_entry(id_priv_dev, //  listen_id 可能会在很多 dev 上 listen 的, 所以在 listen 的时候会为每个 dev 都创建一个 id 然后挂载到 listen_id 的 listen_list 上
					    &id_priv->listen_list,
					    listen_list) {
				if (id_priv_dev->id.device == cm_id->device &&
				    cma_match_net_dev(&id_priv_dev->id,
						      net_dev, req))
					return id_priv_dev;
			}
		}
	}

	return ERR_PTR(-EINVAL);
}

// 基于底层传来的 event 信息解析出 listen id, 同时将 相关信息提取出来保存到 req 里
static struct rdma_id_private *
cma_ib_id_from_event(struct ib_cm_id *cm_id,
		     const struct ib_cm_event *ib_event,
		     struct cma_req_info *req,
		     struct net_device **net_dev)
{
	struct rdma_bind_list *bind_list;
	struct rdma_id_private *id_priv;
	int err;

	// 保存 ib_event 的信息到 req 里
	err = cma_save_req_info(ib_event, req);
	if (err)
		return ERR_PTR(err);

	*net_dev = cma_get_net_dev(ib_event, req);
	if (IS_ERR(*net_dev)) {
		if (PTR_ERR(*net_dev) == -EAFNOSUPPORT) {
			/* Assuming the protocol is AF_IB */
			*net_dev = NULL;
		} else {
			return ERR_CAST(*net_dev);
		}
	}

	mutex_lock(&lock);
	/*
	 * Net namespace might be getting deleted while route lookup,
	 * cm_id lookup is in progress. Therefore, perform netdevice
	 * validation, cm_id lookup under rcu lock.
	 * RCU lock along with netdevice state check, synchronizes with
	 * netdevice migrating to different net namespace and also avoids
	 * case where net namespace doesn't get deleted while lookup is in
	 * progress.
	 * If the device state is not IFF_UP, its properties such as ifindex
	 * and nd_net cannot be trusted to remain valid without rcu lock.
	 * net/core/dev.c change_net_namespace() ensures to synchronize with
	 * ongoing operations on net device after device is closed using
	 * synchronize_net().
	 */
	rcu_read_lock();
	if (*net_dev) {
		/*
		 * If netdevice is down, it is likely that it is administratively
		 * down or it might be migrating to different namespace.
		 * In that case avoid further processing, as the net namespace
		 * or ifindex may change.
		 */
		if (((*net_dev)->flags & IFF_UP) == 0) {
			id_priv = ERR_PTR(-EHOSTUNREACH);
			goto err;
		}

		if (!validate_net_dev(*net_dev,
				 (struct sockaddr *)&req->listen_addr_storage,
				 (struct sockaddr *)&req->src_addr_storage)) {
			id_priv = ERR_PTR(-EHOSTUNREACH);
			goto err;
		}
	}

	// 从 service id 里解析出 port, 然后得到 bind list
	// 再在 bind list 上找到 id
	bind_list = cma_ps_find(*net_dev ? dev_net(*net_dev) : &init_net,
				rdma_ps_from_service_id(req->service_id),
				cma_port_from_service_id(req->service_id));
	id_priv = cma_find_listener(bind_list, cm_id, ib_event, req, *net_dev);
err:
	rcu_read_unlock();
	mutex_unlock(&lock);
	if (IS_ERR(id_priv) && *net_dev) {
		dev_put(*net_dev);
		*net_dev = NULL;
	}
	return id_priv;
}

static inline u8 cma_user_data_offset(struct rdma_id_private *id_priv)
{
	return cma_family(id_priv) == AF_IB ? 0 : sizeof(struct cma_hdr); // ref: IB Spec Vol1 A11.4
}

// native ib 用的
static void cma_cancel_route(struct rdma_id_private *id_priv)
{
	if (rdma_cap_ib_sa(id_priv->id.device, id_priv->id.port_num)) {
		if (id_priv->query)
			ib_sa_cancel_query(id_priv->query_id, id_priv->query);
	}
}

static void cma_cancel_listens(struct rdma_id_private *id_priv)
{
	struct rdma_id_private *dev_id_priv;

	/*
	 * Remove from listen_any_list to prevent added devices from spawning
	 * additional listen requests.
	 */
	mutex_lock(&lock);
	list_del(&id_priv->list);

	// 主要是清理掉 listen_id 的 listen_list 上的 dev_id_priv
	while (!list_empty(&id_priv->listen_list)) {
		dev_id_priv = list_entry(id_priv->listen_list.next,
					 struct rdma_id_private, listen_list);
		/* sync with device removal to avoid duplicate destruction */
		list_del_init(&dev_id_priv->list); // 将 dev_id_priv 从 cma_device.list 拆除
		list_del(&dev_id_priv->listen_list); // 将 dev_id_priv 从 listen_id.listen_list 拆除
		mutex_unlock(&lock);

		rdma_destroy_id(&dev_id_priv->id);
		mutex_lock(&lock);
	}
	mutex_unlock(&lock);
}

static void cma_cancel_operation(struct rdma_id_private *id_priv,
				 enum rdma_cm_state state)
{
	switch (state) {
	case RDMA_CM_ADDR_QUERY:
		rdma_addr_cancel(&id_priv->id.route.addr.dev_addr);
		break;
	case RDMA_CM_ROUTE_QUERY:
		cma_cancel_route(id_priv);
		break;
	case RDMA_CM_LISTEN:
		if (cma_any_addr(cma_src_addr(id_priv)) && !id_priv->cma_dev)
			cma_cancel_listens(id_priv);
		break;
	default:
		break;
	}
}

static void cma_release_port(struct rdma_id_private *id_priv)
{
	struct rdma_bind_list *bind_list = id_priv->bind_list;
	struct net *net = id_priv->id.route.addr.dev_addr.net;

	if (!bind_list)
		return;

	mutex_lock(&lock);
	hlist_del(&id_priv->node); // 将 id_priv 从 bind_list 拆除
	if (hlist_empty(&bind_list->owners)) { // bind_list 要是空了话, bind_list 也干掉
		cma_ps_remove(net, bind_list->ps, bind_list->port);
		kfree(bind_list);
	}
	mutex_unlock(&lock);
}

// 多播相关
static void destroy_mc(struct rdma_id_private *id_priv,
		       struct cma_multicast *mc)
{
	if (rdma_cap_ib_mcast(id_priv->id.device, id_priv->id.port_num))
		ib_sa_free_multicast(mc->sa_mc);

	if (rdma_protocol_roce(id_priv->id.device, id_priv->id.port_num)) {
		struct rdma_dev_addr *dev_addr =
			&id_priv->id.route.addr.dev_addr;
		struct net_device *ndev = NULL;

		if (dev_addr->bound_dev_if)
			ndev = dev_get_by_index(dev_addr->net,
						dev_addr->bound_dev_if);
		if (ndev) {
			union ib_gid mgid;

			cma_set_mgid(id_priv, (struct sockaddr *)&mc->addr,
				     &mgid);
			cma_igmp_send(ndev, &mgid, false);
			dev_put(ndev);
		}
	}
	kfree(mc);
}

// 多播相关
static void cma_leave_mc_groups(struct rdma_id_private *id_priv)
{
	struct cma_multicast *mc;

	while (!list_empty(&id_priv->mc_list)) {
		mc = list_first_entry(&id_priv->mc_list, struct cma_multicast,
				      list);
		list_del(&mc->list);
		destroy_mc(id_priv, mc);
	}
}

static void _destroy_id(struct rdma_id_private *id_priv,
			enum rdma_cm_state state)
{
	cma_cancel_operation(id_priv, state);

	if (id_priv->cma_dev) { // 说明 id 已经绑定搞了 src_addr
		if (rdma_cap_ib_cm(id_priv->id.device, 1)) { // RoCE 也走这里
			if (id_priv->cm_id.ib) // 这时候如果底层的 id 也创建了的话, 也要干掉
				ib_destroy_cm_id(id_priv->cm_id.ib);
		} else if (rdma_cap_iw_cm(id_priv->id.device, 1)) {
			if (id_priv->cm_id.iw)
				iw_destroy_cm_id(id_priv->cm_id.iw);
		}
		cma_leave_mc_groups(id_priv);
		cma_release_dev(id_priv);
	}

	cma_release_port(id_priv);
	cma_id_put(id_priv);
	wait_for_completion(&id_priv->comp); // 会等到 id_priv 上所有的 持有 ref 的角色都 put, 应该还需要别的机制保证, 都 put 后, 没有人会再次 get

	if (id_priv->internal_id)
		cma_id_put(id_priv->id.context);

	kfree(id_priv->id.route.path_rec);

	if (id_priv->id.route.addr.dev_addr.sgid_attr)
		rdma_put_gid_attr(id_priv->id.route.addr.dev_addr.sgid_attr);

	put_net(id_priv->id.route.addr.dev_addr.net);
	rdma_restrack_del(&id_priv->res);
	kfree(id_priv);
}

/*
 * destroy an ID from within the handler_mutex. This ensures that no other
 * handlers can start running concurrently.
 */
static void destroy_id_handler_unlock(struct rdma_id_private *id_priv)
	__releases(&idprv->handler_mutex)
{
	enum rdma_cm_state state;
	unsigned long flags;

	trace_cm_id_destroy(id_priv);

	/*
	 * Setting the state to destroyed under the handler mutex provides a
	 * fence against calling handler callbacks. If this is invoked due to
	 * the failure of a handler callback then it guarentees that no future
	 * handlers will be called.
	 */
	lockdep_assert_held(&id_priv->handler_mutex);
	spin_lock_irqsave(&id_priv->lock, flags);
	state = id_priv->state;
	id_priv->state = RDMA_CM_DESTROYING;
	spin_unlock_irqrestore(&id_priv->lock, flags);
	mutex_unlock(&id_priv->handler_mutex);	// 这种代码很恶心, 外面加锁, 里面解锁
	_destroy_id(id_priv, state);
}

void rdma_destroy_id(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);

	mutex_lock(&id_priv->handler_mutex);
	destroy_id_handler_unlock(id_priv);
}
EXPORT_SYMBOL(rdma_destroy_id);

// 底层收到 REP 报文的时候, 通过 callback 最终调用到这个函数处理 
static int cma_rep_recv(struct rdma_id_private *id_priv)
{
	int ret;

	ret = cma_modify_qp_rtr(id_priv, NULL);
	if (ret)
		goto reject;

	ret = cma_modify_qp_rts(id_priv, NULL);
	if (ret)
		goto reject;

	trace_cm_send_rtu(id_priv);
	ret = ib_send_cm_rtu(id_priv->cm_id.ib, NULL, 0); // 发送三次握手的最后一个报文, ready to use
	if (ret)
		goto reject;

	return 0;
reject:
	pr_debug_ratelimited("RDMA CM: CONNECT_ERROR: failed to handle reply. status %d\n", ret);
	cma_modify_qp_err(id_priv);
	trace_cm_send_rej(id_priv);
	ib_send_cm_rej(id_priv->cm_id.ib, IB_CM_REJ_CONSUMER_DEFINED, // 失败了, 发送 reject 报文
		       NULL, 0, NULL, 0);
	return ret;
}

// helper
// 供下层调用的, 下层提供 rep_data
static void cma_set_rep_event_data(struct rdma_cm_event *event,
				   const struct ib_cm_rep_event_param *rep_data,
				   void *private_data)
{
	event->param.conn.private_data = private_data;
	event->param.conn.private_data_len = IB_CM_REP_PRIVATE_DATA_SIZE;
	event->param.conn.responder_resources = rep_data->responder_resources;
	event->param.conn.initiator_depth = rep_data->initiator_depth;
	event->param.conn.flow_control = rep_data->flow_control;
	event->param.conn.rnr_retry_count = rep_data->rnr_retry_count;
	event->param.conn.srq = rep_data->srq;
	event->param.conn.qp_num = rep_data->remote_qpn;

	event->ece.vendor_id = rep_data->ece.vendor_id;
	event->ece.attr_mod = rep_data->ece.attr_mod;
}


// 最底层的handler, 其他 handler 都会调用这个函数, 将事件分发到其他使用 rdma_cm.ko 的模块 或者 userspace (通过 rdma_ucm.ko 模块)
// 通过调用其他模块 create_id 时传入的 event_handler
static int cma_cm_event_handler(struct rdma_id_private *id_priv,
				struct rdma_cm_event *event)
{
	int ret;

	lockdep_assert_held(&id_priv->handler_mutex);

	trace_cm_event_handler(id_priv, event);
	ret = id_priv->id.event_handler(&id_priv->id, event); // create_id 的时候设置的, ref: %__rdma_create_id()
	trace_cm_event_done(id_priv, event, ret);
	return ret;
}

// 连接建立过程中底层发生的相关的事件都是这个 handler 处理
// 被动方在 listen id 上接收到请求后, 将这个 handler 注册到底层
// 主动方通过 conenct 操作将其注册到底层
static int cma_ib_handler(struct ib_cm_id *cm_id,
			  const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	struct rdma_cm_event event = {};
	enum rdma_cm_state state;
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	state = READ_ONCE(id_priv->state);
	if ((ib_event->event != IB_CM_TIMEWAIT_EXIT &&
	     state != RDMA_CM_CONNECT) ||
	    (ib_event->event == IB_CM_TIMEWAIT_EXIT &&
	     state != RDMA_CM_DISCONNECT))
		goto out;

	switch (ib_event->event) {
	case IB_CM_REQ_ERROR:	// 自己 send req / rep 的时候发生了 error
	case IB_CM_REP_ERROR:
		event.event = RDMA_CM_EVENT_UNREACHABLE;
		event.status = -ETIMEDOUT;
		break;
	case IB_CM_REP_RECEIVED: // 收到了  REP
		if (state == RDMA_CM_CONNECT &&
		    (id_priv->id.qp_type != IB_QPT_UD)) {
			trace_cm_send_mra(id_priv);
			ib_send_cm_mra(cm_id, CMA_CM_MRA_SETTING, NULL, 0);
		}
		if (id_priv->id.qp) {
			event.status = cma_rep_recv(id_priv);
			event.event = event.status ? RDMA_CM_EVENT_CONNECT_ERROR :
						     RDMA_CM_EVENT_ESTABLISHED;
		} else {
			event.event = RDMA_CM_EVENT_CONNECT_RESPONSE;
		}
		cma_set_rep_event_data(&event, &ib_event->param.rep_rcvd,
				       ib_event->private_data);
		break;
	case IB_CM_RTU_RECEIVED: // 收到了 RTU
	case IB_CM_USER_ESTABLISHED:
		event.event = RDMA_CM_EVENT_ESTABLISHED;
		break;
	case IB_CM_DREQ_ERROR:	// 自己发送 DREQ 的时候出错了
		event.status = -ETIMEDOUT;
		fallthrough;
	case IB_CM_DREQ_RECEIVED:
	case IB_CM_DREP_RECEIVED:
		if (!cma_comp_exch(id_priv, RDMA_CM_CONNECT,
				   RDMA_CM_DISCONNECT))
			goto out;
		event.event = RDMA_CM_EVENT_DISCONNECTED;
		break;
	case IB_CM_TIMEWAIT_EXIT:
		event.event = RDMA_CM_EVENT_TIMEWAIT_EXIT;
		break;
	case IB_CM_MRA_RECEIVED:
		/* ignore event */
		goto out;
	case IB_CM_REJ_RECEIVED:
		pr_debug_ratelimited("RDMA CM: REJECTED: %s\n", rdma_reject_msg(&id_priv->id,
										ib_event->param.rej_rcvd.reason));
		cma_modify_qp_err(id_priv);
		event.status = ib_event->param.rej_rcvd.reason;
		event.event = RDMA_CM_EVENT_REJECTED;
		event.param.conn.private_data = ib_event->private_data;
		event.param.conn.private_data_len = IB_CM_REJ_PRIVATE_DATA_SIZE;
		break;
	default:
		pr_err("RDMA CMA: unexpected IB CM event: %d\n",
		       ib_event->event);
		goto out;
	}

	ret = cma_cm_event_handler(id_priv, &event);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		id_priv->cm_id.ib = NULL;
		destroy_id_handler_unlock(id_priv);
		return ret;
	}
out:
	mutex_unlock(&id_priv->handler_mutex);
	return 0;
}

// listen 的时候收到了 req 请求, 为其创建新的 id
static struct rdma_id_private *
cma_ib_new_conn_id(const struct rdma_cm_id *listen_id,
		   const struct ib_cm_event *ib_event,
		   struct net_device *net_dev)
{
	struct rdma_id_private *listen_id_priv;
	struct rdma_id_private *id_priv;
	struct rdma_cm_id *id;
	struct rdma_route *rt;
	const sa_family_t ss_family = listen_id->route.addr.src_addr.ss_family;
	struct sa_path_rec *path = ib_event->param.req_rcvd.primary_path;
	const __be64 service_id =
		ib_event->param.req_rcvd.primary_path->service_id;
	int ret;

	listen_id_priv = container_of(listen_id, struct rdma_id_private, id);
	id_priv = __rdma_create_id(listen_id->route.addr.dev_addr.net,
				   listen_id->event_handler, listen_id->context,
				   listen_id->ps,
				   ib_event->param.req_rcvd.qp_type,
				   listen_id_priv);
	if (IS_ERR(id_priv))
		return NULL;

	id = &id_priv->id;
	if (cma_save_net_info((struct sockaddr *)&id->route.addr.src_addr,
			      (struct sockaddr *)&id->route.addr.dst_addr,
			      listen_id, ib_event, ss_family, service_id))
		goto err;

	rt = &id->route;
	rt->num_paths = ib_event->param.req_rcvd.alternate_path ? 2 : 1;
	rt->path_rec = kmalloc_array(rt->num_paths, sizeof(*rt->path_rec),
				     GFP_KERNEL);
	if (!rt->path_rec)
		goto err;

	rt->path_rec[0] = *path;
	if (rt->num_paths == 2)
		rt->path_rec[1] = *ib_event->param.req_rcvd.alternate_path;

	if (net_dev) {
		rdma_copy_src_l2_addr(&rt->addr.dev_addr, net_dev);
	} else {
		if (!cma_protocol_roce(listen_id) &&
		    cma_any_addr(cma_src_addr(id_priv))) {
			rt->addr.dev_addr.dev_type = ARPHRD_INFINIBAND;
			rdma_addr_set_sgid(&rt->addr.dev_addr, &rt->path_rec[0].sgid);
			ib_addr_set_pkey(&rt->addr.dev_addr, be16_to_cpu(rt->path_rec[0].pkey));
		} else if (!cma_any_addr(cma_src_addr(id_priv))) {
			ret = cma_translate_addr(cma_src_addr(id_priv), &rt->addr.dev_addr);
			if (ret)
				goto err;
		}
	}
	rdma_addr_set_dgid(&rt->addr.dev_addr, &rt->path_rec[0].dgid);

	id_priv->state = RDMA_CM_CONNECT;
	return id_priv;

err:
	rdma_destroy_id(id);
	return NULL;
}

static struct rdma_id_private *
cma_ib_new_udp_id(const struct rdma_cm_id *listen_id,
		  const struct ib_cm_event *ib_event,
		  struct net_device *net_dev)
{
	const struct rdma_id_private *listen_id_priv;
	struct rdma_id_private *id_priv;
	struct rdma_cm_id *id;
	const sa_family_t ss_family = listen_id->route.addr.src_addr.ss_family;
	struct net *net = listen_id->route.addr.dev_addr.net;
	int ret;

	listen_id_priv = container_of(listen_id, struct rdma_id_private, id);
	id_priv = __rdma_create_id(net, listen_id->event_handler,
				   listen_id->context, listen_id->ps, IB_QPT_UD,
				   listen_id_priv);
	if (IS_ERR(id_priv))
		return NULL;

	id = &id_priv->id;
	if (cma_save_net_info((struct sockaddr *)&id->route.addr.src_addr,
			      (struct sockaddr *)&id->route.addr.dst_addr,
			      listen_id, ib_event, ss_family,
			      ib_event->param.sidr_req_rcvd.service_id))
		goto err;

	if (net_dev) {
		rdma_copy_src_l2_addr(&id->route.addr.dev_addr, net_dev);
	} else {
		if (!cma_any_addr(cma_src_addr(id_priv))) {
			ret = cma_translate_addr(cma_src_addr(id_priv),
						 &id->route.addr.dev_addr);
			if (ret)
				goto err;
		}
	}

	id_priv->state = RDMA_CM_CONNECT;
	return id_priv;
err:
	rdma_destroy_id(id);
	return NULL;
}

// helper
// 供下层调用的, 下层提供 req_data
static void cma_set_req_event_data(struct rdma_cm_event *event,
				   const struct ib_cm_req_event_param *req_data,
				   void *private_data, int offset)
{
	event->param.conn.private_data = private_data + offset;
	event->param.conn.private_data_len = IB_CM_REQ_PRIVATE_DATA_SIZE - offset;
	event->param.conn.responder_resources = req_data->responder_resources;
	event->param.conn.initiator_depth = req_data->initiator_depth;
	event->param.conn.flow_control = req_data->flow_control;
	event->param.conn.retry_count = req_data->retry_count;
	event->param.conn.rnr_retry_count = req_data->rnr_retry_count;
	event->param.conn.srq = req_data->srq;
	event->param.conn.qp_num = req_data->remote_qpn;

	event->ece.vendor_id = req_data->ece.vendor_id;
	event->ece.attr_mod = req_data->ece.attr_mod;
}

// id里的 qp_type 和 event 里的能不能对上
static int cma_ib_check_req_qp_type(const struct rdma_cm_id *id,
				    const struct ib_cm_event *ib_event)
{
	return (((ib_event->event == IB_CM_REQ_RECEIVED) &&
		 (ib_event->param.req_rcvd.qp_type == id->qp_type)) ||
		((ib_event->event == IB_CM_SIDR_REQ_RECEIVED) && /* 只有 UD 服务才能使用 SIDR 报文 */
		 (id->qp_type == IB_QPT_UD)) ||
		(!id->qp_type));
}


// listen 的时候, 将这个 handler 挂到底层, 底层收到 req 报文的时候调用这个 handler 处理
//
// ib_event 中包含了底层处理报文的时候得到的信息(含报文里提供的信息)
static int cma_ib_req_handler(struct ib_cm_id *cm_id,
			      const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *listen_id, *conn_id = NULL;
	struct rdma_cm_event event = {};
	struct cma_req_info req = {};
	struct net_device *net_dev;
	u8 offset;
	int ret;

	// 底层的 cm_id 结合 ib_event 事件来得到本层的 listen id, 通过查找 bind_list 得到的
	listen_id = cma_ib_id_from_event(cm_id, ib_event, &req, &net_dev);
	if (IS_ERR(listen_id))
		return PTR_ERR(listen_id);

	trace_cm_req_handler(listen_id, ib_event->event);
	if (!cma_ib_check_req_qp_type(&listen_id->id, ib_event)) { // listen id 找到后还要检查下 qp_type
		ret = -EINVAL;
		goto net_dev_put;
	}

	mutex_lock(&listen_id->handler_mutex);
	if (READ_ONCE(listen_id->state) != RDMA_CM_LISTEN) {
		ret = -ECONNABORTED;
		goto err_unlock;
	}

	offset = cma_user_data_offset(listen_id);
	event.event = RDMA_CM_EVENT_CONNECT_REQUEST;
	if (ib_event->event == IB_CM_SIDR_REQ_RECEIVED) {  // UD 服务用这个, ref: IB Spec vol1 Ch12.11.1
		conn_id = cma_ib_new_udp_id(&listen_id->id, ib_event, net_dev); // listen id 上有新请求了, 为其创建一个新 id 咯
		event.param.ud.private_data = ib_event->private_data + offset; // 然后保存连接相关信息
		event.param.ud.private_data_len =
				IB_CM_SIDR_REQ_PRIVATE_DATA_SIZE - offset;
	} else {  // RC 服务用这个
		conn_id = cma_ib_new_conn_id(&listen_id->id, ib_event, net_dev); // 同样为新连接创建一个 id
		cma_set_req_event_data(&event, &ib_event->param.req_rcvd, // 保存连接相关信息
				       ib_event->private_data, offset);
	}
	if (!conn_id) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	mutex_lock_nested(&conn_id->handler_mutex, SINGLE_DEPTH_NESTING);
	ret = cma_ib_acquire_dev(conn_id, listen_id, &req);
	if (ret) {
		destroy_id_handler_unlock(conn_id);
		goto err_unlock;
	}

	conn_id->cm_id.ib = cm_id; // 和底层的 id 建立起关系
	cm_id->context = conn_id;
	cm_id->cm_handler = cma_ib_handler;

	// 事件通知到更上层
	ret = cma_cm_event_handler(conn_id, &event);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		conn_id->cm_id.ib = NULL;
		mutex_unlock(&listen_id->handler_mutex);
		destroy_id_handler_unlock(conn_id);
		goto net_dev_put;
	}

	if (READ_ONCE(conn_id->state) == RDMA_CM_CONNECT && // 这是正常路径 cma_ib_new_conn_id() 设置的
	    conn_id->id.qp_type != IB_QPT_UD) {
		trace_cm_send_mra(cm_id->context);
		// 发个 MRA 消息给 peer, 告诉对方我收到了, 你暂时不要做 retry 咯
		// ref IB Spec vol1 ch12.6.6
		ib_send_cm_mra(cm_id, CMA_CM_MRA_SETTING, NULL, 0);
	}
	mutex_unlock(&conn_id->handler_mutex);

err_unlock:
	mutex_unlock(&listen_id->handler_mutex);

net_dev_put:
	if (net_dev)
		dev_put(net_dev);

	return ret;
}

// ref: ib spec vol1 A11 基于 IP 的 CM 协议中 service id 的编码
// 另外如果底层是 IB 设备的话, 那么 service id 是不需要特殊编码的
__be64 rdma_get_service_id(struct rdma_cm_id *id, struct sockaddr *addr)
{
	if (addr->sa_family == AF_IB)
		return ((struct sockaddr_ib *) addr)->sib_sid;

	// 以 RDMA_PS_TCP 为例:
	//
	// 如果机器是小端 id->ps 从低 byte 到 高 byte
	//     06 01 00 00 00 00 00 00
	// 左移 
	//     00 00 06 01 00 00 00 00
	// 加法
	//     xx xx 06 01 00 00 00 00
	// 转换为大端
	//     00 00 00 00 01 06 xx xx
	//
	// 如果机器是大端 id->ps 从低 byte 到 高 byte
	//     00 00 00 00 00 00 01 06
	// 左移
	//     00 00 00 00 01 06 00 00
	// 加法
	//     00 00 00 00 01 06 xx xx 
	// 不需要转换为大端
	return cpu_to_be64(((u64)id->ps << 16) + be16_to_cpu(cma_port(addr)));
}
EXPORT_SYMBOL(rdma_get_service_id);

void rdma_read_gids(struct rdma_cm_id *cm_id, union ib_gid *sgid,
		    union ib_gid *dgid)
{
	struct rdma_addr *addr = &cm_id->route.addr;

	if (!cm_id->device) {
		if (sgid)
			memset(sgid, 0, sizeof(*sgid));
		if (dgid)
			memset(dgid, 0, sizeof(*dgid));
		return;
	}

	// roce 协议 gid 就是用 ip 转换过来的
	// iwarp 就压根没有 gid 了
	if (rdma_protocol_roce(cm_id->device, cm_id->port_num)) {
		if (sgid)
			rdma_ip2gid((struct sockaddr *)&addr->src_addr, sgid);
		if (dgid)
			rdma_ip2gid((struct sockaddr *)&addr->dst_addr, dgid);
	} else {
		if (sgid)
			rdma_addr_get_sgid(&addr->dev_addr, sgid);
		if (dgid)
			rdma_addr_get_dgid(&addr->dev_addr, dgid);
	}
}
EXPORT_SYMBOL(rdma_read_gids);

static int cma_iw_handler(struct iw_cm_id *iw_id, struct iw_cm_event *iw_event)
{
	struct rdma_id_private *id_priv = iw_id->context;
	struct rdma_cm_event event = {};
	int ret = 0;
	struct sockaddr *laddr = (struct sockaddr *)&iw_event->local_addr;
	struct sockaddr *raddr = (struct sockaddr *)&iw_event->remote_addr;

	mutex_lock(&id_priv->handler_mutex);
	if (READ_ONCE(id_priv->state) != RDMA_CM_CONNECT)
		goto out;

	switch (iw_event->event) {
	case IW_CM_EVENT_CLOSE:
		event.event = RDMA_CM_EVENT_DISCONNECTED;
		break;
	case IW_CM_EVENT_CONNECT_REPLY:
		memcpy(cma_src_addr(id_priv), laddr,
		       rdma_addr_size(laddr));
		memcpy(cma_dst_addr(id_priv), raddr,
		       rdma_addr_size(raddr));
		switch (iw_event->status) {
		case 0:
			event.event = RDMA_CM_EVENT_ESTABLISHED;
			event.param.conn.initiator_depth = iw_event->ird;
			event.param.conn.responder_resources = iw_event->ord;
			break;
		case -ECONNRESET:
		case -ECONNREFUSED:
			event.event = RDMA_CM_EVENT_REJECTED;
			break;
		case -ETIMEDOUT:
			event.event = RDMA_CM_EVENT_UNREACHABLE;
			break;
		default:
			event.event = RDMA_CM_EVENT_CONNECT_ERROR;
			break;
		}
		break;
	case IW_CM_EVENT_ESTABLISHED:
		event.event = RDMA_CM_EVENT_ESTABLISHED;
		event.param.conn.initiator_depth = iw_event->ird;
		event.param.conn.responder_resources = iw_event->ord;
		break;
	default:
		goto out;
	}

	event.status = iw_event->status;
	event.param.conn.private_data = iw_event->private_data;
	event.param.conn.private_data_len = iw_event->private_data_len;
	ret = cma_cm_event_handler(id_priv, &event);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		id_priv->cm_id.iw = NULL;
		destroy_id_handler_unlock(id_priv);
		return ret;
	}

out:
	mutex_unlock(&id_priv->handler_mutex);
	return ret;
}

static int iw_conn_req_handler(struct iw_cm_id *cm_id,
			       struct iw_cm_event *iw_event)
{
	struct rdma_id_private *listen_id, *conn_id;
	struct rdma_cm_event event = {};
	int ret = -ECONNABORTED;
	struct sockaddr *laddr = (struct sockaddr *)&iw_event->local_addr;
	struct sockaddr *raddr = (struct sockaddr *)&iw_event->remote_addr;

	event.event = RDMA_CM_EVENT_CONNECT_REQUEST;
	event.param.conn.private_data = iw_event->private_data;
	event.param.conn.private_data_len = iw_event->private_data_len;
	event.param.conn.initiator_depth = iw_event->ird;
	event.param.conn.responder_resources = iw_event->ord;

	listen_id = cm_id->context;

	mutex_lock(&listen_id->handler_mutex);
	if (READ_ONCE(listen_id->state) != RDMA_CM_LISTEN)
		goto out;

	/* Create a new RDMA id for the new IW CM ID */
	conn_id = __rdma_create_id(listen_id->id.route.addr.dev_addr.net,
				   listen_id->id.event_handler,
				   listen_id->id.context, RDMA_PS_TCP,
				   IB_QPT_RC, listen_id);
	if (IS_ERR(conn_id)) {
		ret = -ENOMEM;
		goto out;
	}
	mutex_lock_nested(&conn_id->handler_mutex, SINGLE_DEPTH_NESTING);
	conn_id->state = RDMA_CM_CONNECT;

	ret = rdma_translate_ip(laddr, &conn_id->id.route.addr.dev_addr);
	if (ret) {
		mutex_unlock(&listen_id->handler_mutex);
		destroy_id_handler_unlock(conn_id);
		return ret;
	}

	ret = cma_iw_acquire_dev(conn_id, listen_id);
	if (ret) {
		mutex_unlock(&listen_id->handler_mutex);
		destroy_id_handler_unlock(conn_id);
		return ret;
	}

	conn_id->cm_id.iw = cm_id;
	cm_id->context = conn_id;
	cm_id->cm_handler = cma_iw_handler;

	memcpy(cma_src_addr(conn_id), laddr, rdma_addr_size(laddr));
	memcpy(cma_dst_addr(conn_id), raddr, rdma_addr_size(raddr));

	ret = cma_cm_event_handler(conn_id, &event);
	if (ret) {
		/* User wants to destroy the CM ID */
		conn_id->cm_id.iw = NULL;
		mutex_unlock(&listen_id->handler_mutex);
		destroy_id_handler_unlock(conn_id);
		return ret;
	}

	mutex_unlock(&conn_id->handler_mutex);

out:
	mutex_unlock(&listen_id->handler_mutex);
	return ret;
}

// 将 需要 listen 的 service id 插入到底层, 底层收到报文后通过这里提供的 cma_ib_req_handler() callback 回来
static int cma_ib_listen(struct rdma_id_private *id_priv)
{
	struct sockaddr *addr;
	struct ib_cm_id	*id;
	__be64 svc_id;

	addr = cma_src_addr(id_priv);
	svc_id = rdma_get_service_id(&id_priv->id, addr); // local 的 src addr 当然有 listen 的 port, 通过 listen port 可以得到 service id
	id = ib_cm_insert_listen(id_priv->id.device,
				 cma_ib_req_handler, svc_id);
	if (IS_ERR(id))
		return PTR_ERR(id);
	id_priv->cm_id.ib = id;

	return 0;
}

static int cma_iw_listen(struct rdma_id_private *id_priv, int backlog)
{
	int ret;
	struct iw_cm_id	*id;

	id = iw_create_cm_id(id_priv->id.device,
			     iw_conn_req_handler,
			     id_priv);
	if (IS_ERR(id))
		return PTR_ERR(id);

	id->tos = id_priv->tos;
	id->tos_set = id_priv->tos_set;
	id_priv->cm_id.iw = id;

	memcpy(&id_priv->cm_id.iw->local_addr, cma_src_addr(id_priv),
	       rdma_addr_size(cma_src_addr(id_priv)));

	ret = iw_cm_listen(id_priv->cm_id.iw, backlog);

	if (ret) {
		iw_destroy_cm_id(id_priv->cm_id.iw);
		id_priv->cm_id.iw = NULL;
	}

	return ret;
}

// listen 的时候创建了一个 dev_id_priv, 其 handler 就是 这个
// 即底层通过 cma_ib_req_handler() -> cma_listen_handler()
static int cma_listen_handler(struct rdma_cm_id *id,
			      struct rdma_cm_event *event)
{
	struct rdma_id_private *id_priv = id->context;

	/* Listening IDs are always destroyed on removal */
	if (event->event == RDMA_CM_EVENT_DEVICE_REMOVAL)
		return -1;

	id->context = id_priv->id.context;
	id->event_handler = id_priv->id.event_handler;
	trace_cm_event_handler(id_priv, event);
	return id_priv->id.event_handler(id, event);
}

static void cma_listen_on_dev(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev)
{
	struct rdma_id_private *dev_id_priv;
	struct net *net = id_priv->id.route.addr.dev_addr.net;
	int ret;

	lockdep_assert_held(&lock);

	if (cma_family(id_priv) == AF_IB && !rdma_cap_ib_cm(cma_dev->device, 1))
		return;

	// 给 id_priv 搞一个化身, 然后用这个 化身去 listen on cma_dev ???
	dev_id_priv =
		__rdma_create_id(net, cma_listen_handler, id_priv,
				 id_priv->id.ps, id_priv->id.qp_type, id_priv);
	if (IS_ERR(dev_id_priv))
		return;

	dev_id_priv->state = RDMA_CM_ADDR_BOUND;
	memcpy(cma_src_addr(dev_id_priv), cma_src_addr(id_priv),
	       rdma_addr_size(cma_src_addr(id_priv)));

	_cma_attach_to_dev(dev_id_priv, cma_dev);
	list_add_tail(&dev_id_priv->listen_list, &id_priv->listen_list);
	cma_id_get(id_priv);
	dev_id_priv->internal_id = 1;
	dev_id_priv->afonly = id_priv->afonly;
	dev_id_priv->tos_set = id_priv->tos_set;
	dev_id_priv->tos = id_priv->tos;

	// 现在才是真正的 listen
	ret = rdma_listen(&dev_id_priv->id, id_priv->backlog);
	if (ret)
		dev_warn(&cma_dev->device->dev,
			 "RDMA CMA: cma_listen_on_dev, error %d\n", ret);
}

static void cma_listen_on_all(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev;

	mutex_lock(&lock);
	list_add_tail(&id_priv->list, &listen_any_list);
	list_for_each_entry(cma_dev, &dev_list, list)
		cma_listen_on_dev(id_priv, cma_dev);
	mutex_unlock(&lock);
}

void rdma_set_service_type(struct rdma_cm_id *id, int tos)
{
	struct rdma_id_private *id_priv;

	id_priv = container_of(id, struct rdma_id_private, id);
	id_priv->tos = (u8) tos;
	id_priv->tos_set = true;
}
EXPORT_SYMBOL(rdma_set_service_type);

/**
 * rdma_set_ack_timeout() - Set the ack timeout of QP associated
 *                          with a connection identifier.
 * @id: Communication identifier to associated with service type.
 * @timeout: Ack timeout to set a QP, expressed as 4.096 * 2^(timeout) usec.
 *
 * This function should be called before rdma_connect() on active side, // 因为 REQ / REP 报文中要携带
 * and on passive side before rdma_accept(). It is applicable to primary
 * path only. The timeout will affect the local side of the QP, it is not
 * negotiated with remote side and zero disables the timer. In case it is
 * set before rdma_resolve_route, the value will also be used to determine
 * PacketLifeTime for RoCE.
 *
 * Return: 0 for success
 */
// 仅仅影响 local
int rdma_set_ack_timeout(struct rdma_cm_id *id, u8 timeout)
{
	struct rdma_id_private *id_priv;

	if (id->qp_type != IB_QPT_RC)
		return -EINVAL;

	id_priv = container_of(id, struct rdma_id_private, id);
	id_priv->timeout = timeout;
	id_priv->timeout_set = true;

	return 0;
}
EXPORT_SYMBOL(rdma_set_ack_timeout);

// native ib 才会用
static void cma_query_handler(int status, struct sa_path_rec *path_rec,
			      void *context)
{
	struct cma_work *work = context;
	struct rdma_route *route;

	route = &work->id->id.route;

	if (!status) {
		route->num_paths = 1;
		*route->path_rec = *path_rec;
	} else {
		work->old_state = RDMA_CM_ROUTE_QUERY;
		work->new_state = RDMA_CM_ADDR_RESOLVED;
		work->event.event = RDMA_CM_EVENT_ROUTE_ERROR;
		work->event.status = status;
		pr_debug_ratelimited("RDMA CM: ROUTE_ERROR: failed to query path. status %d\n",
				     status);
	}

	queue_work(cma_wq, &work->work);
}

// native ib 才会用
static int cma_query_ib_route(struct rdma_id_private *id_priv,
			      unsigned long timeout_ms, struct cma_work *work)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	struct sa_path_rec path_rec;
	ib_sa_comp_mask comp_mask;
	struct sockaddr_in6 *sin6;
	struct sockaddr_ib *sib;

	memset(&path_rec, 0, sizeof path_rec);

	if (rdma_cap_opa_ah(id_priv->id.device, id_priv->id.port_num))
		path_rec.rec_type = SA_PATH_REC_TYPE_OPA;
	else
		path_rec.rec_type = SA_PATH_REC_TYPE_IB;
	rdma_addr_get_sgid(dev_addr, &path_rec.sgid);
	rdma_addr_get_dgid(dev_addr, &path_rec.dgid);
	path_rec.pkey = cpu_to_be16(ib_addr_get_pkey(dev_addr));
	path_rec.numb_path = 1;
	path_rec.reversible = 1;
	path_rec.service_id = rdma_get_service_id(&id_priv->id,
						  cma_dst_addr(id_priv));

	comp_mask = IB_SA_PATH_REC_DGID | IB_SA_PATH_REC_SGID |
		    IB_SA_PATH_REC_PKEY | IB_SA_PATH_REC_NUMB_PATH |
		    IB_SA_PATH_REC_REVERSIBLE | IB_SA_PATH_REC_SERVICE_ID;

	switch (cma_family(id_priv)) {
	case AF_INET: // for iponib ???
		path_rec.qos_class = cpu_to_be16((u16) id_priv->tos);
		comp_mask |= IB_SA_PATH_REC_QOS_CLASS;
		break;
	case AF_INET6: // for iponib ???
		sin6 = (struct sockaddr_in6 *) cma_src_addr(id_priv);
		path_rec.traffic_class = (u8) (be32_to_cpu(sin6->sin6_flowinfo) >> 20);
		comp_mask |= IB_SA_PATH_REC_TRAFFIC_CLASS;
		break;
	case AF_IB:
		sib = (struct sockaddr_ib *) cma_src_addr(id_priv);
		path_rec.traffic_class = (u8) (be32_to_cpu(sib->sib_flowinfo) >> 20);
		comp_mask |= IB_SA_PATH_REC_TRAFFIC_CLASS;
		break;
	}

	id_priv->query_id = ib_sa_path_rec_get(&sa_client, id_priv->id.device,
					       id_priv->id.port_num, &path_rec,
					       comp_mask, timeout_ms,
					       GFP_KERNEL, cma_query_handler,
					       work, &id_priv->query);

	return (id_priv->query_id < 0) ? id_priv->query_id : 0;
}

// 其他模块让 rdma_cm.ko 帮忙干活的时候, 特别是一些异步的工作的时候, 返回的信息都是通过这个 handler 返回的
static void cma_work_handler(struct work_struct *_work)
{
	struct cma_work *work = container_of(_work, struct cma_work, work);
	struct rdma_id_private *id_priv = work->id;

	mutex_lock(&id_priv->handler_mutex);
	if (READ_ONCE(id_priv->state) == RDMA_CM_DESTROYING ||
	    READ_ONCE(id_priv->state) == RDMA_CM_DEVICE_REMOVAL)
		goto out_unlock;
	if (work->old_state != 0 || work->new_state != 0) {
		if (!cma_comp_exch(id_priv, work->old_state, work->new_state))
			goto out_unlock;
	}

	if (cma_cm_event_handler(id_priv, &work->event)) { // handler here
		cma_id_put(id_priv);
		destroy_id_handler_unlock(id_priv);
		goto out_free;
	}

out_unlock:
	mutex_unlock(&id_priv->handler_mutex);
	cma_id_put(id_priv);
out_free:
	if (work->event.event == RDMA_CM_EVENT_MULTICAST_JOIN)
		rdma_destroy_ah_attr(&work->event.param.ud.ah_attr);
	kfree(work);
}

static void cma_init_resolve_route_work(struct cma_work *work,
					struct rdma_id_private *id_priv)
{
	work->id = id_priv;
	INIT_WORK(&work->work, cma_work_handler);
	work->old_state = RDMA_CM_ROUTE_QUERY;
	work->new_state = RDMA_CM_ROUTE_RESOLVED;
	work->event.event = RDMA_CM_EVENT_ROUTE_RESOLVED;
}

static void enqueue_resolve_addr_work(struct cma_work *work,
				      struct rdma_id_private *id_priv)
{
	/* Balances with cma_id_put() in cma_work_handler */
	cma_id_get(id_priv);

	work->id = id_priv;
	INIT_WORK(&work->work, cma_work_handler);
	work->old_state = RDMA_CM_ADDR_QUERY;
	work->new_state = RDMA_CM_ADDR_RESOLVED;
	work->event.event = RDMA_CM_EVENT_ADDR_RESOLVED;

	queue_work(cma_wq, &work->work);
}

static int cma_resolve_ib_route(struct rdma_id_private *id_priv,
				unsigned long timeout_ms)
{
	struct rdma_route *route = &id_priv->id.route;
	struct cma_work *work;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	cma_init_resolve_route_work(work, id_priv);

	route->path_rec = kmalloc(sizeof *route->path_rec, GFP_KERNEL);
	if (!route->path_rec) {
		ret = -ENOMEM;
		goto err1;
	}

	ret = cma_query_ib_route(id_priv, timeout_ms, work);
	if (ret)
		goto err2;

	return 0;
err2:
	kfree(route->path_rec);
	route->path_rec = NULL;
err1:
	kfree(work);
	return ret;
}

static enum ib_gid_type cma_route_gid_type(enum rdma_network_type network_type,
					   unsigned long supported_gids,
					   enum ib_gid_type default_gid)
{
	if ((network_type == RDMA_NETWORK_IPV4 ||
	     network_type == RDMA_NETWORK_IPV6) &&
	    test_bit(IB_GID_TYPE_ROCE_UDP_ENCAP, &supported_gids))
		return IB_GID_TYPE_ROCE_UDP_ENCAP; // RoCEv2

	return default_gid;
}

/*
 * cma_iboe_set_path_rec_l2_fields() is helper function which sets
 * path record type based on GID type.
 * It also sets up other L2 fields which includes destination mac address
 * netdev ifindex, of the path record.
 * It returns the netdev of the bound interface for this path record entry.
 */
// iboe: ib on ehternet, 即 RoCE
//
// path record 可以理解为是 路由, 这里将路由中 L2 层的相关信息设置好
static struct net_device *
cma_iboe_set_path_rec_l2_fields(struct rdma_id_private *id_priv)
{
	struct rdma_route *route = &id_priv->id.route;
	enum ib_gid_type gid_type = IB_GID_TYPE_ROCE;
	struct rdma_addr *addr = &route->addr;
	unsigned long supported_gids;
	struct net_device *ndev;

	if (!addr->dev_addr.bound_dev_if)
		return NULL;

	ndev = dev_get_by_index(addr->dev_addr.net,
				addr->dev_addr.bound_dev_if);
	if (!ndev)
		return NULL;

	// 一个设备的某个 port 支持的 gid_type
	supported_gids = roce_gid_type_mask_support(id_priv->id.device,
						    id_priv->id.port_num);
	gid_type = cma_route_gid_type(addr->dev_addr.network,
				      supported_gids,
				      id_priv->gid_type);
	/* Use the hint from IP Stack to select GID Type */
	if (gid_type < ib_network_to_gid_type(addr->dev_addr.network))
		gid_type = ib_network_to_gid_type(addr->dev_addr.network);
	route->path_rec->rec_type = sa_conv_gid_to_pathrec_type(gid_type);

	route->path_rec->roce.route_resolved = true;
	sa_path_set_dmac(route->path_rec, addr->dev_addr.dst_dev_addr);
	return ndev;
}

int rdma_set_ib_path(struct rdma_cm_id *id,
		     struct sa_path_rec *path_rec)
{
	struct rdma_id_private *id_priv;
	struct net_device *ndev;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_RESOLVED,
			   RDMA_CM_ROUTE_RESOLVED))
		return -EINVAL;

	// ib 的话, 就用传进来的 path_rec
	id->route.path_rec = kmemdup(path_rec, sizeof(*path_rec),
				     GFP_KERNEL);
	if (!id->route.path_rec) {
		ret = -ENOMEM;
		goto err;
	}

	if (rdma_protocol_roce(id->device, id->port_num)) { // roce here
		ndev = cma_iboe_set_path_rec_l2_fields(id_priv); // roce 的话会进来重新设置 path rec 中 l2 的 fields
		if (!ndev) {
			ret = -ENODEV;
			goto err_free;
		}
		dev_put(ndev);
	}

	id->route.num_paths = 1;
	return 0;

err_free:
	kfree(id->route.path_rec);
	id->route.path_rec = NULL;
err:
	cma_comp_exch(id_priv, RDMA_CM_ROUTE_RESOLVED, RDMA_CM_ADDR_RESOLVED);
	return ret;
}
EXPORT_SYMBOL(rdma_set_ib_path);

static int cma_resolve_iw_route(struct rdma_id_private *id_priv)
{
	struct cma_work *work;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	cma_init_resolve_route_work(work, id_priv);
	queue_work(cma_wq, &work->work);
	return 0;
}

static int get_vlan_ndev_tc(struct net_device *vlan_ndev, int prio)
{
	struct net_device *dev;

	dev = vlan_dev_real_dev(vlan_ndev);
	if (dev->num_tc)
		return netdev_get_prio_tc_map(dev, prio); // 根据 prio 找到在 device 中应该使用的 traffic class

	return (vlan_dev_get_egress_qos_mask(vlan_ndev, prio) &
		VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
}

struct iboe_prio_tc_map {
	int input_prio;
	int output_tc;
	bool found;
};

static int get_lower_vlan_dev_tc(struct net_device *dev,
				 struct netdev_nested_priv *priv)
{
	struct iboe_prio_tc_map *map = (struct iboe_prio_tc_map *)priv->data;

	if (is_vlan_dev(dev))
		map->output_tc = get_vlan_ndev_tc(dev, map->input_prio);
	else if (dev->num_tc) // dev 支持多个 tc 值
		map->output_tc = netdev_get_prio_tc_map(dev, map->input_prio);
	else
		map->output_tc = 0;
	/* We are interested only in first level VLAN device, so always
	 * return 1 to stop iterating over next level devices.
	 */
	map->found = true;
	return 1;
}

// tos -> sevice level
// service level 这里其实用的是 device 的一个 traffic class
static int iboe_tos_to_sl(struct net_device *ndev, int tos)
{
	struct iboe_prio_tc_map prio_tc_map = {};
	int prio = rt_tos2priority(tos);
	struct netdev_nested_priv priv;

	/* If VLAN device, get it directly from the VLAN netdev */
	if (is_vlan_dev(ndev))
		return get_vlan_ndev_tc(ndev, prio);

	prio_tc_map.input_prio = prio;
	priv.data = (void *)&prio_tc_map;
	rcu_read_lock();
	netdev_walk_all_lower_dev_rcu(ndev,
				      get_lower_vlan_dev_tc,
				      &priv);
	rcu_read_unlock();
	/* If map is found from lower device, use it; Otherwise
	 * continue with the current netdevice to get priority to tc map.
	 */
	if (prio_tc_map.found)
		return prio_tc_map.output_tc;
	else if (ndev->num_tc)
		return netdev_get_prio_tc_map(ndev, prio);
	else
		return 0;
}

static __be32 cma_get_roce_udp_flow_label(struct rdma_id_private *id_priv)
{
	struct sockaddr_in6 *addr6;
	u16 dport, sport;
	u32 hash, fl;

	addr6 = (struct sockaddr_in6 *)cma_src_addr(id_priv);
	fl = be32_to_cpu(addr6->sin6_flowinfo) & IB_GRH_FLOWLABEL_MASK;
	if ((cma_family(id_priv) != AF_INET6) || !fl) {
		dport = be16_to_cpu(cma_port(cma_dst_addr(id_priv)));
		sport = be16_to_cpu(cma_port(cma_src_addr(id_priv)));
		hash = (u32)sport * 31 + dport; // sport + dport 来计算 hash 值, 进而得到 flowlabel, ip 不参与么?
		fl = hash & IB_GRH_FLOWLABEL_MASK;
	}

	return cpu_to_be32(fl);
}

// 路由主要就是 path_rec 结构咯
// 根据 id_priv 中的信息来解析得到路由信息 path_rec 并且保存到 id_priv->id.route->path_rec
static int cma_resolve_iboe_route(struct rdma_id_private *id_priv)
{
	struct rdma_route *route = &id_priv->id.route;
	struct rdma_addr *addr = &route->addr;
	struct cma_work *work;
	int ret;
	struct net_device *ndev;

	u8 default_roce_tos = id_priv->cma_dev->default_roce_tos[id_priv->id.port_num -
					rdma_start_port(id_priv->cma_dev->device)];
	u8 tos = id_priv->tos_set ? id_priv->tos : default_roce_tos;


	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	route->path_rec = kzalloc(sizeof *route->path_rec, GFP_KERNEL);
	if (!route->path_rec) {
		ret = -ENOMEM;
		goto err1;
	}

	route->num_paths = 1;

	// 设置 path record 中 l2 fields
	ndev = cma_iboe_set_path_rec_l2_fields(id_priv);
	if (!ndev) {
		ret = -ENODEV;
		goto err2;
	}

	// ip 层的信息设置好
	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.src_addr,
		    &route->path_rec->sgid);
	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.dst_addr,
		    &route->path_rec->dgid);

	if (((struct sockaddr *)&id_priv->id.route.addr.dst_addr)->sa_family != AF_IB)
		/* TODO: get the hoplimit from the inet/inet6 device */
		route->path_rec->hop_limit = addr->dev_addr.hoplimit;
	else
		route->path_rec->hop_limit = 1;
	route->path_rec->reversible = 1;
	route->path_rec->pkey = cpu_to_be16(0xffff);
	route->path_rec->mtu_selector = IB_SA_EQ;
	route->path_rec->sl = iboe_tos_to_sl(ndev, tos);
	route->path_rec->traffic_class = tos;
	route->path_rec->mtu = iboe_get_mtu(ndev->mtu);
	route->path_rec->rate_selector = IB_SA_EQ;
	route->path_rec->rate = iboe_get_rate(ndev);
	dev_put(ndev);
	route->path_rec->packet_life_time_selector = IB_SA_EQ;
	/* In case ACK timeout is set, use this value to calculate
	 * PacketLifeTime.  As per IBTA 12.7.34,
	 * local ACK timeout = (2 * PacketLifeTime + Local CA’s ACK delay).
	 * Assuming a negligible local ACK delay, we can use
	 * PacketLifeTime = local ACK timeout/2
	 * as a reasonable approximation for RoCE networks.
	 */
	route->path_rec->packet_life_time = id_priv->timeout_set ?
		id_priv->timeout - 1 : CMA_IBOE_PACKET_LIFETIME;

	if (!route->path_rec->mtu) {
		ret = -EINVAL;
		goto err2;
	}

	if (rdma_protocol_roce_udp_encap(id_priv->id.device,
					 id_priv->id.port_num))
		route->path_rec->flow_label =
			cma_get_roce_udp_flow_label(id_priv);

	cma_init_resolve_route_work(work, id_priv); // 挂个 work 上去, 由 work 来通知用户态
	queue_work(cma_wq, &work->work);

	return 0;

err2:
	kfree(route->path_rec);
	route->path_rec = NULL;
	route->num_paths = 0;
err1:
	kfree(work);
	return ret;
}

// 根据 id 中已有的地址信息, 获得一些路由信息, 比如路由的度量, MTU 等保存到 id_priv->route.path_rec 里
int rdma_resolve_route(struct rdma_cm_id *id, unsigned long timeout_ms)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_RESOLVED, RDMA_CM_ROUTE_QUERY)) // 先 resolve 了地址, 才能 resolved route
		return -EINVAL;

	cma_id_get(id_priv);
	if (rdma_cap_ib_sa(id->device, id->port_num))
		ret = cma_resolve_ib_route(id_priv, timeout_ms);
	else if (rdma_protocol_roce(id->device, id->port_num)) // RoCE HERE
		ret = cma_resolve_iboe_route(id_priv); // ib on ehternet
	else if (rdma_protocol_iwarp(id->device, id->port_num))
		ret = cma_resolve_iw_route(id_priv);
	else
		ret = -ENOSYS;

	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, RDMA_CM_ROUTE_QUERY, RDMA_CM_ADDR_RESOLVED);
	cma_id_put(id_priv);
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_route);

// helper: 将 addr 初始化为 loopback 地址
static void cma_set_loopback(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *) addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		break;
	case AF_INET6:
		ipv6_addr_set(&((struct sockaddr_in6 *) addr)->sin6_addr,
			      0, 0, 0, htonl(1));
		break;
	default:
		ib_addr_set(&((struct sockaddr_ib *) addr)->sib_addr,
			    0, 0, 0, htonl(1));
		break;
	}
}

static int cma_bind_loopback(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev, *cur_dev;
	union ib_gid gid;
	enum ib_port_state port_state;
	unsigned int p;
	u16 pkey;
	int ret;

	cma_dev = NULL;
	mutex_lock(&lock);
	// 遍历 device, 随便找一个 active 的 port 么?
	// 因为没有一个 loopback 设备, 所以随便找一个设备来实现 loopback
	list_for_each_entry(cur_dev, &dev_list, list) {
		if (cma_family(id_priv) == AF_IB &&
		    !rdma_cap_ib_cm(cur_dev->device, 1))
			continue;

		if (!cma_dev)
			cma_dev = cur_dev;

		rdma_for_each_port (cur_dev->device, p) { // 遍历 device 上的所有 port
			if (!ib_get_cached_port_state(cur_dev->device, p, &port_state) &&
			    port_state == IB_PORT_ACTIVE) {
				cma_dev = cur_dev;
				goto port_found;
			}
		}
	}

	if (!cma_dev) {
		ret = -ENODEV;
		goto out;
	}

	p = 1;

port_found:
	ret = rdma_query_gid(cma_dev->device, p, 0, &gid);
	if (ret)
		goto out;

	ret = ib_get_cached_pkey(cma_dev->device, p, 0, &pkey);
	if (ret)
		goto out;

	id_priv->id.route.addr.dev_addr.dev_type =
		(rdma_protocol_ib(cma_dev->device, p)) ?
		ARPHRD_INFINIBAND : ARPHRD_ETHER;

	rdma_addr_set_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	ib_addr_set_pkey(&id_priv->id.route.addr.dev_addr, pkey);
	id_priv->id.port_num = p;
	cma_attach_to_dev(id_priv, cma_dev);
	cma_set_loopback(cma_src_addr(id_priv));
out:
	mutex_unlock(&lock);
	return ret;
}

// resolve addr 的工作委托给底层, 底层完成后通过这个 callback 回来
static void addr_handler(int status, struct sockaddr *src_addr,
			 struct rdma_dev_addr *dev_addr, void *context)
{
	struct rdma_id_private *id_priv = context;
	struct rdma_cm_event event = {};
	struct sockaddr *addr;
	struct sockaddr_storage old_addr;

	mutex_lock(&id_priv->handler_mutex);
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_QUERY, // 切换 id 状态, 这里是关键, 切换成功了, 说明 resolved 成功了
			   RDMA_CM_ADDR_RESOLVED))
		goto out;

	/*
	 * Store the previous src address, so that if we fail to acquire
	 * matching rdma device, old address can be restored back, which helps
	 * to cancel the cma listen operation correctly.
	 */
	addr = cma_src_addr(id_priv);
	memcpy(&old_addr, addr, rdma_addr_size(addr));
	memcpy(addr, src_addr, rdma_addr_size(src_addr));
	if (!status && !id_priv->cma_dev) { // 成功了在这里
		status = cma_acquire_dev_by_src_ip(id_priv); // 根据 src addr 找一下 cma_dev, 出口设备
		if (status)
			pr_debug_ratelimited("RDMA CM: ADDR_ERROR: failed to acquire device. status %d\n",
					     status);
	} else if (status) {
		pr_debug_ratelimited("RDMA CM: ADDR_ERROR: failed to resolve IP. status %d\n", status);
	}

	if (status) { // status 0 表示成功
		memcpy(addr, &old_addr,
		       rdma_addr_size((struct sockaddr *)&old_addr));
		if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_RESOLVED, // 说明 resolve 失败了, 将状态改成 bound 状态. user 可能需要重试
				   RDMA_CM_ADDR_BOUND))
			goto out;
		event.event = RDMA_CM_EVENT_ADDR_ERROR;
		event.status = status;
	} else
		event.event = RDMA_CM_EVENT_ADDR_RESOLVED;

	if (cma_cm_event_handler(id_priv, &event)) { // 通过 id 关联的 file 通知到用户空间, 当然 create_id 的时候如果没有绑定的话, 就没有什么需要通知的
		destroy_id_handler_unlock(id_priv);
		return;
	}
out:
	mutex_unlock(&id_priv->handler_mutex);
}

static int cma_resolve_loopback(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	union ib_gid gid;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	if (!id_priv->cma_dev) { // why is NULL ? 说明没有 bind 那么内核给你自动 bind 一下
		ret = cma_bind_loopback(id_priv);
		if (ret)
			goto err;
	}

	rdma_addr_get_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	rdma_addr_set_dgid(&id_priv->id.route.addr.dev_addr, &gid);

	enqueue_resolve_addr_work(work, id_priv);
	return 0;
err:
	kfree(work);
	return ret;
}

// RoCE 不用这个
static int cma_resolve_ib_addr(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	if (!id_priv->cma_dev) {
		ret = cma_resolve_ib_dev(id_priv);
		if (ret)
			goto err;
	}

	// 从     id_priv->id.route.addr.dst_addr.sib_addr 里提取出 dst gid
	// 保存到 id_priv->id.route.addr.dev_addr.dst_dev_addr 里 ?
	// why ???
	rdma_addr_set_dgid(&id_priv->id.route.addr.dev_addr, (union ib_gid *)
		&(((struct sockaddr_ib *) &id_priv->id.route.addr.dst_addr)->sib_addr));

	enqueue_resolve_addr_work(work, id_priv);
	return 0;
err:
	kfree(work);
	return ret;
}

// bind 的时候, 如果 src_addr 是 NULL, 也就是希望 listen any addr 咯, 那就借用下 dst_adr 的信息
// - sa_family
// - scope_id
static int cma_bind_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
			 const struct sockaddr *dst_addr)
{
	if (!src_addr || !src_addr->sa_family) { // 如果 src_addr 是空, 这里对 id->route.addr.src_addr 做一些设置
		src_addr = (struct sockaddr *) &id->route.addr.src_addr;
		src_addr->sa_family = dst_addr->sa_family;
		if (IS_ENABLED(CONFIG_IPV6) &&
		    dst_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *src_addr6 = (struct sockaddr_in6 *) src_addr;
			struct sockaddr_in6 *dst_addr6 = (struct sockaddr_in6 *) dst_addr;
			src_addr6->sin6_scope_id = dst_addr6->sin6_scope_id;
			if (ipv6_addr_type(&dst_addr6->sin6_addr) & IPV6_ADDR_LINKLOCAL)
				id->route.addr.dev_addr.bound_dev_if = dst_addr6->sin6_scope_id;
		} else if (dst_addr->sa_family == AF_IB) {
			((struct sockaddr_ib *) src_addr)->sib_pkey =
				((struct sockaddr_ib *) dst_addr)->sib_pkey;
		}
	}
	// 帮忙 bind 一下, 会分配下 port 等
	return rdma_bind_addr(id, src_addr);
}

/*
 * If required, resolve the source address for bind and leave the id_priv in
 * state RDMA_CM_ADDR_BOUND. This oddly uses the state to determine the prior
 * calls made by ULP, a previously bound ID will not be re-bound and src_addr is
 * ignored.
 *
 * 如果 id 还没有 bind, 那就帮忙 bind 一下. 如果 src_addr 不是空, 那就 bind 到 src_addr 上
 * 否则就内核分配 port
 *
 * 就是把 src_addr 准备好
 */
static int resolve_prepare_src(struct rdma_id_private *id_priv,
			       struct sockaddr *src_addr,
			       const struct sockaddr *dst_addr)
{
	int ret;

	memcpy(cma_dst_addr(id_priv), dst_addr, rdma_addr_size(dst_addr));
	// 之前 ULP 没有 bound 的话, 那么这里先 bound 一下, 也就是分配一个本地地址咯
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_ADDR_QUERY)) {
		/* For a well behaved ULP state will be RDMA_CM_IDLE */
		ret = cma_bind_addr(&id_priv->id, src_addr, dst_addr);
		if (ret)
			goto err_dst;
		if (WARN_ON(!cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND,
					   RDMA_CM_ADDR_QUERY))) {
			ret = -EINVAL;
			goto err_dst;
		}
	}

	if (cma_family(id_priv) != dst_addr->sa_family) {
		ret = -EINVAL;
		goto err_state;
	}
	return 0;

err_state:
	cma_comp_exch(id_priv, RDMA_CM_ADDR_QUERY, RDMA_CM_ADDR_BOUND);
err_dst:
	memset(cma_dst_addr(id_priv), 0, rdma_addr_size(dst_addr));
	return ret;
}

// src 是可选的
// 主要是 解析 dst 地址, 然后将信息保存到 id->route.addr.dev_addr
int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      const struct sockaddr *dst_addr, unsigned long timeout_ms)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	int ret;

	ret = resolve_prepare_src(id_priv, src_addr, dst_addr);
	if (ret)
		return ret;

	if (cma_any_addr(dst_addr)) { // rdma 里目的地址是 0.0.0.0 那么被看作是 loopback
		ret = cma_resolve_loopback(id_priv);
	} else {
		if (dst_addr->sa_family == AF_IB) {
			ret = cma_resolve_ib_addr(id_priv); // IB 协议, 地址应该是 GID
		} else { // RoCE HERE
			ret = rdma_resolve_ip(cma_src_addr(id_priv), dst_addr,
					      &id->route.addr.dev_addr,
					      timeout_ms, addr_handler,
					      false, id_priv);
		}
	}
	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, RDMA_CM_ADDR_QUERY, RDMA_CM_ADDR_BOUND);
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_addr);

int rdma_set_reuseaddr(struct rdma_cm_id *id, int reuse)
{
	struct rdma_id_private *id_priv;
	unsigned long flags;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	spin_lock_irqsave(&id_priv->lock, flags);
	if ((reuse && id_priv->state != RDMA_CM_LISTEN) ||
	    id_priv->state == RDMA_CM_IDLE) {
		id_priv->reuseaddr = reuse; // 就是简单设置一个 flag
		ret = 0;
	} else {
		ret = -EINVAL;
	}
	spin_unlock_irqrestore(&id_priv->lock, flags);
	return ret;
}
EXPORT_SYMBOL(rdma_set_reuseaddr);

int rdma_set_afonly(struct rdma_cm_id *id, int afonly)
{
	struct rdma_id_private *id_priv;
	unsigned long flags;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	spin_lock_irqsave(&id_priv->lock, flags);
	if (id_priv->state == RDMA_CM_IDLE || id_priv->state == RDMA_CM_ADDR_BOUND) {
		id_priv->options |= (1 << CMA_OPTION_AFONLY);
		id_priv->afonly = afonly;
		ret = 0;
	} else {
		ret = -EINVAL;
	}
	spin_unlock_irqrestore(&id_priv->lock, flags);
	return ret;
}
EXPORT_SYMBOL(rdma_set_afonly);

// helper
static void cma_bind_port(struct rdma_bind_list *bind_list,
			  struct rdma_id_private *id_priv)
{
	struct sockaddr *addr;
	struct sockaddr_ib *sib;
	u64 sid, mask;
	__be16 port;

	lockdep_assert_held(&lock);

	addr = cma_src_addr(id_priv);
	port = htons(bind_list->port);

	switch (addr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *) addr)->sin_port = port;
		break;
	case AF_INET6:
		((struct sockaddr_in6 *) addr)->sin6_port = port;
		break;
	case AF_IB:
		sib = (struct sockaddr_ib *) addr;
		sid = be64_to_cpu(sib->sib_sid);
		mask = be64_to_cpu(sib->sib_sid_mask);
		sib->sib_sid = cpu_to_be64((sid & mask) | (u64) ntohs(port)); // 这里可以看到 sid 低 16 b里编码了 port
		sib->sib_sid_mask = cpu_to_be64(~0ULL);
		break;
	}
	id_priv->bind_list = bind_list;
	hlist_add_head(&id_priv->node, &bind_list->owners);
}

// ps 这个 space 里分配 snum 这个 port 给 id_priv 这个 id 用
static int cma_alloc_port(enum rdma_ucm_port_space ps,
			  struct rdma_id_private *id_priv, unsigned short snum)
{
	struct rdma_bind_list *bind_list;
	int ret;

	lockdep_assert_held(&lock);

	bind_list = kzalloc(sizeof *bind_list, GFP_KERNEL);
	if (!bind_list)
		return -ENOMEM;

	ret = cma_ps_alloc(id_priv->id.route.addr.dev_addr.net, ps, bind_list,
			   snum);
	if (ret < 0)
		goto err;

	bind_list->ps = ps;
	bind_list->port = snum;
	cma_bind_port(bind_list, id_priv); // 这里是核心, 将 id_priv 绑定到了 bind_list 上, 后续根据 sport 找到 bind_list, 然后遍历一下对比下 5-tuple 就能找到对应的 id_priv
	return 0;
err:
	kfree(bind_list);
	return ret == -ENOSPC ? -EADDRNOTAVAIL : ret;
}

// 根据 4-tuple (sport, dport, saddr, daddr) 判断 id_priv 和已有的 id 是否冲突
// 注意: 这里的 bind_list 是唯一对应一个 sport 的
static int cma_port_is_unique(struct rdma_bind_list *bind_list,
			      struct rdma_id_private *id_priv)
{
	struct rdma_id_private *cur_id;
	struct sockaddr  *daddr = cma_dst_addr(id_priv);
	struct sockaddr  *saddr = cma_src_addr(id_priv);
	__be16 dport = cma_port(daddr);

	lockdep_assert_held(&lock);

	hlist_for_each_entry(cur_id, &bind_list->owners, node) {
		struct sockaddr  *cur_daddr = cma_dst_addr(cur_id);
		struct sockaddr  *cur_saddr = cma_src_addr(cur_id);
		__be16 cur_dport = cma_port(cur_daddr);

		if (id_priv == cur_id)
			continue;

		// 注意: 只要有一个 tuple元素 是 unique, 那么整体就是 unique 的
		// 注意: 如果是 any_port 那么其他和其一样的都是冲突的

		/* different dest port -> unique */
		if (!cma_any_port(daddr) &&
		    !cma_any_port(cur_daddr) &&
		    (dport != cur_dport))
			continue;

		/* different src address -> unique */
		if (!cma_any_addr(saddr) &&
		    !cma_any_addr(cur_saddr) &&
		    cma_addr_cmp(saddr, cur_saddr))
			continue;

		/* different dst address -> unique */
		if (!cma_any_addr(daddr) &&
		    !cma_any_addr(cur_daddr) &&
		    cma_addr_cmp(daddr, cur_daddr))
			continue;

		return -EADDRNOTAVAIL;
	}
	return 0;
}

// bind 没有 指定 port 的话, 就用这个函数分配咯
static int cma_alloc_any_port(enum rdma_ucm_port_space ps,
			      struct rdma_id_private *id_priv)
{
	static unsigned int last_used_port;
	int low, high, remaining;
	unsigned int rover;
	struct net *net = id_priv->id.route.addr.dev_addr.net;

	lockdep_assert_held(&lock);

	inet_get_local_port_range(net, &low, &high);
	remaining = (high - low) + 1;
	rover = prandom_u32() % remaining + low;
retry:
	if (last_used_port != rover) {
		struct rdma_bind_list *bind_list;
		int ret;

		bind_list = cma_ps_find(net, ps, (unsigned short)rover);

		if (!bind_list) {
			ret = cma_alloc_port(ps, id_priv, rover);
		} else {
			ret = cma_port_is_unique(bind_list, id_priv);
			if (!ret)
				cma_bind_port(bind_list, id_priv);
		}
		/*
		 * Remember previously used port number in order to avoid
		 * re-using same port immediately after it is closed.
		 */
		if (!ret)
			last_used_port = rover;
		if (ret != -EADDRNOTAVAIL)
			return ret;
	}
	if (--remaining) {
		rover++;
		if ((rover < low) || (rover > high))
			rover = low;
		goto retry;
	}
	return -EADDRNOTAVAIL;
}

/*
 * Check that the requested port is available.  This is called when trying to
 * bind to a specific port, or when trying to listen on a bound port.  In
 * the latter case, the provided id_priv may already be on the bind_list, but
 * we still need to check that it's okay to start listening.
 */
static int cma_check_port(struct rdma_bind_list *bind_list,
			  struct rdma_id_private *id_priv, uint8_t reuseaddr)
{
	struct rdma_id_private *cur_id;
	struct sockaddr *addr, *cur_addr;

	lockdep_assert_held(&lock);

	addr = cma_src_addr(id_priv);
	hlist_for_each_entry(cur_id, &bind_list->owners, node) {
		if (id_priv == cur_id)
			continue;

		if (reuseaddr && cur_id->reuseaddr)
			continue;

		cur_addr = cma_src_addr(cur_id);
		if (id_priv->afonly && cur_id->afonly &&
		    (addr->sa_family != cur_addr->sa_family))
			continue;

		if (cma_any_addr(addr) || cma_any_addr(cur_addr))
			return -EADDRNOTAVAIL;

		if (!cma_addr_cmp(addr, cur_addr))
			return -EADDRINUSE;
	}
	return 0;
}

static int cma_use_port(enum rdma_ucm_port_space ps,
			struct rdma_id_private *id_priv)
{
	struct rdma_bind_list *bind_list;
	unsigned short snum;
	int ret;

	lockdep_assert_held(&lock);

	snum = ntohs(cma_port(cma_src_addr(id_priv)));
	if (snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;

	bind_list = cma_ps_find(id_priv->id.route.addr.dev_addr.net, ps, snum);
	if (!bind_list) {
		ret = cma_alloc_port(ps, id_priv, snum);
	} else {
		ret = cma_check_port(bind_list, id_priv, id_priv->reuseaddr);
		if (!ret)
			cma_bind_port(bind_list, id_priv);
	}
	return ret;
}

static enum rdma_ucm_port_space
cma_select_inet_ps(struct rdma_id_private *id_priv)
{
	switch (id_priv->id.ps) {
	case RDMA_PS_TCP:
	case RDMA_PS_UDP:
	case RDMA_PS_IPOIB:
	case RDMA_PS_IB:
		return id_priv->id.ps;
	default:

		return 0;
	}
}

// native ib
static enum rdma_ucm_port_space
cma_select_ib_ps(struct rdma_id_private *id_priv)
{
	enum rdma_ucm_port_space ps = 0;
	struct sockaddr_ib *sib;
	u64 sid_ps, mask, sid;

	sib = (struct sockaddr_ib *) cma_src_addr(id_priv);
	mask = be64_to_cpu(sib->sib_sid_mask) & RDMA_IB_IP_PS_MASK;
	sid = be64_to_cpu(sib->sib_sid) & mask;

	if ((id_priv->id.ps == RDMA_PS_IB) && (sid == (RDMA_IB_IP_PS_IB & mask))) {
		sid_ps = RDMA_IB_IP_PS_IB;
		ps = RDMA_PS_IB;
	} else if (((id_priv->id.ps == RDMA_PS_IB) || (id_priv->id.ps == RDMA_PS_TCP)) &&
		   (sid == (RDMA_IB_IP_PS_TCP & mask))) {
		sid_ps = RDMA_IB_IP_PS_TCP;
		ps = RDMA_PS_TCP;
	} else if (((id_priv->id.ps == RDMA_PS_IB) || (id_priv->id.ps == RDMA_PS_UDP)) &&
		   (sid == (RDMA_IB_IP_PS_UDP & mask))) {
		sid_ps = RDMA_IB_IP_PS_UDP;
		ps = RDMA_PS_UDP;
	}

	if (ps) {
		sib->sib_sid = cpu_to_be64(sid_ps | ntohs(cma_port((struct sockaddr *) sib)));
		sib->sib_sid_mask = cpu_to_be64(RDMA_IB_IP_PS_MASK |
						be64_to_cpu(sib->sib_sid_mask));
	}
	return ps;
}

// 检查下 id_priv 里关联的 port 是否可用
// 有 port 那么就 check 下能不能绑定
// 没有设置 port 那就内核分配一个
//
// bind sport 函数, sport 从 id_priv 的 srcaddr 里提取出来的
static int cma_get_port(struct rdma_id_private *id_priv)
{
	enum rdma_ucm_port_space ps;
	int ret;

	if (cma_family(id_priv) != AF_IB)
		ps = cma_select_inet_ps(id_priv);
	else
		ps = cma_select_ib_ps(id_priv);
	if (!ps)
		return -EPROTONOSUPPORT;

	mutex_lock(&lock);
	if (cma_any_port(cma_src_addr(id_priv)))
		ret = cma_alloc_any_port(ps, id_priv); // 内核自己分配咯
	else
		ret = cma_use_port(ps, id_priv);
	mutex_unlock(&lock);

	return ret;
}

// 如果是 local 的话, dev_addr 的 if 就直接设置为 scope_id
static int cma_check_linklocal(struct rdma_dev_addr *dev_addr,
			       struct sockaddr *addr)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct sockaddr_in6 *sin6;

	if (addr->sa_family != AF_INET6)
		return 0;

	sin6 = (struct sockaddr_in6 *) addr;

	if (!(ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL))
		return 0;

	if (!sin6->sin6_scope_id)
			return -EINVAL;

	// 如果是 local device 才会走到这里的
	dev_addr->bound_dev_if = sin6->sin6_scope_id;
#endif
	return 0;
}

int rdma_listen(struct rdma_cm_id *id, int backlog)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	int ret;

	// 先 bound, 再listen, 如果还没有 bound, 就帮你 bound 一下
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_LISTEN)) {
		/* For a well behaved ULP state will be RDMA_CM_IDLE */
		id->route.addr.src_addr.ss_family = AF_INET;
		ret = rdma_bind_addr(id, cma_src_addr(id_priv));
		if (ret)
			return ret;
		if (WARN_ON(!cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND,
					   RDMA_CM_LISTEN)))
			return -EINVAL;
	}

	/*
	 * Once the ID reaches RDMA_CM_LISTEN it is not allowed to be reusable
	 * any more, and has to be unique in the bind list.
	 */
	if (id_priv->reuseaddr) {
		mutex_lock(&lock);
		ret = cma_check_port(id_priv->bind_list, id_priv, 0);
		if (!ret)
			id_priv->reuseaddr = 0;
		mutex_unlock(&lock);
		if (ret)
			goto err;
	}

	id_priv->backlog = backlog;
	if (id->device) { // 就是看 listen 的时候有没有指定设备咯
		if (rdma_cap_ib_cm(id->device, 1)) { // RoCE 也走这里
			ret = cma_ib_listen(id_priv);
			if (ret)
				goto err;
		} else if (rdma_cap_iw_cm(id->device, 1)) {
			ret = cma_iw_listen(id_priv, backlog);
			if (ret)
				goto err;
		} else {
			ret = -ENOSYS;
			goto err;
		}
	} else
		cma_listen_on_all(id_priv);  // 里面又会递归调用到 rdma_listen()->cma_ib_lieten()

	return 0;
err:
	id_priv->backlog = 0;
	/*
	 * All the failure paths that lead here will not allow the req_handler's
	 * to have run.
	 */
	cma_comp_exch(id_priv, RDMA_CM_LISTEN, RDMA_CM_ADDR_BOUND);
	return ret;
}
EXPORT_SYMBOL(rdma_listen);

// 将 addr 绑定到 id 上
//
// 本质就是根据传入的参数, 在 kernel 里做一些初始化 基本不会失败的
//
// 如果 addr 是 any addr 就不需要找一个 dev ? 直接分配或者绑定一个 port 就可以了
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct rdma_id_private *id_priv;
	int ret;
	struct sockaddr  *daddr;

	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6 &&
	    addr->sa_family != AF_IB)
		return -EAFNOSUPPORT;

	// ref: ucma_create_id
	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, RDMA_CM_IDLE, RDMA_CM_ADDR_BOUND)) // 切换连接状态
		return -EINVAL;

	ret = cma_check_linklocal(&id->route.addr.dev_addr, addr);
	if (ret)
		goto err1;

	// 将 addr copy 到了 id_priv 的 src addr 里了
	memcpy(cma_src_addr(id_priv), addr, rdma_addr_size(addr)); // 保存 addr 咯
	if (!cma_any_addr(addr)) { // 如果指定了地址(不是 zero addr)的话, 就会走这里
				   // 如果是 RoCE那么就是用 ip 地址找一个 网络设备, 然后将其 L2 copy 到 dev_addr 里
		ret = cma_translate_addr(addr, &id->route.addr.dev_addr); // 根据 addr 找到一个 dev, 然后设置 dev_addr, 对于 roce 来说, 就是用 ip 地址去找对应的 net device 的
		if (ret)
			goto err1;

		// id_priv 里的 dev_addr 已经保存了前面根据 addr (ip 地址) 找到的底层 mac 地址
		// 现在根据 id_priv 里的 dev_add.src_addr 来寻在 cma 这一层的那个 cma_dev
		ret = cma_acquire_dev_by_src_ip(id_priv);
		if (ret)
			goto err1;
	}
	// 注意: 如果是 any_addr 的话, 是不会找到一个 cma_dev 的

	if (!(id_priv->options & (1 << CMA_OPTION_AFONLY))) {
		if (addr->sa_family == AF_INET)
			id_priv->afonly = 1;
#if IS_ENABLED(CONFIG_IPV6)
		else if (addr->sa_family == AF_INET6) {
			struct net *net = id_priv->id.route.addr.dev_addr.net;

			id_priv->afonly = net->ipv6.sysctl.bindv6only;
		}
#endif
	}
	daddr = cma_dst_addr(id_priv);
	daddr->sa_family = addr->sa_family;

	// 继续填充 id_priv
	ret = cma_get_port(id_priv); // HERE
	if (ret)
		goto err2;

	return 0;
err2:
	if (id_priv->cma_dev)
		cma_release_dev(id_priv);
err1:
	cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_IDLE);
	return ret;
}
EXPORT_SYMBOL(rdma_bind_addr);

// id_priv 中提取信息, 来 format cma_hdr
static int cma_format_hdr(void *hdr, struct rdma_id_private *id_priv)
{
	struct cma_hdr *cma_hdr;

	cma_hdr = hdr;
	cma_hdr->cma_version = CMA_VERSION;
	if (cma_family(id_priv) == AF_INET) {
		struct sockaddr_in *src4, *dst4;

		src4 = (struct sockaddr_in *) cma_src_addr(id_priv);
		dst4 = (struct sockaddr_in *) cma_dst_addr(id_priv);

		cma_set_ip_ver(cma_hdr, 4);
		cma_hdr->src_addr.ip4.addr = src4->sin_addr.s_addr;
		cma_hdr->dst_addr.ip4.addr = dst4->sin_addr.s_addr;
		cma_hdr->port = src4->sin_port;
	} else if (cma_family(id_priv) == AF_INET6) {
		struct sockaddr_in6 *src6, *dst6;

		src6 = (struct sockaddr_in6 *) cma_src_addr(id_priv);
		dst6 = (struct sockaddr_in6 *) cma_dst_addr(id_priv);

		cma_set_ip_ver(cma_hdr, 6);
		cma_hdr->src_addr.ip6 = src6->sin6_addr;
		cma_hdr->dst_addr.ip6 = dst6->sin6_addr;
		cma_hdr->port = src6->sin6_port;
	}
	return 0;
}

// 处理 sidr rep 报文咯
static int cma_sidr_rep_handler(struct ib_cm_id *cm_id,
				const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	struct rdma_cm_event event = {};
	const struct ib_cm_sidr_rep_event_param *rep =
				&ib_event->param.sidr_rep_rcvd;
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	if (READ_ONCE(id_priv->state) != RDMA_CM_CONNECT)
		goto out;

	switch (ib_event->event) {
	case IB_CM_SIDR_REQ_ERROR:
		event.event = RDMA_CM_EVENT_UNREACHABLE;
		event.status = -ETIMEDOUT;
		break;
	case IB_CM_SIDR_REP_RECEIVED:
		event.param.ud.private_data = ib_event->private_data;
		event.param.ud.private_data_len = IB_CM_SIDR_REP_PRIVATE_DATA_SIZE;
		if (rep->status != IB_SIDR_SUCCESS) {
			event.event = RDMA_CM_EVENT_UNREACHABLE;
			event.status = ib_event->param.sidr_rep_rcvd.status;
			pr_debug_ratelimited("RDMA CM: UNREACHABLE: bad SIDR reply. status %d\n",
					     event.status);
			break;
		}
		ret = cma_set_qkey(id_priv, rep->qkey);
		if (ret) {
			pr_debug_ratelimited("RDMA CM: ADDR_ERROR: failed to set qkey. status %d\n", ret);
			event.event = RDMA_CM_EVENT_ADDR_ERROR;
			event.status = ret;
			break;
		}
		ib_init_ah_attr_from_path(id_priv->id.device,
					  id_priv->id.port_num,
					  id_priv->id.route.path_rec,
					  &event.param.ud.ah_attr,
					  rep->sgid_attr);
		event.param.ud.qp_num = rep->qpn;
		event.param.ud.qkey = rep->qkey;
		event.event = RDMA_CM_EVENT_ESTABLISHED;
		event.status = 0;
		break;
	default:
		pr_err("RDMA CMA: unexpected IB CM event: %d\n",
		       ib_event->event);
		goto out;
	}

	ret = cma_cm_event_handler(id_priv, &event);

	rdma_destroy_ah_attr(&event.param.ud.ah_attr);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		id_priv->cm_id.ib = NULL;
		destroy_id_handler_unlock(id_priv);
		return ret;
	}
out:
	mutex_unlock(&id_priv->handler_mutex);
	return 0;
}

// UD 类型的 connect 的时候用这个来触发 SIDR 交互
// 通过 SIDR 交互拿到 QPN / QUEUE key 等信息
static int cma_resolve_ib_udp(struct rdma_id_private *id_priv,
			      struct rdma_conn_param *conn_param)
{
	struct ib_cm_sidr_req_param req;
	struct ib_cm_id	*id;
	void *private_data;
	u8 offset;
	int ret;

	memset(&req, 0, sizeof req);
	offset = cma_user_data_offset(id_priv);
	req.private_data_len = offset + conn_param->private_data_len;
	if (req.private_data_len < conn_param->private_data_len)
		return -EINVAL;

	if (req.private_data_len) {
		private_data = kzalloc(req.private_data_len, GFP_ATOMIC);
		if (!private_data)
			return -ENOMEM;
	} else {
		private_data = NULL;
	}

	if (conn_param->private_data && conn_param->private_data_len)
		memcpy(private_data + offset, conn_param->private_data,
		       conn_param->private_data_len);

	if (private_data) {
		ret = cma_format_hdr(private_data, id_priv);
		if (ret)
			goto out;
		req.private_data = private_data;
	}

	// 为什么要创建一个新的 id ??? 这是要挂到底层的 id, 和 id_priv 不是一个 层次的
	id = ib_create_cm_id(id_priv->id.device, cma_sidr_rep_handler,
			     id_priv);
	if (IS_ERR(id)) {
		ret = PTR_ERR(id);
		goto out;
	}
	id_priv->cm_id.ib = id;

	req.path = id_priv->id.route.path_rec;
	req.sgid_attr = id_priv->id.route.addr.dev_addr.sgid_attr;
	req.service_id = rdma_get_service_id(&id_priv->id, cma_dst_addr(id_priv));
	req.timeout_ms = 1 << (CMA_CM_RESPONSE_TIMEOUT - 8);
	req.max_cm_retries = CMA_MAX_CM_RETRIES;

	trace_cm_send_sidr_req(id_priv);
	ret = ib_send_cm_sidr_req(id_priv->cm_id.ib, &req);
	if (ret) {
		ib_destroy_cm_id(id_priv->cm_id.ib);
		id_priv->cm_id.ib = NULL;
	}
out:
	kfree(private_data);
	return ret;
}

// non-UD 类型的 connect 流程
// 触发 REQ 消息交互
static int cma_connect_ib(struct rdma_id_private *id_priv,
			  struct rdma_conn_param *conn_param)
{
	struct ib_cm_req_param req;
	struct rdma_route *route;
	void *private_data;
	struct ib_cm_id	*id;
	u8 offset;
	int ret;

	memset(&req, 0, sizeof req);
	offset = cma_user_data_offset(id_priv);
	req.private_data_len = offset + conn_param->private_data_len;
	if (req.private_data_len < conn_param->private_data_len)
		return -EINVAL;

	if (req.private_data_len) {
		private_data = kzalloc(req.private_data_len, GFP_ATOMIC);
		if (!private_data)
			return -ENOMEM;
	} else {
		private_data = NULL;
	}

	if (conn_param->private_data && conn_param->private_data_len)
		memcpy(private_data + offset, conn_param->private_data,
		       conn_param->private_data_len);

	// 为什么要创建一个新的 id ??? 这是要挂到底层的 id, 和 id_priv 不是一个 层次的
	// connect 后收到第二次握手的 REP 后, 是 cma_ib_handler 负责发出第三次握手的 RTU 报文
	id = ib_create_cm_id(id_priv->id.device, cma_ib_handler, id_priv);
	if (IS_ERR(id)) {
		ret = PTR_ERR(id);
		goto out;
	}
	id_priv->cm_id.ib = id;

	route = &id_priv->id.route;
	if (private_data) {
		ret = cma_format_hdr(private_data, id_priv);
		if (ret)
			goto out;
		req.private_data = private_data;
	}

	req.primary_path = &route->path_rec[0];
	if (route->num_paths == 2)
		req.alternate_path = &route->path_rec[1];

	req.ppath_sgid_attr = id_priv->id.route.addr.dev_addr.sgid_attr;
	/* Alternate path SGID attribute currently unsupported */
	req.service_id = rdma_get_service_id(&id_priv->id, cma_dst_addr(id_priv));
	req.qp_num = id_priv->qp_num;
	req.qp_type = id_priv->id.qp_type;
	req.starting_psn = id_priv->seq_num;
	req.responder_resources = conn_param->responder_resources;
	req.initiator_depth = conn_param->initiator_depth;
	req.flow_control = conn_param->flow_control;
	req.retry_count = min_t(u8, 7, conn_param->retry_count);
	req.rnr_retry_count = min_t(u8, 7, conn_param->rnr_retry_count);
	req.remote_cm_response_timeout = CMA_CM_RESPONSE_TIMEOUT;
	req.local_cm_response_timeout = CMA_CM_RESPONSE_TIMEOUT;
	req.max_cm_retries = CMA_MAX_CM_RETRIES;
	req.srq = id_priv->srq ? 1 : 0;
	req.ece.vendor_id = id_priv->ece.vendor_id;
	req.ece.attr_mod = id_priv->ece.attr_mod;

	trace_cm_send_req(id_priv);
	ret = ib_send_cm_req(id_priv->cm_id.ib, &req);
out:
	if (ret && !IS_ERR(id)) {
		ib_destroy_cm_id(id);
		id_priv->cm_id.ib = NULL;
	}

	kfree(private_data);
	return ret;
}

// iwarp
static int cma_connect_iw(struct rdma_id_private *id_priv,
			  struct rdma_conn_param *conn_param)
{
	struct iw_cm_id *cm_id;
	int ret;
	struct iw_cm_conn_param iw_param;

	cm_id = iw_create_cm_id(id_priv->id.device, cma_iw_handler, id_priv);
	if (IS_ERR(cm_id))
		return PTR_ERR(cm_id);

	cm_id->tos = id_priv->tos;
	cm_id->tos_set = id_priv->tos_set;
	id_priv->cm_id.iw = cm_id;

	memcpy(&cm_id->local_addr, cma_src_addr(id_priv),
	       rdma_addr_size(cma_src_addr(id_priv)));
	memcpy(&cm_id->remote_addr, cma_dst_addr(id_priv),
	       rdma_addr_size(cma_dst_addr(id_priv)));

	ret = cma_modify_qp_rtr(id_priv, conn_param);
	if (ret)
		goto out;

	if (conn_param) {
		iw_param.ord = conn_param->initiator_depth;
		iw_param.ird = conn_param->responder_resources;
		iw_param.private_data = conn_param->private_data;
		iw_param.private_data_len = conn_param->private_data_len;
		iw_param.qpn = id_priv->id.qp ? id_priv->qp_num : conn_param->qp_num;
	} else {
		memset(&iw_param, 0, sizeof iw_param);
		iw_param.qpn = id_priv->qp_num;
	}
	ret = iw_cm_connect(cm_id, &iw_param);
out:
	if (ret) {
		iw_destroy_cm_id(cm_id);
		id_priv->cm_id.iw = NULL;
	}
	return ret;
}

/**
 * rdma_connect_locked - Initiate an active connection request.
 * @id: Connection identifier to connect.
 * @conn_param: Connection information used for connected QPs.
 *
 * Same as rdma_connect() but can only be called from the
 * RDMA_CM_EVENT_ROUTE_RESOLVED handler callback.
 */
int rdma_connect_locked(struct rdma_cm_id *id,
			struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	int ret;

	if (!cma_comp_exch(id_priv, RDMA_CM_ROUTE_RESOLVED, RDMA_CM_CONNECT))
		return -EINVAL;

	if (!id->qp) {
		id_priv->qp_num = conn_param->qp_num;
		id_priv->srq = conn_param->srq;
	}

	if (rdma_cap_ib_cm(id->device, id->port_num)) { // ib, roce 都走到这里的  ref: %RDMA_CORE_PORT_IBA_ROCE
		if (id->qp_type == IB_QPT_UD)
			ret = cma_resolve_ib_udp(id_priv, conn_param);
		else
			ret = cma_connect_ib(id_priv, conn_param);
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) // iwarp
		ret = cma_connect_iw(id_priv, conn_param);
	else
		ret = -ENOSYS;
	if (ret)
		goto err_state;
	return 0;
err_state:
	cma_comp_exch(id_priv, RDMA_CM_CONNECT, RDMA_CM_ROUTE_RESOLVED);
	return ret;
}
EXPORT_SYMBOL(rdma_connect_locked);

/**
 * rdma_connect - Initiate an active connection request.
 * @id: Connection identifier to connect.
 * @conn_param: Connection information used for connected QPs.
 *
 * Users must have resolved a route for the rdma_cm_id to connect with by having
 * called rdma_resolve_route before calling this routine.
 *
 * This call will either connect to a remote QP or obtain remote QP information
 * for unconnected rdma_cm_id's.  The actual operation is based on the
 * rdma_cm_id's port space.
 */
int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	ret = rdma_connect_locked(id, conn_param);
	mutex_unlock(&id_priv->handler_mutex);
	return ret;
}
EXPORT_SYMBOL(rdma_connect);

/**
 * rdma_connect_ece - Initiate an active connection request with ECE data.
 * @id: Connection identifier to connect.
 * @conn_param: Connection information used for connected QPs.
 * @ece: ECE parameters
 *
 * See rdma_connect() explanation.
 */
int rdma_connect_ece(struct rdma_cm_id *id, struct rdma_conn_param *conn_param,
		     struct rdma_ucm_ece *ece)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);

	id_priv->ece.vendor_id = ece->vendor_id;
	id_priv->ece.attr_mod = ece->attr_mod;

	return rdma_connect(id, conn_param);
}
EXPORT_SYMBOL(rdma_connect_ece);

// ref: rdma_accept()
// accept() 的时候才会触发 rep message 的发送, 这个 和 tcp 不同
static int cma_accept_ib(struct rdma_id_private *id_priv,
			 struct rdma_conn_param *conn_param)
{
	struct ib_cm_rep_param rep;
	int ret;

	ret = cma_modify_qp_rtr(id_priv, conn_param);
	if (ret)
		goto out;

	ret = cma_modify_qp_rts(id_priv, conn_param);
	if (ret)
		goto out;

	memset(&rep, 0, sizeof rep);
	rep.qp_num = id_priv->qp_num;
	rep.starting_psn = id_priv->seq_num;
	rep.private_data = conn_param->private_data;
	rep.private_data_len = conn_param->private_data_len;
	rep.responder_resources = conn_param->responder_resources;
	rep.initiator_depth = conn_param->initiator_depth;
	rep.failover_accepted = 0;
	rep.flow_control = conn_param->flow_control;
	rep.rnr_retry_count = min_t(u8, 7, conn_param->rnr_retry_count);
	rep.srq = id_priv->srq ? 1 : 0;
	rep.ece.vendor_id = id_priv->ece.vendor_id;
	rep.ece.attr_mod = id_priv->ece.attr_mod;

	trace_cm_send_rep(id_priv);
	ret = ib_send_cm_rep(id_priv->cm_id.ib, &rep);
out:
	return ret;
}

// iwarp
static int cma_accept_iw(struct rdma_id_private *id_priv,
		  struct rdma_conn_param *conn_param)
{
	struct iw_cm_conn_param iw_param;
	int ret;

	if (!conn_param)
		return -EINVAL;

	ret = cma_modify_qp_rtr(id_priv, conn_param);
	if (ret)
		return ret;

	iw_param.ord = conn_param->initiator_depth;
	iw_param.ird = conn_param->responder_resources;
	iw_param.private_data = conn_param->private_data;
	iw_param.private_data_len = conn_param->private_data_len;
	if (id_priv->id.qp) {
		iw_param.qpn = id_priv->qp_num;
	} else
		iw_param.qpn = conn_param->qp_num;

	return iw_cm_accept(id_priv->cm_id.iw, &iw_param);
}

// ref: IB Spec vol1 Ch12 
static int cma_send_sidr_rep(struct rdma_id_private *id_priv,
			     enum ib_cm_sidr_status status, u32 qkey,
			     const void *private_data, int private_data_len)
{
	struct ib_cm_sidr_rep_param rep;
	int ret;

	memset(&rep, 0, sizeof rep);
	rep.status = status;
	if (status == IB_SIDR_SUCCESS) {
		ret = cma_set_qkey(id_priv, qkey);
		if (ret)
			return ret;
		rep.qp_num = id_priv->qp_num;
		rep.qkey = id_priv->qkey;

		rep.ece.vendor_id = id_priv->ece.vendor_id;
		rep.ece.attr_mod = id_priv->ece.attr_mod;
	}

	rep.private_data = private_data;
	rep.private_data_len = private_data_len;

	trace_cm_send_sidr_rep(id_priv);
	return ib_send_cm_sidr_rep(id_priv->cm_id.ib, &rep);
}

/**
 * rdma_accept - Called to accept a connection request or response.
 * @id: Connection identifier associated with the request.
 * @conn_param: Information needed to establish the connection.  This must be
 *   provided if accepting a connection request.  If accepting a connection
 *   response, this parameter must be NULL.
 *
 * Typically, this routine is only called by the listener to accept a connection
 * request.  It must also be called on the active side of a connection if the
 * user is performing their own QP transitions.
 *
 * In the case of error, a reject message is sent to the remote side and the
 * state of the qp associated with the id is modified to error, such that any
 * previously posted receive buffers would be flushed.
 *
 * This function is for use by kernel ULPs and must be called from under the
 * handler callback.
 */

// 比较有趣的是, 与 TCP 不同, 第二次握手的报文是 accept 触发的(ib_send_cm_rep()), 是因为第二次握手需要一些用户提供的信息
// 第二点与 TCP 不同的时, accept 传入的这个 id 不是 listen id. 而是在收到 mad req 请求的时候, 内核通过 RDMA_CM_EVENT_CONNECT_REQUEST 通知了用户空间, 这时候在 EVENT 里已经携带了一个 id 给 userspace 了, userspace 用那个 id 直接来 accept. ref: cma_ib_req_handler
// 第三点不同的是, 不是通过 accept() 的返回来告诉 usersapce 或者其他模块有连接来了, 而是通过 RDMA_CM_EVENT_CONNECT_REQUEST 事件通知 userspace, 而且直接将新的 id(类似 socket) 直接返回回去了. 二 usespace 或者其他模块可以选择 reject (rdma_reject())这个连接出发 REJ 报文的发送
int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	int ret;

	lockdep_assert_held(&id_priv->handler_mutex);

	if (READ_ONCE(id_priv->state) != RDMA_CM_CONNECT)
		return -EINVAL;

	if (!id->qp && conn_param) {
		id_priv->qp_num = conn_param->qp_num;
		id_priv->srq = conn_param->srq;
	}

	if (rdma_cap_ib_cm(id->device, id->port_num)) {
		if (id->qp_type == IB_QPT_UD) {
			if (conn_param)
				ret = cma_send_sidr_rep(id_priv, IB_SIDR_SUCCESS,
							conn_param->qkey,
							conn_param->private_data,
							conn_param->private_data_len);
			else
				ret = cma_send_sidr_rep(id_priv, IB_SIDR_SUCCESS,
							0, NULL, 0);
		} else { // RC 服务走这里
			if (conn_param)
				ret = cma_accept_ib(id_priv, conn_param);
			else
				ret = cma_rep_recv(id_priv);
		}
	} else if (rdma_cap_iw_cm(id->device, id->port_num))
		ret = cma_accept_iw(id_priv, conn_param);
	else
		ret = -ENOSYS;

	if (ret)
		goto reject;

	return 0;
reject:
	cma_modify_qp_err(id_priv);
	rdma_reject(id, NULL, 0, IB_CM_REJ_CONSUMER_DEFINED);
	return ret;
}
EXPORT_SYMBOL(rdma_accept);

int rdma_accept_ece(struct rdma_cm_id *id, struct rdma_conn_param *conn_param,
		    struct rdma_ucm_ece *ece)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);

	id_priv->ece.vendor_id = ece->vendor_id;
	id_priv->ece.attr_mod = ece->attr_mod;

	return rdma_accept(id, conn_param);
}
EXPORT_SYMBOL(rdma_accept_ece);

void rdma_lock_handler(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);

	mutex_lock(&id_priv->handler_mutex);
}
EXPORT_SYMBOL(rdma_lock_handler);

void rdma_unlock_handler(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);

	mutex_unlock(&id_priv->handler_mutex);
}
EXPORT_SYMBOL(rdma_unlock_handler);

int rdma_notify(struct rdma_cm_id *id, enum ib_event_type event)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!id_priv->cm_id.ib)
		return -EINVAL;

	switch (id->device->node_type) {
	case RDMA_NODE_IB_CA:
		ret = ib_cm_notify(id_priv->cm_id.ib, event);
		break;
	default:
		ret = 0;
		break;
	}
	return ret;
}
EXPORT_SYMBOL(rdma_notify);

// 这里和 tcp 也不同, 用户在 listen 之后不仅仅可以 accept() 还可以主动 reject
int rdma_reject(struct rdma_cm_id *id, const void *private_data,
		u8 private_data_len, u8 reason)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!id_priv->cm_id.ib)
		return -EINVAL;

	if (rdma_cap_ib_cm(id->device, id->port_num)) {
		if (id->qp_type == IB_QPT_UD) {
			ret = cma_send_sidr_rep(id_priv, IB_SIDR_REJECT, 0,
						private_data, private_data_len);
		} else {
			trace_cm_send_rej(id_priv);
			ret = ib_send_cm_rej(id_priv->cm_id.ib, reason, NULL, 0,
					     private_data, private_data_len);
		}
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) {
		ret = iw_cm_reject(id_priv->cm_id.iw,
				   private_data, private_data_len);
	} else
		ret = -ENOSYS;

	return ret;
}
EXPORT_SYMBOL(rdma_reject);

// 发送 dreq 消息, 断开连接咯
int rdma_disconnect(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!id_priv->cm_id.ib)
		return -EINVAL;

	if (rdma_cap_ib_cm(id->device, id->port_num)) {
		ret = cma_modify_qp_err(id_priv);
		if (ret)
			goto out;
		/* Initiate or respond to a disconnect. */
		trace_cm_disconnect(id_priv);
		if (ib_send_cm_dreq(id_priv->cm_id.ib, NULL, 0)) {
			if (!ib_send_cm_drep(id_priv->cm_id.ib, NULL, 0))
				trace_cm_sent_drep(id_priv);
		} else {
			trace_cm_sent_dreq(id_priv);
		}
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) {
		ret = iw_cm_disconnect(id_priv->cm_id.iw, 0);
	} else
		ret = -EINVAL;

out:
	return ret;
}
EXPORT_SYMBOL(rdma_disconnect);

// multicast 相关
static void cma_make_mc_event(int status, struct rdma_id_private *id_priv,
			      struct ib_sa_multicast *multicast,
			      struct rdma_cm_event *event,
			      struct cma_multicast *mc)
{
	struct rdma_dev_addr *dev_addr;
	enum ib_gid_type gid_type;
	struct net_device *ndev;

	if (!status)
		status = cma_set_qkey(id_priv, be32_to_cpu(multicast->rec.qkey));
	else
		pr_debug_ratelimited("RDMA CM: MULTICAST_ERROR: failed to join multicast. status %d\n",
				     status);

	event->status = status;
	event->param.ud.private_data = mc->context;
	if (status) {
		event->event = RDMA_CM_EVENT_MULTICAST_ERROR;
		return;
	}

	dev_addr = &id_priv->id.route.addr.dev_addr;
	ndev = dev_get_by_index(dev_addr->net, dev_addr->bound_dev_if);
	gid_type =
		id_priv->cma_dev
			->default_gid_type[id_priv->id.port_num -
					   rdma_start_port(
						   id_priv->cma_dev->device)];

	event->event = RDMA_CM_EVENT_MULTICAST_JOIN;
	if (ib_init_ah_from_mcmember(id_priv->id.device, id_priv->id.port_num,
				     &multicast->rec, ndev, gid_type,
				     &event->param.ud.ah_attr)) {
		event->event = RDMA_CM_EVENT_MULTICAST_ERROR;
		goto out;
	}

	event->param.ud.qp_num = 0xFFFFFF;
	event->param.ud.qkey = be32_to_cpu(multicast->rec.qkey);

out:
	if (ndev)
		dev_put(ndev);
}

static int cma_ib_mc_handler(int status, struct ib_sa_multicast *multicast)
{
	struct cma_multicast *mc = multicast->context;
	struct rdma_id_private *id_priv = mc->id_priv;
	struct rdma_cm_event event = {};
	int ret = 0;

	mutex_lock(&id_priv->handler_mutex);
	if (READ_ONCE(id_priv->state) == RDMA_CM_DEVICE_REMOVAL ||
	    READ_ONCE(id_priv->state) == RDMA_CM_DESTROYING)
		goto out;

	cma_make_mc_event(status, id_priv, multicast, &event, mc);
	ret = cma_cm_event_handler(id_priv, &event);
	rdma_destroy_ah_attr(&event.param.ud.ah_attr);
	if (ret) {
		destroy_id_handler_unlock(id_priv);
		return 0;
	}

out:
	mutex_unlock(&id_priv->handler_mutex);
	return 0;
}

// mulitcast 相关
static void cma_set_mgid(struct rdma_id_private *id_priv,
			 struct sockaddr *addr, union ib_gid *mgid)
{
	unsigned char mc_map[MAX_ADDR_LEN];
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	struct sockaddr_in *sin = (struct sockaddr_in *) addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) addr;

	if (cma_any_addr(addr)) {
		memset(mgid, 0, sizeof *mgid);
	} else if ((addr->sa_family == AF_INET6) &&
		   ((be32_to_cpu(sin6->sin6_addr.s6_addr32[0]) & 0xFFF0FFFF) ==
								 0xFF10A01B)) {
		/* IPv6 address is an SA assigned MGID. */
		memcpy(mgid, &sin6->sin6_addr, sizeof *mgid);
	} else if (addr->sa_family == AF_IB) {
		memcpy(mgid, &((struct sockaddr_ib *) addr)->sib_addr, sizeof *mgid);
	} else if (addr->sa_family == AF_INET6) {
		ipv6_ib_mc_map(&sin6->sin6_addr, dev_addr->broadcast, mc_map);
		if (id_priv->id.ps == RDMA_PS_UDP)
			mc_map[7] = 0x01;	/* Use RDMA CM signature */
		*mgid = *(union ib_gid *) (mc_map + 4);
	} else {
		ip_ib_mc_map(sin->sin_addr.s_addr, dev_addr->broadcast, mc_map);
		if (id_priv->id.ps == RDMA_PS_UDP)
			mc_map[7] = 0x01;	/* Use RDMA CM signature */
		*mgid = *(union ib_gid *) (mc_map + 4);
	}
}

static int cma_join_ib_multicast(struct rdma_id_private *id_priv,
				 struct cma_multicast *mc)
{
	struct ib_sa_mcmember_rec rec;
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	ib_sa_comp_mask comp_mask;
	int ret;

	ib_addr_get_mgid(dev_addr, &rec.mgid);
	ret = ib_sa_get_mcmember_rec(id_priv->id.device, id_priv->id.port_num,
				     &rec.mgid, &rec);
	if (ret)
		return ret;

	ret = cma_set_qkey(id_priv, 0);
	if (ret)
		return ret;

	cma_set_mgid(id_priv, (struct sockaddr *) &mc->addr, &rec.mgid);
	rec.qkey = cpu_to_be32(id_priv->qkey);
	rdma_addr_get_sgid(dev_addr, &rec.port_gid);
	rec.pkey = cpu_to_be16(ib_addr_get_pkey(dev_addr));
	rec.join_state = mc->join_state;

	if ((rec.join_state == BIT(SENDONLY_FULLMEMBER_JOIN)) &&
	    (!ib_sa_sendonly_fullmem_support(&sa_client,
					     id_priv->id.device,
					     id_priv->id.port_num))) {
		dev_warn(
			&id_priv->id.device->dev,
			"RDMA CM: port %u Unable to multicast join: SM doesn't support Send Only Full Member option\n",
			id_priv->id.port_num);
		return -EOPNOTSUPP;
	}

	comp_mask = IB_SA_MCMEMBER_REC_MGID | IB_SA_MCMEMBER_REC_PORT_GID |
		    IB_SA_MCMEMBER_REC_PKEY | IB_SA_MCMEMBER_REC_JOIN_STATE |
		    IB_SA_MCMEMBER_REC_QKEY | IB_SA_MCMEMBER_REC_SL |
		    IB_SA_MCMEMBER_REC_FLOW_LABEL |
		    IB_SA_MCMEMBER_REC_TRAFFIC_CLASS;

	if (id_priv->id.ps == RDMA_PS_IPOIB)
		comp_mask |= IB_SA_MCMEMBER_REC_RATE |
			     IB_SA_MCMEMBER_REC_RATE_SELECTOR |
			     IB_SA_MCMEMBER_REC_MTU_SELECTOR |
			     IB_SA_MCMEMBER_REC_MTU |
			     IB_SA_MCMEMBER_REC_HOP_LIMIT;

	mc->sa_mc = ib_sa_join_multicast(&sa_client, id_priv->id.device,
					 id_priv->id.port_num, &rec, comp_mask,
					 GFP_KERNEL, cma_ib_mc_handler, mc);
	return PTR_ERR_OR_ZERO(mc->sa_mc);
}

static void cma_iboe_set_mgid(struct sockaddr *addr, union ib_gid *mgid,
			      enum ib_gid_type gid_type)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

	if (cma_any_addr(addr)) {
		memset(mgid, 0, sizeof *mgid);
	} else if (addr->sa_family == AF_INET6) {
		memcpy(mgid, &sin6->sin6_addr, sizeof *mgid);
	} else {
		mgid->raw[0] =
			(gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP) ? 0 : 0xff;
		mgid->raw[1] =
			(gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP) ? 0 : 0x0e;
		mgid->raw[2] = 0;
		mgid->raw[3] = 0;
		mgid->raw[4] = 0;
		mgid->raw[5] = 0;
		mgid->raw[6] = 0;
		mgid->raw[7] = 0;
		mgid->raw[8] = 0;
		mgid->raw[9] = 0;
		mgid->raw[10] = 0xff;
		mgid->raw[11] = 0xff;
		*(__be32 *)(&mgid->raw[12]) = sin->sin_addr.s_addr;
	}
}

static int cma_iboe_join_multicast(struct rdma_id_private *id_priv,
				   struct cma_multicast *mc)
{
	struct cma_work *work;
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	int err = 0;
	struct sockaddr *addr = (struct sockaddr *)&mc->addr;
	struct net_device *ndev = NULL;
	struct ib_sa_multicast ib;
	enum ib_gid_type gid_type;
	bool send_only;

	send_only = mc->join_state == BIT(SENDONLY_FULLMEMBER_JOIN);

	if (cma_zero_addr(addr))
		return -EINVAL;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	gid_type = id_priv->cma_dev->default_gid_type[id_priv->id.port_num -
		   rdma_start_port(id_priv->cma_dev->device)];
	cma_iboe_set_mgid(addr, &ib.rec.mgid, gid_type);

	ib.rec.pkey = cpu_to_be16(0xffff);
	if (id_priv->id.ps == RDMA_PS_UDP)
		ib.rec.qkey = cpu_to_be32(RDMA_UDP_QKEY);

	if (dev_addr->bound_dev_if)
		ndev = dev_get_by_index(dev_addr->net, dev_addr->bound_dev_if);
	if (!ndev) {
		err = -ENODEV;
		goto err_free;
	}
	ib.rec.rate = iboe_get_rate(ndev);
	ib.rec.hop_limit = 1;
	ib.rec.mtu = iboe_get_mtu(ndev->mtu);

	if (addr->sa_family == AF_INET) {
		if (gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP) {
			ib.rec.hop_limit = IPV6_DEFAULT_HOPLIMIT;
			if (!send_only) {
				err = cma_igmp_send(ndev, &ib.rec.mgid,
						    true);
			}
		}
	} else {
		if (gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP)
			err = -ENOTSUPP;
	}
	dev_put(ndev);
	if (err || !ib.rec.mtu) {
		if (!err)
			err = -EINVAL;
		goto err_free;
	}
	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.src_addr,
		    &ib.rec.port_gid);
	work->id = id_priv;
	INIT_WORK(&work->work, cma_work_handler);
	cma_make_mc_event(0, id_priv, &ib, &work->event, mc);
	/* Balances with cma_id_put() in cma_work_handler */
	cma_id_get(id_priv);
	queue_work(cma_wq, &work->work);
	return 0;

err_free:
	kfree(work);
	return err;
}

int rdma_join_multicast(struct rdma_cm_id *id, struct sockaddr *addr,
			u8 join_state, void *context)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	struct cma_multicast *mc;
	int ret;

	/* Not supported for kernel QPs */
	if (WARN_ON(id->qp))
		return -EINVAL;

	/* ULP is calling this wrong. */
	if (!id->device || (READ_ONCE(id_priv->state) != RDMA_CM_ADDR_BOUND &&
			    READ_ONCE(id_priv->state) != RDMA_CM_ADDR_RESOLVED))
		return -EINVAL;

	mc = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc)
		return -ENOMEM;

	memcpy(&mc->addr, addr, rdma_addr_size(addr));
	mc->context = context;
	mc->id_priv = id_priv;
	mc->join_state = join_state;

	if (rdma_protocol_roce(id->device, id->port_num)) {
		ret = cma_iboe_join_multicast(id_priv, mc);
		if (ret)
			goto out_err;
	} else if (rdma_cap_ib_mcast(id->device, id->port_num)) {
		ret = cma_join_ib_multicast(id_priv, mc);
		if (ret)
			goto out_err;
	} else {
		ret = -ENOSYS;
		goto out_err;
	}

	spin_lock(&id_priv->lock);
	list_add(&mc->list, &id_priv->mc_list);
	spin_unlock(&id_priv->lock);

	return 0;
out_err:
	kfree(mc);
	return ret;
}
EXPORT_SYMBOL(rdma_join_multicast);

void rdma_leave_multicast(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct rdma_id_private *id_priv;
	struct cma_multicast *mc;

	id_priv = container_of(id, struct rdma_id_private, id);
	spin_lock_irq(&id_priv->lock);
	list_for_each_entry(mc, &id_priv->mc_list, list) {
		if (memcmp(&mc->addr, addr, rdma_addr_size(addr)) != 0)
			continue;
		list_del(&mc->list);
		spin_unlock_irq(&id_priv->lock);

		WARN_ON(id_priv->cma_dev->device != id->device);
		destroy_mc(id_priv, mc);
		return;
	}
	spin_unlock_irq(&id_priv->lock);
}
EXPORT_SYMBOL(rdma_leave_multicast);

// 内核通知链机制, 监控底层设备变化
static int cma_netdev_change(struct net_device *ndev, struct rdma_id_private *id_priv)
{
	struct rdma_dev_addr *dev_addr;
	struct cma_work *work;

	dev_addr = &id_priv->id.route.addr.dev_addr;

	if ((dev_addr->bound_dev_if == ndev->ifindex) &&
	    (net_eq(dev_net(ndev), dev_addr->net)) &&
	    memcmp(dev_addr->src_dev_addr, ndev->dev_addr, ndev->addr_len)) {
		pr_info("RDMA CM addr change for ndev %s used by id %p\n",
			ndev->name, &id_priv->id);
		work = kzalloc(sizeof *work, GFP_KERNEL);
		if (!work)
			return -ENOMEM;

		INIT_WORK(&work->work, cma_work_handler);
		work->id = id_priv;
		work->event.event = RDMA_CM_EVENT_ADDR_CHANGE;
		cma_id_get(id_priv);
		queue_work(cma_wq, &work->work);
	}

	return 0;
}

static int cma_netdev_callback(struct notifier_block *self, unsigned long event,
			       void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct cma_device *cma_dev;
	struct rdma_id_private *id_priv;
	int ret = NOTIFY_DONE;

	if (event != NETDEV_BONDING_FAILOVER)
		return NOTIFY_DONE;

	if (!netif_is_bond_master(ndev))
		return NOTIFY_DONE;

	mutex_lock(&lock);
	list_for_each_entry(cma_dev, &dev_list, list)
		list_for_each_entry(id_priv, &cma_dev->id_list, list) {
			ret = cma_netdev_change(ndev, id_priv);
			if (ret)
				goto out;
		}

out:
	mutex_unlock(&lock);
	return ret;
}

static struct notifier_block cma_nb = {
	.notifier_call = cma_netdev_callback
};

// 注册到 ib 核心模块, 检测 ib 设备的添加
static int cma_add_one(struct ib_device *device)
{
	struct cma_device *cma_dev;
	struct rdma_id_private *id_priv;
	unsigned int i;
	unsigned long supported_gids = 0;
	int ret;

	cma_dev = kmalloc(sizeof *cma_dev, GFP_KERNEL);
	if (!cma_dev)
		return -ENOMEM;

	cma_dev->device = device;
	cma_dev->default_gid_type = kcalloc(device->phys_port_cnt,
					    sizeof(*cma_dev->default_gid_type),
					    GFP_KERNEL);
	if (!cma_dev->default_gid_type) {
		ret = -ENOMEM;
		goto free_cma_dev;
	}

	cma_dev->default_roce_tos = kcalloc(device->phys_port_cnt,
					    sizeof(*cma_dev->default_roce_tos),
					    GFP_KERNEL);
	if (!cma_dev->default_roce_tos) {
		ret = -ENOMEM;
		goto free_gid_type;
	}

	rdma_for_each_port (device, i) {
		supported_gids = roce_gid_type_mask_support(device, i);
		WARN_ON(!supported_gids);
		if (supported_gids & (1 << CMA_PREFERRED_ROCE_GID_TYPE))
			cma_dev->default_gid_type[i - rdma_start_port(device)] =
				CMA_PREFERRED_ROCE_GID_TYPE;
		else
			cma_dev->default_gid_type[i - rdma_start_port(device)] =
				find_first_bit(&supported_gids, BITS_PER_LONG);
		cma_dev->default_roce_tos[i - rdma_start_port(device)] = 0;
	}

	init_completion(&cma_dev->comp);
	refcount_set(&cma_dev->refcount, 1);
	INIT_LIST_HEAD(&cma_dev->id_list);
	ib_set_client_data(device, &cma_client, cma_dev);

	mutex_lock(&lock);
	list_add_tail(&cma_dev->list, &dev_list);
	list_for_each_entry(id_priv, &listen_any_list, list)
		cma_listen_on_dev(id_priv, cma_dev);
	mutex_unlock(&lock);

	trace_cm_add_one(device);
	return 0;

free_gid_type:
	kfree(cma_dev->default_gid_type);

free_cma_dev:
	kfree(cma_dev);
	return ret;
}

static void cma_send_device_removal_put(struct rdma_id_private *id_priv)
{
	struct rdma_cm_event event = { .event = RDMA_CM_EVENT_DEVICE_REMOVAL };
	enum rdma_cm_state state;
	unsigned long flags;

	mutex_lock(&id_priv->handler_mutex);
	/* Record that we want to remove the device */
	spin_lock_irqsave(&id_priv->lock, flags);
	state = id_priv->state;
	if (state == RDMA_CM_DESTROYING || state == RDMA_CM_DEVICE_REMOVAL) {
		spin_unlock_irqrestore(&id_priv->lock, flags);
		mutex_unlock(&id_priv->handler_mutex);
		cma_id_put(id_priv);
		return;
	}
	id_priv->state = RDMA_CM_DEVICE_REMOVAL;
	spin_unlock_irqrestore(&id_priv->lock, flags);

	if (cma_cm_event_handler(id_priv, &event)) {
		/*
		 * At this point the ULP promises it won't call
		 * rdma_destroy_id() concurrently
		 */
		cma_id_put(id_priv);
		mutex_unlock(&id_priv->handler_mutex);
		trace_cm_id_destroy(id_priv);
		_destroy_id(id_priv, state);
		return;
	}
	mutex_unlock(&id_priv->handler_mutex);

	/*
	 * If this races with destroy then the thread that first assigns state
	 * to a destroying does the cancel.
	 */
	cma_cancel_operation(id_priv, state);
	cma_id_put(id_priv);
}

static void cma_process_remove(struct cma_device *cma_dev)
{
	mutex_lock(&lock);
	while (!list_empty(&cma_dev->id_list)) {
		struct rdma_id_private *id_priv = list_first_entry(
			&cma_dev->id_list, struct rdma_id_private, list);

		list_del(&id_priv->listen_list);
		list_del_init(&id_priv->list);
		cma_id_get(id_priv);
		mutex_unlock(&lock);

		cma_send_device_removal_put(id_priv);

		mutex_lock(&lock);
	}
	mutex_unlock(&lock);

	cma_dev_put(cma_dev);
	wait_for_completion(&cma_dev->comp);
}

static void cma_remove_one(struct ib_device *device, void *client_data)
{
	struct cma_device *cma_dev = client_data;

	trace_cm_remove_one(device);

	mutex_lock(&lock);
	list_del(&cma_dev->list);
	mutex_unlock(&lock);

	cma_process_remove(cma_dev);
	kfree(cma_dev->default_roce_tos);
	kfree(cma_dev->default_gid_type);
	kfree(cma_dev);
}

static int cma_init_net(struct net *net)
{
	struct cma_pernet *pernet = cma_pernet(net);

	xa_init(&pernet->tcp_ps);
	xa_init(&pernet->udp_ps);
	xa_init(&pernet->ipoib_ps);
	xa_init(&pernet->ib_ps);

	return 0;
}

static void cma_exit_net(struct net *net)
{
	struct cma_pernet *pernet = cma_pernet(net);

	WARN_ON(!xa_empty(&pernet->tcp_ps));
	WARN_ON(!xa_empty(&pernet->udp_ps));
	WARN_ON(!xa_empty(&pernet->ipoib_ps));
	WARN_ON(!xa_empty(&pernet->ib_ps));
}

static struct pernet_operations cma_pernet_operations = {
	.init = cma_init_net,
	.exit = cma_exit_net,
	.id = &cma_pernet_id,
	.size = sizeof(struct cma_pernet),
};

static int __init cma_init(void)
{
	int ret;

	/*
	 * There is a rare lock ordering dependency in cma_netdev_callback()
	 * that only happens when bonding is enabled. Teach lockdep that rtnl
	 * must never be nested under lock so it can find these without having
	 * to test with bonding.
	 */
	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		mutex_lock(&lock);
		rtnl_lock();
		mutex_unlock(&lock);
		rtnl_unlock();
	}

	cma_wq = alloc_ordered_workqueue("rdma_cm", WQ_MEM_RECLAIM);
	if (!cma_wq)
		return -ENOMEM;

	ret = register_pernet_subsys(&cma_pernet_operations);
	if (ret)
		goto err_wq;

	ib_sa_register_client(&sa_client);
	register_netdevice_notifier(&cma_nb);

	ret = ib_register_client(&cma_client);
	if (ret)
		goto err;

	ret = cma_configfs_init();
	if (ret)
		goto err_ib;

	return 0;

err_ib:
	ib_unregister_client(&cma_client);
err:
	unregister_netdevice_notifier(&cma_nb);
	ib_sa_unregister_client(&sa_client);
	unregister_pernet_subsys(&cma_pernet_operations);
err_wq:
	destroy_workqueue(cma_wq);
	return ret;
}

static void __exit cma_cleanup(void)
{
	cma_configfs_exit();
	ib_unregister_client(&cma_client);
	unregister_netdevice_notifier(&cma_nb);
	ib_sa_unregister_client(&sa_client);
	unregister_pernet_subsys(&cma_pernet_operations);
	destroy_workqueue(cma_wq);
}

module_init(cma_init);
module_exit(cma_cleanup);
