/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 */

#ifndef RDMA_CM_H
#define RDMA_CM_H

#include <linux/socket.h>
#include <linux/in6.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_sa.h>
#include <uapi/rdma/rdma_user_cm.h>

/*
 * Upon receiving a device removal event, users must destroy the associated
 * RDMA identifier and release all resources allocated with the device.
 */

// 和 userspace 交互的事件
enum rdma_cm_event_type {
	RDMA_CM_EVENT_ADDR_RESOLVED,          // 地址解析成功
	RDMA_CM_EVENT_ADDR_ERROR,             // 地址解析失败
	RDMA_CM_EVENT_ROUTE_RESOLVED,         // 路由解析成功
	RDMA_CM_EVENT_ROUTE_ERROR,            // 路由解析失败
	RDMA_CM_EVENT_CONNECT_REQUEST,
	RDMA_CM_EVENT_CONNECT_RESPONSE,
	RDMA_CM_EVENT_CONNECT_ERROR,
	RDMA_CM_EVENT_UNREACHABLE,
	RDMA_CM_EVENT_REJECTED,
	RDMA_CM_EVENT_ESTABLISHED,            // 连接建立成功
	RDMA_CM_EVENT_DISCONNECTED,
	RDMA_CM_EVENT_DEVICE_REMOVAL,         // RDMA 设备被移除。可能是硬件被拔出或设备驱动被卸载，用户需要停止相关操作。
	RDMA_CM_EVENT_MULTICAST_JOIN,         // 成功加入多播组。应用程序发起的多播加入请求已完成。
	RDMA_CM_EVENT_MULTICAST_ERROR,
	RDMA_CM_EVENT_ADDR_CHANGE,            // 地址改变。通常是由网络拓扑或设备状态变化引起，用户需要重新解析地址。
	RDMA_CM_EVENT_TIMEWAIT_EXIT           // 超时退出。表示连接资源已从 TIME_WAIT 状态清理完毕，可以重新使用相同资源。
};

const char *__attribute_const__ rdma_event_msg(enum rdma_cm_event_type event);

// PS: Protocol Selector
// 表示 RDMA 底层使用的协议, refer: cma_select_ib_ps
//
// 编码在 service id 里, 另外低 16b 会将 port 编码进去: refer: IB Spec Annex A11
//
// service id 是编码在 REQ MAD 报文里的, refer: IB Spec Ch12
#define RDMA_IB_IP_PS_MASK   0xFFFFFFFFFFFF0000ULL
#define RDMA_IB_IP_PS_TCP    0x0000000001060000ULL // 06 tcp
#define RDMA_IB_IP_PS_UDP    0x0000000001110000ULL // 17 udp
#define RDMA_IB_IP_PS_IB     0x00000000013F0000ULL // 0x3f any local network

struct rdma_addr {
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	struct rdma_dev_addr dev_addr; // 出口设备信息. 表达一些 src_addr, dst_addr 无法表达的信息, 比如在 IB 网络中, LID, GUID 就无法通过 sockaddr_storage 表达
};

// RoCEv2 里, 路由是底层的 UDP/IP 负责的, 这个结构本质就是记录了 src/dst 地址
struct rdma_route {
	struct rdma_addr addr;
	struct sa_path_rec *path_rec; // IB 中有用
	int num_paths; // path_rec 数组的大小
};

// conn 服务的一些参数
struct rdma_conn_param {
	const void *private_data; // 报文里提取的 private data, IB Sepc Ch12
	u8 private_data_len;
	u8 responder_resources;
	u8 initiator_depth;
	u8 flow_control;
	u8 retry_count;		/* ignored when accepting */
	u8 rnr_retry_count;
	/* Fields below ignored if a QP is created on the rdma_cm_id. */
	u8 srq;
	u32 qp_num;
	u32 qkey;
};

// ud 服务的一些参数
struct rdma_ud_param {
	const void *private_data;
	u8 private_data_len;
	struct rdma_ah_attr ah_attr;
	u32 qp_num;
	u32 qkey;
};

struct rdma_cm_event {
	enum rdma_cm_event_type	 event;
	int			 status;
	union {
		struct rdma_conn_param	conn;
		struct rdma_ud_param	ud;
	} param;
	struct rdma_ucm_ece ece;
};

struct rdma_cm_id;

/**
 * rdma_cm_event_handler - Callback used to report user events.
 *
 * Notes: Users may not call rdma_destroy_id from this callback to destroy
 *   the passed in id, or a corresponding listen id.  Returning a
 *   non-zero value from the callback will destroy the passed in id.
 */
typedef int (*rdma_cm_event_handler)(struct rdma_cm_id *id,
				     struct rdma_cm_event *event);

// 一个连接的 ctx, 类似于 tcp 中的一个 socket
struct rdma_cm_id {
	struct ib_device	*device;
	void			*context;
	struct ib_qp		*qp;
	rdma_cm_event_handler	 event_handler;
	struct rdma_route	 route;
	enum rdma_ucm_port_space ps;
	enum ib_qp_type		 qp_type;
	u8			 port_num;
};

struct rdma_cm_id *
__rdma_create_kernel_id(struct net *net, rdma_cm_event_handler event_handler,
			void *context, enum rdma_ucm_port_space ps,
			enum ib_qp_type qp_type, const char *caller);
/* 主要是创建 rdma_id_private
 *
 * 核心函数, 其他函数都是围绕着这个 id 结构
 * */
struct rdma_cm_id *rdma_create_user_id(rdma_cm_event_handler event_handler,
				       void *context,
				       enum rdma_ucm_port_space ps,
				       enum ib_qp_type qp_type);

/**
 * rdma_create_id - Create an RDMA identifier.
 *
 * @net: The network namespace in which to create the new id.
 * @event_handler: User callback invoked to report events associated with the
 *   returned rdma_id.
 * @context: User specified context associated with the id.
 * @ps: RDMA port space.
 * @qp_type: type of queue pair associated with the id.
 *
 * Returns a new rdma_cm_id. The id holds a reference on the network
 * namespace until it is destroyed.
 *
 * The event handler callback serializes on the id's mutex and is
 * allowed to sleep.
 *
 * 创建 ctx 类似于创建一个 socket
 */
#define rdma_create_id(net, event_handler, context, ps, qp_type)               \
	__rdma_create_kernel_id(net, event_handler, context, ps, qp_type,      \
				KBUILD_MODNAME)

/**
  * rdma_destroy_id - Destroys an RDMA identifier.
  *
  * @id: RDMA identifier.
  *
  * Note: calling this function has the effect of canceling in-flight
  * asynchronous operations associated with the id.
  */
void rdma_destroy_id(struct rdma_cm_id *id);

/**
 * rdma_bind_addr - Bind an RDMA identifier to a source address and
 *   associated RDMA device, if needed.
 *
 * @id: RDMA identifier.
 * @addr: Local address information.  Wildcard values are permitted.
 *
 * This associates a source address with the RDMA identifier before calling
 * rdma_listen.  If a specific local address is given, the RDMA identifier will
 * be bound to a local RDMA device.
 *
 * 将一些地址信息(src addr)绑定到 id 上咯, 对于 server 端来说, listen 之前需要做这个操作的
 */
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr);

/**
 * rdma_resolve_addr - Resolve destination and optional source addresses
 *   from IP addresses to an RDMA address.  If successful, the specified
 *   rdma_cm_id will be bound to a local device.
 *
 * @id: RDMA identifier.
 * @src_addr: Source address information.  This parameter may be NULL.
 * @dst_addr: Destination address information.
 * @timeout_ms: Time to wait for resolution to complete.
 *
 * dst 是必须的, src 是可选的
 *
 * 将 ip 地址解析为一个 RDMA 地址, 如果解析成功了, id 就可以关联到一个 local device
 *
 * 当然不同的 rdma 协议, 地址的解析方法是不一样的
 *
 * client 端会调用这个函数, 这样根据目的地址(ip 地址) 找到 口设备
 */
int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      const struct sockaddr *dst_addr,
		      unsigned long timeout_ms);

/**
 * rdma_resolve_route - Resolve the RDMA address bound to the RDMA identifier
 *   into route information needed to establish a connection.
 *
 * This is called on the client side of a connection.
 * Users must have first called rdma_resolve_addr to resolve a dst_addr
 * into an RDMA address before calling this routine.
 *
 * 解析 rdma 地址信息(已经 bound 到 id 了), 得到 route info, 后续用来建立连接
 */
int rdma_resolve_route(struct rdma_cm_id *id, unsigned long timeout_ms);

/**
 * rdma_create_qp - Allocate a QP and associate it with the specified RDMA
 * identifier.
 *
 * QPs allocated to an rdma_cm_id will automatically be transitioned by the CMA
 * through their states.
 */
int rdma_create_qp(struct rdma_cm_id *id, struct ib_pd *pd,
		   struct ib_qp_init_attr *qp_init_attr);

/**
 * rdma_destroy_qp - Deallocate the QP associated with the specified RDMA
 * identifier.
 *
 * Users must destroy any QP associated with an RDMA identifier before
 * destroying the RDMA ID.
 */
void rdma_destroy_qp(struct rdma_cm_id *id);

/**
 * rdma_init_qp_attr - Initializes the QP attributes for use in transitioning
 *   to a specified QP state.
 * @id: Communication identifier associated with the QP attributes to
 *   initialize.
 * @qp_attr: On input, specifies the desired QP state.  On output, the
 *   mandatory and desired optional attributes will be set in order to
 *   modify the QP to the specified state.
 * @qp_attr_mask: The QP attribute mask that may be used to transition the
 *   QP to the specified state.
 *
 * Users must set the @qp_attr->qp_state to the desired QP state.  This call
 * will set all required attributes for the given transition, along with
 * known optional attributes.  Users may override the attributes returned from
 * this call before calling ib_modify_qp.
 *
 * Users that wish to have their QP automatically transitioned through its
 * states can associate a QP with the rdma_cm_id by calling rdma_create_qp().
 */
int rdma_init_qp_attr(struct rdma_cm_id *id, struct ib_qp_attr *qp_attr,
		       int *qp_attr_mask);

int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);
int rdma_connect_locked(struct rdma_cm_id *id,
			struct rdma_conn_param *conn_param);

int rdma_connect_ece(struct rdma_cm_id *id, struct rdma_conn_param *conn_param,
		     struct rdma_ucm_ece *ece);

/**
 * rdma_listen - This function is called by the passive side to
 *   listen for incoming connection requests.
 *
 * Users must have bound the rdma_cm_id to a local address by calling
 * rdma_bind_addr before calling this routine.
 */
int rdma_listen(struct rdma_cm_id *id, int backlog);

int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);

void rdma_lock_handler(struct rdma_cm_id *id);
void rdma_unlock_handler(struct rdma_cm_id *id);
int rdma_accept_ece(struct rdma_cm_id *id, struct rdma_conn_param *conn_param,
		    struct rdma_ucm_ece *ece);

/**
 * rdma_notify - Notifies the RDMA CM of an asynchronous event that has
 * occurred on the connection.
 * @id: Connection identifier to transition to established.
 * @event: Asynchronous event.
 *
 * This routine should be invoked by users to notify the CM of relevant
 * communication events.  Events that should be reported to the CM and
 * when to report them are:
 *
 * IB_EVENT_COMM_EST - Used when a message is received on a connected
 *    QP before an RTU has been received.
 */
int rdma_notify(struct rdma_cm_id *id, enum ib_event_type event);

/**
 * rdma_reject - Called to reject a connection request or response.
 */
int rdma_reject(struct rdma_cm_id *id, const void *private_data,
		u8 private_data_len, u8 reason);

/**
 * rdma_disconnect - This function disconnects the associated QP and
 *   transitions it into the error state.
 */
int rdma_disconnect(struct rdma_cm_id *id);

/**
 * rdma_join_multicast - Join the multicast group specified by the given
 *   address.
 * @id: Communication identifier associated with the request.
 * @addr: Multicast address identifying the group to join.
 * @join_state: Multicast JoinState bitmap requested by port.
 *		Bitmap is based on IB_SA_MCMEMBER_REC_JOIN_STATE bits.
 * @context: User-defined context associated with the join request, returned
 * to the user through the private_data pointer in multicast events.
 */
int rdma_join_multicast(struct rdma_cm_id *id, struct sockaddr *addr,
			u8 join_state, void *context);

/**
 * rdma_leave_multicast - Leave the multicast group specified by the given
 *   address.
 */
void rdma_leave_multicast(struct rdma_cm_id *id, struct sockaddr *addr);

/**
 * rdma_set_service_type - Set the type of service associated with a
 *   connection identifier.
 * @id: Communication identifier to associated with service type.
 * @tos: Type of service.
 *
 * The type of service is interpretted as a differentiated service
 * field (RFC 2474).  The service type should be specified before
 * performing route resolution, as existing communication on the
 * connection identifier may be unaffected.  The type of service
 * requested may not be supported by the network to all destinations.
 */
void rdma_set_service_type(struct rdma_cm_id *id, int tos);

/**
 * rdma_set_reuseaddr - Allow the reuse of local addresses when binding
 *    the rdma_cm_id.
 * @id: Communication identifier to configure.
 * @reuse: Value indicating if the bound address is reusable.
 *
 * Reuse must be set before an address is bound to the id.
 */
int rdma_set_reuseaddr(struct rdma_cm_id *id, int reuse);

/**
 * rdma_set_afonly - Specify that listens are restricted to the
 *    bound address family only.
 * @id: Communication identifer to configure.
 * @afonly: Value indicating if listens are restricted.
 *
 * Must be set before identifier is in the listening state.
 */
int rdma_set_afonly(struct rdma_cm_id *id, int afonly);

int rdma_set_ack_timeout(struct rdma_cm_id *id, u8 timeout);
 /**
 * rdma_get_service_id - Return the IB service ID for a specified address.
 * @id: Communication identifier associated with the address.
 * @addr: Address for the service ID.
 */
__be64 rdma_get_service_id(struct rdma_cm_id *id, struct sockaddr *addr);

/**
 * rdma_reject_msg - return a pointer to a reject message string.
 * @id: Communication identifier that received the REJECT event.
 * @reason: Value returned in the REJECT event status field.
 */
const char *__attribute_const__ rdma_reject_msg(struct rdma_cm_id *id,
						int reason);
/**
 * rdma_consumer_reject_data - return the consumer reject private data and
 *			       length, if any.
 * @id: Communication identifier that received the REJECT event.
 * @ev: RDMA CM reject event.
 * @data_len: Pointer to the resulting length of the consumer data.
 */
const void *rdma_consumer_reject_data(struct rdma_cm_id *id,
				      struct rdma_cm_event *ev, u8 *data_len);

/**
 * rdma_read_gids - Return the SGID and DGID used for establishing
 *                  connection. This can be used after rdma_resolve_addr()
 *                  on client side. This can be use on new connection
 *                  on server side. This is applicable to IB, RoCE, iWarp.
 *                  If cm_id is not bound yet to the RDMA device, it doesn't
 *                  copy and SGID or DGID to the given pointers.
 * @id: Communication identifier whose GIDs are queried.
 * @sgid: Pointer to SGID where SGID will be returned. It is optional.
 * @dgid: Pointer to DGID where DGID will be returned. It is optional.
 * Note: This API should not be used by any new ULPs or new code.
 * Instead, users interested in querying GIDs should refer to path record
 * of the rdma_cm_id to query the GIDs.
 * This API is provided for compatibility for existing users.
 */

void rdma_read_gids(struct rdma_cm_id *cm_id, union ib_gid *sgid,
		    union ib_gid *dgid);

struct iw_cm_id *rdma_iw_cm_id(struct rdma_cm_id *cm_id);
struct rdma_cm_id *rdma_res_to_id(struct rdma_restrack_entry *res);

#endif /* RDMA_CM_H */
