/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 */

#ifndef IB_PACK_H
#define IB_PACK_H

#include <rdma/ib_verbs.h>
#include <uapi/linux/if_ether.h>

/* 来自于 spec */
enum {
	IB_LRH_BYTES		= 8,
	IB_ETH_BYTES		= 14,
	IB_VLAN_BYTES		= 4,
	IB_GRH_BYTES		= 40,
	IB_IP4_BYTES		= 20,
	IB_UDP_BYTES		= 8,
	IB_BTH_BYTES		= 12,
	IB_DETH_BYTES		= 8,
	IB_EXT_ATOMICETH_BYTES	= 28,
	IB_EXT_XRC_BYTES	= 4,
	IB_ICRC_BYTES		= 4
};

/* XXX: 最关键的结构 */
struct ib_field {
	size_t struct_offset_bytes;
	size_t struct_size_bytes;
	int    offset_words;
	int    offset_bits;
	int    size_bits;
	char  *field_name;
};

#define RESERVED \
	.field_name          = "reserved"

/*
 * This macro cleans up the definitions of constants for BTH opcodes.
 * It is used to define constants such as IB_OPCODE_UD_SEND_ONLY,
 * which becomes IB_OPCODE_UD + IB_OPCODE_SEND_ONLY, and this gives
 * the correct value.
 *
 * In short, user code should use the constants defined using the
 * macro rather than worrying about adding together other constants.
*/
#define IB_OPCODE(transport, op) \
	IB_OPCODE_ ## transport ## _ ## op = \
		IB_OPCODE_ ## transport + IB_OPCODE_ ## op

/* XXX: ref: spec 1.4 table 38.
 *
 * opcode 是作为 BTH 的第一个字节出现的
 *
 * code[7-5]: 3b 是 qptype
 * code[4-0]: 5b 是 operation
 *
 * */
enum {
	/* transport types -- just used to define real constants */
	IB_OPCODE_RC                                = 0x00,
	IB_OPCODE_UC                                = 0x20,
	IB_OPCODE_RD                                = 0x40,
	IB_OPCODE_UD                                = 0x60,
	/* per IBTA 1.3 vol 1 Table 38, A10.3.2 */
	IB_OPCODE_CNP                               = 0x80, // 用于拥塞控制的消息
	// 没有定义 XRC(截止到 20251124 v6.18) (???)
	/* Manufacturer specific */
	IB_OPCODE_MSP                               = 0xe0,

	/* operations -- just used to define real constants */
	IB_OPCODE_SEND_FIRST                        = 0x00,
	IB_OPCODE_SEND_MIDDLE                       = 0x01,
	IB_OPCODE_SEND_LAST                         = 0x02,
	IB_OPCODE_SEND_LAST_WITH_IMMEDIATE          = 0x03,
	IB_OPCODE_SEND_ONLY                         = 0x04,
	IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          = 0x05,
	IB_OPCODE_RDMA_WRITE_FIRST                  = 0x06,
	IB_OPCODE_RDMA_WRITE_MIDDLE                 = 0x07,
	IB_OPCODE_RDMA_WRITE_LAST                   = 0x08,
	IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE    = 0x09,
	IB_OPCODE_RDMA_WRITE_ONLY                   = 0x0a,
	IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    = 0x0b,
	IB_OPCODE_RDMA_READ_REQUEST                 = 0x0c,
	IB_OPCODE_RDMA_READ_RESPONSE_FIRST          = 0x0d,
	IB_OPCODE_RDMA_READ_RESPONSE_MIDDLE         = 0x0e,
	IB_OPCODE_RDMA_READ_RESPONSE_LAST           = 0x0f,
	IB_OPCODE_RDMA_READ_RESPONSE_ONLY           = 0x10,
	IB_OPCODE_ACKNOWLEDGE                       = 0x11,
	IB_OPCODE_ATOMIC_ACKNOWLEDGE                = 0x12,
	IB_OPCODE_COMPARE_SWAP                      = 0x13,
	IB_OPCODE_FETCH_ADD                         = 0x14,
	/* opcode 0x15 is reserved */
	IB_OPCODE_SEND_LAST_WITH_INVALIDATE         = 0x16,
	IB_OPCODE_SEND_ONLY_WITH_INVALIDATE         = 0x17,

	/* real constants follow -- see comment about above IB_OPCODE()
	   macro for more details */

	/* RC */
	IB_OPCODE(RC, SEND_FIRST),
	IB_OPCODE(RC, SEND_MIDDLE),
	IB_OPCODE(RC, SEND_LAST),
	IB_OPCODE(RC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, SEND_ONLY),
	IB_OPCODE(RC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_FIRST),
	IB_OPCODE(RC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RC, RDMA_WRITE_LAST),
	IB_OPCODE(RC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_ONLY),
	IB_OPCODE(RC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_READ_REQUEST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RC, ACKNOWLEDGE),
	IB_OPCODE(RC, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RC, COMPARE_SWAP),
	IB_OPCODE(RC, FETCH_ADD),
	IB_OPCODE(RC, SEND_LAST_WITH_INVALIDATE),
	IB_OPCODE(RC, SEND_ONLY_WITH_INVALIDATE),

	/* UC */
	IB_OPCODE(UC, SEND_FIRST),
	IB_OPCODE(UC, SEND_MIDDLE),
	IB_OPCODE(UC, SEND_LAST),
	IB_OPCODE(UC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, SEND_ONLY),
	IB_OPCODE(UC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_FIRST),
	IB_OPCODE(UC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(UC, RDMA_WRITE_LAST),
	IB_OPCODE(UC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_ONLY),
	IB_OPCODE(UC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),

	/* RD */
	IB_OPCODE(RD, SEND_FIRST),
	IB_OPCODE(RD, SEND_MIDDLE),
	IB_OPCODE(RD, SEND_LAST),
	IB_OPCODE(RD, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, SEND_ONLY),
	IB_OPCODE(RD, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_FIRST),
	IB_OPCODE(RD, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RD, RDMA_WRITE_LAST),
	IB_OPCODE(RD, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_ONLY),
	IB_OPCODE(RD, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_READ_REQUEST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RD, ACKNOWLEDGE),
	IB_OPCODE(RD, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RD, COMPARE_SWAP),
	IB_OPCODE(RD, FETCH_ADD),

	/* UD */
	IB_OPCODE(UD, SEND_ONLY),
	IB_OPCODE(UD, SEND_ONLY_WITH_IMMEDIATE)
};

// LRH 头里的 LNH 字段: link next header
enum {
	IB_LNH_RAW        = 0, // next header: RWH (EtherType)
	IB_LNH_IP         = 1, // next header: IPv6
	IB_LNH_IBA_LOCAL  = 2, // next header: BTH
	IB_LNH_IBA_GLOBAL = 3  // next header: grh
};

// LRH: local route header, 链路层, rocev2 没有这一层的
// 这里的结构定义不是报文头的定义, 要用 pack 函数将其转换为报文头的
// 所以注意这里的大小和报文头的真实大小是对不上的
// ref vol 1.4 Ch7.7
struct ib_unpacked_lrh {
	u8        virtual_lane;
	u8        link_version;
	u8        service_level;
	u8        link_next_header; // LNH
	__be16    destination_lid;
	__be16    packet_length;    // 单位是 4B, 包含 LRH 包含 ICRC, 但是不包含 VCRC
	__be16    source_lid;
};

// GRH: global route header, 网络层
// Rocev2 没有这个 头
struct ib_unpacked_grh {
	u8    	     ip_version;
	u8    	     traffic_class;
	__be32 	     flow_label;
	__be16       payload_length;
	u8    	     next_header;
	u8    	     hop_limit;
	union ib_gid source_gid;
	union ib_gid destination_gid;
};

// BTH: base transport header
// XXX: 这里的结构定义不是报文头的定义, 要用 pack 函数将其转换为报文头的所以注
// 意这里的大小和报文头的真实大小是对不上的
// ref: spec1.4 vol1 ch9.2
//
// XXX: SE. 关于 SE 字段的设置
// - 只在 last or only packet of a send, send wit imm, rdma write with imm 里设置. send with invalidate 操作也可以使用
// - 对于 HCA 的影响, ref: spec 1.4 vol1 ch11.4.2.2
//
// XXX: mig_req.
// - 1 表示 connection or EE ctx has been migrated
// - 0. 表示 current migration state is no change. ref: Ch17: Automatic Path Migration
//
// XXX; 下述结构没有 FECN BECN
// - FECN: 0. 表示 FECN indiction 没有收到. 1 表示 packet 经过了拥塞点
// - BECN: 0 表示 packet 没有经过拥塞点. 1 表示 forward congestion. // 这个 bit 通过 ACK 包或者 CN BTH 包带回来的
//
// XXX; reserved 字段要设置为 0. ICRC 是包含 reserved 字段的
//
//
// XXX: PSN 的产生规则. ref: spec1.4 vol1 Ch9.7.3.1
// - 连接建立的时候 requester 选择一个随机 PSN 值. responder 记下来, 称做 expected PSN
// - requester 每发送一个 packet, PSN 增加 1. 但是 RDMA read 操作有例外. 即跟在 rdma read 操作后的请求, 其 PSN 要跳的足够多的(根据 paylaod len 和 MTU 计算)
// - responder ack 包里要将 PSN 带回来的 (这里也是累积确认). 注意一个特殊情况: read request 的 respond 是多个包的. 所幸 requester 发送 rdma request 的时候预留了足够的 PSN 空间的.
//
// 术语:
// - currentPSN: BTH:PSN 字段里的值
struct ib_unpacked_bth {
	u8           opcode;                   // 8b, ref: IB_OPCODE_XXX
	u8           solicited_event;          // 1b, responder 侧是否要产生 CQ event. 不作为 packet header validation 的一部分, 即这个字段是怎么设置都不会导致 NAK 的产生的
	u8           mig_req;                  // 1b, migration request, 表示 migration state
	u8           pad_count;                // 2b. 表示 payload 里的 pad bytes 数量 (报文长度是 4B 对齐的)
	u8           transport_header_version; // 4b, 目前设置为 0
	__be16       pkey;                     // partition key
	__be32       destination_qpn;          // 24b, dst QP number
	u8           ack_req;                  // 1b, 指示 responder 要发回 ack 了
	__be32       psn;                      // 24b, packet sequence number
};


// XXX: 不支持 RD, 所以没有 RDETH 的定义

// deth: datagram extended transport header
// ref: spec1.4 vol1 Ch9.3.1
//
// 还有更多的 rdma 操作相关的 extended transport header 是没有在这里定义的
struct ib_unpacked_deth {
	__be32       qkey;       // 32b
	__be32       source_qpn; // 24b source qpn. 对端回复的时候用这个做 dst qpn(在 BTH 里).
};

// 以太头
struct ib_unpacked_eth {
	u8	dmac_h[4];
	u8	dmac_l[2];
	u8	smac_h[2];
	u8	smac_l[4];
	__be16	type;
};

// ipv4 头
struct ib_unpacked_ip4 {
	u8	ver;
	u8	hdr_len;
	u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	u8	ttl;
	u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
};

// udp 头
struct ib_unpacked_udp {
	__be16	sport;
	__be16	dport;
	__be16	length;
	__be16	csum;
};

// vlan 标签
struct ib_unpacked_vlan {
	__be16  tag;
	__be16  type;
};

// 完整的 UD header 信息
struct ib_ud_header {
	int                     lrh_present;
	struct ib_unpacked_lrh  lrh;
	int			eth_present;
	struct ib_unpacked_eth	eth;
	int                     vlan_present;
	struct ib_unpacked_vlan vlan;
	int			grh_present;
	struct ib_unpacked_grh	grh;
	int			ipv4_present;
	struct ib_unpacked_ip4	ip4;
	int			udp_present;
	struct ib_unpacked_udp	udp;
	struct ib_unpacked_bth	bth;
	struct ib_unpacked_deth deth;
	int			immediate_present;
	__be32			immediate_data;
};

void ib_pack(const struct ib_field        *desc,
	     int                           desc_len,
	     void                         *structure,
	     void                         *buf);

void ib_unpack(const struct ib_field        *desc,
	       int                           desc_len,
	       void                         *buf,
	       void                         *structure);

__sum16 ib_ud_ip4_csum(struct ib_ud_header *header);

int ib_ud_header_init(int		    payload_bytes,
		      int		    lrh_present,
		      int		    eth_present,
		      int		    vlan_present,
		      int		    grh_present,
		      int		    ip_version,
		      int		    udp_present,
		      int		    immediate_present,
		      struct ib_ud_header *header);

int ib_ud_header_pack(struct ib_ud_header *header,
		      void                *buf);

int ib_ud_header_unpack(void                *buf,
			struct ib_ud_header *header);

#endif /* IB_PACK_H */
