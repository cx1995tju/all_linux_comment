/* SPDX-License-Identifier: GPL-2.0 */
/* Written 2000 by Andi Kleen */
#ifndef _ASM_X86_DESC_DEFS_H
#define _ASM_X86_DESC_DEFS_H

/*
 * Segment descriptor structure definitions, usable from both x86_64 and i386
 * archs.
 */

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * ENTRY 的格式
 *  31                                16  15                                   0
 * +-------------------------------------+--------------------------------------+
 * | 基地址 B15-B0                       | 段上限 L15 - L0                      |
 * +-------------------------------------+--------------------------------------+
 * 
 * 
 *  63           56  55   54    53   52   51              48  47  46 45   44   43    42      41    40   39      32
 * +----------------+---+-----+----+-----+------------------+----+------+----+----+-------+------+----+-----------+
 * | 基地址 B31-B24 | G | D/B | O  | AV  | 段上限 L19 - L16 | P  | DPL  | S  | E  | ED/C  | R/W  | A  | B23 - B16 |
 * +----------------+---+-----+----+-----+------------------+----+------+----+----+-------+------+----+-----------+
 * 
 * - A: 是否被访问过
 * - E / ED/C / R/W 要放到一起看
 * 	- E 为 0 表示是数据段
 * 		- R/W: 0表示不可写; 1 表示可写
 * 		- ED/C:
 * 			- 0 表示向上生长，堆
 * 			- 1 表示向下生长，栈
 * 	- E 为 1 表示是代码段
 * 		- R/W: 0表示不可读; 1 表示可读
 * 		- ED/C:
 * 			- 0 表示忽略特权级
 * - S:
 * 	- 0 表示这个段是用于系统管理的，譬如：各种描述表
 * 	- 1 表示这个段是一般的代码段，数据段
 * - P: 1 表示该段在内存中
 * 
 * - AV: 留给软件使用的，CPU 会忽略
 * - O: 永远为0
 * - D/B
 * 	- 0 表示对该段的访问是 16 位指令
 * 	- 1 表示对该段的访问是 32 位指令
 * - G
 * 	- 0 表示基本单位是 Byte
 * 	- 1 表示这个段的基本单位是 4KB	, 所以一个段最大的索引空间是 4KB * 2^20 = 4GB????
 */
/* 8 byte segment descriptor */
struct desc_struct {
	u16	limit0;
	u16	base0;
	u16	base1: 8, type: 4, s: 1, dpl: 2, p: 1;
	u16	limit1: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
} __attribute__((packed));

#define GDT_ENTRY_INIT(flags, base, limit)			\
	{							\
		.limit0		= (u16) (limit),		\
		.limit1		= ((limit) >> 16) & 0x0F,	\
		.base0		= (u16) (base),			\
		.base1		= ((base) >> 16) & 0xFF,	\
		.base2		= ((base) >> 24) & 0xFF,	\
		.type		= (flags & 0x0f),		\
		.s		= (flags >> 4) & 0x01,		\
		.dpl		= (flags >> 5) & 0x03,		\
		.p		= (flags >> 7) & 0x01,		\
		.avl		= (flags >> 12) & 0x01,		\
		.l		= (flags >> 13) & 0x01,		\
		.d		= (flags >> 14) & 0x01,		\
		.g		= (flags >> 15) & 0x01,		\
	}

enum {
	GATE_INTERRUPT = 0xE,
	GATE_TRAP = 0xF,
	GATE_CALL = 0xC,
	GATE_TASK = 0x5,
};

enum {
	DESC_TSS = 0x9,
	DESC_LDT = 0x2,
	DESCTYPE_S = 0x10,	/* !system */
};

/* LDT or TSS descriptor in the GDT. */
struct ldttss_desc {
	u16	limit0;
	u16	base0;

	u16	base1 : 8, type : 5, dpl : 2, p : 1;
	u16	limit1 : 4, zero0 : 3, g : 1, base2 : 8;
#ifdef CONFIG_X86_64
	u32	base3;
	u32	zero1;
#endif
} __attribute__((packed));

typedef struct ldttss_desc ldt_desc;
typedef struct ldttss_desc tss_desc;

struct idt_bits {
	u16		ist	: 3,
			zero	: 5,
			type	: 5,
			dpl	: 2,
			p	: 1;
} __attribute__((packed));

struct idt_data {
	unsigned int	vector; // 中断向量
	unsigned int	segment; // idt entry 中的 segment 字段
	struct idt_bits	bits;	// idt entry 中的 flags
	const void	*addr; // handler 所在地址
};

// 填入 idt table 中的内容, 即 idt table 的entry

/* 64 位系统 x86_64 的 idt entry 结构
 * 127                                                                             96
 * --------------------------------------------------------------------------------
 * |                                                                               |
 * |                                Reserved                                       |
 * |                                                                               |
 *  --------------------------------------------------------------------------------
 * 95                                                                              64
 *  --------------------------------------------------------------------------------
 * |                                                                               |
 * |                               Offset 63..32                                   |
 * |                                                                               |
 *  --------------------------------------------------------------------------------
 * 63                               48 47      46  44   42    39             34    32
 *  --------------------------------------------------------------------------------
 * |                                  |       |  D  |   |     |      |   |   |     |
 * |       Offset 31..16              |   P   |  P  | 0 |Type |0 0 0 | 0 | 0 | IST |
 * |                                  |       |  L  |   |     |      |   |   |     |
 *  --------------------------------------------------------------------------------
 * 31                                   16 15                                      0
 *  --------------------------------------------------------------------------------
 * |                                      |                                        |
 * |          Segment Selector            |                 Offset 15..0           |
 * |                                      |                                        |
 *  --------------------------------------------------------------------------------
 * */
struct gate_struct {
	u16		offset_low;
	u16		segment;
	struct idt_bits	bits;
	u16		offset_middle;
#ifdef CONFIG_X86_64
	u32		offset_high;
	u32		reserved;
#endif
} __attribute__((packed));

typedef struct gate_struct gate_desc;

static inline unsigned long gate_offset(const gate_desc *g)
{
#ifdef CONFIG_X86_64
	return g->offset_low | ((unsigned long)g->offset_middle << 16) |
		((unsigned long) g->offset_high << 32);
#else
	return g->offset_low | ((unsigned long)g->offset_middle << 16);
#endif
}

static inline unsigned long gate_segment(const gate_desc *g)
{
	return g->segment;
}

struct desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed)) ;

#endif /* !__ASSEMBLY__ */

/* Boot IDT definitions */
#define	BOOT_IDT_ENTRIES	32

/* Access rights as returned by LAR */
#define AR_TYPE_RODATA		(0 * (1 << 9))
#define AR_TYPE_RWDATA		(1 * (1 << 9))
#define AR_TYPE_RODATA_EXPDOWN	(2 * (1 << 9))
#define AR_TYPE_RWDATA_EXPDOWN	(3 * (1 << 9))
#define AR_TYPE_XOCODE		(4 * (1 << 9))
#define AR_TYPE_XRCODE		(5 * (1 << 9))
#define AR_TYPE_XOCODE_CONF	(6 * (1 << 9))
#define AR_TYPE_XRCODE_CONF	(7 * (1 << 9))
#define AR_TYPE_MASK		(7 * (1 << 9))

#define AR_DPL0			(0 * (1 << 13))
#define AR_DPL3			(3 * (1 << 13))
#define AR_DPL_MASK		(3 * (1 << 13))

#define AR_A			(1 << 8)   /* "Accessed" */
#define AR_S			(1 << 12)  /* If clear, "System" segment */
#define AR_P			(1 << 15)  /* "Present" */
#define AR_AVL			(1 << 20)  /* "AVaiLable" (no HW effect) */
#define AR_L			(1 << 21)  /* "Long mode" for code segments */
#define AR_DB			(1 << 22)  /* D/B, effect depends on type */
#define AR_G			(1 << 23)  /* "Granularity" (limit in pages) */

#endif /* _ASM_X86_DESC_DEFS_H */
