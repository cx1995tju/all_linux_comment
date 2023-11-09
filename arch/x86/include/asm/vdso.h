/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_VDSO_H
#define _ASM_X86_VDSO_H

#include <asm/page_types.h>
#include <linux/linkage.h>
#include <linux/init.h>

#ifndef __ASSEMBLER__

#include <linux/mm_types.h>

struct vdso_image {
	void *data;
	unsigned long size;   /* Always a multiple of PAGE_SIZE */

	unsigned long alt, alt_len; // refer to: apply_alternatives()

	long sym_vvar_start;  /* Negative offset to the vvar area */

	long sym_vvar_page;
	long sym_pvclock_page;
	long sym_hvclock_page;
	long sym_timens_page;
	long sym_VDSO32_NOTE_MASK;
	long sym___kernel_sigreturn;
	long sym___kernel_rt_sigreturn;
	long sym___kernel_vsyscall;
	long sym_int80_landing_pad;
};

#ifdef CONFIG_X86_64
extern const struct vdso_image vdso_image_64; // 编译时会生成 vdso-iamge-64.c 文件，里面会定义的
/*
 *
 * const struct vdso_image vdso_image_64 = {
 *         .data = raw_data,
 *         .size = 8192,
 *         .alt = 3530,
 *         .alt_len = 247,
 *         .sym_vvar_start = -16384,
 *         .sym_vvar_page = -16384,
 *         .sym_pvclock_page = -12288,
 *         .sym_hvclock_page = -8192,
 *         .sym_timens_page = -4096,
 * };
 * */
#endif

#ifdef CONFIG_X86_X32
extern const struct vdso_image vdso_image_x32;
#endif

#if defined CONFIG_X86_32 || defined CONFIG_COMPAT
extern const struct vdso_image vdso_image_32;	// 如果是 这从清空需要支持 int 80 方式的系统调用
#endif

extern void __init init_vdso_image(const struct vdso_image *image);

extern int map_vdso_once(const struct vdso_image *image, unsigned long addr);

#endif /* __ASSEMBLER__ */

#endif /* _ASM_X86_VDSO_H */
