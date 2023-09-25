/* SPDX-License-Identifier: GPL-2.0-only */
/* ----------------------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

#include <linux/linkage.h>

/*
 * Memory copy routines
 */
	.code16
	.text

//  boot 阶段使用, 此时运行在 real mode
// memcpy(dst, src, size) // dst is ax, src is bx, size is cx
// refer to:  https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html。 linux 编译的时候使用的 REALMODE_CFLAGS 中包含 -mregparm=3
SYM_FUNC_START_NOALIGN(memcpy)
	pushw	%si
	pushw	%di
	movw	%ax, %di
	movw	%dx, %si
	pushw	%cx
	shrw	$2, %cx
	rep; movsl
	popw	%cx
	andw	$3, %cx
	rep; movsb	// 将字节长度从 ds:si 搬到es:di, 重复次数是在 cx 中
	popw	%di
	popw	%si
	retl
SYM_FUNC_END(memcpy)

SYM_FUNC_START_NOALIGN(memset)
	pushw	%di
	movw	%ax, %di
	movzbl	%dl, %eax
	imull	$0x01010101,%eax
	pushw	%cx
	shrw	$2, %cx
	rep; stosl
	popw	%cx
	andw	$3, %cx
	rep; stosb
	popw	%di
	retl
SYM_FUNC_END(memset)

SYM_FUNC_START_NOALIGN(copy_from_fs)
	pushw	%ds
	pushw	%fs
	popw	%ds
	calll	memcpy
	popw	%ds
	retl
SYM_FUNC_END(copy_from_fs)

SYM_FUNC_START_NOALIGN(copy_to_fs)
	pushw	%es
	pushw	%fs
	popw	%es
	calll	memcpy
	popw	%es
	retl
SYM_FUNC_END(copy_to_fs)
