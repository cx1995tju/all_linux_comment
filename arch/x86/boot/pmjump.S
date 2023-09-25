/* SPDX-License-Identifier: GPL-2.0-only */
/* ----------------------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

/*
 * The actual transition into protected mode
 */

#include <asm/boot.h>
#include <asm/processor-flags.h>
#include <asm/segment.h>
#include <linux/linkage.h>

	.text
	.code16

/*
 * void protected_mode_jump(u32 entrypoint, u32 bootparams);

 entrypoint is eax, bootparams is edx

x86/boot/pm.c
 */
SYM_FUNC_START_NOALIGN(protected_mode_jump)
	movl	%edx, %esi		# Pointer to boot_params table

	xorl	%ebx, %ebx
	movw	%cs, %bx
	shll	$4, %ebx
	addl	%ebx, 2f
	jmp	1f			# Short jump to serialize on 386/486
1:

	movw	$__BOOT_DS, %cx
	movw	$__BOOT_TSS, %di

	movl	%cr0, %edx
	orb	$X86_CR0_PE, %dl	# Protected mode // 开启保护模式了, _Here it is_
	movl	%edx, %cr0

	# Transition to 32-bit mode
	.byte	0x66, 0xea		# ljmpl opcode, 0xea 是 long jump，0x66 是一个前缀, 允许mix 16b 32b code
2:	.long	.Lin_pm32		# offset
	.word	__BOOT_CS		# segment
SYM_FUNC_END(protected_mode_jump)

	.code32
	.section ".text32","ax"
SYM_FUNC_START_LOCAL_NOALIGN(.Lin_pm32)	// 保护模式的代码了
	# Set up data segments for flat 32-bit mode
	movl	%ecx, %ds
	movl	%ecx, %es
	movl	%ecx, %fs
	movl	%ecx, %gs
	movl	%ecx, %ss
	# The 32-bit code sets up its own stack, but this way we do have
	# a valid stack if some debugging hack wants to use it.
	addl	%ebx, %esp

	# Set up TR to make Intel VT happy
	ltr	%di

	# Clear registers to allow for future extensions to the
	# 32-bit boot protocol
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	xorl	%edi, %edi

	# Set up LDTR to make Intel VT happy
	lldt	%cx

	jmpl	*%eax			# Jump to the 32-bit entrypoint, code32_start, 默认就是 0x100000 位置 2^20 = 1MB. refer to x86/boot.rst, arch/x86/boot/pm.c:go_to_proctected_mode()
	# ./arch/x86/boot/compressed/head_64.S:.code32 位置
SYM_FUNC_END(.Lin_pm32)
