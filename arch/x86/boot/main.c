// SPDX-License-Identifier: GPL-2.0-only
/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 * ----------------------------------------------------------------------- */

/*
 * Main module for the real-mode kernel code
 */
#include <linux/build_bug.h>

#include "boot.h"
#include "string.h"

struct boot_params boot_params __attribute__((aligned(16)));

char *HEAP = _end;
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 */

static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	BUILD_BUG_ON(sizeof(boot_params) != 4096);
	// memcpy refer to: arch/x86/boot/copy.S, 注意哟，这里的 memcpy 是运行在 real-mode 的
	// sizeof(hdr) 怎么来的??? 参考 boot.h 里面声明了类型，自然也就拿到大小了
	// 至于这个符号本身是在 header.S 中定义的。里面的内容是 boot loader 根据 boot protocol 填充的
	memcpy(&boot_params.hdr, &hdr, sizeof(hdr)); // refer to: arch/x86/boot/header.S, 就是从 vmlinuz 中提取出的 header.S

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

/*
 * Query the keyboard lock status as given by the BIOS, and
 * set the keyboard repeat rate to maximum.  Unclear why the latter
 * is done here; this might be possible to kill off as stale code.
 */
static void keyboard_init(void)
{
	struct biosregs ireg, oreg;
	initregs(&ireg);

	ireg.ah = 0x02;		/* Get keyboard status */
	intcall(0x16, &ireg, &oreg);
	boot_params.kbd_status = oreg.al;

	ireg.ax = 0x0305;	/* Set keyboard repeat rate */
	intcall(0x16, &ireg, NULL);
}

/*
 * Get Intel SpeedStep (IST) information.
 */
static void query_ist(void)
{
	struct biosregs ireg, oreg;

	/* Some older BIOSes apparently crash on this call, so filter
	   it from machines too old to have SpeedStep at all. */
	if (cpu.level < 6)
		return;

	initregs(&ireg);
	ireg.ax  = 0xe980;	 /* IST Support */
	ireg.edx = 0x47534943;	 /* Request value */
	intcall(0x15, &ireg, &oreg);

	boot_params.ist_info.signature  = oreg.eax;
	boot_params.ist_info.command    = oreg.ebx;
	boot_params.ist_info.event      = oreg.ecx;
	boot_params.ist_info.perf_level = oreg.edx;
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2; // 告诉 bios，要用 long mode:  https://en.wikipedia.org/wiki/Long_mode
	intcall(0x15, &ireg, NULL); // 会执行 bios 的int 15 中断
#endif
}

static void init_heap(void)
{
	char *stack_end; // 栈顶部。即地址最小的值

	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		asm("leal %P1(%%esp),%0"			// esp - STACK_SIZE 的值，赋给 stack_end 变量
		    : "=r" (stack_end) : "i" (-STACK_SIZE));

		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200); // refer to boot.rst
		if (heap_end > stack_end) // 如果是kernel自己初始化 stack / heap 的话，这里就是常态
			heap_end = stack_end; // 避免 heap 比 stack 地址更大, 即验证下图的内存布局有没有问题。这里是常态
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}
}

// real-mode
// 此时内存布局如下
//+--------------------------------+ <- esp 注意此时 esp 在这个位置，下面的空间理论来说还不是 stack, esp = heap_end_ptr + STACK_SIZE
//|                                |
//| Stack(size: STACK_SIZE)        | // 一般大小是 1024
//|                                |
//|                                |
//|                                |
//|                                |
//|--------------------------------| <- heap_end_ptr = _end + STACK_SIZE - 512 = _end + 512
//|                                |
//| HEAP (size: STACK_SIZE - 512)  | // 前提是 loadflags 中 enable 了 HEAP
//|                                |
//|--------------------------------| <- _end 符号, refer to: setup.ld
//|                                |
//| BSS(all zero)                  |
//|                                |
//+--------------------------------+
//| kernel setup.elf               |
//+--------------------------------+ <- 一般是 0x10000, ss, cs 等段寄存器是 0x1000
void main(void)
{
	// 利用 bios 提供的 int handler，获取很多信息
	// 进入的时候，还是 real mode
	/* First, copy the boot header into the "zeropage" */
	copy_boot_params();

	/* Initialize the early-boot console */
	console_init();
	if (cmdline_find_option_bool("debug"))
		puts("early console in setup code\n");

	/* End of heap check, 不是 init，仅仅是 check */
	init_heap();

	/* Make sure we have all the proper CPU support */
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* Tell the BIOS what CPU mode we intend to run in. */
	set_bios_mode();

	/* Detect memory layout, 物理内存分布情况 */
	detect_memory();

	/* Set keyboard repeat rate (why?) and query the lock flags */
	keyboard_init();

	/* Query Intel SpeedStep (IST) information */
	// https://en.wikipedia.org/wiki/SpeedStep
	query_ist();

	/* Query APM information */
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios(); // https://en.wikipedia.org/wiki/Advanced_Power_Management , 后来被 acpi 取代了
#endif

	/* Query EDD information */ // enhanced disk drive
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif

	/* Set the video mode */
	set_video();

	// 前面的代码都是在 real-mode 执行的

	/* Do the last things and invoke protected mode */
	go_to_protected_mode();
}
