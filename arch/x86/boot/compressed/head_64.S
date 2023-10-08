/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992, 1993  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00001000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory. [According to comments etc elsewhere on a compressed
 * kernel it will end up at 0x1000 + 1Mb I hope so as I assume this. - AC]
 *
 * Page 0 is deliberately kept safe, since System Management Mode code in 
 * laptops may need to access the BIOS data stored there.  This is also
 * useful for future device drivers that either access the BIOS via VM86 
 * mode.
 */

/*
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */
	.code32
	.text

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/desc_defs.h>
#include "pgtable.h"

/*
 * Locally defined symbols should be marked hidden:
 */
	.hidden _bss
	.hidden _ebss
	.hidden _end

	__HEAD	// .head.text

/*
 * This macro gives the relative virtual address of X, i.e. the offset of X
 * from startup_32. This is the same as the link-time virtual address of X,	// link 的时候 startup_32 在 0 位置，但是加载到内存的时候显然不是
 * since startup_32 is at 0, but defining it this way tells the
 * assembler/linker that we do not want the actual run-time address of X. This
 * prevents the linker from trying to create unwanted run-time relocation
 * entries for the reference when the compressed kernel is linked as PIE.
 *
 * A reference X(%reg) will result in the link-time VA of X being stored with
 * the instruction, and a run-time R_X86_64_RELATIVE relocation entry that
 * adds the 64-bit base address where the kernel is loaded.
 *
 * Replacing it with (X-startup_32)(%reg) results in the offset being stored,
 * and no run-time relocation.
 *
 * The macro should be used as a displacement with a base register containing
 * the run-time address of startup_32 [i.e. rva(X)(%reg)], or as an immediate
 * [$ rva(X)].
 *
 * This macro can only be used from within the .head.text section, since the
 * expression requires startup_32 to be in the same section as the code being
 * assembled.
 */
#define rva(X) ((X) - startup_32)	# 就是相对于 startup_32 的偏移

	// 此时寄存器值可能为
// eax            0x100000	1048576
// ecx            0x0	    0
// edx            0x0	    0
// ebx            0x0	    0
// esp            0x1ff5c	0x1ff5c
// ebp            0x0	    0x0
// esi            0x14470	83056
// edi            0x0	    0
// eip            0x100000	0x100000
// eflags         0x46	    [ PF ZF ]
// cs             0x10	16
// ss             0x18	24
// ds             0x18	24
// es             0x18	24
// fs             0x18	24
// gs             0x18	24
	.code32		// 这里的代码的link。受 arch/x86/boot/compressed/vmlinux.lds.S 脚本控制。从 go_to_protected_mode() 跳转过来的
SYM_FUNC_START(startup_32)	// _保护模式下的第一条指令_  进入保护模式的时候，不知道这个 startup_32 到底被加载到了哪个位置。第一步就是要搞清楚这一点, 此时还没有开启 paging 机制。还是段式寻址, 不过需要 gdt / ldt 参与了。而不是real-mode 下的段式寻址。
	/*
	 * 32bit entry is 0 and it is ABI so immutable!
	 * If we come here directly from a bootloader,
	 * kernel(text+data+bss+brk) ramdisk, zero_page, command line
	 * all need to be under the 4G limit.
	 */
	cld	// clear df flags, 控制 stos，scas 这种字符串处理指令的方向的。cld 后，表示处理的时候是递增 esi 或者 edi 寄存器的
	cli

/*
 * Calculate the delta between where we were compiled to run
 * at and where we were actually loaded at.  This can only be done
 * with a short local call on x86.  Nothing  else will tell us what
 * address we are running at.  The reserved chunk of the real-mode
 * data at 0x1e4 (defined as a scratch field) are used as the stack
 * for this calculation. Only 4 bytes are needed.
 */
	// 进入这里的时候，esi 中保存的是 boot_params 参数
	// 让 zero page 中的scratch 这 4个byte 作为一个临时的stack使用。
	// 这里设置了栈指针 esp 就是 zero page（即boot_params 中的 scartch 位置 + 4）, 注意，栈是从高地址到低地址的，这里 +4，后面的 call 指令会-4的, 同时会将返回地址(即此处的 1: 位置) push 到栈中，即 scratch 位置
	// BP_scratch 就是 1e4, 就是boot_params 中的成员偏移, refer to: arch/x86/kernel/asm-offsets.c
	leal	(BP_scratch+4)(%esi), %esp // esi 寄存器是 boot_params 的基址, 在 进入 protected 模式前，填充的. pmjump.S。这里就是将 boot_params 中的 scratch 成员作为一个临时的栈空间，方便后续的call指令调用
	call	1f // 这里是为了获得自己当前所在地址, call 指令会将 rip 压入栈中，随后 popl 就得到了标号 1: 所在位置
1:	popl	%ebp // ebp 就是 1: 这个 lable 的地址了。因为不知道 boot loader 到底把这部分代码加载到了哪个位置。所以这里要去拿一下当前地址。
	subl	$ rva(1b), %ebp	// 将ebp寄存器，即当前的 1f 的地址减去 1b 的偏移。得到了 startup_32 的地址了 			//    ____注意到这里时，ebp 中的值就是 startup32 的地址了_____ _重要_

	/* Load new GDT with the 64bit segments using 32bit descriptor */
	leal	rva(gdt)(%ebp), %eax	// 将 gdt 地址放到 eax 中
	movl	%eax, 2(%eax)		// 为什么要将 gdt 的地址保存到 gdt 里面呢？
	lgdt	(%eax)			// load gdt

	/* Load segment registers with our descriptors */
	movl	$__BOOT_DS, %eax // __BOOT_DS 值是 0x18, 即使用 gdt table 中的第三个 entry，权限都是最高的 0
	movl	%eax, %ds	// 因为 linux 基本不使用 gdt / ldt 机制，所以都设置为 0x18
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss

/* setup a stack and make sure cpu supports long mode. */
	leal	rva(boot_stack_end)(%ebp), %esp	// 拿到 boot stack 的真实地址，这部分是 boot 阶段临时使用的一个栈空间

	call	verify_cpu	// 需要检查 cpu 是否支持 long mode 以及 sse 指令, refer to:   arch/x86/kernel/verify_cpu.S 
	testl	%eax, %eax	// verify_cpu 的返回值在 eax 里，0表示成功，通过检查，1表示失败。
	jnz	.Lno_longmode	// 不支持 longmode的话，跳转过去 hlt

/*
 * Compute the delta between where we were compiled to run at
 * and where the code will actually run at.
 *
 * %ebp contains the address we are loaded at by the boot loader and %ebx
 * contains the address where we should move the kernel image temporarily
 * for safe in-place decompression.
 */

#ifdef CONFIG_RELOCATABLE	//开启后，kernel 保护模式代码可以不仅仅在 1MB 的位置被加载。一般用于 kexec 的kernel 是必须开启这个的
	movl	%ebp, %ebx	// 记住 ebp 保存了 protected mode 代码加载的位置(虚拟地址, 不过由于现在还没有开启 paging，且 gdt 设置的是 identity map，这里的虚拟地址就是物理地址)。

#ifdef CONFIG_EFI_STUB
/*
 * If we were loaded via the EFI LoadImage service, startup_32 will be at an
 * offset to the start of the space allocated for the image. efi_pe_entry will
 * set up image_offset to tell us where the image actually starts, so that we
 * can use the full available buffer.
 *	image_offset = startup_32 - image_base
 * Otherwise image_offset will be zero and has no effect on the calculations.
 */
	subl    rva(image_offset)(%ebp), %ebx
#endif

	movl	BP_kernel_alignment(%esi), %eax		// esi 是 boot_params 的基地址, eax 保存的是对齐值
	decl	%eax					// --，将对齐值 2的幂，转换为了低位全1 (即 2^n - 1)
	addl	%eax, %ebx				// 为了后续 ebx 向上对齐
	notl	%eax					// 按位取反
	andl	%eax, %ebx				// ebx 向上对齐, 检查 ebx 是否合法
	cmpl	$LOAD_PHYSICAL_ADDR, %ebx		// refer to:  arch/x86/include/asm/boot.h。计算出来的 ebx 值，不能比这个 LOAD_PHYSICAL_ADDR 小
	jae	1f
#endif
	movl	$LOAD_PHYSICAL_ADDR, %ebx		// ebx 不合法，那么就强行使用 LOAD_PHYSICAL_ADDR, 这个地址是后续用来解压 kernel 代码的
1:

	/* Target address to relocate to for decompression */	// 要找一个位置放置解压后的内核, 此时 ebx 保存就是这个地址
	addl	BP_init_size(%esi), %ebx			// 预留一部分初始化过程要使用的线性空间出来
	subl	$ rva(_end), %ebx // ebx 指向的地址，是临时用来做 in-place 解压的。 因为 init_size 包含了当前这些 protected mode 代码的大小，所以要减去一个 _end
	// 至此 ebp 包含的是 load kernel 的位置，即 protected mode 的起始地址。即 未压缩的 protected mode 的代码位置
	// ebx 保存的是，等下用来解压 内核的位置	_重要_

/*
 * Prepare for entering 64 bit mode
 */

	/* Enable PAE mode */
	movl	%cr4, %eax
	orl	$X86_CR4_PAE, %eax
	movl	%eax, %cr4

 /*
  * Build early 4G boot pagetable		// 构建一个 pagetable，在 boot 的时候用一下
  */
	/*
	 * If SEV is active then set the encryption mask in the page tables.
	 * This will insure that when the kernel is copied and decompressed
	 * it will be done so encrypted.
	 */
	call	get_sev_encryption_bit
	xorl	%edx, %edx
	testl	%eax, %eax
	jz	1f
	subl	$32, %eax	/* Encryption bit is always above bit 31 */
	bts	%eax, %edx	/* Set encryption mask for page tables */
1:

	/* 注意此时都还是 _32b 模式_ */
	/* Initialize Page tables to 0 */
	// 注意在 ebx 的起始位置是预留了足够的空间用来初始化的，我们现在在其中拿一部分出来做 pagetable
	// edi 是 pagetable 地址
	// 注意，这里准备的pagetable 是等下 进入 long mode 使用的，所以每个entry 都是 64b
	leal	rva(pgtable)(%ebx), %edi	// 注意，此时 ebx 此时保存的是等下内核解压后会放置到这个位置
	xorl	%eax, %eax
	movl	$(BOOT_INIT_PGT_SIZE/4), %ecx	// 6KB 的空间清0
	rep	stosl				// 先清0

	/*
	// 虚拟地址格式
	 31          22 21    12 11                0
	+--------------+--------+-------------------+
	| 页面目录 dir | 页面表 | 页内偏移 (offset) |
	+--------------+--------+-------------------+


	// 页目录表 / 页表 entry
	 31                   12 11               0
	+-----------------------+-------------------+
	| 页面目录 dir          | flags             |
	+-----------------------+-------------------+
	flags:
		D(bit 6): Dirty
		A(bit 5): Accessed
		PCD(bit 4): Cache Disableed
		PWT(bit 3): Write-Through
		U(bit 2): User-Defined
		XW(bit 1): Writable
		P(bit 0): Present
	 */

	/* 下面是page table 的内容，就是 identity map，物理地址 = 虚拟地址。仅设置了 前 4G 的映射。这个 page table 是等一下 long mode 下会使用的
                +----------------+
                |                |
                |                |
                |                |
        +0x6000B|----------------|
                |                |
                |       .        |
                |       .        |
                |       .        |
                |                |
        +0x2018B|----------------|       Level 2: 2048 entries, every entry for 2MB page 一共 4GB 大小的内存空间。基本就是恒等映射咯
                |       0        |
        +0x2014B|----------------|
                |    0x400183    |
        +0x2010B|----------------|
                |       0        |
        +0x200cB|----------------|
                |    0x200183    |
        +0x2008B|----------------|
                |       0        |
        +0x2004B|----------------|
                |     0x183      |     // 低 12位是 flag, 这个entry 指向的是物理地址0, 一个 entry 是 64b。2K 个 2MB 大小的page (一共48b，高27b是 page 的偏移)
        +0x2000B|----------------|<----+
                |                |     |
                |       .        |     |
                |       .        |     |
                |       .        |     |
                |       .        |     |
                |                |     |
        +0x1020B|----------------|     |
                |       0        |     |
        +0x101cB|----------------|     |
                | pgtbl + 0x5007 |     |
        +0x1018B|----------------|     |
                |       0        |     |
        +0x1014B|----------------|     | Level 3: 4 entries(一共可以有 512 entries 的)
                | pgtbl + 0x4007 |     |
        +0x1010B|----------------|     |
                |       0        |     |
        +0x100cB|----------------|     |
                | pgtbl + 0x3007 |     |
        +0x1008B|----------------|     |
                |       0        |     |
        +0x1004B|----------------|     |
                | pgtbl + 0x2007 +-----+
        +0x1000B|----------------|<----+
                |                |     |
                |       .        |     |
                |       .        |     |
                |       .        |     |
                |       .        |     | Level 4: 1 entry（一共可以有 512 entry的）
                |                |     |
                |----------------|     |
                |       0        |     |
             +4B|----------------|     |
                | pgtbl + 0x1007 +-----+ 007(0000 0000 0111) (User-Defined / Writable / Present)
pgtbl---------->+----------------+
	*/
	// 4-level VA = 9b + 9b + 9b + 21b(2MB page offset)
	/* Build Level 4 */
	leal	rva(pgtable + 0)(%ebx), %edi // ebx: ebx contains the address where should move kernel image temporarily for safe in-place decompression 
	leal	0x1007 (%edi), %eax	// 0x1007 低 12 位是 flag(Present / Writable / User-Defined), 第13位1 表示其指向的地址是 pgtable + 4KB
	movl	%eax, 0(%edi)
	addl	%edx, 4(%edi)

	/* Build Level 3 */
	leal	rva(pgtable + 0x1000)(%ebx), %edi
	leal	0x1007(%edi), %eax
	movl	$4, %ecx
1:	movl	%eax, 0x00(%edi)
	addl	%edx, 0x04(%edi) // 注意，这里准备的pagetable 是等下 进入 long mode 使用的，所以每个entry 都是 64b, 所以这里会又填充4B
	addl	$0x00001000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Build Level 2 */
	leal	rva(pgtable + 0x2000)(%ebx), %edi
	movl	$0x00000183, %eax	// 0x183(0001 1000 0011) 2MB page。bit 7 为1 表示这是一个指向 2MB page 的entry。注意：不是指向的页表。而是已经指向page 了。enable pae 的时候，这个 bit 7 为1的话，其就不指向page table 了，而是直接指向2MB 的 page 了
	movl	$2048, %ecx		// 2048 * 8B = 16KB, 这里构建了 2K 个 2MB 的page，就搞定了 4GB 的内存空间
1:	movl	%eax, 0(%edi)
	addl	%edx, 4(%edi)
	addl	$0x00200000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b
	// page table 设置好之后，是identity map, 即物理地址 == 虚拟地址

	/* Enable the boot page tables */
	leal	rva(pgtable)(%ebx), %eax
	movl	%eax, %cr3		// 将 page table 地址写入 cr3

	/* Enable Long mode in EFER (Extended Feature Enable Register) */
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax	// LME: lone mode enable
	wrmsr

	// 至此 long mode 已经 enable 了
	/* After gdt is loaded */
	xorl	%eax, %eax
	lldt	%ax
	movl    $__BOOT_TSS, %eax	// refer to: arch/x86/include/asm/segment.h
	ltr	%ax			// 加载 tr 寄存器，just for making intel happy？？？

	/*
	 * Setup for the jump to 64bit mode
	 *
	 * When the jump is performend we will be in long mode but
	 * in 32bit compatibility mode with EFER.LME = 1, CS.L = 0, CS.D = 1
	 * (and in turn EFER.LMA = 1).	To jump into 64bit mode we use
	 * the new gdt/idt that has __KERNEL_CS with CS.L = 1.
	 * We place all of the values on our mini stack so lret can
	 * used to perform that far jump.
	 */
	leal	rva(startup_64)(%ebp), %eax		// eax 就是后续进入 long mode 的起始地址
#ifdef CONFIG_EFI_MIXED
	movl	rva(efi32_boot_args)(%ebp), %edi
	cmp	$0, %edi
	jz	1f
	leal	rva(efi64_stub_entry)(%ebp), %eax	// eax 就是后续进入 long mode 的起始地址
	movl	rva(efi32_boot_args+4)(%ebp), %esi
	movl	rva(efi32_boot_args+8)(%ebp), %edx	// saved bootparams pointer
	cmpl	$0, %edx
	jnz	1f
	/*
	 * efi_pe_entry uses MS calling convention, which requires 32 bytes of
	 * shadow space on the stack even if all arguments are passed in
	 * registers. We also need an additional 8 bytes for the space that
	 * would be occupied by the return address, and this also results in
	 * the correct stack alignment for entry.
	 */
	subl	$40, %esp
	leal	rva(efi_pe_entry)(%ebp), %eax
	movl	%edi, %ecx			// MS calling convention
	movl	%esi, %edx
1:
#endif
	pushl	$__KERNEL_CS
	pushl	%eax				// 等下就是跳转到这个地址(startup_64)进入 long mode

	/* Enter paged protected Mode, activating Long Mode */
	movl	$(X86_CR0_PG | X86_CR0_PE), %eax /* Enable Paging and Protected mode, 设置 64b mode */
	movl	%eax, %cr0

	/* Jump from 32bit compatibility mode into 64bit mode. */
	lret					// 跳转到 64b mode, startup_64
SYM_FUNC_END(startup_32)

#ifdef CONFIG_EFI_MIXED
	.org 0x190
SYM_FUNC_START(efi32_stub_entry)
	add	$0x4, %esp		/* Discard return address */
	popl	%ecx
	popl	%edx
	popl	%esi

	call	1f
1:	pop	%ebp
	subl	$ rva(1b), %ebp

	movl	%esi, rva(efi32_boot_args+8)(%ebp)
SYM_INNER_LABEL(efi32_pe_stub_entry, SYM_L_LOCAL)
	movl	%ecx, rva(efi32_boot_args)(%ebp)
	movl	%edx, rva(efi32_boot_args+4)(%ebp)
	movb	$0, rva(efi_is64)(%ebp)

	/* Save firmware GDTR and code/data selectors */
	sgdtl	rva(efi32_boot_gdt)(%ebp)
	movw	%cs, rva(efi32_boot_cs)(%ebp)
	movw	%ds, rva(efi32_boot_ds)(%ebp)

	/* Disable paging */
	movl	%cr0, %eax
	btrl	$X86_CR0_PG_BIT, %eax
	movl	%eax, %cr0

	jmp	startup_32
SYM_FUNC_END(efi32_stub_entry)
#endif

	.code64
	.org 0x200			// 这部分代码会在 offset 0x200 的位置开始, 即 (startup_32 + 0x200)
SYM_CODE_START(startup_64)		// long mode 的起始地址, 注意这里可能是从前面的 startup_32 一步一步执行过来的。也可能是 支持 64b 的 boot loader 直接跳转过来的，所以很多在 startup_32 做的工作，这里要再做一遍
	// 注意：由于前面 page table 的设置，进入这里时，前 4G 的内存是 identity map，即物理地址和虚拟地址一样的
	/*
	 * 64bit entry is 0x200 and it is ABI so immutable!
	 * We come here either from startup_32 or directly from a
	 * 64bit bootloader.
	 * If we come here from a bootloader, kernel(text+data+bss+brk),
	 * ramdisk, zero_page, command line could be above 4G.
	 * We depend on an identity mapped page table being provided
	 * that maps our entire kernel(text+data+bss+brk), zero page
	 * and command line.
	 */

	cld
	cli

	/* Setup data segments. */
	xorl	%eax, %eax	// 清零
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	/*
	 * Compute the decompressed kernel start address.  It is where
	 * we were loaded at aligned to a 2M boundary. %rbp contains the
	 * decompressed kernel start address.
	 *
	 * If it is a relocatable kernel then decompress and run the kernel
	 * from load address aligned to 2MB addr, otherwise decompress and
	 * run the kernel from LOAD_PHYSICAL_ADDR
	 *
	 * We cannot rely on the calculation done in 32-bit mode, since we
	 * may have been invoked via the 64-bit entry point.
	 */

	/* Start with the delta to where the kernel will run at. */
	// 在 32b 模式做的很多工作，现在要重新做一遍
#ifdef CONFIG_RELOCATABLE
	// 使用 rip 相对寻址，将 startup_32 这个符号链接后地址放到 rbp 寄存器中。这里就是 0(refer to 	arch/x86/boot/compressed/vmlinux.lds.S)。注意，不是加载的物理地址哦。真实的物理地址一般是 0x100000
	// 用 rip 相对寻址，内部符号的引用就是位置无关的。
	leaq	startup_32(%rip) /* - $startup_32 */, %rbp	// 链接器会将其处理为 startup_32 的地址的，不过使用的是 rip 相对寻址罢了。 链接后的实际效果和 leaq startup_32, %rbp 没有区别，不过寻址方式不同罢了。

#ifdef CONFIG_EFI_STUB
/*
 * If we were loaded via the EFI LoadImage service, startup_32 will be at an
 * offset to the start of the space allocated for the image. efi_pe_entry will
 * set up image_offset to tell us where the image actually starts, so that we
 * can use the full available buffer.
 *	image_offset = startup_32 - image_base
 * Otherwise image_offset will be zero and has no effect on the calculations.
 */
	movl    image_offset(%rip), %eax
	subq	%rax, %rbp
#endif

	movl	BP_kernel_alignment(%rsi), %eax	// rsi 是第二个参数，也就是 boot_params, refer to: go_to_protected_mode()->protected_mode_jump()
	decl	%eax
	addq	%rax, %rbp
	notq	%rax
	andq	%rax, %rbp			
	cmpq	$LOAD_PHYSICAL_ADDR, %rbp	// LOAD_PHYSICAL_ADDR 是用来加载解压后的内核的位置(物理地址)
	jae	1f
#endif
	movq	$LOAD_PHYSICAL_ADDR, %rbp	// 至此 %rbp 记录解压后的内核保存的物理地址, 而且是对齐的
1:

	/* Target address to relocate to for decompression */
	movl	BP_init_size(%rsi), %ebx
	subl	$ rva(_end), %ebx
	addq	%rbp, %rbx		// rbx 保存的是 target address 了

	/* Set up the stack */
	leaq	rva(boot_stack_end)(%rbx), %rsp // boot 阶段临时使用的一个栈空间

	/*
	 * At this point we are in long mode with 4-level paging enabled,
	 * but we might want to enable 5-level paging or vice versa.
	 *
	 * The problem is that we cannot do it directly. Setting or clearing
	 * CR4.LA57 in long mode would trigger #GP. So we need to switch off
	 * long mode and paging first.
	 *
	 * We also need a trampoline in lower memory to switch over from
	 * 4- to 5-level paging for cases when the bootloader puts the kernel
	 * above 4G, but didn't enable 5-level paging for us.
	 *
	 * The same trampoline can be used to switch from 5- to 4-level paging
	 * mode, like when starting 4-level paging kernel via kexec() when
	 * original kernel worked in 5-level paging mode.
	 *
	 * For the trampoline, we need the top page table to reside in lower
	 * memory as we don't have a way to load 64-bit values into CR3 in
	 * 32-bit mode.
	 *
	 * We go though the trampoline even if we don't have to: if we're
	 * already in a desired paging mode. This way the trampoline code gets
	 * tested on every boot.
	 */

	/* Make sure we have GDT with 32-bit code segment */
	leaq	gdt64(%rip), %rax
	addq	%rax, 2(%rax)
	lgdt	(%rax)

	/* Reload CS so IRET returns to a CS actually in the GDT */
	pushq	$__KERNEL_CS
	leaq	.Lon_kernel_cs(%rip), %rax	// 跳到这里
	pushq	%rax
	lretq

.Lon_kernel_cs:

	pushq	%rsi
	call	load_stage1_idt
	popq	%rsi

	/*
	 * paging_prepare() sets up the trampoline and checks if we need to
	 * enable 5-level paging.
	 *
	 * paging_prepare() returns a two-quadword structure which lands
	 * into RDX:RAX:
	 *   - Address of the trampoline is returned in RAX.
	 *   - Non zero RDX means trampoline needs to enable 5-level
	 *     paging.
	 *
	 * RSI holds real mode data and needs to be preserved across
	 * this function call.
	 */
	pushq	%rsi
	movq	%rsi, %rdi		/* real mode address */
	call	paging_prepare
	popq	%rsi

	/* Save the trampoline address in RCX */
	movq	%rax, %rcx

	/*
	 * Load the address of trampoline_return() into RDI.
	 * It will be used by the trampoline to return to the main code.
	 */
	leaq	trampoline_return(%rip), %rdi

	/* Switch to compatibility mode (CS.L = 0 CS.D = 1) via far return */
	pushq	$__KERNEL32_CS
	leaq	TRAMPOLINE_32BIT_CODE_OFFSET(%rax), %rax
	pushq	%rax
	lretq
trampoline_return:
	/* Restore the stack, the 32-bit trampoline uses its own stack */
	leaq	rva(boot_stack_end)(%rbx), %rsp

	/*
	 * cleanup_trampoline() would restore trampoline memory.
	 *
	 * RDI is address of the page table to use instead of page table
	 * in trampoline memory (if required).
	 *
	 * RSI holds real mode data and needs to be preserved across
	 * this function call.
	 */
	pushq	%rsi
	leaq	rva(top_pgtable)(%rbx), %rdi
	call	cleanup_trampoline
	popq	%rsi

	/* Zero EFLAGS */
	pushq	$0
	popfq

/*
 * Copy the compressed kernel to the end of our buffer
 * where decompression in place becomes safe.
 */
	pushq	%rsi				// 赋值压缩的内核到要解压的位置
	leaq	(_bss-8)(%rip), %rsi
	leaq	rva(_bss-8)(%rbx), %rdi		// 参考前文代码，rbx 保存的是要解压 kernel 的目标位置
	movl	$(_bss - startup_32), %ecx	// _bss - startup_32 是 protected mode 的代码(包含压缩部分以及当前正在执行的未压缩的部分), refer to: arch/x86/boot/compressed/vmlinux.lds.S
	shrl	$3, %ecx
	std
	rep	movsq	// rsi 指向的内容，mov 到 rdi 指向的位置
	cld
	popq	%rsi

	/*
	 * The GDT may get overwritten either during the copy we just did or
	 * during extract_kernel below. To avoid any issues, repoint the GDTR  // 注意，前面我们将未压缩的那部分 protected mode code 也copy 过来了，即: 当前文件, 所以 gdt 部分也copy 过来了
	 * to the new copy of the GDT.
	 */
	leaq	rva(gdt64)(%rbx), %rax
	leaq	rva(gdt)(%rbx), %rdx
	movq	%rdx, 2(%rax)
	lgdt	(%rax)

/*
 * Jump to the relocated address.
 */
	leaq	rva(.Lrelocated)(%rbx), %rax
	jmp	*%rax		// just jump
SYM_CODE_END(startup_64)

#ifdef CONFIG_EFI_STUB
	.org 0x390
SYM_FUNC_START(efi64_stub_entry)
SYM_FUNC_START_ALIAS(efi_stub_entry)
	and	$~0xf, %rsp			/* realign the stack */
	movq	%rdx, %rbx			/* save boot_params pointer */
	call	efi_main
	movq	%rbx,%rsi
	leaq	rva(startup_64)(%rax), %rax
	jmp	*%rax
SYM_FUNC_END(efi64_stub_entry)
SYM_FUNC_END_ALIAS(efi_stub_entry)
#endif

	.text
SYM_FUNC_START_LOCAL_NOALIGN(.Lrelocated)

/*
 * Clear BSS (stack is currently empty)
 */
	xorl	%eax, %eax
	leaq    _bss(%rip), %rdi
	leaq    _ebss(%rip), %rcx
	subq	%rdi, %rcx
	shrq	$3, %rcx
	rep	stosq

/*
 * If running as an SEV guest, the encryption mask is required in the
 * page-table setup code below. When the guest also has SEV-ES enabled
 * set_sev_encryption_mask() will cause #VC exceptions, but the stage2
 * handler can't map its GHCB because the page-table is not set up yet.
 * So set up the encryption mask here while still on the stage1 #VC
 * handler. Then load stage2 IDT and switch to the kernel's own
 * page-table.
 */
	pushq	%rsi
	call	set_sev_encryption_mask
	call	load_stage2_idt

	/* Pass boot_params to initialize_identity_maps() */
	movq	(%rsp), %rdi
	call	initialize_identity_maps
	popq	%rsi


	// 前面是一些准备清理工作，核心是下面的解压，然后跳转到解压后的内核(long mode)

/*
 * Do the extraction, and jump to the new kernel..
 */
	pushq	%rsi			/* Save the real mode argument */
	movq	%rsi, %rdi		/* real mode address */
	leaq	boot_heap(%rip), %rsi	/* malloc area for uncompression */
	leaq	input_data(%rip), %rdx  /* input_data */	// 编译 linux 后会生成一个 piggy.S 的文件，里面有这个符号。是 arch/x86/boot/compressed/mkpiggy.c: 生成的
	movl	input_len(%rip), %ecx	/* input_len */
	movq	%rbp, %r8		/* output target address vmlinux 解压后的 LOAD 部分, 会放置到 output 位置, 即解压后的第一条指令会在这个位置。objudmp -Sl vmlinux 可以知道第一条指令就是 arch/x86/kernel/head_64.S:startup_64 */
	movl	output_len(%rip), %r9d	/* decompressed length, end of relocs  */
	call	extract_kernel		/* returns kernel location in %rax */ // arch/x86/boot/compressed/misc.c
	popq	%rsi

/*
 * Jump to the decompressed kernel.
 */
	// extract_kernel 解压后得到的就是一个 ELF 文件咯。从文件头当然能够找到 ENTRY 咯，默认情况下是 0x1000000 (16MB)，注意此时还是 identity map，这个虚拟地址和实际的物理地址是相等的, refer to: arch/x86/kernel/vmlinux.lds.S
	jmp	*%rax	/* 跳转到解压后的内核, rax 的值来自于 call extract_kernel 的返回值。即 arch/x86/kernel/head_64.S:startup_64  */
SYM_FUNC_END(.Lrelocated)

	.code32
/*
 * This is the 32-bit trampoline that will be copied over to low memory.
 *
 * RDI contains the return address (might be above 4G).
 * ECX contains the base address of the trampoline memory.
 * Non zero RDX means trampoline needs to enable 5-level paging.
 */
SYM_CODE_START(trampoline_32bit_src)
	/* Set up data and stack segments */
	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %ss

	/* Set up new stack */
	leal	TRAMPOLINE_32BIT_STACK_END(%ecx), %esp

	/* Disable paging */
	movl	%cr0, %eax
	btrl	$X86_CR0_PG_BIT, %eax
	movl	%eax, %cr0

	/* Check what paging mode we want to be in after the trampoline */
	cmpl	$0, %edx
	jz	1f

	/* We want 5-level paging: don't touch CR3 if it already points to 5-level page tables */
	movl	%cr4, %eax
	testl	$X86_CR4_LA57, %eax
	jnz	3f
	jmp	2f
1:
	/* We want 4-level paging: don't touch CR3 if it already points to 4-level page tables */
	movl	%cr4, %eax
	testl	$X86_CR4_LA57, %eax
	jz	3f
2:
	/* Point CR3 to the trampoline's new top level page table */
	leal	TRAMPOLINE_32BIT_PGTABLE_OFFSET(%ecx), %eax
	movl	%eax, %cr3
3:
	/* Set EFER.LME=1 as a precaution in case hypervsior pulls the rug */
	pushl	%ecx
	pushl	%edx
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax
	wrmsr
	popl	%edx
	popl	%ecx

	/* Enable PAE and LA57 (if required) paging modes */
	movl	$X86_CR4_PAE, %eax
	cmpl	$0, %edx
	jz	1f
	orl	$X86_CR4_LA57, %eax
1:
	movl	%eax, %cr4

	/* Calculate address of paging_enabled() once we are executing in the trampoline */
	leal	.Lpaging_enabled - trampoline_32bit_src + TRAMPOLINE_32BIT_CODE_OFFSET(%ecx), %eax

	/* Prepare the stack for far return to Long Mode */
	pushl	$__KERNEL_CS
	pushl	%eax

	/* Enable paging again */
	movl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movl	%eax, %cr0

	lret
SYM_CODE_END(trampoline_32bit_src)

	.code64
SYM_FUNC_START_LOCAL_NOALIGN(.Lpaging_enabled)
	/* Return from the trampoline */
	jmp	*%rdi
SYM_FUNC_END(.Lpaging_enabled)

	/*
         * The trampoline code has a size limit.
         * Make sure we fail to compile if the trampoline code grows
         * beyond TRAMPOLINE_32BIT_CODE_SIZE bytes.
	 */
	.org	trampoline_32bit_src + TRAMPOLINE_32BIT_CODE_SIZE

	.code32
SYM_FUNC_START_LOCAL_NOALIGN(.Lno_longmode)
	/* This isn't an x86-64 CPU, so hang intentionally, we cannot continue */
1:
	hlt
	jmp     1b
SYM_FUNC_END(.Lno_longmode)

#include "../../kernel/verify_cpu.S"

	.data
SYM_DATA_START_LOCAL(gdt64)
	.word	gdt_end - gdt - 1
	.quad   gdt - gdt64
SYM_DATA_END(gdt64)
	.balign	8
SYM_DATA_START_LOCAL(gdt) // refer to: arch/x86/include/asm/segment.h
	.word	gdt_end - gdt - 1
	.long	0			// 这个位置保存了 gdt 的地址, 详见前文 movl %eax, 2(%eax); lgdt (%eax)		
	.word	0			// 这里是 第 0 个entry, NULL descriptor， GDT 的第0个entry是不使用的。Intel 的规定，防止加电后段寄存器没有初始化就进入保护模式使用 GDT
	/*
		0x0000(B15-B0) ffff(L15-L0)

		0x00(B31-B24)

		c(0x1100 G is 1 means 4KB, D/B is 1 means 32b code)

		f(L19-L16)

		9a(0x1001 1010)
			- P is 1: present
			- DPL is 00: 最高优先级
			- S is 1: 代码段 或者数据段

			- E is 1: 代码段 
			- ED/C is 0  
			- R/W is 1
			- A is 0

		00(B23-B16)

		Base Addr = 0x00000000
		Limit = 0xfffff * 4KB (4GB - 4KB) 的访问空间

	 */
	.quad	0x00cf9a000000ffff	/* __KERNEL32_CS */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */	// 第3个entry
	.quad	0x0080890000000000	/* TS descriptor */
	.quad   0x0000000000000000	/* TS continued */
SYM_DATA_END_LABEL(gdt, SYM_L_LOCAL, gdt_end)

SYM_DATA_START(boot_idt_desc)
	.word	boot_idt_end - boot_idt - 1
	.quad	0
SYM_DATA_END(boot_idt_desc)
	.balign 8
SYM_DATA_START(boot_idt)
	.rept	BOOT_IDT_ENTRIES
	.quad	0
	.quad	0
	.endr
SYM_DATA_END_LABEL(boot_idt, SYM_L_GLOBAL, boot_idt_end)

#ifdef CONFIG_EFI_STUB
SYM_DATA(image_offset, .long 0)
#endif
#ifdef CONFIG_EFI_MIXED
SYM_DATA_LOCAL(efi32_boot_args, .long 0, 0, 0)
SYM_DATA(efi_is64, .byte 1)

#define ST32_boottime		60 // offsetof(efi_system_table_32_t, boottime)
#define BS32_handle_protocol	88 // offsetof(efi_boot_services_32_t, handle_protocol)
#define LI32_image_base		32 // offsetof(efi_loaded_image_32_t, image_base)

	__HEAD
	.code32
SYM_FUNC_START(efi32_pe_entry)
/*
 * efi_status_t efi32_pe_entry(efi_handle_t image_handle,
 *			       efi_system_table_32_t *sys_table)
 */

	pushl	%ebp
	movl	%esp, %ebp
	pushl	%eax				// dummy push to allocate loaded_image

	pushl	%ebx				// save callee-save registers
	pushl	%edi

	call	verify_cpu			// check for long mode support
	testl	%eax, %eax
	movl	$0x80000003, %eax		// EFI_UNSUPPORTED
	jnz	2f

	call	1f
1:	pop	%ebx
	subl	$ rva(1b), %ebx

	/* Get the loaded image protocol pointer from the image handle */
	leal	-4(%ebp), %eax
	pushl	%eax				// &loaded_image
	leal	rva(loaded_image_proto)(%ebx), %eax
	pushl	%eax				// pass the GUID address
	pushl	8(%ebp)				// pass the image handle

	/*
	 * Note the alignment of the stack frame.
	 *   sys_table
	 *   handle             <-- 16-byte aligned on entry by ABI
	 *   return address
	 *   frame pointer
	 *   loaded_image       <-- local variable
	 *   saved %ebx		<-- 16-byte aligned here
	 *   saved %edi
	 *   &loaded_image
	 *   &loaded_image_proto
	 *   handle             <-- 16-byte aligned for call to handle_protocol
	 */

	movl	12(%ebp), %eax			// sys_table
	movl	ST32_boottime(%eax), %eax	// sys_table->boottime
	call	*BS32_handle_protocol(%eax)	// sys_table->boottime->handle_protocol
	addl	$12, %esp			// restore argument space
	testl	%eax, %eax
	jnz	2f

	movl	8(%ebp), %ecx			// image_handle
	movl	12(%ebp), %edx			// sys_table
	movl	-4(%ebp), %esi			// loaded_image
	movl	LI32_image_base(%esi), %esi	// loaded_image->image_base
	movl	%ebx, %ebp			// startup_32 for efi32_pe_stub_entry
	/*
	 * We need to set the image_offset variable here since startup_32() will
	 * use it before we get to the 64-bit efi_pe_entry() in C code.
	 */
	subl	%esi, %ebx
	movl	%ebx, rva(image_offset)(%ebp)	// save image_offset
	jmp	efi32_pe_stub_entry

2:	popl	%edi				// restore callee-save registers
	popl	%ebx
	leave
	ret
SYM_FUNC_END(efi32_pe_entry)

	.section ".rodata"
	/* EFI loaded image protocol GUID */
	.balign 4
SYM_DATA_START_LOCAL(loaded_image_proto)
	.long	0x5b1b31a1
	.word	0x9562, 0x11d2
	.byte	0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b
SYM_DATA_END(loaded_image_proto)
#endif

/*
 * Stack and heap for uncompression
 */
	.bss
	.balign 4
SYM_DATA_LOCAL(boot_heap,	.fill BOOT_HEAP_SIZE, 1, 0)

SYM_DATA_START_LOCAL(boot_stack)		// 这部分空间作为 boot 过程临时的栈使用。
	.fill BOOT_STACK_SIZE, 1, 0		// 大小 0x4000	14KB
	.balign 16
SYM_DATA_END_LABEL(boot_stack, SYM_L_LOCAL, boot_stack_end) // 注意这里的高地址是栈底

/*
 * Space for page tables (not in .bss so not zeroed)
 */
	.section ".pgtable","aw",@nobits
	.balign 4096			// 填充 4K 大小的0
SYM_DATA_LOCAL(pgtable,		.fill BOOT_PGT_SIZE, 1, 0) // 继续填充 BOOT_PGT_SIZE(19 * 4K) 大小的0

/*
 * The page table is going to be used instead of page table in the trampoline
 * memory.
 */
SYM_DATA_LOCAL(top_pgtable,	.fill PAGE_SIZE, 1, 0)
