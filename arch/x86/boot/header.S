/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	header.S
 *
 *	Copyright (C) 1991, 1992 Linus Torvalds
 *
 *	Based on bootsect.S and setup.S
 *	modified by more people than can be counted
 *
 *	Rewritten as a common file by H. Peter Anvin (Apr 2007)
 *
 * BIG FAT NOTE: We're in real mode using 64k segments.  Therefore segment
 * addresses must be multiplied by 16 to obtain their respective linear
 * addresses. To avoid confusion, linear addresses are written using leading
 * hex while segment addresses are written as segment:offset.
 *
 */
#include <linux/pe.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/page_types.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include "boot.h"
#include "voffset.h"
#include "zoffset.h"

BOOTSEG		= 0x07C0		/* original address of boot-sector */ //注意需要 << 4, 即 0x7c00, 0x7c00 是加载 boot loader 的地方
SYSSEG		= 0x1000		/* historical load address >> 4 */ //同上，0x10000, header.S 一般加载到这个位置

#ifndef SVGA_MODE
#define SVGA_MODE ASK_VGA
#endif

#ifndef ROOT_RDONLY
#define ROOT_RDONLY 1
#endif

// 这部分的链接编译，参考 setup.ld 脚本
	.code16		// 告诉编译器这里的代码是 16 位模式的
	.section ".bstext", "ax"	// ax 说明这个 section 是可执行的

	.global bootsect_start		// 告诉链接器这是一个 global 符号
bootsect_start:
#ifdef CONFIG_EFI_STUB			// 用于 UEFI 支持的
	# "MZ", MS-DOS header
	.word	MZ_MAGIC		// 一般是 0x10000 位置, 未开启 kaslr
#endif

	# Normalize the start address, 为了设置下 CS 寄存器, CS <- $BOOTSEG, IP <- $start2
	ljmp	$BOOTSEG, $start2 # 跳到start2, Linux早期自带的 boot loader, grub 场景下不会执行这部分代码了

start2:
	movw	%cs, %ax # 此时cs应该是0x07c0, 见前文的 ljmp 指令
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	xorw	%sp, %sp # sp 置零
	sti
	cld

	movw	$bugger_off_msg, %si

msg_loop:
	lodsb
	andb	%al, %al
	jz	bs_die
	movb	$0xe, %ah
	movw	$7, %bx
	int	$0x10
	jmp	msg_loop

bs_die:
	# Allow the user to press a key, then reboot
	xorw	%ax, %ax
	int	$0x16
	int	$0x19

	# int 0x19 should never return.  In case it does anyway,
	# invoke the BIOS reset code...
	ljmp	$0xf000,$0xfff0 # 这是bios的起始地址，注意不是0xf000fff0 而是 0xfffffff0

#ifdef CONFIG_EFI_STUB
	.org	0x3c
	#
	# Offset to the PE header.
	#
	.long	pe_header
#endif /* CONFIG_EFI_STUB */

	.section ".bsdata", "a"
bugger_off_msg:
	.ascii	"Use a boot loader.\r\n"
	.ascii	"\n"
	.ascii	"Remove disk and press any key to reboot...\r\n"
	.byte	0

#ifdef CONFIG_EFI_STUB
pe_header: // 这部分是为了支持 UEFI boot，将 CS 设置为了 0x07c0
	.long	PE_MAGIC

coff_header:
#ifdef CONFIG_X86_32
	.set	image_file_add_flags, IMAGE_FILE_32BIT_MACHINE
	.set	pe_opt_magic, PE_OPT_MAGIC_PE32
	.word	IMAGE_FILE_MACHINE_I386
#else
	.set	image_file_add_flags, 0
	.set	pe_opt_magic, PE_OPT_MAGIC_PE32PLUS
	.word	IMAGE_FILE_MACHINE_AMD64
#endif
	.word	section_count			# nr_sections
	.long	0 				# TimeDateStamp
	.long	0				# PointerToSymbolTable
	.long	1				# NumberOfSymbols
	.word	section_table - optional_header	# SizeOfOptionalHeader
	.word	IMAGE_FILE_EXECUTABLE_IMAGE	| \
		image_file_add_flags		| \
		IMAGE_FILE_DEBUG_STRIPPED	| \
		IMAGE_FILE_LINE_NUMS_STRIPPED	# Characteristics

optional_header:
	.word	pe_opt_magic
	.byte	0x02				# MajorLinkerVersion
	.byte	0x14				# MinorLinkerVersion

	# Filled in by build.c
	.long	0				# SizeOfCode

	.long	0				# SizeOfInitializedData
	.long	0				# SizeOfUninitializedData

	# Filled in by build.c
	.long	0x0000				# AddressOfEntryPoint

	.long	0x0200				# BaseOfCode
#ifdef CONFIG_X86_32
	.long	0				# data
#endif

extra_header_fields:
	# PE specification requires ImageBase to be 64k aligned
	.set	image_base, (LOAD_PHYSICAL_ADDR + 0xffff) & ~0xffff
#ifdef CONFIG_X86_32
	.long	image_base			# ImageBase
#else
	.quad	image_base			# ImageBase
#endif
	.long	0x20				# SectionAlignment
	.long	0x20				# FileAlignment
	.word	0				# MajorOperatingSystemVersion
	.word	0				# MinorOperatingSystemVersion
	.word	LINUX_EFISTUB_MAJOR_VERSION	# MajorImageVersion
	.word	LINUX_EFISTUB_MINOR_VERSION	# MinorImageVersion
	.word	0				# MajorSubsystemVersion
	.word	0				# MinorSubsystemVersion
	.long	0				# Win32VersionValue

	#
	# The size of the bzImage is written in tools/build.c
	#
	.long	0				# SizeOfImage

	.long	0x200				# SizeOfHeaders
	.long	0				# CheckSum
	.word	IMAGE_SUBSYSTEM_EFI_APPLICATION	# Subsystem (EFI application)
	.word	0				# DllCharacteristics
#ifdef CONFIG_X86_32
	.long	0				# SizeOfStackReserve
	.long	0				# SizeOfStackCommit
	.long	0				# SizeOfHeapReserve
	.long	0				# SizeOfHeapCommit
#else
	.quad	0				# SizeOfStackReserve
	.quad	0				# SizeOfStackCommit
	.quad	0				# SizeOfHeapReserve
	.quad	0				# SizeOfHeapCommit
#endif
	.long	0				# LoaderFlags
	.long	(section_table - .) / 8		# NumberOfRvaAndSizes

	.quad	0				# ExportTable
	.quad	0				# ImportTable
	.quad	0				# ResourceTable
	.quad	0				# ExceptionTable
	.quad	0				# CertificationTable
	.quad	0				# BaseRelocationTable

	# Section table
section_table:
	#
	# The offset & size fields are filled in by build.c.
	#
	.ascii	".setup"
	.byte	0
	.byte	0
	.long	0
	.long	0x0				# startup_{32,64}
	.long	0				# Size of initialized data
						# on disk
	.long	0x0				# startup_{32,64}
	.long	0				# PointerToRelocations
	.long	0				# PointerToLineNumbers
	.word	0				# NumberOfRelocations
	.word	0				# NumberOfLineNumbers
	.long	IMAGE_SCN_CNT_CODE		| \
		IMAGE_SCN_MEM_READ		| \
		IMAGE_SCN_MEM_EXECUTE		| \
		IMAGE_SCN_ALIGN_16BYTES		# Characteristics

	#
	# The EFI application loader requires a relocation section
	# because EFI applications must be relocatable. The .reloc
	# offset & size fields are filled in by build.c.
	#
	.ascii	".reloc"
	.byte	0
	.byte	0
	.long	0
	.long	0
	.long	0				# SizeOfRawData
	.long	0				# PointerToRawData
	.long	0				# PointerToRelocations
	.long	0				# PointerToLineNumbers
	.word	0				# NumberOfRelocations
	.word	0				# NumberOfLineNumbers
	.long	IMAGE_SCN_CNT_INITIALIZED_DATA	| \
		IMAGE_SCN_MEM_READ		| \
		IMAGE_SCN_MEM_DISCARDABLE	| \
		IMAGE_SCN_ALIGN_1BYTES		# Characteristics

#ifdef CONFIG_EFI_MIXED
	#
	# The offset & size fields are filled in by build.c.
	#
	.asciz	".compat"
	.long	0
	.long	0x0
	.long	0				# Size of initialized data
						# on disk
	.long	0x0
	.long	0				# PointerToRelocations
	.long	0				# PointerToLineNumbers
	.word	0				# NumberOfRelocations
	.word	0				# NumberOfLineNumbers
	.long	IMAGE_SCN_CNT_INITIALIZED_DATA	| \
		IMAGE_SCN_MEM_READ		| \
		IMAGE_SCN_MEM_DISCARDABLE	| \
		IMAGE_SCN_ALIGN_1BYTES		# Characteristics
#endif

	#
	# The offset & size fields are filled in by build.c.
	#
	.ascii	".text"
	.byte	0
	.byte	0
	.byte	0
	.long	0
	.long	0x0				# startup_{32,64}
	.long	0				# Size of initialized data
						# on disk
	.long	0x0				# startup_{32,64}
	.long	0				# PointerToRelocations
	.long	0				# PointerToLineNumbers
	.word	0				# NumberOfRelocations
	.word	0				# NumberOfLineNumbers
	.long	IMAGE_SCN_CNT_CODE		| \
		IMAGE_SCN_MEM_READ		| \
		IMAGE_SCN_MEM_EXECUTE		| \
		IMAGE_SCN_ALIGN_16BYTES		# Characteristics

	.set	section_count, (. - section_table) / 40
#endif /* CONFIG_EFI_STUB */

	# Kernel attributes; used by setup.  This is part 1 of the
	# header, from the old boot sector.

	# 此时是 real-mode，一般 bootloader 会将各个段寄存器都设置为 gs = fs = es = ds = ss = 0x1000, cs = 0x1020。因为 boot loader 将 这部分代码加载到了 0x10000(64KB) 位置，而 jmp 指令在 0x10200 位置，所以将 cs 设置为 0x1020，rip 设置为0就可以找到正确的jmp 指令位置了。如果 bootloader 将这部分 setup 代码加载到别的位置的话，这几个寄存器的设置也要有更改的, refer to: boot.rst
	.section ".header", "a"		// arch/x86/boot/setup.ld 将这个 section 控制在 0x1ef offset 位置，这样后面的jump 指令就正好在 0x200 offset位置了
	.globl	sentinel
sentinel:	.byte 0xff, 0xff        /* Used to detect broken loaders */

	.globl	hdr
hdr:
setup_sects:	.byte 0			/* Filled in by build.c */
root_flags:	.word ROOT_RDONLY
syssize:	.long 0			/* Filled in by build.c */
ram_size:	.word 0			/* Obsolete */
vid_mode:	.word SVGA_MODE
root_dev:	.word 0			/* Filled in by build.c */
boot_flag:	.word 0xAA55		// 启动盘第一个扇区的最后两个字节应该是这个

	# offset 512(0x200), entry point

	.globl	_start	// 参考 boot.rst, 怎么控制这个符号正好在setup.elf 的 0x200 位置？？? setup.lds 控制了 .header section 的位置
_start: # 0x200, 这是setup_header 的 512Bytes 偏移位置，这里必须是一条 jump 指令。boot loader 知道这里是jump 指令，会直接执行的
		# Explicitly enter this as bytes, or the assembler
		# tries to generate a 3-byte jump here, which causes
		# everything else to push off to the wrong offset.
		# 根据 boot protocol，boot loader 知道这里有一条 jump指令，就会执行这条指令
		.byte	0xeb		# short (2-byte) jump 这个是一条jump指令, 0xeb 是条jump指令, bootloader 最后会执行这条指令的
		.byte	start_of_setup-1f # 0x202 这里表示两个label: start_of_setup 和 1f 之间的距离。结合这个相对跳转指令。所以就是跳转到start_of_setup 位置。即header.S 的代码段开始位置。
1:

	# Part 2 of the header, from the old setup.S

		.ascii	"HdrS"		# header signature
		.word	0x020f		# header version number (>= 0x0105)
					# or else old loadlin-1.5 will fail)
		.globl realmode_swtch
realmode_swtch:	.word	0, 0		# default_switch, SETUPSEG
start_sys_seg:	.word	SYSSEG		# obsolete and meaningless, but just
					# in case something decided to "use" it
		.word	kernel_version-512 # pointing to kernel version string
					# above section of header is compatible
					# with loadlin-1.5 (header v1.5). Don't
					# change it.

type_of_loader:	.byte	0		# 0 means ancient bootloader, newer
					# bootloaders know to change this.
					# See Documentation/x86/boot.rst for
					# assigned ids

# flags, unused bits must be zero (RFU) bit within loadflags
loadflags:
		.byte	LOADED_HIGH	# The kernel is to be loaded high

setup_move_size: .word  0x8000		# size to move, when setup is not
					# loaded at 0x90000. We will move setup
					# to 0x90000 then just before jumping
					# into the kernel. However, only the
					# loader knows how much data behind
					# us also needs to be loaded.

code32_start:				# here loaders can put a different
					# start address for 32-bit code.
		.long	0x100000	# 0x100000 = default for big kernel

ramdisk_image:	.long	0		# address of loaded ramdisk image
					# Here the loader puts the 32-bit
					# address where it loaded the image.
					# This only will be read by the kernel.

ramdisk_size:	.long	0		# its size in bytes

bootsect_kludge:
		.long	0		# obsolete

heap_end_ptr:	.word	_end+STACK_SIZE-512	# heap 的大小只有 STACK_SIZE-512 = 512 Bytes，太小咯
					# (Header version 0x0201 or later)
					# space from here (exclusive) down to
					# end of setup code can be used by setup
					# for local heap purposes.

ext_loader_ver:
		.byte	0		# Extended boot loader version
ext_loader_type:
		.byte	0		# Extended boot loader type

cmd_line_ptr:	.long	0		# (Header version 0x0202 or later)
					# If nonzero, a 32-bit pointer
					# to the kernel command line.
					# The command line should be
					# located between the start of
					# setup and the end of low
					# memory (0xa0000), or it may
					# get overwritten before it
					# gets read.  If this field is
					# used, there is no longer
					# anything magical about the
					# 0x90000 segment; the setup
					# can be located anywhere in
					# low memory 0x10000 or higher.

initrd_addr_max: .long 0x7fffffff
					# (Header version 0x0203 or later)
					# The highest safe address for
					# the contents of an initrd
					# The current kernel allows up to 4 GB,
					# but leave it at 2 GB to avoid
					# possible bootloader bugs.

kernel_alignment:  .long CONFIG_PHYSICAL_ALIGN	#physical addr alignment
						#required for protected mode
						#kernel
#ifdef CONFIG_RELOCATABLE
relocatable_kernel:    .byte 1
#else
relocatable_kernel:    .byte 0
#endif
min_alignment:		.byte MIN_KERNEL_ALIGN_LG2	# minimum alignment

xloadflags:
#ifdef CONFIG_X86_64
# define XLF0 XLF_KERNEL_64			/* 64-bit kernel */
#else
# define XLF0 0
#endif

#if defined(CONFIG_RELOCATABLE) && defined(CONFIG_X86_64)
   /* kernel/boot_param/ramdisk could be loaded above 4g */
# define XLF1 XLF_CAN_BE_LOADED_ABOVE_4G
#else
# define XLF1 0
#endif

#ifdef CONFIG_EFI_STUB
# ifdef CONFIG_EFI_MIXED
#  define XLF23 (XLF_EFI_HANDOVER_32|XLF_EFI_HANDOVER_64)
# else
#  ifdef CONFIG_X86_64
#   define XLF23 XLF_EFI_HANDOVER_64		/* 64-bit EFI handover ok */
#  else
#   define XLF23 XLF_EFI_HANDOVER_32		/* 32-bit EFI handover ok */
#  endif
# endif
#else
# define XLF23 0
#endif

#if defined(CONFIG_X86_64) && defined(CONFIG_EFI) && defined(CONFIG_KEXEC_CORE)
# define XLF4 XLF_EFI_KEXEC
#else
# define XLF4 0
#endif

#ifdef CONFIG_X86_64
#ifdef CONFIG_X86_5LEVEL
#define XLF56 (XLF_5LEVEL|XLF_5LEVEL_ENABLED)
#else
#define XLF56 XLF_5LEVEL
#endif
#else
#define XLF56 0
#endif

			.word XLF0 | XLF1 | XLF23 | XLF4 | XLF56

cmdline_size:   .long   COMMAND_LINE_SIZE-1     #length of the command line,
                                                #added with boot protocol
                                                #version 2.06

hardware_subarch:	.long 0			# subarchitecture, added with 2.07
						# default to 0 for normal x86 PC

hardware_subarch_data:	.quad 0

payload_offset:		.long ZO_input_data
payload_length:		.long ZO_z_input_len

setup_data:		.quad 0			# 64-bit physical pointer to
						# single linked list of
						# struct setup_data

pref_address:		.quad LOAD_PHYSICAL_ADDR	# preferred load addr

#
# Getting to provably safe in-place decompression is hard. Worst case
# behaviours need to be analyzed. Here let's take the decompression of
# a gzip-compressed kernel as example, to illustrate it:
#
# The file layout of gzip compressed kernel is:
#
#    magic[2]
#    method[1]
#    flags[1]
#    timestamp[4]
#    extraflags[1]
#    os[1]
#    compressed data blocks[N]
#    crc[4] orig_len[4]
#
# ... resulting in +18 bytes overhead of uncompressed data.
#
# (For more information, please refer to RFC 1951 and RFC 1952.)
#
# Files divided into blocks
# 1 bit (last block flag)
# 2 bits (block type)
#
# 1 block occurs every 32K -1 bytes or when there 50% compression
# has been achieved. The smallest block type encoding is always used.
#
# stored:
#    32 bits length in bytes.
#
# fixed:
#    magic fixed tree.
#    symbols.
#
# dynamic:
#    dynamic tree encoding.
#    symbols.
#
#
# The buffer for decompression in place is the length of the uncompressed
# data, plus a small amount extra to keep the algorithm safe. The
# compressed data is placed at the end of the buffer.  The output pointer
# is placed at the start of the buffer and the input pointer is placed
# where the compressed data starts. Problems will occur when the output
# pointer overruns the input pointer.
#
# The output pointer can only overrun the input pointer if the input
# pointer is moving faster than the output pointer.  A condition only
# triggered by data whose compressed form is larger than the uncompressed
# form.
#
# The worst case at the block level is a growth of the compressed data
# of 5 bytes per 32767 bytes.
#
# The worst case internal to a compressed block is very hard to figure.
# The worst case can at least be bounded by having one bit that represents
# 32764 bytes and then all of the rest of the bytes representing the very
# very last byte.
#
# All of which is enough to compute an amount of extra data that is required
# to be safe.  To avoid problems at the block level allocating 5 extra bytes
# per 32767 bytes of data is sufficient.  To avoid problems internal to a
# block adding an extra 32767 bytes (the worst case uncompressed block size)
# is sufficient, to ensure that in the worst case the decompressed data for
# block will stop the byte before the compressed data for a block begins.
# To avoid problems with the compressed data's meta information an extra 18
# bytes are needed.  Leading to the formula:
#
# extra_bytes = (uncompressed_size >> 12) + 32768 + 18
#
# Adding 8 bytes per 32K is a bit excessive but much easier to calculate.
# Adding 32768 instead of 32767 just makes for round numbers.
#
# Above analysis is for decompressing gzip compressed kernel only. Up to
# now 6 different decompressor are supported all together. And among them
# xz stores data in chunks and has maximum chunk of 64K. Hence safety
# margin should be updated to cover all decompressors so that we don't
# need to deal with each of them separately. Please check
# the description in lib/decompressor_xxx.c for specific information.
#
# extra_bytes = (uncompressed_size >> 12) + 65536 + 128
#
# LZ4 is even worse: data that cannot be further compressed grows by 0.4%,
# or one byte per 256 bytes. OTOH, we can safely get rid of the +128 as
# the size-dependent part now grows so fast.
#
# extra_bytes = (uncompressed_size >> 8) + 65536
#
# ZSTD compressed data grows by at most 3 bytes per 128K, and only has a 22
# byte fixed overhead but has a maximum block size of 128K, so it needs a
# larger margin.
#
# extra_bytes = (uncompressed_size >> 8) + 131072

#define ZO_z_extra_bytes	((ZO_z_output_len >> 8) + 131072)
#if ZO_z_output_len > ZO_z_input_len
# define ZO_z_extract_offset	(ZO_z_output_len + ZO_z_extra_bytes - \
				 ZO_z_input_len)
#else
# define ZO_z_extract_offset	ZO_z_extra_bytes
#endif

/*
 * The extract_offset has to be bigger than ZO head section. Otherwise when
 * the head code is running to move ZO to the end of the buffer, it will
 * overwrite the head code itself.
 */
#if (ZO__ehead - ZO_startup_32) > ZO_z_extract_offset
# define ZO_z_min_extract_offset ((ZO__ehead - ZO_startup_32 + 4095) & ~4095)
#else
# define ZO_z_min_extract_offset ((ZO_z_extract_offset + 4095) & ~4095)
#endif

#define ZO_INIT_SIZE	(ZO__end - ZO_startup_32 + ZO_z_min_extract_offset)

#define VO_INIT_SIZE	(VO__end - VO__text)
#if ZO_INIT_SIZE > VO_INIT_SIZE
# define INIT_SIZE ZO_INIT_SIZE
#else
# define INIT_SIZE VO_INIT_SIZE
#endif

init_size:		.long INIT_SIZE		# kernel initialization size
handover_offset:	.long 0			# Filled in by build.c
kernel_info_offset:	.long 0			# Filled in by build.c

# End of setup header #####################################################

	.section ".entrytext", "ax"
	# 现在还是实模式, 还是段式寻址
	# 在这个位置时，bootloader 会将寄存器设置为: gs = fs = es = ds = ss = 0x1000, 前提是 header.S 被加载到了这里 0x10000
	# cs = 0x1020		// 注意段寄存器使用的时候会左移4b
start_of_setup:			// kenerl 真正开始的位置,此时还是 real-mode
# Force %es = %ds		// 接下来kernel 要做4件事: 1. make sure all segment register values are equal； 2. setup a correct stack; 3. set up bss; 4. jump to the C code in arch/x86/boot/main.c
	movw	%ds, %ax
	movw	%ax, %es
	cld

# Apparently some ancient versions of LILO invoked the kernel with %ss != %ds,
# which happened to work by accident for the old code.  Recalculate the stack
# pointer if %ss is invalid.  Otherwise leave it alone, LOADLIN sets up the
# stack behind its own code, so we can't blindly put it directly past the heap.

	movw	%ss, %dx
	cmpw	%ax, %dx	# %ds == %ss?  ss 寄存器用来索引栈的，ds 寄存器用来索引数据的。在 linux 中后续基本不使用段机制，会让所段有寄存器的值相等的。
	movw	%sp, %dx	# 取决于 bootloader 的设置
	je	2f		# -> assume %sp is reasonably set。linux 需要强制 ss == ds 的。说明 boot loader 将栈控制设置好了，不需要 kernel 重新搞了。一般都是 bootloader 设置好 stack / heap 空间的。kernel 不需要自己操作的

	# Invalid %ss, make up a new stack,  ss 寄存器不符合linux 的需求，那么这个栈需要重构
	movw	$_end, %dx	# refer to setup.ld 可以看到 _end 符号是 header.S 编译后的尾部。即其加载到内存后的尾部位置
	testb	$CAN_USE_HEAP, loadflags # refer to: arch/x86/include/uapi/asm/bootparam.h
	jz	1f		# 如果是 0 就会跳转，说明 loadflags 是0；不跳转的话，说明设置了 CAN_USE_HEAP flag
	movw	heap_end_ptr, %dx	# 可以使用 head 的话，dx 就是 head end
1:	addw	$STACK_SIZE, %dx	# head end + STACK size, boot loader 没有设置好栈空间，kernel 需要字节设置一下, refer to: arch/x86/boot/boot.h
	jnc	2f			# jnc: jump on not carry，没有进位的时候就跳转
	xorw	%dx, %dx	# Prevent wraparound

2:	# Now %dx should point to the end of our stack space, 即 sp 指针。
	andw	$~3, %dx	# dword align (might as well...)
	jnz	3f
	movw	$0xfffc, %dx	# Make sure we're not zero
3:	movw	%ax, %ss	# 注意看，前面将ds 的值保存到了 ax 中的
	movzwl	%dx, %esp	# Clear upper half of %esp
	sti			# Now we should have a working stack ,为啥开中断？？？

# We will have entered with %cs = %ds+0x20, normalize %cs so
# it is on par with the other segments.
	pushw	%ds #  which pushes the value of ds to the stack, followed by the address of the 6 label and executes the lretw instruction. When the lretw instruction is called, it loads the address of label 6 into the instruction pointer register and loads cs with the value of ds. Afterward, ds and cs will have the same values.
	pushw	$6f #  一个 ret 就跳转到这里了。同时会用这里 push 进去的 ds 来加载 cs。注意此时还是实模式
	lretw  # 因为这里是一条 lret，所以会加载 cs 寄存器。 cs = ds；ip = 6f 了。因为 ds 被设置为 header.S 被加载的位置。所以这里就lret 到了 6的位置继续执行了
6:

# Check signature at end of setup
	cmpl	$0x5a5aaa55, setup_sig	# refer to: setup.ld
	jne	setup_bad

# Zero the bss
	movw	$__bss_start, %di	# refer to: setup.ld, 从 __bss_start 到 _end+3 位置全部设置为0
	movw	$_end+3, %cx
	xorl	%eax, %eax
	subw	%di, %cx
	shrw	$2, %cx			# 右移两位，高位补0
	rep; stosl

# Jump to C code (should not return)

# real-mode
# 如果是kernel自己设置的 heap 和 stack 的话，此时内存布局如下
# 到这里的时候，内存布局如下图所示: 注意，下图忽略了一些边界对齐的情况, 仅做示意
#+--------------------------------+ <- esp 注意此时 esp 在这个位置，下面的空间理论来说还不是 stack, esp = heap_end_ptr + STACK_SIZE
#|                                |
#| Stack(size: STACK_SIZE)        | // 一般大小是 1024
#|                                |
#|                                |
#|                                |
#|                                |
#|--------------------------------| <- heap_end_ptr = _end + STACK_SIZE - 512 = _end + 512
#|                                |
#| HEAP (size: STACK_SIZE - 512)  | // 前提是 loadflags 中 enable 了 HEAP, 这里 heap 的空间大小只有 512Bytes
#|                                |
#|--------------------------------| <- _end 符号, refer to: setup.ld
#|                                |
#| BSS(all zero)                  |
#|                                |
#+--------------------------------+
#| kernel setup.elf               |
#+--------------------------------+ <- 一般是 0x10000, ss, cs 等段寄存器是 0x1000
	calll	main # arch/x86/boot/main.c::main()，因为这几个文件最终都是link 到一起的

# Setup corrupt somehow...
setup_bad:
	movl	$setup_corrupt, %eax
	calll	puts
	# Fall through...

	.globl	die
	.type	die, @function
die:
	hlt
	jmp	die

	.size	die, .-die

	.section ".initdata", "a"
setup_corrupt:
	.byte	7
	.string	"No setup signature found...\n"
