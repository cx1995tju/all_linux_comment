/*
 * setup.ld
 *
 * Linker script for the i386 setup code
 */
OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)		/* 这里说明了入口是 _start, header.S 中有一个 _start 符号。仅仅是在链接得到的 elf 文件中记录了一个入口地址，即相对于该文件的偏移 offset。至于loader 如何使用这个 entry，是否使用那都是取决于 loader 的实现 */

SECTIONS
{
	. = 0;						/* 告诉链接器 此处的 VMA 是 0, 如果kernel 没有开启kaslr的话，setup 这部分代码一般会被 boot loader 加载到 0x10000 位置，即这里的 offset 0 就在 0x10000 位置。可以用 qemu 拉起虚拟机, disable kaslr。然后dump 下物理内存就知道了  */
	.bstext		: { *(.bstext) }		/* 所有文件的 bstext 段汇聚到一起，组成一个新的 .bstext 段, 而且这个段是在文件的最前面的 */
	.bsdata		: { *(.bsdata) }

	. = 495;			/* 0x1ef */ /* 将当前地址设置成了 0x1ef */
	.header		: { *(.header) } /* 表示任意文件的 .header 段放到这里来 */
	.entrytext	: { *(.entrytext) }
	.inittext	: { *(.inittext) }
	.initdata	: { *(.initdata) }
	__end_init = .;

	.text		: { *(.text .text.*) } /* 代码段 */
	.text32		: { *(.text32) }

	. = ALIGN(16);
	.rodata		: { *(.rodata*) }

	.videocards	: {
		video_cards = .; /* video_cards 是一个地址, refer to:  arch/x86/boot/video-vga.c:video_vga 定义的时候会把符号 video_vga 放到这个 section中，然后这些 section 都会被聚集到一起。同时这里的两个符号也定位了这个 section 起始结束位置*/
		*(.videocards)	/* 所有的 card_info 结构都会被放在这个位置 */
		video_cards_end = .;
	}

	. = ALIGN(16);	/* 将当前的 VMA 做对齐 */
	.data		: { *(.data*) }

	.signature	: {
		setup_sig = .;		/* 最终会成为二进制文件中的一份符号 */
		LONG(0x5a5aaa55)	/* 该位置会放置一个 LONG 大小的数值 */
	}


	. = ALIGN(16);
	.bss		:		/* 一些全局变量都放在这里 */
	{
		__bss_start = .;
		*(.bss)
		__bss_end = .;
	}
	. = ALIGN(16);
	_end = .;

	/DISCARD/	: {
		*(.note*)
	}

	/*
	 * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
	 */
	. = ASSERT(_end <= 0x8000, "Setup too big!");
	. = ASSERT(hdr == 0x1f1, "The setup header has the wrong offset!");
	/* Necessary for the very-old-loader check to work... */
	. = ASSERT(__end_init <= 5*512, "init sections too big!");

}
