/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGE_64_H
#define _ASM_X86_PAGE_64_H

#include <asm/page_64_types.h>

#ifndef __ASSEMBLY__
#include <asm/alternative.h>

/* duplicated to the one in bootmem.h */
extern unsigned long max_pfn;
extern unsigned long phys_base; // refer to: arch/x86/kernel/head_64.S: 这个是kernel 真正加载的物理地址，因为可能有 kaslr 的

extern unsigned long page_offset_base;  // 这个是最终的page_offset，会根据各种配置基于 __PAGE_OFFSET_BASE_L[4|5]  做修正的。譬如：KASLR 就会影响的
extern unsigned long vmalloc_base;
extern unsigned long vmemmap_base;

//内核虚拟地址转物理地址, x是作为输入的物理地址
static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	// x 减掉 kernel 代码段的起始地址
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */

	// 如果 x > __START_KERNEL_map ===> x > x - __START_KERNEL_map ===> x > y
	// x == __START_KERNEL_map ===> x > y ====> x > 0
	// 如果 x < __START_KERNEL_map，那么 y = x - __START_KERNEL_map = -(__START_KERNEL_map - x) = 2^64 - (__START_KERNEL_map - x) = 2^64 - __START_KERNEL_map + x > x
	// 故
	// x < __START_KERNEL_map <=> y > x <=> x > y is false		// false 说明不再 kernel _text 部分，所以用 direct map 来计算物理地址
	// x > __START_KERNEL_map <=> x > y <=> x > y is true		// true 说明地址是在 kernel _text 部分的, 用 kernel 的 text map 来计算物理地址
	// x = __START_KERNEL_map <=> y = 0 <=> x > y is true
	//
	// 故:
	// x > y is true <=> x >= __START_KERNEL_map		// [KERNEL text 部分] 此时 x = x - __START_KERNEL_map + phys_base, 这部分是在获取kernel 代码段的物理地址, phys_base 应该是kernel加载的起始地址。一般是0，可能被修正, refer to: arch/x86/kernel/head_64.S
	// x > y is false <=> x < __START_KERNEL_map		// [direct map 部分] 此时 x = y + __START_KERNEL_map - PAGE_OFFSET = x - PAGE_OFFSET = x - page_offset_base
	// refer to: 0bdf525f04afd3a32c14e5a8778771f9c9e0f074 。这种写法更加 流水线友好
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}

#ifdef CONFIG_DEBUG_VIRTUAL
extern unsigned long __phys_addr(unsigned long);
extern unsigned long __phys_addr_symbol(unsigned long);
#else
#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_symbol(x) \
	((unsigned long)(x) - __START_KERNEL_map + phys_base)	// x - __START_KERNEL_map 得到 x 在 kernel 中的offset。然后加上 phys_base 就得到其对应的物理地址。 phys_base arch/x86/kernel/head_64.S  phys_base 也保存了 代码段的起始物理地址
#endif

#define __phys_reloc_hide(x)	(x)

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)          ((pfn) < max_pfn)
#endif

void clear_page_orig(void *page);
void clear_page_rep(void *page);
void clear_page_erms(void *page);

static inline void clear_page(void *page)
{
	alternative_call_2(clear_page_orig,
			   clear_page_rep, X86_FEATURE_REP_GOOD,
			   clear_page_erms, X86_FEATURE_ERMS,
			   "=D" (page),
			   "0" (page)
			   : "cc", "memory", "rax", "rcx");
}

void copy_page(void *to, void *from);

#endif	/* !__ASSEMBLY__ */

#ifdef CONFIG_X86_VSYSCALL_EMULATION
# define __HAVE_ARCH_GATE_AREA 1
#endif

#endif /* _ASM_X86_PAGE_64_H */
