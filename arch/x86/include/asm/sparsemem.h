/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SPARSEMEM_H
#define _ASM_X86_SPARSEMEM_H

#ifdef CONFIG_SPARSEMEM
/*
 * generic non-linear memory support:
 *
 * 1) we will not split memory into more chunks than will fit into the flags
 *    field of the struct page
 *
 * SECTION_SIZE_BITS		2^n: size of each section
 * MAX_PHYSMEM_BITS		2^n: max size of physical address space
 *
 */

#ifdef CONFIG_X86_32
# ifdef CONFIG_X86_PAE
#  define SECTION_SIZE_BITS	29
#  define MAX_PHYSMEM_BITS	36
# else
#  define SECTION_SIZE_BITS	26
#  define MAX_PHYSMEM_BITS	32
# endif
#else /* CONFIG_X86_32 */
# define SECTION_SIZE_BITS	27 /* matt - 128 is convenient right now */	// 定义了一个 section 最多代表多少的物理内存空间，2^27
# define MAX_PHYSMEM_BITS	(pgtable_l5_enabled() ? 52 : 46)	// 那么一共有 2^(MAX_PHYSMEM_BITS - SECTION_SIZE_BITS) 个 section
// 换句话说，一个物理地址，低 27位 是 section 内部的索引, 接下来的 52 - 27 位是用来索引 section 的
#endif

#endif /* CONFIG_SPARSEMEM */

#ifndef __ASSEMBLY__
#ifdef CONFIG_NUMA_KEEP_MEMINFO
extern int phys_to_target_node(phys_addr_t start);
#define phys_to_target_node phys_to_target_node
extern int memory_add_physaddr_to_nid(u64 start);
#define memory_add_physaddr_to_nid memory_add_physaddr_to_nid
#endif
#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_SPARSEMEM_H */
