// SPDX-License-Identifier: GPL-2.0
/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

#define __SYSCALL_X32(nr, sym)
#define __SYSCALL_COMMON(nr, sym) __SYSCALL_64(nr, sym)

// 注意这里 的 SYSCALL_64 有两个 define 哟
#define __SYSCALL_64(nr, sym) extern long __x64_##sym(const struct pt_regs *);
// 这里将 syscalls_64.h 里的定义处理成为了函数声明
#include <asm/syscalls_64.h>
#undef __SYSCALL_64

#define __SYSCALL_64(nr, sym) [nr] = __x64_##sym,		// 这些函数的定义 refer to: syscall_wrapper.h。SYSCALL_DEFINEx 宏定义的

asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &__x64_sys_ni_syscall,	// refer to: arch/x86/entry/common.c SYSCALL_DEFINE0(ni_syscall)。这里将所有的东西初始化为 __x64_sys_ni_syscall。后面的 include 有将某些实现了的元素重新赋值了
	// 这里的 include 将 syscalls_64.h 里的定义处理成了 [nr] = __x64_##sym 的函数
#include <asm/syscalls_64.h> // 根据 syscall_64.tbl 生成的  arch/x86/include/generated/asm/syscalls_64.h
};
