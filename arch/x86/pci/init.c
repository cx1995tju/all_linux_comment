// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/init.h>
#include <asm/pci_x86.h>
#include <asm/x86_init.h>
#include <asm/irqdomain.h>

/* arch_initcall has too random ordering, so call the initializers
   in the right sequence from here. */
//x86 系统执行的第一个与PCI总线初始化相关的函数
static __init int pci_arch_init(void)
{
	int type;

	x86_create_pci_msi_domain(); //针对x86 的pci 创建的irq domain, refer to: %x86_pci_msi_default_domain 

	type = pci_direct_probe(); //主要是判断使用那种方式访问PCI配置空间

	if (!(pci_probe & PCI_PROBE_NOEARLY)) //pci_probe 来自于内核启动参数pci=xxx
		pci_mmcfg_early_init();

	if (x86_init.pci.arch_init && !x86_init.pci.arch_init()) //pci_numachip_init()???
		return 0;

	pci_pcbios_init(); //没用，linux不用bios的结果

	/*
	 * don't check for raw_pci_ops here because we want pcbios as last
	 * fallback, yet it's needed to run first to set pcibios_last_bus
	 * in case legacy PCI probing is used. otherwise detecting peer busses
	 * fails.
	 */
	pci_direct_init(type);

	if (!raw_pci_ops && !raw_pci_ext_ops)
		printk(KERN_ERR
		"PCI: Fatal: No config space access function found\n");

	dmi_check_pciprobe();

	dmi_check_skip_isa_align();

	return 0;
}
arch_initcall(pci_arch_init);
