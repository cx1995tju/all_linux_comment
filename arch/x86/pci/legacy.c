// SPDX-License-Identifier: GPL-2.0-only
/*
 * legacy.c - traditional, old school PCI bus probing
 */
#include <linux/init.h>
#include <linux/export.h>
#include <linux/pci.h>
#include <asm/jailhouse_para.h>
#include <asm/pci_x86.h>

/*
 * Discover remaining PCI buses in case there are peer host bridges.
 * We use the number of last PCI bus provided by the PCI BIOS.
 */
static void pcibios_fixup_peer_bridges(void)
{
	int n;

	if (pcibios_last_bus <= 0 || pcibios_last_bus > 0xff)
		return;
	DBG("PCI: Peer bridge fixup\n");

	for (n=0; n <= pcibios_last_bus; n++)
		pcibios_scan_specific_bus(n);
}

//完成对PCI总线的美剧，并在proc sysfs中建立相关结构
int __init pci_legacy_init(void)
{
	if (!raw_pci_ops)
		return 1;

	pr_info("PCI: Probing PCI hardware\n");
	pcibios_scan_root(0);
	return 0;
}

void pcibios_scan_specific_bus(int busn)
{
	int stride = jailhouse_paravirt() ? 1 : 8;
	int devfn;
	u32 l;

	if (pci_find_bus(0, busn))
		return;

	for (devfn = 0; devfn < 256; devfn += stride) {
		if (!raw_pci_read(0, busn, devfn, PCI_VENDOR_ID, 2, &l) &&
		    l != 0x0000 && l != 0xffff) {
			DBG("Found device at %02x:%02x [%04x]\n", busn, devfn, l);
			pr_info("PCI: Discovered peer bus %02x\n", busn);
			pcibios_scan_root(busn);
			return;
		}
	}
}
EXPORT_SYMBOL_GPL(pcibios_scan_specific_bus);

static int __init pci_subsys_init(void)
{
	/*
	 * The init function returns an non zero value when
	 * pci_legacy_init should be invoked.
	 */
	if (x86_init.pci.init()) { //refer to: `x86_init.c: struct x86_init_ops x86_init __initdata` / pci_acpi_init
		//引入了ACPI机制之后，这里一般不会进入了
		if (pci_legacy_init()) { 
			pr_info("PCI: System does not support PCI\n");
			return -ENODEV;
		}
	}

	pcibios_fixup_peer_bridges();
	x86_init.pci.init_irq(); //这里使用ACPI提供的中断路由表，来初始化中断(现在不会使用ACPI提供的中断路由表了)
	pcibios_init();

	return 0;
}
subsys_initcall(pci_subsys_init);
