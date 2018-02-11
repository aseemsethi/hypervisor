//-------------------------------------------------------------------
//	linuxvmm.c
//
//	This Linux kernel module implements a device-driver (named
//	'/dev/vmm') which lets an application program execute some
//	real-mode code in Virtual-8086 mode within a guest virtual
//	machine, assuming the cpu supports Intel VMX instructions.  
//
//		compile using:  $ mmake linuxvmm
//		install using:  $ /sbin/insmod linuxvmm.ko
//
//	NOTE: Written and tested using Linux x86_64 kernel 2.6.17.
//
//	programmer: ALLAN CRUSE
//	date begun: 29 APR 2007
//	completion: 03 MAY 2007	-- just our initial driver-prototype
//	revised on: 21 JUL 2008 -- for Linux kernel version 2.6.26.
//      programmer: DAVID WEINSTEIN
//      revised on: 13 JUN 2012 -- for Linux kernel version 3.3.4
//-------------------------------------------------------------------

#include <linux/module.h>	// for init_module() 
#include <linux/proc_fs.h>	// for create_proc_read_entry() 
#include <linux/fs.h>		// for struct file_operations 
#include <linux/mm.h>		// for remap_pfn_range()
#include <linux/mutex.h>	// for DEFINE_MUTEX, mutex_trylock, mutex_unlock
#include <asm/io.h>		// for virt_to_phys()
#include <asm/uaccess.h>	// for copy_from_user()
#include "machine.h"		// for our VMCS fields
#include "myvmx.h"		// for 'regs_ia32'
#include <linux/slab.h>		// for kmalloc()
#include <linux/proc_fs.h>	// for create proc entry
#include <linux/seq_file.h>

#define N_ARENAS	11	// number of 64KB memory allocations
#define ARENA_LENGTH  (64<<10)	// size of each allocated memory-arena
#define MSR_VMX_CAPS	0x480	// index for VMX-Capabilities MSRs
#define LEGACY_REACH  0x110000	// end of 'real-addressible' memory

#define PAGE_DIR_OFFSET	0x2000
#define PAGE_TBL_OFFSET	0x3000
#define IDT_KERN_OFFSET	0x4000
#define GDT_KERN_OFFSET	0x4800
#define LDT_KERN_OFFSET	0x4A00
#define TSS_KERN_OFFSET	0x4C00
#define TOS_KERN_OFFSET	0x8000
#define MSR_KERN_OFFSET	0x8000
#define __SELECTOR_TASK	0x0008
#define __SELECTOR_LDTR	0x0010
#define __SELECTOR_CODE	0x0004
#define __SELECTOR_DATA	0x000C
#define __SELECTOR_VRAM	0x0014
#define __SELECTOR_FLAT	0x001C

#define IA32_VMX_BASIC 0x480
#define IA32_VMX_PINBASED_CTLS 0x481
#define IA32_VMX_PROCBASED_CTLS 0x482
#define IA32_VMX_PROCBASED_CTLS2 0x48B


char modname[] = "wiser";
int my_major = 88;
char cpu_oem[16];
int cpu_features;
void *kmem[ N_ARENAS ];
unsigned long msr0x480[ 11 ];
unsigned long cr0, cr4;
unsigned long msr_efer;
unsigned long vmxon_region;
unsigned long guest_region;
unsigned long pgdir_region;
unsigned long pgtbl_region;
unsigned long g_IDT_region;
unsigned long g_GDT_region;
unsigned long g_LDT_region;
unsigned long g_TSS_region;
unsigned long g_TOS_region;
unsigned long h_MSR_region;
void getProcCpuid(void);
void getCrRegs(void);
void getMSR(u32 msr, u32 *low, u32 *hi);
int vmxCheckSupportEPT(void);

DEFINE_MUTEX(my_mutex);

long my_ioctl( struct file *, unsigned int, unsigned long );

int my_mmap( struct file *file, struct vm_area_struct *vma )
{
	unsigned long	user_virtaddr = vma->vm_start;
	unsigned long	region_length = vma->vm_end - vma->vm_start;
	unsigned long	physical_addr, pfn;
	int		i;

	// we require prescribed parameter-values from our client
	if ( user_virtaddr != 0x00000000L ) return -EINVAL;
	if ( region_length != LEGACY_REACH ) return -EINVAL;

	// let the kernel know not to try swapping out this region
	vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);

	// ask the kernel to add page-table entries to 'map' these arenas
	// Maps kernel physical memroy in kmem[] to user_virtaddr (starting at 
	// 0x00000000L) in userspace.
	for (i = 0; i < N_ARENAS+6; i++)
		{
		int	j = i % 16;
		if ( j < 0xA ) physical_addr = virt_to_phys( kmem[ j ] );
		else	physical_addr = user_virtaddr;
		pfn = ( physical_addr >> PAGE_SHIFT );
		if ( remap_pfn_range( vma, user_virtaddr, pfn,
			ARENA_LENGTH, vma->vm_page_prot ) ) return -EAGAIN;
		user_virtaddr += ARENA_LENGTH;
		}
	
	// copy page-frame 0x000 to bottom of arena 0x0 (for IVT and BDA)
	memcpy( kmem[0], phys_to_virt( 0x00000 ), PAGE_SIZE );

	// copy page-frames 0x90 to 0x9F to arena 0x9 (for EBDA)	
	memcpy( kmem[9], phys_to_virt( 0x90000 ), ARENA_LENGTH );	

	return	0;	// SUCCESS
}


struct file_operations	
my_fops =	{
		.owner=			THIS_MODULE,
		.unlocked_ioctl=	my_ioctl,
		.mmap=			my_mmap,
		};


int wiser_show(struct seq_file *m, void *v) {
	int	i;

	seq_printf( m, "\n\t%s\n\n", "VMX-Capability MSRs" );
	for (i = 0; i < 11; i++)
		{
		seq_printf( m, "\tMSR0x%X=", 0x480 + i );
		seq_printf( m, "%016lX \n", msr0x480[i] );
		}
	seq_printf( m, "\n" );
	seq_printf( m, "\n" );

	seq_printf( m, "CR0=%016lX  ", cr0 );
	seq_printf( m, "CR4=%016lX  ", cr4 );
	seq_printf( m, "EFER=%016lX  ", msr_efer );
	seq_printf( m, "\n" );	

	seq_printf( m, "\n\t\t\t" );
	seq_printf( m, "vmxon_region=%016lX \n", vmxon_region );
	seq_printf( m, "\n" );
	seq_printf( m, "guest_region=%016lX \n", guest_region );
	seq_printf( m, "pgdir_region=%016lX \n", pgdir_region );
	seq_printf( m, "pgtbl_region=%016lX \n", pgtbl_region );
	seq_printf( m, "g_IDT_region=%016lX \n", g_IDT_region );
	seq_printf( m, "g_GDT_region=%016lX \n", g_GDT_region );
	seq_printf( m, "g_LDT_region=%016lX \n", g_LDT_region );
	seq_printf( m, "g_TSS_region=%016lX \n", g_TSS_region );
	seq_printf( m, "g_TOS_region=%016lX \n", g_TOS_region );
	seq_printf( m, "h_MSR_region=%016lX \n", h_MSR_region );
	seq_printf( m, "\n" );
	
	return 0;
}

static int wiser_open(struct inode *inode, struct  file *file) {
  return single_open(file, wiser_show, NULL);
}
static const struct file_operations wiserInfo = {
  .owner = THIS_MODULE,
  .open = wiser_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

void set_CR4_vmxe( void *dummy )
{
	asm(	" mov %%cr4, %%rax 	\n"\
		" bts $13, %%rax 	\n"\
		" mov %%rax, %%cr4	" ::: "ax" );
}

void clear_CR4_vmxe( void *dummy )
{
	asm(	" mov %%cr4, %%rax 	\n"\
		" btr $13, %%rax 	\n"\
		" mov %%rax, %%cr4	" ::: "ax" );
}


struct proc_dir_entry *proc_file_entry = NULL;
int init_module( void )
{
	int	i, j;
	u32 low, hi;
        uint32_t vmcs_num_bytes;

        getProcCpuid();
        getCrRegs();
        getMSR(IA32_VMX_BASIC,  &low, &hi);
        vmcs_num_bytes  =  hi & 0xfff; // Bits 44:32
        printk("vmcs_num_bytes = 0x%x\n", vmcs_num_bytes);

	// confirm installation and show device-major number
	printk( "<1>\nInstalling \'%s\' module ", modname );
	printk( "(major=%d) \n", my_major );

	// verify processor supports Intel Virtualization Technology
	asm(	" xor 	%%eax, %%eax		\n"\
		" cpuid				\n"\
		" mov	%%ebx, cpu_oem+0 	\n"\
		" mov	%%edx, cpu_oem+4 	\n"\
		" mov	%%ecx, cpu_oem+8 	\n"\
		::: "ax", "bx", "cx", "dx"	);
	printk( " processor is \'%s\' \n", cpu_oem );

	if ( strncmp( cpu_oem, "GenuineIntel", 12 ) == 0 )
		asm(	" mov	$1, %%eax		\n"\
			" cpuid				\n"\
			" mov	%%ecx, cpu_features	\n"\
			::: "ax", "bx", "cx", "dx" 	);
	if ( ( cpu_features & (1<<5) ) == 0 )
		{
		printk( " Virtualization Technology is unsupported \n" ); 
		return	-ENODEV;
		}
	else	printk( " Virtualization Technology is supported \n" );

	// read contents of the VMX-Capability Model-Specific Registers
	asm(	" xor	%%rbx, %%rbx			\n"\
		" mov	%0, %%rcx			\n"\
		"nxcap:					\n"\
		" rdmsr					\n"\
		" mov	%%eax, msr0x480+0(, %%rbx, 8)	\n"\
		" mov	%%edx, msr0x480+4(, %%rbx, 8)	\n"\
		" inc	%%rcx				\n"\
		" inc	%%rbx				\n"\
		" cmp	$11, %%rbx			\n"\
		" jb	nxcap				\n"\
		:: "i" (MSR_VMX_CAPS) : "ax", "bx", "cx", "dx" 	);

	// preserve the initial values in relevant system registers
	asm( " mov %%cr0, %%rax \n mov %%rax, cr0 " ::: "ax" );
	asm( " mov %%cr4, %%rax \n mov %%rax, cr4 " ::: "ax" );

	asm(	" mov	%0, %%ecx		\n"\
		" rdmsr				\n"\
		" mov	%%eax, msr_efer+0	\n"\
		" mov	%%edx, msr_efer+4	\n"\
		:: "i" (MSR_EFER) : "ax", "cx", "dx" );

	// allocate page-aligned blocks of non-pageable kernel memory
	for (i = 0; i < N_ARENAS; i++)
		{
		kmem[ i ] = kmalloc( ARENA_LENGTH, GFP_KERNEL );
		if ( kmem[ i ] == NULL )
			{
			for (j = 0; j < i; j++) kfree( kmem[ j ] );
			return	-ENOMEM;
			}
		else	memset( kmem[ i ], 0x00, ARENA_LENGTH );
		}

	// assign usages to allocated kernel memory areas
	vmxon_region = virt_to_phys( kmem[ 10 ] + 0x0000 );
	guest_region = virt_to_phys( kmem[ 10 ] + 0x1000 );
	pgdir_region = virt_to_phys( kmem[ 10 ] + PAGE_DIR_OFFSET );
	pgtbl_region = virt_to_phys( kmem[ 10 ] + PAGE_TBL_OFFSET );
	g_IDT_region = virt_to_phys( kmem[ 10 ] + IDT_KERN_OFFSET );
	g_GDT_region = virt_to_phys( kmem[ 10 ] + GDT_KERN_OFFSET );
	g_LDT_region = virt_to_phys( kmem[ 10 ] + LDT_KERN_OFFSET );
	g_TSS_region = virt_to_phys( kmem[ 10 ] + TSS_KERN_OFFSET );
	g_TOS_region = virt_to_phys( kmem[ 10 ] + TOS_KERN_OFFSET );
	h_MSR_region = virt_to_phys( kmem[ 10 ] + MSR_KERN_OFFSET );

	// enable virtual machine extensions (bit 13 in CR4)
	set_CR4_vmxe( NULL );	
	smp_call_function( set_CR4_vmxe, NULL, 1);

	//create_proc_read_entry( modname, 0, NULL, my_info, NULL );
	proc_file_entry = proc_create(modname, 0, NULL, &wiserInfo);
	if(proc_file_entry == NULL) {
		printk("Could not create proc entry\n");
		return 0;
	}
	return	register_chrdev( my_major, modname, &my_fops );
}


void cleanup_module( void )
{
	int	i;

	smp_call_function( clear_CR4_vmxe, NULL, 1);
	clear_CR4_vmxe( NULL );

	unregister_chrdev( my_major, modname );
	if(proc_file_entry != NULL)
		remove_proc_entry(modname, NULL);
	for (i = 0; i < N_ARENAS; i++) kfree( kmem[ i ] );

	printk( "<1>Removing \'%s\' module\n", modname );
}

MODULE_LICENSE("GPL"); 

unsigned short	_gdtr[ 5 ], _idtr[ 5 ];
unsigned int	_eax, _ebx, _ecx, _edx, _esp, _ebp, _esi, _edi;
int		retval = -1;

regs_ia32	vm;

long my_ioctl( struct file *file, unsigned int count, unsigned long buf )
{
	unsigned long	*gdt, *ldt, *idt;
	unsigned int	*pgtbl, *pgdir, *tss, phys_addr = 0;
	signed long	desc = 0;
	int		i, j;
	int ret;	
		
	// this is now called in an unlocked ioctl context
	// is there are lock we should be grabbing at this point?
	// -DW
	ret = mutex_trylock( &my_mutex );
	if (ret == 0) {
		return -ERESTARTSYS;
	}
	
	// sanity check: we require the client-process to pass an
	// exact amount of data representing CPU's register-state
	if ( count != sizeof( regs_ia32 ) ) { 
		mutex_unlock(&my_mutex);
		return -EINVAL;
	}

	// reinitialize the Virtual Machine Control Stuctures
	memset( phys_to_virt( vmxon_region ), 0x00, PAGE_SIZE );
	memset( phys_to_virt( guest_region ), 0x00, PAGE_SIZE );
	memcpy( phys_to_virt( vmxon_region ), msr0x480, 4 );
	memcpy( phys_to_virt( guest_region ), msr0x480, 4 );

	// initialize our guest-task's page-table and page-directory
    // Set the page tables up as follows
    // for index [0] - [9], pick up phys address as kmem[i]
    // Now, since each kmem[i] is 64 Kbyte, it can have 16 Pages
    // So, 16 * (i=10) = 160 PTEs map out the complete 64K of kmem
    // memory, we have allcoated.
    // Now, pick up 6 more, and add PTEs for the next [10] to [15]
    // i.e. 6 * 16 PTEs = 96 PTE entries
    // Finally, set 16 PTEs from 16*16 (256 to 271) to kmem[0], and 
    // 17*16(272) to 287 to kmem[10]
    // So, a total of 287 PTEs
    // These are Interrupt Vector Table and Extended BIOS areas
    // Now, set pgdir to physical address of pgdir_region and set its
    // first member to physical address of pgtbl_region above
    // Note that "7" is added to all entries to set the Present/Rd&Wr/User bit
    // for all entries
	pgtbl = (unsigned int*)phys_to_virt( pgtbl_region );
	for (i = 0; i < 18; i++)
		{
		switch ( i )
			{
			case 0: case 1: case 2: case 3: case 4:
			case 5: case 6: case 7: case 8: case 9:
			phys_addr = virt_to_phys( kmem[ i ] ); break;
			case 10: case 11: case 12: case 13: case 14: case 15:
			phys_addr = i * ARENA_LENGTH; break;
			case 16: 
			phys_addr = virt_to_phys( kmem[ 0 ] ); break;
			case 17:
			phys_addr = virt_to_phys( kmem[ 10 ] ); break;
			}
		for (j = 0; j < 16; j++)
			pgtbl[ i*16 + j ] = phys_addr + (j << PAGE_SHIFT) + 7;
		}
	pgdir = (unsigned int*)phys_to_virt( pgdir_region );
	pgdir[ 0 ] = (unsigned int)pgtbl_region + 7;

	// copy the client's virtual-machine register-values
	if ( copy_from_user( &vm, (void*)buf, count ) ) {
		mutex_unlock(&my_mutex);
		return -EFAULT;
	}
    // Copy in the guest register values
    // 24.11.2 VMREAD, VMWRITE, and Encodings of VMCS Fields
	guest_ES_selector = vm.es;
	guest_CS_selector = vm.cs;
	guest_SS_selector = vm.ss;
	guest_DS_selector = vm.ds;
	guest_FS_selector = vm.fs;
	guest_GS_selector = vm.gs;
	_eax = vm.eax;
	_ebx = vm.ebx;
	_ecx = vm.ecx;
	_edx = vm.edx;
	_ebp = vm.ebp;
	_esi = vm.esi;
	_edi = vm.edi;
	guest_RSP = vm.esp;
	guest_RIP = vm.eip;
	guest_RFLAGS = vm.eflags;
	guest_RFLAGS |= (1 << 17);	// VM=1 (for Virtual-8086 mode)
	guest_RFLAGS |= (1 <<  1);	// it's essential to set bit #1

	// setup other guest-state fields (for Virtual-8086 mode)
	// The segment address is added to a 16-bit offset in the instruction
	// to yield a linear address, which is the same as physical address
	// in this mode. That is the reason, the selector is left shifted to
	// get the base address, that is added to the instruction.
	// 24.4 GUEST-STATE AREA and 27.3 SAVING GUEST STATE - Intel Arch
	guest_ES_base = (guest_ES_selector << 4);
	guest_CS_base = (guest_CS_selector << 4);
	guest_SS_base = (guest_SS_selector << 4);
	guest_DS_base = (guest_DS_selector << 4);
	guest_FS_base = (guest_FS_selector << 4);
	guest_GS_base = (guest_GS_selector << 4);
	guest_ES_limit = 0xFFFF;
	guest_CS_limit = 0xFFFF;
	guest_SS_limit = 0xFFFF;
	guest_DS_limit = 0xFFFF;
	guest_FS_limit = 0xFFFF;
	guest_GS_limit = 0xFFFF;
	guest_ES_access_rights = 0xF3;
	guest_CS_access_rights = 0xF3;
	guest_SS_access_rights = 0xF3;
	guest_DS_access_rights = 0xF3;
	guest_FS_access_rights = 0xF3;
	guest_GS_access_rights = 0xF3;

    // CR0:
    // 0    PE  Protected Mode Enable
    // 4    ET  Extension type
    // 5    NE  Numeric error
    // 31   PG  Paging
	guest_CR0 = 0x80000031;
    // CR4: 
    // 0    VME Virtual 8086 Mode Extensions
    // 4    PSE Page Size Extension - page size is increased to 4 MiB
    // 13   VMXE    Virtual Machine Extensions Enable
	guest_CR4 = 0x00002011;
	guest_CR3 = pgdir_region;
	guest_VMCS_link_pointer_full = 0xFFFFFFFF;
	guest_VMCS_link_pointer_high = 0xFFFFFFFF;

	guest_IDTR_base = LEGACY_REACH + IDT_KERN_OFFSET;
	guest_GDTR_base = LEGACY_REACH + GDT_KERN_OFFSET;
	guest_LDTR_base = LEGACY_REACH + LDT_KERN_OFFSET;
	guest_TR_base   = LEGACY_REACH + TSS_KERN_OFFSET;
	guest_IDTR_limit = (256 * 8) - 1;
	guest_GDTR_limit = (3 * 8) - 1;
	guest_LDTR_limit = (4 * 8) - 1;
	guest_TR_limit   = (26 * 4) + 0x20 + 0x2000;
	guest_LDTR_access_rights = 0x82;
	guest_TR_access_rights   = 0x8B;
	guest_LDTR_selector = __SELECTOR_LDTR;
	guest_TR_selector   = __SELECTOR_TASK;

	// provisionally initialize our guest-task's LDTR
	ldt = (unsigned long*)phys_to_virt( g_LDT_region );
	ldt[ __SELECTOR_CODE >> 3 ] = 0x00CF9B000000FFFF;
	ldt[ __SELECTOR_DATA >> 3 ] = 0x00CF93000000FFFF;
	ldt[ __SELECTOR_VRAM >> 3 ] = 0x0000920B8000FFFF;
	ldt[ __SELECTOR_FLAT >> 3 ] = 0x008F92000000FFFF;
	// Adjust the CODE and DATA descriptors here
	desc = ( LEGACY_REACH << 16 )&0x000000FFFFFF0000;
	ldt[ __SELECTOR_CODE >> 3 ] |= desc;
	ldt[ __SELECTOR_DATA >> 3 ] |= desc;

	// initialize our guest-task's GDTR
	gdt = (unsigned long*)phys_to_virt( g_GDT_region );
	desc = 0x00008B0000000000;
	desc |= (guest_TR_base << 32)&0xFF00000000000000;
	desc |= (guest_TR_base << 16)&0x000000FFFFFF0000;
	desc |= (guest_TR_limit & 0xFFFF);
	gdt[ __SELECTOR_TASK >> 3 ] = desc;
	desc = 0x0000820000000000;
	desc |= ( guest_LDTR_base << 32)&0xFF00000000000000;
	desc |= ( guest_LDTR_base << 16)&0x000000FFFFFF0000;
	desc |= ( guest_LDTR_limit & 0xFFFF );
	gdt[ __SELECTOR_LDTR >> 3 ] = desc;

	// TODO: initialize our guest's IDT
	idt = (unsigned long*)phys_to_virt( g_IDT_region );
	desc = 0x00010000;	// load-address of isr <---- ???
	desc &= 0x00000000FFFFFFFF;
	desc |= (desc << 32);
	desc &= 0xFFFF00000000FFFF;
	desc |= ( __SELECTOR_CODE << 16);
	desc |= 0x00008E0000000000;
	idt[ 13 ] = desc;

	// initialize our guest's Task-State Segment
	tss = (unsigned int*)phys_to_virt( g_TSS_region );
	tss[ 1 ] = TOS_KERN_OFFSET;
	tss[ 2 ] = __SELECTOR_DATA;
	tss[ 25 ] = 0x00880000;
	tss[ guest_TR_limit >> 2 ] = 0xFF;

	//----------------------------------------------------
	// initialize the global variables for the host state
	//----------------------------------------------------
	asm(" mov %%cr0, %%rax \n mov %%rax, host_CR0 " ::: "ax" );
	asm(" mov %%cr4, %%rax \n mov %%rax, host_CR4 " ::: "ax" );
	asm(" mov %%cr3, %%rax \n mov %%rax, host_CR3 " ::: "ax" );
	asm(" str host_TR_selector ");
	asm(" mov %es, host_ES_selector ");	
	asm(" mov %cs, host_CS_selector ");	
	asm(" mov %ss, host_SS_selector ");	
	asm(" mov %ds, host_DS_selector ");	
	asm(" mov %fs, host_FS_selector ");	
	asm(" mov %gs, host_GS_selector ");	
	asm(" sgdt _gdtr \n sidt _idtr ");
	host_GDTR_base = *(unsigned long*)( _gdtr+1 );
	host_IDTR_base = *(unsigned long*)( _idtr+1 );
	
	gdt = (unsigned long*)host_GDTR_base;
	desc = gdt[ (host_TR_selector >> 3) + 0 ];
	host_TR_base = ((desc >> 16)&0x00FFFFFF)|((desc >> 32)&0xFF000000);
	desc = gdt[ (host_TR_selector >> 3) + 1 ];
	desc <<= 48;	// maneuver to insure 'canonical' address
	host_TR_base |= (desc >> 16)&0xFFFFFFFF00000000;

	asm(	" mov	$0x174, %%ecx			\n"\
		" rdmsr					\n"\
		" mov	%%eax, host_SYSENTER_CS		\n"\
		" inc	%%ecx				\n"\
		" rdmsr					\n"\
		" mov	%%eax, host_SYSENTER_ESP+0 	\n"\
		" mov	%%edx, host_SYSENTER_ESP+4 	\n"\
		" inc	%%ecx				\n"\
		" rdmsr					\n"\
		" mov	%%eax, host_SYSENTER_EIP+0	\n"\
		" mov	%%edx, host_SYSENTER_EIP+4 	\n"\
		::: "ax", "cx", "dx" );

	asm(	" mov	%0, %%ecx		\n"\
		" rdmsr				\n"\
		" mov	%%eax, host_FS_base+0 	\n"\
		" mov	%%edx, host_FS_base+4	\n"\
		:: "i" (0xC0000100) : "ax", "cx", "dx" );

	asm(	" mov	%0, %%ecx		\n"\
		" rdmsr				\n"\
		" mov	%%eax, host_GS_base+0 	\n"\
		" mov	%%edx, host_GS_base+4	\n"\
		:: "i" (0xC0000101) : "ax", "cx", "dx" );

	//------------------------------------------------------
	// initialize the global variables for the VMX controls
	//------------------------------------------------------
	control_VMX_pin_based = msr0x480[ 1 ];
	// control_VMX_pin_based |= (1 << 0);	// exit on interrupts	
	control_VMX_cpu_based = msr0x480[ 2 ];
	control_pagefault_errorcode_match = 0xFFFFFFFF;
	control_VM_exit_controls = msr0x480[ 3 ];
	control_VM_exit_controls |= (1 << 9);	// exit to 64-bit host
	control_VM_entry_controls = msr0x480[ 4 ];
	control_CR0_mask = 0x80000021;
	control_CR4_mask = 0x00002000;
	control_CR0_shadow = 0x80000021;
	control_CR4_shadow = 0x00002000;
	control_CR3_target_count = 2;
	control_CR3_target0 = guest_CR3;	// guest's directory
	control_CR3_target1 = host_CR3;		// host's directory

	//---------------------
	// launch the guest VM 
	//---------------------
	// lea instruction below, loads the my_vmm pointer into RAX, which
	// is then copied into host RIP
	// There are two flags used to signify the success or failure of a VM 
	// instruction. The carry flag(CF) and the zero flag(ZF).
	// If both of these flags are clear after a VM instruction was executed 
	// then it succeeded.  
	//
	// If carry flag is set then current VMCS pointer //is invalid.
	// If the zero flag is set, it indicates that the VMCS pointer is valid 
	// but there is some other error specified in the VM-instruction error 
	// field (encoding 4400h) - info_vminstr_error
	//
	// retval - is the return value, and is set various numbers to indicate
	// the progress in case something fails

	asm volatile ("	.type  my_vmm, @function	\n"\
		" pushfq				\n"\
		" push	%rax				\n"\
		" push	%rbx				\n"\
		" push	%rcx				\n"\
		" push	%rdx				\n"\
		" push	%rbp				\n"\
		" push	%rsi				\n"\
		" push	%rdi				\n"\
		" push	%r11				\n"\
		" lea	my_vmm, %rax			\n"\
		" mov	%rax, host_RIP			\n"\
		" mov	%rsp, host_RSP			\n"\
		" vmxon	vmxon_region			\n"\
		" jc	fail				\n"\
		" jz	over				\n"\
		" movl	$1, retval			\n"\
		" vmclear guest_region			\n"\
		" movl	$2, retval			\n"\
		" vmptrld guest_region			\n"\
		" movl	$3, retval			\n"\
		"					\n"\
		" xor	%rdx, %rdx			\n"\
		" mov	elements, %rcx			\n"\
		"nxwr:					\n"\
		" mov	machine+0(%rdx), %rax		\n"\
		" mov	machine+8(%rdx), %rbx		\n"\
		" vmwrite (%rbx), %rax			\n"\
		" add	$16, %rdx			\n"\
		" loop	nxwr				\n"\
		"					\n"\
		" movl 	$4, retval			\n"\
		" mov	_eax, %eax			\n"\
		" mov	_ebx, %ebx			\n"\
		" mov	_ecx, %ecx			\n"\
		" mov	_edx, %edx			\n"\
		" mov	_ebp, %ebp			\n"\
		" mov	_esi, %esi			\n"\
		" mov	_edi, %edi			\n"\
		"  vmlaunch				\n"\
		" movl 	$5, retval			\n"\
		" jmp	read				\n"\
		"my_vmm:				\n"\
		"					\n"\
		" mov	%eax, _eax			\n"\
		" mov	%ebx, _ebx			\n"\
		" mov	%ecx, _ecx			\n"\
		" mov	%edx, _edx			\n"\
		" mov	%ebp, _ebp			\n"\
		" mov	%esi, _esi			\n"\
		" mov	%edi, _edi			\n"\
		"read:					\n"\
		" xor	%rdx, %rdx			\n"\
		" mov	rocount, %rcx			\n"\
		"nxrd:					\n"\
		" mov	results+0(%rdx), %rax		\n"\
		" mov	results+8(%rdx), %rbx		\n"\
		" vmread %rax, (%rbx)			\n"\
		" add	$16, %rdx			\n"\
		" loop	nxrd				\n"\
		"					\n"\
		" movl  $0, retval			\n"\
		"over:					\n"\
		" vmxoff				\n"\
		"fail:					\n"\
		" pop	%r11				\n"\
		" pop	%rdi				\n"\
		" pop	%rsi				\n"\
		" pop	%rbp				\n"\
		" pop	%rdx				\n"\
		" pop	%rcx				\n"\
		" pop	%rbx				\n"\
		" pop	%rax				\n"\
		" popfq					\n"\
		);

// show why the VMentry failed, or else why the VMexit occurred	
printk( "\n VM-instruction error: %08X ", info_vminstr_error );
printk( " Exit Reason: %08X \n", info_vmexit_reason );
printk( " VMexit-interruption-information: %08X \n",
			info_vmexit_interrupt_information );
printk( " VMexit-interruption-error-code:  %08X \n",
			info_vmexit_interrupt_error_code  );

	// copy the client's virtual-machine register-values
	vm.eflags = (unsigned int)guest_RFLAGS;
	vm.eip = (unsigned int)guest_RIP;	
	vm.esp = (unsigned int)guest_RSP;	
	vm.eax = _eax;
	vm.ebx = _ebx;
	vm.ecx = _ecx;
	vm.edx = _edx;
	vm.ebp = _ebp;
	vm.esi = _esi;
	vm.edi = _edi;
	vm.es  = guest_ES_selector;
	vm.cs  = guest_CS_selector;
	vm.ss  = guest_SS_selector;
	vm.ds  = guest_DS_selector;
	vm.fs  = guest_FS_selector;
	vm.gs  = guest_GS_selector;
	if ( copy_to_user( (void*)buf, &vm, count ) ) {
		mutex_unlock(&my_mutex);
		return -EFAULT;
	}
	
	mutex_unlock(&my_mutex);
	return	retval;
}

//------------------------------
/*
 * home computer: Model 7, Extended Model 1
 * Intel Core 2 Extreme processor, Intel Xeon, model 17h
 */

void getCpuid (unsigned int *eax, unsigned int *ebx,
		 unsigned int *ecx, unsigned int *edx) {
	// ecx is input and output
	asm volatile("cpuid"
		: "=a" (*eax), // outputs
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));  // inputs - 0th index 
}

/* 
 * https://en.wikipedia.org/wiki/CPUID
 * The format of the information in EAX is as follows:
 * 3:0 – Stepping
 * 7:4 – Model
 * 11:8 – Family
 * Processor Type: 00: Original OEM, 01: OneDrive, 10: Dual proc, 11: Intel resvd 
 * 13:12 – Processor Type
 * 19:16 – Extended Model
 * 27:20 – Extended Family
 */
void getProcCpuid(void) {
	unsigned eax, ebx, ecx, edx;

	ecx = 0x0;
	eax = 1; // proc info
	getCpuid(&eax, &ebx, &ecx, &edx);
	printk("Stepping %d\n", eax & 0xF);
	printk("Model %d\n", (eax >> 4) & 0xF);
	printk("Family %d\n", (eax >> 12) & 0xF);
	printk("Processor Type %d\n", (eax >> 12) & 0x3);
	printk("Extended Model %d\n", (eax >> 16) & 0xF);
	printk("Extended Family %d\n", (eax >> 20) & 0xFF);

	eax = 3; // serial number
	getCpuid(&eax, &ebx, &ecx, &edx);
	printk("Serial Number 0x%08x%08x\n", edx, ecx);
}
void setCr4Vmxe(void *dummy) {
	asm( "mov %%cr4, %%rax	\n"\
		 "bts $13, %%rax	\n"\
		 "mov %%rax, %%cr4	\n"\
		:::"ax");
}

void clearCr4Vmxe(void *dummy) {
	asm( "mov %%cr4, %%rax	\n"\
		 "btr $13, %%rax	\n"\
		 "mov %%rax, %%cr4	\n"\
		:::"ax");
}
#define CHKBIT(val, x) ((val>>x) & 0x1)

/*
 * en.wikipedia.org/wiki/CPUID
 * EAX=1: Processor Info and Feature Bits
 * Check bit5 of ECX for VMX support
 */
int vmxCheckSupport(int cmd) {
	unsigned eax, ebx, ecx, edx;

	ecx = 0x0;
	eax = cmd; // proc info
	getCpuid(&eax, &ebx, &ecx, &edx);
	if (CHKBIT(ecx, 5) == 1)
		return 1;
	else
		return 0;

}

/*
 * processor is in 32 bit mode here
 */
void writeCr0(unsigned long val) {
         asm volatile(
			"mov %0, %%cr0"
		: 
		:"r" (val)
		);
}

/*
 * READ MSRs// 30:00 VMCS revision id
 *  31:31 shadow VMCS indicator
 *  -----------------------------
 *  32:47 VMCS region size, 0 <= size <= 4096
 *  48:48 use 32-bit physical address, set when x86_64 disabled
 *  49:49 support of dual-monitor treatment of SMI and SMM
 *  53:50 memory type used for VMCS access
 *  54:54 logical processor reports information in the VM-exit 
 *        instruction-information field on VM exits due to
 *        execution of INS/OUTS
 *  55:55 set if any VMX controls that default to `1 may be
 *        cleared to `0, also indicates that IA32_VMX_TRUE_PINBASED_CTLS,
 *        IA32_VMX_TRUE_PROCBASED_CTLS, IA32_VMX_TRUE_EXIT_CTLS and
 *        IA32_VMX_TRUE_ENTRY_CTLS MSRs are supported.
 *  56:63 reserved, must be zero
 */
void getMSR(u32 msr, u32 *low, u32 *hi) {
	asm volatile("rdmsr" : "=a"(*low), "=d"(*hi) : "c"(msr));
	printk("getMSR: msr=0x%x, hi=%x lo=%x\n", msr, *hi, *low);
}

int vmxCheckSupportEPT() {
	u32 low, hi;
	getMSR(IA32_VMX_PROCBASED_CTLS, &low, &hi);
	printk("MSR IA32_VMX_PROCBASED_CTLS: hi: %x, low: %x\n", hi, low);
	if (CHKBIT(hi, 31) == 1) { // 63rd bit should be 1
		getMSR(IA32_VMX_PROCBASED_CTLS2, &low, &hi);
		if (CHKBIT(hi, 2) == 1) // 33rd bit should be 1
			return 1;
	}
	return 0;
}

void getCrRegs(void) {
#ifdef __x86_64__
	u64 cr0, cr2, cr3;
	printk("x86_64 mode\n");
	asm volatile (
		"mov %%cr0, %%rax\n\t"
		"mov %%eax, %0\n\t"
		"mov %%cr2, %%rax\n\t"
		"mov %%eax, %1\n\t"
		"mov %%cr4, %%rax\n\t"
		"mov %%eax, %2\n\t"
	:	"=m" (cr0), "=m" (cr2), "=m" (cr3)
	:	/* no input */
	:	"%rax"
	);
#elif defined(__i386__)
	printk("x86 i386 mode\n");
	u32 cr0, cr2, cr3;
	printk("x86_64 mode\n");
	asm volatile (
		"mov %%cr0, %%eax\n\t"
		"mov %%eax, %0\n\t"
		"mov %%cr2, %%eax\n\t"
		"mov %%eax, %1\n\t"
		"mov %%cr4, %%eax\n\t"
		"mov %%eax, %2\n\t"
	:	"=m" (cr0), "=m" (cr2), "=m" (cr3)
	:	/* no input */
	:	"%eax"
	);
#endif
	printk("cr0 = 0x%llx\n", cr0);
	printk("cr2 = 0x%llx\n", cr2);
	printk("cr3 = 0x%llx\n", cr3);
}
