//-------------------------------------------------------------------
//	trydelay.cpp
//
//	This program relies on services of our 'nmiexits.c' kernel
//	module to execute a 'real-mode' procedure inside a virtual 
//	machine that is running in Virtual-8086 emulation mode (as
//	a guest-process managed by a Linux x86_64 host-process).
//
//		to compile:  $ g++ trydelay.cpp -o trydelay
//		to prepare:  $ /sbin/insmod nmiexits.ko
//		to execute:  $ ./trydelay
//		to restore:  $ /sbin/rmmod nmiexits
//
//	programmer: ALLAN CRUSE
//	written on: 06 APR 2007
//	revised on: 14 MAY 2007
//	correction: 25 MAY 2007 -- fixed compile/install directions
//-------------------------------------------------------------------

#include <stdio.h>	// for printf(), perror() 
#include <fcntl.h>	// for open() 
#include <stdlib.h>	// for exit() 
#include <unistd.h>	// for read(), write(), close()
#include <string.h>	// for memcpy()
#include <sys/mman.h>	// for mmap()
#include <sys/ioctl.h>	// for ioctl()
#include "myvmx.h"	// for 'regs_ia32' 

regs_ia32	vm;
char devname[] = "/dev/nmiexits";

int main( int argc, char **argv )
{
	// open the virtual-machine device-file
	int	fd = open( devname, O_RDWR );
	if ( fd < 0 ) { perror( devname ); exit(1); }

	// map in the legacy 8086 memory-area
	int	size = 0x110000;
	int	prot = PROT_READ | PROT_WRITE;
	int	flag = MAP_FIXED | MAP_SHARED;
	if ( mmap( (void*)0, size, prot, flag, fd, 0 ) == MAP_FAILED )
		{ perror( "mmap" ); exit(1); }
	
	// fetch the vector for the desired interrupt
	unsigned int	interrupt_number = 0x11;
	unsigned int	vector = *(unsigned int*)( interrupt_number << 2 );
	
	printf( "\ninterrupt-0x%02X: ", interrupt_number );
	printf( "vector = %08X \n", vector );

	// plant the 'return' stack and code
	unsigned short	*tos = (unsigned short*)0x8000;
	unsigned int	*eoi = (unsigned int*)0x8000;

	// transition to our Virtual Machine Monifor
	eoi[ 0 ] = 0x90C93166;	// xor %ecx, %ecx
	eoi[ 1 ] = 0x90904966;	// spin: dec %ecx
	eoi[ 2 ] = 0x90C90966;	// or %ecx, %ecx
	eoi[ 3 ] = 0x9090F675;	// jnz spin
	eoi[ 4 ] = 0x90C1010F;	// 'vmcall' instruction


	tos[ -1 ] = 0x0000;	// image of FLAGS
	tos[ -2 ] = 0x0000;	// image of CS
	tos[ -3 ] = 0x8000;	// image of IP

	// initialize the virtual-machine registers
	vm.eflags = 0x00023000;
	vm.eip    = vector & 0xFFFF;
	vm.cs	  = (vector >> 16);
	vm.esp	  = 0x7FFA;
	vm.ss	  = 0x0000;

	vm.eax	= 0xAAAAAAAA;
	vm.ebx	= 0xBBBBBBBB;
	vm.ecx	= 0xCCCCCCCC;
	vm.edx	= 0xDDDDDDDD;
	vm.ebp	= 0xBBBBBBBB;
	vm.esi	= 0xCCCCCCCC;
	vm.edi	= 0xDDDDDDDD;
	vm.ds	= 0xDDDD;
	vm.es	= 0xEEEE;
	vm.fs	= 0x8888;
	vm.gs	= 0x9999;

	// invoke the virtual-machine
	int	retval = ioctl( fd, sizeof( vm ), &vm );
	
	// display the register-values upon return
	printf( "\nretval = %-3d ", retval );
	printf( "EIP=%08X ", vm.eip );
	printf( "EFLAGS=%08X ", vm.eflags );

	printf( "\n" );
	printf( "EAX=%08X ", vm.eax );
	printf( "EBX=%08X ", vm.ebx );
	printf( "ECX=%08X ", vm.ecx );
	printf( "EDX=%08X ", vm.edx );
	printf( "CS=%04X ", vm.cs );
	printf( "DS=%04X ", vm.ds );
	printf( "FS=%04X ", vm.fs );

	printf( "\n" );
	printf( "ESP=%08X ", vm.esp );
	printf( "EBP=%08X ", vm.ebp );
	printf( "ESI=%08X ", vm.esi );
	printf( "EDI=%08X ", vm.edi );
	printf( "SS=%04X ", vm.ss );
	printf( "ES=%04X ", vm.es );
	printf( "GS=%04X ", vm.gs );

	printf( "\n\n" );
}

