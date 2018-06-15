
// change the version
#define KERN_VER 505

// comment to use usb method!
//#define DEBUG_SOCKET

// comment if you dont want ps4 to turn off after completing kdump
//#define SHUTDOWN_ON_FINISH

// multi version support
#if KERN_VER == 405

	#define	KERN_PRINTF		0x00347580
	#define	KERN_BASE_PTR		0x0030EB30
	#define	KERN_COPYOUT		0x00286d70
	#define	KERN_BZERO		0x00286c30
	#define	KERN_PRISON0		0x00F26010
	#define	KERN_ROOTVNODE		0x0206D250
	#define	KERN_UART_ENABLE	0x0186b0a0

	#define KERN_DUMPSIZE 		108806144	// can change if you want but may crash if you hit critical code in gpu memory

#elif KERN_VER == 455

	#define	KERN_BASE_PTR 		0x03095d0
	#define	KERN_PRINTF 		0x0017F30
	#define	KERN_COPYOUT 		0x014A7B0
	#define	KERN_BZERO 		0x014A610
	#define	KERN_PRISON0 		0x10399B0
	#define	KERN_ROOTVNODE 		0x21AFA30
	#define	KERN_UART_ENABLE 	0x1997BC8

	#define KERN_DUMPSIZE 		100663296	// can change if you want but may crash if you hit critical code in gpu memory

#elif KERN_VER == 505

	#define	KERN_PRINTF		0x0436040
	#define	KERN_BASE_PTR 		0x00001C0
	#define	KERN_COPYOUT		0x01ea630
	#define	KERN_BZERO		0x01ea510 
	#define	KERN_PRISON0 		0x10986A0
	#define	KERN_ROOTVNODE 		0x22C1A70
	#define	KERN_UART_ENABLE 		0	// mira takes care of this

	#define KERN_DUMPSIZE 		108806144	// can change if you want but may crash if you hit critical code in gpu memory

#else // crash your shit lol

	#define	KERN_PRINTF 			0
	#define	KERN_BASE_PTR			0
	#define	KERN_COPYOUT			0
	#define	KERN_BZERO			0
	#define	KERN_COPYIN			0
	#define	KERN_PRISON0			0
	#define	KERN_ROOTVNODE			0
	#define	KERN_UART_ENABLE		0

	#define KERN_DUMPSIZE 			0	

#endif





#define PAGE_SIZE 16348
#define KERN_DUMPITER KERN_DUMPSIZE / PAGE_SIZE 	// can only dump a page at at time so we need to iterate
#define KERN_FILEPATH "/mnt/usb0/kdump.bin"		// file path if debug socket isnt defined

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define	CTL_KERN	1				/* "high kernel": proc, limits */
#define	KERN_PROC	14				/* struct: process entries */
#define	KERN_PROC_VMMAP	32				/* VM map entries for process */
#define	KERN_PROC_PID	1				/* by process id */

#ifdef DEBUG_SOCKET
	#define printfsocket(format, ...)\
		do {\
			char buffer[512];\
			int size = sprintf(buffer, format, ##__VA_ARGS__);\
			sceNetSend(sock, buffer, size, 0);\
		} while(0)

#else
	#define printfsocket(format, ...)\
		do {\
		} while(0)
#endif

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};


void notify(char *message)
{
	char buffer[512];
	sprintf(buffer, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(0x81, buffer);
}
 
unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}


struct ucred {
			uint32_t useless1;
			uint32_t cr_uid;     // effective user id
			uint32_t cr_ruid;    // real user id
 			uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};

struct thread {
    	void *useless;
    	struct proc *td_proc;
};


struct payload_info
{
  uint64_t uaddr;
};

struct payload_info_dumper
{
  uint64_t uaddr;
  uint64_t kaddr;
};

struct kdump_args
{
  void* syscall_handler;
  struct payload_info_dumper* payload_info_dumper;
};

struct kpayload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};
