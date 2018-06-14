/*****************************************************************
*
* ============== Kernel Dumper for PS4 - WildCard ===============
*
*	Support for 4.05/4.55/5.05
*
*	Thanks to:
*	-Qwertyuiop for his kernel exploits
* -Specter for his Code Execution method
*	-IDC for helping to understand things
*	-Shadow for the copyout trick ;)
*
******************************************************************/
#include "ps4.h"
#include "defines.h"

int kdump(struct thread *td, struct kdump_args* args){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_BASE_PTR];

	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + KERN_PRINTF);
	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + KERN_COPYOUT);
	void (*bzero)(void *b, size_t len) = (void *)(kernel_base + KERN_BZERO);

	// pull in our arguments
  uint64_t kaddr = args->payload_info_dumper->kaddr;
	uint64_t uaddr = args->payload_info_dumper->uaddr;

	// run copyout into userland memory for the kaddr we specify
	int cpRet = copyout(kaddr, uaddr , PAGE_SIZE);

	// if mapping doesnt exist zero out that mem
	if(cpRet == -1){
		printfkernel("bzero at 0x%016llx\n", kaddr);
		bzero(uaddr, PAGE_SIZE);
		return cpRet;
	}
	
	return cpRet;
}


int kpayload(struct thread *td,struct kpayload_args* args){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;


	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_BASE_PTR];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[KERN_PRISON0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	// resolve kernel functions

	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + KERN_PRINTF);
	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + KERN_COPYOUT);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
#if KERN_VER < 505
	// enable uart :)
	*(char *)(kernel_base + KERN_UART_ENABLE) = 0; 
#endif

	// Restore write protection
	writeCr0(cr0);

	// Say hello and put the kernel base in userland to we can use later

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	// Say hello and put the kernel base in userland to we can use later

	uint64_t uaddr = args->payload_info->uaddr;

	printfkernel("uaddr is:0x%016llx\n", uaddr);

	copyout(&kernel_base, uaddr, 8);

	return 0;
}

// props to Hitodama for his hexdump function always nice to have near
int hexDumpKern(const void *data, size_t size, uint64_t kernel_base){

	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	// hook kernel print for uart hex dumping
	int (*printf)(const char *fmt, ...) = (void *)(kernel_base + KERN_PRINTF);

	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';
	
	printf("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){
				printf("  %s\n", b);
				}
			printf("%016lx ", (unsigned char *)data + i);
		}

		if(i % consoleSize == 8)
			printf(" ");
		printf(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];

		else
			b[i % consoleSize + 1] = '.';
		}

		while((i % consoleSize) != 0)
		{

		if(i % consoleSize == 8)
			printf("    ");
	
		else
			printf("   ");
			b[i % consoleSize + 1] = '.';
			i++;
		}

		printf("  %s\n", b);
		return 0;
}

// userland hexdump over socket
int hexDump(const void *data, size_t size,int sock)
{
	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';
	
	printfsocket("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){
				printfsocket("  %s\n", b);
				}
			printfsocket("%016lx ", (unsigned char *)data + i);
		}

		if(i % consoleSize == 8)
			printfsocket(" ");
		printfsocket(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];
		else
			b[i % consoleSize + 1] = '.';
	}
	while((i % consoleSize) != 0)
	{
		if(i % consoleSize == 8)
			printfsocket("    ");
		else
			printfsocket("   ");
		b[i % consoleSize + 1] = '.';
		i++;
	}
	printfsocket("  %s\n", b);
	return 0;
}



int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

#ifdef DEBUG_SOCKET

	// create our server
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 77);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	int sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

#endif
	
	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, KERN_DUMPSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	printfsocket("connected\n");

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	
  struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayload,&payload_info);

	// resolve notifications after we have access to full fs
	initSysUtil();

	notify("Kernel patched!");

	printfsocket("Kernel patched!\n");

	// retreive the kernel base copied into userland memory and set it

	uint64_t kbase;

	memcpy(&kbase,dump,8);

	printfsocket("kernBase is:0x%016llx\n",kbase);
	printfsocket("dump is:0x%016llx\n",dump);

	// loop on our kdump payload 
	
	uint64_t pos = 0;
  struct payload_info_dumper payload_info_dumper;

	notify("Starting Kernel Dump...");

	// loop enough to dump up until gpu used memory
	for(int i = 0; i < KERN_DUMPITER; i++){
	
 		payload_info_dumper.kaddr = kbase + pos;

#ifdef DEBUG_SOCKET
		payload_info_dumper.uaddr = dump;

		// call our copyout wrapper and send the userland buffer over socket
		kexec(&kdump, &payload_info_dumper);

		sceNetSend(sock,dump,PAGE_SIZE,0);

#else
		payload_info_dumper.uaddr = filedump + pos;

		// call our copyout wrapper and send the userland buffer over socket
		kexec(&kdump, &payload_info_dumper);

#endif

		pos = pos + PAGE_SIZE;
	}
	
#ifdef DEBUG_SOCKET
	printfsocket("Finished dumping Kernel!\n");
	sceNetSocketClose(sock);

#else
	notify("Finished dumping Kernel to userland!");
		
	sceKernelSleep(5);

	// write to file		
	int fd = open(KERN_FILEPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if(fd==-1) 
	{
		notify("Cant create file :/");
	}
	
	else
	{
		write(fd, filedump, KERN_DUMPSIZE); // Write the userland buffer to USB
	
		notify("Finished writing Kernel to a File :)");
		close(fd);
	}

#endif

	munmap(dump, PAGE_SIZE);
	munmap(filedump, KERN_DUMPSIZE);

#ifdef SHUTDOWN_ON_FINISH
		int evf = syscall(540, "SceSysCoreReboot");
		syscall(546, evf, 0x4000, 0);
		syscall(541, evf);
		syscall(37, 1, 30);

#endif

	return 0;
}


