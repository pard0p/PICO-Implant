#include <windows.h>
#include "includes/tp.h"

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(GetProcAddress);
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualFree);
} WIN32FUNCS;

WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

/*
 * This is an example of a hooked function that proxies through to the real API via our TP layer.
 */
int WINAPI _VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	NTARGS args = {0};

	args.functionPtr = (ULONG_PTR)KERNEL32$VirtualFree;
	args.argument1  = (ULONG_PTR)lpAddress;
	args.argument2  = (ULONG_PTR)dwSize;
	args.argument3  = (ULONG_PTR)dwFreeType;
	
	ProxyNtApi(&args);

	return 0;
}

char * WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	char * result = (char *)GetProcAddress(hModule, lpProcName);

	if ((char *)GetProcAddress == result) {
		return (char *)_GetProcAddress;
	}

	else if ((char *)KERNEL32$VirtualFree == result) {
		return (char *)_VirtualFree;
	}

	return result;
}

void go(WIN32FUNCS * funcs) {
	funcs->GetProcAddress = (__typeof__(GetProcAddress) *)_GetProcAddress;
}