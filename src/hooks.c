#include <windows.h>
#include "includes/tp.h"
#include "includes/gate.h"

#define NTAPI __stdcall
#define NtCurrentProcess()  ( HANDLE ) ( ( HANDLE ) - 1 )

typedef LONG NTSTATUS;

typedef struct {
	HMODULE (WINAPI *LoadLibraryA)(LPCSTR lpLibFileName);
	FARPROC (WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	LPVOID (WINAPI *VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	BOOL (WINAPI *VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
} WIN32FUNCS;

WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
NTSTATUS NTAPI NTDLL$NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

/**
 * Indirect syscall wrapper for NtFreeVirtualMemory
 * 
 * 1. Prepares the indirect syscall with the original SSN.
 * 2. Executes through Windows Thread Pool to further obfuscate the callstack.
 * 
 */
NTSTATUS _NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {       
    PVOID args[4] = {0};
    args[0] = ProcessHandle;
    args[1] = BaseAddress;
    args[2] = RegionSize;
    args[3] = (PVOID)(ULONG_PTR)FreeType;
    
    SYSCALL_GATE gate = PrepareSyscall("NtFreeVirtualMemory", args, 4, TRUE);
    
    if (gate.ssn == 0) {
        return -1; /* Indicate failure to prepare syscall */
    }
    
    NTARGS ntArgs = {0};
    ntArgs.functionPtr = (ULONG_PTR)ExecuteSyscall;
    ntArgs.argument1   = (ULONG_PTR)&gate;
    ntArgs.argument2   = 0;
    ntArgs.argument3   = 0;
    
    ProxyNtApi(&ntArgs);

    return 0;
}

/**
 * Hooked VirtualFree implementation that uses indirect syscalls
 * 
 * This function intercepts calls to VirtualFree and redirects them through
 * our indirect syscall mechanism.
 * 
 * @param lpAddress Pointer to the base address of the memory region to free
 * @param dwSize Size of the memory region (ignored for MEM_RELEASE operations)
 * @param dwFreeType Type of free operation (MEM_DECOMMIT, MEM_RELEASE, etc.)
 * @return Non-zero on success, zero on failure
 */
int WINAPI _VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {   
    /* Use current process handle for the operation */
    HANDLE hProcess = NtCurrentProcess();
    
    /* For MEM_RELEASE operations, size must be 0 according to NTAPI specification */
    SIZE_T regionSize = (dwFreeType & MEM_RELEASE) ? 0 : dwSize;

    /* Execute the memory free operation via indirect syscall */
    NTSTATUS status = _NtFreeVirtualMemory(hProcess, &lpAddress, &regionSize, MEM_RELEASE);
    
    /* Convert NTSTATUS to Win32 boolean result */
    return (status >= 0) ? 1 : 0;  /* Success if NTSTATUS >= 0 */
}

/**
 * Hooked GetProcAddress implementation for API redirection
 * 
 * This function intercepts GetProcAddress calls and redirects specific
 * function requests to our hooked implementations. This allows us to
 * transparently replace API calls with our indirect syscall versions.
 * 
 * @param hModule Handle to the module containing the function
 * @param lpProcName Name of the function to retrieve
 * @return Pointer to the function (original or hooked version)
 */
char * WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    /* Get the original function address first */
    char * result = (char *)GetProcAddress(hModule, lpProcName);

    /* Redirect recursive calls to our hooked GetProcAddress */
    if ((char *)GetProcAddress == result) {
        return (char *)_GetProcAddress;
    }
    /* Redirect VirtualFree calls to our hooked implementation */
    else if ((char *)KERNEL32$VirtualFree == result) {
        return (char *)_VirtualFree;
    }

    /* Return original function pointer for all other cases */
    return result;
}

/**
 * Entry point for hook installation
 * 
 * This function is called to install our API hooks by replacing function
 * pointers in the provided WIN32FUNCS structure. The modified structure
 * will cause subsequent API calls to be redirected through our hooks.
 * 
 * @param funcs Pointer to WIN32FUNCS structure to modify with hook addresses
 */
void go(WIN32FUNCS * funcs) {
    /* Install GetProcAddress hook to intercept function resolution */
    funcs->GetProcAddress = (FARPROC (WINAPI *)(HMODULE, LPCSTR))_GetProcAddress;
}