#include <windows.h>

/* NTSTATUS type definition */
typedef LONG NTSTATUS;

/**
 * Syscall gate structure containing all necessary execution information
 */
typedef struct _SYSCALL_GATE {
    DWORD ssn;              /* System Service Number */
    PVOID syscallAddr;      /* Address of syscall instruction sequence */
    PVOID *args;            /* Pointer to argument array */
    DWORD argCount;         /* Number of arguments */
    PVOID returnGadget;     /* Return gadget address (NULL = use CALL mode) */
} SYSCALL_GATE, *PSYSCALL_GATE;


/* Prepare syscall with optional ROP gadget (TRUE = JUMP mode, FALSE = CALL mode) */
SYSCALL_GATE PrepareSyscall(LPCSTR functionName, PVOID *arguments, DWORD argCount, BOOL enableRopGadget);

/* Execute prepared syscall */
NTSTATUS ExecuteSyscall(PSYSCALL_GATE gate);