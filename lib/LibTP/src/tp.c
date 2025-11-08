/*
 * Copyright 2025 Daniel Duggan, Zero-Point Security
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tp.h"

WINBASEAPI VOID NTAPI NTDLL$TpAllocWork   (PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
WINBASEAPI VOID NTAPI NTDLL$TpPostWork    (PTP_WORK);
WINBASEAPI VOID NTAPI NTDLL$TpWaitForWork (PTP_WORK, BOOL);
WINBASEAPI VOID NTAPI NTDLL$TpReleaseWork (PTP_WORK);

void __attribute__((naked)) WorkCallback()
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "mov rbx, rdx;"
        
        "mov rax, [rbx];"
        "mov rcx, [rbx + 0x8];"
        "mov rdx, [rbx + 0x10];"
        "mov r8,  [rbx + 0x18];"
        "mov r9,  [rbx + 0x20];"
        
        "mov r10, [rbx + 0x30];"
        "mov [rsp + 0x30], r10;"
        
        "mov r10, [rbx + 0x28];"
        "mov [rsp + 0x28], r10;"
        
        "jmp rax;"
        ".att_syntax prefix;"
    );
}

VOID ProxyNtApi(NTARGS * args)
{
    PTP_WORK WorkReturn = NULL;

    NTDLL$TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback, args, NULL);
    NTDLL$TpPostWork(WorkReturn);
    NTDLL$TpWaitForWork(WorkReturn, FALSE);
    NTDLL$TpReleaseWork(WorkReturn);
}