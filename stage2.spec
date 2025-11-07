#
# Stage 2 of our loading process. We handle the actual DLL here.
#

x86:
	# push stage2.x6.o contents onto the stack
	load "bin/stage2.x86.o"
		# interpret these contents as a COFF
		make object

		# map the pointers passed to PicoLoad() via IMPORTFUNCS parameter
		# to functions within this COFF
		import "LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree"

		# merge the Tradecraft Garden Library into our PICO
		mergelib "lib/LibTCG/libtcg.x86.zip"

		load "bin/transport.x86.o"
            make object
			mergelib "lib/LibWinHttp/libwinhttp.x86.zip"
            export
            link "transport_module"

		# export our COFF as a ready-to-load PICO and return to stage 1
		export

x64:
	load "bin/stage2.x64.o"
		make object
		import "LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree"

		mergelib "lib/LibTCG/libtcg.x64.zip"

		load "bin/transport.x64.o"
            make object
			mergelib "lib/LibWinHttp/libwinhttp.x64.zip"
            export
            link "transport_module"

		export