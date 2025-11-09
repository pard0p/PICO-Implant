#
# Stage 2 of our loading process. We handle the actual DLL here.
#

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

		load "bin/hooks.x64.o"
            make object
			mergelib "lib/LibTP/libtp.x64.zip"
			mergelib "lib/LibGate/libgate.x64.zip"
            export
            link "hooks_module"

		export