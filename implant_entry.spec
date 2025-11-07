#
# Implant Main Loop - PICO
#

x86:
	load "bin/entry.x86.o"
		make object
		mergelib "lib/LibTCG/libtcg.x64.zip"
		export

x64:
	load "bin/entry.x64.o"
		make object
		mergelib "lib/LibTCG/libtcg.x64.zip"
		export