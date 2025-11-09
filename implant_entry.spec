#
# Implant Main Loop - PICO
#

x64:
	load "bin/entry.x64.o"
		make object
		mergelib "lib/LibTCG/libtcg.x64.zip"
		export