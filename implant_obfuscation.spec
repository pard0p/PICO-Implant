#
# Implant Obfuscation - PICO
#

x86:
	load "bin/obfuscation.x86.o"
		make object
		export

x64:
	load "bin/obfuscation.x64.o"
		make object
		export