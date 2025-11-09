#
# Stage 1: our bootstrap PIC code to use an environment-derived key to decrypt our stage 2.
#

x64:
	load "bin/stage1.x64.o"
		make pic +gofirst

		dfr "resolve" "ror13"
		mergelib "lib/libTCG/libtcg.x64.zip"

		run "stage2.spec"
			prepsum
			rc4 $ENVKEY
			preplen
			link "coff_s2"

		load "bin/guardrail.x64.o"
			make object
			export
			link "coff_gr"

		export
