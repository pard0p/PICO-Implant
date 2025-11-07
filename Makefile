CC=i686-w64-mingw32-gcc
CC_64=x86_64-w64-mingw32-gcc

all: bin/stage1.x86.o bin/stage1.x64.o

bin:
	mkdir bin

#
# x86 targets
#
bin/stage1.x86.o: bin
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/guardrail.c -o bin/guardrail.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/stage1.c -o bin/stage1.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/stage2.c -o bin/stage2.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/entry.c -o bin/entry.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/transport.c -o bin/transport.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/obfuscation.c -o bin/obfuscation.x86.o

#
# x64 targets
#
bin/stage1.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/guardrail.c -o bin/guardrail.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/stage1.c -o bin/stage1.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/stage2.c -o bin/stage2.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/entry.c -o bin/entry.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/transport.c -o bin/transport.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/obfuscation.c -o bin/obfuscation.x64.o

#
# Other targets
#
clean:
	rm -f bin/*
