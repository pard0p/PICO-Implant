CC=i686-w64-mingw32-gcc
CC_64=x86_64-w64-mingw32-gcc

all: libtcg.x86.zip libtcg.x64.zip

bin:
	mkdir bin

#
# x86 targets
#
libtcg.x86.zip: bin
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/loaddll.c     -o bin/loaddll.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/resolve_eat.c -o bin/resolve_eat.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/picorun.c     -o bin/picorun.x86.o
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c src/debug.c       -o bin/debug.x86.o
	zip -q -j libtcg.x86.zip bin/*.x86.o

#
# x64 targets
#
libtcg.x64.zip: bin
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/loaddll.c     -o bin/loaddll.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/resolve_eat.c -o bin/resolve_eat.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/picorun.c     -o bin/picorun.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/debug.c       -o bin/debug.x64.o
	zip -q -j libtcg.x64.zip bin/*.x64.o

#
# Other targets
#
clean:
	rm -rf bin/*.o
	rm -f libtcg.x86.zip
	rm -f libtcg.x64.zip
