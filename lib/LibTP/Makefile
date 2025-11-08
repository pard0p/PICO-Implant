CC_64=x86_64-w64-mingw32-gcc

all: libtp.x64.zip

bin:
	mkdir bin

libtp.x64.zip: bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -fno-ident -c src/tp.c -o bin/tp.x64.o
	zip -q -j libtp.x64.zip bin/*.x64.o

clean:
	rm -rf bin/*.o
	rm -f libtp.x64.zip
