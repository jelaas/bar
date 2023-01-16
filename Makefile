CC=musl-gcc-x86_32
CFLAGS=-Wall
LDLIBS=-lz -llzma -lzstd
all:	bar
bar:	bar.o md5.o jelopt.o jelist.o zstream.o sha256.o digest.o bar_cpio.o bar_rpm.o bar_extract.o
rpm:	bar
	strip bar
	./bar -c --license=GPLv2+ --version 1.14 --release 1 --name bar --prefix=/usr/bin --fgroup=root --fuser=root bar-1.14-1.rpm bar
clean:
	rm -f *.o bar bar.rpm
