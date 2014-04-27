CC=musl-gcc-x86_32
CFLAGS=-Wall
LDLIBS=-lz -llzma
all:	bar
bar:	bar.o md5.o jelopt.o jelist.o zstream.o sha256.o digest.o bar_cpio.o bar_rpm.o bar_extract.o
rpm:	bar
	./bar -c --license=GPLv2+ --name bar bar.rpm bar
clean:
	rm -f *.o bar bar.rpm
