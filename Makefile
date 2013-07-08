CC=musl-gcc-x86_32
CFLAGS=-Wall
LDLIBS=-lz
all:	bar
bar:	bar.o md5.o jelopt.o jelist.o
rpm:	bar
	./bar -c --license=GPLv2+ --name bar bar.rpm bar
clean:
	rm -f *.o bar bar.rpm
