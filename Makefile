CC=musl-gcc-x86_32
CFLAGS=-Wall
LDLIBS=-lz
all:	bar
bar:	bar.o md5.o jelopt.o jelist.o
clean:
	rm -f *.o bar
