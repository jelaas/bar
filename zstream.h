#ifndef ZSTREAM_H
#define ZSTREAM_H

#include <zlib.h>
#include <lzma.h>

struct zstream  {
	int (*open)(struct zstream *, int, char *);
	ssize_t (*read)(struct zstream *, void *, size_t);
	ssize_t (*write)(struct zstream *, void *, size_t);
	int (*init)(struct zstream *);
	int (*close)(struct zstream *);
	union {
		struct {
			lzma_stream stream;
			int fd, eof;
			size_t bufsize;
			void *inbuf, *outbuf;
		} xz;
		gzFile gzip;
	};
};

int zstream(struct zstream *z, const char *codec);

#endif
