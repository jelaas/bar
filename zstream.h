#ifndef ZSTREAM_H
#define ZSTREAM_H

#include <zlib.h>
#include <lzma.h>
#include <zstd.h>

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
    struct {
      ZSTD_DCtx *ctx;
      int fd, eof;
      void *inbuf, *outbuf;
      size_t inbufsize, outbufsize;
      ZSTD_inBuffer input;
      ZSTD_outBuffer output;
    } zstd;
  };
};

int zstream(struct zstream *z, const char *codec);

#endif
