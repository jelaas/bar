#include <stdlib.h>
#include <string.h>
#include "zstream.h"

static int gzip_init(struct zstream *z)
{
	z->gzip = (void*)0;
	return 0;
}

static int xz_init(struct zstream *z)
{
	lzma_stream tmp = LZMA_STREAM_INIT;
	z->xz.eof = 1;
	z->xz.stream = tmp;
	z->xz.bufsize = 4096;
	z->xz.inbuf = malloc(z->xz.bufsize);
	if(!z->xz.inbuf) return -1;
	z->xz.outbuf = malloc(z->xz.bufsize);
	if(!z->xz.outbuf) return -1;
	return 0;
}

static int zstd_init(struct zstream *z)
{
	z->zstd.ctx = 0;
	z->zstd.inbufsize = ZSTD_DStreamInSize();
	z->zstd.inbuf = malloc(z->zstd.inbufsize);
	if(!z->zstd.inbuf) return -1;
	z->zstd.outbufsize = ZSTD_DStreamOutSize();
	z->zstd.outbuf = malloc(z->zstd.outbufsize);
	if(!z->zstd.outbuf) return -1;
	return 0;
}

static int gzip_open(struct zstream *z, int fd, char *mode)
{
	z->gzip = gzdopen(fd, mode);
	if(!z->gzip) {
		return -1;
	}
	return 0;
}

static int xz_open(struct zstream *z, int fd, char *mode)
{
	lzma_ret ret;

	z->xz.eof = 0;
	z->xz.fd = fd;
	if(*mode == 'w') {
		ret = lzma_easy_encoder(&z->xz.stream, 5, LZMA_CHECK_CRC64);
		if (ret == LZMA_OK)
			return 0;
		return -1;
	}
	if(*mode == 'r') {
		z->xz.stream.next_in = NULL;
		z->xz.stream.avail_in = 0;
		z->xz.stream.next_out = z->xz.outbuf;
		z->xz.stream.avail_out = z->xz.bufsize;
		
		ret = lzma_stream_decoder(&z->xz.stream, UINT64_MAX, LZMA_CONCATENATED);
		if (ret == LZMA_OK)
			return 0;
		return -1;
	}

	return -1;
}

static int zstd_open(struct zstream *z, int fd, char *mode)
{
	z->zstd.ctx = ZSTD_createDCtx();
	if(!z->zstd.ctx) return -1;
	z->zstd.fd = fd;
	z->zstd.eof = 0;
	z->zstd.output.dst = z->zstd.outbuf;
	z->zstd.output.size = z->zstd.outbufsize;
	z->zstd.output.pos = 0;
	z->zstd.input.src = z->zstd.inbuf;
	z->zstd.input.size = 0;
	z->zstd.input.pos = 0;
	return 0;
}

static ssize_t gzip_read(struct zstream *z, void *buf, size_t size)
{
	return gzread(z->gzip, buf, size);
}

static ssize_t xz_read(struct zstream *z, void *buf, size_t size)
{
	size_t avail, copysize;
	int iter = 2;
	lzma_ret ret;
	lzma_action action = LZMA_RUN;

	if(z->xz.eof) action = LZMA_FINISH;
	
	while(iter > 0) {
		if (z->xz.stream.avail_in == 0 && (!z->xz.eof)) {
			z->xz.stream.next_in = z->xz.inbuf;
			z->xz.stream.avail_in = read(z->xz.fd, z->xz.inbuf, z->xz.bufsize);
			if(z->xz.stream.avail_in < 0) {
				/* read error */
				return -1;
			}
			if(z->xz.stream.avail_in == 0) {
				/* EOF */
				z->xz.eof = 1;
				z->xz.stream.avail_in = 0;
				action = LZMA_FINISH;
				iter = 0;
			}
		}
		ret = lzma_code(&z->xz.stream, action);
		if (ret != LZMA_OK) {
			if(ret == LZMA_MEM_ERROR) return -3;
			if(ret == LZMA_FORMAT_ERROR) return -4;
			if(ret == LZMA_OPTIONS_ERROR) return -5;
			if(ret == LZMA_DATA_ERROR) return -6;
			if(ret == LZMA_BUF_ERROR) return -7;
			if(ret == LZMA_PROG_ERROR) return -8;
			if (ret != LZMA_STREAM_END) return -2;
		}
		avail = z->xz.bufsize - z->xz.stream.avail_out;
		if (avail) {
			copysize = avail;
			if(copysize > size) {
				copysize = size;
			}
			memcpy(buf, z->xz.outbuf, copysize);
			memmove(z->xz.outbuf, z->xz.outbuf + copysize, avail - copysize);
			z->xz.stream.next_out = z->xz.outbuf + (avail - copysize);
			z->xz.stream.avail_out = z->xz.bufsize - (avail - copysize);
			return copysize;
		}
		iter--;
	}

	return 0;
}

static ssize_t zstd_read(struct zstream *z, void *buf, size_t size)
{
	size_t got, ret, total=0, copysize;

	while(total < size) {
		if(z->zstd.output.pos) {
                        /* copy min( (size - total), z->zstd.output.pos) */
			copysize = (size - total) < z->zstd.output.pos ? (size - total) : z->zstd.output.pos;
			memcpy(buf+total, z->zstd.outbuf, copysize);
			total += copysize;
			if (copysize < z->zstd.output.pos ) {
				memmove(z->zstd.outbuf, z->zstd.outbuf + copysize, z->zstd.output.pos - copysize);
			} else {
				z->zstd.output.pos = 0;
			}
			continue;
		}
		if(z->zstd.input.pos < z->zstd.input.size) {
			ret = ZSTD_decompressStream(z->zstd.ctx, &z->zstd.output , &z->zstd.input);
			if(ZSTD_isError(ret)) return -1;
			continue;
		}
		if(z->zstd.eof) return -1;
		got = read(z->zstd.fd, z->zstd.inbuf, z->zstd.inbufsize);
		if(got <= 0) {
			z->zstd.eof = 1;
			break;
		}
		z->zstd.input.src = z->zstd.inbuf;
		z->zstd.input.size = got;
		z->zstd.input.pos = 0;
	}
	return total;
}

static ssize_t gzip_write(struct zstream *z, void *buf, size_t count)
{
	return gzwrite(z->gzip, buf, count);
}

static ssize_t xz_write(struct zstream *z, void *buf, size_t count)
{
	return -1;
}

static ssize_t zstd_write(struct zstream *z, void *buf, size_t count)
{
	return -1;
}

static int gzip_close(struct zstream *z)
{
	int rc = gzclose(z->gzip);
	z->gzip = (void*)0;
	return rc;
}

static int xz_close(struct zstream *z)
{
	int rc = close(z->xz.fd);
	z->xz.fd = -1;
	lzma_end(&z->xz.stream);
	return rc;
}

static int zstd_close(struct zstream *z)
{
	int rc = close(z->zstd.fd);
	z->zstd.fd = -1;
	ZSTD_freeDCtx(z->zstd.ctx);
	return rc;
}

int zstream(struct zstream *z, const char *codec)
{
	if(!strcmp(codec, "gzip")) {
		z->init = gzip_init;
		z->open = gzip_open;
		z->read = gzip_read;
		z->write = gzip_write;
		z->close = gzip_close;
		return 0;
	}
	if(!strcmp(codec, "xz")) {
		z->init = xz_init;
		z->open = xz_open;
		z->read = xz_read;
		z->write = xz_write;
		z->close = xz_close;
		return 0;
	}
	if(!strcmp(codec, "zstd")) {
		z->init = zstd_init;
		z->open = zstd_open;
		z->read = zstd_read;
		z->write = zstd_write;
		z->close = zstd_close;
		return 0;
	}
	return -1;
}

