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
	z->xz.outbuf = malloc(z->xz.bufsize);
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

static ssize_t gzip_read(struct zstream *z, void *buf, size_t size)
{
	return gzread(z->gzip, buf, size);
}

static ssize_t xz_read(struct zstream *z, void *buf, size_t size)
{
	size_t avail, copysize;
	lzma_ret ret;
	lzma_action action = LZMA_RUN;

	if(z->xz.eof) action = LZMA_FINISH;
	
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
		}
	}
	ret = lzma_code(&z->xz.stream, action);
	if (ret != LZMA_OK) {
		if (ret != LZMA_STREAM_END) {
			return -2;
		}
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

	return 0;
}

static ssize_t gzip_write(struct zstream *z, void *buf, size_t count)
{
	return gzwrite(z->gzip, buf, count);
}

static ssize_t xz_write(struct zstream *z, void *buf, size_t count)
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
	return -1;
}

/*
static int zstream_init(struct zstream *z)
{
	// lzma_stream strm *s;
	z->xz = LZMA_STREAM_INIT;
	lzma_ret ret = lzma_easy_encoder(z->xz, 9, LZMA_CHECK_CRC64);
	if (ret == LZMA_OK)
		return 0;
	return -1;
}

static int ztream_write(struct zstream *z)
{
	uint8_t inbuf[BUFSIZ];
	uint8_t outbuf[BUFSIZ];
	
	strm->next_in = NULL;
	strm->avail_in = 0;
	strm->next_out = outbuf;
	strm->avail_out = sizeof(outbuf);

	while (true) {
		// Fill the input buffer if it is empty.
		if (strm->avail_in == 0 && !feof(infile)) {
			strm->next_in = inbuf;
			strm->avail_in = fread(inbuf, 1, sizeof(inbuf),
					       infile);

			if (ferror(infile)) {
				fprintf(stderr, "Read error: %s\n",
					strerror(errno));
				return false;
			}

			// Once the end of the input file has been reached,
			// we need to tell lzma_code() that no more input
			// will be coming and that it should finish the
			// encoding.
			if (feof(infile))
				action = LZMA_FINISH;
		}

		// Tell liblzma do the actual encoding.
		//
		// This reads up to strm->avail_in bytes of input starting
		// from strm->next_in. avail_in will be decremented and
		// next_in incremented by an equal amount to match the
		// number of input bytes consumed.
		//
		// Up to strm->avail_out bytes of compressed output will be
		// written starting from strm->next_out. avail_out and next_out
		// will be incremented by an equal amount to match the number
		// of output bytes written.
		//
		// The encoder has to do internal buffering, which means that
		// it may take quite a bit of input before the same data is
		// available in compressed form in the output buffer.
		lzma_ret ret = lzma_code(strm, action);

		// If the output buffer is full or if the compression finished
		// successfully, write the data from the output bufffer to
		// the output file.
		if (strm->avail_out == 0 || ret == LZMA_STREAM_END) {
			// When lzma_code() has returned LZMA_STREAM_END,
			// the output buffer is likely to be only partially
			// full. Calculate how much new data there is to
			// be written to the output file.
			size_t write_size = sizeof(outbuf) - strm->avail_out;

			if (fwrite(outbuf, 1, write_size, outfile)
			    != write_size) {
				fprintf(stderr, "Write error: %s\n",
					strerror(errno));
				return false;
			}

			// Reset next_out and avail_out.
			strm->next_out = outbuf;
			strm->avail_out = sizeof(outbuf);
		}

		// Normally the return value of lzma_code() will be LZMA_OK
		// until everything has been encoded.
		if (ret != LZMA_OK) {
			// Once everything has been encoded successfully, the
			// return value of lzma_code() will be LZMA_STREAM_END.
			//
			// It is important to check for LZMA_STREAM_END. Do not
			// assume that getting ret != LZMA_OK would mean that
			// everything has gone well.
			if (ret == LZMA_STREAM_END)
				return true;

			// It's not LZMA_OK nor LZMA_STREAM_END,
			// so it must be an error code. See lzma/base.h
			// (src/liblzma/api/lzma/base.h in the source package
			// or e.g. /usr/include/lzma/base.h depending on the
			// install prefix) for the list and documentation of
			// possible values. Most values listen in lzma_ret
			// enumeration aren't possible in this example.
			const char *msg;
			switch (ret) {
			case LZMA_MEM_ERROR:
				msg = "Memory allocation failed";
				break;

			case LZMA_DATA_ERROR:
				// This error is returned if the compressed
				// or uncompressed size get near 8 EiB
				// (2^63 bytes) because that's where the .xz
				// file format size limits currently are.
				// That is, the possibility of this error
				// is mostly theoretical unless you are doing
				// something very unusual.
				//
				// Note that strm->total_in and strm->total_out
				// have nothing to do with this error. Changing
				// those variables won't increase or decrease
				// the chance of getting this error.
				msg = "File size limits exceeded";
				break;

			default:
				// This is most likely LZMA_PROG_ERROR, but
				// if this program is buggy (or liblzma has
				// a bug), it may be e.g. LZMA_BUF_ERROR or
				// LZMA_OPTIONS_ERROR too.
				//
				// It is inconvenient to have a separate
				// error message for errors that should be
				// impossible to occur, but knowing the error
				// code is important for debugging. That's why
				// it is good to print the error code at least
				// when there is no good error message to show.
				msg = "Unknown error, possibly a bug";
				break;
			}

			fprintf(stderr, "Encoder error: %s (error code %u)\n",
				msg, r
}
*/

