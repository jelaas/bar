#include <string.h>
#include <stdio.h>
#include "digest.h"

static int md5_init(struct digest *d)
{
	return MD5Init(&d->ctx.md5);
}

static int sha256_init(struct digest *d)
{
	sha256_init_ctx(&d->ctx.sha256);
	return 0;
}

static int md5_final(struct digest *d)
{
	int i;
	
	MD5Final(d->sum.md5, &d->ctx.md5);
	for(i=0;i<MD5_DIGEST_LENGTH;i++) {
		sprintf(d->hex.md5+i*2, "%02x", d->sum.md5[i]);
	}
	return 0;
}

static int sha256_final(struct digest *d)
{
	int i;
	
	sha256_finish_ctx(&d->ctx.sha256, &d->sum.sha256);
	for(i=0;i<SHA256_DIGEST_LENGTH;i++) {
		sprintf(d->hex.sha256+i*2, "%02x", d->sum.sha256[i]);
	}
	return 0;
}

static int md5_update(struct digest *d, void *data, size_t len)
{
	MD5Update(&d->ctx.md5, data, len);
	return 0;
}

static int sha256_update(struct digest *d, void *data, size_t len)
{
	sha256_process_bytes(data, len, &d->ctx.sha256);
	return 0;
}

int digest(struct digest *d, char *algo)
{
	if(!strcmp(algo, "md5")) {
		d->init = md5_init;
		d->update = md5_update;
		d->final = md5_final;
		d->hexstr = d->hex.md5;
		d->binary = d->sum.md5;
		d->size = MD5_DIGEST_LENGTH;
		return d->init(d);
	}
	if(!strcmp(algo, "sha256")) {
		d->init = sha256_init;
		d->update = sha256_update;
		d->final = sha256_final;
		d->hexstr = d->hex.sha256;
		d->binary = d->sum.sha256;
		d->size = SHA256_DIGEST_LENGTH;
		return d->init(d);
	}
	return -1;
}

