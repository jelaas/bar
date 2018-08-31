/*
 * File: bar.c
 * Implements: rpm file archive creator and extractor
 *
 * Copyright: Jens Låås, Uppsala University, 2013 - 2014
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>

#include "bar_rpm.h"
#include "bar_extract.h"
#include "bar_cpio.h"
#include "jelopt.h"
#include "jelist.h"
#include "zstream.h"
#include "digest.h"

/*
 * bar [-options] archive-file [path ..]
 *
 * Options:
 * h -- help
 * r -- recursive
 * c -- create
 * x -- extract
 * v -- verbose
 * V -- verify
 *
 */

struct {
	int recursive,create,extract,verbose,verify;
	int quotechar;
	struct {
		char *arch, *buildtime, *os, *license, *version, *release, *name;
		char *summary, *description, *group;
		char *fuser, *fgroup;
		char *postin, *postun, *posttrans;
		char *prein, *preun, *pretrans;
	} tag;
	struct logcb log;
	struct bar_options opt;
	struct jlhead *requires;
} conf;

struct filespec {
	uint32_t flags;
	int recursive;
	char *user, *group, *prefix;
};

struct req {
	char *name;
	char *version;
};

/*
 * Remove quotes and translate special quotes 'n', 't'
 */
char *dequote(char *s)
{
	char *p, *d = strdup(s);
	for(p=d;*s;) {
		if(*s == conf.quotechar) {
			if(*(s+1) == conf.quotechar) {
				*p++ = *s++;
				s++;
				continue;
			}
			if(!*(s+1))
				break;
			if(*(s+1) == 'n') {
				s+=2;
				*p++ = '\n';
				continue;
			}
			if(*(s+1) == 't') {
				s+=2;
				*p++ = '\t';
				continue;
			}
			s+=2;
			continue;
		}
		*p++ = *s++;
	}
	*p = 0;
	return d;
}

static int hextobin(char *dst, const uint8_t *src, size_t len)
{
	int i;
	static const uint8_t hextable[] = {
		[0 ... 255] = -1,
		['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		['A'] = 10, 11, 12, 13, 14, 15,
		['a'] = 10, 11, 12, 13, 14, 15
	};
	for(i=0; i < len;i++) {
		if(!*src) return -1;
		*dst = hextable[*src++] << 4;
		*dst += hextable[*src++];
		dst++;
	}
	return 0;
}


static int ftest(const char *path, mode_t flags)
{
	struct stat b;
	if(lstat(path, &b))
		return -1;
	if(b.st_mode & flags) return 0;
	return -1;
}

static struct tag *tag_new(int n)
{
	struct tag *tag;
	
	tag = malloc(sizeof(struct tag));
	if(!tag) return (void*)0;
	memset(tag, 0, sizeof(struct tag));
	tag->tag = n;
	tag->type = HDRTYPE_STRING;
	tag->count = 1;
	tag->size = 0;
	return tag;
}

static int rpm_lead_write(int fd, struct rpm *rpm)
{
	if(conf.verbose > 1) fprintf(stderr, "bar: Writing lead, %zd bytes\n", sizeof(struct rpmlead));
	rpm->lead.magic = htonl(RPMMAGIC);
	if(write(fd, &rpm->lead, sizeof(struct rpmlead))!= sizeof(struct rpmlead)) {
		fprintf(stderr, "bar: Failed to write lead.\n");
                return -1;		
	}
	return 0;
}

static int rpm_payload_write(int fd, struct rpm *rpm, struct jlhead *files)
{
	struct zstream z;
	struct cpio_file *f;
	struct cpio_file trailer;
	ssize_t n;
	int zfd;
	
	zfd = dup(fd);
	zstream(&z, "gzip");
	z.init(&z);
	z.open(&z, zfd, "w");
	jl_foreach(files, f) {
		if(conf.verbose) printf("%s\n", f->normalized_name);
		if((n=cpio_write(&conf.log, &z, f, &rpm->sumsize)) == -1) {
			fprintf(stderr, "bar: Error writing cpio header\n");
			return -1;
		}
		rpm->uncompressed_size += n;
	}
	memset(&trailer, 0, sizeof(trailer));
	trailer.name = "TRAILER!!!";
	trailer.normalized_name = "TRAILER!!!";
	trailer.cpio_name = "TRAILER!!!";
	if((n=cpio_write(&conf.log, &z, &trailer, &rpm->sumsize)) == -1) {
		fprintf(stderr, "bar: Error writing cpio header for trailer\n");
		return -1;
	}
	rpm->uncompressed_size += n;
	
	z.close(&z);
	
	rpm->eofoffset = lseek(fd, 0, SEEK_CUR);
	
	return 0;
}

static int rpm_hdr_write(int fd, struct rpm *rpm, struct header *hdr, struct jlhead *tags, int align)
{
	int i, len;
	char *store, *storep;
	int store_len;
	struct indexentry *index, *indexp;
	int index_len;
	struct tag *tag;
	ssize_t off_md5=-1, off_size=-1, off_payloadsize=-1, off_sumsize=-1;
	off_t pos;
	
	hdr->magic = htonl((HEADERMAGIC << 8) | 1);
	hdr->entries = htonl(tags->len);
	
	store_len = 1024;
	store = storep = malloc(store_len);
	if(!store) {
		fprintf(stderr, "bar: Failed to allocate memory for store\n");
		return -1;
	}
	index_len = tags->len;
	index = indexp = malloc(index_len * sizeof(struct indexentry));
	if(!index) {
		fprintf(stderr, "bar: Failed to allocate memory for index\n");
		return -1;
	}
	
	/* create index and store simultaneously */
	jl_foreach(tags, tag) {

		if(tag->type == HDRTYPE_INT32) {
			/* align */
			while((storep-store) % 4)
				storep++;
		}
		if(tag->type == HDRTYPE_INT16) {
			/* align */
			while((storep-store) % 2)
				storep++;
		}
		
		if(tag->track) {
			if(tag->tag == SIGTAG_MD5) off_md5 = storep-store;
			if(tag->tag == SIGTAG_SIZE) off_size = storep-store;
			if(tag->tag == RPMTAG_SIZE) off_sumsize = storep-store;
			if(tag->tag == SIGTAG_PAYLOADSIZE) off_payloadsize = storep-store;
		}

		indexp->tag = htonl(tag->tag);
		indexp->offset = htonl(storep - store);
		indexp->count = htonl(tag->count);
		indexp->type = htonl(tag->type);
		
		switch(tag->type) {
		case HDRTYPE_STRARRAY:
			indexp->count = htonl(tag->count);
			while(((storep-store)+tag->size+8) > store_len) {
				off_t poffset;
				poffset = storep-store;
				store_len += 1024;
				store = realloc(store, store_len);
				storep = store + poffset;
			}
			memcpy(storep, tag->value, tag->size);
			storep += tag->size;
			indexp++;
			break;
		case HDRTYPE_I18NSTRING:
		case HDRTYPE_STRING:
			while(((storep-store)+strlen(tag->value)+1+8) > store_len) {
				off_t poffset;
				poffset = storep-store;
				store_len += 1024;
				store = realloc(store, store_len);
				storep = store + poffset;
			}
			
			strcpy(storep, tag->value);
			storep += (strlen(tag->value)+1);
			indexp++;
			break;
		case HDRTYPE_BIN:
			len = (strlen(tag->value)+1)/2;
			indexp->count = htonl(len);
			if(conf.verbose > 2)
				fprintf(stderr, "bar: Writing binary of size %d bytes\n", ntohl(indexp->count));
			while(((storep-store)+len+8) > store_len) {
				off_t poffset;
				poffset = storep-store;
				store_len += 1024;
				store = realloc(store, store_len);
				storep = store + poffset;
			}
			if(hextobin(storep, (uint8_t*) tag->value, len)) {
				fprintf(stderr, "bar: Failed to convert hex to binary.\n");
				return -1;
			}
			storep += len;
			indexp++;
			break;
		case HDRTYPE_INT32:
			while(((storep-store)+tag->count*sizeof(int32_t)+8) > store_len) {
				off_t poffset;
				poffset = storep-store;
				store_len += 1024;
				store = realloc(store, store_len);
				storep = store + poffset;
			}
			
			if(conf.verbose > 2)
				fprintf(stderr, "bar: Writing 32bit value to alignment: %d\n", ((storep-store)) % 4);
			
			{
				char *p;
				p = tag->value;
				for(i=0;i<tag->count;i++) {
					int32_t value;
					if(!p) {
						fprintf(stderr, "bar: Error writing INT32 array. count=%d\n", tag->count);
						return -1;
					}
					value = strtol(p, (void*)0, 10);
					*(int32_t*)storep = htonl(value);
					storep += 4;
					p = strchr(p, '\n');
					if(p) p++;
				}
			}
			indexp++;
			break;
		case HDRTYPE_INT16:
			while(((storep-store)+tag->count*sizeof(int16_t)+8) > store_len) {
				off_t poffset;
				poffset = storep-store;
				store_len += 1024;
				store = realloc(store, store_len);
				storep = store + poffset;
			}
			
			if(conf.verbose > 2)
				fprintf(stderr, "bar: Writing 16bit value to alignment: %d\n", ((storep-store)) % 2);
			
			{
				char *p;
				p = tag->value;
				for(i=0;i<tag->count;i++) {
					int16_t value;
					if(!p) {
						fprintf(stderr, "bar: Error writing INT16 array. count=%d\n", tag->count);
						return -1;
					}
					value = strtol(p, (void*)0, 10);
					*(int16_t*)storep = htons(value);
					storep += 2;
					p = strchr(p, '\n');
					if(p) p++;
				}
			}
			indexp++;
			break;
		default:
			fprintf(stderr, "bar: Unsupported tag type: %d\n", tag->type);
			return -1;
			break;
		}
		if(conf.verbose > 2)
			fprintf(stderr, "bar: Current store size: %d bytes\n", storep-store);
	}

	/* set size of store */
	hdr->size = htonl(storep-store);

	if(conf.verbose > 2)
		fprintf(stderr, "bar: Writing index header sized: %d bytes\n", sizeof(struct header));
	if(write(fd, hdr, sizeof(struct header))!= sizeof(struct header)) {
		fprintf(stderr, "bar: Failed to write signature header\n");
                return -1;
	}

	if(conf.verbose > 2)
		fprintf(stderr, "bar: Writing index sized: %d bytes\n", tags->len * sizeof(struct indexentry));
	write(fd, index, tags->len * sizeof(struct indexentry));
	
	/* align */
	if(align) {
		i = (ntohl(hdr->size)+7)&~0x7; /* adjust to even 8-byte boundary */
		if(conf.verbose > 1) printf("Aligned[8] %d to %d\n", ntohl(hdr->size), i);
	}
	else
		i = ntohl(hdr->size);
	
	/* record positions of certain sigtag values, for later filling in of correct contents */
	pos = lseek(fd, 0, SEEK_CUR);
	if(off_md5 != -1) rpm->sigtag_md5sum = off_md5 + pos;
	if(off_size != -1) rpm->sigtag_size = off_size + pos;
	if(off_sumsize != -1) rpm->rpmtag_size = off_sumsize + pos;
	if(off_payloadsize != -1) rpm->sigtag_payloadsize = off_payloadsize + pos;

	/* write store */
	if(conf.verbose > 2)
		fprintf(stderr, "bar: Writing store sized: %d bytes\n", i);
	if(write(fd, store, i)!=i) {
		fprintf(stderr, "bar: Failed to write signature store\n");
		return -1;
	}

	return 0;
}

static int rpm_sig_write(int fd, struct rpm *rpm)
{
	int rc;
	rc = rpm_hdr_write(fd, rpm, &rpm->sig, rpm->sigtags, 1);
	rpm->headeroffset = lseek(fd, 0, SEEK_CUR);
	if(conf.verbose > 2) {
		fprintf(stderr, "bar: SIGTAG: md5sum value at file offset: %ju\n", rpm->sigtag_md5sum);
		fprintf(stderr, "bar: SIGTAG: size value at file offset: %ju\n", rpm->sigtag_size);
		fprintf(stderr, "bar: SIGTAG: payloadsize value at file offset: %ju\n", rpm->sigtag_payloadsize);
	}
	return rc;
}

static int rpm_header_write(int fd, struct rpm *rpm)
{
	int rc;
	rc = rpm_hdr_write(fd, rpm, &rpm->header, rpm->tags, 0);
	rpm->payloadoffset = lseek(fd, 0, SEEK_CUR);
	if(conf.verbose > 2) {
		fprintf(stderr, "bar: RPMTAG: sumsize value at file offset: %ju\n", rpm->rpmtag_size);
	}
	return rc;
}

static int rpm_sig_rewrite(int fd, struct rpm *rpm)
{
	uint32_t val;
	
	if(lseek(fd, rpm->sigtag_size, SEEK_SET)==-1) {
		fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->sigtag_size);
		return -1;
	}
	if(conf.verbose > 1)
		fprintf(stderr, "bar: Rewriting SIGTAG_SIZE to %ju - %ju = %ju\n",
			rpm->eofoffset, rpm->headeroffset, rpm->eofoffset - rpm->headeroffset);
	val = htonl(rpm->eofoffset - rpm->headeroffset);
	write(fd, &val, 4);

	if(lseek(fd, rpm->sigtag_payloadsize, SEEK_SET)==-1) {
		fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->sigtag_payloadsize);
		return -1;
	}
	val = htonl(rpm->uncompressed_size);
	write(fd, &val, 4);

	if(lseek(fd, rpm->rpmtag_size, SEEK_SET)==-1) {
		fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->rpmtag_size);
		return -1;
	}
	val = htonl(rpm->sumsize);
	write(fd, &val, 4);

	/* calculate RPMSIGTAG_MD5 
	 *  This tag specifies the 128-bit MD5 checksum of the combined Header and Archive sections.
	 */
	if(lseek(fd, rpm->headeroffset, SEEK_SET)==-1) {
                fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->headeroffset);
                return -1;
        }
	{
		ssize_t n;
		unsigned char buf[1024];
		struct digest d;

		if(digest(&d, "md5")) {
                        fprintf(stderr, "bar: MD5Init failed.\n");
                        return -1;
                }
		while(1) {
                        n = read(fd, buf, sizeof(buf));
                        if(n < 1) break;
                        d.update(&d, buf, n);
                }
                d.final(&d);

		if(lseek(fd, rpm->sigtag_md5sum, SEEK_SET)==-1) {
			fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->sigtag_md5sum);
			return -1;
		}
		if(conf.verbose > 1) {
			fprintf(stderr, "bar: Rewriting SIGTAG_MD5\n");
		}
		write(fd, d.binary, d.size);
	}
	return 0;
}

static int bar_create(const char *archive, struct jlhead *files, int *err)
{
	int fd;
	struct rpm *rpm;
	struct tag *tag;
	struct cpio_file *f;
	char *p;
	
	rpm = rpm_new();

        /* SIGTAG_SIZE: internal Header+Payload size (32bit) in bytes */
	tag = tag_new(SIGTAG_SIZE);
	tag->value = "0";
	tag->type = HDRTYPE_INT32;
	tag->track = 1;
	jl_append(rpm->sigtags, tag);
	
	/* SIGTAG_MD5 */
	tag = tag_new(SIGTAG_MD5);
	tag->value = "178e7818ef31bd94a342b9feef0d3da8";
	tag->type = HDRTYPE_BIN;
	tag->track = 1;
	jl_append(rpm->sigtags, tag);

	/* SIGTAG_PAYLOADSIZE: internal uncompressed payload size (32bit) in bytes */
	tag = tag_new(SIGTAG_PAYLOADSIZE);
	tag->value = "0";
	tag->type = HDRTYPE_INT32;
	tag->track = 1;
	jl_append(rpm->sigtags, tag);
	
	tag = tag_new(RPMTAG_NAME);
	tag->value = conf.tag.name;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_VERSION);
	tag->value = conf.tag.version;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_RELEASE);
	tag->value = conf.tag.release;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_SUMMARY);
	tag->value = conf.tag.summary;
        tag->type = HDRTYPE_I18NSTRING;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_DESCRIPTION);
	tag->value = conf.tag.description;
        tag->type = HDRTYPE_I18NSTRING;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_BUILDTIME);
	tag->value = conf.tag.buildtime;
	tag->type = HDRTYPE_INT32;
	jl_append(rpm->tags, tag);


	/*
	RPMTAG_SIZE INT32 This tag specifies the sum of the sizes of the regular files in the archive.
	*/	
	tag = tag_new(RPMTAG_SIZE);
	tag->value = "0";
	tag->track = 1;
	tag->type = HDRTYPE_INT32;
	jl_append(rpm->tags, tag);

	/* RPMTAG_COPYRIGHT 1014 */
	tag = tag_new(RPMTAG_COPYRIGHT);
	tag->value = conf.tag.license;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_GROUP);
	tag->value = conf.tag.group;
        tag->type = HDRTYPE_I18NSTRING;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_OS);
	tag->value = conf.tag.os;
        jl_append(rpm->tags, tag);

	/* RPMTAG_ARCH 1022 */
	tag = tag_new(RPMTAG_ARCH);
	tag->value = conf.tag.arch;
        jl_append(rpm->tags, tag);

	/* RPMTAG_PREIN 1023 */
	if(conf.tag.prein) {
		tag = tag_new(RPMTAG_PREIN);
		tag->value = conf.tag.prein;
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_POSTIN 1024 */
	if(conf.tag.postin) {
		tag = tag_new(RPMTAG_POSTIN);
		tag->value = conf.tag.postin;
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_PREUN 1025 */
	if(conf.tag.preun) {
		tag = tag_new(RPMTAG_PREUN);
		tag->value = conf.tag.preun;
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_POSTUN 1026 */
	if(conf.tag.postun) {
		tag = tag_new(RPMTAG_POSTUN);
		tag->value = conf.tag.postun;
		jl_append(rpm->tags, tag);
	}
	
	/* RPMTAG_FILENAMES 1027 */
	tag = tag_new(RPMTAG_FILENAMES);
	tag->type = HDRTYPE_STRARRAY;
	tag->count = files->len;
	tag->size = 0;
	jl_foreach(files, f) {
		tag->size += (strlen(f->normalized_name)+1);
	}
	tag->value = malloc(tag->size);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, f->normalized_name);
		p += (strlen(f->normalized_name)+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILESIZES */
	tag = tag_new(RPMTAG_FILESIZES);
	tag->type = HDRTYPE_INT32;
	tag->count = files->len;
	tag->value = malloc(files->len * 12);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%ju\n", f->stat.st_size);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILEMODES */
	tag = tag_new(RPMTAG_FILEMODES);
	tag->type = HDRTYPE_INT16;
	tag->count = files->len;
	tag->value = malloc(files->len * 7);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%u\n", f->stat.st_mode);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);	

	/* RPMTAG_FILERDEVS */
	tag = tag_new(RPMTAG_FILERDEVS);
	tag->type = HDRTYPE_INT16;
	tag->count = files->len;
	tag->value = malloc(files->len * 7);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%lld\n", f->stat.st_rdev);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);	

	/* RPMTAG_FILEMTIMES */
	tag = tag_new(RPMTAG_FILEMTIMES);
	tag->type = HDRTYPE_INT32;
	tag->count = files->len;
	tag->value = malloc(files->len * 12);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%ld\n", f->stat.st_mtime);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILEMD5S STRING_ARRAY */
	tag = tag_new(RPMTAG_FILEMD5S);
	tag->type = HDRTYPE_STRARRAY;
	tag->count = files->len;
	tag->size = 0;
	jl_foreach(files, f) {
		tag->size += (strlen(f->md5)+1);
	}
	tag->value = malloc(tag->size);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, f->md5);
		p += (strlen(f->md5)+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILELINKTOS STRING_ARRAY */
	tag = tag_new(RPMTAG_FILELINKTOS);
	tag->type = HDRTYPE_STRARRAY;
	tag->count = files->len;
	tag->size = 0;
	jl_foreach(files, f) {
		tag->size += (strlen(f->link)+1);
	}
	tag->value = malloc(tag->size);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, f->link);
		p += (strlen(f->link)+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILEFLAGS 1037 INT32, '0' is fine 
	 * http://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/pkgformat.html
	 */
	tag = tag_new(RPMTAG_FILEFLAGS);
	tag->type = HDRTYPE_INT32;
	tag->count = files->len;
	tag->value = malloc(files->len * 12);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%d\n", f->fileflags);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILEUSERNAME 1039 STRING_ARRAY */
	tag = tag_new(RPMTAG_FILEUSERNAME);
	tag->type = HDRTYPE_STRARRAY;
	tag->count = files->len;
	tag->size = 0;
	jl_foreach(files, f) {
		tag->size += (strlen(f->user)+1);
	}
	tag->value = malloc(tag->size);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, f->user);
		p += (strlen(f->user)+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILEGROUPNAME 1040 STRING_ARRAY */
	tag = tag_new(RPMTAG_FILEGROUPNAME);
	tag->type = HDRTYPE_STRARRAY;
	tag->count = files->len;
	tag->size = 0;
	jl_foreach(files, f) {
		tag->size += (strlen(f->group)+1);
	}
	tag->value = malloc(tag->size);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, f->group);
		p += (strlen(f->group)+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_SOURCERPM                1044 */
	tag = tag_new(RPMTAG_SOURCERPM);
	tag->value = "None";
        jl_append(rpm->tags, tag);
	
	if(conf.requires) {
		int i;
		struct req *req;
		
		/* RPMTAG_REQUIREFLAGS 1048 */
		tag = tag_new(RPMTAG_REQUIREFLAGS);
		tag->type = HDRTYPE_INT32;
		tag->count = conf.requires->len;
		tag->value = malloc(conf.requires->len * 12);
		if(!tag->value) {
			fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
			return -1;
		}
		p = tag->value;
		for(i=0;i<conf.requires->len;i++) {
			sprintf(p, "%d\n", RPMSENSE_GREATER|RPMSENSE_EQUAL);
			p += strlen(p);
		}
		jl_append(rpm->tags, tag);
		
		/* RPMTAG_REQUIRENAME 1049 */
		tag = tag_new(RPMTAG_REQUIRENAME);
		tag->type = HDRTYPE_STRARRAY;
		tag->count = conf.requires->len;
		tag->size = 0;
		jl_foreach(conf.requires, req) {
			tag->size += (strlen(req->name)+1);
		}
		tag->value = malloc(tag->size);
		if(!tag->value) {
			fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
			return -1;
		}
		p = tag->value;
		jl_foreach(conf.requires, req) {
			strcpy(p, req->name);
			p += (strlen(p)+1);
		}
		jl_append(rpm->tags, tag);

		/* RPMTAG_REQUIREVERSION 1050 */
		tag = tag_new(RPMTAG_REQUIREVERSION);
		tag->type = HDRTYPE_STRARRAY;
		tag->count = conf.requires->len;
		tag->size = 0;
		jl_foreach(conf.requires, req) {
			tag->size += (strlen(req->version)+1);
		}
		tag->value = malloc(tag->size);
		if(!tag->value) {
			fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
			return -1;
		}
		p = tag->value;
		jl_foreach(conf.requires, req) {
			strcpy(p, req->version);
			p += (strlen(p)+1);
		}
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_PREINPROG 1085 */
	if(conf.tag.prein) {
		tag = tag_new(RPMTAG_PREINPROG);
		tag->value = "/bin/sh";
		jl_append(rpm->tags, tag);
	}
	
	/* RPMTAG_POSTINPROG 1086 */
	if(conf.tag.postin) {
		tag = tag_new(RPMTAG_POSTINPROG);
		tag->value = "/bin/sh";
		jl_append(rpm->tags, tag);
	}
	
        /* RPMTAG_PREUNPROG 1087 */
	if(conf.tag.preun) {
		tag = tag_new(RPMTAG_PREUNPROG);
		tag->value = "/bin/sh";
		jl_append(rpm->tags, tag);
	}

        /* RPMTAG_POSTUNPROG 1088 */
	if(conf.tag.postun) {
		tag = tag_new(RPMTAG_POSTUNPROG);
		tag->value = "/bin/sh";
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_FILEDEVICES 1095 INT32 */
	tag = tag_new(RPMTAG_FILEDEVICES);
	tag->type = HDRTYPE_INT32;
	tag->count = files->len;
	tag->value = malloc(files->len * 12);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%lld\n", f->stat.st_dev);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILEINODES 1096 INT32 */
	tag = tag_new(RPMTAG_FILEINODES);
	tag->type = HDRTYPE_INT32;
	tag->count = files->len;
	tag->value = malloc(files->len * 12);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "%llu\n", f->stat.st_ino);
		p += strlen(p);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_FILELANGS 1097 STRING_ARRAY */
	tag = tag_new(RPMTAG_FILELANGS);
	tag->type = HDRTYPE_STRARRAY;
	tag->count = files->len;
	tag->size = 0;
	jl_foreach(files, f) {
		tag->size += (strlen("")+1);
	}
	tag->value = malloc(tag->size);
	if(!tag->value) {
		fprintf(stderr, "bar: Failed to allocate buffer for tag value\n");
		return -1;
	}
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, "");
		p += (strlen("")+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_PAYLOADFORMAT */
	tag = tag_new(RPMTAG_PAYLOADFORMAT);
	tag->value = "cpio";
	jl_append(rpm->tags, tag);

	/* RPMTAG_PAYLOADCOMPRESSOR */
	tag = tag_new(RPMTAG_PAYLOADCOMPRESSOR);
	tag->value = "gzip";
	jl_append(rpm->tags, tag);

	/* RPMTAG_PAYLOADFLAGS 1126 */
	tag = tag_new(RPMTAG_PAYLOADFLAGS);
	tag->value = "9";
	jl_append(rpm->tags, tag);

	/* RPMTAG_PRETRANS 1151 */
	if(conf.tag.pretrans) {
		tag = tag_new(RPMTAG_PRETRANS);
		tag->value = conf.tag.pretrans;
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_POSTTRANS 1152 */
	if(conf.tag.posttrans) {
		tag = tag_new(RPMTAG_POSTTRANS);
		tag->value = conf.tag.posttrans;
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_PRETRANSPROG 1153 */
	if(conf.tag.pretrans) {
		tag = tag_new(RPMTAG_PRETRANSPROG);
		tag->value = "/bin/sh";
		jl_append(rpm->tags, tag);
	}

	/* RPMTAG_POSTTRANSPROG 1154 */
	if(conf.tag.posttrans) {
		tag = tag_new(RPMTAG_POSTTRANSPROG);
		tag->value = "/bin/sh";
		jl_append(rpm->tags, tag);
	}

	fd = open(archive, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if(fd == -1) return -1;

	strncpy(rpm->lead.name, conf.tag.name, sizeof(rpm->lead)-1);
	rpm->lead.major = 3;
	rpm->lead.minor = 0;
	rpm->lead.archnum = htons(ARCHNUM_X86);
	rpm->lead.osnum = htons(OSNUM_LINUX);
	rpm->lead.signature_type = htons(RPMSIGTYPE_HEADERSIG);

	if(rpm_lead_write(fd, rpm)) return -1;
        if(rpm_sig_write(fd, rpm)) return -1;
        if(rpm_header_write(fd, rpm)) return -1;

        if(rpm_payload_write(fd, rpm, files)) return -1;
	
	if(rpm_sig_rewrite(fd, rpm)) return -1;
	
	close(fd);
	*err = 0;
	return 0;
}

static int file_new(struct jlhead *files, const char *fn, int create, struct filespec *spec)
{
	struct cpio_file *f;
	int fd;
	ssize_t n;
	unsigned char buf[PATH_MAX];
	struct digest d;
	
	f = malloc(sizeof(struct cpio_file));
	if(!f) {
		fprintf(stderr, "bar: failed to malloc memory: ");
		fprintf(stderr, "%s\n", fn);
		return -1;
	}
	
	f->name = strdup(fn);
	f->fileflags = spec->flags;
	
	/* normalize name to always start with '/' */
	if(*fn != '/') {
		if(strncmp(fn, "./", 2)==0) {
			f->normalized_name = strdup(fn+1);
		} else {
			sprintf((char*) buf, "/%s", fn);
			f->normalized_name = strdup((char*)buf);
		}
	} else {
		f->normalized_name = strdup(fn);
	}
	if(!create) {
		/* we are done. no need to fetch additional file info when not creating an archive */
		if(jl_ins(files, f)) {
                        fprintf(stderr, "bar: list insert failed for %s\n", f->name);
			return -1;
                }
		return 0;
	}

	if(conf.verbose > 2) {
		fprintf(stderr, "bar: processing file %s\n", f->name);
	}

	{
		char *prefix = (void*) 0;
		if(conf.opt.prefix) prefix = conf.opt.prefix;
		if(spec->prefix) prefix = spec->prefix;
		if(prefix) {
			char *p;
			p = malloc(strlen(prefix)+strlen(f->normalized_name)+1);
			if(!p) {
				fprintf(stderr, "bar: failed to malloc memory for prefixed filename: ");
				fprintf(stderr, "%s\n", f->name);
				return -1;
			}
			strcpy(p, prefix);
			strcat(p, f->normalized_name);
			f->normalized_name = p;
		}
	}
	
	/* Names in the cpio archive should start with "./" */
	f->cpio_name = malloc(strlen(f->normalized_name)+2);
	if(!f->cpio_name) {
		fprintf(stderr, "bar: failed to malloc memory for filename with ./ prefix: ");
		fprintf(stderr, "%s\n", f->normalized_name);
		return -1;
	}
	strcpy(f->cpio_name+1, f->normalized_name);
	*f->cpio_name = '.';
	
	if(lstat(f->name, &f->stat)) {
		fprintf(stderr, "bar: Failed to lstat %s\n", f->name);
		return -1;
	}
	
	f->md5 = malloc(DIGEST_MAX_HEX_SIZE);
	if(!f->md5) {
		fprintf(stderr, "bar: failed to malloc memory for md5 computation: ");
		fprintf(stderr, "%s\n", f->name);
		return -1;
	}
	strcpy(f->md5, ""); /* empty by default. only regular files */
	
	if(conf.verbose > 2) {
		fprintf(stderr, "bar: assigning user and group ownership to %s\n", f->name);
	}

	if(conf.tag.fuser)
		f->user = conf.tag.fuser;
	else {
		f->user = "root";
		{
			struct passwd *pw;
			pw = getpwuid(f->stat.st_uid);
			if(pw) {
				if(strlen(pw->pw_name))
					f->user = strdup(pw->pw_name);
			}
		}
	}
	if(conf.tag.fgroup)
		f->group = conf.tag.fgroup;
	else {
		f->group = "root";
		{
			struct group *gr;
			gr = getgrgid(f->stat.st_gid);
			if(gr) {
				if(strlen(gr->gr_name))
					f->group = strdup(gr->gr_name);
			}
		}
	}
	f->link = "";

	if(spec->user) f->user = spec->user;
	if(spec->group) f->group = spec->group;
	if(conf.verbose > 2) {
		fprintf(stderr, "bar: %s:%s %s\n", f->user, f->group, f->name);
	}

	if(S_ISLNK(f->stat.st_mode)) {
		if(conf.verbose > 2) {
			fprintf(stderr, "bar: processing link file  %s\n", f->name);
		}
		n = readlink(f->name, (char*)buf, sizeof(buf)-1);
		if(n == -1) {
			fprintf(stderr, "bar: Failed to read link %s\n", f->name);
			return -1;
		}
		buf[n] = 0;
		f->link = strdup((char*)buf);
	}
	
	if(S_ISREG(f->stat.st_mode)) {
		if(conf.verbose > 2) {
			fprintf(stderr, "bar: processing regular file %s\n", f->name);
		}

		fd = open(f->name, O_RDONLY);
		if(fd == -1) {
			fprintf(stderr, "bar: Failed to open file %s\n", f->name);
			return -1;
		}
		
		if(digest(&d, "md5")) {
			fprintf(stderr, "bar: MD5Init failed.\n");
			close(fd);
			return -1;
		}
		while(1) {
			n = read(fd, buf, sizeof(buf));
			if(n < 1) break;
			d.update(&d, buf, n);
		}
		close(fd);
		d.final(&d);
		strcpy(f->md5, d.hexstr);
	}
	if(conf.verbose > 2) {
		fprintf(stderr, "bar: Added file: %s md5sum: %s\n", f->name, f->md5);
	}

	if(spec->recursive && S_ISDIR(f->stat.st_mode)) {
		DIR *dir;
		struct dirent *ent;
		
		if(conf.verbose > 2) {
			fprintf(stderr, "bar: recursive decent into directory %s\n", f->name);
		}

		if(jl_ins(files, f)) {
			fprintf(stderr, "bar: list insert failed for %s\n", f->name);
			return -1;
		}
		
		if(!(dir = opendir(fn))) {
			fprintf(stderr, "bar: Failed to open dir %s\n", fn);
			return -1;
		}
		while((ent = readdir(dir))) {
			if(!strcmp(ent->d_name, ".")) continue;
			if(!strcmp(ent->d_name, "..")) continue;
			
			if(strlen(fn)+strlen(ent->d_name) > (sizeof(buf)-1)) {
				fprintf(stderr, "bar: File path to long.\n");
				closedir(dir);
				return -1;
			}
			
			snprintf((char*)buf, sizeof(buf), "%s/%s", fn, ent->d_name);
			if(file_new(files, (char*)buf, create, spec)) {
				fprintf(stderr, "bar: Failed to add file %s\n", buf);
				closedir(dir);
				return -1;
			}
		}
		closedir(dir);
		return 0;
	}

	if(jl_ins(files, f)) {
		fprintf(stderr, "bar: list insert failed for %s\n", f->name);
		return -1;
	}
	return 0;
}

int sort_files(const void *a, const void *b)
{
	return strcmp(((struct cpio_file*)a)->normalized_name, ((struct cpio_file*)b)->normalized_name);
}


int barlog_pre()
{
	return fprintf(stderr, "bar: ");
}

int barlog_post()
{
	return fprintf(stderr, "\n");
}

int barlog_log(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	
	return vfprintf(stderr, fmt, ap);
}

int barlog_logln(const char *fmt, ...)
{
	int n;
	va_list ap;
	va_start(ap, fmt);
	
	n = barlog_pre();
	n += vfprintf(stderr, fmt, ap);
	n += barlog_post();
	return n;
}

int main(int argc, char **argv)
{
	int err=0, rc=2, i;
	char *archive;
	struct jlhead *files;

	files = jl_new();
	jl_sort(files, sort_files);
	
	i=256;
	conf.opt.cwd = malloc(i);
	while(!getcwd(conf.opt.cwd, i)) {
		i = i*2;
		conf.opt.cwd = realloc(conf.opt.cwd, i);
		if(!conf.opt.cwd) exit(2);
	}

	conf.opt.prefix = 0;
	
	{
		struct utsname buf;
		if(uname(&buf)) {
			conf.tag.arch = "noarch"; /* x86_64 i586 noarch */
			conf.tag.os = "Linux";
		} else {
			conf.tag.arch = strdup(buf.machine);
			conf.tag.os = strdup(buf.sysname);
		}
	}
	conf.tag.summary = "None";
	conf.tag.description = "None";
	conf.tag.group = "None";
	conf.tag.license = "GPLv2+";
	conf.tag.version = "0";
	{
		struct tm tm;
		char buf[32];
		time_t now = time(0);
		if(localtime_r(&now, &tm)) {
			sprintf(buf, "%d%02d%02d.%02d%02d%02d",
				tm.tm_year+1900,
				tm.tm_mon+1,
				tm.tm_mday,
				tm.tm_hour,
				tm.tm_min,
				tm.tm_sec);
			conf.tag.release = strdup(buf);
		} else {
			conf.tag.release = "0";
		}
	}
	conf.tag.fuser = (void*)0;
	conf.tag.fgroup = (void*)0;
	{
		char buf[32];
		sprintf(buf, "%d", (int)time(0));
		conf.tag.buildtime = strdup(buf);
	}

	conf.quotechar = '%';
	conf.opt.sync = 1;
	
	if(jelopt(argv, 0, "examples", 0, &err)) {
		printf("Examples: \n"
		       " Listing contents:\n"
		       "  $ bar -lv archive.rpm\n"
		       " Creating an archive:\n"
		       "  $ bar -cr archive.rpm /file/path\n"
		       " Advanced archive creation:\n"
		       "  $ bar	\\\n"
		       "     --license=GPLv2+\\\n"
		       "     --summary \"My archive named 'archive'\"\\\n"
		       "     --group=Applications/Internet\\\n"
		       "     --description \"Text%%nSecond line.%%nThird line\"\\\n"
		       "     --prefix=/path/to/prepend\\\n"
		       "     --fuser=myuser --fgroup=users\\\n"
		       "     --version=3.0.0\\\n"
		       "     --release=1\\\n"
		       "     --arch=noarch\\\n"
		       "     --name=archive\\\n"
		       "     --postin \"echo post_install%%necho line2%%n\"\\\n"
		       "     -cr archive-3.0.0-1.noarch.rpm path1 path2\n"
		       " Marking a configuration file:\n"
		       "  $ bar -c archive.rpm config::etc/config\n"
		       " Specifying owner:\n"
		       "  $ bar -c archive.rpm owner@wheel:wheel::etc/config\n"
		       " Specify package requirement:\n"
		       "  $ bar -c a.rpm --require bash 4.0.0-1\n"
			);
		exit(0);
	}
	if(jelopt(argv, 'h', "help", 0, &err)) {
	usage:
		printf("bar [-hriclxv] archive-file [path ..]\n"
		       " h -- help\n"
		       " r -- recursive\n"
		       " c -- create\n"
		       " x -- extract\n"
		       " l -- list\n"
		       " i -- show header info\n"
		       " v -- verbose\n"
		       "\n"
		       " Overriding default tag values:\n"
		       " --arch <archname>      [from uname]\n"
		       " --buildtime <unixtime> [current time]\n"
		       " --description <string> [None]\n"
		       " --fgroup <groupname>   [file owner]\n"
		       " --fuser <username>     [file owner]\n"
		       " --group <packagegroup> [None]\n"
		       " --license <string>     [GPLv2+]\n"
		       " --name <string>        [from archive-file name]\n"
		       " --os <osname>          [from uname]\n"
		       " --prein <string>       pre install script\n"
		       " --preun <string>       pre uninstall script\n"
		       " --pretrans <string>    pre transaction script\n"
		       " --postin <string>      post install script\n"
		       " --postun <string>      post uninstall script\n"
		       " --posttrans <string>   post transaction script\n"
		       " --release <string>     [current date and time YYYYMMDD.HHMMSS]\n"
		       " --require <pkgname> <pkgversion>\n"
		       " --summary <string>     [None]\n"
		       " --version <string>     [0]\n"
		       "\n"
		       " Create/extract options:\n"
		       " --prefix <path>        add prefix <path> to all filepaths\n"
		       " --nosum                ignore checksums\n"
		       " --nosync               do not sync to disk while writing\n"
		       " --quotechar <char>     [%%] used for inserting special chars\n"
		       " --printtag <tag number>\n"
		       "\n"
		       " Package handler information:\n"
		       " --pkginfo\n"
		       "\n"
		       " Examples:\n"
		       " --examples\n"
		       "\n"
		       " 'path' can be prefixed with one or more of:\n"
		       " config::               Mark as configfile\n"
		       " noreplace::            Mark as configfile and not to be replaced\n"
		       " missingok::            Mark as missingok\n"
		       " owner@USER:GROUP::     Specify owner of files\n"
		       " prefix/PATH::          Add path prefix\n"
		       " r::                    Recursive descent into path\n"
		       " nor::                  No recursive descent into path\n"
			);
		exit(rc);
	}
	while(jelopt(argv, 'r', "recursive", 0, &err)) conf.recursive=1;
	while(jelopt(argv, 'c', "create", 0, &err)) conf.create=1;
	while(jelopt(argv, 'i', "info", 0, &err)) conf.extract=conf.opt.info=1;
	while(jelopt(argv, 'l', "list", 0, &err)) conf.extract=conf.opt.list=1;
	while(jelopt(argv, 'x', "extract", 0, &err)) conf.extract=1;
	while(jelopt(argv, 'v', "verbose", 0, &err)) conf.verbose++;
	while(jelopt(argv, 'V', "verify", 0, &err)) conf.verify=1;
	while(jelopt(argv, 0, "arch", &conf.tag.arch, &err));
	while(jelopt(argv, 0, "buildtime", &conf.tag.buildtime, &err));
	while(jelopt(argv, 0, "fgroup", &conf.tag.fgroup, &err));
	while(jelopt(argv, 0, "fuser", &conf.tag.fuser, &err));
	while(jelopt(argv, 0, "license", &conf.tag.license, &err));
	while(jelopt(argv, 0, "name", &conf.tag.name, &err));
	while(jelopt(argv, 0, "os", &conf.tag.os, &err));
	{
		char *tmp;
		while(jelopt(argv, 0, "quotechar", &tmp, &err))
			if(tmp) conf.quotechar = *tmp;
	}
	while(jelopt(argv, 0, "prein", &conf.tag.prein, &err))
		conf.tag.prein = dequote(conf.tag.prein);
	while(jelopt(argv, 0, "preun", &conf.tag.preun, &err))
		conf.tag.preun = dequote(conf.tag.preun);
	while(jelopt(argv, 0, "pretrans", &conf.tag.pretrans, &err))
		conf.tag.pretrans = dequote(conf.tag.pretrans);
	while(jelopt(argv, 0, "postin", &conf.tag.postin, &err))
		conf.tag.postin = dequote(conf.tag.postin);
	while(jelopt(argv, 0, "postun", &conf.tag.postun, &err))
		conf.tag.postun = dequote(conf.tag.postun);
	while(jelopt(argv, 0, "posttrans", &conf.tag.posttrans, &err))
		conf.tag.posttrans = dequote(conf.tag.posttrans);
	while(jelopt(argv, 0, "release", &conf.tag.release, &err));
	while(jelopt(argv, 0, "version", &conf.tag.version, &err));
	while(jelopt(argv, 0, "description", &conf.tag.description, &err))
		conf.tag.description = dequote(conf.tag.description);
	while(jelopt(argv, 0, "group", &conf.tag.group, &err))
		conf.tag.group = dequote(conf.tag.group);
	while(jelopt(argv, 0, "summary", &conf.tag.summary, &err))
		conf.tag.summary = dequote(conf.tag.summary);
	while(jelopt(argv, 0, "pkginfo", NULL, &err)) conf.opt.pkginfo=conf.verbose=1;
	while(jelopt_int(argv, 0, "printtag", &conf.opt.printtag, &err));
	while(jelopt(argv, 0, "nosum", NULL, &err)) conf.opt.ignore_chksum=1;
	while(jelopt(argv, 0, "nosync", NULL, &err)) conf.opt.sync=0;
	while(jelopt(argv, 0, "prefix", &conf.opt.prefix, &err)) {
		int len = strlen(conf.opt.prefix);
		if(len)
			if(conf.opt.prefix[len-1] == '/')
				conf.opt.prefix[len-1] = 0;
	}
	{
		char *values[3];
		while(jelopt_multi(argv, 0, "require", 2, values, &err)) {
			struct req *req;
			if(!conf.requires) {
				conf.requires = jl_new();
			}
			
			req = malloc(sizeof(struct req));
			req->name = strdup(values[0]);
			req->version = strdup(values[1]);
			jl_append(conf.requires, req);
		}
	}
	
	conf.log.level = conf.verbose;
	conf.log.pre = &barlog_pre;
	conf.log.post = &barlog_post;
	conf.log.log = &barlog_log;
	conf.log.logln = &barlog_logln;
	
	argc = jelopt_final(argv, &err);
	if(err) {
		fprintf(stderr, "bar: Syntax error in options: %d\n", err);
		exit(2);
	}
	if(conf.create+conf.extract+conf.verify > 1) {
		fprintf(stderr, "bar: You must specify exactly one of [cxli]\n");
		exit(2);
	}
	if(conf.create+conf.extract+conf.verify == 0) {
		fprintf(stderr, "bar: You must specify one of [cxli]\n");
		exit(2);
	}
	if(argc < 2) {
		fprintf(stderr, "bar: You must specify archive-file.\n");
	}
	rc=2;
	
	archive = strdup(argv[1]);
	if(!conf.create) {
		if(ftest(archive, S_IFREG)) {
			fprintf(stderr, "bar: '%s' is not a regular file.\n", archive);
			exit(2);
		}
	}
	if(conf.create) {
		if(ftest(archive, 0777777) != -1) {
			fprintf(stderr, "bar: Archive file '%s' already exists.\n", archive);
			exit(2);
		}
	}
	
	if(!conf.tag.name) {
		char *p;
		conf.tag.name = strdup(archive);
		p = strrchr(conf.tag.name, '.');
		if(p && (strcmp(p, ".rpm")==0)) *p = 0;
	}


	for(i=2;i<argc;i++) {
		struct filespec spec;
		char *p;
		spec.flags = 0;
		spec.user = (void*)0;
		spec.group = (void*)0;
		spec.prefix = (void*)0;
		spec.recursive = conf.recursive;
		p = argv[i];
		while(1) {
			if(!strncmp(p, "config::", 8)) {
				spec.flags = RPMFILE_CONFIG;
				p+=8;
				continue;
			}
			if(!strncmp(p, "noreplace::", 11)) {
				spec.flags = RPMFILE_CONFIG|RPMFILE_NOREPLACE;
				p+=11;
				continue;
			}
			if(!strncmp(p, "missingok::", 11)) {
				spec.flags = RPMFILE_MISSINGOK;
				p+=11;
				continue;
			}
			if(!strncmp(p, "r::", 3)) {
				spec.recursive = 1;
				p+=3;
				continue;
			}
			if(!strncmp(p, "nor::", 5)) {
				spec.recursive = 0;
				p+=5;
				continue;
			}
			if(!strncmp(p, "owner@", 6)) {
				char *end;
				p+=6;
				spec.user = strdup(p);
				spec.group = strchr(spec.user, ':');
				if(!spec.group) break;
				*(spec.group) = 0;
				spec.group++;
				p = strstr(p, "::");
				if(!p) break;
				end = strstr(spec.group, "::");
				*end=0;
				p += 2;
				if(conf.verbose > 2) printf("spec.user = '%s'\n", spec.user);
				if(conf.verbose > 2) printf("spec.group = '%s'\n", spec.group);
				continue;
			}
			if(!strncmp(p, "prefix/", 7)) {
				char *end;
				p+=6;
				end = strstr(p, "::");
				if(!end) break;
				*end=0;
				spec.prefix = strdup(p);
				{
					int len = strlen(spec.prefix);
					if(len)
						if(spec.prefix[len-1] == '/')
							spec.prefix[len-1] = 0;
				}
				p = end+2;
				if(conf.verbose > 2) printf("spec.prefix = '%s'\n", spec.prefix);
				continue;
			}
			if(file_new(files, p, conf.create, &spec)) {
				fprintf(stderr, "bar: Failed to add file %s. Aborting.\n", argv[i]);
				exit(1);
			}
			break;
		}
	}
	
	if(conf.extract) {
		err=0;
		if(bar_extract(&conf.log, archive, files, &err, &conf.opt)) {
			fprintf(stderr, "bar: '%s' extract failed\n", archive);
			exit(1);
		}
		exit(err);
	}

	if(conf.create) {
		err=0;
		if(bar_create(archive, files, &err)) {
			fprintf(stderr, "bar: '%s' create failed\n", archive);
			exit(1);
		}
		exit(err);
	}
	
	goto usage;
}
