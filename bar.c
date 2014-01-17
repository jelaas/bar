/*
 * File: bar.c
 * Implements: rpm file archive creator and extractor
 *
 * Copyright: Jens Låås, Uppsala University, 2013
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
#include <zlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include "md5.h"
#include "bar_rpm.h"
#include "bar_cpio.h"
#include "jelopt.h"
#include "jelist.h"

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
	int recursive,create,extract,verbose,verify,list,info,pkginfo;
	int ignore_chksum;
	int printtag;
	int quotechar;
	char *prefix;
	char *cwd;
	struct {
		char *arch, *buildtime, *os, *license, *version, *release, *name;
		char *fuser, *fgroup;
		char *postin, *postun;
	} tag;
} conf;

struct tag {
	int tag;
	int type;
	int track;
	int count;
	int size;
	char *value;
};

struct file {
	char *name; /* name to use for file access when creating archive */
	char *normalized_name; /* name to write in header */
	char *cpio_name; /* name to write in cpio-archive */
	struct stat stat;
	char *md5;
	char *user, *group;
	char *link;
};

struct rpm {
	struct rpmlead lead;
	struct header sig;
	struct jlhead *sigtags;
	struct header header;
	struct jlhead *tags;
	off_t headeroffset;
	off_t payloadoffset;
	off_t eofoffset;
	size_t uncompressed_size;
	size_t sumsize;
	
	/* offsets to sigtag values that can only be written after the whole payload is generated */
	off_t sigtag_md5sum;
	off_t sigtag_size;	
	off_t sigtag_payloadsize;

	/* offsets within header */
	off_t rpmtag_size;
};

struct cpio_host {
	char c_magic[6]; /* cpio: 070701 */
        uint64_t c_ino;
        uint32_t c_mode;
        uint32_t c_uid;
        uint32_t c_gid;
        uint32_t c_nlink;
	uint64_t c_mtime;
        uint64_t c_filesize;
        uint64_t c_filesize_a;
        uint32_t c_devmajor;
        uint32_t c_devminor;
	dev_t rdev;
	uint32_t c_rdevmajor;
	uint32_t c_rdevminor;
	uint32_t c_namesize;
	char *name, *mode;

	size_t uncompressed_size;
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


/* normalize name to always start with '/'
 */
const char *normalize_name(const char *fn)
{
	if(*fn == '/') return fn;
	if(strncmp(fn, "./", 2)==0) return fn+1;
	return fn;
}

int strindex(const char *lines, const char *str)
{
	char *p=(char*)lines;
	char *n;
	int i=0;

	while(p && *p) {
		n = strchr(p, '\n');
		if(n && !strncmp(p, str, n-p))
			return i;
		if(!n) {
			if(!strcmp(p, str)) return i;
			return -1;
		}
		i++;
		p = n+1;
	}
	return -1;
}

char *stratindex(const char *lines, int idx)
{
	char *p=(char*)lines;
	char *n;
	while(p && *p) {
		n = strchr(p, '\n');
		if(idx == 0) {
			if(n) return strndup(p, n-p);
			return strdup(p);
		}
		p = n;
		if(p) p++;
		idx--;
	}
	return (void*)0;
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

static int mkpath(const char *path)
{
	const char *p;
	const char *n;
	char buf[NAME_MAX+1];
	
	p = path;
	if(chdir(conf.cwd)) return -1;
	
	while(1) {
		while(*p == '/') p++;
		n = strchr(p, '/');
		if(!n) break;
		if( (n-p) >= sizeof(buf)) {
			fprintf(stderr, "bar: Path element too long\n");
			return -1;
		}
		strncpy(buf, p, n-p);
		buf[n-p] = 0;
		if(chdir(buf)) {
			if(conf.verbose) fprintf(stderr, "bar: Creating subdirectory '%s'\n", buf);
			mkdir(buf, 0755);
			if(chdir(buf)) {
				fprintf(stderr, "bar: Failed chdir('%s')\n", buf);
				return -1;
			}
		}
		p=n+1;
	}
	if(chdir(conf.cwd)) return -1;
	return 0;
}

static const char *hdrtypestr(int t)
{
	switch(t) {
	case HDRTYPE_NULL:
		return "NULL";
	case HDRTYPE_CHAR:
		return "CHAR";
	case HDRTYPE_INT8:
		return "INT8";
	case HDRTYPE_INT16:
		return "INT16";
	case HDRTYPE_INT32:
		return "INT32";
	case HDRTYPE_INT64:
		return "INT64";
	case HDRTYPE_STRING:
		return "STRING";
	case HDRTYPE_BIN:
		return "BIN";
	case HDRTYPE_STRARRAY:
		return "STRARRAY";
	case HDRTYPE_I18NSTRING:
		return "I18NSTRING";
	}
	return "UNKNOWN";
}

static const char *sigstr(int t)
{
	switch(t) {
	case SIGTAG_MD5:
		return "SIGTAG_MD5";
	case SIGTAG_SIZE:
		return "SIGTAG_SIZE";
	case SIGTAG_PAYLOADSIZE:
		return "SIGTAG_PAYLOADSIZE";
	case SIGTAG_HEADERSIGNATURES:
		return "SIGTAG_HEADERSIGNATURES";
	case SIGTAG_SHA1:
		return "SIGTAG_SHA1";
	}
	return "";
}

static const char *tagstr(int t)
{
	switch(t) {
	case RPMTAG_NAME:
		return "RPMTAG_NAME";
	case RPMTAG_VERSION:
		return "RPMTAG_VERSION";
	case RPMTAG_RELEASE:
		return "RPMTAG_RELEASE";
	case RPMTAG_SUMMARY:
		return "RPMTAG_SUMMARY";
	case RPMTAG_DESCRIPTION:
		return "RPMTAG_DESCRIPTION";
	case RPMTAG_BUILDTIME:
		return "RPMTAG_BUILDTIME";
	case RPMTAG_SIZE:
		return "RPMTAG_SIZE";
	case RPMTAG_COPYRIGHT:
		return "RPMTAG_COPYRIGHT";
	case RPMTAG_GROUP:
		return "RPMTAG_GROUP";
	case RPMTAG_OS:
		return "RPMTAG_OS";
	case RPMTAG_ARCH:
		return "RPMTAG_ARCH";
	case RPMTAG_PAYLOADFORMAT:
		return "RPMTAG_PAYLOADFORMAT";
	case RPMTAG_PAYLOADCOMPRESSOR:
		return "RPMTAG_PAYLOADCOMPRESSOR";
	case RPMTAG_PAYLOADFLAGS:
		return "RPMTAG_PAYLOADFLAGS";
	case RPMTAG_HEADERI18NTABLE:
		return "RPMTAG_HEADERI18NTABLE";
	case RPMTAG_FILENAMES:
		return "RPMTAG_FILENAMES";
	case RPMTAG_FILESIZES:
		return "RPMTAG_FILESIZES";
	case RPMTAG_FILEMODES:
		return "RPMTAG_FILEMODES";
	case RPMTAG_FILERDEVS:
		return "RPMTAG_FILERDEVS";
	case RPMTAG_FILEMD5S:
		return "RPMTAG_FILEMD5S";
	case RPMTAG_DIRINDEXES:
		return "RPMTAG_DIRINDEXES";
	case RPMTAG_BASENAMES:
		return "RPMTAG_BASENAMES";
	case RPMTAG_DIRNAMES:
		return "RPMTAG_DIRNAMES";
	case RPMTAG_POSTIN:
		return "RPMTAG_POSTIN";
	case RPMTAG_POSTUN:
		return "RPMTAG_POSTUN";
	case RPMTAG_POSTINPROG:
		return "RPMTAG_POSTINPROG";
	case RPMTAG_POSTUNPROG:
		return "RPMTAG_POSTUNPROG";
	}
	return "";
}

static struct rpm *rpm_new()
{
	struct rpm *rpm;
	rpm = malloc(sizeof(struct rpm));
	if(!rpm) return (void*)0;
	memset(rpm, 0, sizeof(struct rpm));
	rpm->sigtags = jl_new();
	rpm->tags = jl_new();
	return rpm;
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

static const char *tag(struct rpm *rpm, int n, const char *miss)
{
	struct tag *tag;
	
	jl_foreach(rpm->tags, tag) {
		if(tag->tag == n)
			return tag->value;
	}
	return miss;
}

static const char *sig(struct rpm *rpm, int n)
{
	struct tag *tag;
	
	jl_foreach(rpm->sigtags, tag) {
		if(tag->tag == n)
			return tag->value;
	}
	return "";
}

static ssize_t cpio_write(gzFile file, const struct file *f, struct rpm *rpm)
{
	struct cpio_header header;
	struct stat statb;
	char buf[16];
	void *fbuf;
	int ifd;
	size_t filesize;
	int n;
	int trailer = 0;
	ssize_t count, uncompressed_size = 0;

	if(conf.verbose > 1)
		fprintf(stderr, "bar: Adding %s to index\n", f->name);

	if(!strcmp("TRAILER!!!", f->name))
		trailer = 1;
	
	if(trailer)
		memset(&statb, 0, sizeof(statb));
	else {
		if(lstat(f->name, &statb)) {
			fprintf(stderr, "bar: Failed to stat %s\n", f->name);
			return -1;
		}
	}

	memset(&header, '0', sizeof(header));
	
	strncpy(header.c_magic, CPIOMAGIC, 6);

	sprintf(buf, "%08X", statb.st_nlink);
	memcpy(header.c_nlink, buf, 8);

	sprintf(buf, "%08X", (unsigned int) statb.st_mtime);
	memcpy(header.c_mtime, buf, 8);

	sprintf(buf, "%08X", statb.st_mode);
	memcpy(header.c_mode, buf, 8);

	sprintf(buf, "%08X", statb.st_uid);
	memcpy(header.c_uid, buf, 8);
	
	sprintf(buf, "%08X", statb.st_gid);
	memcpy(header.c_gid, buf, 8);
	
	sprintf(buf, "%08X", strlen(f->cpio_name));
	memcpy(header.c_namesize, buf, 8);

	if(S_ISREG(statb.st_mode)) {
		sprintf(buf, "%08X", (unsigned int) statb.st_size);
		memcpy(header.c_filesize, buf, 8);
	}
	if(S_ISLNK(statb.st_mode)) {
		sprintf(buf, "%08X", (unsigned int) statb.st_size+1);
		memcpy(header.c_filesize, buf, 8);
	}
	
	n = gzwrite(file, &header, sizeof(header));
	if(n <= 0) return -1;
	uncompressed_size += n;
	
	if(conf.verbose > 1)
		fprintf(stderr, "bar: Aligned [4] %d to %d\n",
			sizeof(header)+strlen(f->cpio_name),
			(sizeof(header)+strlen(f->cpio_name)+3)&~3);
	n = gzwrite(file, f->cpio_name, ((sizeof(header)+strlen(f->cpio_name)+3)&~3) - sizeof(header));
	if(n <= 0) return -1;
	uncompressed_size += n;
	
	if(S_ISREG(statb.st_mode)) {
		/* write file, 4-byte aligned */
		if(conf.verbose > 1)
			fprintf(stderr, "bar: Writing contents of file %s\n", f->name);
		filesize = statb.st_size;
		ifd = open(f->name, O_RDONLY);
		if(ifd == -1) {
			fprintf(stderr, "bar: Failed to open %s\n", f->name);
			return -1;
		}
		#define FBUFSIZE 4096
		fbuf = malloc(FBUFSIZE);
		if(!fbuf) {
			fprintf(stderr, "bar: Failed to malloc fbuf memory %s\n", f->name);
			return -1;
		}
		while(filesize) {
			count = read(ifd, fbuf, FBUFSIZE);
			if(count < 1) {
				fprintf(stderr, "bar: read failed. bytes left %zu. for %s\n", filesize, f->name);
				return -1;
			}
			filesize -= count;
			n = gzwrite(file, fbuf, count);
			if(n <= 0) {
				fprintf(stderr, "bar: gzwrite failed. bytes left %zu. for %s\n", filesize, f->name);
				return -1;
			}
			uncompressed_size += n;
			rpm->sumsize += n;
		}
		if(fbuf) free(fbuf);
		close(ifd);
		
		n = ((statb.st_size + 3) & ~3) - statb.st_size;
		if(n) {
			memset(buf, 0, sizeof(buf));
			n = gzwrite(file, buf, n);
			if(n <= 0) {
				fprintf(stderr, "bar: gzwrite failed for padding. %s\n", f->name);
				return -1;
			}
			uncompressed_size += n;
		}
	}
	if(S_ISLNK(statb.st_mode)) {
		/* write link, 4-byte aligned */
		if(conf.verbose > 1)
			fprintf(stderr, "bar: Writing contents of link %s\n", f->name);
		filesize = statb.st_size;
		fbuf = malloc(filesize+16);
		if(!fbuf) return -1;

		count = readlink(f->name, fbuf, filesize+16);
		if(count < 1) {
			fprintf(stderr, "bar: Error reading link %s\n", f->name);
			return -1;
		}
		((char*)fbuf)[count] = 0; /* zero terminate link string */
		count++;
		n = gzwrite(file, fbuf, count);
		if(n <= 0) return -1;
		uncompressed_size += n;
		rpm->sumsize += n;
		
		n = ((count + 3) & ~3) - count;
		if(n) {
			memset(buf, 0, sizeof(buf));
			n = gzwrite(file, buf, n);
			if(n <= 0) return -1;
			uncompressed_size += n;
		}
		free(fbuf);
	}
	
	return uncompressed_size;
}

static int cpio_read(gzFile file, struct cpio_host *cpio)
{
	struct cpio_header header;
	int n, trailer=0;
	char buf[16];
	
	cpio->uncompressed_size = 0;
	
	n = gzread(file, &header, sizeof(header));
	if(n <= 0) {
		fprintf(stderr, "bar: Failed reading the cpio_header. EOF?\n");
		return -1;
	}
	cpio->uncompressed_size += n;
	
	if(strncmp(header.c_magic, CPIOMAGIC, 6)) {
		fprintf(stderr, "bar: Wrong cpio magic\n");
		return -1;
	}
	strncpy(cpio->c_magic, header.c_magic, 6);
	
	strncpy(buf, header.c_mode, 8); buf[8] = 0;
	cpio->c_mode = strtoul(buf, (void*)0, 16);
	cpio->mode = "?";
	if(S_ISREG(cpio->c_mode)) cpio->mode = "f";
	if(S_ISDIR(cpio->c_mode)) cpio->mode = "d";
	if(S_ISLNK(cpio->c_mode)) cpio->mode = "l";
	if(S_ISCHR(cpio->c_mode)) cpio->mode = "c";
	if(S_ISBLK(cpio->c_mode)) cpio->mode = "b";

	strncpy(buf, header.c_nlink, 8); buf[8] = 0;
	cpio->c_nlink = strtoull(buf, (void*)0, 16);

	strncpy(buf, header.c_rdevmajor, 8); buf[8] = 0;
	cpio->c_rdevmajor = strtoull(buf, (void*)0, 16);
	strncpy(buf, header.c_rdevminor, 8); buf[8] = 0;
	cpio->c_rdevminor = strtoull(buf, (void*)0, 16);
	cpio->rdev = makedev(cpio->c_rdevmajor, cpio->c_rdevminor);

	strncpy(buf, header.c_uid, 8); buf[8] = 0;
	cpio->c_uid = strtoull(buf, (void*)0, 16);
	strncpy(buf, header.c_gid, 8); buf[8] = 0;
	cpio->c_gid = strtoull(buf, (void*)0, 16);

	strncpy(buf, header.c_mtime, 8); buf[8] = 0;
	cpio->c_mtime = strtoull(buf, (void*)0, 16);
	
	strncpy(buf, header.c_filesize, 8); buf[8] = 0;
	cpio->c_filesize = strtoull(buf, (void*)0, 16);
	cpio->c_filesize_a = (cpio->c_filesize+3)&~0x3;
	
	strncpy(buf, header.c_namesize, 8); buf[8] = 0;
	cpio->c_namesize = strtoul(buf, (void*)0, 16);
	cpio->c_namesize += (((sizeof(header)+cpio->c_namesize+3)&~0x3) -
			    (sizeof(header)+cpio->c_namesize));
	cpio->name = malloc(cpio->c_namesize+1+strlen("./"));
	n = gzread(file, cpio->name+2, cpio->c_namesize);
	if(n>0) cpio->name[n+2] = 0;
	else { 
		fprintf(stderr, "bar: Error reading name from cpio.\n");
		return -1;
	}
	if(conf.verbose > 3) fprintf(stderr, "bar: raw cpioname: [%s]\n",
				     cpio->name+2);
	if(strcmp(cpio->name+2, "TRAILER!!!")==0)
		trailer=1;
	if(cpio->name[2] == '/') {
		cpio->name[1] = '.';
		cpio->name++;
	} else {
		if(strncmp(cpio->name+2, "./", 2)) {
			if(trailer) {
				cpio->name += 2;
			} else {
				cpio->name[0] = '.';
				cpio->name[1] = '/';
			}
		} else {
			cpio->name += 2;
		}
	}
	if(conf.prefix && (trailer==0) ) {
		char *p;
		if(strncmp(cpio->name, "./", 2)==0)
			cpio->name+=2;
		p = malloc(strlen(conf.prefix)+strlen(cpio->name)+1);
		if(!p) {
			fprintf(stderr, "bar: Failed to allocate memory for prefixed name of %s\n", cpio->name);
			return -1;
		}
		strcpy(p, conf.prefix);
		strcat(p, cpio->name);
		cpio->name = p;
	}
	cpio->uncompressed_size += n;
	return 0;
}

static int rpm_lead_read(int fd, struct rpm *rpm)
{
	if(conf.verbose > 1) fprintf(stderr, "bar: Reading lead sized %d bytes\n", sizeof(struct rpmlead));
	if(read(fd, &rpm->lead, sizeof(struct rpmlead))!= sizeof(struct rpmlead)) {
		fprintf(stderr, "bar: Failed to read lead.\n");
                return -1;
	}
	if(ntohl(rpm->lead.magic) != RPMMAGIC) {
		fprintf(stderr, "bar: Incorrect rpm magic in lead.\n");
		return -1;
	}

	if(conf.verbose > 2) {
		fprintf(stderr, "bar: LEAD name: %s\n", rpm->lead.name);
		fprintf(stderr, "bar: LEAD major: %x minor: %x\n", rpm->lead.major, rpm->lead.minor);
		fprintf(stderr, "bar: LEAD type: %x\n", ntohs(rpm->lead.type));
		if(ntohs(rpm->lead.archnum) <= ARCHNUM__MAX)
			fprintf(stderr, "bar: LEAD archnum: %s\n", table_archnum[ntohs(rpm->lead.archnum)].name);
		else
			fprintf(stderr, "bar: LEAD archnum: %x\n", ntohs(rpm->lead.archnum));
		if(ntohs(rpm->lead.osnum) <= OSNUM__MAX)
			fprintf(stderr, "bar: LEAD osnum: %s\n", table_osnum[ntohs(rpm->lead.osnum)].name);
		else
			fprintf(stderr, "bar: LEAD osnum: %x\n", ntohs(rpm->lead.osnum));
		fprintf(stderr, "bar: LEAD signature_type: %x\n", ntohs(rpm->lead.signature_type));
	}

	return 0;
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
	gzFile file;
	struct file *f;
	struct file trailer;
	ssize_t n;
	int zfd;
	
	zfd = dup(fd);
	file = gzdopen(zfd, "w");
	jl_foreach(files, f) {
		if(conf.verbose) printf("%s\n", f->normalized_name);
		if((n=cpio_write(file, f, rpm)) == -1) {
			fprintf(stderr, "bar: Error writing cpio header\n");
			return -1;
		}
		rpm->uncompressed_size += n;
	}
	memset(&trailer, 0, sizeof(trailer));
	trailer.name = "TRAILER!!!";
	trailer.normalized_name = "TRAILER!!!";
	trailer.cpio_name = "TRAILER!!!";
	if((n=cpio_write(file, &trailer, rpm)) == -1) {
		fprintf(stderr, "bar: Error writing cpio header for trailer\n");
		return -1;
	}
	rpm->uncompressed_size += n;
	
	gzclose(file);
	
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
	index_len = tags->len;
	index = indexp = malloc(index_len * sizeof(struct indexentry));
	
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

static int rpm_sig_read(int fd, struct rpm *rpm)
{
	int i;
	char *store;
	struct indexentry *entry;
	struct tag *tag;
	struct jlhead *entries;
	if(conf.verbose > 1) fprintf(stderr, "bar: Reading signature sized %d bytes\n", sizeof(struct header));
	entries = jl_new();
	
	if(read(fd, &rpm->sig, sizeof(struct header))!= sizeof(struct header)) {
		fprintf(stderr, "bar: Failed to read signature header\n");
                return -1;
	}
	if((ntohl(rpm->sig.magic) >> 8) !=HEADERMAGIC) {
		fprintf(stderr, "bar: Incorrect rpm-header magic in signature.\n");
		if(conf.verbose) {
			fprintf(stderr, "bar: Magic was: %x, should be %x\n",
				(ntohl(rpm->sig.magic) >> 8),
				HEADERMAGIC);
		}
                return -1;
        }
	
	if(conf.verbose > 2) fprintf(stderr, "bar: Reading index sized %d bytes\n",
				     sizeof(struct indexentry)*ntohl(rpm->sig.entries));
	for(i=0;i<ntohl(rpm->sig.entries);i++) {
		entry = malloc(sizeof(struct indexentry));
		if(read(fd, entry, sizeof(struct indexentry)) != sizeof(struct indexentry)) {
			fprintf(stderr, "bar: Failed to read indexentry %d.\n", i);
			return -1;
		}
		jl_append(entries, entry);
	}
	
	store = malloc(ntohl(rpm->sig.size));
	
	i = (ntohl(rpm->sig.size)+7)&~0x7; /* adjust to even 8-byte boundary */
	if(conf.verbose > 1) fprintf(stderr, "bar: Aligned %d to %d\n", ntohl(rpm->sig.size), i);
	if(conf.verbose > 1) fprintf(stderr, "bar: Reading store sized %d bytes\n", i);
	if(read(fd, store, i)!=i) {
		fprintf(stderr, "bar: Failed to read signature store\n");
		return -1;
	}

	/*
	 * Set the header offset.
	 * If we want to verify the MD5 signature, we need to seek back here later.
	 */
	rpm->headeroffset = lseek(fd, 0, SEEK_CUR);
	
	jl_foreach(entries, entry) {
		char buf[2048];

		if(conf.verbose > 3)
			fprintf(stderr, "bar: Entry: %d [%s] type: %s offset: %d count: %d\n",
				ntohl(entry->tag), sigstr(ntohl(entry->tag)),
				hdrtypestr(ntohl(entry->type)), ntohl(entry->offset), ntohl(entry->count));

		tag = malloc(sizeof(struct tag));
		memset(tag, 0, sizeof(struct tag));
		tag->tag = ntohl(entry->tag);
		tag->type = ntohl(entry->type);
		if(ntohl(entry->count) >= ((sizeof(buf)-2)/2)) {
			fprintf(stderr, "bar: Signature entry too large: %d. max %d allowed\n", ntohl(entry->count),
				(sizeof(buf)-2)/2);
			entry->count = htonl((sizeof(buf)-2)/2);
		}
		if(ntohl(entry->type) == HDRTYPE_BIN) {
			unsigned char *p;
			char *b;
			b = buf;
			for(p=(unsigned char*) store + ntohl(entry->offset);
			    p<(unsigned char*)(store + ntohl(entry->offset)+ntohl(entry->count));
			    p++) {
				sprintf(b, "%02x", *p);
				b+=2;
			}
			tag->value = strdup(buf);
		}
		if(ntohl(entry->type) == HDRTYPE_STRING) {
			tag->value = strdup(store + ntohl(entry->offset));
		}
		if(ntohl(entry->type) == HDRTYPE_STRARRAY) {
			char *b, *p;
			int n, len=0;
                        b = buf;
			p = store + ntohl(entry->offset);
			for(i=0;i<ntohl(entry->count);i++) {
				n = strlen(p);
				len += n;
				len++;
				p += n;
				p++;
			}
			tag->value=malloc(len+1);
			b = tag->value;
			p = store + ntohl(entry->offset);
			for(i=0;i<ntohl(entry->count);i++) {
				n = sprintf(b, "%s\n", p);
				b += n;
				p += (n-1);
				p++;
			}
		}
		if(ntohl(entry->type) == HDRTYPE_I18NSTRING) {
			tag->value = strdup(store + ntohl(entry->offset));
		}
		if(ntohl(entry->type) == HDRTYPE_INT32) {
			sprintf(buf, "%d", ntohl(*(int32_t*)(store + ntohl(entry->offset))));
			tag->value = strdup(buf);
		}
		if(tag->value) jl_append(rpm->sigtags, tag);
	}
	
	if(conf.verbose > 2) 
		jl_foreach(rpm->sigtags, tag) {
			fprintf(stderr, "bar: Sigtag: %d [%s] type: %s value: %s\n", tag->tag, sigstr(tag->tag), hdrtypestr(tag->type), tag->value);
		}
	
	return 0;
}

static int rpm_header_read(int fd, struct rpm *rpm)
{
	int i;
	char *store;
	struct indexentry *entry;
	struct tag *tag;
	struct jlhead *entries;
	char *buf;
	size_t bufsize = 2048;

	if(conf.verbose > 1) fprintf(stderr, "bar: Reading header sized %d\n", sizeof(struct header));
	entries = jl_new();

	if(read(fd, &rpm->header, sizeof(struct header))!= sizeof(struct header)) {
		fprintf(stderr, "bar: Failed to read rpm header\n");
                return -1;
	}
	if((ntohl(rpm->header.magic) >> 8) != HEADERMAGIC) {
		fprintf(stderr, "bar: Incorrect rpm-header magic in rpm header.\n");
		if(conf.verbose) {
			fprintf(stderr, "bar: Magic was: %x, should be %x\n",
				(ntohl(rpm->sig.magic) >> 8),
				HEADERMAGIC);
		}
                return -1;
        }
	
	if(conf.verbose > 2) fprintf(stderr, "bar: Reading index sized %d\n",
				     sizeof(struct indexentry)*ntohl(rpm->header.entries));
	for(i=0;i<ntohl(rpm->header.entries);i++) {
		entry = malloc(sizeof(struct indexentry));
		if(read(fd, entry, sizeof(struct indexentry)) != sizeof(struct indexentry)) {
			fprintf(stderr, "bar: Failed to read indexentries.\n");
			return -1;
		}
		jl_append(entries, entry);
	}
	
	store = malloc(ntohl(rpm->header.size));
	
	i = ntohl(rpm->header.size);
	if(conf.verbose > 1) fprintf(stderr, "bar: Reading store sized %d\n", i);
	if(read(fd, store, i)!=i) {
		fprintf(stderr, "bar: Failed to read header store\n");
		return -1;
	}

	/*
	 * Set the payload offset.
	 * We may later want to seek to this position to unpack the payload
	 */
	rpm->payloadoffset = lseek(fd, 0, SEEK_CUR);

        buf = malloc(bufsize);
	if(!buf) {
		fprintf(stderr, "bar: Failed to allocate buffer for rpm header\n");
		return -1;
	}
	
	jl_foreach(entries, entry) {
		if(conf.verbose > 3)
			fprintf(stderr, "bar: Entry: %d [%s] type: %s offset: %d count: %d\n",
				ntohl(entry->tag), tagstr(ntohl(entry->tag)),
				hdrtypestr(ntohl(entry->type)), ntohl(entry->offset), ntohl(entry->count));
		
		tag = malloc(sizeof(struct tag));
		memset(tag, 0, sizeof(struct tag));
		tag->tag = ntohl(entry->tag);
		tag->type = ntohl(entry->type);

		if(ntohl(entry->count) >= ((bufsize-2)/2)) {
			char *newbuf;
			if(ntohl(entry->count) < 1<<24) {
				newbuf = malloc( (ntohl(entry->count)+2)*2);
				if(newbuf) {
					free(buf);
					buf = newbuf;
					bufsize = (ntohl(entry->count)+2)*2;
				}
			}
		}

		if(ntohl(entry->count) >= ((bufsize-2)/2)) {
			fprintf(stderr, "bar: Header entry too large: %d. max %d allowed\n", ntohl(entry->count),
				(bufsize-2)/2);
			entry->count = htonl((bufsize-2)/2);
		}

		if(ntohl(entry->type) == HDRTYPE_BIN) {
			unsigned char *p;
			char *b;
			b = buf;
			for(p=(unsigned char*) store + ntohl(entry->offset);
			    p<(unsigned char*)(store + ntohl(entry->offset)+ntohl(entry->count));
			    p++) {
				sprintf(b, "%02x", *p);
				b+=2;
			}
			tag->value = strdup(buf);
		}
		if(ntohl(entry->type) == HDRTYPE_STRING) {
			tag->value = strdup(store + ntohl(entry->offset));
		}
		if(ntohl(entry->type) == HDRTYPE_STRARRAY) {
			char *b, *p;
			int n, len=0;
                        b = buf;
			p = store + ntohl(entry->offset);
			for(i=0;i<ntohl(entry->count);i++) {
				n = strlen(p);
				len += n;
				len++;
				p += n;
				p++;
			}
			tag->value=malloc(len+1);
			b = tag->value;
			p = store + ntohl(entry->offset);
			for(i=0;i<ntohl(entry->count);i++) {
				n = sprintf(b, "%s", p);
				b += n;
				p += n;
				if(i < ntohl(entry->count)-1) {
					sprintf(b, "\n");
					b++;
				}
				p++;
			}
		}
		if(ntohl(entry->type) == HDRTYPE_I18NSTRING) {
			tag->value = strdup(store + ntohl(entry->offset));
		}
		if(ntohl(entry->type) == HDRTYPE_INT32) {
			char *b, *p;
			int n;
			tag->value = malloc(ntohl(entry->count) * 12);
			b = tag->value;
			p = store + ntohl(entry->offset);
			for(i=0;i<ntohl(entry->count);i++) {
				n = sprintf(b, "%d", ntohl(*(int32_t*)p));
				b += n;
				if(i < ntohl(entry->count)-1) {
                                        sprintf(b, "\n");
                                        b++;
                                }
				p += sizeof(int32_t);
			}
		}
		if(ntohl(entry->type) == HDRTYPE_INT16) {
			char *b, *p;
			int n;
			tag->value = malloc(ntohl(entry->count) * 7);
			b = tag->value;
			p = store + ntohl(entry->offset);
			for(i=0;i<ntohl(entry->count);i++) {
				n = sprintf(b, "%hu", ntohs(*(int16_t*)p));
				b += n;
				if(i < ntohl(entry->count)-1) {
                                        sprintf(b, "\n");
                                        b++;
                                }
				p += sizeof(int16_t);
			}
		}
		if(tag->value) jl_append(rpm->tags, tag);
		else {
			if(conf.verbose) {
				fprintf(stderr, "bar: Skipping tag %d of unknown type: %d\n", tag->tag, ntohl(entry->type));
			}
		}
	}
	
	if(conf.verbose > 2 || conf.printtag) 
		jl_foreach(rpm->tags, tag) {
			if(conf.verbose > 2 || conf.printtag == tag->tag)
				fprintf(stderr, "bar: Tag: %d [%s] type: %s value: %s\n", tag->tag, tagstr(tag->tag), hdrtypestr(tag->type), tag->value);
		}
	free(buf);
	return 0;
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
		MD5_CTX md5;
		unsigned char md5sum[MD5_DIGEST_LENGTH];

		if(MD5Init(&md5)) {
                        fprintf(stderr, "bar: MD5Init failed.\n");
                        return -1;
                }
		while(1) {
                        n = read(fd, buf, sizeof(buf));
                        if(n < 1) break;
                        MD5Update(&md5, buf, n);
                }
                MD5Final(md5sum, &md5);

		if(lseek(fd, rpm->sigtag_md5sum, SEEK_SET)==-1) {
			fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->sigtag_md5sum);
			return -1;
		}
		if(conf.verbose > 1) {
			fprintf(stderr, "bar: Rewriting SIGTAG_MD5\n");
		}
		write(fd, md5sum, MD5_DIGEST_LENGTH);
	}
	return 0;
}


struct jlhead *rpm_read_filenames(struct rpm *rpm)
{
	struct jlhead *l = jl_new();
	const char *names = tag(rpm, RPMTAG_FILENAMES, (void*)0);
	const char *dirindexes, *dirnames;
	
	/* the old simple way. plain filenames in a list */
	if(names) {
		const char *p=names;
		char *n;
		while(p && *p) {
			n = strchr(p, '\n');
			if(n) jl_append(l, strndup(p, n-p));
			if(!n) {
				jl_append(l, strdup(p));
				break;
			}
			p = n+1;
		}
		return l;
	}
	
	names = tag(rpm, RPMTAG_BASENAMES, (void*)0);
	if(!names) {
		fprintf(stderr, "bar: header lacks filenames\n");
		return l;
	}
	dirindexes = tag(rpm, RPMTAG_DIRINDEXES, (void*)0);
	if(!dirindexes) {
		fprintf(stderr, "bar: header lacks DIRINDEXES\n");
		return l;
	}
	dirnames = tag(rpm, RPMTAG_DIRNAMES, (void*)0);
	if(!dirnames) {
		fprintf(stderr, "bar: header lacks DIRNAMES\n");
		return l;
	}

	{
		const char *d=dirindexes;
		const char *p=names;
		char *nd, *np;
		char *name, *dir;
		int i;
		while(d && p && *d && *p) {
			nd = strchr(d, '\n');
			np = strchr(p, '\n');
			i = atoi(d);
			dir = stratindex(dirnames, i);
			name = malloc(strlen(dir)+(np?np-p:strlen(p))+1);
			strcpy(name, dir);
			free(dir);
			strncat(name, p, np?np-p:strlen(p));
			jl_append(l, name);
			if(!np) break;
			p = np+1;
			d = nd+1;
		}
	}
	return l;
}

static int bar_create(const char *archive, struct jlhead *files, int *err)
{
	int fd;
	struct rpm *rpm;
	struct tag *tag;
	struct file *f;
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
	tag->value = "None";
        tag->type = HDRTYPE_I18NSTRING;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_DESCRIPTION);
	tag->value = "None";
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

	tag = tag_new(RPMTAG_COPYRIGHT);
	tag->value = conf.tag.license;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_GROUP);
	tag->value = "None";
        tag->type = HDRTYPE_I18NSTRING;
	jl_append(rpm->tags, tag);

	tag = tag_new(RPMTAG_OS);
	tag->value = conf.tag.os;
        jl_append(rpm->tags, tag);

	/* RPMTAG_ARCH 1022 */
	tag = tag_new(RPMTAG_ARCH);
	tag->value = conf.tag.arch;
        jl_append(rpm->tags, tag);

	/* RPMTAG_POSTIN 1024 */
	if(conf.tag.postin) {
		tag = tag_new(RPMTAG_POSTIN);
		tag->value = conf.tag.postin;
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
	p = tag->value;
	jl_foreach(files, f) {
		sprintf(p, "0\n");
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
	p = tag->value;
	jl_foreach(files, f) {
		strcpy(p, f->group);
		p += (strlen(f->group)+1);
	}
	jl_append(rpm->tags, tag);

	/* RPMTAG_POSTINPROG 1086 */
	tag = tag_new(RPMTAG_POSTINPROG);
	tag->value = "/bin/sh";
        jl_append(rpm->tags, tag);
	
        /* RPMTAG_POSTUNPROG 1088 */
	tag = tag_new(RPMTAG_POSTUNPROG);
	tag->value = "/bin/sh";
        jl_append(rpm->tags, tag);

	/* RPMTAG_FILEDEVICES 1095 INT32 */
	tag = tag_new(RPMTAG_FILEDEVICES);
	tag->type = HDRTYPE_INT32;
	tag->count = files->len;
	tag->value = malloc(files->len * 12);
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

	/* RPMTAG_PAYLOADFLAGS */
	tag = tag_new(RPMTAG_PAYLOADFLAGS);
	tag->value = "9";
	jl_append(rpm->tags, tag);

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

static int bar_extract(const char *archive, struct jlhead *files, int *err)
{
	int fd;
	struct rpm *rpm;
	struct jlhead *filenames;
	
	*err = 0;

	rpm = rpm_new();
	fd = open(archive, O_RDONLY);
	if(fd == -1) return -1;
	
	if(rpm_lead_read(fd, rpm)) return -1;
	if(rpm_sig_read(fd, rpm)) return -1;

	/* verify MD5 signature */
	if(!conf.ignore_chksum)	{
		ssize_t n;
		int i;
		unsigned char buf[1024];
		MD5_CTX md5;
		unsigned char md5sum[MD5_DIGEST_LENGTH];
		char sigmd5sum[MD5_DIGEST_LENGTH*2+1];

		if(MD5Init(&md5)) {
                        fprintf(stderr, "bar: MD5Init failed.\n");
                        return -1;
                }
		while(1) {
                        n = read(fd, buf, sizeof(buf));
                        if(n < 1) break;
                        MD5Update(&md5, buf, n);
                }
                MD5Final(md5sum, &md5);
		for(i=0;i<MD5_DIGEST_LENGTH;i++) {
			sprintf(sigmd5sum+i*2, "%02x", md5sum[i]);
		}
		if(strcmp(sig(rpm, SIGTAG_MD5), sigmd5sum)) {
			fprintf(stderr, "bar: MD5sum verification failed: %s %s\n", sig(rpm, SIGTAG_MD5), sigmd5sum);
			return -1;
		} else {
			if(conf.verbose > 2)
				fprintf(stderr, "bar: MD5sum verification succeeded.\n");
		}
		
	}
	
	/* rewind to start of header */
	if(lseek(fd, rpm->headeroffset, SEEK_SET)==-1) {
		fprintf(stderr, "bar: Failed to seek to pos %ju\n", rpm->headeroffset);
	}
	
	if(rpm_header_read(fd, rpm)) return -1;

	if(conf.info) {
		printf("name=%s\n", tag(rpm, RPMTAG_NAME, ""));
		printf("version=%s\n", tag(rpm, RPMTAG_VERSION, ""));
		printf("release=%s\n", tag(rpm, RPMTAG_RELEASE, ""));
		printf("os=%s\n", tag(rpm, RPMTAG_OS, ""));
		printf("arch=%s\n", tag(rpm, RPMTAG_ARCH, ""));
		printf("license=%s\n", tag(rpm, RPMTAG_COPYRIGHT, ""));
		printf("size=%s\n", tag(rpm, RPMTAG_SIZE, ""));
		return 0;
	}

	if(strcmp(tag(rpm, RPMTAG_PAYLOADFORMAT, "cpio"), "cpio")) {
		fprintf(stderr, "bar: Unsupported payload format '%s'\n", tag(rpm, RPMTAG_PAYLOADFORMAT, ""));
		return -1;
	}
	if(strcmp(tag(rpm, RPMTAG_PAYLOADCOMPRESSOR, "gzip"), "gzip")) {
		fprintf(stderr, "bar: Unsupported payload compressor '%s'\n", tag(rpm, RPMTAG_PAYLOADCOMPRESSOR, ""));
		return -1;
	}

	/* retrieve filenames; they might be encoded in two different ways */
	filenames = rpm_read_filenames(rpm);

	{
		gzFile file;
		struct cpio_host cpio;
		int n, ofd=-1;
		char buf[4096];
		int selected;
		char *filemd5 = (void*)0;
		char *tmpname = (void*)0;
		
		rpm->uncompressed_size = 0;
		
		file = gzdopen(dup(fd), "r");
		if(!file) {
			fprintf(stderr, "bar: gzdopen of compressed payload failed\n");
			return -1;
		}
		while(1) {
			selected=0;
			if(cpio_read(file, &cpio)) {
				fprintf(stderr, "bar: Error reading cpio header\n");
				return -1;
			}
			rpm->uncompressed_size += cpio.uncompressed_size;
			
			if(strcmp(cpio.name, "TRAILER!!!")==0)
				break;
			if(files->len == 0) selected=1;
			else {
				struct file *f;
				jl_foreach(files, f) {
					if(!strcmp(f->name, cpio.name)) {
						selected=1;
						break;
					}
				}
			}

			{
				int fileindex = 0;
				char *name;
				filemd5 = (void*)0;
				if(!conf.ignore_chksum) {
					jl_foreach(filenames, name) {
						if(strcmp(name, normalize_name(cpio.name))==0) {
							filemd5 = stratindex(tag(rpm, RPMTAG_FILEMD5S, (void*)0), fileindex);
							break;
						}
						fileindex++;
					}
				}
			}
			
			if(selected && (conf.list || conf.verbose)) {
				if(conf.verbose) {
					/* mode nlink uid gid size date filename */
					struct tm tm;
					time_t t = cpio.c_mtime;
					localtime_r(&t, &tm);
					strftime(buf, sizeof(buf), "%F %T", &tm);
					if(conf.pkginfo)
						printf("%s\t%llu\t%s\t%s\n",
						       cpio.mode, cpio.c_filesize, filemd5?filemd5:"-", cpio.name);
					else
						printf("%-8o %4d %6d %6d %9llu %9s %s\n",
						       cpio.c_mode, cpio.c_nlink, cpio.c_uid, cpio.c_gid,
						       cpio.c_filesize, buf, cpio.name);
				} else
					printf("%s\n", cpio.name);
			}
			if(selected && (!conf.list)) {
				if(mkpath(cpio.name)) {
					fprintf(stderr, "bar: Failed to create filesystem path for %s\n", cpio.name);
					return -1;
				}
				if(!strcmp(cpio.mode,"l")) {
					char *path;
					path = malloc(cpio.c_filesize_a);
					n = gzread(file, path, cpio.c_filesize_a);
					if(n != cpio.c_filesize_a) {
						fprintf(stderr, "bar: Failed to read symlink for: %s\n", cpio.name);
						return -1;
					}
					rpm->uncompressed_size += n;
					unlink(cpio.name);
					symlink(path, cpio.name);
					free(path);
					/* set size to zero, so it wont be read later */
					cpio.c_filesize_a = 0;
				}
				if(!strcmp(cpio.mode,"f")) {
					size_t tmplen = strlen(cpio.name)+64;
					struct timespec tp;
					if(clock_gettime(CLOCK_MONOTONIC, &tp)) {
						tp.tv_nsec = time(0);
					}
					tmpname = malloc(tmplen);
					if(!tmpname) {
						fprintf(stderr, "bar: Failed to alloc tmpname for %s\n", cpio.name);
						return -1;
					}
					snprintf(tmpname, tmplen, "%s.tmp.%u.%ld", cpio.name, getpid(), tp.tv_nsec);
					tmpname[tmplen-1] = 0;
					if(!ftest(tmpname, 0777777)) {
						if(unlink(tmpname)) {
							fprintf(stderr, "bar: Failed to unlink tmp file %s\n", tmpname);
							return -1;
						}
					}
					ofd = open(tmpname, O_WRONLY|O_CREAT|O_TRUNC, 0755);
					if(ofd == -1) {
						fprintf(stderr, "bar: Failed to create file %s\n", tmpname);
						if(tmpname) rename(tmpname, cpio.name);
						return -1;
					}
				}
				if(!strcmp(cpio.mode,"c")) {
					if(!ftest(cpio.name, S_IFCHR)) {
						struct stat statb;
						
						if(lstat(cpio.name, &statb)==0) {
							if(statb.st_rdev != cpio.rdev)
								unlink(cpio.name);
						}
					}
					if(ftest(cpio.name, S_IFCHR)) {
						mknod(cpio.name, cpio.c_mode, cpio.rdev);
					}
				}
				if(!strcmp(cpio.mode,"b")) {
					if(!ftest(cpio.name, S_IFBLK)) {
						struct stat statb;
						
						if(lstat(cpio.name, &statb)==0) {
							if(statb.st_rdev != cpio.rdev)
								unlink(cpio.name);
						}
					}
					if(ftest(cpio.name, S_IFCHR)) {
						mknod(cpio.name, cpio.c_mode, cpio.rdev);
					}
				}
				if(!strcmp(cpio.mode,"d"))
					if(ftest(cpio.name, S_IFDIR)) {
						if(mkdir(cpio.name, 0755)) {
							fprintf(stderr, "bar: Failed to create directory %s\n",
								cpio.name);
							return -1;
						}
					}
				if(chmod(tmpname?tmpname:cpio.name, cpio.c_mode & 07777)) {
					fprintf(stderr, "bar: Failed to set mode of %s\n", tmpname?tmpname:cpio.name);
					*err=1;
				}
				if(chown(tmpname?tmpname:cpio.name, cpio.c_uid, cpio.c_gid)) {
					fprintf(stderr, "bar: Failed to set owner of %s\n", tmpname?tmpname:cpio.name);
					*err=1;
				}

				{
					struct timeval tv[2];
					tv[0].tv_sec = cpio.c_mtime;
					tv[0].tv_usec = 0;
					tv[1].tv_sec = cpio.c_mtime;
					tv[1].tv_usec = 0;
					if(lutimes(tmpname?tmpname:cpio.name, tv)) {
						fprintf(stderr, "bar: Failed to set mtime of %s\n", tmpname?tmpname:cpio.name);
						*err=1;
					}
				}

			}
			if(conf.verbose > 1) {
				if(cpio.c_filesize_a) {
					fprintf(stderr, "bar: Reading %llu bytes of file contents for %s\n",
						cpio.c_filesize_a, cpio.name);
				}
			}

			{
				int i;
				uint64_t actualsize;
				unsigned char md5sum[MD5_DIGEST_LENGTH];
				char filemd5sum[MD5_DIGEST_LENGTH*2+1];
				MD5_CTX md5;

				if(MD5Init(&md5)) {
					fprintf(stderr, "bar: MD5Init failed.\n");
					return -1;
				}
				
				if(filemd5 && (conf.verbose > 2)) {
					if(filemd5)
						fprintf(stderr, "bar: md5sum of %s should be %s\n", cpio.name, filemd5);
				}
				
				actualsize = cpio.c_filesize;
				while(actualsize) {
					n = gzread(file, buf, actualsize < sizeof(buf) ? actualsize : sizeof(buf));
					if(n <= 0) break;
					
					if(!conf.ignore_chksum) MD5Update(&md5, buf, n);
					
					rpm->uncompressed_size += n;
					if(ofd >= 0) {
						if(write(ofd, buf, n)==-1) {
							fprintf(stderr, "bar: error writing to %s: %s\n", tmpname, strerror(errno));
							close(ofd);
							unlink(tmpname);
							return -1;
						}
					}
					cpio.c_filesize_a -= n;
					actualsize -= n;
				}
				while(cpio.c_filesize_a) {
					n = gzread(file, buf, cpio.c_filesize_a < sizeof(buf) ? cpio.c_filesize_a : sizeof(buf));
                                        if(n <= 0) break;
					cpio.c_filesize_a -= n;
				}
				MD5Final(md5sum, &md5);
				for(i=0;i<MD5_DIGEST_LENGTH;i++) {
					sprintf(filemd5sum+i*2, "%02x", md5sum[i]);
				}
				if(!conf.ignore_chksum) {
					if(conf.verbose > 2)
						fprintf(stderr, "bar: md5sum calculated to %s\n", filemd5sum);
					if(filemd5) {
						if(!strcmp(cpio.mode,"f") && strcmp(filemd5sum, filemd5)) {
							fprintf(stderr, "bar: md5sum mismatch of file %s\n", cpio.name);
							return -1;
						}
					}
				}
				if(filemd5) free(filemd5);
			}
			if(ofd >= 0) {
				struct timeval tv[2];
				ftruncate(ofd, cpio.c_filesize);
				tv[0].tv_sec = cpio.c_mtime;
				tv[0].tv_usec = 0;
				tv[1].tv_sec = cpio.c_mtime;
				tv[1].tv_usec = 0;
				if(futimes(ofd, tv)) {
					fprintf(stderr, "bar: Failed to set mtime of %s\n", tmpname);
                                        *err=1;
				}
				if(fsync(ofd)) {
					fprintf(stderr, "bar: fsync failed for %s\n", tmpname);
					close(fd);
					return -1;
				}
				close(ofd);
				if(rename(tmpname, cpio.name)) {
					fprintf(stderr, "bar: fsync failed to rename %s to %s\n", tmpname, cpio.name);
					return -1;
				}
				ofd=-1;
				free(tmpname);
				tmpname = (void*)0;
			}
		}
		gzclose_r(file);
	}

	if(conf.verbose > 1) {
		fprintf(stderr, "bar: Uncompressed size of payload: %zu\n", rpm->uncompressed_size);
	}
	
	return 0;
}

static int file_new(struct jlhead *files, const char *fn, int create, int recursive)
{
	struct file *f;
	int fd, i;
	ssize_t n;
	unsigned char buf[PATH_MAX];
	MD5_CTX md5;
	unsigned char md5sum[MD5_DIGEST_LENGTH];
	
	f = malloc(sizeof(struct file));
	if(!f) {
		fprintf(stderr, "bar: failed to malloc memory: ");
		fprintf(stderr, "%s\n", fn);
		return -1;
	}

	f->name = strdup(fn);
	
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

	if(conf.prefix) {
		char *p;
		p = malloc(strlen(conf.prefix)+strlen(f->normalized_name)+1);
		strcpy(p, conf.prefix);
		strcat(p, f->normalized_name);
		f->normalized_name = p;
	}
	
	/* Names in the cpio archive should start with "./" */
	f->cpio_name = malloc(strlen(f->normalized_name)+2);
	strcpy(f->cpio_name+1, f->normalized_name);
	*f->cpio_name = '.';
	
	if(lstat(f->name, &f->stat)) {
		fprintf(stderr, "bar: Failed to lstat %s\n", f->name);
		return -1;
	}
	
	f->md5 = malloc(MD5_DIGEST_LENGTH*2+1);
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
		
		if(MD5Init(&md5)) {
			fprintf(stderr, "bar: MD5Init failed.\n");
			close(fd);
			return -1;
		}
		while(1) {
			n = read(fd, buf, sizeof(buf));
			if(n < 1) break;
			MD5Update(&md5, buf, n);
		}
		close(fd);
		MD5Final(md5sum, &md5);
		for(i=0;i<MD5_DIGEST_LENGTH;i++) {
			sprintf(f->md5+i*2, "%02x", md5sum[i]);
		}
	}
	if(conf.verbose > 2) {
		fprintf(stderr, "bar: Added file: %s md5sum: %s\n", f->name, f->md5);
	}

	if(recursive && S_ISDIR(f->stat.st_mode)) {
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
			if(file_new(files, (char*)buf, create, recursive)) {
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
	return strcmp(((struct file*)a)->normalized_name, ((struct file*)b)->normalized_name);
}

int main(int argc, char **argv)
{
	int err=0, rc=2, i;
	char *archive;
	struct jlhead *files;

	files = jl_new();
	jl_sort(files, sort_files);
	
	i=256;
	conf.cwd = malloc(i);
	while(!getcwd(conf.cwd, i)) {
		i = i*2;
		conf.cwd = realloc(conf.cwd, i);
		if(!conf.cwd) exit(2);
	}

	conf.prefix = 0;
	
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
	conf.tag.license = "Unknown";
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
		       " --fgroup <groupname>   [file owner]\n"
		       " --fuser <username>     [file owner]\n"
		       " --license <string>     [GPLv2+]\n"
		       " --name <string>        [from archive-file name]\n"
		       " --os <osname>          [from uname]\n"
		       " --postin <string>      post install script\n"
		       " --postun <string>      post uninstall script\n"
		       " --release <string>     [current date and time YYYYMMDD.HHMMSS]\n"
		       " --version <string>     [0]\n"
		       "\n"
		       " Create/extract options:\n"
		       " --prefix <path>        add prefix <path> to all filepaths\n"
		       " --nosum                ignore checksums\n"
		       " --quotechar <char>     [%%] used for inserting special chars\n"
		       " --printtag <tag number>\n"
		       "\n"
		       " Package handler information:\n"
		       " --pkginfo\n"
			);
		exit(rc);
	}
	while(jelopt(argv, 'r', "recursive", 0, &err)) conf.recursive=1;
	while(jelopt(argv, 'c', "create", 0, &err)) conf.create=1;
	while(jelopt(argv, 'i', "info", 0, &err)) conf.extract=conf.info=1;
	while(jelopt(argv, 'l', "list", 0, &err)) conf.extract=conf.list=1;
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
	while(jelopt(argv, 0, "postin", &conf.tag.postin, &err))
		conf.tag.postin = dequote(conf.tag.postin);
	while(jelopt(argv, 0, "postun", &conf.tag.postun, &err))
		conf.tag.postun = dequote(conf.tag.postun);
	{
		char *tmp;
		while(jelopt(argv, 0, "quotechar", &tmp, &err))
			if(tmp) conf.quotechar = *tmp;
	}
	while(jelopt(argv, 0, "release", &conf.tag.release, &err));
	while(jelopt(argv, 0, "version", &conf.tag.version, &err));
	while(jelopt(argv, 0, "pkginfo", NULL, &err)) conf.pkginfo=conf.verbose=1;
	while(jelopt_int(argv, 0, "printtag", &conf.printtag, &err));
	while(jelopt(argv, 0, "nosum", NULL, &err)) conf.ignore_chksum=1;
	while(jelopt(argv, 0, "prefix", &conf.prefix, &err)) {
		int len = strlen(conf.prefix);
		if(len)
			if(conf.prefix[len-1] == '/')
				conf.prefix[len-1] = 0;
	}
	
	argc = jelopt_final(argv, &err);
	if(err) {
		fprintf(stderr, "bar: Syntax error in options.\n");
		exit(2);
	}
	if(conf.create+conf.extract+conf.verify > 1) {
		fprintf(stderr, "bar: You must specify exactly one of [cxV]\n");
		exit(2);
	}
	if(conf.create+conf.extract+conf.verify == 0) {
		fprintf(stderr, "bar: You must specify one of [cxV]\n");
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
		if(file_new(files, argv[i], conf.create, conf.recursive)) {
			fprintf(stderr, "bar: Failed to add file %s. Aborting.\n", argv[i]);
			exit(1);
		}
	}
	
	if(conf.extract) {
		err=0;
		if(bar_extract(archive, files, &err)) {
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
