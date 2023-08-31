/*
 * File: bar_extract.c
 * Implements: rpm file archive extractor
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
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>

#include "bar_rpm.h"
#include "bar_cpio.h"
#include "jelist.h"
#include "zstream.h"
#include "digest.h"

#include "bar_extract.h"


static struct canon table_osnum[] = { 
  { "" },
  { "LINUX" },
  { "IRIX" },
  { "SOLARIS" },
  { "SUNOS" },
  { "AIX" },
  { "HPUX10" },
  { "OSF1" },
  { "FREEBSD" },
  { "SCO" },
  { "IRIX64" },
  { "NEXTSTEP" },
  { "BSDI" },
  { "MACHTEN" },
  { "CYGWIN32_NT" },
  { "CYGWIN32_95" },
  { "MP_RAS" },
  { "MINT" },
  { "OS390" },
  { "VM_ESA" },
  { "LINUX_390" },
  { "MACOSX" },
  { NULL }
};

static struct canon table_archnum[] = { 
  { "" },
  { "X86" },
  { "ALPHA" },
  { "SPARC" },
  { "MIPS" },
  { "PPC" },
  { "M68K" },
  { "SGI" },
  { "RS6000" },
  { "IA64" },
  { "" },
  { "MIPSEL" },
  { "ARM" },
  { "M68KMINT" },
  { "S390" },
  { "S390X" },
  { "PPC64" },
  { "SH" },
  { "XTENSA" },
  { NULL }
};


static const char *sig(struct rpm *rpm, int n)
{
	struct tag *tag;
	
	jl_foreach(rpm->sigtags, tag) {
		if(tag->tag == n)
			return tag->value;
	}
	return "";
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
		if(p) 
			p++;
		else
			break;
		idx--;
	}
	return (void*)0;
}

static int ftest(const char *path, mode_t flags)
{
	struct stat b;
	if(lstat(path, &b))
		return -1;
	if(b.st_mode & flags) return 0;
	return -1;
}

static int mkpath(const struct logcb *log, const char *path, const char *cwd)
{
	const char *p;
	const char *n;
	char buf[NAME_MAX+1];
	
	p = path;
	if(chdir(cwd)) return -1;
	
	while(1) {
		while(*p == '/') p++;
		n = strchr(p, '/');
		if(!n) break;
		if( (n-p) >= sizeof(buf)) {
			if(log) log->logln("Path element too long");
			return -1;
		}
		strncpy(buf, p, n-p);
		buf[n-p] = 0;
		if(chdir(buf)) {
			if(log && log->level) log->logln("Creating subdirectory '%s'", buf);
			mkdir(buf, 0755);
			if(chdir(buf)) {
				if(log) log->logln("Failed chdir('%s')\n", buf);
				return -1;
			}
		}
		p=n+1;
	}
	if(chdir(cwd)) return -1;
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
	case SIGTAG_SHA256:
		return "SIGTAG_SHA256";
	case SIGTAG_RESERVEDSPACE:
		return "SIGTAG_RESERVEDSPACE";
	case SIGTAG_PGP:
		return "SIGTAG_PGP";
	case SIGTAG_RSA:
		return "SIGTAG_RSA";
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
	case RPMTAG_FILEFLAGS:
		return "RPMTAG_FILEFLAGS";
	case RPMTAG_SOURCERPM:
		return "RPMTAG_SOURCERPM";
	case RPMTAG_FILEVERIFYFLAGS:
		return "RPMTAG_FILEVERIFYFLAGS";
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
	case RPMTAG_POSTTRANS:
		return "RPMTAG_POSTTRANS";
	case RPMTAG_PREIN:
		return "RPMTAG_PREIN";
	case RPMTAG_PRETRANS:
		return "RPMTAG_PRETRANS";
	case RPMTAG_PREUN:
		return "RPMTAG_PREUN";
	case RPMTAG_POSTINPROG:
		return "RPMTAG_POSTINPROG";
	case RPMTAG_POSTTRANSPROG:
		return "RPMTAG_POSTTRANSPROG";
	case RPMTAG_POSTUNPROG:
		return "RPMTAG_POSTUNPROG";
	case RPMTAG_FILEDIGESTALGO:
		return "RPMTAG_FILEDIGESTALGO";
	case RPMTAG_REQUIRENAME:
		return "RPMTAG_REQUIRENAME";
	case RPMTAG_REQUIREFLAGS:
		return "RPMTAG_REQUIREFLAGS";
	case RPMTAG_REQUIREVERSION:
		return "RPMTAG_REQUIREVERSION";
	case RPMTAG_OBSOLETENAME:
		return "RPMTAG_OBSOLETENAME";
	case RPMTAG_OBSOLETEFLAGS:
		return "RPMTAG_OBSOLETEFLAGS";
	case RPMTAG_OBSOLETEVERSION:
		return "RPMTAG_OBSOLETEVERSION";
	case RPMTAG_SHA256HEADER:
		return "RPMTAG_SHA256HEADER";
	case RPMTAG_PAYLOADDIGEST:
		return "RPMTAG_PAYLOADDIGEST";
	case RPMTAG_PAYLOADDIGESTALGO:
		return "RPMTAG_PAYLOADDIGESTALGO";
	case RPMTAG_PAYLOADDIGESTALT:
		return "RPMTAG_PAYLOADDIGESTALT";
	case RPMTAG_HEADERIMMUTABLE:
		return "RPMTAG_HEADERIMMUTABLE";
	}
	return "";
}

static int rpm_lead_read(const struct logcb *log, int fd, struct rpm *rpm)
{
	if(log && log->level > 1) log->logln("Reading lead sized %d bytes", sizeof(struct rpmlead));
	if(read(fd, &rpm->lead, sizeof(struct rpmlead))!= sizeof(struct rpmlead)) {
		if(log) log->logln("Failed to read lead.");
                return -1;
	}
	if(ntohl(rpm->lead.magic) != RPMMAGIC) {
		if(log) log->logln("Incorrect rpm magic in lead.\n");
		return -1;
	}

	if(log && log->level > 2) {
		log->logln("LEAD name: %s", rpm->lead.name);
		log->logln("LEAD major: %x minor: %x", rpm->lead.major, rpm->lead.minor);
		log->logln("LEAD type: %x", ntohs(rpm->lead.type));
		if(ntohs(rpm->lead.archnum) <= ARCHNUM__MAX)
			log->logln("LEAD archnum: %s", table_archnum[ntohs(rpm->lead.archnum)].name);
		else
			log->logln("LEAD archnum: %x", ntohs(rpm->lead.archnum));
		if(ntohs(rpm->lead.osnum) <= OSNUM__MAX)
			log->logln("LEAD osnum: %s", table_osnum[ntohs(rpm->lead.osnum)].name);
		else
			log->logln("LEAD osnum: %x", ntohs(rpm->lead.osnum));
		log->logln("LEAD signature_type: %x", ntohs(rpm->lead.signature_type));
	}

	return 0;
}

static int rpm_sig_read(const struct logcb *log, int fd, struct rpm *rpm)
{
	int i;
	char *store;
	struct indexentry *entry;
	struct tag *tag;
	struct jlhead *entries;
	if(log && log->level > 1) log->logln("Reading signature sized %d bytes", sizeof(struct header));
	entries = jl_new();
	
	if(read(fd, &rpm->sig, sizeof(struct header))!= sizeof(struct header)) {
		if(log) log->logln("Failed to read signature header");
                return -1;
	}
	if((ntohl(rpm->sig.magic) >> 8) !=HEADERMAGIC) {
		if(log) log->logln("Incorrect rpm-header magic in signature.");
		if(log && log->level) log->logln("Magic was: %x, should be %x",
						 (ntohl(rpm->sig.magic) >> 8),
						 HEADERMAGIC);
                return -1;
        }
	
	if(log && log->level > 2) log->logln("Reading index sized %d bytes",
					     sizeof(struct indexentry)*ntohl(rpm->sig.entries));
	for(i=0;i<ntohl(rpm->sig.entries);i++) {
		entry = malloc(sizeof(struct indexentry));
		if(!entry) {
			if(log) log->logln("Failed to allocate memory for indexentry %d.", i);
                        return -1;
		}
		if(read(fd, entry, sizeof(struct indexentry)) != sizeof(struct indexentry)) {
			if(log) log->logln("Failed to read indexentry %d.", i);
			return -1;
		}
		jl_append(entries, entry);
	}
	
	store = malloc(ntohl(rpm->sig.size));
	if(!store) {
		if(log) log->logln("Failed to allocate memory for store");
		return -1;
	}
	
	i = (ntohl(rpm->sig.size)+7)&~0x7; /* adjust to even 8-byte boundary */
	if(log && log->level > 1) log->logln("Aligned %d to %d", ntohl(rpm->sig.size), i);
	if(log && log->level > 1) log->logln("Reading signature store sized %d bytes", i);
	if(read(fd, store, i)!=i) {
		if(log) log->logln("Failed to read signature store");
		return -1;
	}

	/*
	 * Set the header offset.
	 * If we want to verify the MD5 signature, we need to seek back here later.
	 */
	rpm->headeroffset = lseek(fd, 0, SEEK_CUR);
	
	{
		char *buf;
		size_t bufsize = 10*1024;

		buf = malloc(bufsize);
		if(!buf) {
			if(log) log->logln("Failed to allocate memory for signature entries");
			return -1;
		}
		
		jl_foreach(entries, entry) {
			if(log && log->level > 3)
				log->logln("Entry: %d [%s] type: %s offset: %d count: %d",
					   ntohl(entry->tag), sigstr(ntohl(entry->tag)),
					   hdrtypestr(ntohl(entry->type)), ntohl(entry->offset), ntohl(entry->count));
			
			tag = malloc(sizeof(struct tag));
			if(!tag) {
				if(log) log->logln("Failed to allocate memory for tag");
				return -1;
			}
			memset(tag, 0, sizeof(struct tag));
			tag->tag = ntohl(entry->tag);
			tag->type = ntohl(entry->type);
			if(ntohl(entry->count) >= ((bufsize-2)/2)) {
				if(log) log->logln("Signature entry too large: %d. max %d allowed", ntohl(entry->count),
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
				if(!tag->value) {
					if(log) log->logln("Failed to allocate memory for tag value");
					return -1;
				}
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
	}
	
	if(log && log->level > 2) 
		jl_foreach(rpm->sigtags, tag) {
			log->logln("Sigtag: %d [%s] type: %s value: %s", tag->tag, sigstr(tag->tag), hdrtypestr(tag->type), tag->value);
		}
	
	return 0;
}

static int rpm_header_read(const struct logcb *log, int fd, struct rpm *rpm, int printtag)
{
	int i;
	char *store;
	struct indexentry *entry;
	struct tag *tag;
	struct jlhead *entries;
	char *buf;
	size_t bufsize = 2048;
	struct digest d;
	const char *sigtag_sha256;
	
	sigtag_sha256 =	sig(rpm, SIGTAG_SHA256);

	if(digest(&d, "sha256")) {
		if(log)	log->logln("SHA256Init failed.");
		return -1;
	}

	if(log && log->level > 1) log->logln("Reading header sized %d", sizeof(struct header));
	entries = jl_new();

	if(read(fd, &rpm->header, sizeof(struct header))!= sizeof(struct header)) {
		if(log) log->logln("Failed to read rpm header");
                return -1;
	}
	if((ntohl(rpm->header.magic) >> 8) != HEADERMAGIC) {
		if(log) log->logln("Incorrect rpm-header magic in rpm header.");
		if(log && log->level) log->logln("Magic was: %x, should be %x",
						 (ntohl(rpm->sig.magic) >> 8),
						 HEADERMAGIC);
                return -1;
        }
	d.update(&d, &rpm->header, sizeof(struct header));
	
	if(log && log->level > 1) log->logln("Reading index sized %d",
					     sizeof(struct indexentry)*ntohl(rpm->header.entries));
	for(i=0;i<ntohl(rpm->header.entries);i++) {
		entry = malloc(sizeof(struct indexentry));
		if(!entry) {
			if(log) log->logln("Failed to allocate memory for entry");
			return -1;
		}
		if(read(fd, entry, sizeof(struct indexentry)) != sizeof(struct indexentry)) {
			if(log) log->logln("Failed to read indexentries.");
			return -1;
		}
		d.update(&d, entry, sizeof(struct indexentry));
		jl_append(entries, entry);
	}
	
	store = malloc(ntohl(rpm->header.size));
	if(!store) {
		if(log) log->logln("Failed to allocate memory for store");
		return -1;
	}
	
	i = ntohl(rpm->header.size);
	if(log && log->level > 1) log->logln("Reading store sized %d", i);
	if(read(fd, store, i)!=i) {
		if(log) log->logln("Failed to read header store");
		return -1;
	}
	d.update(&d, store, i);
	d.final(&d);
	if(*sigtag_sha256) {
		if(strcmp(sigtag_sha256, d.hexstr)) {
			if(log) log->logln("SHA256 checksum verification of header failed: %s %s", sigtag_sha256, d.hexstr);
			return -1;
		} else {
			if(log && log->level > 1)
				if(log) log->logln("SHA256 checksum verification of header succeeded.");
		}
	}

	/*
	 * Set the payload offset.
	 * We may later want to seek to this position to unpack the payload
	 */
	rpm->payloadoffset = lseek(fd, 0, SEEK_CUR);

        buf = malloc(bufsize);
	if(!buf) {
		if(log) log->logln("Failed to allocate buffer for rpm header");
		return -1;
	}
	
	jl_foreach(entries, entry) {
		if(log && log->level > 3) log->logln("Entry: %d [%s] type: %s offset: %d count: %d",
				ntohl(entry->tag), tagstr(ntohl(entry->tag)),
				hdrtypestr(ntohl(entry->type)), ntohl(entry->offset), ntohl(entry->count));
		
		tag = malloc(sizeof(struct tag));
		if(!tag) {
			if(log) log->logln("Failed to allocate buffer for tag");
			return -1;
		}
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
			if(log) log->logln("Header entry too large: %d. max %d allowed", ntohl(entry->count),
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
			if(!tag->value) {
				if(log) log->logln("Failed to allocate buffer for tag value");
				return -1;
			}
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
			if(!tag->value) {
                                if(log) log->logln("Failed to allocate buffer for tag value");
                                return -1;
                        }
		}
		if(ntohl(entry->type) == HDRTYPE_INT32) {
			char *b, *p;
			int n;
			tag->value = malloc(ntohl(entry->count) * 12);
			if(!tag->value) {
                                if(log) log->logln("Failed to allocate buffer for tag value");
                                return -1;
                        }
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
			if(!tag->value) {
                                if(log) log->logln("Failed to allocate buffer for tag value");
                                return -1;
                        }
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
			if(log && log->level) log->logln("Skipping tag %d of unknown type: %d", tag->tag, ntohl(entry->type));
		}
	}
	
	if(log && (log->level > 2 || printtag))
		jl_foreach(rpm->tags, tag) {
		   if(log->level > 2 || printtag == tag->tag)
			   log->logln("Tag: %d [%s] type: %s value: %s", tag->tag, tagstr(tag->tag), hdrtypestr(tag->type), tag->value);
		}
	free(buf);
	return 0;
}

struct jlhead *rpm_read_filenames(const struct logcb *log, struct rpm *rpm)
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
		if(log) log->logln("header lacks filenames");
//		return l;
	}
	dirindexes = tag(rpm, RPMTAG_DIRINDEXES, (void*)0);
	if(!dirindexes) {
		if(log) log->logln("header lacks DIRINDEXES");
//		return l;
	}
	dirnames = tag(rpm, RPMTAG_DIRNAMES, (void*)0);
	if(!dirnames) {
		if(log) log->logln("header lacks DIRNAMES");
//		return l;
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
			name = malloc((dir?strlen(dir):0)+(np?np-p:strlen(p))+1);
			if(!name) {
				if(log) log->logln("Failed to allocate memory for filename");
				return NULL;
			}
			strcpy(name, dir?dir:"");
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

int bar_extract(const struct logcb *log, const char *archive, struct jlhead *files, int *err, const struct bar_options *conf)
{
	int fd;
	struct rpm *rpm;
	struct jlhead *filenames;
	
	*err = 0;

	rpm = rpm_new();
	fd = open(archive, O_RDONLY);
	if(fd == -1) return -1;
	
	if(rpm_lead_read(log, fd, rpm)) return -1;
	if(rpm_sig_read(log, fd, rpm)) return -1;

	/* verify MD5 signature */
	if(!conf->ignore_chksum)	{
		ssize_t n;
		unsigned char buf[1024];
		struct digest d;
		const char *sigtag_md5;

		sigtag_md5 = sig(rpm, SIGTAG_MD5);

		if(*sigtag_md5) {
			if(digest(&d, "md5")) {
				if(log)	log->logln("MD5Init failed.");
				return -1;
			}
			while(1) {
				n = read(fd, buf, sizeof(buf));
				if(n < 1) break;
				d.update(&d, buf, n);
			}
			d.final(&d);
			if(strcmp(sigtag_md5, d.hexstr)) {
				if(log) log->logln("MD5sum verification failed: %s %s", sigtag_md5, d.hexstr);
				return -1;
			} else {
				if(log && log->level > 1)
					if(log) log->logln("MD5sum verification succeeded.");
			}
		}
	}
	
	/* rewind to start of header */
	if(lseek(fd, rpm->headeroffset, SEEK_SET)==-1) {
		if(log) log->logln(" Failed to seek to pos %ju", rpm->headeroffset);
	}
	
	if(rpm_header_read(log, fd, rpm, conf->printtag)) return -1;

	if(conf->info) {
		printf("name=%s\n", tag(rpm, RPMTAG_NAME, ""));
		printf("version=%s\n", tag(rpm, RPMTAG_VERSION, ""));
		printf("release=%s\n", tag(rpm, RPMTAG_RELEASE, ""));
		printf("os=%s\n", tag(rpm, RPMTAG_OS, ""));
		printf("arch=%s\n", tag(rpm, RPMTAG_ARCH, ""));
		printf("license=%s\n", tag(rpm, RPMTAG_COPYRIGHT, ""));
		printf("sourcerpm=%s\n", tag(rpm, RPMTAG_SOURCERPM, ""));
		printf("size=%s\n", tag(rpm, RPMTAG_SIZE, ""));
		return 0;
	}

	if(strcmp(tag(rpm, RPMTAG_PAYLOADFORMAT, "cpio"), "cpio")) {
		if(log) log->logln("Unsupported payload format '%s'", tag(rpm, RPMTAG_PAYLOADFORMAT, ""));
		return -1;
	}
	
	rpm->compressor = (void*) 0;
	if(strcmp(tag(rpm, RPMTAG_PAYLOADCOMPRESSOR, ""), "xz") == 0)
		rpm->compressor = "xz";
	if(strcmp(tag(rpm, RPMTAG_PAYLOADCOMPRESSOR, ""), "zstd") == 0)
		rpm->compressor = "zstd";
	if(strcmp(tag(rpm, RPMTAG_PAYLOADCOMPRESSOR, "gzip"), "gzip") == 0)
		rpm->compressor = "gzip";

	if(!rpm->compressor) {
		if(log) log->logln("Unsupported payload compressor '%s'", tag(rpm, RPMTAG_PAYLOADCOMPRESSOR, ""));
		return -1;
	}

	rpm->digestalgo = "md5";
	/* See for algo numbers https://tools.ietf.org/html/rfc4880#section-9.4 */
	if(strcmp(tag(rpm, RPMTAG_FILEDIGESTALGO, ""), "8") == 0)
		rpm->digestalgo = "sha256";
	
	if(log && log->level > 2) log->logln("Using digest algorithm: %s", rpm->digestalgo);
	
	/* retrieve filenames; they might be encoded in two different ways */
	filenames = rpm_read_filenames(log, rpm);
	{
		struct zstream z;
		struct cpio_host cpio;
		int n, ofd=-1;
		char buf[4096];
		int selected;
		char *filemd5 = (void*)0;
		char *fileuser = (void*)0;
		char *filegroup = (void*)0;
		char *fileflags = (void*)0;
		char *tmpname = (void*)0;
		
		rpm->uncompressed_size = 0;
		
		if(zstream(&z, rpm->compressor)) {
			if(log) log->logln("unsupported compressor %s", rpm->compressor);
			return -1;
		}
		z.init(&z);
		if(z.open(&z, dup(fd), "r")) {
			if(log) log->logln("open of compressed payload failed");
			return -1;
		}
		while(1) {
			selected=0;
			if(cpio_read(log, &z, &cpio, conf->prefix)) {
				if(log) log->logln("Error reading cpio header");
				return -1;
			}
			rpm->uncompressed_size += cpio.uncompressed_size;
			
			if(strcmp(cpio.name, "TRAILER!!!")==0)
				break;
			if(files->len == 0) selected=1;
			else {
				struct cpio_file *f;
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
				fileuser = (void*)0;
				filegroup = (void*)0;
				fileflags = (void*)0;
				jl_foreach(filenames, name) {
					if(strcmp(name, normalize_name(cpio.name))==0) {
						if(!conf->ignore_chksum) {
							filemd5 = stratindex(tag(rpm, RPMTAG_FILEMD5S, (void*)0), fileindex);
						}
						fileuser = stratindex(tag(rpm, RPMTAG_FILEUSERNAME, (void*)0), fileindex);
						filegroup = stratindex(tag(rpm, RPMTAG_FILEGROUPNAME, (void*)0), fileindex);
						fileflags = stratindex(tag(rpm, RPMTAG_FILEFLAGS, (void*)0), fileindex);
						break;
					}
					fileindex++;
				}
			}

			{
				char uidbuf[16], gidbuf[16];
				if(!fileuser) {
					snprintf(uidbuf, sizeof(uidbuf), "%d", cpio.c_uid);
					fileuser = strdup(uidbuf);
				}
				if(!filegroup) {
					snprintf(gidbuf, sizeof(gidbuf), "%d", cpio.c_gid);
					filegroup = strdup(gidbuf);
				}
			}

			{
				char s[16];
				s[0] = 0;
				
				if(fileflags) {
					int i;
					i = atoi(fileflags);
					free(fileflags);
					fileflags = (void*)0;
					if(i) {
						strcat(s, "[");
						if(i & RPMFILE_CONFIG) strcat(s, "c");
						if(i & RPMFILE_DOC) strcat(s, "d");
						if(i & RPMFILE_ICON) strcat(s, "i");
						if(i & RPMFILE_MISSINGOK) strcat(s, "m");
						if(i & RPMFILE_NOREPLACE) strcat(s, "n");
						if(i & RPMFILE_SPECFILE) strcat(s, "s");
						if(i & RPMFILE_GHOST) strcat(s, "g");
						if(i & RPMFILE_LICENSE) strcat(s, "l");
						if(i & RPMFILE_README) strcat(s, "r");
						if(i & RPMFILE_PUBKEY) strcat(s, "p");
						strcat(s, "]");
						fileflags = s;
					}
				}
			}
			
			if(selected && (conf->list || (log && log->level))) {
				if(log && log->level) {
					/* mode nlink uid gid size date filename */
					struct tm tm;
					time_t t = cpio.c_mtime;
					localtime_r(&t, &tm);
					strftime(buf, sizeof(buf), "%F %T", &tm);
					if(conf->pkginfo)
						printf("%s\t%llu\t%s\t%s\n",
						       cpio.mode, (long long unsigned int) cpio.c_filesize, filemd5?filemd5:"-", cpio.name);
					else
						printf("%-8o %9llu %4d %6s %6s %9llu %9s %s %s\n",
						       cpio.c_mode, (long long unsigned int) cpio.c_ino, cpio.c_nlink, fileuser,
						       filegroup, (long long unsigned int) cpio.c_filesize, buf, cpio.name,
						       fileflags?fileflags:"");
				} else
					printf("%s\n", cpio.name);
			}
			if(selected && (!conf->list)) {
				if(mkpath(log, cpio.name, conf->cwd)) {
					if(log) log->logln("Failed to create filesystem path for %s", cpio.name);
					return -1;
				}
				if(!strcmp(cpio.mode,"l")) {
					char *path;
					path = malloc(cpio.c_filesize_a+1);
					if(!path) {
						if(log) log->logln("Failed to alloc link content memory for %s", cpio.name);
						return -1;
					}
					if(log && log->level > 1) {
						if(cpio.c_filesize_a) {
							if(log) log->logln("Reading %llu bytes of link contents for %s (%llu)",
									   cpio.c_filesize_a, cpio.name, cpio.c_filesize);
						}
					}
					n = z.read(&z, path, cpio.c_filesize_a);
					if(n != cpio.c_filesize_a) {
						if(log) log->logln("Failed to read symlink for: %s", cpio.name);
						return -1;
					}
					path[cpio.c_filesize] = 0;
					rpm->uncompressed_size += n;
					unlink(cpio.name);
					symlink(path, cpio.name);
					free(path);
					/* set size to zero, so it wont be read later */
					cpio.c_filesize_a = cpio.c_filesize = 0;
				}
				if(!strcmp(cpio.mode,"f")) {
					size_t tmplen = strlen(cpio.name)+64;
					struct timespec tp;
					if(clock_gettime(CLOCK_MONOTONIC, &tp)) {
						tp.tv_nsec = time(0);
					}
					tmpname = malloc(tmplen);
					if(!tmpname) {
						if(log) log->logln("Failed to alloc tmpname for %s", cpio.name);
						return -1;
					}
					snprintf(tmpname, tmplen, "%s.tmp.%u.%ld", cpio.name, getpid(), tp.tv_nsec);
					tmpname[tmplen-1] = 0;
					if(!ftest(tmpname, 0777777)) {
						if(unlink(tmpname)) {
							if(log) log->logln("Failed to unlink tmp file %s", tmpname);
							return -1;
						}
					}
					ofd = open(tmpname, O_WRONLY|O_CREAT|O_TRUNC, 0755);
					if(ofd == -1) {
						if(log) log->logln("Failed to create file %s", tmpname);
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
							if(log) log->logln("Failed to create directory %s",
								cpio.name);
							return -1;
						}
					}
				if(chmod(tmpname?tmpname:cpio.name, cpio.c_mode & 07777)) {
					if(log) log->logln("Failed to set mode of %s", tmpname?tmpname:cpio.name);
					*err=1;
				}
				if(chown(tmpname?tmpname:cpio.name, cpio.c_uid, cpio.c_gid)) {
					if(log) log->logln("Failed to set owner of %s", tmpname?tmpname:cpio.name);
					*err=1;
				}

				{
					struct timeval tv[2];
					tv[0].tv_sec = cpio.c_mtime;
					tv[0].tv_usec = 0;
					tv[1].tv_sec = cpio.c_mtime;
					tv[1].tv_usec = 0;
					if(lutimes(tmpname?tmpname:cpio.name, tv)) {
						if(log) log->logln("Failed to set mtime of %s", tmpname?tmpname:cpio.name);
						*err=1;
					}
				}

			}
			if(log && log->level > 1) {
				if(cpio.c_filesize_a) {
					if(log) log->logln("Reading %llu bytes of file contents for %s",
						cpio.c_filesize_a, cpio.name);
				}
			}

			{
				uint64_t actualsize;
				struct digest d;

				if(digest(&d, rpm->digestalgo)) {
					if(log) log->logln("Digest init failed for algorith: %s", rpm->digestalgo);
					return -1;
				}
				
				if(filemd5 && (log && log->level > 2)) {
					if(filemd5)
						if(log) log->logln("md5sum of %s should be %s", cpio.name, filemd5);
				}
				
				actualsize = cpio.c_filesize;
				while(actualsize) {
					n = z.read(&z, buf, actualsize < sizeof(buf) ? actualsize : sizeof(buf));
					if(n <= 0) break;
					
					if(!conf->ignore_chksum) d.update(&d, buf, n);
					
					rpm->uncompressed_size += n;
					if(ofd >= 0) {
						if(write(ofd, buf, n)==-1) {
							if(log) log->logln("error writing to %s: %s", tmpname, strerror(errno));
							close(ofd);
							unlink(tmpname);
							return -1;
						}
					}
					cpio.c_filesize_a -= n;
					actualsize -= n;
				}
				while(cpio.c_filesize_a) {
					n = z.read(&z, buf, cpio.c_filesize_a < sizeof(buf) ? cpio.c_filesize_a : sizeof(buf));
                                        if(n <= 0) break;
					cpio.c_filesize_a -= n;
				}
				d.final(&d);
				if(!conf->ignore_chksum) {
					if(log && log->level > 2)
						log->logln("md5sum calculated to %s", d.hexstr);
					if(filemd5) {
						if(!strcmp(cpio.mode,"f") && strcmp(d.hexstr, filemd5)) {
							if(log) log->logln("md5sum mismatch of file %s", cpio.name);
							return -1;
						}
					}
				}
				if(filemd5) free(filemd5);
				if(fileuser) free(fileuser);
				if(filegroup) free(filegroup);
			}
			if(ofd >= 0) {
				struct timeval tv[2];
				ftruncate(ofd, cpio.c_filesize);
				tv[0].tv_sec = cpio.c_mtime;
				tv[0].tv_usec = 0;
				tv[1].tv_sec = cpio.c_mtime;
				tv[1].tv_usec = 0;
				if(futimes(ofd, tv)) {
					if(log) log->logln("Failed to set mtime of %s", tmpname);
                                        *err=1;
				}
				if(conf->sync && fsync(ofd)) {
					if(log) log->logln("fsync failed for %s", tmpname);
					close(fd);
					return -1;
				}
				if(close(ofd)) {
					if(log) log->logln("failed closing file %s after writing", tmpname);
					/* try to clean up the tmp-file atleast */
					unlink(tmpname);
					return -1;
				}
				if(rename(tmpname, cpio.name)) {
					if(log) log->logln("failed to rename %s to %s", tmpname, cpio.name);
					return -1;
				}
				ofd=-1;
				free(tmpname);
				tmpname = (void*)0;
			}
		}
		z.close(&z);
	}

	if(log && log->level > 1) {
		log->logln("Uncompressed size of payload: %zu", rpm->uncompressed_size);
	}
	
	return 0;
}

