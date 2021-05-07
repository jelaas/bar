#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

#include "bar_cpio.h"

ssize_t cpio_write(const struct logcb *log, struct zstream *z, const struct cpio_file *f, size_t *sumsize)
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

	if(log && log->level > 1)
		log->logln("Adding %s to index", f->name);

	if(!strcmp("TRAILER!!!", f->name))
		trailer = 1;
	
	if(trailer)
		memset(&statb, 0, sizeof(statb));
	else {
		if(lstat(f->name, &statb)) {
			if(log) log->logln("Failed to stat %s", f->name);
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
		sprintf(buf, "%08X", (unsigned int) statb.st_size);
		memcpy(header.c_filesize, buf, 8);
	}
	
	n = z->write(z, &header, sizeof(header));
	if(n <= 0) return -1;
	uncompressed_size += n;
	
	if(log && log->level > 1)
		log->logln( "Aligned [4] %d to %d",
			sizeof(header)+strlen(f->cpio_name),
			(sizeof(header)+strlen(f->cpio_name)+3)&~3);
	n = z->write(z, f->cpio_name, ((sizeof(header)+strlen(f->cpio_name)+3)&~3) - sizeof(header));
	if(n <= 0) return -1;
	uncompressed_size += n;
	
	if(S_ISREG(statb.st_mode)) {
		/* write file, 4-byte aligned */
		if(log && log->level > 1)
			log->logln("Writing contents of file %s", f->name);
		filesize = statb.st_size;
		ifd = open(f->name, O_RDONLY);
		if(ifd == -1) {
			if(log) log->logln("Failed to open %s", f->name);
			return -1;
		}
		#define FBUFSIZE 4096
		fbuf = malloc(FBUFSIZE);
		if(!fbuf) {
			if(log) log->logln("Failed to malloc fbuf memory %s", f->name);
			return -1;
		}
		while(filesize) {
			count = read(ifd, fbuf, FBUFSIZE);
			if(count < 1) {
				if(log) log->logln("read failed. bytes left %zu. for %s", filesize, f->name);
				return -1;
			}
			filesize -= count;
			n = z->write(z, fbuf, count);
			if(n <= 0) {
				if(log) log->logln("compressed write failed. bytes left %zu. for %s", filesize, f->name);
				return -1;
			}
			uncompressed_size += n;
			(*sumsize) += n;
		}
		if(fbuf) free(fbuf);
		close(ifd);
		
		n = ((statb.st_size + 3) & ~3) - statb.st_size;
		if(n) {
			memset(buf, 0, sizeof(buf));
			n = z->write(z, buf, n);
			if(n <= 0) {
				if(log) log->logln("compressed write failed for padding. %s", f->name);
				return -1;
			}
			uncompressed_size += n;
		}
	}
	if(S_ISLNK(statb.st_mode)) {
		/* write link, 4-byte aligned */
		if(log && log->level > 1)
			log->logln("Writing contents of link %s", f->name);
		filesize = statb.st_size;
		fbuf = malloc(filesize+16);
		if(!fbuf) return -1;

		count = readlink(f->name, fbuf, filesize+16);
		if(count < 1) {
			if(log) log->logln("Error reading link %s", f->name);
			return -1;
		}
		n = z->write(z, fbuf, count);
		if(n <= 0) return -1;
		uncompressed_size += n;
		(*sumsize) += n;
		
		n = ((count + 3) & ~3) - count;
		if(n) {
			if(log && log->level > 3) log->logln("Count %d computes to %d padding", count, n);
			memset(buf, 0, sizeof(buf));
			n = z->write(z, buf, n);
			if(n <= 0) return -1;
			uncompressed_size += n;
		}
		free(fbuf);
	}
	
	return uncompressed_size;
}

int cpio_read(const struct logcb *log, struct zstream *z, struct cpio_host *cpio, const char *prefix)
{
	struct cpio_header header;
	int n, trailer=0;
	char buf[16];
	
	cpio->uncompressed_size = 0;
	
	n = z->read(z, &header, sizeof(header));
	if(n <= 0) {
		if(log) log->logln("Failed reading the cpio_header. EOF?");
		return -1;
	}
	cpio->uncompressed_size += n;
	
	if(strncmp(header.c_magic, CPIOMAGIC, 6)) {
		if(log) log->logln("Wrong cpio magic");
		if(log && log->level > 3) log->logln("Magic is: %02x%02x%02x%02x%02x%02x", header.c_magic[0], header.c_magic[1], header.c_magic[2], header.c_magic[3], header.c_magic[4], header.c_magic[5]);
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
	if(!cpio->name) {
		if(log) {
			log->pre();
			log->log("Failed to malloc memory for cpio name ");
			log->log("of length %d", cpio->c_namesize);
			log->post();
		}
		return -1;
	}
	n = z->read(z, cpio->name+2, cpio->c_namesize);
	if(n>0) cpio->name[n+2] = 0;
	else { 
		if(log) log->logln("Error reading name from cpio.");
		return -1;
	}
	if(log && log->level > 3) log->logln("raw cpioname: [%s]",
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
	if(prefix && (trailer==0) ) {
		char *p;
		if(strncmp(cpio->name, "./", 2)==0)
			cpio->name+=2;
		p = malloc(strlen(prefix)+strlen(cpio->name)+1);
		if(!p) {
			if(log) log->logln("Failed to allocate memory for prefixed name of %s", cpio->name);
			return -1;
		}
		strcpy(p, prefix);
		strcat(p, cpio->name);
		cpio->name = p;
	}
	cpio->uncompressed_size += n;
	return 0;
}

