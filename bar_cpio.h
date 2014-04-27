#ifndef BAR_CPIO_H
#define BAR_CPIO_H

#include "zstream.h"
#include "logcb.h"

/* http://people.freebsd.org/~kientzle/libarchive/man/cpio.5.txt */

#define CPIOMAGIC "070701"
struct cpio_header {
  char    c_magic[6]; /* cpio: 070701 */
  char    c_ino[8];
  char    c_mode[8];
  char    c_uid[8];
  char    c_gid[8];
  char    c_nlink[8];
  char    c_mtime[8];
  char    c_filesize[8];
  char    c_devmajor[8];
  char    c_devminor[8];
  char    c_rdevmajor[8];
  char    c_rdevminor[8];
  char    c_namesize[8];
  char    c_check[8];
};

struct cpio_file {
  char *name; /* name to use for file access when creating archive */
  char *normalized_name; /* name to write in header */
  char *cpio_name; /* name to write in cpio-archive */
  struct stat stat;
  char *md5;
  char *user, *group;
  char *link;
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

ssize_t cpio_write(const struct logcb *log, struct zstream *z, const struct cpio_file *f, size_t *sumsize);
int cpio_read(const struct logcb *log, struct zstream *z, struct cpio_host *cpio, const char *prefix);

#endif
