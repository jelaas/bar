#ifndef DIGEST_H
#define DIGEST_H

#include <sys/types.h>
#include "md5.h"
#include "sha256.h"

struct digest  {
  int (*init)(struct digest *);
  int (*update)(struct digest *, void *, size_t);
  int (*final)(struct digest *); /* result will be in 'sum' and 'hexstr' */
  union {
    MD5_CTX md5;
    struct sha256_ctx sha256;
  } ctx;
  union {
    unsigned char md5[MD5_DIGEST_LENGTH];
    unsigned char sha256[SHA256_DIGEST_LENGTH];
  } sum;
  union {
    char md5[MD5_DIGEST_LENGTH*2+1];
    char sha256[SHA256_DIGEST_LENGTH*2+1];
  } hex;
  char *hexstr;
  unsigned char *binary;
  int size;
};

int digest(struct digest *d, char *algo);

#define DIGEST_MAX_HEX_SIZE sizeof(((struct digest *)0)->hex)

#endif
