/* MD5 context. */
typedef struct {
	int fd;
	int algfd;
} MD5_CTX;

int MD5Init(MD5_CTX *);
int MD5Update(MD5_CTX *, const unsigned char *, unsigned int);
int MD5Final(unsigned char *, MD5_CTX *); /* 16 bytes */
#define MD5_DIGEST_LENGTH 16
