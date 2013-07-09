#include "md5.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct sockaddr_alg {
        uint16_t salg_family;
        uint8_t salg_type[14];
	uint32_t salg_feat;
        uint32_t salg_mask;
	uint8_t salg_name[64];
};

int MD5Init(MD5_CTX *ctx)
{
        struct sockaddr_alg sa = {
                .salg_family = AF_ALG,
                .salg_type = "hash",
                .salg_name = "md5"
        };
        ctx->algfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if(ctx->algfd == -1) return 1;
        if(bind(ctx->algfd, (struct sockaddr *)&sa, sizeof(sa)))
		return 2;
        ctx->fd = accept(ctx->algfd, NULL, 0);
	if(ctx->fd == -1) return 3;
	return 0;
}

int MD5Update(MD5_CTX *ctx, const unsigned char *buf, unsigned int len)
{
	ssize_t n;
	n = send(ctx->fd, buf, len, MSG_MORE);
	if(n != len) return 1;
	return 0;
}

int MD5Final(unsigned char *digest, MD5_CTX *ctx)
{
	ssize_t n;
	n = read(ctx->fd, digest, MD5_DIGEST_LENGTH);
	close(ctx->fd);
	close(ctx->algfd);
	if( n != MD5_DIGEST_LENGTH )
                return 1;
        return 0;
}
