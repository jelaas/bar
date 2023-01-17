/* SHA256-based Unix crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.

   Modified by jens@laas.mine.nu. So all bugs belong to me.
  */

#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include "sha256.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#else
# define SWAP(n) (n)
#endif


/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };


/* Constants for SHA256 from FIPS 180-2:4.2.2.  */
static const uint32_t K[64] =
  {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };


/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void sha256_process_block (const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	unsigned int t;
	const uint32_t *words = buffer;
	size_t nwords = len / sizeof (uint32_t);
	uint32_t a = ctx->H[0];
	uint32_t b = ctx->H[1];
	uint32_t c = ctx->H[2];
	uint32_t d = ctx->H[3];
	uint32_t e = ctx->H[4];
	uint32_t f = ctx->H[5];
	uint32_t g = ctx->H[6];
	uint32_t h = ctx->H[7];
	
	/* First increment the byte count.  FIPS 180-2 specifies the possible
	   length of the file up to 2^64 bits.  Here we only compute the
	   number of bytes.  Do a double word increment.  */
	ctx->total[0] += len;
	if (ctx->total[0] < len)
		++ctx->total[1];
	
	/* Process all bytes in the buffer with 64 bytes in each round of
	   the loop.  */
	while (nwords > 0) {
		uint32_t W[64];
		uint32_t a_save = a;
		uint32_t b_save = b;
		uint32_t c_save = c;
		uint32_t d_save = d;
		uint32_t e_save = e;
		uint32_t f_save = f;
		uint32_t g_save = g;
		uint32_t h_save = h;

		/* Operators defined in FIPS 180-2:4.1.2.  */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC (x, 2) ^ CYCLIC (x, 13) ^ CYCLIC (x, 22))
#define S1(x) (CYCLIC (x, 6) ^ CYCLIC (x, 11) ^ CYCLIC (x, 25))
#define R0(x) (CYCLIC (x, 7) ^ CYCLIC (x, 18) ^ (x >> 3))
#define R1(x) (CYCLIC (x, 17) ^ CYCLIC (x, 19) ^ (x >> 10))
		
		/* It is unfortunate that C does not provide an operator for
		   cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) ((w >> s) | (w << (32 - s)))
		
		/* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
		for (t = 0; t < 16; ++t) {
			W[t] = SWAP (*words);
			++words;
		}
		for (t = 16; t < 64; ++t)
			W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];
		
		/* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
		for (t = 0; t < 64; ++t) {
			uint32_t T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
			uint32_t T2 = S0 (a) + Maj (a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		
		/* Add the starting values of the context according to FIPS 180-2:6.2.2
		   step 4.  */
		a += a_save;
		b += b_save;
		c += c_save;
		d += d_save;
		e += e_save;
		f += f_save;
		g += g_save;
		h += h_save;
		
		/* Prepare for the next round.  */
		nwords -= 16;
	}
	
	/* Put checksum in context given as argument.  */
	ctx->H[0] = a;
	ctx->H[1] = b;
	ctx->H[2] = c;
	ctx->H[3] = d;
	ctx->H[4] = e;
	ctx->H[5] = f;
	ctx->H[6] = g;
	ctx->H[7] = h;
}


/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
void sha256_init_ctx (struct sha256_ctx *ctx)
{
  ctx->H[0] = 0x6a09e667;
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}


/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha256_finish_ctx (struct sha256_ctx *ctx, void *resbuf)
{
	/* Take yet unprocessed bytes into account.  */
	unsigned int i;
	uint32_t bytes = ctx->buflen;
	size_t pad;
	
	/* Now count remaining bytes.  */
	ctx->total[0] += bytes;
	if (ctx->total[0] < bytes)
		++ctx->total[1];
	
	pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
	memcpy (&ctx->buffer[bytes], fillbuf, pad);
	
	/* Put the 64-bit file length in *bits* at the end of the buffer.  */
	*(uint32_t *) &ctx->buffer[bytes + pad + 4] = SWAP (ctx->total[0] << 3);
	*(uint32_t *) &ctx->buffer[bytes + pad] = SWAP ((ctx->total[1] << 3) |
							(ctx->total[0] >> 29));
	
	/* Process last bytes.  */
	sha256_process_block (ctx->buffer, bytes + pad + 8, ctx);
	
	/* Put result from CTX in first 32 bytes following RESBUF.  */
	for (i = 0; i < 8; ++i)
		((uint32_t *) resbuf)[i] = SWAP (ctx->H[i]);
	
	return resbuf;
}

void sha256_process_bytes (const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	/* When we already have some bits in our internal buffer concatenate
	   both inputs first.  */
	if (ctx->buflen != 0) {
		size_t left_over = ctx->buflen;
		size_t add = 128 - left_over > len ? len : 128 - left_over;
		
		memcpy (&ctx->buffer[left_over], buffer, add);
		ctx->buflen += add;
		
		if (ctx->buflen > 64) {
			sha256_process_block (ctx->buffer, ctx->buflen & ~63, ctx);
			
			ctx->buflen &= 63;
			/* The regions in the following copy operation cannot overlap.  */
			memcpy (ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
				ctx->buflen);
		}
		
		buffer = (const char *) buffer + add;
		len -= add;
	}
	
	/* Process available complete blocks.  */
	if (len >= 64) {
/* To check alignment gcc has an appropriate operator.  Other
   compilers don't.  */
#if __GNUC__ >= 2
# define UNALIGNED_P(p) (((uintptr_t) p) % __alignof__ (uint32_t) != 0)
#else
# define UNALIGNED_P(p) (((uintptr_t) p) % sizeof (uint32_t) != 0)
#endif
		if (UNALIGNED_P (buffer))
			while (len > 64) {
				sha256_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
				buffer = (const char *) buffer + 64;
				len -= 64;
			} else {
			sha256_process_block (buffer, len & ~63, ctx);
			buffer = (const char *) buffer + (len & ~63);
			len &= 63;
		}
	}
	
	/* Move remaining bytes into internal buffer.  */
	if (len > 0) {
		size_t left_over = ctx->buflen;
		
		memcpy (&ctx->buffer[left_over], buffer, len);
		left_over += len;
		if (left_over >= 64) {
			sha256_process_block (ctx->buffer, 64, ctx);
			left_over -= 64;
			memcpy (ctx->buffer, &ctx->buffer[64], left_over);
		}
		ctx->buflen = left_over;
	}
}

#ifdef TEST
static const struct
{
  const char *input;
  const char result[32];
} tests[] =
  {
    /* Test vectors from FIPS 180-2: appendix B.1.  */
    { "abc",
      "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
      "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
    /* Test vectors from FIPS 180-2: appendix B.2.  */
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
      "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
    /* Test vectors from the NESSIE project.  */
    { "",
      "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
      "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" },
    { "a",
      "\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d"
      "\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb" },
    { "message digest",
      "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
      "\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50" },
    { "abcdefghijklmnopqrstuvwxyz",
      "\x71\xc4\x80\xdf\x93\xd6\xae\x2f\x1e\xfa\xd1\x44\x7c\x66\xc9\x52"
      "\x5e\x31\x62\x18\xcf\x51\xfc\x8d\x9e\xd8\x32\xf2\xda\xf1\x8b\x73" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
      "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80"
      "\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0" },
    { "123456789012345678901234567890123456789012345678901234567890"
      "12345678901234567890",
      "\xf3\x71\xbc\x4a\x31\x1f\x2b\x00\x9e\xef\x95\x2d\xd8\x3c\xa8\x0e"
      "\x2b\x60\x02\x6c\x8e\x93\x55\x92\xd0\xf9\xc3\x08\x45\x3c\x81\x3e" }
  };
#define ntests (sizeof (tests) / sizeof (tests[0]))


static const struct
{
  const char *salt;
  const char *input;
  const char *expected;
} tests2[] =
{
  { "$5$saltstring", "Hello world!",
    "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
  { "$5$rounds=10000$saltstringsaltstring", "Hello world!",
    "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
    "opqey6IcA" },
  { "$5$rounds=5000$toolongsaltstring", "This is just a test",
    "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
    "mGRcvxa5" },
  { "$5$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
    "than one line.",
    "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
    "oP84Bnq1" },
  { "$5$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" },
  { "$5$rounds=123456$asaltof16chars..", "a short string",
    "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
    "cZKmF/wJvD" },
  { "$5$rounds=10$roundstoolow", "the minimum number is still observed",
    "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
    "2bIC" },
};
#define ntests2 (sizeof (tests2) / sizeof (tests2[0]))


int
main (void)
{
  struct sha256_ctx ctx;
  char sum[32];
  int result = 0;
  int cnt;

  for (cnt = 0; cnt < (int) ntests; ++cnt)
    {
      sha256_init_ctx (&ctx);
      sha256_process_bytes (tests[cnt].input, strlen (tests[cnt].input), &ctx);
      sha256_finish_ctx (&ctx, sum);
      if (memcmp (tests[cnt].result, sum, 32) != 0)
	{
	  printf ("test %d run %d failed\n", cnt, 1);
	  result = 1;
	}

      sha256_init_ctx (&ctx);
      for (int i = 0; tests[cnt].input[i] != '\0'; ++i)
	sha256_process_bytes (&tests[cnt].input[i], 1, &ctx);
      sha256_finish_ctx (&ctx, sum);
      if (memcmp (tests[cnt].result, sum, 32) != 0)
	{
	  printf ("test %d run %d failed\n", cnt, 2);
	  result = 1;
	}
    }

  /* Test vector from FIPS 180-2: appendix B.3.  */
  char buf[1000];
  memset (buf, 'a', sizeof (buf));
  sha256_init_ctx (&ctx);
  for (int i = 0; i < 1000; ++i)
    sha256_process_bytes (buf, sizeof (buf), &ctx);
  sha256_finish_ctx (&ctx, sum);
  static const char expected[32] =
    "\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67"
    "\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";
  if (memcmp (expected, sum, 32) != 0)
    {
      printf ("test %d failed\n", cnt);
      result = 1;
    }

  for (cnt = 0; cnt < ntests2; ++cnt)
    {
      char *cp = sha256_crypt (tests2[cnt].input, tests2[cnt].salt);

      if (strcmp (cp, tests2[cnt].expected) != 0)
	{
	  printf ("test %d: expected \"%s\", got \"%s\"\n",
		  cnt, tests2[cnt].expected, cp);
	  result = 1;
	}
    }

  if (result == 0)
    puts ("all tests OK");

  return result;
}
#endif
