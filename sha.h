/* -*- c -*- */
/* $Id$ */

/* sha.h - Declaration of functions and datatypes for SHA1 sum computing
   library functions.

   Copyright (C) 1999, Scott G. Miller
*/

#ifndef __SHA_H__
#define __SHA_H__ 1

#include <p_integral.h>

#include <stdio.h>

/* Structure to save state of computation between the single steps.  */
struct sha_ctx
{
  ruint32_t A;
  ruint32_t B;
  ruint32_t C;
  ruint32_t D;
  ruint32_t E;

  ruint32_t total[2];
  ruint32_t buflen;
  char buffer[128];
};


/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
void sha_process_block(const void *buffer, size_t len, struct sha_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
void sha_process_bytes(const void *buffer, size_t len, struct sha_ctx *ctx);

/* Initialize structure containing state of computation. */
void sha_init_ctx(struct sha_ctx *ctx);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha_finish_ctx(struct sha_ctx *ctx, void *resbuf);


/* Put result from CTX in first 16 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha_read_ctx(const struct sha_ctx *ctx, void *resbuf);


/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
int sha_stream(FILE *stream, void *resblock);

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *sha_buffer(const char *buffer, size_t len, void *resblock);

#endif /* __SHA_H__ */

