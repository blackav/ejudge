/* -*- c -*- */
/* $Id$ */

#ifndef __SHA_H__
#define __SHA_H__ 1

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* This file is taken from textutils-2.1. Cher. */

/* sha.h - Declaration of functions and datatypes for SHA1 sum computing
   library functions.

   Copyright (C) 1999, Scott G. Miller
*/

#include <reuse/ReuseDefs.h>
#if defined REUSE_VERSION && REUSE_VERSION >= 4
#include <reuse/integral.h>
#else
#include <p_integral.h>
#endif /* reuse version >= 4 */

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
   in first 20 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha_finish_ctx(struct sha_ctx *ctx, void *resbuf);

/* Put result from CTX in first 20 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha_read_ctx(const struct sha_ctx *ctx, void *resbuf);

/* Compute SHA1 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 20 bytes
   beginning at RESBLOCK.  */
int sha_stream(FILE *stream, void *resblock);

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *sha_buffer(const char *buffer, size_t len, void *resblock);

#endif /* __SHA_H__ */

