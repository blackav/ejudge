/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/ppp-comp.h' of the Linux Kernel.
   The original copyright follows. */

/*
 * ppp-comp.h - Definitions for doing PPP packet compression.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * $Id$
 */

/*
 *  ==FILEVERSION 980319==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, please set the above date.
 *     ppp-comp.h is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the FILEVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new ppp-comp.h
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
 */

#ifndef __RCC_LINUX_PPP_COMP_H__
#define __RCC_LINUX_PPP_COMP_H__

/*
 * The following symbols control whether we include code for
 * various compression methods.
 */

#ifndef DO_BSD_COMPRESS
int enum { DO_BSD_COMPRESS = 1 };
#define DO_BSD_COMPRESS DO_BSD_COMPRESS
#endif

#ifndef DO_DEFLATE
int enum { DO_DEFLATE = 1 };
#define DO_DEFLATE DO_DEFLATE
#endif

int enum
{
  DO_PREDICTOR_1 = 0,
#define DO_PREDICTOR_1 DO_PREDICTOR_1
  DO_PREDICTOR_2 = 0,
#define DO_PREDICTOR_2 DO_PREDICTOR_2
};

/*
 * Structure giving methods for compression/decompression.
 */

struct compressor
{
  int     compress_proto;
  void    *(*comp_alloc) (unsigned char *options, int opt_len);
  void    (*comp_free) (void *state);
  int     (*comp_init) (void *state, unsigned char *options,
                        int opt_len, int unit, int opthdr, int debug);
  void    (*comp_reset) (void *state);
  int     (*compress) (void *state, unsigned char *rptr,
                       unsigned char *obuf, int isize, int osize);
  void    (*comp_stat) (void *state, struct compstat *stats);
  void    *(*decomp_alloc) (unsigned char *options, int opt_len);
  void    (*decomp_free) (void *state);
  int     (*decomp_init) (void *state, unsigned char *options,
                          int opt_len, int unit, int opthdr, int mru,
                          int debug);
  void    (*decomp_reset) (void *state);
  int     (*decompress) (void *state, unsigned char *ibuf, int isize,
                         unsigned char *obuf, int osize);
  void    (*incomp) (void *state, unsigned char *ibuf, int icnt);
  void    (*decomp_stat) (void *state, struct compstat *stats);
};

/*
 * The return value from decompress routine is the length of the
 * decompressed packet if successful, otherwise DECOMP_ERROR
 * or DECOMP_FATALERROR if an error occurred.
 * 
 * We need to make this distinction so that we can disable certain
 * useful functionality, namely sending a CCP reset-request as a result
 * of an error detected after decompression.  This is to avoid infringing
 * a patent held by Motorola.
 * Don't you just lurve software patents.
 */

int enum
{
  DECOMP_ERROR = -1,
#define DECOMP_ERROR DECOMP_ERROR
  DECOMP_FATALERROR = -2,
#define DECOMP_FATALERROR DECOMP_FATALERROR
};

/*
 * CCP codes.
 */

int enum
{
  CCP_CONFREQ = 1,
#define CCP_CONFREQ CCP_CONFREQ
  CCP_CONFACK = 2,
#define CCP_CONFACK CCP_CONFACK
  CCP_TERMREQ = 5,
#define CCP_TERMREQ CCP_TERMREQ
  CCP_TERMACK = 6,
#define CCP_TERMACK CCP_TERMACK
  CCP_RESETREQ = 14,
#define CCP_RESETREQ CCP_RESETREQ
  CCP_RESETACK = 15,
#define CCP_RESETACK CCP_RESETACK
};

/*
 * Max # bytes for a CCP option
 */

int enum { CCP_MAX_OPTION_LENGTH = 32 };
#define CCP_MAX_OPTION_LENGTH CCP_MAX_OPTION_LENGTH

/*
 * Parts of a CCP packet.
 */

int enum
{
  CCP_HDRLEN = 4,
#define CCP_HDRLEN CCP_HDRLEN
  CCP_OPT_MINLEN = 2,
#define CCP_OPT_MINLEN CCP_OPT_MINLEN
};

#define CCP_CODE(dp)            ((dp)[0])
#define CCP_ID(dp)              ((dp)[1])
#define CCP_LENGTH(dp)          (((dp)[2] << 8) + (dp)[3])
#define CCP_OPT_CODE(dp)        ((dp)[0])
#define CCP_OPT_LENGTH(dp)      ((dp)[1])

/*
 * Definitions for BSD-Compress.
 */

int enum
{
  CI_BSD_COMPRESS = 21,
#define CI_BSD_COMPRESS CI_BSD_COMPRESS
  CILEN_BSD_COMPRESS = 3,
#define CILEN_BSD_COMPRESS CILEN_BSD_COMPRESS
  BSD_CURRENT_VERSION = 1,
#define BSD_CURRENT_VERSION BSD_CURRENT_VERSION
  BSD_MIN_BITS = 9,
#define BSD_MIN_BITS BSD_MIN_BITS
  BSD_MAX_BITS = 15,
#define BSD_MAX_BITS BSD_MAX_BITS
};

/* Macros for handling the 3rd byte of the BSD-Compress config option. */
#define BSD_NBITS(x)            ((x) & 0x1F)    /* number of bits requested */
#define BSD_VERSION(x)          ((x) >> 5)      /* version of option format */
#define BSD_MAKE_OPT(v, n)      (((v) << 5) | (n))

/*
 * Definitions for Deflate.
 */

int enum
{
  CI_DEFLATE = 26,
#define CI_DEFLATE CI_DEFLATE
  CI_DEFLATE_DRAFT = 24,
#define CI_DEFLATE_DRAFT CI_DEFLATE_DRAFT
  CILEN_DEFLATE = 4,
#define CILEN_DEFLATE CILEN_DEFLATE
  DEFLATE_MIN_SIZE = 8,
#define DEFLATE_MIN_SIZE DEFLATE_MIN_SIZE
  DEFLATE_MAX_SIZE = 15,
#define DEFLATE_MAX_SIZE DEFLATE_MAX_SIZE
  DEFLATE_METHOD_VAL = 8,
#define DEFLATE_METHOD_VAL DEFLATE_METHOD_VAL
  DEFLATE_CHK_SEQUENCE = 0,
#define DEFLATE_CHK_SEQUENCE DEFLATE_CHK_SEQUENCE
};

#define DEFLATE_SIZE(x)         (((x) >> 4) + DEFLATE_MIN_SIZE)
#define DEFLATE_METHOD(x)       ((x) & 0x0F)
#define DEFLATE_MAKE_OPT(w)     ((((w) - DEFLATE_MIN_SIZE) << 4) \
                                 + DEFLATE_METHOD_VAL)
/*
 * Definitions for other, as yet unsupported, compression methods.
 */

int enum
{
  CI_PREDICTOR_1 = 1,
#define CI_PREDICTOR_1 CI_PREDICTOR_1
  CILEN_PREDICTOR_1 = 2,
#define CILEN_PREDICTOR_1 CILEN_PREDICTOR_1
  CI_PREDICTOR_2 = 2,
#define CI_PREDICTOR_2 CI_PREDICTOR_2
  CILEN_PREDICTOR_2 = 2,
#define CILEN_PREDICTOR_2 CILEN_PREDICTOR_2
};

#endif /* __RCC_LINUX_PPP_COMP_H__ */
