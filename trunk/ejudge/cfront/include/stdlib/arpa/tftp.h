/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `arpa/tftp.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tftp.h      8.1 (Berkeley) 6/2/93
 */

#ifndef __RCC_ARPA_TFTP_H__
#define __RCC_ARPA_TFTP_H__ 1

#include <features.h>

/*
 * Trivial File Transfer Protocol (IEN-133)
 */
int enum { SEGSIZE = 512 };
#define SEGSIZE SEGSIZE

/*
 * Packet types.
 */
int enum
{
  RRQ = 01,
#define RRQ RRQ
  WRQ = 02,
#define WRQ WRQ
  DATA = 03,
#define DATA DATA
  ACK = 04,
#define ACK ACK
  ERROR = 05,
#define ERROR ERROR
};

struct tftphdr
{
  short   th_opcode;
  union
  {
    unsigned short  tu_block;
    short   tu_code;
    char    tu_stuff[1];
  } th_u;
  char    th_data[1];
};

#define th_block        th_u.tu_block
#define th_code         th_u.tu_code
#define th_stuff        th_u.tu_stuff
#define th_msg          th_data

/*
 * Error codes.
 */
int enum
{
  EUNDEF = 0,
#define EUNDEF EUNDEF
  ENOTFOUND = 1,
#define ENOTFOUND ENOTFOUND
  EACCESS = 2,
#define EACCESS EACCESS
  ENOSPACE = 3,
#define ENOSPACE ENOSPACE
  EBADOP = 4,
#define EBADOP EBADOP
  EBADID = 5,
#define EBADID EBADID
  EEXISTS = 6,
#define EEXISTS EEXISTS
  ENOUSER = 7,
#define ENOUSER ENOUSER
};

#endif /* __RCC_ARPA_TFTP_H__ */
