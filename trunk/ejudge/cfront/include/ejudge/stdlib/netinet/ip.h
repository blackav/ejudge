/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netinet/ip.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1991,92,93,95,96,97,98,99,2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_NETINET_IP_H__
#define __RCC_NETINET_IP_H__ 1

#include <features.h>
#include <sys/types.h>
#include <netinet/in.h>

struct timestamp
{
  u_int8_t len;
  u_int8_t ptr;
  unsigned int flags:4;
  unsigned int overflow:4;
  u_int32_t data[9];
};

struct iphdr
{
  unsigned int ihl:4;
  unsigned int version:4;
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
};

/*
 * Copyright (c) 1982, 1986, 1993
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
 *      @(#)ip.h        8.1 (Berkeley) 6/10/93
 */

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */

int enum
{
  IP_RF = 0x8000,
#define IP_RF IP_RF
  IP_DF = 0x4000,
#define IP_DF IP_DF
  IP_MF = 0x2000,
#define IP_MF IP_MF
  IP_OFFMASK = 0x1fff,
#define IP_OFFMASK IP_OFFMASK
};

/*
 * Structure of an internet header, naked of options.
 */
struct ip
{
  unsigned int ip_hl:4;               /* header length */
  unsigned int ip_v:4;                /* version */
  u_int8_t ip_tos;                    /* type of service */
  u_short ip_len;                     /* total length */
  u_short ip_id;                      /* identification */
  u_short ip_off;                     /* fragment offset field */
  u_int8_t ip_ttl;                    /* time to live */
  u_int8_t ip_p;                      /* protocol */
  u_short ip_sum;                     /* checksum */
  struct in_addr ip_src, ip_dst;      /* source and dest address */
};

/*
 * Time stamp option structure.
 */
struct ip_timestamp
{
  u_int8_t ipt_code;                  /* IPOPT_TS */
  u_int8_t ipt_len;                   /* size of structure (variable) */
  u_int8_t ipt_ptr;                   /* index of current entry */
  unsigned int ipt_flg:4;             /* flags, see below */
  unsigned int ipt_oflw:4;            /* overflow counter */
  u_int32_t data[9];
};

int enum
{
  IPVERSION = 4,
#define IPVERSION IPVERSION
  IP_MAXPACKET = 65535,
#define IP_MAXPACKET IP_MAXPACKET
};

/*
 * Definitions for IP type of service (ip_tos)
 */
int enum
{
  IPTOS_TOS_MASK = 0x1E,
#define IPTOS_TOS_MASK IPTOS_TOS_MASK
  IPTOS_LOWDELAY = 0x10,
#define IPTOS_LOWDELAY IPTOS_LOWDELAY
  IPTOS_THROUGHPUT = 0x08,
#define IPTOS_THROUGHPUT IPTOS_THROUGHPUT
  IPTOS_RELIABILITY = 0x04,
#define IPTOS_RELIABILITY IPTOS_RELIABILITY
  IPTOS_LOWCOST = 0x02,
#define IPTOS_LOWCOST IPTOS_LOWCOST
  IPTOS_MINCOST = IPTOS_LOWCOST,
#define IPTOS_MINCOST IPTOS_MINCOST
};

#define IPTOS_TOS(tos)          ((tos) & IPTOS_TOS_MASK)

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
int enum
{
  IPTOS_PREC_MASK = 0xe0,
#define IPTOS_PREC_MASK IPTOS_PREC_MASK
  IPTOS_PREC_NETCONTROL = 0xe0,
#define IPTOS_PREC_NETCONTROL IPTOS_PREC_NETCONTROL
  IPTOS_PREC_INTERNETCONTROL = 0xc0,
#define IPTOS_PREC_INTERNETCONTROL IPTOS_PREC_INTERNETCONTROL
  IPTOS_PREC_CRITIC_ECP = 0xa0,
#define IPTOS_PREC_CRITIC_ECP IPTOS_PREC_CRITIC_ECP
  IPTOS_PREC_FLASHOVERRIDE = 0x80,
#define IPTOS_PREC_FLASHOVERRIDE IPTOS_PREC_FLASHOVERRIDE
  IPTOS_PREC_FLASH = 0x60,
#define IPTOS_PREC_FLASH IPTOS_PREC_FLASH
  IPTOS_PREC_IMMEDIATE = 0x40,
#define IPTOS_PREC_IMMEDIATE IPTOS_PREC_IMMEDIATE
  IPTOS_PREC_PRIORITY = 0x20,
#define IPTOS_PREC_PRIORITY IPTOS_PREC_PRIORITY
  IPTOS_PREC_ROUTINE = 0x00,
#define IPTOS_PREC_ROUTINE IPTOS_PREC_ROUTINE
};

#define IPTOS_PREC(tos) ((tos) & IPTOS_PREC_MASK)

/*
 * Definitions for options.
 */
int enum
{
  IPOPT_COPY = 0x80,
#define IPOPT_COPY IPOPT_COPY
  IPOPT_CLASS_MASK = 0x60,
#define IPOPT_CLASS_MASK IPOPT_CLASS_MASK
  IPOPT_NUMBER_MASK = 0x1f,
#define IPOPT_NUMBER_MASK IPOPT_NUMBER_MASK
  IPOPT_CONTROL = 0x00,
#define IPOPT_CONTROL IPOPT_CONTROL
  IPOPT_RESERVED1 = 0x20,
#define IPOPT_RESERVED1 IPOPT_RESERVED1
  IPOPT_DEBMEAS = 0x40,
#define IPOPT_DEBMEAS IPOPT_DEBMEAS
  IPOPT_MEASUREMENT = IPOPT_DEBMEAS,
#define IPOPT_MEASUREMENT IPOPT_MEASUREMENT
  IPOPT_RESERVED2 = 0x60,
#define IPOPT_RESERVED2 IPOPT_RESERVED2
  IPOPT_EOL = 0,
#define IPOPT_EOL IPOPT_EOL
  IPOPT_END = IPOPT_EOL,
#define IPOPT_END IPOPT_END
  IPOPT_NOP = 1,
#define IPOPT_NOP IPOPT_NOP
  IPOPT_NOOP = IPOPT_NOP,
#define IPOPT_NOOP IPOPT_NOOP
  IPOPT_RR = 7,
#define IPOPT_RR IPOPT_RR
  IPOPT_TS = 68,
#define IPOPT_TS IPOPT_TS
  IPOPT_TIMESTAMP = IPOPT_TS,
#define IPOPT_TIMESTAMP IPOPT_TIMESTAMP
  IPOPT_SECURITY = 130,
#define IPOPT_SECURITY IPOPT_SECURITY
  IPOPT_SEC = IPOPT_SECURITY,
#define IPOPT_SEC IPOPT_SEC
  IPOPT_LSRR = 131,
#define IPOPT_LSRR IPOPT_LSRR
  IPOPT_SATID = 136,
#define IPOPT_SATID IPOPT_SATID
  IPOPT_SID = IPOPT_SATID,
#define IPOPT_SID IPOPT_SID
  IPOPT_SSRR = 137,
#define IPOPT_SSRR IPOPT_SSRR
  IPOPT_RA = 148,
#define IPOPT_RA IPOPT_RA
  IPOPT_OPTVAL = 0,
#define IPOPT_OPTVAL IPOPT_OPTVAL
  IPOPT_OLEN = 1,
#define IPOPT_OLEN IPOPT_OLEN
  IPOPT_OFFSET = 2,
#define IPOPT_OFFSET IPOPT_OFFSET
  IPOPT_MINOFF = 4,
#define IPOPT_MINOFF IPOPT_MINOFF
  MAX_IPOPTLEN = 40,
#define MAX_IPOPTLEN MAX_IPOPTLEN
  IPOPT_TS_TSONLY = 0,
#define IPOPT_TS_TSONLY IPOPT_TS_TSONLY
  IPOPT_TS_TSANDADDR = 1,
#define IPOPT_TS_TSANDADDR IPOPT_TS_TSANDADDR
  IPOPT_TS_PRESPEC = 3,
#define IPOPT_TS_PRESPEC IPOPT_TS_PRESPEC
  IPOPT_SECUR_UNCLASS = 0x0000,
#define IPOPT_SECUR_UNCLASS IPOPT_SECUR_UNCLASS
  IPOPT_SECUR_CONFID = 0xf135,
#define IPOPT_SECUR_CONFID IPOPT_SECUR_CONFID
  IPOPT_SECUR_EFTO = 0x789a,
#define IPOPT_SECUR_EFTO IPOPT_SECUR_EFTO
  IPOPT_SECUR_MMMM = 0xbc4d,
#define IPOPT_SECUR_MMMM IPOPT_SECUR_MMMM
  IPOPT_SECUR_RESTR = 0xaf13,
#define IPOPT_SECUR_RESTR IPOPT_SECUR_RESTR
  IPOPT_SECUR_SECRET = 0xd788,
#define IPOPT_SECUR_SECRET IPOPT_SECUR_SECRET
  IPOPT_SECUR_TOPSECRET = 0x6bc5,
#define IPOPT_SECUR_TOPSECRET IPOPT_SECUR_TOPSECRET
};

#define IPOPT_COPIED(o)         ((o) & IPOPT_COPY)
#define IPOPT_CLASS(o)          ((o) & IPOPT_CLASS_MASK)
#define IPOPT_NUMBER(o)         ((o) & IPOPT_NUMBER_MASK)

/*
 * Internet implementation parameters.
 */
int enum
{
  MAXTTL = 255,
#define MAXTTL MAXTTL
  IPDEFTTL = 64,
#define IPDEFTTL IPDEFTTL
  IPFRAGTTL = 60,
#define IPFRAGTTL IPFRAGTTL
  IPTTLDEC = 1,
#define IPTTLDEC IPTTLDEC
  IP_MSS = 576,
#define IP_MSS IP_MSS
};

#endif /* __RCC_NETINET_IP_H__ */
