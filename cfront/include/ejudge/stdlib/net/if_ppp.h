/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `net/if_ppp.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*      From: if_ppp.h,v 1.3 1995/06/12 11:36:50 paulus Exp */

/*
 * if_ppp.h - Point-to-Point Protocol definitions.
 *
 * Copyright (c) 1989 Carnegie Mellon University. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CARNEGIE MELLON UNIVERSITY AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 *  ==FILEVERSION 960926==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, please set the above date.
 *     if_ppp.h is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the FILEVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new if_ppp.h
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
 */

#ifndef __RCC_NET_IF_PPP_H__
#define __RCC_NET_IF_PPP_H__ 1

#include <features.h>
#include <sys/types.h>
//#include <sys/cdefs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ppp_defs.h>


/*
 * Packet sizes
 */

#define PPP_VERSION     "2.2.0"

int enum
{
  PPP_MTU = 1500,
#define PPP_MTU PPP_MTU
  PPP_MAXMRU = 65000,
#define PPP_MAXMRU PPP_MAXMRU
  PPP_MAGIC = 0x5002,
#define PPP_MAGIC PPP_MAGIC
  PROTO_IPX = 0x002b,
#define PROTO_IPX PROTO_IPX
  PROTO_DNA_RT = 0x0027,
#define PROTO_DNA_RT PROTO_DNA_RT
};

/*
 * Bit definitions for flags.
 */
int enum
{
  SC_COMP_PROT = 0x00000001,
#define SC_COMP_PROT SC_COMP_PROT
  SC_COMP_AC = 0x00000002,
#define SC_COMP_AC SC_COMP_AC
  SC_COMP_TCP = 0x00000004,
#define SC_COMP_TCP SC_COMP_TCP
  SC_NO_TCP_CCID = 0x00000008,
#define SC_NO_TCP_CCID SC_NO_TCP_CCID
  SC_REJ_COMP_AC = 0x00000010,
#define SC_REJ_COMP_AC SC_REJ_COMP_AC
  SC_REJ_COMP_TCP = 0x00000020,
#define SC_REJ_COMP_TCP SC_REJ_COMP_TCP
  SC_CCP_OPEN = 0x00000040,
#define SC_CCP_OPEN SC_CCP_OPEN
  SC_CCP_UP = 0x00000080,
#define SC_CCP_UP SC_CCP_UP
  SC_ENABLE_IP = 0x00000100,
#define SC_ENABLE_IP SC_ENABLE_IP
  SC_COMP_RUN = 0x00001000,
#define SC_COMP_RUN SC_COMP_RUN
  SC_DECOMP_RUN = 0x00002000,
#define SC_DECOMP_RUN SC_DECOMP_RUN
  SC_DEBUG = 0x00010000,
#define SC_DEBUG SC_DEBUG
  SC_LOG_INPKT = 0x00020000,
#define SC_LOG_INPKT SC_LOG_INPKT
  SC_LOG_OUTPKT = 0x00040000,
#define SC_LOG_OUTPKT SC_LOG_OUTPKT
  SC_LOG_RAWIN = 0x00080000,
#define SC_LOG_RAWIN SC_LOG_RAWIN
  SC_LOG_FLUSH = 0x00100000,
#define SC_LOG_FLUSH SC_LOG_FLUSH
  SC_MASK = 0x0fE0ffff,
#define SC_MASK SC_MASK
  SC_ESCAPED = 0x80000000,
#define SC_ESCAPED SC_ESCAPED
  SC_FLUSH = 0x40000000,
#define SC_FLUSH SC_FLUSH
  SC_VJ_RESET = 0x20000000,
#define SC_VJ_RESET SC_VJ_RESET
  SC_XMIT_BUSY = 0x10000000,
#define SC_XMIT_BUSY SC_XMIT_BUSY
  SC_RCV_ODDP = 0x08000000,
#define SC_RCV_ODDP SC_RCV_ODDP
  SC_RCV_EVNP = 0x04000000,
#define SC_RCV_EVNP SC_RCV_EVNP
  SC_RCV_B7_1 = 0x02000000,
#define SC_RCV_B7_1 SC_RCV_B7_1
  SC_RCV_B7_0 = 0x01000000,
#define SC_RCV_B7_0 SC_RCV_B7_0
  SC_DC_FERROR = 0x00800000,
#define SC_DC_FERROR SC_DC_FERROR
  SC_DC_ERROR = 0x00400000,
#define SC_DC_ERROR SC_DC_ERROR
};

/*
 * Ioctl definitions.
 */
struct npioctl
{
  int         protocol;
  enum NPmode mode;
};

/* Structure describing a CCP configuration option, for PPPIOCSCOMPRESS */
struct ppp_option_data
{
  u_int8_t  *ptr;
  u_int32_t length;
  int       transmit;
};

struct ifpppstatsreq
{
  struct ifreq     b;
  struct ppp_stats stats;
};

struct ifpppcstatsreq
{
  struct ifreq          b;
  struct ppp_comp_stats stats;
};

#define ifr__name       b.ifr_ifrn.ifrn_name
#define stats_ptr       b.ifr_ifru.ifru_data

/*
 * Ioctl definitions.
 */

#define PPPIOCGFLAGS    _IOR('t', 90, int)      /* get configuration flags */
#define PPPIOCSFLAGS    _IOW('t', 89, int)      /* set configuration flags */
#define PPPIOCGASYNCMAP _IOR('t', 88, int)      /* get async map */
#define PPPIOCSASYNCMAP _IOW('t', 87, int)      /* set async map */
#define PPPIOCGUNIT     _IOR('t', 86, int)      /* get ppp unit number */
#define PPPIOCGRASYNCMAP _IOR('t', 85, int)     /* get receive async map */
#define PPPIOCSRASYNCMAP _IOW('t', 84, int)     /* set receive async map */
#define PPPIOCGMRU      _IOR('t', 83, int)      /* get max receive unit */
#define PPPIOCSMRU      _IOW('t', 82, int)      /* set max receive unit */
#define PPPIOCSMAXCID   _IOW('t', 81, int)      /* set VJ max slot ID */
#define PPPIOCGXASYNCMAP _IOR('t', 80, ext_accm) /* get extended ACCM */
#define PPPIOCSXASYNCMAP _IOW('t', 79, ext_accm) /* set extended ACCM */
#define PPPIOCXFERUNIT  _IO('t', 78)            /* transfer PPP unit */
#define PPPIOCSCOMPRESS _IOW('t', 77, struct ppp_option_data)
#define PPPIOCGNPMODE   _IOWR('t', 76, struct npioctl) /* get NP mode */
#define PPPIOCSNPMODE   _IOW('t', 75, struct npioctl)  /* set NP mode */
#define PPPIOCGDEBUG    _IOR('t', 65, int)      /* Read debug level */
#define PPPIOCSDEBUG    _IOW('t', 64, int)      /* Set debug level */
#define PPPIOCGIDLE     _IOR('t', 63, struct ppp_idle) /* get idle time */

#define SIOCGPPPSTATS   (SIOCDEVPRIVATE + 0)
#define SIOCGPPPVER     (SIOCDEVPRIVATE + 1)  /* NEVER change this!! */
#define SIOCGPPPCSTATS  (SIOCDEVPRIVATE + 2)

#if !defined(ifr_mtu)
#define ifr_mtu ifr_ifru.ifru_metric
#endif

#endif /* __RCC_NET_IF_PPP_H__ */
