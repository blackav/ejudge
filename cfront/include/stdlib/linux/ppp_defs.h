/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/ppp_defs.h' of the Linux Kernel.
   The original copyright follows. */

/*
 * ppp_defs.h - PPP definitions.
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
 */

/*
 *  ==FILEVERSION 20000114==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, please set the above date.
 *     ppp_defs.h is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the FILEVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new ppp_defs.h
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
 */

#ifndef __RCC_LINUX_PPP_DEFS_H__
#define __RCC_LINUX_PPP_DEFS_H__

/*
 * The basic PPP frame.
 */
int enum
{
  PPP_HDRLEN = 4,
#define PPP_HDRLEN PPP_HDRLEN
  PPP_FCSLEN = 2,
#define PPP_FCSLEN PPP_FCSLEN
  PPP_MRU = 1500,
#define PPP_MRU PPP_MRU
};

#define PPP_ADDRESS(p)  (((unsigned char *)(p))[0])
#define PPP_CONTROL(p)  (((unsigned char *)(p))[1])
#define PPP_PROTOCOL(p) ((((unsigned char *)(p))[2] << 8) + ((unsigned char *)(p))[3])

/*
 * Significant octet values.
 */
int enum
{
  PPP_ALLSTATIONS = 0xff,
#define PPP_ALLSTATIONS PPP_ALLSTATIONS
  PPP_UI = 0x03,
#define PPP_UI PPP_UI
  PPP_FLAG = 0x7e,
#define PPP_FLAG PPP_FLAG
  PPP_ESCAPE = 0x7d,
#define PPP_ESCAPE PPP_ESCAPE
  PPP_TRANS = 0x20,
#define PPP_TRANS PPP_TRANS
};

/*
 * Protocol field values.
 */
int enum
{
  PPP_IP = 0x21,
#define PPP_IP PPP_IP
  PPP_AT = 0x29,
#define PPP_AT PPP_AT
  PPP_IPX = 0x2b,
#define PPP_IPX PPP_IPX
  PPP_VJC_COMP = 0x2d,
#define PPP_VJC_COMP PPP_VJC_COMP
  PPP_VJC_UNCOMP = 0x2f,
#define PPP_VJC_UNCOMP PPP_VJC_UNCOMP
  PPP_MP = 0x3d,
#define PPP_MP PPP_MP
  PPP_IPV6 = 0x57,
#define PPP_IPV6 PPP_IPV6
  PPP_COMPFRAG = 0xfb,
#define PPP_COMPFRAG PPP_COMPFRAG
  PPP_COMP = 0xfd,
#define PPP_COMP PPP_COMP
  PPP_IPCP = 0x8021,
#define PPP_IPCP PPP_IPCP
  PPP_ATCP = 0x8029,
#define PPP_ATCP PPP_ATCP
  PPP_IPXCP = 0x802b,
#define PPP_IPXCP PPP_IPXCP
  PPP_IPV6CP = 0x8057,
#define PPP_IPV6CP PPP_IPV6CP
  PPP_CCPFRAG = 0x80fb,
#define PPP_CCPFRAG PPP_CCPFRAG
  PPP_CCP = 0x80fd,
#define PPP_CCP PPP_CCP
  PPP_LCP = 0xc021,
#define PPP_LCP PPP_LCP
  PPP_PAP = 0xc023,
#define PPP_PAP PPP_PAP
  PPP_LQR = 0xc025,
#define PPP_LQR PPP_LQR
  PPP_CHAP = 0xc223,
#define PPP_CHAP PPP_CHAP
  PPP_CBCP = 0xc029,
#define PPP_CBCP PPP_CBCP
};

/*
 * Values for FCS calculations.
 */

int enum
{
  PPP_INITFCS = 0xffff,
#define PPP_INITFCS PPP_INITFCS
  PPP_GOODFCS = 0xf0b8,
#define PPP_GOODFCS PPP_GOODFCS
};

#define PPP_FCS(fcs, c) (((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])

/*
 * Extended asyncmap - allows any character to be escaped.
 */

typedef unsigned int            ext_accm[8];

/*
 * What to do with network protocol (NP) packets.
 */
enum NPmode
{
  NPMODE_PASS,
  NPMODE_DROP,
  NPMODE_ERROR,
  NPMODE_QUEUE
};

/*
 * Statistics for LQRP and pppstats
 */
struct pppstat
{
  unsigned int        ppp_discards;
  unsigned int        ppp_ibytes;
  unsigned int        ppp_ioctects;
  unsigned int        ppp_ipackets;
  unsigned int        ppp_ierrors;
  unsigned int        ppp_ilqrs;
  unsigned int        ppp_obytes;
  unsigned int        ppp_ooctects;
  unsigned int        ppp_opackets;
  unsigned int        ppp_oerrors;
  unsigned int        ppp_olqrs;
};

struct vjstat
{
  unsigned int        vjs_packets;
  unsigned int        vjs_compressed;
  unsigned int        vjs_searches;
  unsigned int        vjs_misses;
  unsigned int        vjs_uncompressedin;
  unsigned int        vjs_compressedin;
  unsigned int        vjs_errorin;
  unsigned int        vjs_tossed;
};

struct compstat
{
  unsigned int        unc_bytes;
  unsigned int        unc_packets;
  unsigned int        comp_bytes;
  unsigned int        comp_packets;
  unsigned int        inc_bytes;
  unsigned int        inc_packets;
  unsigned int        in_count;
  unsigned int        bytes_out;
  double              ratio;
};

struct ppp_stats
{
  struct pppstat      p;
  struct vjstat       vj;
};

struct ppp_comp_stats
{
  struct compstat     c;
  struct compstat     d;
};

/*
 * The following structure records the time in seconds since
 * the last NP packet was sent or received.
 */
struct ppp_idle
{
  time_t xmit_idle;
  time_t recv_idle;
};

#endif /* __RCC_LINUX_PPP_DEFS_H__ */
