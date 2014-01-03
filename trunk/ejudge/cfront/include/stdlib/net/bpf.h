/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `net/bpf.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*-
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence 
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 *      @(#)bpf.h       7.1 (Berkeley) 5/7/91
 */

#ifndef __RCC_NET_BPF_H__
#define __RCC_NET_BPF_H__

/* BSD style release date */
#define BPF_RELEASE 199606

#include <features.h>
#include <sys/types.h>
typedef int bpf_int32;
typedef u_int bpf_u_int32;

/*
 * Alignment macros.  BPF_WORDALIGN rounds up to the next 
 * even multiple of BPF_ALIGNMENT. 
 */
#define BPF_ALIGNMENT sizeof(bpf_int32)
#define BPF_WORDALIGN(x) (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))

int enum
{
  BPF_MAXINSNS = 512,
#define BPF_MAXINSNS BPF_MAXINSNS
  BPF_MAXBUFSIZE = 0x8000,
#define BPF_MAXBUFSIZE BPF_MAXBUFSIZE
  BPF_MINBUFSIZE = 32,
#define BPF_MINBUFSIZE BPF_MINBUFSIZE
};

/*
 *  Structure for BIOCSETF.
 */
struct bpf_program
{
  u_int bf_len;
  struct bpf_insn *bf_insns;
};
 
/*
 * Struct returned by BIOCGSTATS.
 */
struct bpf_stat
{
  u_int bs_recv;
  u_int bs_drop;
};

/*
 * Struct return by BIOCVERSION.  This represents the version number of 
 * the filter language described by the instruction encodings below.
 * bpf understands a program iff kernel_major == filter_major &&
 * kernel_minor >= filter_minor, that is, if the value returned by the
 * running kernel has the same major number and a minor number equal
 * equal to or less than the filter being downloaded.  Otherwise, the
 * results are undefined, meaning an error may be returned or packets
 * may be accepted haphazardly.
 * It has nothing to do with the source code version.
 */
struct bpf_version
{
  u_short bv_major;
  u_short bv_minor;
};

/* Current version number of filter architecture. */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*
 * BPF ioctls
 *
 * The first set is for compatibility with Sun's pcc style
 * header files.  If your using gcc, we assume that you
 * have run fixincludes so the latter set should work.
 */
#define BIOCGBLEN       _IOR('B',102, u_int)
#define BIOCSBLEN       _IOWR('B',102, u_int)
#define BIOCSETF        _IOW('B',103, struct bpf_program)
#define BIOCFLUSH       _IO('B',104)
#define BIOCPROMISC     _IO('B',105)
#define BIOCGDLT        _IOR('B',106, u_int)
#define BIOCGETIF       _IOR('B',107, struct ifreq)
#define BIOCSETIF       _IOW('B',108, struct ifreq)
#define BIOCSRTIMEOUT   _IOW('B',109, struct timeval)
#define BIOCGRTIMEOUT   _IOR('B',110, struct timeval)
#define BIOCGSTATS      _IOR('B',111, struct bpf_stat)
#define BIOCIMMEDIATE   _IOW('B',112, u_int)
#define BIOCVERSION     _IOR('B',113, struct bpf_version)
#define BIOCSTCPF       _IOW('B',114, struct bpf_program)
#define BIOCSUDPF       _IOW('B',115, struct bpf_program)

/*
 * Structure prepended to each packet.
 */
struct bpf_hdr
{
  struct timeval  bh_tstamp;
  bpf_u_int32     bh_caplen;
  bpf_u_int32     bh_datalen;
  u_short         bh_hdrlen;
};

/*
 * These are the types that are the same on all platforms; on other
 * platforms, a <net/bpf.h> should be supplied that defines the additional
 * DLT_* codes appropriately for that platform (the BSDs, for example,
 * should not just pick up this version of "bpf.h"; they should also define
 * the additional DLT_* codes used by their kernels, as well as the values
 * defined here - and, if the values they use for particular DLT_ types
 * differ from those here, they should use their values, not the ones
 * here).
 */
int enum
{
  DLT_NULL = 0,
#define DLT_NULL DLT_NULL
  DLT_EN10MB = 1,
#define DLT_EN10MB DLT_EN10MB
  DLT_EN3MB = 2,
#define DLT_EN3MB DLT_EN3MB
  DLT_AX25 = 3,
#define DLT_AX25 DLT_AX25
  DLT_PRONET = 4,
#define DLT_PRONET DLT_PRONET
  DLT_CHAOS = 5,
#define DLT_CHAOS DLT_CHAOS
  DLT_IEEE802 = 6,
#define DLT_IEEE802 DLT_IEEE802
  DLT_ARCNET = 7,
#define DLT_ARCNET DLT_ARCNET
  DLT_SLIP = 8,
#define DLT_SLIP DLT_SLIP
  DLT_PPP = 9,
#define DLT_PPP DLT_PPP
  DLT_FDDI = 10,
#define DLT_FDDI DLT_FDDI
  DLT_ATM_RFC1483 = 11,
#define DLT_ATM_RFC1483 DLT_ATM_RFC1483
  DLT_RAW = 12,
#define DLT_RAW DLT_RAW
  DLT_SLIP_BSDOS = 15,
#define DLT_SLIP_BSDOS DLT_SLIP_BSDOS
  DLT_PPP_BSDOS = 16,
#define DLT_PPP_BSDOS DLT_PPP_BSDOS
  DLT_ATM_CLIP = 19,
#define DLT_ATM_CLIP DLT_ATM_CLIP
  DLT_PPP_SERIAL = 50,
#define DLT_PPP_SERIAL DLT_PPP_SERIAL
  DLT_C_HDLC = 104,
#define DLT_C_HDLC DLT_C_HDLC
  DLT_CHDLC = DLT_C_HDLC,
#define DLT_CHDLC DLT_CHDLC
  DLT_IEEE802_11 = 105,
#define DLT_IEEE802_11 DLT_IEEE802_11
  DLT_LOOP = 108,
#define DLT_LOOP DLT_LOOP
  DLT_LINUX_SLL = 113,
#define DLT_LINUX_SLL DLT_LINUX_SLL
};

/*
 * The instruction encodings.
 */
/* instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_MODE(code)  ((code) & 0xe0)
#define BPF_OP(code)    ((code) & 0xf0)
#define BPF_SRC(code)   ((code) & 0x08)
#define BPF_RVAL(code)  ((code) & 0x18)
#define BPF_MISCOP(code) ((code) & 0xf8)

int enum
{
  BPF_LD = 0x00,
#define BPF_LD BPF_LD
  BPF_LDX = 0x01,
#define BPF_LDX BPF_LDX
  BPF_ST = 0x02,
#define BPF_ST BPF_ST
  BPF_STX = 0x03,
#define BPF_STX BPF_STX
  BPF_ALU = 0x04,
#define BPF_ALU BPF_ALU
  BPF_JMP = 0x05,
#define BPF_JMP BPF_JMP
  BPF_RET = 0x06,
#define BPF_RET BPF_RET
  BPF_MISC = 0x07,
#define BPF_MISC BPF_MISC
  BPF_W = 0x00,
#define BPF_W BPF_W
  BPF_H = 0x08,
#define BPF_H BPF_H
  BPF_B = 0x10,
#define BPF_B BPF_B
  BPF_IMM = 0x00,
#define BPF_IMM BPF_IMM
  BPF_ABS = 0x20,
#define BPF_ABS BPF_ABS
  BPF_IND = 0x40,
#define BPF_IND BPF_IND
  BPF_MEM = 0x60,
#define BPF_MEM BPF_MEM
  BPF_LEN = 0x80,
#define BPF_LEN BPF_LEN
  BPF_MSH = 0xa0,
#define BPF_MSH BPF_MSH
  BPF_ADD = 0x00,
#define BPF_ADD BPF_ADD
  BPF_SUB = 0x10,
#define BPF_SUB BPF_SUB
  BPF_MUL = 0x20,
#define BPF_MUL BPF_MUL
  BPF_DIV = 0x30,
#define BPF_DIV BPF_DIV
  BPF_OR = 0x40,
#define BPF_OR BPF_OR
  BPF_AND = 0x50,
#define BPF_AND BPF_AND
  BPF_LSH = 0x60,
#define BPF_LSH BPF_LSH
  BPF_RSH = 0x70,
#define BPF_RSH BPF_RSH
  BPF_NEG = 0x80,
#define BPF_NEG BPF_NEG
  BPF_JA = 0x00,
#define BPF_JA BPF_JA
  BPF_JEQ = 0x10,
#define BPF_JEQ BPF_JEQ
  BPF_JGT = 0x20,
#define BPF_JGT BPF_JGT
  BPF_JGE = 0x30,
#define BPF_JGE BPF_JGE
  BPF_JSET = 0x40,
#define BPF_JSET BPF_JSET
  BPF_K = 0x00,
#define BPF_K BPF_K
  BPF_X = 0x08,
#define BPF_X BPF_X
  BPF_A = 0x10,
#define BPF_A BPF_A
  BPF_TAX = 0x00,
#define BPF_TAX BPF_TAX
  BPF_TXA = 0x80,
#define BPF_TXA BPF_TXA
};

/*
 * The instruction data structure.
 */
struct bpf_insn
{
  u_short code;
  u_char  jt;
  u_char  jf;
  bpf_int32 k;
};

/*
 * Macros for insn array initializers.
 */
#define BPF_STMT(code, k) { (u_short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (u_short)(code), jt, jf, k }

int bpf_validate(struct bpf_insn *, int);
u_int bpf_filter(struct bpf_insn *, u_char *, u_int, u_int);

/*
 * Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
 */
int enum { BPF_MEMWORDS = 16 };
#define BPF_MEMWORDS BPF_MEMWORDS

#endif /* __RCC_NET_BPF_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "u_short" "u_char" "u_int" "bpf_int32" "bpf_u_int32")
 * End:
 */
