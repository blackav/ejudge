/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `arpa/nameser.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*
 * Copyright (c) 1983, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
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
 */

/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 *      $BINDId: nameser.h,v 8.37 2000/03/30 21:16:49 vixie Exp $
 */

#ifndef __RCC_ARPA_NAMESER_H__
#define __RCC_ARPA_NAMESER_H__

#define BIND_4_COMPAT

#include <features.h>
#include <sys/param.h>
# include <sys/types.h>

/*
 * Revision information.  This is the release date in YYYYMMDD format.
 * It can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__NAMESER > 19931104)".  Do not
 * compare for equality; rather, use it to determine whether your libbind.a
 * contains a new enough lib/nameser/ to support the feature you need.
 */

#define __NAMESER       19991006        /* New interface version stamp. */

/*
 * Define constants based on RFC 883, RFC 1034, RFC 1035
 */
int enum
{
  NS_PACKETSZ = 512,
#define NS_PACKETSZ NS_PACKETSZ
  NS_MAXDNAME = 1025,
#define NS_MAXDNAME NS_MAXDNAME
  NS_MAXCDNAME = 255,
#define NS_MAXCDNAME NS_MAXCDNAME
  NS_MAXLABEL = 63,
#define NS_MAXLABEL NS_MAXLABEL
  NS_HFIXEDSZ = 12,
#define NS_HFIXEDSZ NS_HFIXEDSZ
  NS_QFIXEDSZ = 4,
#define NS_QFIXEDSZ NS_QFIXEDSZ
  NS_RRFIXEDSZ = 10,
#define NS_RRFIXEDSZ NS_RRFIXEDSZ
  NS_INT32SZ = 4,
#define NS_INT32SZ NS_INT32SZ
  NS_INT16SZ = 2,
#define NS_INT16SZ NS_INT16SZ
  NS_INT8SZ = 1,
#define NS_INT8SZ NS_INT8SZ
  NS_INADDRSZ = 4,
#define NS_INADDRSZ NS_INADDRSZ
  NS_IN6ADDRSZ = 16,
#define NS_IN6ADDRSZ NS_IN6ADDRSZ
  NS_CMPRSFLGS = 0xc0,
#define NS_CMPRSFLGS NS_CMPRSFLGS
  NS_DEFAULTPORT = 53,
#define NS_DEFAULTPORT NS_DEFAULTPORT
};

/*
 * These can be expanded with synonyms, just keep ns_parse.c:ns_parserecord()
 * in synch with it.
 */
typedef enum __ns_sect
{
  ns_s_qd = 0,
  ns_s_zn = 0,
  ns_s_an = 1,
  ns_s_pr = 1,
  ns_s_ns = 2,
  ns_s_ud = 2,
  ns_s_ar = 3,
  ns_s_max = 4
} ns_sect;

/*
 * This is a message handle.  It is caller allocated and has no dynamic data.
 * This structure is intended to be opaque to all but ns_parse.c, thus the
 * leading _'s on the member names.  Use the accessor functions, not the _'s.
 */
typedef struct __ns_msg
{
  const u_char    *_msg, *_eom;
  u_int16_t       _id, _flags, _counts[ns_s_max];
  const u_char    *_sections[ns_s_max];
  ns_sect         _sect;
  int             _rrnum;
  const u_char    *_ptr;
} ns_msg;

/* Private data structure - do not use from outside library. */
struct _ns_flagdata {  int mask, shift;  };
extern struct _ns_flagdata _ns_flagdata[];

/* Accessor macros - this is part of the public interface. */
#define ns_msg_getflag(handle, flag) ( \
                        ((handle)._flags & _ns_flagdata[flag].mask) \
                         >> _ns_flagdata[flag].shift \
                        )
#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)

/*
 * This is a parsed record.  It is caller allocated and has no dynamic data.
 */
typedef struct __ns_rr
{
  char            name[NS_MAXDNAME];
  u_int16_t       type;
  u_int16_t       rr_class;
  u_int32_t       ttl;
  u_int16_t       rdlength;
  const u_char *  rdata;
} ns_rr;

/* Accessor macros - this is part of the public interface. */
#define ns_rr_name(rr)  (((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_type(rr)  ((ns_type)((rr).type + 0))
#define ns_rr_class(rr) ((ns_class)((rr).rr_class + 0))
#define ns_rr_ttl(rr)   ((rr).ttl + 0)
#define ns_rr_rdlen(rr) ((rr).rdlength + 0)
#define ns_rr_rdata(rr) ((rr).rdata + 0)

/*
 * These don't have to be in the same order as in the packet flags word,
 * and they can even overlap in some cases, but they will need to be kept
 * in synch with ns_parse.c:ns_flagdata[].
 */
typedef enum __ns_flag
{
  ns_f_qr,
  ns_f_opcode,
  ns_f_aa,
  ns_f_tc,
  ns_f_rd,
  ns_f_ra,
  ns_f_z,
  ns_f_ad,
  ns_f_cd,
  ns_f_rcode,
  ns_f_max
} ns_flag;

/*
 * Currently defined opcodes.
 */
typedef enum __ns_opcode
{
  ns_o_query = 0,
  ns_o_iquery = 1,
  ns_o_status = 2,
  ns_o_notify = 4,
  ns_o_update = 5,
  ns_o_max = 6
} ns_opcode;

/*
 * Currently defined response codes.
 */
typedef enum __ns_rcode
{
  ns_r_noerror = 0,
  ns_r_formerr = 1,
  ns_r_servfail = 2,
  ns_r_nxdomain = 3,
  ns_r_notimpl = 4,
  ns_r_refused = 5,
  ns_r_yxdomain = 6,
  ns_r_yxrrset = 7,
  ns_r_nxrrset = 8,
  ns_r_notauth = 9,
  ns_r_notzone = 10,
  ns_r_max = 11,
  ns_r_badsig = 16,
  ns_r_badkey = 17,
  ns_r_badtime = 18
} ns_rcode;

/* BIND_UPDATE */
typedef enum __ns_update_operation
{
  ns_uop_delete = 0,
  ns_uop_add = 1,
  ns_uop_max = 2
} ns_update_operation;

/*
 * This structure is used for TSIG authenticated messages
 */
struct ns_tsig_key
{
  char name[NS_MAXDNAME], alg[NS_MAXDNAME];
  unsigned char *data;
  int len;
};
typedef struct ns_tsig_key ns_tsig_key;

/*
 * This structure is used for TSIG authenticated TCP messages
 */
struct ns_tcp_tsig_state
{
  int counter;
  struct dst_key *key;
  void *ctx;
  unsigned char sig[NS_PACKETSZ];
  int siglen;
};
typedef struct ns_tcp_tsig_state ns_tcp_tsig_state;

#define NS_TSIG_ALG_HMAC_MD5 "HMAC-MD5.SIG-ALG.REG.INT"

int enum
{
  NS_TSIG_FUDGE = 300,
#define NS_TSIG_FUDGE NS_TSIG_FUDGE
  NS_TSIG_TCP_COUNT = 100,
#define NS_TSIG_TCP_COUNT NS_TSIG_TCP_COUNT
  NS_TSIG_ERROR_NO_TSIG = -10,
#define NS_TSIG_ERROR_NO_TSIG NS_TSIG_ERROR_NO_TSIG
  NS_TSIG_ERROR_NO_SPACE = -11,
#define NS_TSIG_ERROR_NO_SPACE NS_TSIG_ERROR_NO_SPACE
  NS_TSIG_ERROR_FORMERR = -12,
#define NS_TSIG_ERROR_FORMERR NS_TSIG_ERROR_FORMERR
};

/*
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type
{
  ns_t_invalid = 0,
  ns_t_a = 1,
  ns_t_ns = 2,
  ns_t_md = 3,
  ns_t_mf = 4,
  ns_t_cname = 5,
  ns_t_soa = 6,
  ns_t_mb = 7,
  ns_t_mg = 8,
  ns_t_mr = 9,
  ns_t_null = 10,
  ns_t_wks = 11,
  ns_t_ptr = 12,
  ns_t_hinfo = 13,
  ns_t_minfo = 14,
  ns_t_mx = 15,
  ns_t_txt = 16,
  ns_t_rp = 17,
  ns_t_afsdb = 18,
  ns_t_x25 = 19,
  ns_t_isdn = 20,
  ns_t_rt = 21,
  ns_t_nsap = 22,
  ns_t_nsap_ptr = 23,
  ns_t_sig = 24,
  ns_t_key = 25,
  ns_t_px = 26,
  ns_t_gpos = 27,
  ns_t_aaaa = 28,
  ns_t_loc = 29,
  ns_t_nxt = 30,
  ns_t_eid = 31,
  ns_t_nimloc = 32,
  ns_t_srv = 33,
  ns_t_atma = 34,
  ns_t_naptr = 35,
  ns_t_kx = 36,
  ns_t_cert = 37,
  ns_t_a6 = 38,
  ns_t_dname = 39,
  ns_t_sink = 40,
  ns_t_opt = 41,
  ns_t_tsig = 250,
  ns_t_ixfr = 251,
  ns_t_axfr = 252,
  ns_t_mailb = 253,
  ns_t_maila = 254,
  ns_t_any = 255,
  ns_t_zxfr = 256,
  ns_t_max = 65536
} ns_type;

/* Exclusively a QTYPE? (not also an RTYPE) */
#define ns_t_qt_p(t) (ns_t_xfr_p(t) || (t) == ns_t_any || \
                      (t) == ns_t_mailb || (t) == ns_t_maila)
/* Some kind of meta-RR? (not a QTYPE, but also not an RTYPE) */
#define ns_t_mrr_p(t) ((t) == ns_t_tsig || (t) == ns_t_opt)
/* Exclusively an RTYPE? (not also a QTYPE or a meta-RR) */
#define ns_t_rr_p(t) (!ns_t_qt_p(t) && !ns_t_mrr_p(t))
#define ns_t_udp_p(t) ((t) != ns_t_axfr && (t) != ns_t_zxfr)
#define ns_t_xfr_p(t) ((t) == ns_t_axfr || (t) == ns_t_ixfr || \
                       (t) == ns_t_zxfr)

/*
 * Values for class field
 */
typedef enum __ns_class
{
  ns_c_invalid = 0,
  ns_c_in = 1,
  ns_c_2 = 2,
  ns_c_chaos = 3,
  ns_c_hs = 4,
  ns_c_none = 254,
  ns_c_any = 255,
  ns_c_max = 65536
} ns_class;

/* DNSSEC constants. */

typedef enum __ns_key_types
{
  ns_kt_rsa = 1,
  ns_kt_dh  = 2,
  ns_kt_dsa = 3,
  ns_kt_private = 254
} ns_key_types;

typedef enum __ns_cert_types
{
  cert_t_pkix = 1,
  cert_t_spki = 2,
  cert_t_pgp  = 3,
  cert_t_url  = 253,
  cert_t_oid  = 254
} ns_cert_types;

/* Flags field of the KEY RR rdata. */
int enum
{
  NS_KEY_TYPEMASK = 0xC000,
#define NS_KEY_TYPEMASK NS_KEY_TYPEMASK
  NS_KEY_TYPE_AUTH_CONF = 0x0000,
#define NS_KEY_TYPE_AUTH_CONF NS_KEY_TYPE_AUTH_CONF
  NS_KEY_TYPE_CONF_ONLY = 0x8000,
#define NS_KEY_TYPE_CONF_ONLY NS_KEY_TYPE_CONF_ONLY
  NS_KEY_TYPE_AUTH_ONLY = 0x4000,
#define NS_KEY_TYPE_AUTH_ONLY NS_KEY_TYPE_AUTH_ONLY
  NS_KEY_TYPE_NO_KEY = 0xC000,
#define NS_KEY_TYPE_NO_KEY NS_KEY_TYPE_NO_KEY
  NS_KEY_NO_AUTH = 0x8000,
#define NS_KEY_NO_AUTH NS_KEY_NO_AUTH
  NS_KEY_NO_CONF = 0x4000,
#define NS_KEY_NO_CONF NS_KEY_NO_CONF
  NS_KEY_RESERVED2 = 0x2000,
#define NS_KEY_RESERVED2 NS_KEY_RESERVED2
  NS_KEY_EXTENDED_FLAGS = 0x1000,
#define NS_KEY_EXTENDED_FLAGS NS_KEY_EXTENDED_FLAGS
  NS_KEY_RESERVED4 = 0x0800,
#define NS_KEY_RESERVED4 NS_KEY_RESERVED4
  NS_KEY_RESERVED5 = 0x0400,
#define NS_KEY_RESERVED5 NS_KEY_RESERVED5
  NS_KEY_NAME_TYPE = 0x0300,
#define NS_KEY_NAME_TYPE NS_KEY_NAME_TYPE
  NS_KEY_NAME_USER = 0x0000,
#define NS_KEY_NAME_USER NS_KEY_NAME_USER
  NS_KEY_NAME_ENTITY = 0x0200,
#define NS_KEY_NAME_ENTITY NS_KEY_NAME_ENTITY
  NS_KEY_NAME_ZONE = 0x0100,
#define NS_KEY_NAME_ZONE NS_KEY_NAME_ZONE
  NS_KEY_NAME_RESERVED = 0x0300,
#define NS_KEY_NAME_RESERVED NS_KEY_NAME_RESERVED
  NS_KEY_RESERVED8 = 0x0080,
#define NS_KEY_RESERVED8 NS_KEY_RESERVED8
  NS_KEY_RESERVED9 = 0x0040,
#define NS_KEY_RESERVED9 NS_KEY_RESERVED9
  NS_KEY_RESERVED10 = 0x0020,
#define NS_KEY_RESERVED10 NS_KEY_RESERVED10
  NS_KEY_RESERVED11 = 0x0010,
#define NS_KEY_RESERVED11 NS_KEY_RESERVED11
  NS_KEY_SIGNATORYMASK = 0x000F,
#define NS_KEY_SIGNATORYMASK NS_KEY_SIGNATORYMASK
  NS_KEY_RESERVED_BITMASK = ( NS_KEY_RESERVED2 | NS_KEY_RESERVED4 | NS_KEY_RESERVED5 | NS_KEY_RESERVED8 | NS_KEY_RESERVED9 | NS_KEY_RESERVED10 | NS_KEY_RESERVED11 ),
#define NS_KEY_RESERVED_BITMASK NS_KEY_RESERVED_BITMASK
  NS_KEY_RESERVED_BITMASK2 = 0xFFFF,
#define NS_KEY_RESERVED_BITMASK2 NS_KEY_RESERVED_BITMASK2
};

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
int enum
{
  NS_ALG_MD5RSA = 1,
#define NS_ALG_MD5RSA NS_ALG_MD5RSA
  NS_ALG_DH = 2,
#define NS_ALG_DH NS_ALG_DH
  NS_ALG_DSA = 3,
#define NS_ALG_DSA NS_ALG_DSA
  NS_ALG_DSS = NS_ALG_DSA,
#define NS_ALG_DSS NS_ALG_DSS
  NS_ALG_EXPIRE_ONLY = 253,
#define NS_ALG_EXPIRE_ONLY NS_ALG_EXPIRE_ONLY
  NS_ALG_PRIVATE_OID = 254,
#define NS_ALG_PRIVATE_OID NS_ALG_PRIVATE_OID
};

/* Protocol values  */
/* value 0 is reserved */
int enum
{
  NS_KEY_PROT_TLS = 1,
#define NS_KEY_PROT_TLS NS_KEY_PROT_TLS
  NS_KEY_PROT_EMAIL = 2,
#define NS_KEY_PROT_EMAIL NS_KEY_PROT_EMAIL
  NS_KEY_PROT_DNSSEC = 3,
#define NS_KEY_PROT_DNSSEC NS_KEY_PROT_DNSSEC
  NS_KEY_PROT_IPSEC = 4,
#define NS_KEY_PROT_IPSEC NS_KEY_PROT_IPSEC
  NS_KEY_PROT_ANY = 255,
#define NS_KEY_PROT_ANY NS_KEY_PROT_ANY
};

/* Signatures */
int enum
{
  NS_MD5RSA_MIN_BITS = 512,
#define NS_MD5RSA_MIN_BITS NS_MD5RSA_MIN_BITS
  NS_MD5RSA_MAX_BITS = 2552,
#define NS_MD5RSA_MAX_BITS NS_MD5RSA_MAX_BITS
  NS_MD5RSA_MAX_BYTES = ((NS_MD5RSA_MAX_BITS+7/8)*2+3),
#define NS_MD5RSA_MAX_BYTES NS_MD5RSA_MAX_BYTES
  NS_MD5RSA_MAX_BASE64 = (((NS_MD5RSA_MAX_BYTES+2)/3)*4),
#define NS_MD5RSA_MAX_BASE64 NS_MD5RSA_MAX_BASE64
  NS_MD5RSA_MIN_SIZE = ((NS_MD5RSA_MIN_BITS+7)/8),
#define NS_MD5RSA_MIN_SIZE NS_MD5RSA_MIN_SIZE
  NS_MD5RSA_MAX_SIZE = ((NS_MD5RSA_MAX_BITS+7)/8),
#define NS_MD5RSA_MAX_SIZE NS_MD5RSA_MAX_SIZE
};

int enum
{
  NS_DSA_SIG_SIZE = 41,
#define NS_DSA_SIG_SIZE NS_DSA_SIG_SIZE
  NS_DSA_MIN_SIZE = 213,
#define NS_DSA_MIN_SIZE NS_DSA_MIN_SIZE
  NS_DSA_MAX_BYTES = 405,
#define NS_DSA_MAX_BYTES NS_DSA_MAX_BYTES
};

/* Offsets into SIG record rdata to find various values */
int enum
{
  NS_SIG_TYPE = 0,
#define NS_SIG_TYPE NS_SIG_TYPE
  NS_SIG_ALG = 2,
#define NS_SIG_ALG NS_SIG_ALG
  NS_SIG_LABELS = 3,
#define NS_SIG_LABELS NS_SIG_LABELS
  NS_SIG_OTTL = 4,
#define NS_SIG_OTTL NS_SIG_OTTL
  NS_SIG_EXPIR = 8,
#define NS_SIG_EXPIR NS_SIG_EXPIR
  NS_SIG_SIGNED = 12,
#define NS_SIG_SIGNED NS_SIG_SIGNED
  NS_SIG_FOOT = 16,
#define NS_SIG_FOOT NS_SIG_FOOT
  NS_SIG_SIGNER = 18,
#define NS_SIG_SIGNER NS_SIG_SIGNER
};

/* How RR types are represented as bit-flags in NXT records */
int enum
{
  NS_NXT_BITS = 8,
#define NS_NXT_BITS NS_NXT_BITS
  NS_NXT_MAX = 127,
#define NS_NXT_MAX NS_NXT_MAX
};

#define NS_NXT_BIT_SET(  n,p) (p[(n)/NS_NXT_BITS] |=  (0x80>>((n)%NS_NXT_BITS)))
#define NS_NXT_BIT_CLEAR(n,p) (p[(n)/NS_NXT_BITS] &= ~(0x80>>((n)%NS_NXT_BITS)))
#define NS_NXT_BIT_ISSET(n,p) (p[(n)/NS_NXT_BITS] &   (0x80>>((n)%NS_NXT_BITS)))

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
#define NS_GET16(s, cp) do { \
        register u_char *t_cp = (u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)

#define NS_GET32(l, cp) do { \
        register u_char *t_cp = (u_char *)(cp); \
        (l) = ((u_int32_t)t_cp[0] << 24) \
            | ((u_int32_t)t_cp[1] << 16) \
            | ((u_int32_t)t_cp[2] << 8) \
            | ((u_int32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)

#define NS_PUT16(s, cp) do { \
        register u_int16_t t_s = (u_int16_t)(s); \
        register u_char *t_cp = (u_char *)(cp); \
        *t_cp++ = t_s >> 8; \
        *t_cp   = t_s; \
        (cp) += NS_INT16SZ; \
} while (0)

#define NS_PUT32(l, cp) do { \
        register u_int32_t t_l = (u_int32_t)(l); \
        register u_char *t_cp = (u_char *)(cp); \
        *t_cp++ = t_l >> 24; \
        *t_cp++ = t_l >> 16; \
        *t_cp++ = t_l >> 8; \
        *t_cp   = t_l; \
        (cp) += NS_INT32SZ; \
} while (0)

/*
 * ANSI C identifier hiding for bind's lib/nameser.
 */
#define ns_get16                __ns_get16
#define ns_get32                __ns_get32
#define ns_put16                __ns_put16
#define ns_put32                __ns_put32
#define ns_initparse            __ns_initparse
#define ns_skiprr               __ns_skiprr
#define ns_parserr              __ns_parserr
#define ns_sprintrr             __ns_sprintrr
#define ns_sprintrrf            __ns_sprintrrf
#define ns_format_ttl           __ns_format_ttl
#define ns_parse_ttl            __ns_parse_ttl
#define ns_datetosecs           __ns_datetosecs
#define ns_name_ntol            __ns_name_ntol
#define ns_name_ntop            __ns_name_ntop
#define ns_name_pton            __ns_name_pton
#define ns_name_unpack          __ns_name_unpack
#define ns_name_pack            __ns_name_pack
#define ns_name_compress        __ns_name_compress
#define ns_name_uncompress      __ns_name_uncompress
#define ns_name_skip            __ns_name_skip
#define ns_name_rollback        __ns_name_rollback
#define ns_sign                 __ns_sign
#define ns_sign_tcp             __ns_sign_tcp
#define ns_sign_tcp_init        __ns_sign_tcp_init
#define ns_find_tsig            __ns_find_tsig
#define ns_verify               __ns_verify
#define ns_verify_tcp           __ns_verify_tcp
#define ns_verify_tcp_init      __ns_verify_tcp_init
#define ns_samedomain           __ns_samedomain
#define ns_subdomain            __ns_subdomain
#define ns_makecanon            __ns_makecanon
#define ns_samename             __ns_samename

u_int ns_get16(const u_char *);
u_long ns_get32(const u_char *);
void ns_put16(u_int, u_char *);
void ns_put32(u_long, u_char *);
int ns_initparse(const u_char *, int, ns_msg *);
int ns_skiprr(const u_char *, const u_char *, ns_sect, int);
int ns_parserr(ns_msg *, ns_sect, int, ns_rr *);
int ns_sprintrr(const ns_msg *, const ns_rr *,
                const char *, const char *, char *, size_t);
int ns_sprintrrf(const u_char *, size_t, const char *,
                 ns_class, ns_type, u_long, const u_char *,
                 size_t, const char *, const char *,
                 char *, size_t);
int ns_format_ttl(u_long, char *, size_t);
int ns_parse_ttl(const char *, u_long *);
u_int32_t ns_datetosecs(const char *cp, int *errp);
int ns_name_ntol(const u_char *, u_char *, size_t);
int ns_name_ntop(const u_char *, char *, size_t);
int ns_name_pton(const char *, u_char *, size_t);
int ns_name_unpack(const u_char *, const u_char *,
                   const u_char *, u_char *, size_t);
int ns_name_pack(const u_char *, u_char *, int,
                 const u_char **, const u_char **);
int ns_name_uncompress(const u_char *, const u_char *,
                       const u_char *, char *, size_t);
int ns_name_compress(const char *, u_char *, size_t,
                     const u_char **, const u_char **);
int ns_name_skip (const u_char **, const u_char *);
void ns_name_rollback (const u_char *, const u_char **, const u_char **);
int ns_sign(u_char *, int *, int, int, void *,
            const u_char *, int, u_char *, int *, time_t);
int ns_sign_tcp(u_char *, int *, int, int, ns_tcp_tsig_state *, int);
int ns_sign_tcp_init(void *, const u_char *, int, ns_tcp_tsig_state *);
u_char *ns_find_tsig(u_char *, u_char *);
int ns_verify(u_char *, int *, void *, const u_char *, int, u_char *, int *,
              time_t *, int);
int ns_verify_tcp(u_char *, int *, ns_tcp_tsig_state *, int);
int ns_verify_tcp_init(void *, const u_char *, int, ns_tcp_tsig_state *);
int ns_samedomain(const char *, const char *);
int ns_subdomain(const char *, const char *);
int ns_makecanon(const char *, char *, size_t);
int ns_samename(const char *, const char *);

#ifdef BIND_4_COMPAT
#include <arpa/nameser_compat.h>
#endif

#endif /* __RCC_ARPA_NAMESER_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "u_char" "ns_tcp_tsig_state" "u_long" "ns_class" "ns_type" "u_int" "ns_msg" "ns_sect" "ns_rr")
 * End:
 */
