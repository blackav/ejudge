/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `resolv.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*
 * Copyright (c) 1983, 1987, 1989
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
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
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
 *      @(#)resolv.h    8.1 (Berkeley) 6/2/93
 *      $BINDId: resolv.h,v 8.31 2000/03/30 20:16:50 vixie Exp $
 */

#ifndef __RCC_RESOLV_H__
#define __RCC_RESOLV_H__

#include <features.h>
#include <sys/types.h>
#include <netinet/in.h>

# include <sys/param.h>
# include <stdio.h>
# include <arpa/nameser.h>

typedef int enum
{
  res_goahead,
  res_nextns,
  res_modified,
  res_done,
  res_error
} res_sendhookact;

typedef res_sendhookact (*res_send_qhook)(struct sockaddr_in * const *ns,
                                          const u_char **query,
                                          int *querylen,
                                          u_char *ans,
                                          int anssiz,
                                          int *resplen);

typedef res_sendhookact (*res_send_rhook)(const struct sockaddr_in *ns,
                                          const u_char *query,
                                          int querylen,
                                          u_char *ans,
                                          int anssiz,
                                          int *resplen);

/*
 * Global defines and variables for resolver stub.
 */
int enum
{
  MAXNS = 3,
#define MAXNS MAXNS
  MAXDFLSRCH = 3,
#define MAXDFLSRCH MAXDFLSRCH
  MAXDNSRCH = 6,
#define MAXDNSRCH MAXDNSRCH
  LOCALDOMAINPARTS = 2,
#define LOCALDOMAINPARTS LOCALDOMAINPARTS
  RES_TIMEOUT = 5,
#define RES_TIMEOUT RES_TIMEOUT
  MAXRESOLVSORT = 10,
#define MAXRESOLVSORT MAXRESOLVSORT
  RES_MAXNDOTS = 15,
#define RES_MAXNDOTS RES_MAXNDOTS
  RES_MAXRETRANS = 30,
#define RES_MAXRETRANS RES_MAXRETRANS
  RES_MAXRETRY = 5,
#define RES_MAXRETRY RES_MAXRETRY
  RES_DFLRETRY = 2,
#define RES_DFLRETRY RES_DFLRETRY
  RES_MAXTIME = 65535,
#define RES_MAXTIME RES_MAXTIME
};

struct __res_state
{
  int     retrans;
  int     retry;
  u_long  options;
  int     nscount;
  struct sockaddr_in nsaddr_list[MAXNS];
  u_short id;
  char    *dnsrch[MAXDNSRCH+1];
  char    defdname[256];
  u_long  pfcode;
  unsigned ndots:4;
  unsigned nsort:4;
  char    unused[3];
  struct
  {
    struct in_addr  addr;
    u_int32_t       mask;
  } sort_list[MAXRESOLVSORT];
  res_send_qhook qhook;
  res_send_rhook rhook;
  int     res_h_errno;
  int     _vcsock;
  u_int   _flags;
  union
  {
    char    pad[52];
    struct
    {
      u_int16_t               nscount;
      u_int16_t               nsmap[MAXNS];
      int                     nssocks[MAXNS];
      u_int16_t               nscount6;
      u_int16_t               nsinit;
      struct sockaddr_in6     *nsaddrs[MAXNS];
    } _ext;
  } _u;
};

#define nsaddr nsaddr_list[0]

typedef struct __res_state *res_state;

#define __RES   19991006

/*
 * Resolver configuration file.
 * Normally not present, but may contain the address of the
 * inital name server(s) to query and the domain search list.
 */

#ifndef _PATH_RESCONF
#define _PATH_RESCONF        "/etc/resolv.conf"
#endif

struct res_sym
{
  int     number;
  char *  name;
  char *  humanname;
};

/*
 * Resolver flags (used to be discrete per-module statics ints).
 */
int enum
{
  RES_F_VC = 0x00000001,
#define RES_F_VC RES_F_VC
  RES_F_CONN = 0x00000002,
#define RES_F_CONN RES_F_CONN
};

/* res_findzonecut() options */
int enum { RES_EXHAUSTIVE = 0x00000001 };
#define RES_EXHAUSTIVE RES_EXHAUSTIVE

/*
 * Resolver options (keep these in synch with res_debug.c, please)
 */
int enum
{
  RES_INIT = 0x00000001,
#define RES_INIT RES_INIT
  RES_DEBUG = 0x00000002,
#define RES_DEBUG RES_DEBUG
  RES_AAONLY = 0x00000004,
#define RES_AAONLY RES_AAONLY
  RES_USEVC = 0x00000008,
#define RES_USEVC RES_USEVC
  RES_PRIMARY = 0x00000010,
#define RES_PRIMARY RES_PRIMARY
  RES_IGNTC = 0x00000020,
#define RES_IGNTC RES_IGNTC
  RES_RECURSE = 0x00000040,
#define RES_RECURSE RES_RECURSE
  RES_DEFNAMES = 0x00000080,
#define RES_DEFNAMES RES_DEFNAMES
  RES_STAYOPEN = 0x00000100,
#define RES_STAYOPEN RES_STAYOPEN
  RES_DNSRCH = 0x00000200,
#define RES_DNSRCH RES_DNSRCH
  RES_INSECURE1 = 0x00000400,
#define RES_INSECURE1 RES_INSECURE1
  RES_INSECURE2 = 0x00000800,
#define RES_INSECURE2 RES_INSECURE2
  RES_NOALIASES = 0x00001000,
#define RES_NOALIASES RES_NOALIASES
  RES_USE_INET6 = 0x00002000,
#define RES_USE_INET6 RES_USE_INET6
  RES_ROTATE = 0x00004000,
#define RES_ROTATE RES_ROTATE
  RES_NOCHECKNAME = 0x00008000,
#define RES_NOCHECKNAME RES_NOCHECKNAME
  RES_KEEPTSIG = 0x00010000,
#define RES_KEEPTSIG RES_KEEPTSIG
  RES_BLAST = 0x00020000,
#define RES_BLAST RES_BLAST
  RES_DEFAULT = (RES_RECURSE | RES_DEFNAMES | RES_DNSRCH),
#define RES_DEFAULT RES_DEFAULT
};

/*
 * Resolver "pfcode" values.  Used by dig.
 */
int enum
{
  RES_PRF_STATS = 0x00000001,
#define RES_PRF_STATS RES_PRF_STATS
  RES_PRF_UPDATE = 0x00000002,
#define RES_PRF_UPDATE RES_PRF_UPDATE
  RES_PRF_CLASS = 0x00000004,
#define RES_PRF_CLASS RES_PRF_CLASS
  RES_PRF_CMD = 0x00000008,
#define RES_PRF_CMD RES_PRF_CMD
  RES_PRF_QUES = 0x00000010,
#define RES_PRF_QUES RES_PRF_QUES
  RES_PRF_ANS = 0x00000020,
#define RES_PRF_ANS RES_PRF_ANS
  RES_PRF_AUTH = 0x00000040,
#define RES_PRF_AUTH RES_PRF_AUTH
  RES_PRF_ADD = 0x00000080,
#define RES_PRF_ADD RES_PRF_ADD
  RES_PRF_HEAD1 = 0x00000100,
#define RES_PRF_HEAD1 RES_PRF_HEAD1
  RES_PRF_HEAD2 = 0x00000200,
#define RES_PRF_HEAD2 RES_PRF_HEAD2
  RES_PRF_TTLID = 0x00000400,
#define RES_PRF_TTLID RES_PRF_TTLID
  RES_PRF_HEADX = 0x00000800,
#define RES_PRF_HEADX RES_PRF_HEADX
  RES_PRF_QUERY = 0x00001000,
#define RES_PRF_QUERY RES_PRF_QUERY
  RES_PRF_REPLY = 0x00002000,
#define RES_PRF_REPLY RES_PRF_REPLY
  RES_PRF_INIT = 0x00004000,
#define RES_PRF_INIT RES_PRF_INIT
};

/* Things involving an internal (static) resolver context. */
struct __res_state *__res_state(void);
#define _res (*__res_state())

#define fp_nquery               __fp_nquery
#define fp_query                __fp_query
#define hostalias               __hostalias
#define p_query                 __p_query
#define res_close               __res_close
#define res_init                __res_init
#define res_isourserver         __res_isourserver
#define res_mkquery             __res_mkquery
#define res_query               __res_query
#define res_querydomain         __res_querydomain
#define res_search              __res_search
#define res_send                __res_send

void            fp_nquery (const u_char *, int, FILE *);
void            fp_query (const u_char *, FILE *);
const char *    hostalias(const char *);
void            p_query(const u_char *);
void            res_close(void);
int             res_init (void);
int             res_isourserver(const struct sockaddr_in *);
int             res_mkquery(int, const char *, int, int, const u_char *,
                                 int, const u_char *, u_char *, int);
int             res_query(const char *, int, int, u_char *, int);
int             res_querydomain(const char *, const char *, int, int,
                                     u_char *, int);
int             res_search(const char *, int, int, u_char *, int);
int             res_send (const u_char *, int, u_char *, int);

#define b64_ntop                __b64_ntop
#define b64_pton                __b64_pton
#define dn_comp                 __dn_comp
#define dn_count_labels         __dn_count_labels
#define dn_expand               __dn_expand
#define dn_skipname             __dn_skipname
#define fp_resstat              __fp_resstat
#define loc_aton                __loc_aton
#define loc_ntoa                __loc_ntoa
#define p_cdname                __p_cdname
#define p_cdnname               __p_cdnname
#define p_class                 __p_class
#define p_fqname                __p_fqname
#define p_fqnname               __p_fqnname
#define p_option                __p_option
#define p_secstodate            __p_secstodate
#define p_section               __p_section
#define p_time                  __p_time
#define p_type                  __p_type
#define p_rcode                 __p_rcode
#define putlong                 __putlong
#define putshort                __putshort
#define res_dnok                __res_dnok
#define res_hnok                __res_hnok
#define res_hostalias           __res_hostalias
#define res_mailok              __res_mailok
#define res_nameinquery         __res_nameinquery
#define res_nclose              __res_nclose
#define res_ninit               __res_ninit
#define res_nmkquery            __res_nmkquery
#define res_npquery             __res_npquery
#define res_nquery              __res_nquery
#define res_nquerydomain        __res_nquerydomain
#define res_nsearch             __res_nsearch
#define res_nsend               __res_nsend
#define res_nisourserver        __res_nisourserver
#define res_ownok               __res_ownok
#define res_queriesmatch        __res_queriesmatch
#define res_randomid            __res_randomid
#define sym_ntop                __sym_ntop
#define sym_ntos                __sym_ntos
#define sym_ston                __sym_ston
int             res_hnok (const char *);
int             res_ownok (const char *);
int             res_mailok (const char *);
int             res_dnok (const char *);
int             sym_ston (const struct res_sym *, const char *, int *);
const char *    sym_ntos (const struct res_sym *, int, int *);
const char *    sym_ntop (const struct res_sym *, int, int *);
int             b64_ntop (u_char const *, size_t, char *, size_t);
int             b64_pton (char const *, u_char *, size_t);
int             loc_aton (const char *ascii, u_char *binary);
const char *    loc_ntoa (const u_char *binary, char *ascii);
int             dn_skipname (const u_char *, const u_char *);
void            putlong (u_int32_t, u_char *);
void            putshort (u_int16_t, u_char *);
const char *    p_class (int);
const char *    p_time (u_int32_t);
const char *    p_type (int);
const char *    p_rcode (int);
const u_char *  p_cdnname (const u_char *, const u_char *, int, FILE *);
const u_char *  p_cdname (const u_char *, const u_char *, FILE *);
const u_char *  p_fqnname (const u_char *cp, const u_char *msg,
                               int, char *, int);
const u_char *  p_fqname (const u_char *, const u_char *, FILE *);
const char *    p_option (u_long option);
char *          p_secstodate (u_long);
int             dn_count_labels (const char *);
int             dn_comp (const char *, u_char *, int,
                             u_char **, u_char **);
int             dn_expand (const u_char *, const u_char *, const u_char *,
                               char *, int);
u_int           res_randomid (void);
int             res_nameinquery (const char *, int, int,
                                     const u_char *, const u_char *);
int             res_queriesmatch (const u_char *, const u_char *,
                                      const u_char *, const u_char *);
const char *    p_section (int section, int opcode);
/* Things involving a resolver context. */
int             res_ninit (res_state);
int             res_nisourserver (const res_state,
                                      const struct sockaddr_in *);
void            fp_resstat (const res_state, FILE *);
void            res_npquery (const res_state, const u_char *, int, FILE *);
const char *    res_hostalias (const res_state, const char *,
                                   char *, size_t);
int             res_nquery (res_state,
                                const char *, int, int, u_char *, int);
int             res_nsearch (res_state, const char *, int,
                                 int, u_char *, int);
int             res_nquerydomain (res_state,
                                      const char *, const char *, int, int,
                                      u_char *, int);
int             res_nmkquery (res_state,
                                  int, const char *, int, int, const u_char *,
                                  int, const u_char *, u_char *, int);
int             res_nsend (res_state, const u_char *, int, u_char *, int);
void            res_nclose (res_state);

#endif /* __RCC_RESOLV_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "res_sendhookact" "u_char" "u_long" "u_short" "res_send_qhook" "res_send_rhook" "u_int" "res_state")
 * End:
 */
