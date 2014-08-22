/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/netdb.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* @(#)netdb.h  2.1 88/07/29 3.9 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*      @(#)rpc.h 1.8 87/07/24 SMI      */

/* Cleaned up for GNU C library roland@gnu.ai.mit.edu:
   added multiple inclusion protection and use of <sys/cdefs.h>.
   In GNU this file is #include'd by <netdb.h>.  */

#ifndef __RCC_RPC_NETDB_H__
#define __RCC_RPC_NETDB_H__ 1

#include <features.h>
#define __need_size_t
#include <stddef.h>

struct rpcent
{
  char *r_name;
  char **r_aliases;
  int r_number;
};

void setrpcent(int stayopen);
void endrpcent(void);
struct rpcent *getrpcbyname(const char *name);
struct rpcent *getrpcbynumber(int number);
struct rpcent *getrpcent(void);
int getrpcbyname_r(const char *name, struct rpcent *result_buf,
                   char *buffer, size_t buflen, struct rpcent **result);
int getrpcbynumber_r(int number, struct rpcent *result_buf,
                     char *buffer, size_t buflen, struct rpcent **result);
int getrpcent_r(struct rpcent *result_buf, char *buffer,
                size_t buflen, struct rpcent **result);

#endif /* __RCC_RPC_NETDB_H__ */
