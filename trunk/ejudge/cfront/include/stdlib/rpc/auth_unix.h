/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/auth_unix.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* @(#)auth_unix.h      2.2 88/07/29 4.0 RPCSRC; from 1.8 88/02/08 SMI */
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
/*      @(#)auth_unix.h 1.5 86/07/16 SMI      */

/*
 * auth_unix.h, Protocol for UNIX style authentication parameters for RPC
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

/*
 * The system is very weak.  The client uses no encryption for  it
 * credentials and only sends null verifiers.  The server sends backs
 * null verifiers or optionally a verifier that suggests a new short hand
 * for the credentials.
 */

#ifndef __RCC_RPC_AUTH_UNIX_H__
#define __RCC_RPC_AUTH_UNIX_H__ 1

#include <features.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/xdr.h>

/* The machine name is part of a credential; it may not exceed 255 bytes */
int enum { MAX_MACHINE_NAME = 255 };
#define MAX_MACHINE_NAME MAX_MACHINE_NAME
int enum { NGRPS = 16 };
#define NGRPS NGRPS

/*
 * Unix style credentials.
 */
struct authunix_parms
{
  u_long aup_time;
  char *aup_machname;
  uid_t aup_uid;
  gid_t aup_gid;
  u_int aup_len;
  gid_t *aup_gids;
};

bool_t xdr_authunix_parms(XDR *xdrs, struct authunix_parms *p);

/*
 * If a response verifier has flavor AUTH_SHORT,
 * then the body of the response verifier encapsulates the following structure;
 * again it is serialized in the obvious fashion.
 */
struct short_hand_verf
{
  struct opaque_auth new_cred;
};

#endif /* __RCC_RPC_AUTH_UNIX_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "des_block" "XDR" "u_int" "AUTH" "netobj" "u_long")
 * End:
 */
