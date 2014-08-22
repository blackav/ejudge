/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/auth.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* @(#)auth.h   2.3 88/08/07 4.0 RPCSRC; from 1.17 88/02/08 SMI */
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

/*
 * auth.h, Authentication interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * The data structures are completely opaque to the client.  The client
 * is required to pass a AUTH * to routines that create rpc
 * "sessions".
 */

#ifndef __RCC_RPC_AUTH_H__
#define __RCC_RPC_AUTH_H__ 1

#include <features.h>
#include <rpc/xdr.h>

int enum
{
  MAX_AUTH_BYTES = 400,
#define MAX_AUTH_BYTES MAX_AUTH_BYTES
  MAXNETNAMELEN = 255,
#define MAXNETNAMELEN MAXNETNAMELEN
};

/*
 * Status returned from authentication check
 */
int enum auth_stat
{
  AUTH_OK=0,
  AUTH_BADCRED=1,
  AUTH_REJECTEDCRED=2,
  AUTH_BADVERF=3,
  AUTH_REJECTEDVERF=4,
  AUTH_TOOWEAK=5,
  AUTH_INVALIDRESP=6,
  AUTH_FAILED=7
};

union des_block
{
  struct
  {
    u_int32_t high;
    u_int32_t low;
  } key;
  char c[8];
};

typedef union des_block des_block;
bool_t xdr_des_block(XDR *xdrs, des_block *blkp);

/*
 * Authentication info.  Opaque to client.
 */
struct opaque_auth
{
  enum_t  oa_flavor;
  caddr_t oa_base;
  u_int   oa_length;
};

/*
 * Auth handle, interface to client side authenticators.
 */
typedef struct AUTH AUTH;
struct AUTH
{
  struct opaque_auth ah_cred;
  struct opaque_auth ah_verf;
  union des_block ah_key;
  struct auth_ops
  {
    void (*ah_nextverf)(AUTH *);
    int  (*ah_marshal)(AUTH *, XDR *);
    int  (*ah_validate)(AUTH *, struct opaque_auth *);
    int  (*ah_refresh)(AUTH *);
    void (*ah_destroy)(AUTH *);
  } *ah_ops;
  caddr_t ah_private;
};


/*
 * Authentication ops.
 * The ops and the auth handle provide the interface to the authenticators.
 *
 * AUTH *auth;
 * XDR  *xdrs;
 * struct opaque_auth verf;
 */
#define AUTH_NEXTVERF(auth)             \
                ((*((auth)->ah_ops->ah_nextverf))(auth))
#define auth_nextverf(auth)             \
                ((*((auth)->ah_ops->ah_nextverf))(auth))

#define AUTH_MARSHALL(auth, xdrs)       \
                ((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define auth_marshall(auth, xdrs)       \
                ((*((auth)->ah_ops->ah_marshal))(auth, xdrs))

#define AUTH_VALIDATE(auth, verfp)      \
                ((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define auth_validate(auth, verfp)      \
                ((*((auth)->ah_ops->ah_validate))((auth), verfp))

#define AUTH_REFRESH(auth)              \
                ((*((auth)->ah_ops->ah_refresh))(auth))
#define auth_refresh(auth)              \
                ((*((auth)->ah_ops->ah_refresh))(auth))

#define AUTH_DESTROY(auth)              \
                ((*((auth)->ah_ops->ah_destroy))(auth))
#define auth_destroy(auth)              \
                ((*((auth)->ah_ops->ah_destroy))(auth))

extern struct opaque_auth _null_auth;

/*
 * These are the various implementations of client side authenticators.
 */

/*
 * Unix style authentication
 * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
 *      char *machname;
 *      int uid;
 *      int gid;
 *      int len;
 *      int *aup_gids;
 */
AUTH *authunix_create(char *machname, uid_t uid, id_t gid,
                      int len, gid_t *aup_gids);
AUTH *authunix_create_default(void);
AUTH *authnone_create(void);
AUTH *authdes_create(const char *servername, u_int window,
                     struct sockaddr *syncaddr, des_block *ckey);
AUTH *authdes_pk_create(const char *, netobj *, u_int,
                        struct sockaddr *, des_block *);

int enum
{
  AUTH_NONE = 0,
#define AUTH_NONE AUTH_NONE
  AUTH_NULL = 0,
#define AUTH_NULL AUTH_NULL
  AUTH_SYS = 1,
#define AUTH_SYS AUTH_SYS
  AUTH_UNIX = AUTH_SYS,
#define AUTH_UNIX AUTH_UNIX
  AUTH_SHORT = 2,
#define AUTH_SHORT AUTH_SHORT
  AUTH_DES = 3,
#define AUTH_DES AUTH_DES
  AUTH_DH = AUTH_DES,
#define AUTH_DH AUTH_DH
  AUTH_KERB = 4,
#define AUTH_KERB AUTH_KERB
};

/*
 *  Netname manipulating functions
 *
 */
int getnetname(char *);
int host2netname(char *, const char *, const char *);
int user2netname(char *, const uid_t, const char *);
int netname2user(const char *, uid_t *, gid_t *, int *, gid_t *);
int netname2host(const char *, char *, const int);

/*
 *
 * These routines interface to the keyserv daemon
 *
 */
int key_decryptsession(char *, des_block *);
int key_decryptsession_pk(char *, netobj *, des_block *);
int key_encryptsession(char *, des_block *);
int key_encryptsession_pk(char *, netobj *, des_block *);
int key_gendes(des_block *);
int key_setsecret(char *);
int key_secretkey_is_set(void);
int key_get_conv(char *, des_block *);

/*
 * XDR an opaque authentication struct.
 */
bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);

#endif /* __RCC_RPC_AUTH_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "des_block" "XDR" "u_int" "AUTH" "netobj")
 * End:
 */
