/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/types.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

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
/* fixincludes should not add extern "C" to this file */
/*
 * Rpc additions to <sys/types.h>
 */

#ifndef __RCC_RPC_TYPES_H__
#define __RCC_RPC_TYPES_H__ 1

#include <features.h>

typedef int bool_t;
typedef int enum_t;
/* This needs to be changed to uint32_t in the future */
typedef unsigned long rpcprog_t;
typedef unsigned long rpcvers_t;
typedef unsigned long rpcproc_t;
typedef unsigned long rpcprot_t;
typedef unsigned long rpcport_t;

#define        __dontcare__    -1

#ifndef FALSE
#define FALSE   (0)
#endif

#ifndef TRUE
#define TRUE    (1)
#endif

#ifndef NULL
#define NULL 0
#endif

#include <stdlib.h>             /* For malloc decl.  */
#define mem_alloc(bsize)        malloc(bsize)
/*
 * XXX: This must not use the second argument, or code in xdr_array.c needs
 * to be modified.
 */
#define mem_free(ptr, bsize)    free(ptr)

#ifndef makedev /* ie, we haven't already included it */
#include <sys/types.h>
#endif
/*
#ifndef __u_char_defined
typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;
# define __u_char_defined
#endif
#ifndef __daddr_t_defined
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;
# define __daddr_t_defined
#endif
*/
#include <sys/time.h>
#include <sys/param.h>

#include <netinet/in.h>

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK         (u_long)0x7F000001
#endif
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  64
#endif

#endif /* __RCC_RPC_TYPES_H__ */
