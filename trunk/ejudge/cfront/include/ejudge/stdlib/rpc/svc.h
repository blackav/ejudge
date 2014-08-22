/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/svc.h' of the GNU C Library,
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

/*
 * svc.h, Server-side remote procedure call interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef __RCC_RPC_SVC_H__
#define __RCC_RPC_SVC_H__ 1

#include <features.h>
#include <rpc/rpc_msg.h>

/*
 * This interface must manage two items concerning remote procedure calling:
 *
 * 1) An arbitrary number of transport connections upon which rpc requests
 * are received.  The two most notable transports are TCP and UDP;  they are
 * created and registered by routines in svc_tcp.c and svc_udp.c, respectively;
 * they in turn call xprt_register and xprt_unregister.
 *
 * 2) An arbitrary number of locally registered services.  Services are
 * described by the following four data: program number, version number,
 * "service dispatch" function, a transport handle, and a boolean that
 * indicates whether or not the exported program should be registered with a
 * local binder service;  if true the program's number and version and the
 * port number from the transport handle are registered with the binder.
 * These data are registered with the rpc svc system via svc_register.
 *
 * A service's dispatch function is called whenever an rpc request comes in
 * on a transport.  The request's program and version numbers must match
 * those of the registered service.  The dispatch function is passed two
 * parameters, struct svc_req * and SVCXPRT *, defined below.
 */

int enum xprt_stat
{
  XPRT_DIED,
  XPRT_MOREREQS,
  XPRT_IDLE
};

/*
 * Server side transport handle
 */
typedef struct SVCXPRT SVCXPRT;
struct SVCXPRT
{
  int xp_sock;
  u_short xp_port;              /* associated port number */
  const struct xp_ops
  {
    bool_t (*xp_recv)(SVCXPRT *xprt, struct rpc_msg *msg);
    enum xprt_stat (*xp_stat)(SVCXPRT *xprt);
    bool_t (*xp_getargs)(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr);
    bool_t (*xp_reply)(SVCXPRT *xprt, struct rpc_msg *msg);
    bool_t (*xp_freeargs)(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr);
    void (*xp_destroy)(SVCXPRT *xprt);
  } *xp_ops;
  int           xp_addrlen;
  struct sockaddr_in xp_raddr;
  struct opaque_auth xp_verf;
  caddr_t               xp_p1;
  caddr_t               xp_p2;
  char          xp_pad [256];
};

/*
 *  Approved way of getting address of caller
 */
#define svc_getcaller(x) (&(x)->xp_raddr)

/*
 * Operations defined on an SVCXPRT handle
 *
 * SVCXPRT              *xprt;
 * struct rpc_msg       *msg;
 * xdrproc_t             xargs;
 * caddr_t               argsp;
 */
#define SVC_RECV(xprt, msg)                             \
        (*(xprt)->xp_ops->xp_recv)((xprt), (msg))
#define svc_recv(xprt, msg)                             \
        (*(xprt)->xp_ops->xp_recv)((xprt), (msg))

#define SVC_STAT(xprt)                                  \
        (*(xprt)->xp_ops->xp_stat)(xprt)
#define svc_stat(xprt)                                  \
        (*(xprt)->xp_ops->xp_stat)(xprt)

#define SVC_GETARGS(xprt, xargs, argsp)                 \
        (*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))
#define svc_getargs(xprt, xargs, argsp)                 \
        (*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))

#define SVC_REPLY(xprt, msg)                            \
        (*(xprt)->xp_ops->xp_reply) ((xprt), (msg))
#define svc_reply(xprt, msg)                            \
        (*(xprt)->xp_ops->xp_reply) ((xprt), (msg))

#define SVC_FREEARGS(xprt, xargs, argsp)                \
        (*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))
#define svc_freeargs(xprt, xargs, argsp)                \
        (*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))

#define SVC_DESTROY(xprt)                               \
        (*(xprt)->xp_ops->xp_destroy)(xprt)
#define svc_destroy(xprt)                               \
        (*(xprt)->xp_ops->xp_destroy)(xprt)

/*
 * Service request
 */
struct svc_req
{
  rpcprog_t rq_prog;
  rpcvers_t rq_vers;
  rpcproc_t rq_proc;
  struct opaque_auth rq_cred;
  caddr_t rq_clntcred;
  SVCXPRT *rq_xprt;
};

#ifndef __DISPATCH_FN_T
#define __DISPATCH_FN_T
typedef void (*__dispatch_fn_t)(struct svc_req*, SVCXPRT*);
#endif

bool_t svc_register(SVCXPRT *xprt, rpcprog_t prog, rpcvers_t vers,
                    __dispatch_fn_t dispatch, rpcprot_t protocol);
void svc_unregister(rpcprog_t prog, rpcvers_t vers);
void xprt_register(SVCXPRT *xprt);
void xprt_unregister(SVCXPRT *xprt);
bool_t svc_sendreply(SVCXPRT *xprt, xdrproc_t xdr_results,
                     caddr_t xdr_location);
void svcerr_decode(SVCXPRT *xprt);
void svcerr_weakauth(SVCXPRT *xprt);
void svcerr_noproc(SVCXPRT *xprt);
void svcerr_progvers(SVCXPRT *xprt, rpcvers_t low_vers, rpcvers_t high_vers);
void svcerr_auth(SVCXPRT *xprt, enum auth_stat why);
void svcerr_noprog(SVCXPRT *xprt);
void svcerr_systemerr(SVCXPRT *xprt);

/*
 * Lowest level dispatching -OR- who owns this process anyway.
 * Somebody has to wait for incoming requests and then call the correct
 * service routine.  The routine svc_run does infinite waiting; i.e.,
 * svc_run never returns.
 * Since another (coexistent) package may wish to selectively wait for
 * incoming calls or other events outside of the rpc architecture, the
 * routine svc_getreq is provided.  It must be passed readfds, the
 * "in-place" results of a select system call (see select, section 2).
 */

/*
 * Global keeper of rpc service descriptors in use
 * dynamic; must be inspected before each call to select
 */

extern struct pollfd *svc_pollfd;
extern int svc_max_pollfd;
extern fd_set svc_fdset;
#define svc_fds svc_fdset.fds_bits[0]   /* compatibility */

/*
 * a small program implemented by the svc_rpc implementation itself;
 * also see clnt.h for protocol numbers.
 */
void svc_getreq(int rdfds);
void svc_getreq_common(const int fd);
void svc_getreqset(fd_set *readfds);
void svc_getreq_poll(struct pollfd *, const int);
void svc_exit(void);
void svc_run(void);

/*
 * Socket to use on svcxxx_create call to get default socket
 */
int enum { RPC_ANYSOCK = -1 };
#define RPC_ANYSOCK RPC_ANYSOCK

SVCXPRT *svcraw_create(void);
SVCXPRT *svcudp_create(int sock) ;
SVCXPRT *svcudp_bufcreate(int sock, u_int sendsz, u_int recvsz);
SVCXPRT *svctcp_create(int sock, u_int sendsize, u_int recvsize);
SVCXPRT *svcunix_create(int sock, u_int sendsize, u_int recvsize, char *path);

#endif /* __RCC_RPC_SVC_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "des_block" "XDR" "u_int" "AUTH" "netobj" "u_long" "CLIENT" "u_char" "u_short" "SVCXPRT" "fd_set")
 * End:
 */
