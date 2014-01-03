/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/clnt.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* @(#)clnt.h   2.1 88/07/29 4.0 RPCSRC; from 1.31 88/02/08 SMI*/
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
 * clnt.h - Client side remote procedure call interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef __RCC_RPC_CLNT_H__
#define __RCC_RPC_CLNT_H__ 1

#include <features.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <sys/un.h>

int enum clnt_stat
{
  RPC_SUCCESS=0,
  RPC_CANTENCODEARGS=1,
  RPC_CANTDECODERES=2,
  RPC_CANTSEND=3,
  RPC_CANTRECV=4,
  RPC_TIMEDOUT=5,
  RPC_VERSMISMATCH=6,
  RPC_AUTHERROR=7,
  RPC_PROGUNAVAIL=8,
  RPC_PROGVERSMISMATCH=9,
  RPC_PROCUNAVAIL=10,
  RPC_CANTDECODEARGS=11,
  RPC_SYSTEMERROR=12,
  RPC_NOBROADCAST = 21,
  RPC_UNKNOWNHOST=13,
  RPC_UNKNOWNPROTO=17,
  RPC_UNKNOWNADDR = 19,
  RPC_RPCBFAILURE=14,
  RPC_PROGNOTREGISTERED=15,
  RPC_N2AXLATEFAILURE = 22,
  RPC_FAILED=16,
  RPC_INTR=18,
  RPC_TLIERROR=20,
  RPC_UDERROR=23,
  RPC_INPROGRESS = 24,
  RPC_STALERACHANDLE = 25
};
#define RPC_PMAPFAILURE RPC_RPCBFAILURE

/*
 * Error info.
 */
struct rpc_err
{
  enum clnt_stat re_status;
  union
  {
    int RE_errno;
    enum auth_stat RE_why;
    struct
    {
      u_long low;
      u_long high;
    } RE_vers;
    struct
    {
      long s1;
      long s2;
    } RE_lb;
  } ru;
};
#define re_errno        ru.RE_errno
#define re_why          ru.RE_why
#define re_vers         ru.RE_vers
#define re_lb           ru.RE_lb


/*
 * Client rpc handle.
 * Created by individual implementations, see e.g. rpc_udp.c.
 * Client is responsible for initializing auth, see e.g. auth_none.c.
 */
typedef struct CLIENT CLIENT;
struct CLIENT
{
  AUTH  *cl_auth;
  struct clnt_ops
  {
    enum clnt_stat (*cl_call)(CLIENT *, u_long, xdrproc_t, caddr_t, xdrproc_t,
                              caddr_t, struct timeval);
    void (*cl_abort)(void);
    void (*cl_geterr)(CLIENT *, struct rpc_err *);
    bool_t (*cl_freeres)(CLIENT *, xdrproc_t, caddr_t);
    void (*cl_destroy)(CLIENT *);
    bool_t (*cl_control)(CLIENT *, int, char *);
  } *cl_ops;
  caddr_t cl_private;
};

/*
 * client side rpc interface ops
 *
 * Parameter types are:
 *
 */

/*
 * enum clnt_stat
 * CLNT_CALL(rh, proc, xargs, argsp, xres, resp, timeout)
 *      CLIENT *rh;
 *      u_long proc;
 *      xdrproc_t xargs;
 *      caddr_t argsp;
 *      xdrproc_t xres;
 *      caddr_t resp;
 *      struct timeval timeout;
 */
#define CLNT_CALL(rh, proc, xargs, argsp, xres, resp, secs)     \
        ((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))
#define clnt_call(rh, proc, xargs, argsp, xres, resp, secs)     \
        ((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))

/*
 * void
 * CLNT_ABORT(rh);
 *      CLIENT *rh;
 */
#define CLNT_ABORT(rh)  ((*(rh)->cl_ops->cl_abort)(rh))
#define clnt_abort(rh)  ((*(rh)->cl_ops->cl_abort)(rh))

/*
 * struct rpc_err
 * CLNT_GETERR(rh);
 *      CLIENT *rh;
 */
#define CLNT_GETERR(rh,errp)    ((*(rh)->cl_ops->cl_geterr)(rh, errp))
#define clnt_geterr(rh,errp)    ((*(rh)->cl_ops->cl_geterr)(rh, errp))


/*
 * bool_t
 * CLNT_FREERES(rh, xres, resp);
 *      CLIENT *rh;
 *      xdrproc_t xres;
 *      caddr_t resp;
 */
#define CLNT_FREERES(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))
#define clnt_freeres(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))

/*
 * bool_t
 * CLNT_CONTROL(cl, request, info)
 *      CLIENT *cl;
 *      u_int request;
 *      char *info;
 */
#define CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
#define clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))

/*
 * control operations that apply to all transports
 *
 * Note: options marked XXX are no-ops in this implementation of RPC.
 * The are present in TI-RPC but can't be implemented here since they
 * depend on the presence of STREAMS/TLI, which we don't have.
 */
int enum
{
  CLSET_TIMEOUT = 1,
#define CLSET_TIMEOUT CLSET_TIMEOUT
  CLGET_TIMEOUT = 2,
#define CLGET_TIMEOUT CLGET_TIMEOUT
  CLGET_SERVER_ADDR = 3,
#define CLGET_SERVER_ADDR CLGET_SERVER_ADDR
  CLGET_FD = 6,
#define CLGET_FD CLGET_FD
  CLGET_SVC_ADDR = 7,
#define CLGET_SVC_ADDR CLGET_SVC_ADDR
  CLSET_FD_CLOSE = 8,
#define CLSET_FD_CLOSE CLSET_FD_CLOSE
  CLSET_FD_NCLOSE = 9,
#define CLSET_FD_NCLOSE CLSET_FD_NCLOSE
  CLGET_XID = 10,
#define CLGET_XID CLGET_XID
  CLSET_XID = 11,
#define CLSET_XID CLSET_XID
  CLGET_VERS = 12,
#define CLGET_VERS CLGET_VERS
  CLSET_VERS = 13,
#define CLSET_VERS CLSET_VERS
  CLGET_PROG = 14,
#define CLGET_PROG CLGET_PROG
  CLSET_PROG = 15,
#define CLSET_PROG CLSET_PROG
  CLSET_SVC_ADDR = 16,
#define CLSET_SVC_ADDR CLSET_SVC_ADDR
  CLSET_PUSH_TIMOD = 17,
#define CLSET_PUSH_TIMOD CLSET_PUSH_TIMOD
  CLSET_POP_TIMOD = 18,
#define CLSET_POP_TIMOD CLSET_POP_TIMOD
  CLSET_RETRY_TIMEOUT = 4,
#define CLSET_RETRY_TIMEOUT CLSET_RETRY_TIMEOUT
  CLGET_RETRY_TIMEOUT = 5,
#define CLGET_RETRY_TIMEOUT CLGET_RETRY_TIMEOUT
};

/*
 * void
 * CLNT_DESTROY(rh);
 *      CLIENT *rh;
 */
#define CLNT_DESTROY(rh)        ((*(rh)->cl_ops->cl_destroy)(rh))
#define clnt_destroy(rh)        ((*(rh)->cl_ops->cl_destroy)(rh))


/*
 * RPCTEST is a test program which is accessible on every rpc
 * transport/port.  It is used for testing, performance evaluation,
 * and network administration.
 */
#define RPCTEST_PROGRAM         ((u_long)1)
#define RPCTEST_VERSION         ((u_long)1)
#define RPCTEST_NULL_PROC       ((u_long)2)
#define RPCTEST_NULL_BATCH_PROC ((u_long)3)

/*
 * By convention, procedure 0 takes null arguments and returns them
 */
#define NULLPROC ((u_long)0)

/*
 * Below are the client handle creation routines for the various
 * implementations of client side rpc.  They can return NULL if a
 * creation failure occurs.
 */

CLIENT *clntraw_create(const u_long prog, const u_long vers);
CLIENT *clnt_create(const char *host, const u_long prog,
                    const u_long vers, const char *prot);
CLIENT *clnttcp_create(struct sockaddr_in *raddr, u_long prog,
                       u_long version, int *sockp, u_int sendsz, u_int recvsz);
CLIENT *clntudp_create(struct sockaddr_in *raddr, u_long program,
                       u_long version, struct timeval wait_resend,
                       int *sockp);
CLIENT *clntudp_bufcreate(struct sockaddr_in *raddr,
                          u_long program, u_long version,
                          struct timeval wait_resend, int *sockp,
                          u_int sendsz, u_int recvsz);
CLIENT *clntunix_create(struct sockaddr_un *raddr, u_long program,
                        u_long version, int *sockp,
                        u_int sendsz, u_int recvsz);

int callrpc(const char *host, const u_long prognum,
            const u_long versnum, const u_long procnum,
            const xdrproc_t inproc, const char *in,
            const xdrproc_t outproc, char *out);
int _rpc_dtablesize(void);

/*
 * Print why creation failed
 */
void clnt_pcreateerror (const char *msg);
char *clnt_spcreateerror(const char *msg);
void clnt_perrno(enum clnt_stat num);
void clnt_perror(CLIENT *clnt, const char *msg);
char *clnt_sperror(CLIENT *clnt, const char *msg);

/*
 * If a creation fails, the following allows the user to figure out why.
 */
struct rpc_createerr
{
  enum clnt_stat cf_stat;
  struct rpc_err cf_error;
};

extern struct rpc_createerr rpc_createerr;

char *clnt_sperrno(enum clnt_stat num);
int getrpcport(const char *host, u_long prognum, u_long versnum, u_int proto);
void get_myaddress(struct sockaddr_in *);

int enum
{
  UDPMSGSIZE = 8800,
#define UDPMSGSIZE UDPMSGSIZE
  RPCSMALLMSGSIZE = 400,
#define RPCSMALLMSGSIZE RPCSMALLMSGSIZE
};

#endif /* __RCC_RPC_CLNT_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "des_block" "XDR" "u_int" "AUTH" "netobj" "u_long" "CLIENT")
 * End:
 */
