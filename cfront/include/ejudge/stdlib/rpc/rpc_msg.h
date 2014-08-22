/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/rpc_msg.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* @(#)rpc_msg.h        2.1 88/07/29 4.0 RPCSRC */
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
/*      @(#)rpc_msg.h 1.7 86/07/16 SMI      */

#ifndef __RCC_RPC_MSG_H__
#define __RCC_RPC_MSG_H__ 1

#include <features.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>

/*
 * rpc_msg.h
 * rpc message definition
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

unsigned long enum { RPC_MSG_VERSION = ((u_long) 2) };
#define RPC_MSG_VERSION RPC_MSG_VERSION
unsigned short enum { RPC_SERVICE_PORT = ((u_short) 2048) };
#define RPC_SERVICE_PORT RPC_SERVICE_PORT

/*
 * Bottom up definition of an rpc message.
 * NOTE: call and reply use the same overall struct but
 * different parts of unions within it.
 */

int enum msg_type
{
  CALL=0,
  REPLY=1
};

int enum reply_stat
{
  MSG_ACCEPTED=0,
  MSG_DENIED=1
};

int enum accept_stat
{
  SUCCESS=0,
  PROG_UNAVAIL=1,
  PROG_MISMATCH=2,
  PROC_UNAVAIL=3,
  GARBAGE_ARGS=4,
  SYSTEM_ERR=5
};

int enum reject_stat
{
  RPC_MISMATCH=0,
  AUTH_ERROR=1
};

/*
 * Reply part of an rpc exchange
 */

/*
 * Reply to an rpc request that was accepted by the server.
 * Note: there could be an error even though the request was
 * accepted.
 */
struct accepted_reply 
{
  struct opaque_auth      ar_verf;
  enum accept_stat        ar_stat;
  union
  {
    struct
    {
      u_long  low;
      u_long  high;
    } AR_versions;
    struct
    {
      caddr_t where;
      xdrproc_t proc;
    } AR_results;
    /* and many other null cases */
  } ru;
};
#define ar_results      ru.AR_results
#define ar_vers         ru.AR_versions

/*
 * Reply to an rpc request that was rejected by the server.
 */
struct rejected_reply
{
  enum reject_stat rj_stat;
  union
  {
    struct
    {
      u_long low;
      u_long high;
    } RJ_versions;
    enum auth_stat RJ_why;
  } ru;
};
#define rj_vers ru.RJ_versions
#define rj_why  ru.RJ_why

/*
 * Body of a reply to an rpc request.
 */
struct reply_body
{
  enum reply_stat rp_stat;
  union
  {
    struct accepted_reply RP_ar;
    struct rejected_reply RP_dr;
  } ru;
};
#define rp_acpt ru.RP_ar
#define rp_rjct ru.RP_dr

/*
 * Body of an rpc request call.
 */
struct call_body
{
  u_long cb_rpcvers;
  u_long cb_prog;
  u_long cb_vers;
  u_long cb_proc;
  struct opaque_auth cb_cred;
  struct opaque_auth cb_verf;
};

/*
 * The rpc message
 */
struct rpc_msg
{
  u_long                  rm_xid;
  enum msg_type           rm_direction;
  union
  {
    struct call_body RM_cmb;
    struct reply_body RM_rmb;
  } ru;
};
#define rm_call         ru.RM_cmb
#define rm_reply        ru.RM_rmb
#define acpted_rply     ru.RM_rmb.ru.RP_ar
#define rjcted_rply     ru.RM_rmb.ru.RP_dr

bool_t xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg);
bool_t xdr_callhdr(XDR *xdrs, struct rpc_msg *cmsg);
bool_t xdr_replymsg(XDR *xdrs, struct rpc_msg *rmsg);
void _seterr_reply(struct rpc_msg *msg, struct rpc_err *error);

#endif /* __RCC_RPC_MSG_H__ */
