/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/auth_des.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_RPC_AUTH_DES_H__
#define __RCC_RPC_AUTH_DES_H__ 1

#include <features.h>
#include <rpc/auth.h>

/* There are two kinds of "names": fullnames and nicknames */
int enum authdes_namekind
{
  ADN_FULLNAME,
  ADN_NICKNAME
};

/* A fullname contains the network name of the client,
   a conversation key and the window */
struct authdes_fullname
{
  char *name;
  des_block key;
  uint32_t window;
};

/* A credential */
struct authdes_cred
{
  enum authdes_namekind adc_namekind;
  struct authdes_fullname adc_fullname;
  uint32_t adc_nickname;
};

/* A timeval replacement for !32bit platforms */
struct rpc_timeval
{
  uint32_t tv_sec;
  uint32_t tv_usec;
};

/* A des authentication verifier */
struct authdes_verf
{
  union
  {
    struct rpc_timeval adv_ctime;
    des_block adv_xtime;
  } adv_time_u;
  uint32_t adv_int_u;
};

#define adv_timestamp  adv_time_u.adv_ctime
#define adv_xtimestamp adv_time_u.adv_xtime
#define adv_winverf    adv_int_u

#define adv_timeverf   adv_time_u.adv_ctime
#define adv_xtimeverf  adv_time_u.adv_xtime
#define adv_nickname   adv_int_u

int authdes_getucred(const struct authdes_cred *adc, uid_t *uid, gid_t *gid,
                     short *grouplen, gid_t *groups);
int getpublickey(const char *name, char *key);
int getsecretkey(const char *name, char *key, const char *passwd);
int rtime(struct sockaddr_in *addrp, struct rpc_timeval *timep,
          struct rpc_timeval *timeout);

#endif /* __RCC_RPC_AUTH_DES_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "des_block")
 * End:
 */
