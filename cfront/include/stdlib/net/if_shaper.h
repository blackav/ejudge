/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `net/if_shaper.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1998 Free Software Foundation, Inc.
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

#ifndef __RCC_NET_IF_SHAPER_H__
#define __RCC_NET_IF_SHAPER_H__ 1

#include <features.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>

int enum
{
  SHAPER_QLEN = 10,
#define SHAPER_QLEN SHAPER_QLEN
  SHAPER_LATENCY = (5 * HZ),
#define SHAPER_LATENCY SHAPER_LATENCY
  SHAPER_MAXSLIP = 2,
#define SHAPER_MAXSLIP SHAPER_MAXSLIP
  SHAPER_BURST = (HZ / 50),
#define SHAPER_BURST SHAPER_BURST

  SHAPER_SET_DEV = 0x0001,
#define SHAPER_SET_DEV SHAPER_SET_DEV
  SHAPER_SET_SPEED = 0x0002,
#define SHAPER_SET_SPEED SHAPER_SET_SPEED
  SHAPER_GET_DEV = 0x0003,
#define SHAPER_GET_DEV SHAPER_GET_DEV
  SHAPER_GET_SPEED = 0x0004,
#define SHAPER_GET_SPEED SHAPER_GET_SPEED
};

struct shaperconf
{
  u_int16_t ss_cmd;
  union
  {
    char ssu_name[14];
    u_int32_t ssu_speed;
  } ss_u;
};

#define ss_speed ss_u.ssu_speed
#define ss_name ss_u.ssu_name

#endif /* __RCC_NET_IF_SHAPER_H__ */
