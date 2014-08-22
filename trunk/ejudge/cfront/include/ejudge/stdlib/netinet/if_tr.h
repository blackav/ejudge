/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netinet/if_tr.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1997 Free Software Foundation, Inc.
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

#ifndef __RCC_NETINET_IF_TR_H__
#define __RCC_NETINET_IF_TR_H__ 1

//#include <sys/cdefs.h>
#include <features.h>
#include <sys/types.h>
//#include <asm/types.h>
#include <linux/if_tr.h>

struct trn_hdr
{
  u_int8_t trn_ac;
  u_int8_t trn_fc;
  u_int8_t trn_dhost[TR_ALEN];
  u_int8_t trn_shost[TR_ALEN];
  u_int16_t trn_rcf;
  u_int16_t trn_rseg[8];
};

#endif  /* __RCC_NETINET_IF_TR_H__ */
