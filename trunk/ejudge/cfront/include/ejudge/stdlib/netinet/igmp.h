/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netinet/igmp.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1997, 1999 Free Software Foundation, Inc.
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

#ifndef __RCC_NETINET_IGMP_H__
#define __RCC_NETINET_IGMP_H__ 1

//#include <sys/cdefs.h>
#include <features.h>
#include <sys/types.h>
//#include <asm/types.h>
#include <linux/igmp.h>
#include <netinet/in.h>

/*
 * Copyright (c) 1988 Stephen Deering.
 * Copyright (c) 1992, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)igmp.h      8.1 (Berkeley) 6/10/93
 *      $FreeBSD$
 */

struct igmp
{
  u_int8_t igmp_type;             /* IGMP type */
  u_int8_t igmp_code;             /* routing code */
  u_int16_t igmp_cksum;           /* checksum */
  struct in_addr igmp_group;      /* group address */
};

/*
 * Message types, including version number.
 */
int enum
{
  IGMP_MEMBERSHIP_QUERY = 0x11,
#define IGMP_MEMBERSHIP_QUERY IGMP_MEMBERSHIP_QUERY
  IGMP_V1_MEMBERSHIP_REPORT = 0x12,
#define IGMP_V1_MEMBERSHIP_REPORT IGMP_V1_MEMBERSHIP_REPORT
  IGMP_V2_MEMBERSHIP_REPORT = 0x16,
#define IGMP_V2_MEMBERSHIP_REPORT IGMP_V2_MEMBERSHIP_REPORT
  IGMP_V2_LEAVE_GROUP = 0x17,
#define IGMP_V2_LEAVE_GROUP IGMP_V2_LEAVE_GROUP
};

#endif  /* __RCC_NETINET_IGMP_H__ */
