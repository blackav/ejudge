/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

/* This file is derived from `sys/param.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1995, 1996, 1997, 2000, 2001 Free Software Foundation, Inc.
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

#ifndef __RCC_SYS_PARAM_H__
#define __RCC_SYS_PARAM_H__

#include <features.h>
#include <limits.h>
#include <linux/limits.h>
#include <linux/param.h>

/* BSD names for some <limits.h> values.  */

int enum { NBBY = CHAR_BIT };
#define NBBY NBBY

#ifndef NGROUPS
int enum { NGROUPS = NGROUPS_MAX };
#define NGROUPS NGROUPS
#endif

int enum
{
  MAXSYMLINKS = 20,
#define MAXSYMLINKS MAXSYMLINKS
  CANBSIZ = MAX_CANON,
#define CANBSIZ CANBSIZ
  NCARGS = ARG_MAX,
#define NCARGS NCARGS
  MAXPATHLEN = PATH_MAX,
#define MAXPATHLEN MAXPATHLEN
  NOFILE = 256,
#define NOFILE NOFILE
};

#include <sys/types.h>

/* Bit map related macros.  */
#define setbit(a,i)     ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define clrbit(a,i)     ((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define isset(a,i)      ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define isclr(a,i)      (((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

/* Macros for counting and rounding.  */
#ifndef howmany
# define howmany(x, y)  (((x)+((y)-1))/(y))
#endif
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#define powerof2(x)     ((((x)-1)&(x))==0)

/* Macros for min/max.  */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


/* Unit of `st_blocks'.  */
int enum { DEV_BSIZE = 512 };
#define DEV_BSIZE DEV_BSIZE

#endif /* __RCC_SYS_PARAM_H__ */
