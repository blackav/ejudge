/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/ustat.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Header describing obsolete `ustat' interface.
   Copyright (C) 1996, 1998, 1999 Free Software Foundation, Inc.
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

/*
 * This interface is obsolete.  Use <sys/statfs.h> instead.
 */

#ifndef __RCC_SYS_USTAT_H__
#define __RCC_SYS_USTAT_H__ 1

#include <features.h>
#include <sys/types.h>

struct ustat
{
  daddr_t f_tfree;
  ino_t f_tinode;
  char f_fname[6];
  char f_fpack[6];
};

int ustat(dev_t dev, struct ustat *ubuf);

#endif /* __RCC_SYS_USTAT_H__ */
