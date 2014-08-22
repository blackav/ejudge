/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/file.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1991, 92, 96, 97, 98, 99 Free Software Foundation, Inc.
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

#ifndef __RCC_SYS_FILE_H__
#define __RCC_SYS_FILE_H__ 1

#include <features.h>
#include <fcntl.h>

/* Alternate names for values for the WHENCE argument to `lseek'.
   These are the same as SEEK_SET, SEEK_CUR, and SEEK_END, respectively.  */
#ifndef L_SET
int enum
{
  L_SET = 0,
#define L_SET L_SET
  L_INCR = 1,
#define L_INCR L_INCR
  L_XTND = 2,
#define L_XTND L_XTND
};
#endif


/* Operations for the `flock' call.  */
int enum
{
  LOCK_SH = 1,
#define LOCK_SH LOCK_SH
  LOCK_EX = 2,
#define LOCK_EX LOCK_EX
  LOCK_UN = 8,
#define LOCK_UN LOCK_UN
  LOCK_NB = 4,
#define LOCK_NB LOCK_NB
};


/* Apply or remove an advisory lock, according to OPERATION,
   on the file FD refers to.  */
int flock(int fd, int operation);

#endif /* __RCC_SYS_FILE_H__ */
