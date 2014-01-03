/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/statfs.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Definitions for getting information about a filesystem.
   Copyright (C) 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
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

#ifndef __RCC_SYS_STATFS_H__
#define __RCC_SYS_STATFS_H__ 1

/* Get the system-specific definition of `struct statfs'.  */
#include <features.h>
#include <sys/types.h>

struct statfs
{
  __SWORD_TYPE f_type;
  __SWORD_TYPE f_bsize;
  __fsblkcnt_t f_blocks;
  __fsblkcnt_t f_bfree;
  __fsblkcnt_t f_bavail;
  __fsfilcnt_t f_files;
  __fsfilcnt_t f_ffree;
  __fsid_t f_fsid;
  __SWORD_TYPE f_namelen;
  __SWORD_TYPE f_spare[6];
};

struct statfs64
{
  __SWORD_TYPE f_type;
  __SWORD_TYPE f_bsize;
  __fsblkcnt64_t f_blocks;
  __fsblkcnt64_t f_bfree;
  __fsblkcnt64_t f_bavail;
  __fsfilcnt64_t f_files;
  __fsfilcnt64_t f_ffree;
  __fsid_t f_fsid;
  __SWORD_TYPE f_namelen;
  __SWORD_TYPE f_spare[6];
};

/* Tell code we have this member.  */
#define _STATFS_F_NAMELEN

/* Return information about the filesystem on which FILE resides.  */
int statfs(const char *file, struct statfs *buf);
int statfs64(const char *file, struct statfs64 *buf);

/* Return information about the filesystem containing the file FILDES
   refers to.  */
int fstatfs(int fildes, struct statfs *buf);
int fstatfs64(int fildes, struct statfs64 *buf);

#endif  /* __RCC_SYS_STATFS_H__ */
