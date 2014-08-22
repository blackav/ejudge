/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/statvfs.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Definitions for getting information about a filesystem.
   Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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

#ifndef __RCC_SYS_STATVFS_H__
#define __RCC_SYS_STATVFS_H__ 1

#include <features.h>
#include <sys/types.h>

/* Get the system-specific definition of `struct statfs'.  */

struct statvfs
{
  unsigned long int f_bsize;
  unsigned long int f_frsize;
  __fsblkcnt_t f_blocks;
  __fsblkcnt_t f_bfree;
  __fsblkcnt_t f_bavail;
  __fsfilcnt_t f_files;
  __fsfilcnt_t f_ffree;
  __fsfilcnt_t f_favail;
  unsigned long int f_fsid;
  int __f_unused;
  unsigned long int f_flag;
  unsigned long int f_namemax;
  int __f_spare[6];
};

struct statvfs64
{
  unsigned long int f_bsize;
  unsigned long int f_frsize;
  __fsblkcnt64_t f_blocks;
  __fsblkcnt64_t f_bfree;
  __fsblkcnt64_t f_bavail;
  __fsfilcnt64_t f_files;
  __fsfilcnt64_t f_ffree;
  __fsfilcnt64_t f_favail;
  unsigned long int f_fsid;
  int __f_unused;
  unsigned long int f_flag;
  unsigned long int f_namemax;
  int __f_spare[6];
};

/* Definitions for the flag in `f_flag'.  These definitions should be
   kept in sync with the definitions in <sys/mount.h>.  */
int enum
{
  ST_RDONLY = 1,
#define ST_RDONLY ST_RDONLY
  ST_NOSUID = 2,
#define ST_NOSUID ST_NOSUID
  ST_NODEV = 4,
#define ST_NODEV ST_NODEV
  ST_NOEXEC = 8,
#define ST_NOEXEC ST_NOEXEC
  ST_SYNCHRONOUS = 16,
#define ST_SYNCHRONOUS ST_SYNCHRONOUS
  ST_MANDLOCK = 64,
#define ST_MANDLOCK ST_MANDLOCK
  ST_WRITE = 128,
#define ST_WRITE ST_WRITE
  ST_APPEND = 256,
#define ST_APPEND ST_APPEND
  ST_IMMUTABLE = 512,
#define ST_IMMUTABLE ST_IMMUTABLE
  ST_NOATIME = 1024,
#define ST_NOATIME ST_NOATIME
  ST_NODIRATIME = 2048
#define ST_NODIRATIME ST_NODIRATIME
};

/* Return information about the filesystem on which FILE resides.  */
int statvfs(const char *file, struct statvfs *buf);
int statvfs64(const char *file, struct statvfs64 *buf);
int fstatvfs(int fildes, struct statvfs *buf);
int fstatvfs64(int fildes, struct statvfs64 *buf);

#endif  /* __RCC_SYS_STATVFS_H__ */
