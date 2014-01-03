/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/mount.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Header file for mounting/unmount Linux filesystems.
   Copyright (C) 1996, 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
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

/* This is taken from /usr/include/linux/fs.h.  */

#ifndef __RCC_SYS_MOUNT_H__
#define __RCC_SYS_MOUNT_H__ 1

#include <features.h>
#include <sys/ioctl.h>

int enum
{
  BLOCK_SIZE = 1024,
#define BLOCK_SIZE BLOCK_SIZE
  BLOCK_SIZE_BITS = 10,
#define BLOCK_SIZE_BITS BLOCK_SIZE_BITS
};

/* These are the fs-independent mount-flags: up to 16 flags are
   supported  */
enum
{
  MS_RDONLY = 1,
#define MS_RDONLY       MS_RDONLY
  MS_NOSUID = 2,
#define MS_NOSUID       MS_NOSUID
  MS_NODEV = 4,
#define MS_NODEV        MS_NODEV
  MS_NOEXEC = 8,
#define MS_NOEXEC       MS_NOEXEC
  MS_SYNCHRONOUS = 16,
#define MS_SYNCHRONOUS  MS_SYNCHRONOUS
  MS_REMOUNT = 32,
#define MS_REMOUNT      MS_REMOUNT
  MS_MANDLOCK = 64,
#define MS_MANDLOCK     MS_MANDLOCK
  S_WRITE = 128,
#define S_WRITE         S_WRITE
  S_APPEND = 256,
#define S_APPEND        S_APPEND
  S_IMMUTABLE = 512,
#define S_IMMUTABLE     S_IMMUTABLE
  MS_NOATIME = 1024,
#define MS_NOATIME      MS_NOATIME
  MS_NODIRATIME = 2048,
#define MS_NODIRATIME   MS_NODIRATIME
  MS_BIND = 4096,
#define MS_BIND         MS_BIND
};

int enum
{
  MS_RMT_MASK = (MS_RDONLY | MS_MANDLOCK),
#define MS_RMT_MASK MS_RMT_MASK
  MS_MGC_VAL = 0xc0ed0000,
#define MS_MGC_VAL MS_MGC_VAL
  MS_MGC_MSK = 0xffff0000,
#define MS_MGC_MSK MS_MGC_MSK
};

/* The read-only stuff doesn't really belong here, but any other place
   is probably as bad and I don't want to create yet another include
   file.  */
#define BLKROSET   _IO(0x12, 93)
#define BLKROGET   _IO(0x12, 94)
#define BLKRRPART  _IO(0x12, 95)
#define BLKGETSIZE _IO(0x12, 96)
#define BLKFLSBUF  _IO(0x12, 97)
#define BLKRASET   _IO(0x12, 98)
#define BLKRAGET   _IO(0x12, 99)

/* Possible value for FLAGS parameter of `umount2'.  */
enum
{
  MNT_FORCE = 1
#define MNT_FORCE MNT_FORCE
};

/* Mount a filesystem.  */
int mount(const char *special_file, const char *dir,
          const char *fstype, unsigned long int rwflag,
          const void *data);

/* Unmount a filesystem.  */
int umount(const char *special_file);

/* Unmount a filesystem.  Force unmounting if FLAGS is set to MNT_FORCE.  */
int umount2(const char *special_file, int flags);

#endif /* __RCC_SYS_MOUNT_H__ */
