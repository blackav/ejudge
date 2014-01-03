/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `mntent.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Utilities for reading/writing fstab, mtab, etc.
   Copyright (C) 1995, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
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

#ifndef __RCC_MNTENT_H__
#define __RCC_MNTENT_H__ 1

#include <features.h>
#include <stdio.h>
#include <paths.h>

#define MNTTAB  _PATH_MNTTAB
#define MOUNTED _PATH_MOUNTED

#define MNTTYPE_IGNORE  "ignore"
#define MNTTYPE_NFS     "nfs"
#define MNTTYPE_SWAP    "swap"

#define MNTOPT_DEFAULTS "defaults"
#define MNTOPT_RO       "ro"
#define MNTOPT_RW       "rw"
#define MNTOPT_SUID     "suid"
#define MNTOPT_NOSUID   "nosuid"
#define MNTOPT_NOAUTO   "noauto"

struct mntent
{
  char *mnt_fsname;
  char *mnt_dir;
  char *mnt_type;
  char *mnt_opts;
  int mnt_freq;
  int mnt_passno;
};

FILE *setmntent(const char *file, const char *mode);
struct mntent *getmntent(FILE *stream);
struct mntent *getmntent_r(FILE *stream, struct mntent *result,
                           char *buffer, int bufsize);
int addmntent(FILE *stream, const struct mntent *mnt);
int endmntent(FILE *stream);
char *hasmntopt(const struct mntent *mnt, const char *opt);

#endif /* __RCC_MNTENT_H__ */
