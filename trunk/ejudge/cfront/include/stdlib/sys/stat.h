/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_STAT_H__
#define __RCC_SYS_STAT_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>
#include <sys/types.h>

/* these structures are copied from GNU libc 2.1.3 for Linux */
struct stat
{
  dev_t st_dev;
  ino_t st_ino;
  mode_t st_mode;
  nlink_t st_nlink;
  uid_t st_uid;
  gid_t st_gid;
  dev_t st_rdev;
  off_t st_size;
  unsigned long int st_blksize;
  blkcnt_t st_blocks;
  time_t st_atime;
  time_t st_mtime;
  time_t st_ctime;
  struct timespec st_ctim;
  struct timespec st_mtim;
  struct timespec st_atim;
};

struct stat64
{
  dev_t st_dev;
  ino64_t st_ino;
  mode_t st_mode;
  nlink_t st_nlink;
  uid_t st_uid;
  gid_t st_gid;
  dev_t st_rdev;
  off64_t st_size;
  unsigned long int st_blksize;
  blkcnt64_t st_blocks;
  time_t st_atime;
  time_t st_mtime;
  time_t st_ctime;
};

int enum
  {
    S_IFMT   = 0170000,
    S_IFDIR  = 0040000,
    S_IFCHR  = 0020000,
    S_IFBLK  = 0060000,
    S_IFREG  = 0100000,
    S_IFIFO  = 0010000,
    S_IFLNK  = 0120000,
    S_IFSOCK = 0140000,

    S_ISUID = 04000,
    S_ISGID = 02000,
    S_ISVTX = 01000,
    S_IREAD = 0400,
    S_IWRITE = 0200,
    S_IEXEC = 0100,

    S_IRUSR = S_IREAD,
    S_IWUSR = S_IWRITE,
    S_IXUSR = S_IEXEC,
    S_IRWXU = (S_IREAD|S_IWRITE|S_IEXEC),
    S_IRGRP = (S_IRUSR >> 3),
    S_IWGRP = (S_IWUSR >> 3),
    S_IXGRP = (S_IXUSR >> 3),
    S_IRWXG = (S_IRWXU >> 3),
    S_IROTH = (S_IRGRP >> 3),
    S_IWOTH = (S_IWGRP >> 3),
    S_IXOTH = (S_IXGRP >> 3),
    S_IRWXO = (S_IRWXG >> 3),
  };

#define	S_ISTYPE(mode, mask)	(((mode) & S_IFMT) == (mask))
#define	S_ISDIR(mode)	 S_ISTYPE((mode), S_IFDIR)
#define	S_ISCHR(mode)	 S_ISTYPE((mode), S_IFCHR)
#define	S_ISBLK(mode)	 S_ISTYPE((mode), S_IFBLK)
#define	S_ISREG(mode)	 S_ISTYPE((mode), S_IFREG)
#define S_ISFIFO(mode)	 S_ISTYPE((mode), S_IFIFO)

#define S_ISLNK(mode)	 S_ISTYPE((mode), S_IFLNK)
#define S_ISSOCK(mode)   S_ISTYPE((mode), S_IFSOCK)

mode_t umask(mode_t);

int mkdir(const char *, mode_t);
int mkfifo(const char *, mode_t);

int chmod(const char *, mode_t);
int fchmod(int, mode_t);

int stat(const char *, struct stat *);
int fstat(int, struct stat *);
int lstat(const char *, struct stat *);

#endif /* __RCC_SYS_STAT_H__ */
