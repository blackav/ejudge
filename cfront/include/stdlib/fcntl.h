/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_FCNTL_H__
#define __RCC_FCNTL_H__

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

int enum
  {
    O_ACCMODE = 0003,
#define O_ACCMODE O_ACCMODE
    O_RDONLY = 00,
#define O_RDONLY O_RDONLY
    O_WRONLY = 01,
#define O_WRONLY O_WRONLY
    O_RDWR = 02,
#define O_RDWR O_RDWR
    O_CREAT = 0100,
#define O_CREAT O_CREAT
    O_EXCL = 0200,
#define O_EXCL O_EXCL
    O_NOCTTY = 0400,
#define O_NOCTTY O_NOCTTY
    O_TRUNC = 01000,
#define O_TRUNC O_TRUNC
    O_APPEND = 02000,
#define O_APPEND O_APPEND
    O_NONBLOCK = 04000,
#define O_NONBLOCK O_NONBLOCK
    O_NDELAY = O_NONBLOCK,
#define O_NONBLOCK O_NONBLOCK
    O_SYNC = 010000,
#define O_SYNC O_SYNC
    O_FSYNC = O_SYNC,
#define O_FSYNC O_FSYNC
    O_ASYNC = 020000,
#define O_ASYNC O_ASYNC
    O_DIRECT = 040000,
#define O_DIRECT O_DIRECT
    O_DIRECTORY = 0200000,
#define O_DIRECTORY O_DIRECTORY
    O_NOFOLLOW = 0400000,
#define O_NOFOLLOW O_NOFOLLOW
    O_DSYNC = O_SYNC,
#define O_DSYNC O_DSYNC
    O_RSYNC = O_SYNC,
#define O_RSYNC O_RSYNC
    O_LARGEFILE = 0100000,
#define O_LARGEFILE O_LARGEFILE
  };

#ifndef SEEK_SET
int enum
{
#defconst SEEK_SET 0
#defconst SEEK_CUR 1
#defconst SEEK_END 2
};
#endif /* SEEK_SET */

#ifndef RCC_X_OK_DEFINED
#define RCC_X_OK_DEFINED
int enum
  {
    R_OK = 4,
#define R_OK R_OK
    W_OK = 2,
#define W_OK W_OK
    X_OK = 1,
#define X_OK X_OK
    F_OK = 0
#define F_OK F_OK
  };
#endif /* RCC_X_OK_DEFINED */

int enum
  {
    F_DUPFD = 0,
#define F_DUPFD F_DUPFD
    F_GETFD = 1,
#define F_GETFD F_GETFD
    F_SETFD = 2,
#define F_SETFD F_SETFD
    F_GETFL = 3,
#define F_GETFL F_GETFL
    F_SETFL = 4,
#define F_SETFL F_SETFL
    F_GETLK = 5,
#define F_GETLK F_GETLK
    F_SETLK = 6,
#define F_SETLK F_SETLK
    F_SETLKW = 7,
#define F_SETLKW F_SETLKW
    F_GETLK64 = 5,
#define F_GETLK64 F_GETLK64
    F_SETLK64 = 6,
#define F_SETLK64 F_SETLK64
    F_SETLKW64 = 7,
#define F_SETLKW64 F_SETLKW64
    F_SETOWN = 8,
#define F_SETOWN F_SETOWN
    F_GETOWN = 9,
#define F_GETOWN F_GETOWN
    F_SETSIG = 10,
#define F_SETSIG F_SETSIG
    F_GETSIG = 11,
#define F_GETSIG F_GETSIG
    F_SETLEASE = 1024,
#define F_SETLEASE F_SETLEASE
    F_GETLEASE = 1025,
#define F_GETLEASE F_GETLEASE
    F_NOTIFY = 1026,
#define F_NOTIFY F_NOTIFY
  };

int enum
  {
    FD_CLOEXEC = 1
#define FD_CLOEXEC FD_CLOEXEC
  };

#define F_RDLCK         0       /* Read lock.  */
#define F_WRLCK         1       /* Write lock.  */
#define F_UNLCK         2       /* Remove lock.  */

int open(const char *, int, ...);
int open64(const char *, int, ...);
int creat(const char *, mode_t);
int creat64(const char *, mode_t);

int fcntl(int, int, ...);

struct flock
  {
    short int l_type;   /* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    short int l_whence; /* Where `l_start' is relative to (like `lseek').  */
#ifndef __USE_FILE_OFFSET64
   off_t l_start;    /* Offset where the lock begins.  */
   off_t l_len;      /* Size of the locked area; zero means until EOF.  */
#else
   off64_t l_start;  /* Offset where the lock begins.  */
   off64_t l_len;    /* Size of the locked area; zero means until EOF.  */
#endif
   pid_t l_pid;      /* Process holding the lock.  */
  };

#ifndef F_ULOCK
int enum
{
  F_ULOCK,
#define F_ULOCK F_ULOCK
  F_LOCK,
#define F_LOCK F_LOCK
  F_TLOCK,
#define F_TLOCK F_TLOCK
  F_TEST,
#define F_TEST F_TEST
};
#endif

int lockf(int, int, off_t);
int lockf64(int, int, off64_t);

int posix_fadvise(int, off_t, size_t, int);
int posix_fadvise64(int off64_t, size_t, int);

int posix_fallocate(int, off_t, size_t);
int posix_fallocate64(int, off64_t, size_t);

int enum
{
  DN_ACCESS = 0x00000001,
#define DN_ACCESS DN_ACCESS
  DN_MODIFY = 0x00000002,
#define DN_MODIFY DN_MODIFY
  DN_CREATE = 0x00000004,
#define DN_CREATE DN_CREATE
  DN_DELETE = 0x00000008,
#define DN_DELETE DN_DELETE
  DN_RENAME = 0x00000010,
#define DN_RENAME DN_RENAME
  DN_ATTRIB = 0x00000020,
#define DN_ATTRIB DN_ATTRIB
  DN_MULTISHOT = 0x80000000,
#define DN_MULTISHOT DN_MULTISHOT
};

int enum { FNDELAY = O_NDELAY };
#define FNDELAY FNDELAY

#endif /* __RCC_FCNTL_H__ */
