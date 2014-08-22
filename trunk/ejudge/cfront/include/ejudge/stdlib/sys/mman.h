/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_SYS_MMAN_H__
#define	__RCC_SYS_MMAN_H__ 1

/* Copyright (C) 2003-2005 Alexander Chernov <cher@ispras.ru> */

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
#include <stdlib.h>

int enum
{
  PROT_READ = 0x1,
#define PROT_READ PROT_READ
  PROT_WRITE = 0x2,
#define PROT_WRITE PROT_WRITE
  PROT_EXEC = 0x4,
#define PROT_EXEC PROT_EXEC
  PROT_NONE = 0
#define PROT_NONE PROT_NONE
};

int enum
{
  MAP_SHARED = 0x01,
#define MAP_SHARED MAP_SHARED
  MAP_PRIVATE = 0x02,
#define MAP_PRIVATE MAP_PRIVATE
  MAP_TYPE = 0x0f,
#define MAP_TYPE MAP_TYPE
  MAP_FIXED = 0x10,
#define MAP_FIXED MAP_FIXED
  MAP_FILE = 0,
#define MAP_FILE MAP_FILE
  MAP_ANONYMOUS = 0x20,
#define MAP_ANONYMOUS MAP_ANONYMOUS
  MAP_ANON = MAP_ANONYMOUS,
#define MAP_ANON MAP_ANON
  MAP_GROWSDOWN = 0x0100,
#define MAP_GROWSDOWN MAP_GROWSDOWN
  MAP_DENYWRITE = 0x0800,
#define MAP_DENYWRITE MAP_DENYWRITE
  MAP_EXECUTABLE = 0x1000,
#define MAP_EXECUTABLE MAP_EXECUTABLE
  MAP_LOCKED = 0x2000,
#define MAP_LOCKED MAP_LOCKED
  MAP_NORESERVE = 0x4000,
#define MAP_NORESERVE MAP_NORESERVE
};

/* flags for `msync' */
int enum
{
  MS_ASYNC = 1,
  MS_SYNC = 4,
  MS_INVALIDATE = 2,
};

/* Flags for `mlockall'  */
int enum
{
  MCL_CURRENT = 1,
#define MCL_CURRENT MCL_CURRENT
  MCL_FUTURE = 2,
#define MCL_FUTURE MCL_FUTURE
};

int enum
{
  MREMAP_MAYMOVE = 1,
#define MREMAP_MAYMOVE MREMAP_MAYMOVE
};

int enum
{
  MADV_NORMAL = 0,
#define MADV_NORMAL MADV_NORMAL
#define POSIX_MADV_NORMAL MADV_NORMAL
  MADV_RANDOM = 1,
#define MADV_RANDOM MADV_RANDOM
#define POSIX_MADV_RANDOM MADV_RANDOM
  MADV_SEQUENTIAL = 2,
#define MADV_SEQUENTIAL MADV_SEQUENTIAL
#define POSIX_MADV_SEQUENTIAL MADV_SEQUENTIAL
  MADV_WILLNEED = 3,
#define MADV_WILLNEED MADV_WILLNEED
#define POSIX_MADV_WILLNEED MADV_WILLNEED
  MADV_DONTNEED = 4,
#define MADV_DONTNEED MADV_DONTNEED
#define POSIX_MADV_DONTNEED MADV_DONTNEED
};

#define MAP_FAILED	((void *) -1)

void *mmap(void *, size_t, int, int, int, off_t);
void *mmap64(void *, size_t, int, int, int, off64_t);
int munmap(void *, size_t);
int mprotect(void *, size_t, int);
int msync(void *, size_t, int);

int madvise(void *, size_t, int);
int posix_madvise(void *, size_t, int);

int mlock(const void *, size_t);
int munlock(const void *, size_t);
int mlockall(int);
int munlockall(void);

void *mremap(void *, size_t, size_t, int);
int mincore(void *, size_t, unsigned char *);

int shm_open(const char *, int, mode_t);
int shm_unlink(const char *);

#endif	/* __RCC_SYS_MMAN_H__ */
