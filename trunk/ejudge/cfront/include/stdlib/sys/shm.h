/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_SYS_SHM_H__
#define __RCC_SYS_SHM_H__ 1

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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
#include <sys/ipc.h>

/* Permission flag for shmget.  */
int enum
{
  SHM_R = 0400,
#define SHM_R SHM_R
  SHM_W = 0200,
#define SHM_W SHM_W
};

/* Flags for `shmat'.  */
int enum
{
  SHM_RDONLY = 010000,
#define SHM_RDONLY SHM_RDONLY
  SHM_RND = 020000,
#define SHM_RND    SHM_RND
  SHM_REMAP = 040000,
#define SHM_REMAP  SHM_REMAP
};

/* Commands for `shmctl'.  */
int enum
{
  SHM_LOCK = 11,
#define SHM_LOCK SHM_LOCK
  SHM_UNLOCK = 12,
#define SHM_UNLOCK SHM_UNLOCK
  SHM_STAT = 13,
#define SHM_STAT SHM_STAT
  SHM_INFO = 14,
#define SHM_INFO SHM_INFO
};

/* Segment low boundary address multiple.  */
#define SHMLBA (__getpagesize ())
int __getpagesize (void);


/* Type to count number of attaches.  */
typedef unsigned long int shmatt_t;

struct shmid_ds
{
  struct ipc_perm shm_perm;		/* operation permission struct */
  size_t shm_segsz;			/* size of segment in bytes */
  time_t shm_atime;			/* time of last shmat() */
  unsigned long int __unused1;
  time_t shm_dtime;			/* time of last shmdt() */
  unsigned long int __unused2;
  time_t shm_ctime;			/* time of last change by shmctl() */
  unsigned long int __unused3;
  pid_t shm_cpid;			/* pid of creator */
  pid_t shm_lpid;			/* pid of last shmop */
  shmatt_t shm_nattch;		/* number of current attaches */
  unsigned long int __unused4;
  unsigned long int __unused5;
};

/* shm_mode upper byte flags */
int enum
{
  SHM_DEST = 01000,
#define SHM_DEST SHM_DEST
  SHM_LOCKED = 02000,
#define SHM_LOCKED SHM_LOCKED
  SHM_HUGETLB = 04000,
#define SHM_HUGETLB SHM_HUGETLB
};

struct shminfo
{
  unsigned long int shmmax;
  unsigned long int shmmin;
  unsigned long int shmmni;
  unsigned long int shmseg;
  unsigned long int shmall;
  unsigned long int __unused1;
  unsigned long int __unused2;
  unsigned long int __unused3;
  unsigned long int __unused4;
};

struct shm_info
{
  int used_ids;
  unsigned long int shm_tot;
  unsigned long int shm_rss;
  unsigned long int shm_swp;
  unsigned long int swap_attempts;
  unsigned long int swap_successes;
};

/* Shared memory control operation.  */
int shmctl (int __shmid, int __cmd, struct shmid_ds *__buf);

/* Get shared memory segment.  */
int shmget (key_t __key, size_t __size, int __shmflg);

/* Attach shared memory segment.  */
void *shmat (int __shmid, __const void *__shmaddr, int __shmflg);

/* Detach shared memory segment.  */
int shmdt (const void *__shmaddr);

#endif /* __RCC_SYS_SHM_H__ */
