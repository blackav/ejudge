/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_SYS_IPC_H__
#define __RCC_SYS_IPC_H__	1

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
#include <sys/types.h>

int enum
{
  IPC_CREAT = 01000,
#define IPC_CREAT IPC_CREAT
  IPC_EXCL = 02000,
#define IPC_EXCL  IPC_EXCL
  IPC_NOWAIT = 04000,
#define IPC_NOWAIT IPC_NOWAIT
};

int enum
{
  IPC_RMID = 0,
#define IPC_RMID IPC_RMID
  IPC_SET = 1,
#define IPC_SET IPC_SET
  IPC_STAT = 2,
#define IPC_STAT IPC_STAT
  IPC_INFO = 3,
#define IPC_INFO IPC_INFO
};

#define IPC_PRIVATE	((key_t) 0)


struct ipc_perm
{
  key_t __key;
  uid_t uid;
  gid_t gid;
  uid_t cuid;
  gid_t cgid;
  unsigned short int mode;
  unsigned short int __pad1;
  unsigned short int __seq;
  unsigned short int __pad2;
  unsigned long int __unused1;
  unsigned long int __unused2;
};

key_t ftok(const char *, int);

#endif /* __RCC_SYS_IPC_H__ */
