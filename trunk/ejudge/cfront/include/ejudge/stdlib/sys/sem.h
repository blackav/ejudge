/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_SYS_SEM_H__
#define __RCC_SYS_SEM_H__ 1

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

/* Flags for `semop'.  */
int enum { SEM_UNDO = 0x1000 };

/* Commands for `semctl'.  */
int enum
{
  GETPID = 11,
#define GETPID GETPID
  GETVAL = 12,
#define GETVAL GETVAL
  GETALL = 13,
#define GETALL GETALL
  GETNCNT = 14,
#define GETNCNT GETNCNT
  GETZCNT = 15,
#define GETZCNT GETZCNT
  SETVAL = 16,
#define SETVAL SETVAL
  SETALL = 17,
#define SETALL SETALL
  SEM_STAT = 18,
#define SEM_STAT SEM_STAT
  SEM_INFO = 19,
#define SEM_INFO SEM_INFO
};

/* Data structure describing a set of semaphores.  */
struct semid_ds
{
  struct ipc_perm sem_perm;		/* operation permission struct */
  time_t sem_otime;			/* last semop() time */
  unsigned long int __unused1;
  time_t sem_ctime;			/* last time changed by semctl() */
  unsigned long int __unused2;
  unsigned long int sem_nsems;		/* number of semaphores in set */
  unsigned long int __unused3;
  unsigned long int __unused4;
};

/* The user should define a union like the following to use it for arguments
   for `semctl'.

   union semun
   {
     int val;				<= value for SETVAL
     struct semid_ds *buf;		<= buffer for IPC_STAT & IPC_SET
     unsigned short int *array;		<= array for GETALL & SETALL
     struct seminfo *__buf;		<= buffer for IPC_INFO
   };

   Previous versions of this file used to define this union but this is
   incorrect.  One can test the macro _SEM_SEMUN_UNDEFINED to see whether
   one must define the union or not.  */
#define _SEM_SEMUN_UNDEFINED	1

/* ipcs ctl cmds */
struct  seminfo
{
  int semmap;
  int semmni;
  int semmns;
  int semmnu;
  int semmsl;
  int semopm;
  int semume;
  int semusz;
  int semvmx;
  int semaem;
};

/* Structure used for argument to `semop' to describe operations.  */
struct sembuf
{
  unsigned short int sem_num;	/* semaphore number */
  short int sem_op;		/* semaphore operation */
  short int sem_flg;		/* operation flag */
};

/* Semaphore control operation.  */
int semctl (int __semid, int __semnum, int __cmd, ...);

/* Get semaphore.  */
int semget (key_t __key, int __nsems, int __semflg);

/* Operate on semaphore.  */
int semop (int __semid, struct sembuf *__sops, size_t __nsops);

#endif /* __RCC_SYS_SEM_H__ */
