/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "cr_serialize.h"
#include "prepare.h"
#include "prepare_vars.h"
#include "errlog.h"

#include <reuse/osdeps.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>

static int semid = -1;

int
cr_serialize_init(void)
{
  int saved_errno;

  if (!global->cr_serialization_key) return 0;
  if (semid >= 0) return 0;

  semid = semget(global->cr_serialization_key, 1, IPC_CREAT | IPC_EXCL | 0666);
  if (semid < 0) {
    if (errno != EEXIST) {
      saved_errno = errno;
      err("cr_serialize_init: semget() failed: %s", os_ErrorMsg());
      errno = saved_errno;
      return -saved_errno;
    }
    semid = semget(global->cr_serialization_key, 1, 0);
    if (semid < 0) {
      saved_errno = errno;
      err("cr_serialize_init: semget() failed: %s", os_ErrorMsg());
      errno = saved_errno;
      return -saved_errno;
    }
    return 0;
  }

  if (semctl(semid, 0, SETVAL, 1) < 0) {
    saved_errno = errno;
    err("cr_serialize_init: semctl() failed: %s", os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }
  return 0;
}

int
cr_serialize_lock(void)
{
  int saved_errno;
  struct sembuf ops[1] = {{ 0, -1, SEM_UNDO }};
  struct sembuf ops_nowait[1] = {{ 0, -1, SEM_UNDO | IPC_NOWAIT }};

  if (!global->cr_serialization_key) return 0;

  while (1) {
    if (semop(semid, ops_nowait, 1) >= 0) return 0;
    if (errno == EAGAIN || errno == EINTR) break;
    saved_errno = errno;
    err("cr_serialize_lock: semop failed: %s", os_ErrorMsg());
    // FIXME: maybe handle recoverable errors?
    errno = saved_errno;
    return -saved_errno;
  }

  info("cr_serialize_lock: waiting for lock");
  while (1) {
    if (semop(semid, ops, 1) >= 0) break;
    if (errno == EINTR) {
      info("cr_serialize_lock: interrupted");
      continue;
    }
    saved_errno = errno;
    err("cr_serialize_lock: semop failed: %s", os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }
  return 0;
}

int
cr_serialize_unlock(void)
{
  struct sembuf ops[1] = {{ 0, 1, SEM_UNDO }};
  int saved_errno;

  if (!global->cr_serialization_key) return 0;

  if (semop(semid, ops, 1) < 0) {
    saved_errno = errno;
    err("cr_serialize_unlock: semop failed: %s", os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
