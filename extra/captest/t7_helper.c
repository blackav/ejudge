/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(void)
{
  int val;

  errno = 0;
  val = semget(17842, 1, 0600 | IPC_CREAT);
  if (val >= 0) {
    fprintf(stderr, "failed: semget() successfully created a semaphore\n");
    semctl(val, 0, IPC_RMID);
    _exit(111);
  }
  if (errno != EPERM) {
    fprintf(stderr, "failed: semget() returned %s\n", strerror(errno));
    _exit(111);
  }

  exit(0);
}
