/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/**
 *  NAME:    os_SetLock
 *  PURPOSE: set the lockfile with the specified name
 *  ARGS:    path      - lock file path
 *           perms     - file permissions
 *           left_open - 1, if the function should return the open file
 *                       0, if the function should close the file
 *  RETURN:  >= 0 - ok, -1 - file is locked, -2 - other error
 *  NOTE:    function works reliably over NFS (Network Failure System)
 */
  int
os_SetLock(char const *path, int perms, int left_open)
{
  char *dirname   = os_DirName(path);
  char *hostname  = os_NodeName();
  char *uniq_name = 0;
  int   fd        = -1;
  int   code      = 0;
  int   file_flag = 0;
  struct stat buf;

  /* 1. Create the unique file on the same filesystem */
  uniq_name = xmalloc(strlen(dirname) + strlen(hostname) + 32);
  sprintf(uniq_name, "%s/LCK_%s_%d", dirname, hostname, (int) getpid());
  if ((fd = open(uniq_name, O_WRONLY | O_CREAT, perms)) < 0) {
    code = -2;
    goto free_resources;
  }
  file_flag = 1;

  /* 2. Use link(2) to create a link to the lockfile */
  /*    do not use the return value of link call */
  link(uniq_name, path);

  /* 3. Use stat(2) on the unique file to check that the link count
        is increased to 2 */
  if (fstat(fd, &buf) < 0) {
    code = -2;
    goto free_resources;
  }
  if (buf.st_nlink != 2) {
    code = -1;
    goto free_resources;
  }

  /* at this point lock file is created */
  if (left_open) {
    code = fd;
    fd = -1;
  }

 free_resources:
  if (file_flag) unlink(uniq_name);
  free(uniq_name);
  free(dirname);
  if (fd >= 0) close(fd);
  return code;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
