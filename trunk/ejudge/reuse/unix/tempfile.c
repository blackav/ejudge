/* $Id$ */

/* Copyright (C) 1998-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1998-01-20 19:11:20 cher> */

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

/**
 * FILE:    utils/tempfile.c
 * PURPOSE: temporary file support
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/tempfile.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* structure to store information about temp files */
typedef struct tempnode_t
{
  int   used;                   /* 1, if this entry is used */
  char *path;                   /* path to the file */
} tempnode_t;

/* structure of extendable array of temporary files structures */
typedef struct temparr_t
{
  struct tempnode_t *v;
  int                u;
  int                a;
} temparr_t;

static struct temparr_t temps;         /* array of temp files */

static void logged_unlink(char const *) __attribute__((unused));

/**
 * NAME:    temp_Create
 * PURPOSE: create a temporary file
 * ARGS:    dir - directory (if NULL, system temporary files dir is used)
 *          pfx - file prefix
 *          sfx - file suffix
 * RETURN:  name of the temporary file
 * NOTE:    DO NOT free the returned name of the file
 */
  char *
temp_Create(const char *dir, const char *pfx, const char *sfx)
{
  char *s = NULL;
  int   i;
  int   fd = -1;

  /* find an entry for this file */
  for (i = 0; i < temps.u; i++)
    if (!temps.v[i].used)
      break;

  if (i >= temps.u)
    {
      if (temps.u >= temps.a)
        {
          temps.a += 16;
          temps.v = xrealloc(temps.v, sizeof(temps.v[0]) * temps.a);
        }
      i = temps.u++;
    }

  while (1)
    {
      if (!(s = os_tempnam(dir, pfx))) goto failed;
      s = xstrmerge1(s, (char*) sfx);

      errno = 0;
      fd = open(s, O_WRONLY | O_CREAT | O_EXCL, 0644);
      if (fd >= 0) break;
      if (errno != EEXIST) goto failed;
      xfree(s);
    }

  close(fd);
  temps.v[i].used = 1;
  temps.v[i].path = s;

  write_log(LOG_REUSE, LOG_DEBUG, "Temp file '%s' created", s);

  return s;

 failed:
  if (s)
    write_log(LOG_REUSE, LOG_ERROR, "Failed to create temp file '%s'", s);
  else
    write_log(LOG_REUSE, LOG_ERROR, "Failed to create temp file");

  if (fd >= 0) close(fd);
  xfree(s);

  return NULL;
}

/**
 * NAME:    temp_Remove
 * PURPOSE: remove a temporary file
 * ARGS:    path - path to the temporary file
 * NOTE:    the temporary file should be requested with temp_Create call
 *          if the file was not created with temp_Create call, the file
 *          will not be removed.
 *          So it is safe to call the function with the name of a
 *          permanent (non temporary file).
 */
  void
temp_Remove(const char *path)
{
  int i;

  if (!path) return;

  for (i = 0; i < temps.u; i++)
    if (temps.v[i].used && !strcmp(temps.v[i].path, path))
      break;

  if (i >= temps.u) return;

  unlink(temps.v[i].path);
  //logged_unlink(temps.v[i].path);

  xfree(temps.v[i].path);
  temps.v[i].used = 0;
  temps.v[i].path = 0;
}

/**
 * NAME:    temp_Initialize
 * PURPOSE: initialize the module
 */
  void
temp_Initialize(void)
{
}

/**
 * NAME:    temp_Finalize
 * PURPOSE: finalize the module
 * NOTE:    all temporary files not removed explicitly are removed
 */
  void
temp_Finalize(void)
{
  int i;

  for (i = 0; i < temps.u; i++)
    {
      if (!temps.v[i].used) continue;

      unlink(temps.v[i].path);
      //logged_unlink(temps.v[i].path);

      xfree(temps.v[i].path);
      temps.v[i].used = 0;
      temps.v[i].path = 0;
    }
  xfree(temps.v);
  temps.v = 0;
  temps.a = temps.u = 0;
}

/**
 * NAME:    logged_unlink
 * PURPOSE: unlink the file and log this event
 * ARGS:    path - path to the file
 */
  static void
logged_unlink(char const *path)
{
  errno = 0;
  if (unlink(path) < 0)
    {
      write_log(LOG_REUSE, LOG_ERROR,
                "Failed to remove temp file '%s': %s",
                path,
                os_GetErrorString(errno));
    }
  else
    {
      write_log(LOG_REUSE, LOG_DEBUG,
                "Temp file '%s' removed", path);
    }
}
