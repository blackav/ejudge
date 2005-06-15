/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

#include "timestamp.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct file_stamp
{
  time_t mtime;
  off_t  size;
  time_t check_time;
};

file_stamp_t
file_stamp_get(const unsigned char *path)
{
  struct stat sb;
  file_stamp_t ts = 0;

  ASSERT(path);
  if (stat(path, &sb) < 0) return 0;
  XCALLOC(ts, 1);
  ts->mtime = sb.st_mtime;
  ts->size = sb.st_size;
  ts->check_time = time(0);
  return ts;
}

int
file_stamp_is_updated(const unsigned char *path, const file_stamp_t ts)
{
  struct stat sb;

  ASSERT(path);
  ASSERT(ts);

  /* FIXME: check for time interval */
  if (stat(path, &sb) < 0) return 1;
  if (sb.st_mtime != ts->mtime || sb.st_size != ts->size) return 1;
  ts->check_time = time(0);
  return 0;
}

file_stamp_t
file_stamp_update(const unsigned char *path, file_stamp_t ts)
{
  struct stat sb;

  ASSERT(path);

  if (!ts) return file_stamp_get(path);
  if (stat(path, &sb) < 0) return file_stamp_free(ts);
  ts->mtime = sb.st_mtime;
  ts->size = sb.st_size;
  ts->check_time = time(0);
  return ts;
}

file_stamp_t
file_stamp_free(file_stamp_t ts)
{
  if (!ts) return 0;
  xfree(ts);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
