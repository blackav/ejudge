/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "watched_file.h"
#include "fileutl.h"

#include <reuse/xalloc.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void
watched_file_update(struct watched_file *pw, const unsigned char *path,
                    time_t cur_time)
{
  struct stat stb;
  char *tmpc = 0;

  if (!path) {
    if (!pw->path) return;
    xfree(pw->path);
    xfree(pw->text);
    memset(pw, 0, sizeof(*pw));
    return;
  }

  if (!cur_time) cur_time = time(0);
  if (pw->path && strcmp(path, pw->path) != 0) {
    xfree(pw->path);
    xfree(pw->text);
    memset(pw, 0, sizeof(*pw));
  }
  if (!pw->path) {
    pw->path = xstrdup(path);
    pw->last_check = cur_time;
    if (stat(pw->path, &stb) < 0) return;
    pw->last_mtime = stb.st_mtime;
    generic_read_file(&tmpc, 0, &pw->size, 0, 0, pw->path, "");
    pw->text = tmpc;
    return;
  }
  if (pw->last_check + 10 > cur_time) return;
  if (stat(pw->path, &stb) < 0) {
    xfree(pw->text); pw->text = 0;
    pw->size = 0;
    pw->last_check = cur_time;
    return;
  }
  if (pw->last_mtime == stb.st_mtime) return;
  pw->last_mtime = stb.st_mtime;
  pw->last_check = cur_time;
  xfree(pw->text); pw->text = 0;
  pw->size = 0;
  generic_read_file(&tmpc, 0, &pw->size, 0, 0, pw->path, "");
  pw->text = tmpc;  
}

void
watched_file_clear(struct watched_file *pw)
{
  if (!pw) return;

  xfree(pw->text);
  xfree(pw->path);
  memset(pw, 0, sizeof(pw));
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
