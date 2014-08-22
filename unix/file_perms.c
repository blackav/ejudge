/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2009-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/file_perms.h"
#include "ejudge/misctext.h"

#include "ejudge/osdeps.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <unistd.h>

int
file_perms_parse_mode(const unsigned char *mode)
{
  char *eptr = 0;
  int m = 0;

  if (!mode) return -1;
  if (is_empty_string(mode)) return -1;
  m = strtol(mode, &eptr, 8);
  if (!is_empty_string(eptr)) return -1;
  m &= 07777;
  return m;
}

int
file_perms_parse_group(const unsigned char *group)
{
  struct group *g = 0;

  if (!group) return -1;
  if (is_empty_string(group)) return -1;
  if (!(g = getgrnam(group))) return -1;
  return g->gr_gid;
}

int
file_perms_set(
        FILE *flog,
        const unsigned char *path,
        int group,
        int mode,
        int old_group,
        int old_mode)
{
  if (group > 0) {
    if (chown(path, -1, group) < 0) {
      fprintf(flog, "chown: %s: %s\n", path, os_ErrorMsg());
    }
  } else if (old_group > 0) {
    chown(path, -1, old_group);
  }
  if (mode > 0) {
    if (chmod(path, mode) < 0) {
      fprintf(flog, "chmod: %s: %s\n", path, os_ErrorMsg());
    }
  } else if (old_mode > 0) {
    chmod(path, old_mode);
  }
  return 0;
}

void
file_perms_get(
        const unsigned char *path,
        int *p_group,
        int *p_mode)
{
  struct stat stb;

  if (*p_group) *p_group = 0;
  if (*p_mode) *p_mode = 0;

  if (stat(path, &stb) < 0) return;

  if (p_group) *p_group = stb.st_gid;
  if (p_mode) *p_mode = stb.st_mode & 07777;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
