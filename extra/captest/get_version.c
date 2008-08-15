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

static int get_linux_version(void)
{
  struct utsname ub;
  int minor = 0, major = 0, rev = 0;

  if (uname(&ub) < 0) {
    fprintf(stderr, "failed: uname() error: %s\n", strerror(errno));
    return -1;
  }
  if (strcmp(ub.sysname, "Linux")) return 0;
  if (sscanf(ub.release, "%d.%d.%d", &major, &minor, &rev) != 3) return 0;
  if (major < 2 || minor < 0 || rev < 0) return 0;
  if (major == 2 && minor < 4) return 0;
  if (minor > 999) minor = 999;
  if (rev > 999) rev = 999;
  return (major * 1000 + minor) * 1000 + rev;
}
static int linux_version = -1;

