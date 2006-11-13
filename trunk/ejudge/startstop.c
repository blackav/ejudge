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

#include "config.h"
#include "settings.h"
#include "ej_types.h"
#include "version.h"

#include "pathutl.h"
#include "errlog.h"

#include <reuse/osdeps.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

static path_t self_exe;
static char **self_argv;

void
start_set_self_args(int argc, char *argv[])
{
  int n;

  if ((n = readlink("/proc/self/exe", self_exe, sizeof(self_exe))) <= 0) {
    fprintf(stderr, "%s: cannot access /proc/self/exe: %s\n",
            argv[0], os_ErrorMsg());
    snprintf(self_exe, sizeof(self_exe), "%s", argv[0]);
  } else {
    self_exe[n] = 0;
  }
  self_argv = argv;
}

int
start_switch_user(const unsigned char *user, const unsigned char *group)
{
  struct passwd *pwinfo;
  struct group *grinfo;

  if (!user || !*user) {
    err("user is not specified (use -u option)");
    return -1;
  }
  if (!group || !*group) group = user;
  if (!(pwinfo = getpwnam(user))) {
    err("no such user: %s", user);
    return -1;
  }
  if (!(grinfo = getgrnam(group))) {
    err("no such group: %s", group);
    return -1;
  }
  if (setgid(grinfo->gr_gid) < 0) {
    err("cannot change gid: %s", os_ErrorMsg());
    return -1;
  }
  if (setuid(pwinfo->pw_uid) < 0) {
    err("cannot change uid: %s", os_ErrorMsg());
    return -1;
  }
  return 0;
}

int
start_prepare(const unsigned char *user, const unsigned char *group,
              const unsigned char *workdir)
{
  if (getuid() == 0) {
    if (start_switch_user(user, group) < 0) return -1;
  }

  if (workdir && *workdir) {
    if (chdir(workdir) < 0) {
      err("cannot change directory to %s", workdir);
      return -1;
    }
  }
  return 0;
}

void
start_restart(void)
{
  execv(self_exe, self_argv);
}
