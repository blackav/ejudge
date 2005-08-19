/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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
#include "version.h"

#include "vcs.h"
#include "pathutl.h"
#include "ej_process.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

enum
{
  VCS_NONE,
  VCS_SVN,
  VCS_CVS,

  VCS_LAST,
};

static int
get_vcs_type(const unsigned char *dir)
{
  path_t path2;
  struct stat sb;

  snprintf(path2, sizeof(path2), "%s/.svn", dir);
  if (stat(path2, &sb) >= 0 && S_ISDIR(sb.st_mode))
    return VCS_SVN;
  snprintf(path2, sizeof(path2), "%s/CVS", dir);
  if (stat(path2, &sb) >= 0 && S_ISDIR(sb.st_mode))
    return VCS_CVS;

  return VCS_NONE;
}

typedef int (*vcs_func_t)(const unsigned char *, const unsigned char *,
                          unsigned char **);

static int
execute_commands(const unsigned char *dir,
                 const unsigned char **cmds,
                 unsigned char **p_log_txt)
{
  FILE *fout = 0;
  char *fout_txt = 0;
  size_t fout_len = 0;
  int i;
  unsigned char *s;

  fout = open_memstream(&fout_txt, &fout_len);
  for (i = 0; cmds[i]; i++) {
    fprintf(fout, ">%s\n", cmds[i]);
    s = read_process_output(cmds[i], dir, 0, 1);
    fprintf(fout, "%s\n", s);
    xfree(s);
  }
  fclose(fout);
  if (p_log_txt) *p_log_txt = fout_txt;
  else xfree(fout_txt);
  return 1;
}

static int
svn_add(const unsigned char *dir, const unsigned char *file,
        unsigned char **p_log_txt)
{
  path_t cmd1, cmd2, cmd3;
  const unsigned char *cmds[] = { cmd1, cmd2, cmd3, 0 };

  snprintf(cmd1, sizeof(cmd1), "svn add \"%s\"", file);
  snprintf(cmd2, sizeof(cmd2), "svn ps svn:eol-style native \"%s\"", file);
  snprintf(cmd3, sizeof(cmd3), "svn ps svn:keywords Id \"%s\"", file);
  return execute_commands(dir, cmds, p_log_txt);
}
static int
cvs_add(const unsigned char *dir, const unsigned char *file,
        unsigned char **p_log_txt)
{
  path_t cmd1;
  const unsigned char *cmds[] = { cmd1, 0 };

  snprintf(cmd1, sizeof(cmd1), "cvs add \"%s\"", file);
  return execute_commands(dir, cmds, p_log_txt);
}

static int
svn_commit(const unsigned char *dir, const unsigned char *file,
           unsigned char **p_log_txt)
{
  path_t cmd1;
  const unsigned char *cmds[] = { cmd1, 0 };

  snprintf(cmd1, sizeof(cmd1), "svn ci -m \"\" \"%s\"", file);
  return execute_commands(dir, cmds, p_log_txt);
}
static int
cvs_commit(const unsigned char *dir, const unsigned char *file,
           unsigned char **p_log_txt)
{
  path_t cmd1;
  const unsigned char *cmds[] = { cmd1, 0 };

  snprintf(cmd1, sizeof(cmd1), "cvs ci -m \"\" \"%s\"", file);
  return execute_commands(dir, cmds, p_log_txt);
}

static int
vcs_do_action(const unsigned char *path, unsigned char **p_log_txt,
              vcs_func_t funcs[])
{
  path_t dir;
  path_t name;
  int type;
  vcs_func_t func;

  os_rGetLastname(path, name, sizeof(name));
  os_rDirName(path, dir, sizeof(dir));
  if ((type = get_vcs_type(dir)) <= VCS_NONE) return type;
  ASSERT(type < VCS_LAST);
  func = funcs[type];
  ASSERT(func);
  return (*func)(dir, name, p_log_txt);
}

static vcs_func_t vcs_add_funcs[] =
{
  [VCS_SVN] = svn_add,
  [VCS_CVS] = cvs_add,
};

int
vcs_add(const unsigned char *path, unsigned char **p_log_txt)
{
  return vcs_do_action(path, p_log_txt, vcs_add_funcs);
}

static vcs_func_t vcs_commit_funcs[] =
{
  [VCS_SVN] = svn_commit,
  [VCS_CVS] = cvs_commit,
};

int
vcs_commit(const unsigned char *path, unsigned char **p_log_txt)
{
  return vcs_do_action(path, p_log_txt, vcs_commit_funcs);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
