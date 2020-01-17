/* -*- c -*- */

/* Copyright (C) 2010-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/ncheck_packet.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static const unsigned char *program_name;
static unsigned char *program_dir;
static unsigned char *config_file;

static void
die(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
die(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", program_name, buf);
  exit(1);
}

static void
get_program_dir(const unsigned char *program_path)
{
  unsigned char *workdir = 0;
  unsigned char fullpath[EJ_PATH_MAX];

  if (os_IsAbsolutePath(program_path)) {
    program_dir = os_DirName(program_path);
    os_normalize_path(program_dir);
    return;
  }

  workdir = os_GetWorkingDir();
  snprintf(fullpath, sizeof(fullpath), "%s/%s", workdir, program_path);
  xfree(workdir); workdir = 0;
  os_normalize_path(fullpath);
  program_dir = os_DirName(fullpath);
}

static void
get_config_file(void)
{
  unsigned char buf[EJ_PATH_MAX];

  if (config_file) return;

  snprintf(buf, sizeof(buf), "%s/ncheck.cfg", program_dir);
  config_file = xstrdup(buf);
}

static void
print_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

static void
print_help(void)
{
  exit(0);
}

struct config_global_data
{
  struct generic_section_config g;
};

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define CONFIG_OFFSET(x)   XOFFSET(struct config_global_data, x)
#define CONFIG_SIZE(x)     XFSIZE(struct config_global_data, x)
#define CONFIG_PARAM(x, t) { #x, t, CONFIG_OFFSET(x), CONFIG_SIZE(x) }
static const struct config_parse_info config_global_params[] =
{
  //CONFIG_PARAM(sleep_time, "d"),
  //CONFIG_PARAM(spool_dir, "s"),
  //CONFIG_PARAM(work_dir, "s"),
  //CONFIG_PARAM(cache_dir, "s"),

  { 0, 0, 0, 0 }
};

static const struct config_section_info params[] __attribute__((unused)) =
{
  { "global", sizeof(struct config_global_data), config_global_params, 0, 0, 0 },
  { NULL, 0, NULL }
};

int
main(int argc, char *argv[])
{
  int i;

  if (argc <= 0 || !argv[0]) {
    fprintf(stderr, "invalid program name\n");
    return 1;
  }
  program_name = os_GetLastname(argv[0]);
  get_program_dir(argv[0]);

  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--version")) {
      print_version();
    } else if (!strcmp(argv[i], "--help")) {
      print_help();
    } else {
      die("invalid option: %s", argv[i]);
    }
  }

  get_config_file();

  return 0;
}
