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

#include "errlog.h"
#include "server_framework.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>

struct server_framework_params
{
};

static void startup_error(const char *, ...) __attribute__((noreturn,format(printf, 1, 2)));
static void
startup_error(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}


int
main(int argc, char *argv[])
{
  int i;

  program_name = argv[0];
  for (i = 1; i < argc; ) {
    if (!strcmp(argv[i], "-D")) {
      daemon_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-f")) {
      forced_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else
      break;
  }

  info("new-server %s, compiled %s", compile_version, compile_date);
  if (getuid() == 0) {
    startup_error("sorry, will not run as the root");
  }

  prepare();
  do_work();
  cleanup();

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
