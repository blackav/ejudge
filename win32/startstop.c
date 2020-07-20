/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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

#define STARTSTOP_DEBUG 0

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/version.h"
#include "ejudge/startstop.h"

#include "ejudge/logger.h"

#if STARTSTOP_DEBUG - 0
#include <stdio.h>
#endif /* STARTSTOP_DEBUG - 0 */

void
start_set_self_args(int argc, char *argv[])
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_set_self_args\n");
#endif /* STARTSTOP_DEBUG - 0 */
}

int
start_switch_user(const unsigned char *user, const unsigned char *group)
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_switch_user\n");
#endif /* STARTSTOP_DEBUG - 0 */
  return 0;
}

int
start_prepare(const unsigned char *user, const unsigned char *group,
              const unsigned char *workdir)
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_prepare\n");
#endif /* STARTSTOP_DEBUG - 0 */
  return 0;
}

void
start_restart(void)
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_restart\n");
#endif /* STARTSTOP_DEBUG - 0 */
}

void
start_set_args(char *argv[])
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_set_args\n");
#endif /* STARTSTOP_DEBUG - 0 */
}

int
start_find_process(const unsigned char *name, int *p_uid)
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_find_process\n");
#endif /* STARTSTOP_DEBUG - 0 */
  return 0;
}

int
start_daemon(const unsigned char *log_path)
{
#if STARTSTOP_DEBUG - 0
  printf("win32/startstop.c: start_daemon\n");
#endif /* STARTSTOP_DEBUG - 0 */
  return 0;
}
