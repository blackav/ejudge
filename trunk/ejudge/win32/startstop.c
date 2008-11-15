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

#include "config.h"
#include "ej_types.h"
#include "version.h"
#include "startstop.h"

#include <reuse/logger.h>

void
start_set_self_args(int argc, char *argv[])
{
  SWERR(("not implemented"));
}

int
start_switch_user(const unsigned char *user, const unsigned char *group)
{
  SWERR(("not implemented"));
}

int
start_prepare(const unsigned char *user, const unsigned char *group,
              const unsigned char *workdir)
{
  SWERR(("not implemented"));
}

void
start_restart(void)
{
  SWERR(("not implemented"));
}

void
start_set_args(char *argv[])
{
  SWERR(("not implemented"));
}
