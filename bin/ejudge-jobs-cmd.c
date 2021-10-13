/* -*- mode: c -*- */

/* Copyright (C) 2006-2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/version.h"
#include "ejudge/job_packet.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
  int r;
  unsigned char **args = (unsigned char**) argv + 1;

  r = send_job_packet(NULL, args);
  if (r >= 0) return 0;
  return 1;
}
