/* -*- mode: c -*- */

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/cpu.h"
#include "ejudge/errlog.h"

#include <stdlib.h>

int
cpu_get_bogomips(void)
{
  err("cpu_get_bogomips: not implemented");
  return -1;
}

void
cpu_get_performance_info(unsigned char **p_model, unsigned char **p_mhz)
{
  *p_model = NULL;
  *p_mhz = NULL;
}
