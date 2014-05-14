/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/curtime.h"

#include <sys/time.h>
#include <stdlib.h>

void
get_current_time(int *p_sec, int *p_usec)
{
  struct timeval tv;

  //memset(&tv, 0, sizeof(tv));
  gettimeofday(&tv, 0);
  if (p_sec) *p_sec = tv.tv_sec;
  if (p_usec) *p_usec = tv.tv_usec;
}

long long
get_current_time_ms(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  long long result = tv.tv_sec * 1000LL;
  result += (tv.tv_usec + 500LL) / 1000LL;
  return result;
}
