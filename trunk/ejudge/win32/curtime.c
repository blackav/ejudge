/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2006 Alexander Chernov <cher@ispras.ru> */

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

#include "curtime.h"

#include <time.h>
#include <windows.h>

void
get_current_time(int *p_sec, int *p_usec)
{
  time_t t1;
  SYSTEMTIME t2;

  time(&t1);
  GetSystemTime(&t2);
  if (p_sec) *p_sec = t1;
  if (p_usec) *p_usec = t2.wMilliseconds * 1000;
}
