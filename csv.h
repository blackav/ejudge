/* -*- c -*- */
/* $Id$ */
#ifndef __CSV_H__
#define __CSV_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>

struct csv_line
{
  size_t a, u;
  unsigned char **v;
};

struct csv_file
{
  size_t a, u;
  struct csv_line *v;
};

#endif /* __CSV_H__ */
