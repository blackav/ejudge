/* -*- c -*- */
/* $Id$ */

#ifndef __WATCHED_FILE_H__
#define __WATCHED_FILE_H__

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

#include <time.h>

struct watched_file
{
  unsigned char *path;
  time_t last_check;
  time_t last_mtime;
  size_t size;
  unsigned char *text;
};

void
watched_file_update(struct watched_file *pw, const unsigned char *path,
                    time_t cur_time);
void
watched_file_clear(struct watched_file *pw);

#endif /* __WATCHED_FILE_H__ */
