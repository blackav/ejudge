/* -*- mode:c -*- */
#ifndef __POS_H__
#define __POS_H__

/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

typedef struct s_pos_t
{
  int line;
  int column;
  int file;
} pos_t;

typedef struct s_dpos_t
{
  pos_t beg;
  pos_t end;
} dpos_t;

unsigned char *pos_get_file(const pos_t *ppos);
void pos_set(pos_t *ppos, const unsigned char *file, int line, int column);
int pos_is_valid_file(int i);
unsigned char *pos_get_file_by_num(int i);

#endif /* __POS_H__ */
