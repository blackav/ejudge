/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_SERVE_H__
#define __PREPARE_SERVE_H__

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

struct user_adjustment_map
{
  int vintage;
  int user_map_size;
  struct user_adjustment_info **user_map;
};

#endif /* __PREPARE_SERVE_H__ */
