/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_SERVE_H__
#define __PREPARE_SERVE_H__

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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

struct variant_map_item
{
  unsigned char *login;
  unsigned char *name;
  int user_id;
  int var_num;
  int *variants;

  // variant map version 2
  int real_variant;             /* one for all problems */
  int virtual_variant;          /* the displayed variant */
};

struct variant_map
{
  int *prob_map;
  int prob_map_size;
  int *prob_rev_map;
  int prob_rev_map_size;
  int var_prob_num;
  int vintage;

  size_t user_map_size;
  struct variant_map_item **user_map;

  size_t a, u;
  struct variant_map_item *v;
};

struct user_adjustment_map
{
  int vintage;
  int user_map_size;
  struct user_adjustment_info **user_map;
};

#endif /* __PREPARE_SERVE_H__ */
