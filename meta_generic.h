/* -*- c -*- */
/* $Id$ */

#ifndef __META_GENERIC_H__
#define __META_GENERIC_H__

/* Copyright (C) 2008-2012 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>

struct meta_info_item
{
  int tag;
  int type;
  size_t size;
  char *name;
  int offset;
};

#ifndef XSIZE
#define XSIZE(t,f) (sizeof(((t*)0)->f))
#endif

struct meta_automaton
{
  unsigned char remap[256];
  int char_num;

  short **st;                   /* states */
  int st_u;
  int st_a;
};

struct meta_automaton *
meta_build_automaton(const struct meta_info_item *item, int num);
int
meta_lookup_string(const struct meta_automaton *atm, const char *str);

struct meta_methods
{
  int last_tag;
  size_t size;
  int (*get_type)(int tag);
  size_t (*get_size)(int tag);
  const char *(*get_name)(int tag);
  const void *(*get_ptr)(const void *ptr, int tag);
  void *(*get_ptr_nc)(void *ptr, int tag);
  int (*lookup_field)(const char *name);
};

void
meta_destroy_fields(const struct meta_methods *mth, void *ptr);

int
meta_parse_string(
        FILE *log_f,
        int lineno,
        void *obj,
        int field_id,
        const struct meta_methods *mm,
        const unsigned char *name,
        const unsigned char *value,
        int charset_id);

void
meta_unparse_cfg(
        FILE *out_f,
        const struct meta_methods *mth,
        const void *ptr,
        const void *default_ptr);

#endif /* __META_GENERIC_H__ */
