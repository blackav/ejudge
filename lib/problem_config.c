/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2012-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/problem_config.h"
#include "ejudge/meta/problem_config_meta.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include <limits.h>

void
problem_config_section_init(struct generic_section_config *gp)
{
  for (int field_id = META_PROBLEM_CONFIG_SECTION_manual_checking;
       field_id < META_PROBLEM_CONFIG_SECTION_init_env;
       ++field_id) {
    // 'B' - ejintbool_t
    // 'i' - int
    // 't' - time_t
    // 'Z' - size_t
    // 's' - unsigned char *
    // 'x' - char **
    // 'X' - ejenvlist_t
    int type_id = meta_problem_config_section_get_type(field_id);
    void *vp = meta_problem_config_section_get_ptr_nc((struct problem_config_section*) gp, field_id);
    if (type_id == 'B') {
      *(ejintbool_t *) vp = -1;
    } else if (type_id == 'Z') {
      *(size_t *) vp = ~((size_t) 0);
    } else if (type_id == 'i') {
      int *ip = (int*) vp;
      if (field_id == META_PROBLEM_CONFIG_SECTION_priority_adjustment) {
        *ip = INT_MIN;
      } else {
        *ip = -1;
      }
    }
  }
}

struct problem_config_section *
problem_config_section_alloc(void)
{
  struct problem_config_section *p = NULL;
  XCALLOC(p, 1);
  problem_config_section_init((struct generic_section_config *) p);
  return p;
}

void
problem_config_section_free(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_problem_config_section_methods, gp);
    xfree(gp);
  }
}

static struct config_section_info problem_config_section_info[] =
{
  { "problem", sizeof(struct problem_config_section), NULL, NULL,
    problem_config_section_init, problem_config_section_free,
    &meta_problem_config_section_methods },

  { NULL, 0 },
};

struct problem_config_section *
problem_config_section_parse_cfg(const unsigned char *path, FILE *f)
{
  struct generic_section_config *cfg = parse_param(path, f, problem_config_section_info, 1, 0, 0, NULL);
  return (struct problem_config_section *) cfg;
}

struct problem_config_section *
problem_config_section_parse_cfg_str(const unsigned char *path, char *buf, size_t size)
{
  FILE *f = fmemopen(buf, size, "r");
  if (!f) return NULL;
  // FIXME: parse_param closes 'f'
  return problem_config_section_parse_cfg(path, f);
}

static struct problem_config_section default_values;

void
problem_config_section_unparse_cfg(FILE *out_f, const struct problem_config_section *p)
{
  if (default_values.manual_checking >= 0) {
    problem_config_section_init((struct generic_section_config *) &default_values);
  }
  if (p) {
    fprintf(out_f, "# -*- coding: utf-8 -*-\n\n");
    fprintf(out_f, "[problem]\n");
    meta_unparse_cfg(out_f, &meta_problem_config_section_methods, p, &default_values);
  }
}
