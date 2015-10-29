/* -*- c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/dates_config.h"
#include "ejudge/meta_generic.h"
#include "ejudge/meta/dates_config_meta.h"

#include "ejudge/xalloc.h"

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define GLOBAL_OFFSET(x)   XOFFSET(struct dates_global_data, x)
#define GLOBAL_SIZE(x)     XFSIZE(struct dates_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }

static const struct config_parse_info dates_global_params[] =
{
    { 0, 0, 0, 0 }
};

#define PROBLEM_OFFSET(x)   XOFFSET(struct dates_problem_data, x)
#define PROBLEM_SIZE(x)     XFSIZE(struct dates_problem_data, x)
#define PROBLEM_PARAM(x, t) { #x, t, PROBLEM_OFFSET(x), PROBLEM_SIZE(x) }

static const struct config_parse_info dates_problem_params[] =
{
    { 0, 0, 0, 0 }
};

static void dates_global_init_func(struct generic_section_config *);
static void dates_global_free_func(struct generic_section_config *);
static void dates_problem_init_func(struct generic_section_config *);
static void dates_problem_free_func(struct generic_section_config *);

/*static*/ const struct config_section_info dates_params[] =
{
    { 
        "global", sizeof(struct dates_global_data), NULL, NULL,
        dates_global_init_func, dates_global_free_func,
        &meta_dates_global_data_methods,
    },
    {
        "problem", sizeof(struct dates_problem_data), NULL, NULL,
        dates_problem_init_func, dates_problem_free_func,
        &meta_dates_problem_data_methods,
    },

    { NULL, 0, NULL }
};

static void
dates_global_init_func(struct generic_section_config *gp)
{
}

static void
dates_global_free_func(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_dates_global_data_methods, gp);
    xfree(gp);
  }
}

static void
dates_problem_init_func(struct generic_section_config *gp)
{
}

static void
dates_problem_free_func(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_dates_problem_data_methods, gp);
    xfree(gp);
  }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
