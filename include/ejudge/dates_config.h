/* -*- c -*- */
#ifndef __DATES_CONFIG_H__
#define __DATES_CONFIG_H__

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

#include "ejudge/ej_types.h"
#include "ejudge/parsecfg.h"

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

#include <time.h>

struct dates_global_data
{
    struct generic_section_config g META_ATTRIB((meta_hidden));

    time_t deadline;
    time_t start_date;
    char **date_penalty;
    char **group_start_date;
    char **group_deadline;
    char **personal_deadline;
};

struct dates_problem_data
{
    struct generic_section_config g META_ATTRIB((meta_hidden));

    ejintbool_t abstract;
    unsigned char *super;
    unsigned char *short_name;
    unsigned char *use_dates_of;
    time_t deadline;
    time_t start_date;
    char **date_penalty;
    char **group_start_date;
    char **group_deadline;
    char **personal_deadline;
    char *extid;

    struct dates_problem_data *use_dates_of_ref META_ATTRIB((meta_hidden));
    struct dates_problem_data *super_ref META_ATTRIB((meta_hidden));
};

struct dates_config
{
    struct generic_section_config *list;
    struct dates_global_data *global;
    struct dates_problem_data **aprobs;
    struct dates_problem_data **probs;
    int aprob_count;
    int prob_count;
};

struct dates_config *
dates_config_parse_cfg(
        const unsigned char *path,
        const unsigned char *main_path);
struct dates_config *
dates_config_free(struct dates_config *cfg);

#endif /* __DATES_CONFIG_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
