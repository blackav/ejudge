/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __RUN_PROPS_H__
#define __RUN_PROPS_H__

/* Copyright (C) 2024 Alexander Chernov <cher@ejudge.ru> */

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

struct run_properties
{
    unsigned char *start_cmd;   // the command (interpreter) for program
    unsigned char **start_args; // additional arguments, incl. the main file
    unsigned char is_archive;   // the executable file is actually an archive
};

struct cJSON;

struct run_properties *
run_properties_free(struct run_properties *p);

int
run_properties_parse_json_str(
        const unsigned char *str,
        struct run_properties **p_props,
        unsigned char **p_message);

int
run_properties_parse_json_file(
        const unsigned char *path,
        struct run_properties **p_props,
        unsigned char **p_message);

#endif /* __RUN_PROPS_H__ */

