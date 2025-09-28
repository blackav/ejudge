/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __EJUDGE_PROBLEM_IMPL_H__
#define __EJUDGE_PROBLEM_IMPL_H__

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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

struct problem_state;
struct ppxml_problem;

struct problem_state *
ejudge_problem_new_state();

void
ejudge_problem_set_ppxml(
        struct problem_state *ps,
        struct ppxml_problem *ppxml,
        const unsigned char *problem_xml_file);

int
ejudge_problem_read_full_file(
        FILE *log_f,
        const unsigned char *path,
        unsigned char **p_str,
        size_t *p_size);

int
ejudge_problem_collect_dependencies(
        FILE *log_f,
        struct problem_state *ps,
        int no_norm_check);

int
ejudge_problem_build(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_clean(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_print_makefile(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_print_topological(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_print_build_info(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_print_hash(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_print_source_files(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_normalize_tests(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

int
ejudge_problem_create_zip_tool(
        FILE *log_f,
        struct problem_state *ps,
        char *args[]);

#endif /* __EJUDGE_PROBLEM_IMPL_H__ */
