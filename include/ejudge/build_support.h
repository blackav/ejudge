/* -*- c -*- */
/* $Id$ */
#ifndef __BUILD_SUPPORT_H__
#define __BUILD_SUPPORT_H__

/* Copyright (C) 2012 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>

// supported languages
enum
{
  LANG_C = 1,
  LANG_CPP = 2,
  LANG_JAVA = 4,
  LANG_FPC = 8,
  LANG_DCC = 16,
  LANG_PY = 32,
  LANG_PL = 64,
  LANG_SH = 128,
  LANG_KUM = 256,
  LANG_OTHER = 0x200,
};

struct ejudge_cfg;
struct serve_state;
struct sid_state;
struct section_global_data;
struct section_problem_data;
struct contest_desc;

const unsigned char *
build_get_source_suffix(int mask);
unsigned long
build_find_suffix(const unsigned char *str);
unsigned long
build_guess_language_by_cmd(unsigned char *path, int *p_count);
unsigned long
build_guess_language_by_src(const unsigned char *src);

unsigned char *
build_get_compiler_script(
        FILE *log_f,
        const struct ejudge_cfg *config,
        const unsigned char *script_dir_default,
        const unsigned char *lang_short_name);

unsigned char *
build_get_compiler_path(
        FILE *log_f,
        const struct ejudge_cfg *config,
        const unsigned char *script_dir_default,
        const unsigned char *lang_short_name);

const unsigned char *
build_replace_cmd_suffix(
        unsigned char *buf,
        int size,
        const unsigned char *cmd,
        const unsigned char *suffix);

int
build_prepare_test_file_names(
        FILE *log_f,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant,
        const unsigned char *pat_prefix,
        int buf_size,
        unsigned char *test_dir,
        unsigned char *test_pat,
        unsigned char *corr_pat,
        unsigned char *info_pat,
        unsigned char *tgz_pat,
        unsigned char *tgzdir_pat);

int
build_generate_makefile(
        FILE  *log_f,
        const struct ejudge_cfg *ejudge_config,
        const struct contest_desc *cnts,
        struct serve_state *cs,
        struct sid_state *sstate,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant);

#endif /* __BUILD_SUPPORT_H__ */
