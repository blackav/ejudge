/* -*- c -*- */
/* $Id$ */
#ifndef __LANG_CONFIG_VIS_H__
#define __LANG_CONFIG_VIS_H__

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "shellcfg_parse.h"

#include <stdlib.h>

struct lang_config_info
{
  struct lang_config_info *prev, *next;
  unsigned char *lang;
  unsigned char *config_arg;
  int enabled;
  int id;
  unsigned char *cfg_txt;
  size_t cfg_len;
  unsigned char *short_name;
  unsigned char *version;
  struct shellconfig *cfg;
};

struct lang_config_info *
lang_config_get_first(void);
struct lang_config_info *
lang_config_lookup(const unsigned char *lang);
void
lang_configure_screen(
        const unsigned char *script_dir,
        const unsigned char * const * script_in_dirs,
        const unsigned char *config_dir,
        const unsigned char *working_dir,
        unsigned char **keys,
        unsigned char **values,
        const unsigned char *header);
void
lang_configure_batch(
        const unsigned char *script_dir,
        const unsigned char * const * script_in_dirs,
        const unsigned char *config_dir,
        const unsigned char *working_dir,
        unsigned char **keys,
        unsigned char **values,
        FILE *log_f);
int
lang_config_menu(
        const unsigned char *script_dir,
        const unsigned char * const * script_in_dirs,
        const unsigned char *working_dir,
        const unsigned char *header,
        int utf8_mode,
        int *p_cur_item);

void
lang_config_get_sorted(
        int *p_num,
        struct lang_config_info ***p_langs);

void
lang_config_generate_compile_cfg(
        FILE *f,
        const unsigned char *prog,
        const unsigned char *compile_home_dir,
        int serialization_key,
        const unsigned char *lang_config_dir);

#endif /* __LANG_CONFIG_VIS_H__ */
