/* -*- c -*- */
/* $Id$ */
#ifndef __PARSECFG_H__
#define __PARSECFG_H__

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

struct generic_section_config
{
  struct generic_section_config *next;
  char                           name[32];
  int                            data[0];
};

struct config_parse_info
{
  char          *name;
  char          *type;
  unsigned long  offset;
  unsigned long  size;
};

struct config_section_info
{
  char                     *name;
  unsigned long             size;
  struct config_parse_info *info;
  int                      *pcounter;
  void (*init_func)(struct generic_section_config *);
};

enum
{
  PARSECFG_T_VOID = 0,
  PARSECFG_T_LONG,
  PARSECFG_T_STRING,
};

typedef union cfg_cond_value
{
  int tag;
  struct
  {
    int tag;
    long long val;
  } l;
  struct
  {
    int tag;
    unsigned char *str;
  } s;
} cfg_cond_value_t;

typedef struct cfg_cond_var
{
  unsigned char *name;
  cfg_cond_value_t val;
} cfg_cond_var_t;

struct generic_section_config *parse_param(char const *path,
                                           void *f, /* actually, FILE * */
                                           struct config_section_info *,
                                           int quiet_flag,
                                           int nvar,
                                           cfg_cond_var_t *pvar);
struct generic_section_config *param_make_global_section(struct config_section_info *params);

int    sarray_len(char **);
char **sarray_merge_pf(char **, char **);
char **sarray_free(char **);
char **sarray_merge_arr(int, char ***);

#endif /* __PARSECFG_H__ */
