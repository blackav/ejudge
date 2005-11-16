/* -*- c -*- */
/* $Id$ */
#ifndef __PARSECFG_H__
#define __PARSECFG_H__

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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
  void (*free_func)(struct generic_section_config *);
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
                                           FILE *f,
                                           struct config_section_info *,
                                           int quiet_flag,
                                           int nvar,
                                           cfg_cond_var_t *pvar,
                                           int *p_cond_count);
struct generic_section_config *param_make_global_section(struct config_section_info *params);

struct generic_section_config *param_free(struct generic_section_config *,
                                          const struct config_section_info *);

struct generic_section_config *param_merge(struct generic_section_config *s1,
                                           struct generic_section_config *s2);

struct generic_section_config *param_alloc_section(const unsigned char *name,
                                                   const struct config_section_info *);

int    sarray_len(char **);
char **sarray_merge_pf(char **, char **);
char **sarray_free(char **);
char **sarray_merge_arr(int, char ***);
char  *sarray_unparse(char **);
char  *sarray_unparse_2(char **a);
int    sarray_parse(const unsigned char *, char ***);
int    sarray_parse_2(const unsigned char *, char ***);

#endif /* __PARSECFG_H__ */
