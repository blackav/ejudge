/* -*- c -*- */
/* $Id$ */
#ifndef __SHELLCONFIG_H__
#define __SHELLCONFIG_H__

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

#include <stdio.h>
#include <stdlib.h>

struct shellconfig
{
  size_t size;
  size_t usage;
  unsigned char **names;
  size_t *lengths;
  unsigned char **values;
};
typedef struct shellconfig *shellconfig_t;

shellconfig_t shellconfig_parse(FILE *log_f, FILE *f,const unsigned char *path);
shellconfig_t shellconfig_free(shellconfig_t);
int shellconfig_find_by_prefix(shellconfig_t, const unsigned char *,
                               size_t);
const unsigned char *
shellconfig_get_name_by_num(
	shellconfig_t cfg,
        int num);
const unsigned char *
shellconfig_get_value_by_num(
	shellconfig_t cfg,
        int num);

#endif /* __SHELLCONFIG_H__ */
