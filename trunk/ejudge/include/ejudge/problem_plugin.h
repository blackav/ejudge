/* -*- c -*- */
/* $Id$ */

#ifndef __PROBLEM_PLUGIN_H__
#define __PROBLEM_PLUGIN_H__

/* Copyright (C) 2007-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ejudge_plugin.h"
#include "ejudge/ej_types.h"
#include "ejudge/iterators.h"

#include <stdio.h>

struct ejudge_cfg;
struct xml_tree;

/* version of the plugin interface structure */
#define PROBLEM_PLUGIN_IFACE_VERSION 2

struct http_request_info;
struct contest_desc;
struct contest_extra;

struct problem_plugin_iface
{
  struct ejudge_plugin_iface b;
  int problem_version;

  const size_t *sizes_array;
  size_t sizes_array_size;

  void *(*init)(void);
  void (*finalize)(void *);
  unsigned char * (*parse_form)(void *, 
                                FILE *flog,
                                struct http_request_info *phr,
                                const struct contest_desc *cnts,
                                struct contest_extra *extra);
  unsigned char * (*unparse_form)(void *, 
                                  struct http_request_info *phr,
                                  const struct contest_desc *cnts,
                                  struct contest_extra *extra,
                                  const unsigned char *text);
};

#endif /* __PROBLEM_PLUGIN_H__ */
