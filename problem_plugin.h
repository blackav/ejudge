/* -*- c -*- */
/* $Id$ */

#ifndef __PROBLEM_PLUGIN_H__
#define __PROBLEM_PLUGIN_H__

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge_plugin.h"
#include "ej_types.h"
#include "iterators.h"

struct ejudge_cfg;
struct xml_tree;

/* version of the plugin interface structure */
#define PROBLEM_PLUGIN_IFACE_VERSION 1

struct problem_plugin_iface
{
  struct ejudge_plugin_iface b;
  int problem_version;

  void *(*init)(void);
  void (*finalize)(void *);
};

#endif /* __PROBLEM_PLUGIN_H__ */
