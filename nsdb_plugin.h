/* -*- c -*- */
/* $Id$ */

#ifndef __NSDB_PLUGIN_H__
#define __NSDB_PLUGIN_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
#define NSDB_PLUGIN_IFACE_VERSION 1

struct nsdb_plugin_iface
{
  struct ejudge_plugin_iface b;
  int nsdb_version;

  // initialize the plugin
  void *(*init)(const struct ejudge_cfg *);
  // parse the configuration settings
  int (*parse)(void *, const struct ejudge_cfg *, struct xml_tree *);
  // open (initialize) the connection
  int (*open)(void *);
  // close the connection
  int (*close)(void *);
  // check the data and probably upgrade it
  int (*check)(void *);
  // initialize the data
  int (*create)(void *);
};

/* default plugin: compiled into new-server */
extern struct nsdb_plugin_iface nsdb_plugin_files;

#endif /* __NSDB_PLUGIN_H__ */
