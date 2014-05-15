/* -*- c -*- */
/* $Id$ */

#ifndef __COMMON_PLUGIN_H__
#define __COMMON_PLUGIN_H__

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ejudge_cfg.h"

#define COMMON_PLUGIN_IFACE_VERSION 1

struct common_plugin_data;

struct common_plugin_iface
{
  struct ejudge_plugin_iface b;
  int common_version;

  // initialize the plugin
  struct common_plugin_data *(*init)(void);
  // destroy the plugin data
  int (*finish)(struct common_plugin_data *);
  // parse the plugin configuration
  int (*prepare)(struct common_plugin_data *, const struct ejudge_cfg *,
                 struct xml_tree *);
};

struct common_loaded_plugin
{
  unsigned char *type;
  unsigned char *name;
  struct common_plugin_iface *iface;
  struct common_plugin_data  *data;
};

const struct common_loaded_plugin *
plugin_register_builtin(
        struct common_plugin_iface *iface,
        const struct ejudge_cfg *config);
const struct common_loaded_plugin *
plugin_load_external(
        const unsigned char *path,
        const unsigned char *type,
        const unsigned char *name,
        const struct ejudge_cfg *config);
const struct common_loaded_plugin *
plugin_get(
        const unsigned char *type,
        const unsigned char *name);

#endif /* __COMMON_PLUGIN_H__ */
