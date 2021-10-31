/* -*- mode: c -*- */
/* $Id$ */

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

#include "ejudge/common_plugin.h"
#include "ejudge/errlog.h"

#include "ejudge/xalloc.h"

#include <string.h>

static int plugins_num = 0;
static int plugins_size = 0;
static struct common_loaded_plugin *plugins = 0;

const struct common_loaded_plugin *
plugin_register_builtin(
        struct common_plugin_iface *iface,
        const struct ejudge_cfg *config)
{
  int i;
  struct common_plugin_data *data;
  const unsigned char *fname = __FUNCTION__;
  struct xml_tree *pcfg;

  if (iface->common_version != COMMON_PLUGIN_IFACE_VERSION) {
    err("%s: incompatible version of common plugin", fname);
    return NULL;
  }
  if (iface->b.version != EJUDGE_PLUGIN_IFACE_VERSION) {
    err("%s: incompatible version of base plugin", fname);
    return NULL;
  }
  if (iface->b.size < sizeof(*iface)) {
    err("%s: invalid size of common plugin", fname);
    return NULL;
  }

  // check that the plugin is already loaded
  for (i = 0; i < plugins_num; ++i) {
    if (!strcmp(plugins[i].type, iface->b.type)
        && !strcmp(plugins[i].name, iface->b.name)) {
      if (plugins[i].iface != iface) {
        err("%s: iface mismatch", fname);
        return NULL;
      }
      return &plugins[i];
    }
  }

  // create the plugin
  if (plugins_num == plugins_size) {
    if (!plugins_size) plugins_size = 8;
    plugins_size *= 2;
    XREALLOC(plugins, plugins_size);
  }

  pcfg = ejudge_cfg_get_plugin_config(config, iface->b.type, iface->b.name);
  if (!(data = iface->init())) {
    err("%s: init failed for %s, %s", fname, iface->b.type, iface->b.name);
    return NULL;
  }
  if (iface->prepare(data, config, pcfg) < 0) {
    err("%s: prepare failed for %s, %s", fname, iface->b.type, iface->b.name);
    return NULL;
  }

  plugins[plugins_num].type = xstrdup(iface->b.type);
  plugins[plugins_num].name = xstrdup(iface->b.name);
  plugins[plugins_num].iface = iface;
  plugins[plugins_num].data = data;

  return &plugins[plugins_num++];
}

const struct common_loaded_plugin *
plugin_load_external(
        const unsigned char *path,
        const unsigned char *type,
        const unsigned char *name,
        const struct ejudge_cfg *config)
{
  int i;
  struct common_plugin_data *data;
  const unsigned char *fname = __FUNCTION__;
  struct ejudge_plugin_iface *base_iface = 0;
  struct common_plugin_iface *common_iface = 0;
  struct xml_tree *pcfg;

  for (i = 0; i < plugins_num; ++i)
    if (!strcmp(plugins[i].type, type) && !strcmp(plugins[i].name, name))
      return &plugins[i];

  // create the plugin
  if (plugins_num == plugins_size) {
    if (!plugins_size) plugins_size = 8;
    plugins_size *= 2;
    XREALLOC(plugins, plugins_size);
  }

  plugin_set_directory(config->plugin_dir);
  if (!(base_iface = plugin_load(path, type, name))) {
    err("%s: cannot load plugin %s, %s", fname, type, name);
    return NULL;
  }
  common_iface = (struct common_plugin_iface*) base_iface;
  if (base_iface->size < sizeof(*common_iface)) {
    err("%s: plugin %s, %s size mismatch", fname, type, name);
    return NULL;
  }
  if (common_iface->common_version != COMMON_PLUGIN_IFACE_VERSION) {
    err("%s: plugin %s, %s version mismatch", fname, type, name);
    return NULL;
  }

  pcfg = ejudge_cfg_get_plugin_config(config, type, name);
  if (!pcfg) {
    err("%s: plugin configuration not found for %s, %s", fname, type, name);
    return NULL;
  }
  if (!(data = common_iface->init())) {
    err("%s: init failed for %s, %s", fname, type, name);
    return NULL;
  }
  if (common_iface->prepare(data, config, pcfg) < 0) {
    err("%s: prepare failed for %s, %s", fname, type, name);
    common_iface->finish(data);
    return NULL;
  }

  plugins[plugins_num].type = xstrdup(type);
  plugins[plugins_num].name = xstrdup(name);
  plugins[plugins_num].iface = common_iface;
  plugins[plugins_num].data = data;

  return &plugins[plugins_num++];
}

const struct common_loaded_plugin *
plugin_get(
        const unsigned char *type,
        const unsigned char *name)
{
  int i;

  for (i = 0; i < plugins_num; ++i)
    if (!strcmp(plugins[i].type, type) && !strcmp(plugins[i].name, name))
      return &plugins[i];
  return NULL;
}
