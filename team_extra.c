/* -*- c -*- */

/* Copyright (C) 2004-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_limits.h"
#include "ejudge/team_extra.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"
#include "ejudge/common_plugin.h"
#include "ejudge/xuser_plugin.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

struct team_extra *
team_extra_free(struct team_extra *te)
{
  if (te) {
    int j;
    struct team_warning *tw;

    for (j = 0; j < te->warn_u; j++) {
      if (!(tw = te->warns[j])) continue;
      xfree(tw->text);
      xfree(tw->comment);
      xfree(tw);
    }
    xfree(te->warns);
    xfree(te->clar_map);
    xfree(te->disq_comment);
    xfree(te->clar_uuids);
    xfree(te);
  }
  return NULL;
}

void
team_extra_extend_clar_map(struct team_extra *te, int clar_id)
{
  int new_size = te->clar_map_size;
  int new_alloc;
  unsigned long *new_map = 0;

  if (!new_size) new_size = 128;
  while (new_size <= clar_id) new_size *= 2;
  new_alloc = new_size / BPE;
  XCALLOC(new_map, new_alloc);
  if (te->clar_map_size > 0) {
    memcpy(new_map, te->clar_map, sizeof(new_map[0]) * te->clar_map_alloc);
    xfree(te->clar_map);
  }
  te->clar_map_size = new_size;
  te->clar_map_alloc = new_alloc;
  te->clar_map = new_map;
}

extern struct xuser_plugin_iface plugin_xuser_file;
struct xuser_cnts_state *
team_extra_open(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags)
{
  const struct common_loaded_plugin *loaded_plugin = NULL;
  const struct xuser_plugin_iface *iface = NULL;

  if (!plugin_register_builtin(&plugin_xuser_file.b, config)) {
    err("cannot register default plugin");
    return NULL;
  }

  if (!plugin_name) {
    if (global) plugin_name = global->xuser_plugin;
  }
  if (!plugin_name) plugin_name = "";

  if (!plugin_name[0] || !strcmp(plugin_name, "file")) {
    if (!(loaded_plugin = plugin_get("xuser", "file"))) {
      err("cannot load default plugin");
      return NULL;
    }
    iface = (struct xuser_plugin_iface*) loaded_plugin->iface;
    return iface->open(loaded_plugin->data, config, cnts, global, flags);
  }

  if ((loaded_plugin = plugin_get("xuser", plugin_name))) {
    iface = (struct xuser_plugin_iface*) loaded_plugin->iface;
    return iface->open(loaded_plugin->data, config, cnts, global, flags);
  }

  if (!config) {
    err("cannot load any plugin");
    return NULL;
  }

  const struct xml_tree *p = NULL;
  const struct ejudge_plugin *plg = NULL;
  for (p = config->plugin_list; p; p = p->right) {
    plg = (const struct ejudge_plugin*) p;
    if (plg->load_flag && !strcmp(plg->type, "xuser")
        && !strcmp(plg->name, plugin_name))
      break;
  }
  if (!p || !plg) {
    err("xuser plugin '%s' is not registered", plugin_name);
    return NULL;
  }

  loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
  if (!loaded_plugin) {
    err("cannot load plugin %s, %s", plg->type, plg->name);
    return NULL;
  }
  iface = (struct xuser_plugin_iface*) loaded_plugin->iface;
  return iface->open(loaded_plugin->data, config, cnts, global, flags);
}
