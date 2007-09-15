/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "settings.h"
#include "ej_limits.h"
#include "ejudge_plugin.h"
#include "errlog.h"
#include "pathutl.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

struct plugin_info
{
  unsigned char *type;
  unsigned char *name;
  void *handle;
  struct ejudge_plugin_iface *iface;
};

struct plugin_arr
{
  int a, u;
  struct plugin_info **v;
};

static const unsigned char *plugin_dir;
static struct plugin_arr plugins;

int
plugin_set_directory(const unsigned char *dir)
{
  struct stat stbuf;

  if (!dir || !*dir) {
    err("plugin directory is not set");
    return -1;
  }
  if (stat(dir, &stbuf) < 0) {
    err("plugin directory `%s' does not exist", dir);
    return -1;
  }
  if (!S_ISDIR(stbuf.st_mode)) {
    err("plugin directory `%s' is not a directory", dir);
    return -1;
  }

  plugin_dir = xstrdup(dir);
  return 0;
}

struct ejudge_plugin_iface *
plugin_load(const unsigned char *path,
            const unsigned char *type,
            const unsigned char *name)
{
  int i;
  path_t plugin_path;
  path_t plugin_desc;
  void *hnd;
  struct ejudge_plugin_iface *plg;
  unsigned char *errmsg;
  struct plugin_info *pinfo;

  if (!plugin_dir) {
    err("plugin directory is not set");
    return NULL;
  }

  for (i = 0; i < plugins.u; i++) {
    if (!strcmp(plugins.v[i]->type, type)
        && !strcmp(plugins.v[i]->name, name))
      break;
  }

  if (i < plugins.u) return plugins.v[i]->iface;

  if (path) {
    snprintf(plugin_path, sizeof(plugin_path), "%s", path);
  } else {
    snprintf(plugin_path, sizeof(plugin_path), "%s/%s_%s.so",
             plugin_dir, type, name);
  }

  if (!(hnd = dlopen(plugin_path, RTLD_NOW | RTLD_GLOBAL))) {
    err("cannot load `%s': %s", plugin_path, dlerror());
    return NULL;
  }

  snprintf(plugin_desc, sizeof(plugin_desc), "plugin_%s_%s", type, name);
  if (!(plg = (struct ejudge_plugin_iface*) dlsym(hnd, plugin_desc))) {
    errmsg = dlerror();
    if (!errmsg) errmsg = "unknown error";
    err("no plugin entry point: %s", errmsg);
    dlclose(hnd);
    return NULL;
  }

  if (plg->size < sizeof(*plg)) {
    err("incompatible plugin: descriptor size too small");
    dlclose(hnd);
    return NULL;
  }
  if (plg->version != EJUDGE_PLUGIN_IFACE_VERSION) {
    err("incompatible plugin: version mismatch");
    dlclose(hnd);
    return NULL;
  }
  if (strcmp(type, plg->type) != 0) {
    err("incompatible plugin: type mismatch");
    dlclose(hnd);
    return NULL;
  }
  if (strcmp(name, plg->name) != 0) {
    err("incompatible plugin: name mismatch");
    dlclose(hnd);
    return NULL;
  }

  XCALLOC(pinfo, 1);
  XEXPAND2(plugins);

  plugins.v[plugins.u++] = pinfo;
  pinfo->type = xstrdup(type);
  pinfo->name = xstrdup(name);
  pinfo->handle = hnd;
  pinfo->iface = plg;
  return plg;
}

void
plugin_unload(struct ejudge_plugin_iface *plugin)
{
  int i;

  for (i = 0; i < plugins.u; i++)
    if (plugins.v[i]->iface == plugin)
      break;
  if (i == plugins.u) return;

  xfree(plugins.v[i]->type);
  xfree(plugins.v[i]->name);
  dlclose(plugins.v[i]->handle);
  xfree(plugins.v[i]);
  for (i++; i < plugins.u; i++)
    plugins.v[i - 1] = plugins.v[i];
  plugins.v[i - 1] = 0;
  plugins.u--;
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
