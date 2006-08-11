/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include "uldb_plugin.h"

#include <reuse/xalloc.h>

static void *init_func(const struct ejudge_cfg *);
static int parse_func(const struct ejudge_cfg *,struct xml_tree *, void *);

struct uldb_plugin_iface uldb_plugin_xml =
{
  {
    sizeof (struct uldb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "userdb",
    "uldb_xml",
  },

  ULDB_PLUGIN_IFACE_VERSION,

  init_func,
  parse_func,
};

struct uldb_xml_state
{
  int dummy;
};

static void *
init_func(const struct ejudge_cfg *ej_cfg)
{
  struct uldb_xml_state *state;

  XCALLOC(state, 1);
  return (void*) state;
}

// do nothing
static int
parse_func(const struct ejudge_cfg *ej_cfg,struct xml_tree *t, void *data)
{
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
