/* -*- mode: c -*- */
/* $Id$ */

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

#include "nsdb_plugin.h"
#include "expat_iface.h"
#include "xml_utils.h"
#include "errlog.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <string.h>

static void *init_func(const struct ejudge_cfg *config);
static int parse_func(void *data, const struct ejudge_cfg *config, struct xml_tree *tree);
static int open_func(void *data);
static int close_func(void *data);
static int check_func(void *data);
static int create_func(void *data);

struct nsdb_plugin_iface nsdb_plugin_files =
{
  {
    sizeof (struct nsdb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "userdb",
    "nsdb_xml",
  },

  NSDB_PLUGIN_IFACE_VERSION,

  init_func,
  parse_func,
  open_func,
  close_func,
  check_func,
  create_func,
};

struct nsdb_files_state
{
  unsigned char *data_dir;
};

static void *
init_func(const struct ejudge_cfg *config)
{
  struct nsdb_files_state *state;

  XCALLOC(state, 1);
  return (void*) state;
}

static int
parse_func(void *data, const struct ejudge_cfg *config, struct xml_tree *tree)
{
  struct nsdb_files_state *state = (struct nsdb_files_state*) data;
  struct xml_tree *p;

  if (!tree) {
    err("configuration for files plugin is not specified");
    return -1;
  }
  ASSERT(tree->tag == xml_err_spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text(tree) < 0) return -1;
  if (tree->first) return xml_err_attrs(tree);

  for (p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == xml_err_spec->default_elem);
    if (!strcmp(p->name[0], "data_dir")) {
      if (xml_leaf_elem(p, &state->data_dir, 1, 0) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!state->data_dir) return xml_err_elem_undefined_s(tree, "data_dir");

  return 0;
}

static int
open_func(void *data)
{
  return 0;
}

static int
close_func(void *data)
{
  // TODO: implement
  return 0;
}

static int
check_func(void *data)
{
  // TODO: implement
  return 0;
}

static int
create_func(void *data)
{
  // TODO: implement
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
