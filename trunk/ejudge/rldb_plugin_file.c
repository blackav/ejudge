/* -*- mode: c -*- */
/* $Id$ */

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

#include "rldb_plugin.h"
#include "ejudge_cfg.h"

static struct rldb_plugin_data *
init_func(const struct ejudge_cfg*);
static int
close_func(struct rldb_plugin_data *);

struct rldb_plugin_iface rldb_plugin_xml =
{
  {
    sizeof (struct rldb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "rldb",
    "file",
  },

  RLDB_PLUGIN_IFACE_VERSION,

  init_func,
  close_func,
};

static struct rldb_plugin_data *
init_func(const struct ejudge_cfg *config)
{
  return 0;
}

static int
close_func(struct rldb_plugin_data *data)
{
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
