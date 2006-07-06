/* -*- mode: c -*- */
/* $Id*/

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

#include "config.h"
#include "settings.h"
#include "ej_limits.h"

#include "uldb_plugin.h"

/* plugin entry point */
struct uldb_plugin_iface uldb_mysql_plugin =
{
  sizeof (struct uldb_plugin_iface),
  ULDB_PLUGIN_IFACE_VERSION,
};

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
