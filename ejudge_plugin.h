/* -*- c -*- */
/* $Id$ */

#ifndef __EJUDGE_PLUGIN_H__
#define __EJUDGE_PLUGIN_H__

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

#include <stdlib.h>

/* version of the plugin interface structure */
#define EJUDGE_PLUGIN_IFACE_VERSION 1

struct ejudge_plugin_iface
{
  size_t size;                  /* size of the structure */
  int version;                  /* the version of the interface */
  const unsigned char *type;    /* type of the plugin */
  const unsigned char *name;    /* name of the plugin */
};

int plugin_set_directory(const unsigned char *dir);
struct ejudge_plugin_iface *
plugin_load(const unsigned char *path,
            const unsigned char *type, const unsigned char *name);
void plugin_unload(struct ejudge_plugin_iface *);

#endif /* __EJUDGE_PLUGIN_H__ */
