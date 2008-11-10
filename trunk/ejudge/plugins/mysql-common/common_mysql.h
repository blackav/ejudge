/* -*- c -*- */
/* $Id$ */

#ifndef __COMMON_MYSQL_H__
#define __COMMON_MYSQL_H__

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

#include "ejudge_plugin.h"
#include "common_plugin.h"

#define COMMON_MYSQL_PLUGIN_IFACE_VERSION 1

struct common_mysql_state;

struct common_mysql_iface
{
  struct common_plugin_iface b;
  int common_mysql_version;
};

#endif /* __COMMON_MYSQL_H__ */
