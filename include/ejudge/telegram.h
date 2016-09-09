/* -*- c -*- */
#ifndef __TELEGRAM_H__
#define __TELEGRAM_H__

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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

#define TELEGRAM_PLUGIN_IFACE_VERSION 1

struct telegram_plugin_data;

struct telegram_plugin_iface
{
    struct common_plugin_iface b;
    int telegram_plugin_iface_version;
};

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
