/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __AUTH_BASE_PLUGIN_H__
#define __AUTH_BASE_PLUGIN_H__

/* Copyright (C) 2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"

#define AUTH_BASE_PLUGIN_IFACE_VERSION 1

struct auth_base_plugin_iface
{
    struct common_plugin_iface b;
    int auth_base_version;

    int (*open)(void *);
    int (*check)(void *);
};

struct auth_base_plugin_state;

#endif /* __AUTH_BASE_PLUGIN_H__ */
