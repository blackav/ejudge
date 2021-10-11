/* -*- c -*- */
#ifndef __TELEGRAM_H__
#define __TELEGRAM_H__

/* Copyright (C) 2016-2021 Alexander Chernov <cher@ejudge.ru> */

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

typedef void (*tg_command_handler_t)(int uid, int argc, char **argv, void *self);
typedef void (*tg_timer_handler_t)(void *self);

typedef void (*tg_set_command_handler_t)(void *set_self, const unsigned char *cmd, tg_command_handler_t handler, void *tg_self);
typedef void (*tg_set_timer_handler_t)(void *set_self, tg_timer_handler_t handler, void *tg_self);

#define TELEGRAM_PLUGIN_IFACE_VERSION 2

struct telegram_plugin_data;

struct telegram_plugin_iface
{
    struct common_plugin_iface b;
    int telegram_plugin_iface_version;

    void (*set_set_command_handler)(void *data, tg_set_command_handler_t setter, void *setter_self);
    void (*set_set_timer_handler)(void *data, tg_set_timer_handler_t setter, void *setter_self);
    int (*start)(void *data);
};

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
