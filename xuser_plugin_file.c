/* -*- mode: c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xuser_plugin.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

/* plugin state */
struct xuser_file_state
{
};

/* per-contest plugin state */
struct xuser_file_cnts_state
{
};

struct xuser_plugin_iface plugin_xuser_file =
{
    {
        {
            sizeof(struct xuser_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "xuser",
            "file",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        NULL, /* init */
        NULL, /* finish */
        NULL, /* prepare */
    },
    XUSER_PLUGIN_IFACE_VERSION,
};

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
