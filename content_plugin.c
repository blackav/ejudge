/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/content_plugin.h"

#define DEFAULT_CONTENT_PLUGIN "none"

#define CONTENT_PLUGIN_TYPE "content"

struct content_loaded_plugin *
content_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name)
{
    return NULL;
}

struct content_loaded_plugin *
content_plugin_destroy(struct content_loaded_plugin *plugin)
{
    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
