/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/notify_plugin.h"
#include "ejudge/errlog.h"

#include <string.h>

struct notify_plugin_data *
notify_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name)
{
    return NULL;
}
