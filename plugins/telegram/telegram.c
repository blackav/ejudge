/* -*- mode: c -*- */

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

#include "ejudge/telegram.h"

#include "ejudge/xalloc.h"

#include <string.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

struct telegram_plugin_iface plugin_sn_telegram =
{
    { /* struct common_plugin_iface */
        { /* struct ejudge_plugin_iface */
            sizeof (struct telegram_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "sn",
            "telegram",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    TELEGRAM_PLUGIN_IFACE_VERSION,
};

struct telegram_plugin_data
{
    int dummy;
};

static struct common_plugin_data *
init_func(void)
{
    struct telegram_plugin_data *state = NULL;
    XCALLOC(state, 1);
    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;
  (void) state;

  return 0;
}


/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
