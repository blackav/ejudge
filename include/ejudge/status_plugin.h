/* -*- c -*- */

#ifndef __STATUS_PLUGIN_H__
#define __STATUS_PLUGIN_H__

/* Copyright (C) 2019 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ejudge_plugin.h"
#include "ejudge/common_plugin.h"
#include "ejudge/ej_types.h"
#include "ejudge/ejudge_cfg.h"

#define STATUS_PLUGIN_IFACE_VERSION 1

struct common_loaded_plugin;
struct status_db_state
{
    const struct common_loaded_plugin *plugin;
};

struct prot_serve_status;

struct status_plugin_iface
{
    struct common_plugin_iface b;
    int status_version;

    struct status_db_state * (*open)(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);

    void (*close)(struct status_db_state *sds);

    int (*load)(
        struct status_db_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat);

    int (*save)(
        struct status_db_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat);

    void (*remove)(
        struct status_db_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global);
};

#endif /* __STATUS_PLUGIN_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
