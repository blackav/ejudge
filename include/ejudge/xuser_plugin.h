/* -*- c -*- */

#ifndef __XUSER_PLUGIN_H__
#define __XUSER_PLUGIN_H__

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

#include "ejudge/ejudge_plugin.h"
#include "ejudge/common_plugin.h"
#include "ejudge/ej_types.h"
#include "ejudge/iterators.h"
#include "ejudge/ejudge_cfg.h"

/* version of the plugin interface structure */
#define XUSER_PLUGIN_IFACE_VERSION 1

struct ejudge_cfg;
struct contest_desc;
struct section_global_data;
struct xuser_cnts_state;
struct team_extra;

struct xuser_team_extras
{
    struct xuser_team_extras *(*free)(struct xuser_team_extras *e);
    const struct team_extra *(*get)(struct xuser_team_extras *e, int user_id);
};

struct xuser_plugin_iface
{
    struct common_plugin_iface b;
    int xuser_version;

    struct xuser_cnts_state * (*open)(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
    struct xuser_cnts_state * (*close)(
        struct xuser_cnts_state *data);
    const struct team_extra * (*get_entry)(
        struct xuser_cnts_state *data,
        int user_id);
    int (*get_clar_status)(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid);
    int (*set_clar_status)(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid);
    void (*flush)(
        struct xuser_cnts_state *data);
    int (*append_warning)(
        struct xuser_cnts_state *data,
        int user_id,
        int issuer_id,
        const ej_ip_t *issuer_ip,
        time_t issue_date,
        const unsigned char *txt,
        const unsigned char *cmt);
    int (*set_status)(
        struct xuser_cnts_state *data,
        int user_id,
        int status);
    int (*set_disq_comment)(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment);
    int (*get_run_fields)(
        struct xuser_cnts_state *data,
        int user_id);
    int (*set_run_fields)(
        struct xuser_cnts_state *data,
        int user_id,
        int run_fields);
    int (*count_read_clars)(
        struct xuser_cnts_state *data,
        int user_id);
    struct xuser_team_extras * (*get_entries)(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids);
};

struct xuser_cnts_state
{
    struct xuser_plugin_iface *vt;
};

#endif /* __CLDB_PLUGIN_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
