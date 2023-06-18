/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __SUBMIT_PLUGIN_H__
#define __SUBMIT_PLUGIN_H__

/* Copyright (C) 2022-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_uuid.h"
#include "ejudge/mixed_id.h"

#include <stdio.h>

#define SUBMIT_PLUGIN_IFACE_VERSION 1

struct submit_entry
{
    ej_uuid_t     uuid;         /* submit own uuid */
    ej_uuid_t     prob_uuid;    /* problem uuid */
    ej_uuid_t     judge_uuid;   /* judge uuid */
    ej_mixed_id_t ext_user;     /* external user ID */
    ej_mixed_id_t notify_queue; /* notification queue ID */
    int64_t       serial_id;
    int64_t       source_id;
    int64_t       input_id;
    int64_t       protocol_id;
    int64_t       source_size;
    int64_t       input_size;
    int64_t       create_time_us;
    int64_t       last_status_change_time_us;
    ej_ip_t       ip;           /* ip address */
    int           contest_id;
    int           user_id;
    int           prob_id;
    int           variant;
    int           lang_id;
    unsigned char status;
    signed char   locale_id;
    unsigned char ssl_flag;
    signed char   eoln_type;
    unsigned char ext_user_kind;
    unsigned char notify_driver;
    unsigned char notify_kind;
};

struct submit_totals
{
    int64_t count;
    int64_t source_size;
    int64_t input_size;
};

// the plugin state
struct submit_plugin_data
{
    struct common_plugin_data b;
};

struct submit_plugin_iface;

// the contest-specific plugin state
struct submit_cnts_plugin_data
{
    struct submit_plugin_iface *vt;
};

struct ejudge_cfg;
struct contest_desc;
struct section_global_data;
struct serve_state;

enum
{
    SUBMIT_FIELD_STATUS = 1,
    SUBMIT_FIELD_PROTOCOL_ID = 2,
    SUBMIT_FIELD_JUDGE_UUID = 4,
};

struct submit_plugin_iface
{
    struct common_plugin_iface b;
    int submit_version;

    struct submit_cnts_plugin_data * (*open)(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct serve_state *state,
        int flags);
    struct submit_cnts_plugin_data * (*close)(
        struct submit_cnts_plugin_data *data);
    int (*insert)(
        struct submit_cnts_plugin_data *data,
        struct submit_entry *pse);
    int (*change_status)(
        struct submit_cnts_plugin_data *data,
        int64_t submit_id,
        unsigned mask,
        int status,
        int64_t protocol_id,
        const ej_uuid_t *p_judge_uuid,
        struct submit_entry *p_se);
    int (*fetch)(
        struct submit_cnts_plugin_data *data,
        int64_t submit_id,
        struct submit_entry *pse);
    int (*fetch_for_user)(
        struct submit_cnts_plugin_data *data,
        int user_id,
        int limit,
        int start,
        size_t *p_count,
        struct submit_entry **p_ses);
    int (*fetch_totals)(
        struct submit_cnts_plugin_data *data,
        int user_id,
        struct submit_totals *p_totals);
};

struct submit_cnts_plugin_data *
submit_plugin_open(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct serve_state *state,
        const unsigned char *plugin_name,
        int flags);

#endif /* __SUBMIT_PLUGIN_H__ */
