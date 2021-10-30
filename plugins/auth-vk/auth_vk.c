/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/config.h"
#include "ejudge/auth_plugin.h"
#include "ejudge/auth_base_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#else
#error curl required
#endif

#include <string.h>

static struct common_plugin_data*
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);
static int
open_func(void *data);
static int
check_func(void *data);
static int
start_thread_func(void *data);
static void
set_set_command_handler_func(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self);
static void
set_send_job_handler_func(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self);

struct auth_plugin_iface plugin_auth_vk =
{
    {
        {
            sizeof (struct auth_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "vk",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AUTH_PLUGIN_IFACE_VERSION,
    open_func,
    check_func,
    start_thread_func,
    set_set_command_handler_func,
    set_send_job_handler_func,
};

struct auth_vk_state
{
    struct auth_base_plugin_iface *bi;
    struct auth_base_plugin_state *bd;

    // curl for auth endpoint discovery
    CURL *curl;

    unsigned char *client_id;
    unsigned char *client_secret;
    unsigned char *redirect_uri;

    auth_set_command_handler_t set_command_handler_func;
    void *set_command_handler_data;

    auth_send_job_handler_t send_job_handler_func;
    void *send_job_handler_data;
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_vk_state *state;

    XCALLOC(state, 1);

    state->curl = curl_easy_init();

    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct auth_vk_state *state = (struct auth_vk_state*) data;
    const struct xml_parse_spec *spec = ejudge_cfg_get_spec();

    // load auth base plugin
    const struct common_loaded_plugin *mplg;
    if (!(mplg = plugin_load_external(0, "auth", "base", config))) {
        err("cannot load auth_base plugin");
        return -1;
    }
    state->bi = (struct auth_base_plugin_iface *) mplg->iface;
    state->bd = (struct auth_base_plugin_state *) mplg->data;

    // handle config section
    ASSERT(tree->tag == spec->default_elem);
    ASSERT(!strcmp(tree->name[0], "config"));

    for (struct xml_tree *p = tree->first_down; p; p = p->right) {
        ASSERT(p->tag == spec->default_elem);

        if (!strcmp(p->name[0], "client_id")) {
            if (xml_leaf_elem(p, &state->client_id, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "client_secret")) {
            if (xml_leaf_elem(p, &state->client_secret, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "redirect_uri")) {
            if (xml_leaf_elem(p, &state->redirect_uri, 1, 0) < 0) return -1;
        }
    }

    return 0;
}

static int
open_func(void *data)
{
    struct auth_vk_state *state = (struct auth_vk_state*) data;

    return state->bi->open(state->bd);
}

static int
check_func(void *data)
{
    struct auth_vk_state *state = (struct auth_vk_state*) data;

    return state->bi->check(state->bd);
}

static void
set_set_command_handler_func(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self)
{
    struct auth_vk_state *state = (struct auth_vk_state*) data;

    state->set_command_handler_func = setter;
    state->set_command_handler_data = setter_self;
}

static void
set_send_job_handler_func(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self)
{
    struct auth_vk_state *state = (struct auth_vk_state*) data;

    state->send_job_handler_func = handler;
    state->send_job_handler_data = handler_self;
}

static void
queue_packet_handler_auth_vk(int uid, int argc, char **argv, void *user)
{
    struct auth_vk_state *state = (struct auth_vk_state*) user;
    state->bi->enqueue_action(state->bd, NULL, /*packet_handler_auth_vk,*/
                              uid, argc, argv, user);
}

static int
start_thread_func(void *data)
{
    struct auth_vk_state *state = (struct auth_vk_state*) data;

    if (!state->set_command_handler_func) {
        return 0;
    }

    state->set_command_handler_func(state->set_command_handler_data,
                                    "auth_vk",
                                    queue_packet_handler_auth_vk,
                                    data);

    return state->bi->start_thread(state->bd);
}
