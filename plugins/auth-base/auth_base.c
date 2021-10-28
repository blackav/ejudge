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
#include "ejudge/auth_base_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <pthread.h>
#include <string.h>
#include <signal.h>

struct auth_base_queue_item
{
    void (*handler)(int uid, int argc, char **argv, void *user);
    int uid;
    int argc;
    char **argv;
    void *user;
};

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
start_thread_func(void *data);
static void
enqueue_action_func(
        void *data,
        void (*handler)(int uid, int argc, char **argv, void *user),
        int uid,
        int argc,
        char **argv,
        void *user);

struct auth_base_plugin_iface plugin_auth_base =
{
    {
        {
            sizeof (struct auth_base_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "base",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AUTH_BASE_PLUGIN_IFACE_VERSION,
    open_func,
    NULL, // check_func
    start_thread_func,
    enqueue_action_func,
};

enum { QUEUE_SIZE = 64 };

struct auth_base_plugin_state
{
    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    pthread_t worker_thread;
    _Atomic _Bool worker_thread_finish_request;

    pthread_mutex_t q_m;
    pthread_cond_t  q_c;
    int q_first;
    int q_len;
    struct auth_base_queue_item queue[QUEUE_SIZE];
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_base_plugin_state *state;

    XCALLOC(state, 1);

    pthread_mutex_init(&state->q_m, NULL);
    pthread_cond_init(&state->q_c, NULL);

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
    const struct common_loaded_plugin *mplg;
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }

    struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

static int
open_func(void *data)
{
    struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;

    if (state->mi->connect(state->md) < 0)
        return -1;

    return 0;
}

static void
enqueue_action_func(
        void *data,
        void (*handler)(int uid, int argc, char **argv, void *user),
        int uid,
        int argc,
        char **argv,
        void *user)
{
    struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;

    pthread_mutex_lock(&state->q_m);
    if (state->q_len == QUEUE_SIZE) {
        err("telegram_plugin: request queue overflow, request dropped");
        goto done;
    }
    struct auth_base_queue_item *item = &state->queue[(state->q_first + state->q_len++) % QUEUE_SIZE];
    memset(item, 0, sizeof(*item));
    item->handler = handler;
    item->uid = uid;
    item->argc = argc;
    item->argv = calloc(argc + 1, sizeof(item->argv[0]));
    for (int i = 0; i < argc; ++i) {
        item->argv[i] = strdup(argv[i]);
    }
    item->user = user;
    if (state->q_len == 1)
        pthread_cond_signal(&state->q_c);

done:
    pthread_mutex_unlock(&state->q_m);
}

static void *
thread_func(void *data)
{
    struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;

    sigset_t ss;
    sigfillset(&ss);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);

    while (!state->worker_thread_finish_request) {
        pthread_mutex_lock(&state->q_m);
        while (state->q_len == 0 && !state->worker_thread_finish_request) {
            pthread_cond_wait(&state->q_c, &state->q_m);
        }
        if (state->worker_thread_finish_request) {
            pthread_mutex_unlock(&state->q_m);
            break;
        }
        // this is local copy of the queue item
        struct auth_base_queue_item item = state->queue[state->q_first];
        memset(&state->queue[state->q_first], 0, sizeof(item));
        state->q_first = (state->q_first + 1) % QUEUE_SIZE;
        --state->q_len;
        pthread_mutex_unlock(&state->q_m);

        item.handler(item.uid, item.argc, item.argv, item.user);

        for (int i = 0; i < item.argc; ++i) {
            free(item.argv[i]);
        }
        free(item.argv);
    }
    return NULL;
}

static int
start_thread_func(void *data)
{
    struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;

    int r = pthread_create(&state->worker_thread, NULL, thread_func, state);
    if (r) {
        err("auth_google: cannot create worker thread: %s", os_ErrorMsg());
        return -1;
    }

    return 0;
}
