/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2021-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include <stdatomic.h>

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
check_func(void *data);
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
static int
insert_stage1_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *provider,
        const unsigned char *role,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data,
        time_t create_time,
        time_t expiry_time);
static int
extract_stage1_func(
        void *data,
        const unsigned char *state_id,
        struct oauth_stage1_internal *poas1);
static void
free_stage1_func(
        void *data,
        struct oauth_stage1_internal *poas1);
static int
insert_stage2_func(
        void *data,
        struct oauth_stage2_internal *poas2);
static int
extract_stage2_func(
        void *data,
        const unsigned char *request_id,
        struct oauth_stage2_internal *poas2);
static int
update_stage2_func(
        void *data,
        const unsigned char *request_id,
        int request_status,
        const unsigned char *error_message,
        const unsigned char *response_name,
        const unsigned char *response_user_id,
        const unsigned char *response_email,
        const unsigned char *access_token,
        const unsigned char *id_token);
static void
free_stage2_func(
        void *data,
        struct oauth_stage2_internal *poas2);

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
    check_func,
    start_thread_func,
    enqueue_action_func,
    insert_stage1_func,
    extract_stage1_func,
    free_stage1_func,
    insert_stage2_func,
    extract_stage2_func,
    update_stage2_func,
    free_stage2_func,
};

enum { OAUTH_STAGE1_ROW_WIDTH = 8 };

#define OAUTH_STAGE1_OFFSET(f) XOFFSET(struct oauth_stage1_internal, f)

static const struct common_mysql_parse_spec oauth_stage1_spec[OAUTH_STAGE1_ROW_WIDTH] =
{
    { 1, 's', "state_id", OAUTH_STAGE1_OFFSET(state_id), 0 },
    { 1, 's', "provider", OAUTH_STAGE1_OFFSET(provider), 0 },
    { 1, 's', "role", OAUTH_STAGE1_OFFSET(role), 0 },
    { 1, 's', "cookie", OAUTH_STAGE1_OFFSET(cookie), 0 },
    { 0, 'd', "contest_id", OAUTH_STAGE1_OFFSET(contest_id), 0 },
    { 1, 's', "extra_data", OAUTH_STAGE1_OFFSET(extra_data), 0 },
    { 0, 't', "create_time", OAUTH_STAGE1_OFFSET(create_time), 0 },
    { 0, 't', "expiry_time", OAUTH_STAGE1_OFFSET(expiry_time), 0 },
};

enum { OAUTH_STAGE2_ROW_WIDTH = 16 };

#define OAUTH_STAGE2_OFFSET(f) XOFFSET(struct oauth_stage2_internal, f)

static const struct common_mysql_parse_spec oauth_stage2_spec[OAUTH_STAGE2_ROW_WIDTH] =
{
    { 1, 's', "request_id", OAUTH_STAGE2_OFFSET(request_id), 0 },
    { 1, 's', "provider", OAUTH_STAGE2_OFFSET(provider), 0 },
    { 1, 's', "role", OAUTH_STAGE2_OFFSET(role), 0 },
    { 0, 'd', "request_state", OAUTH_STAGE2_OFFSET(request_state), 0 },
    { 1, 's', "request_code", OAUTH_STAGE2_OFFSET(request_code), 0 },
    { 1, 's', "cookie", OAUTH_STAGE2_OFFSET(cookie), 0 },
    { 0, 'd', "contest_id", OAUTH_STAGE2_OFFSET(contest_id), 0 },
    { 1, 's', "extra_data", OAUTH_STAGE2_OFFSET(extra_data), 0 },
    { 0, 't', "create_time", OAUTH_STAGE2_OFFSET(create_time), 0 },
    { 1, 't', "update_time", OAUTH_STAGE2_OFFSET(update_time), 0 },
    { 1, 's', "response_user_id", OAUTH_STAGE2_OFFSET(response_user_id), 0 },
    { 1, 's', "response_email", OAUTH_STAGE2_OFFSET(response_email), 0 },
    { 1, 's', "response_name", OAUTH_STAGE2_OFFSET(response_name), 0 },
    { 1, 's', "access_token", OAUTH_STAGE2_OFFSET(access_token), 0 },
    { 1, 's', "id_token", OAUTH_STAGE2_OFFSET(id_token), 0 },
    { 1, 's', "error_message", OAUTH_STAGE2_OFFSET(error_message), 0 },
};

enum { QUEUE_SIZE = 64 };

struct auth_base_state
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

    _Atomic _Bool open_called;
    _Atomic _Bool check_called;
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_base_state *state;

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

    struct auth_base_state *state = (struct auth_base_state*) data;
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

static int
open_func(void *data)
{
    struct auth_base_state *state = (struct auth_base_state*) data;

    if (atomic_exchange(&state->open_called, 1))
        return 0;

    if (state->mi->connect(state->md) < 0)
        return -1;

    return 0;
}

enum { OAUTH_VERSION_LATEST = 3 };

static const char oauth_stage1_create_str[] =
"CREATE TABLE %soauth_stage1 ( \n"
"    state_id VARCHAR(64) NOT NULL PRIMARY KEY,\n"
"    provider VARCHAR(64) NOT NULL,\n"
"    role VARCHAR(64) DEFAULT NULL,\n"
"    cookie VARCHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    extra_data VARCHAR(512) DEFAULT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    expiry_time DATETIME NOT NULL\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;";

static const char oauth_stage2_create_str[] =
"CREATE TABLE %soauth_stage2 ( \n"
"    request_id VARCHAR(64) NOT NULL PRIMARY KEY,\n"
"    provider VARCHAR(64) NOT NULL,\n"
"    role VARCHAR(64) DEFAULT NULL,\n"
"    request_state INT NOT NULL DEFAULT 0,\n"
"    request_code VARCHAR(256) NOT NULL,\n"
"    cookie VARCHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    extra_data VARCHAR(512) DEFAULT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    update_time DATETIME DEFAULT NULL,\n"
"    response_user_id VARCHAR(64) DEFAULT NULL,\n"
"    response_email VARCHAR(64) DEFAULT NULL,\n"
"    response_name VARCHAR(64) DEFAULT NULL,\n"
"    access_token VARCHAR(256) DEFAULT NULL,\n"
"    id_token VARCHAR(2048) DEFAULT NULL,\n"
"    error_message VARCHAR(256) DEFAULT NULL\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;";

static int
do_check_database(struct auth_base_state *state)
{
    if (state->mi->simple_fquery(state->md, "SELECT config_val FROM %sconfig WHERE config_key = 'oauth_version' ;", state->md->table_prefix) < 0) {
        err("probably the database is not created. use --convert or --create");
        return -1;
    }
    if((state->md->field_count = mysql_field_count(state->md->conn)) != 1) {
        err("wrong database format: field_count == %d", state->md->field_count);
        return -1;
    }
    if (!(state->md->res = mysql_store_result(state->md->conn)))
        return state->mi->error(state->md);

    state->md->row_count = mysql_num_rows(state->md->res);
    if (!state->md->row_count) {
        int version = OAUTH_VERSION_LATEST;
        if (state->mi->simple_fquery(state->md, oauth_stage1_create_str,
                                     state->md->table_prefix) < 0)
            return -1;
        if (state->mi->simple_fquery(state->md, oauth_stage2_create_str,
                                     state->md->table_prefix) < 0)
            return -1;
        if (state->mi->simple_fquery(state->md, "INSERT INTO %sconfig SET config_key='oauth_version', config_val='%d';",
                                     state->md->table_prefix, version) < 0)
            return -1;
    } else {
        if (state->md->row_count > 1) {
            err("wrong database format: row_count == %d", state->md->row_count);
            return -1;
        }
        int version = 0;
        if (state->mi->int_val(state->md, &version, 0) < 0) {
            return -1;
        }
        if (version < 1 || version > OAUTH_VERSION_LATEST) {
            err("invalid version %d", version);
            return -1;
        }
        while (version != OAUTH_VERSION_LATEST) {
            switch (version) {
            case 1:
                if (state->mi->simple_fquery(state->md, "ALTER TABLE %soauth_stage2 ADD COLUMN response_user_id VARCHAR(64) DEFAULT NULL AFTER update_time",
                                      state->md->table_prefix) < 0)
                    return -1;
                break;
            case 2:
                if (state->mi->simple_fquery(state->md, "ALTER TABLE %soauth_stage1 ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;",
                                             state->md->table_prefix) < 0)
                    return -1;
                if (state->mi->simple_fquery(state->md, "ALTER TABLE %soauth_stage2 ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;",
                                             state->md->table_prefix) < 0)
                    return -1;
                if (state->mi->simple_fquery(state->md, "ALTER TABLE %soauth_stage1 MODIFY COLUMN state_id VARCHAR(64) NOT NULL, MODIFY COLUMN provider VARCHAR(64) NOT NULL, MODIFY COLUMN role VARCHAR(64) DEFAULT NULL, MODIFY COLUMN cookie VARCHAR(64) NOT NULL, MODIFY COLUMN extra_data VARCHAR(512) DEFAULT NULL ;",
                                             state->md->table_prefix) < 0)
                    return -1;
                if (state->mi->simple_fquery(state->md, "ALTER TABLE %soauth_stage2 MODIFY COLUMN request_id VARCHAR(64) NOT NULL, MODIFY COLUMN provider VARCHAR(64) NOT NULL, MODIFY COLUMN role VARCHAR(64) DEFAULT NULL, MODIFY COLUMN request_code VARCHAR(256) NOT NULL, MODIFY COLUMN cookie VARCHAR(64) NOT NULL, MODIFY COLUMN extra_data VARCHAR(512) DEFAULT NULL, MODIFY COLUMN response_user_id VARCHAR(64) DEFAULT NULL, MODIFY COLUMN response_email VARCHAR(64) DEFAULT NULL, MODIFY COLUMN response_name VARCHAR(64) DEFAULT NULL, MODIFY COLUMN access_token VARCHAR(256) DEFAULT NULL, MODIFY COLUMN id_token VARCHAR(2048) DEFAULT NULL, MODIFY COLUMN error_message VARCHAR(256) DEFAULT NULL ;",
                                             state->md->table_prefix) < 0)
                    return -1;
                break;
            default:
                err("invalid version %d", version);
                return -1;
            }
            ++version;
            if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'oauth_version' ;", state->md->table_prefix, version) < 0)
                return -1;
        }
    }
    state->mi->free_res(state->md);
    return 0;
}

static int
check_database(struct auth_base_state *state)
{
    int result = -1;
    time_t current_time = time(NULL);

    if (state->mi->simple_fquery(state->md, "INSERT INTO %sconfig SET config_key='oauth_update_lock', config_val='%ld';",
                                 state->md->table_prefix, (long) current_time) < 0) {
        // FIXME: check for DUPLICATE PKEY error
        // FIXME: sleep for some time and then reattempt
        // FIXME: fail after some attempts
        return 0;
    }

    result = do_check_database(state);

    state->mi->simple_fquery(state->md, "DELETE FROM %sconfig WHERE config_key = 'oauth_update_lock';", state->md->table_prefix);
    return result;
}

static int
check_func(void *data)
{
    struct auth_base_state *state = (struct auth_base_state*) data;

    if (atomic_exchange(&state->check_called, 1))
        return 0;

    if (!state->md->conn) return -1;

    check_database(state);

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
    struct auth_base_state *state = (struct auth_base_state*) data;

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
    struct auth_base_state *state = (struct auth_base_state*) data;

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
    struct auth_base_state *state = (struct auth_base_state*) data;

    int r = pthread_create(&state->worker_thread, NULL, thread_func, state);
    if (r) {
        err("auth_base: cannot create worker thread: %s", os_ErrorMsg());
        return -1;
    }

    return 0;
}

static int
insert_stage1_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *provider,
        const unsigned char *role,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data,
        time_t create_time,
        time_t expiry_time)
{
    struct auth_base_state *state = (struct auth_base_state*) data;
    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    int retval = -1;

    state->mi->lock(state->md);
    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "INSERT INTO %soauth_stage1 VALUES (", state->md->table_prefix);
    fprintf(req_f, "'%s'", state_id);
    state->mi->write_escaped_string(state->md, req_f, ",", provider);
    state->mi->write_escaped_string(state->md, req_f, ",", role);
    state->mi->write_escaped_string(state->md, req_f, ",", cookie);
    fprintf(req_f, ", %d", contest_id);
    state->mi->write_escaped_string(state->md, req_f, ",", extra_data);
    state->mi->write_timestamp(state->md, req_f, ",", create_time);
    state->mi->write_timestamp(state->md, req_f, ",", expiry_time);
    fprintf(req_f, ") ;");
    fclose(req_f); req_f = NULL;

    if (state->mi->simple_query(state->md, req_s, req_z) < 0) goto fail;
    free(req_s); req_s = NULL;

    retval = 0;

fail:;
    if (req_f) fclose(req_f);
    free(req_f);
    state->mi->unlock(state->md);
    return retval;
}

static int
extract_stage1_func(
        void *data,
        const unsigned char *state_id,
        struct oauth_stage1_internal *poas1)
{
    struct auth_base_state *state = (struct auth_base_state*) data;

    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    int retval = -1;

    state->mi->lock(state->md);
    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "SELECT * FROM %soauth_stage1 WHERE state_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, "", state_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;

    if (state->mi->query(state->md, req_s, req_z, OAUTH_STAGE1_ROW_WIDTH) < 0) goto fail;
    free(req_s); req_s = NULL; req_z = 0;

    if (state->md->row_count > 1) {
        err("auth_base: extract_stage1: row_count == %d", state->md->row_count);
        goto fail;
    }
    if (!state->md->row_count) {
        err("auth_base: extract_stage1: callback: state_id '%s' does not exist", state_id);
        retval = 0;
        goto fail;
    }
    if (state->mi->next_row(state->md) < 0) goto fail;
    if (state->mi->parse_spec(state->md, state->md->field_count, state->md->row, state->md->lengths,
                              OAUTH_STAGE1_ROW_WIDTH, oauth_stage1_spec, poas1) < 0)
        goto fail;
    state->mi->free_res(state->md);

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "DELETE FROM %soauth_stage1 WHERE state_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, "", state_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;
    state->mi->simple_query(state->md, req_s, req_z);
    free(req_s); req_s = NULL; req_z = 0;
    retval = 1;

fail:;
    state->mi->free_res(state->md);
    if (req_f) fclose(req_f);
    free(req_s);
    state->mi->unlock(state->md);
    return retval;
}

static void
free_stage1_func(
        void *data,
        struct oauth_stage1_internal *poas1)
{
    free(poas1->state_id);
    free(poas1->provider);
    free(poas1->role);
    free(poas1->cookie);
    free(poas1->extra_data);

    memset(poas1, 0, sizeof(*poas1));
}

static int
insert_stage2_func(
        void *data,
        struct oauth_stage2_internal *poas2)
{
    struct auth_base_state *state = (struct auth_base_state*) data;
    char *req_s = NULL;
    size_t req_z;
    FILE *req_f = NULL;
    int retval = -1;

    state->mi->lock(state->md);
    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "INSERT INTO %soauth_stage2 VALUES ( ", state->md->table_prefix);
    state->mi->unparse_spec(state->md, req_f, OAUTH_STAGE2_ROW_WIDTH, oauth_stage2_spec, poas2);
    fprintf(req_f, ") ;");
    fclose(req_f); req_f = NULL;
    if (state->mi->simple_query(state->md, req_s, req_z) < 0) goto done;
    free(req_s); req_s = NULL;
    retval = 0;

done:;
    if (req_f) fclose(req_f);
    free(req_s);
    state->mi->unlock(state->md);
    return retval;
}

static void
free_stage2_func(
        void *data,
        struct oauth_stage2_internal *poas2)
{
    free(poas2->request_id);
    free(poas2->provider);
    free(poas2->role);
    free(poas2->request_code);
    free(poas2->cookie);
    free(poas2->extra_data);
    free(poas2->response_user_id);
    free(poas2->response_email);
    free(poas2->response_name);
    free(poas2->access_token);
    free(poas2->id_token);
    free(poas2->error_message);

    memset(poas2, 0, sizeof(*poas2));
}

static int
extract_stage2_func(
        void *data,
        const unsigned char *request_id,
        struct oauth_stage2_internal *poas2)
{
    struct auth_base_state *state = (struct auth_base_state*) data;
    char *req_s = NULL;
    size_t req_z;
    FILE *req_f = NULL;
    int retval = -1;

    state->mi->lock(state->md);
    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "SELECT * FROM %soauth_stage2 WHERE request_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, "", request_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;

    if (state->mi->query(state->md, req_s, req_z, OAUTH_STAGE2_ROW_WIDTH) < 0) {
        //error_message = xstrdup("query failed");
        goto done;
    }
    free(req_s); req_s = NULL; req_z = 0;
    if (state->md->row_count > 1) {
        err("auth_base: get_result: row_count == %d", state->md->row_count);
        //error_message = xstrdup("non unique row");
        goto done;
    }
    if (!state->md->row_count) {
        err("auth_base: get_result: request_id '%s' does not exist", request_id);
        //error_message = xstrdup("nonexisting request");
        retval = 0;
        goto done;
    }

    if (state->mi->next_row(state->md) < 0) goto done;
    if (state->mi->parse_spec(state->md, state->md->field_count, state->md->row, state->md->lengths,
                              OAUTH_STAGE2_ROW_WIDTH, oauth_stage2_spec, poas2) < 0)
        goto done;
    retval = 1;

done:;
    state->mi->free_res(state->md);
    if (req_f) fclose(req_f);
    free(req_s);
    state->mi->unlock(state->md);
    return retval;
}

static int
update_stage2_func(
        void *data,
        const unsigned char *request_id,
        int request_status,
        const unsigned char *error_message,
        const unsigned char *response_name,
        const unsigned char *response_user_id,
        const unsigned char *response_email,
        const unsigned char *access_token,
        const unsigned char *id_token)
{
    struct auth_base_state *state = (struct auth_base_state*) data;
    char *req_s = NULL;
    size_t req_z;
    FILE *req_f = NULL;
    int retval = -1;

    state->mi->lock(state->md);
    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "UPDATE %soauth_stage2 SET request_state = %d",
            state->md->table_prefix, request_status);
    if (error_message && *error_message) {
        fprintf(req_f, ", error_message = ");
        state->mi->write_escaped_string(state->md, req_f, "", error_message);
    }
    if (response_name && *response_name) {
        fprintf(req_f, ", response_name = ");
        state->mi->write_escaped_string(state->md, req_f, "", response_name);
    }
    if (response_user_id && *response_user_id) {
        fprintf(req_f, ", response_user_id = ");
        state->mi->write_escaped_string(state->md, req_f, "", response_user_id);
    }
    if (response_email && *response_email) {
        fprintf(req_f, ", response_email = ");
        state->mi->write_escaped_string(state->md, req_f, "", response_email);
    }
    if (access_token && *access_token) {
        fprintf(req_f, ", access_token = ");
        state->mi->write_escaped_string(state->md, req_f, "", access_token);
    }
    if (id_token && *id_token) {
        fprintf(req_f, ", id_token = ");
        state->mi->write_escaped_string(state->md, req_f, "", id_token);
    }
    fprintf(req_f, ", update_time = NOW() WHERE request_id = ");
    state->mi->write_escaped_string(state->md, req_f, "", request_id);
    fprintf(req_f, " ;");
    fclose(req_f); req_f = NULL;
    retval = state->mi->simple_query(state->md, req_s, req_z);
    free(req_s); req_s = NULL;
    state->mi->unlock(state->md);
    return retval;
}
