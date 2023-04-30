/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/config.h"
#include "ejudge/auth_plugin.h"
#include "ejudge/auth_base_plugin.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/base64.h"
#include "ejudge/random.h"
#include "ejudge/cJSON.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#else
#error curl required
#endif

#include <string.h>

static const char authorization_endpoint[] = "https://oauth.yandex.ru/authorize";
static const char info_endpoint[] = "https://login.yandex.ru/info";

struct auth_yandex_state
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
    struct auth_yandex_state *state;

    XCALLOC(state, 1);

    state->curl = curl_easy_init();
    curl_easy_setopt(state->curl, CURLOPT_NOSIGNAL, 1L);

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
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;
    __attribute__((unused)) const struct xml_parse_spec *spec = ejudge_cfg_get_spec();

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
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    return state->bi->open(state->bd);
}

static int
check_func(void *data)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    return state->bi->check(state->bd);
}

static void
set_set_command_handler_func(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    state->set_command_handler_func = setter;
    state->set_command_handler_data = setter_self;
}

static void
set_send_job_handler_func(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    state->send_job_handler_func = handler;
    state->send_job_handler_data = handler_self;
}

static void
packet_handler_auth_yandex(int uid, int argc, char **argv, void *user);

static void
queue_packet_handler_auth_yandex(int uid, int argc, char **argv, void *user)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) user;
    state->bi->enqueue_action(state->bd, packet_handler_auth_yandex,
                              uid, argc, argv, user);
}

static int
start_thread_func(void *data)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    if (!state->set_command_handler_func) {
        return 0;
    }

    state->set_command_handler_func(state->set_command_handler_data,
                                    "auth_yandex",
                                    queue_packet_handler_auth_yandex,
                                    data);

    return state->bi->start_thread(state->bd);
}

static unsigned char *
get_redirect_url_func(
        void *data,
        const unsigned char *cookie,
        const unsigned char *provider,
        const unsigned char *role,
        int contest_id,
        const unsigned char *extra_data)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    unsigned char rbuf[16];
    unsigned char ebuf[32];
    time_t create_time = time(NULL);
    time_t expiry_time = create_time + 60;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

    random_init();
    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), ebuf);
    ebuf[len] = 0;

    if (state->bi->insert_stage1(state->bd,
                                 ebuf, provider, role, cookie, contest_id,
                                 extra_data, create_time, expiry_time) < 0) {
        goto fail;
    }

    url_f = open_memstream(&url_s, &url_z);
    fprintf(url_f, "%s?client_id=%s&response_type=token",
            authorization_endpoint,
            url_armor_buf(&ab, state->client_id));
    fprintf(url_f, "&state=%s", ebuf);
    fclose(url_f); url_f = NULL;

    html_armor_free(&ab);
    return url_s;

fail:
    html_armor_free(&ab);
    return NULL;
}

static unsigned char *
process_auth_callback_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;

    struct oauth_stage1_internal oas1 = {};
    struct oauth_stage2_internal oas2 = {};
    unsigned char rbuf[16];
    unsigned char ebuf[32] = {};

    if (state->bi->extract_stage1(state->bd, state_id, &oas1) <= 0) {
        goto fail;
    }
    random_init();
    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), ebuf);
    ebuf[len] = 0;

    oas2.request_id = xstrdup(ebuf);
    oas2.request_code = xstrdup(code);
    oas2.cookie = oas1.cookie; oas1.cookie = NULL;
    oas2.provider = oas1.provider; oas1.provider = NULL;
    oas2.role = oas1.role; oas1.role = NULL;
    oas2.contest_id = oas1.contest_id;
    oas2.extra_data = oas1.extra_data; oas1.extra_data = NULL;
    oas2.create_time = time(NULL);

    if (state->bi->insert_stage2(state->bd, &oas2) < 0) {
        goto fail;
    }

    if (state->send_job_handler_func) {
        unsigned char *args[] = { "auth_yandex", oas2.request_id, oas2.request_code, NULL };
        state->send_job_handler_func(state->send_job_handler_data, args);
    } else {
        err("send_job_handler_func is not installed");
        goto fail;
    }

    state->bi->free_stage1(state->bd, &oas1);
    state->bi->free_stage2(state->bd, &oas2);

    return xstrdup(ebuf);

fail:
    state->bi->free_stage1(state->bd, &oas1);
    state->bi->free_stage2(state->bd, &oas2);
    return NULL;
}

static struct OAuthLoginResult
get_result_func(
        void *data,
        const unsigned char *request_id)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) data;
    unsigned char *error_message = NULL;
    struct oauth_stage2_internal oas2 = {};
    struct OAuthLoginResult res = {};

    if (state->bi->extract_stage2(state->bd, request_id, &oas2) <= 0) {
        goto fail;
    }

    res.status = oas2.request_state;
    res.provider = oas2.provider; oas2.provider = NULL;
    res.role = oas2.role; oas2.role = NULL;
    res.cookie = oas2.cookie; oas2.cookie = NULL;
    res.extra_data = oas2.extra_data; oas2.extra_data = NULL;
    res.user_id = oas2.response_user_id; oas2.response_user_id = NULL;
    res.email = oas2.response_email; oas2.response_email = NULL;
    res.name = oas2.response_name; oas2.response_name = NULL;
    res.access_token = oas2.access_token; oas2.access_token = NULL;
    res.id_token = oas2.id_token; oas2.id_token = NULL;
    res.error_message = oas2.error_message; oas2.error_message = NULL;
    res.contest_id = oas2.contest_id;
    state->bi->free_stage2(state->bd, &oas2);
    return res;

fail:
    state->bi->free_stage2(state->bd, &oas2);
    if (!error_message) error_message = xstrdup("unknown error");
    return (struct OAuthLoginResult) { .status = 2, .error_message = error_message };
}

struct auth_plugin_iface plugin_auth_yandex =
{
    {
        {
            sizeof (struct auth_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "yandex",
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
    get_redirect_url_func,
    process_auth_callback_func,
    get_result_func,
};

/*
  args[0] = "auth_yandex"
  args[1] = request_id
  args[2] = request_code
  args[3] = NULL;
 */
static void
packet_handler_auth_yandex(int uid, int argc, char **argv, void *user)
{
    struct auth_yandex_state *state = (struct auth_yandex_state*) user;
    const unsigned char *request_id = argv[1];
    const unsigned char *request_code = argv[2];
    const char *error_message = "unknown error";
    const unsigned char *response_user_id = NULL;
    const unsigned char *response_email = NULL;
    const unsigned char *response_name = NULL;
    const unsigned char *access_token = NULL;
    int request_status = 2;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;
    char *json_s = NULL;
    size_t json_z = 0;
    FILE *json_f = NULL;
    CURLcode res = 0;
    cJSON *root = NULL;
    struct curl_slist *headers = NULL;
    char *header = NULL;
    __attribute__((unused)) int _;

    url_f = open_memstream(&url_s, &url_z);
    fprintf(url_f, "%s", info_endpoint);
    fprintf(url_f, "?format=json");
    fclose(url_f); url_f = NULL;
    _ = asprintf(&header, "Authorization: OAuth %s", request_code);
    headers = curl_slist_append(headers, header);
    json_f = open_memstream(&json_s, &json_z);
    curl_easy_reset(state->curl);
    curl_easy_setopt(state->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(state->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(state->curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(state->curl, CURLOPT_URL, url_s);
    curl_easy_setopt(state->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(state->curl, CURLOPT_WRITEDATA, json_f);
    curl_easy_setopt(state->curl, CURLOPT_HTTPHEADER, headers);
    res = curl_easy_perform(state->curl);
    fclose(json_f); json_f = NULL;
    free(url_s); url_s = NULL; url_z = 0;
    if (res != CURLE_OK) {
        err("Request failed: %s", curl_easy_strerror(res));
        error_message = "request failed";
        goto done;
    }

    //fprintf(stderr, ">>%s<<\n", json_s);

    if (!(root = cJSON_Parse(json_s))) {
        error_message = "yandex JSON parse failed";
        goto done;
    }
    free(json_s); json_s = NULL; json_z = 0;
    if (root->type != cJSON_Object) {
        error_message = "yandex root document expected";
        goto done;
    }

    cJSON *j = cJSON_GetObjectItem(root, "default_email");
    if (j && j->type == cJSON_String) {
        response_email = j->valuestring;
    }
    if (!response_email || !*response_email) {
        error_message = "yandex json: no default_email";
        goto done;
    }

    j = cJSON_GetObjectItem(root, "psuid");
    if (j && j->type == cJSON_String) {
        access_token = j->valuestring;
    }

    j = cJSON_GetObjectItem(root, "real_name");
    if (j && j->type == cJSON_String) {
        response_name = j->valuestring;
    }

    j = cJSON_GetObjectItem(root, "id");
    if (j && j->type == cJSON_String) {
        response_user_id = j->valuestring;
    }

    // success
    request_status = 3;
    error_message = NULL;

done:;
    state->bi->update_stage2(state->bd, request_id,
                             request_status, error_message,
                             response_name,
                             response_user_id,
                             response_email,
                             access_token, NULL);

    if (root) cJSON_Delete(root);
    if (url_f) fclose(url_f);
    if (json_f) fclose(json_f);
    free(url_s);
    free(json_s);
    curl_slist_free_all(headers);
    free(header);
}
