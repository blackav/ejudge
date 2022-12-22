/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2021-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/xml_utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "ejudge/cJSON.h"
#include "ejudge/base64.h"
#include "ejudge/random.h"
#include "ejudge/misctext.h"
#include "ejudge/auth_base_plugin.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#else
#error curl required
#endif

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
static unsigned char *
get_redirect_url_func(
        void *data,
        const unsigned char *cookie,
        const unsigned char *provider,
        const unsigned char *role,
        int contest_id,
        const unsigned char *extra_data);
static unsigned char *
process_auth_callback_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code);
static struct OAuthLoginResult
get_result_func(
        void *data,
        const unsigned char *job_id);

struct auth_plugin_iface plugin_auth_google =
{
    {
        {
            sizeof (struct auth_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "google",
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

struct auth_google_state
{
    struct auth_base_plugin_iface *bi;
    struct auth_base_plugin_state *bd;

    // curl for auth endpoint discovery
    CURL *curl;
    unsigned char *authorization_endpoint;
    unsigned char *token_endpoint;

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
    struct auth_google_state *state;

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
    struct auth_google_state *state = (struct auth_google_state*) data;
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
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (state->bi->open(state->bd) < 0)
        return 1;

    return 0;
}

static int
fetch_google_endpoints(struct auth_google_state *state)
{
    char *page_text = NULL;
    size_t page_size = 0;
    FILE *file = NULL;
    CURLcode res = 0;
    cJSON *root = NULL;

    curl_easy_reset(state->curl);
    curl_easy_setopt(state->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(state->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(state->curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(state->curl, CURLOPT_URL, "https://accounts.google.com/.well-known/openid-configuration");
    file = open_memstream(&page_text, &page_size);
    curl_easy_setopt(state->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(state->curl, CURLOPT_WRITEDATA, file);
    res = curl_easy_perform(state->curl);
    fclose(file); file = NULL;
    if (res != CURLE_OK) {
        err("Request failed: %s", curl_easy_strerror(res));
        goto fail;
    }
    root = cJSON_Parse(page_text);
    free(page_text); page_text = NULL;
    if (!root) {
        err("JSON parse failed");
        goto fail;
    }
    if (root->type != cJSON_Object) {
        err("invalid json, root document expected");
        goto fail;
    }
    cJSON *jauth = cJSON_GetObjectItem(root, "authorization_endpoint");
    if (!jauth || jauth->type != cJSON_String) {
        err("invalid json, invalid authorization_endpoint");
        goto fail;
    }
    state->authorization_endpoint = xstrdup(jauth->valuestring);

    cJSON *jtoken = cJSON_GetObjectItem(root, "token_endpoint");
    if (!jtoken || jtoken->type != cJSON_String) {
        err("invalid json, invalid token_endpoint");
        goto fail;
    }
    state->token_endpoint = xstrdup(jtoken->valuestring);
    cJSON_Delete(root);

    return 0;

fail:
    if (root) cJSON_Delete(root);
    if (file) fclose(file);
    free(page_text);
    return -1;
}

static int
check_func(void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (state->bi->check(state->bd) < 0)
        return -1;

    fetch_google_endpoints(state);

    return 0;
}

static void
set_set_command_handler_func(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    state->set_command_handler_func = setter;
    state->set_command_handler_data = setter_self;
}

static void
set_send_job_handler_func(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    state->send_job_handler_func = handler;
    state->send_job_handler_data = handler_self;
}

static void
queue_packet_handler_auth_google(int uid, int argc, char **argv, void *user);

static int
start_thread_func(void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (!state->set_command_handler_func) {
        return 0;
    }

    state->set_command_handler_func(state->set_command_handler_data,
                                    "auth_google",
                                    queue_packet_handler_auth_google,
                                    data);

    int r = state->bi->start_thread(state->bd);
    return r;
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
    struct auth_google_state *state = (struct auth_google_state*) data;

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
    fprintf(url_f, "%s?client_id=%s&response_type=code",
            state->authorization_endpoint,
            url_armor_buf(&ab, state->client_id));
    fprintf(url_f, "&redirect_uri=%s/S1", url_armor_buf(&ab, state->redirect_uri));
    fprintf(url_f, "&state=%s", ebuf);
    fprintf(url_f, "&scope=openid%%20profile%%20email");
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
    struct auth_google_state *state = (struct auth_google_state*) data;

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
        unsigned char *args[] = { "auth_google", oas2.request_id, oas2.request_code, NULL };
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
    struct auth_google_state *state = (struct auth_google_state*) data;
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

/*
  args[0] = "auth_google"
  args[1] = request_id
  args[2] = request_code
  args[3] = NULL;
 */
static void
packet_handler_auth_google(int uid, int argc, char **argv, void *user)
{
    struct auth_google_state *state = (struct auth_google_state*) user;

    const unsigned char *request_id = argv[1];
    const unsigned char *request_code = argv[2];

    char *post_s = NULL;
    size_t post_z = 0;
    FILE *post_f = NULL;
    char *json_s = NULL;
    size_t json_z = 0;
    FILE *json_f = NULL;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    CURLcode res = 0;
    int request_status = 2;   // failed
    const char *error_message = "unknown error";
    const unsigned char *response_email = NULL;
    const unsigned char *response_name = NULL;
    const unsigned char *access_token = NULL;
    const unsigned char *id_token = NULL;
    cJSON *root = NULL;
    cJSON *jwt = NULL;
    unsigned char *jwt_payload = NULL;

    post_f = open_memstream(&post_s, &post_z);
    fprintf(post_f, "grant_type=authorization_code");
    fprintf(post_f, "&code=%s", url_armor_buf(&ab, request_code));
    fprintf(post_f, "&client_id=%s", url_armor_buf(&ab, state->client_id));
    fprintf(post_f, "&client_secret=%s", url_armor_buf(&ab, state->client_secret));
    fprintf(post_f, "&redirect_uri=%s/S1", url_armor_buf(&ab, state->redirect_uri));
    fclose(post_f); post_f = NULL;

    json_f = open_memstream(&json_s, &json_z);
    curl_easy_reset(state->curl);
    curl_easy_setopt(state->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(state->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(state->curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(state->curl, CURLOPT_URL, state->token_endpoint);
    curl_easy_setopt(state->curl, CURLOPT_POST, 1);
    curl_easy_setopt(state->curl, CURLOPT_POSTFIELDS, post_s);
    curl_easy_setopt(state->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(state->curl, CURLOPT_WRITEDATA, json_f);
    res = curl_easy_perform(state->curl);
    fclose(json_f); json_f = NULL;
    free(post_s); post_s = NULL; post_z = 0;
    if (res != CURLE_OK) {
        err("Request failed: %s", curl_easy_strerror(res));
        error_message = "request failed";
        goto done;
    }

    //fprintf(stderr, ">>%s<<\n", json_s);

    if (!(root = cJSON_Parse(json_s))) {
        error_message = "google JSON parse failed";
        goto done;
    }
    free(json_s); json_s = NULL; json_z = 0;

    if (root->type != cJSON_Object) {
        error_message = "google root document expected";
        goto done;
    }

    cJSON *j = cJSON_GetObjectItem(root, "access_token");
    if (!j || j->type != cJSON_String) {
        error_message = "invalid google json: access_token";
        goto done;
    }
    access_token = j->valuestring;

    if (!(j = cJSON_GetObjectItem(root, "id_token")) || j->type != cJSON_String) {
        error_message = "invalid google json: id_token";
        goto done;
    }
    id_token = j->valuestring;

    // parse payload of JWT
    {
        char *p1 = strchr(id_token, '.');
        if (!p1) {
            error_message = "invalid google json: invalid JWT (1)";
            goto done;
        }
        char *p2 = strchr(p1 + 1, '.');
        if (!p2) {
            error_message = "invalid google json: invalid JWT (2)";
            goto done;
        }

        jwt_payload = xmalloc(strlen(id_token) + 1);
        int err = 0;
        int len = base64u_decode(p1 + 1, p2 - p1 - 1, jwt_payload, &err);
        if (err) {
            error_message = "invalid google json: base64u payload decode error";
            goto done;
        }
        jwt_payload[len] = 0;
    }

    if (!(jwt = cJSON_Parse(jwt_payload))) {
        error_message = "JWT payload parse failed";
        goto done;
    }
    if (jwt->type != cJSON_Object) {
        error_message = "JWT payload root document expected";
        goto done;
    }

    if (!(j = cJSON_GetObjectItem(jwt, "email")) || j->type != cJSON_String) {
        error_message = "JWT payload email expected";
        goto done;
    }
    response_email = j->valuestring;

    if ((j = cJSON_GetObjectItem(jwt, "name")) && j->type == cJSON_String) {
        response_name = j->valuestring;
    }

    // success
    request_status = 3;
    error_message = NULL;

done:
    state->bi->update_stage2(state->bd, request_id,
                             request_status, error_message,
                             response_name,
                             NULL /* response_user_id */,
                             response_email,
                             access_token, id_token);

    free(jwt_payload);
    if (root) cJSON_Delete(root);
    html_armor_free(&ab);
    if (json_f) fclose(json_f);
    free(json_s);
    if (post_f) fclose(post_f);
    free(post_s);
    if (jwt) cJSON_Delete(jwt);
}

static void
queue_packet_handler_auth_google(int uid, int argc, char **argv, void *user)
{
    struct auth_google_state *state = (struct auth_google_state*) user;
    state->bi->enqueue_action(state->bd, packet_handler_auth_google,
                              uid, argc, argv, user);
}
