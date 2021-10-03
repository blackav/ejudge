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
#include "ejudge/xml_utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "ejudge/cJSON.h"
#include "ejudge/base64.h"
#include "ejudge/random.h"
#include "ejudge/misctext.h"
#include "ejudge/osdeps.h"
#include "../common-mysql/common_mysql.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#else
#error curl required
#endif

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

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
static unsigned char *
get_redirect_url_func(
        void *data,
        const char *cookie,
        int contest_id,
        const char *extra_data);
static unsigned char *
process_auth_callback_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code,
        void (*fd_register_func)(int fd, void (*callback)(int fd, void *), void *data));

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
    get_redirect_url_func,
    process_auth_callback_func,
};

struct auth_google_state
{
    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;
    // curl for auth endpoint discovery
    CURL *curl;
    unsigned char *authorization_endpoint;
    unsigned char *token_endpoint;

    unsigned char *client_id;
    unsigned char *client_secret;
    unsigned char *redirect_uri;

    int bg_w_fd;
    int bg_r_fd;
    int bg_pid;
};

struct oauth_stage1_internal
{
    unsigned char *state_id;
    unsigned char *provider;
    unsigned char *cookie;
    int contest_id;
    unsigned char *extra_data;
    time_t create_time;
    time_t expiry_time;
};

enum { OAUTH_STAGE1_ROW_WIDTH = 7 };

#define OAUTH_STAGE1_OFFSET(f) XOFFSET(struct oauth_stage1_internal, f)

static const struct common_mysql_parse_spec oauth_stage1_spec[OAUTH_STAGE1_ROW_WIDTH] =
{
    { 1, 's', "state_id", OAUTH_STAGE1_OFFSET(state_id), 0 },
    { 1, 's', "provider", OAUTH_STAGE1_OFFSET(provider), 0 },
    { 1, 's', "cookie", OAUTH_STAGE1_OFFSET(cookie), 0 },
    { 0, 'd', "contest_id", OAUTH_STAGE1_OFFSET(contest_id), 0 },
    { 1, 's', "extra_data", OAUTH_STAGE1_OFFSET(extra_data), 0 },
    { 0, 't', "create_time", OAUTH_STAGE1_OFFSET(create_time), 0 },
    { 0, 't', "expiry_time", OAUTH_STAGE1_OFFSET(expiry_time), 0 },
};

struct oauth_stage2_internal
{
    unsigned char *request_id;
    int request_state;
    unsigned char *request_code;
    unsigned char *cookie;
    int contest_id;
    unsigned char *extra_data;
    time_t create_time;
    time_t update_time;
    unsigned char *response_email;
    unsigned char *response_name;
    unsigned char *access_token;
    unsigned char *id_token;
    unsigned char *error_message;
};

enum { OAUTH_STAGE2_ROW_WIDTH = 13 };

#define OAUTH_STAGE2_OFFSET(f) XOFFSET(struct oauth_stage2_internal, f)

static const struct common_mysql_parse_spec oauth_stage2_spec[OAUTH_STAGE2_ROW_WIDTH] =
{
    { 1, 's', "request_id", OAUTH_STAGE2_OFFSET(request_id), 0 },
    { 0, 'd', "request_state", OAUTH_STAGE2_OFFSET(request_state), 0 },
    { 1, 's', "request_code", OAUTH_STAGE2_OFFSET(request_code), 0 },
    { 1, 's', "cookie", OAUTH_STAGE2_OFFSET(cookie), 0 },
    { 0, 'd', "contest_id", OAUTH_STAGE2_OFFSET(contest_id), 0 },
    { 1, 's', "extra_data", OAUTH_STAGE2_OFFSET(extra_data), 0 },
    { 0, 't', "create_time", OAUTH_STAGE2_OFFSET(create_time), 0 },
    { 1, 't', "update_time", OAUTH_STAGE2_OFFSET(update_time), 0 },
    { 1, 's', "response_email", OAUTH_STAGE2_OFFSET(response_email), 0 },
    { 1, 's', "response_name", OAUTH_STAGE2_OFFSET(response_name), 0 },
    { 1, 's', "access_token", OAUTH_STAGE2_OFFSET(access_token), 0 },
    { 1, 's', "id_token", OAUTH_STAGE2_OFFSET(id_token), 0 },
    { 1, 's', "error_message", OAUTH_STAGE2_OFFSET(error_message), 0 },
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_google_state *state;

    XCALLOC(state, 1);

    state->curl = curl_easy_init();
    state->bg_w_fd = -1;
    state->bg_r_fd = -1;

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
    const struct xml_parse_spec *spec = ejudge_cfg_get_spec();

    // load common_mysql plugin
    const struct common_loaded_plugin *mplg;
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }

    struct auth_google_state *state = (struct auth_google_state*) data;
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

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

  if (state->mi->connect(state->md) < 0)
    return -1;

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

    return 0;

fail:
    if (root) cJSON_Delete(root);
    if (file) fclose(file);
    free(page_text);
    return -1;
}

static const char oauth_stage1_create_str[] =
"CREATE TABLE %soauth_stage1 ( \n"
"    state_id VARCHAR(64) NOT NULL PRIMARY KEY,\n"
"    provider VARCHAR(64) NOT NULL,\n"
"    cookie VARCHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    extra_data VARCHAR(512) DEFAULT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    expiry_time DATETIME NOT NULL\n"
") DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

static const char oauth_stage2_create_str[] =
"CREATE TABLE %soauth_stage2 ( \n"
"    request_id VARCHAR(64) NOT NULL PRIMARY KEY,\n"
"    request_state INT NOT NULL DEFAULT 0,\n"
"    request_code VARCHAR(64) NOT NULL,\n"
"    cookie VARCHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    extra_data VARCHAR(512) DEFAULT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    update_time DATETIME DEFAULT NULL,\n"
"    response_email VARCHAR(64) DEFAULT NULL,\n"
"    response_name VARCHAR(64) DEFAULT NULL,\n"
"    access_token VARCHAR(256) DEFAULT NULL,\n"
"    id_token VARCHAR(512) DEFAULT NULL,\n"
"    error_message VARCHAR(256) DEFAULT NULL\n"
") DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

static int
check_func(void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (!state->md->conn) return -1;

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
        int version = 1;
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
        if (version != 1) {
            err("invalid version %d", version);
            return -1;
        }
    }
    state->mi->free_res(state->md);

    fetch_google_endpoints(state);

    return 0;
}

static unsigned char *
get_redirect_url_func(
        void *data,
        const char *cookie,
        int contest_id,
        const char *extra_data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    unsigned char rbuf[16];
    unsigned char ebuf[32];
    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    time_t create_time = time(NULL);
    time_t expiry_time = create_time + 60;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), ebuf);
    ebuf[len] = 0;

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "INSERT INTO %soauth_stage1 VALUES (", state->md->table_prefix);
    fprintf(req_f, "'%s'", ebuf);
    fprintf(req_f, ", 'google'");
    state->mi->write_escaped_string(state->md, req_f, ",", cookie);
    fprintf(req_f, ", %d", contest_id);
    state->mi->write_escaped_string(state->md, req_f, ",", extra_data);
    state->mi->write_timestamp(state->md, req_f, ",", create_time);
    state->mi->write_timestamp(state->md, req_f, ",", expiry_time);
    fprintf(req_f, ") ;");
    fclose(req_f); req_f = NULL;

    if (state->mi->simple_query(state->md, req_s, req_z) < 0) goto fail;
    free(req_s); req_s = NULL;

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
    free(req_s);
    return NULL;
}

static unsigned char *
handle_oauth_query(struct auth_google_state *state, const unsigned char *data)
{
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    char *resp_s = NULL;
    size_t resp_z = 0;
    FILE *resp_f = open_memstream(&resp_s, &resp_z);
    int request_status = 2;   // failed
    const char *error_message = "unknown error";
    cJSON *root = NULL;
    const unsigned char *request_id = NULL;
    const unsigned char *request_code = NULL;
    char *post_s = NULL;
    size_t post_z = 0;
    FILE *post_f = NULL;
    char *json_s = NULL;
    size_t json_z = 0;
    FILE *json_f = NULL;
    CURLcode res = 0;
    const unsigned char *access_token = NULL;
    int expires_in = 0;
    const unsigned char *id_token = NULL;
    const unsigned char *scope = NULL;
    const unsigned char *token_type = NULL;
    unsigned char *jwt_payload = NULL;
    cJSON *jwt = NULL;
    const unsigned char *response_email = NULL;
    const unsigned char *response_name = NULL;

    if (!(root = cJSON_Parse(data))) {
        error_message = "JSON parse failed";
        goto done;
    }
    if (root->type != cJSON_Object) {
        error_message = "root document expected";
        goto done;
    }
    cJSON *jid = cJSON_GetObjectItem(root, "request_id");
    if (!jid || jid->type != cJSON_String) {
        error_message = "invalid json: request_id";
        goto done;
    }
    request_id = jid->valuestring;
    cJSON *jcode = cJSON_GetObjectItem(root, "request_code");
    if (!jcode || jcode->type != cJSON_String) {
        error_message = "invalid json: request_code";
        goto done;
    }
    request_code = jcode->valuestring;

    post_f = open_memstream(&post_s, &post_z);
    fprintf(post_f, "grant_type=authorization_code");
    fprintf(post_f, "&code=%s", url_armor_buf(&ab, request_code));
    fprintf(post_f, "&client_id=%s", url_armor_buf(&ab, state->client_id));
    fprintf(post_f, "&client_secret=%s", url_armor_buf(&ab, state->client_secret));
    fprintf(post_f, "&redirect_uri=%s", url_armor_buf(&ab, state->redirect_uri));
    fclose(post_f); post_f = NULL;
    cJSON_Delete(root); root = NULL;

    json_f = open_memstream(&json_s, &json_z);
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

    if (!(root = cJSON_Parse(json_s))) {
        error_message = "google JSON parse failed";
        goto done;
    }
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

    if (!(j = cJSON_GetObjectItem(root, "expires_in")) || j->type != cJSON_Number) {
        error_message = "invalid google json: expires_in";
        goto done;
    }
    expires_in = j->valueint;

    if (!(j = cJSON_GetObjectItem(root, "id_token")) || j->type != cJSON_String) {
        error_message = "invalid google json: id_token";
        goto done;
    }
    id_token = j->valuestring;

    if (!(j = cJSON_GetObjectItem(root, "scope")) || j->type != cJSON_String) {
        error_message = "invalid google json: scope";
        goto done;
    }
    scope = j->valuestring;

    if (!(j = cJSON_GetObjectItem(root, "token_type")) || j->type != cJSON_String) {
        error_message = "invalid google json: token_type";
        goto done;
    }
    token_type = j->valuestring;

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
    fprintf(resp_f, "{ \"request_status\" = %d", request_status);
    if (error_message) fprintf(resp_f, ", \"error_message\" = \"%s\"", json_armor_buf(&ab, error_message));
    if (request_id) fprintf(resp_f, ", \"request_id\" = \"%s\"", json_armor_buf(&ab, request_id));
    if (access_token) fprintf(resp_f, ", \"access_token\" = \"%s\"", json_armor_buf(&ab, access_token));
    if (expires_in) fprintf(resp_f, ", \"expires_in\" = %d", expires_in);
    if (id_token) fprintf(resp_f, ", \"id_token\" = \"%s\"", json_armor_buf(&ab, id_token));
    if (scope) fprintf(resp_f, ", \"scope\" = \"%s\"", json_armor_buf(&ab, scope));
    if (token_type) fprintf(resp_f, ", \"token_type\" = \"%s\"", json_armor_buf(&ab, token_type));
    if (response_email) fprintf(resp_f, ", \"response_email\" = \"%s\"", json_armor_buf(&ab, response_email));
    if (response_name) fprintf(resp_f, ", \"response_name\" = \"%s\"", json_armor_buf(&ab, response_name));
    fprintf(resp_f, " }");
    fclose(resp_f);
    if (post_f) fclose(post_f);
    free(post_s);
    if (root) cJSON_Delete(root);
    if (json_f) fclose(json_f);
    free(json_s);
    html_armor_free(&ab);
    free(jwt_payload);
    if (jwt) cJSON_Delete(jwt);
    return resp_s;
}

static void
do_background_oauth_queries(struct auth_google_state *state, int rfd, int wfd)
{
    fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL) & ~O_NONBLOCK);

    unsigned length;
    int r;
    unsigned char inbuf[32768];
    unsigned char outbuf[32768];

    while ((r = read(rfd, &length, sizeof(length))) == sizeof(length)) {
        if (length > 32000) {
            err("auth_google: background: length is too big: %u", length);
            _exit(1);
        }
        r = read(rfd, inbuf, length);
        if (r < 0) {
            err("auth_google: background: read failed: %s", os_ErrorMsg());
            _exit(1);
        }
        if (!r) {
            err("auth_google: background: unexpected EOF");
            _exit(1);
        }
        if (r != length) {
            err("auth_google: background: invalid length:");
            _exit(1);
        }
        inbuf[r] = 0;

        unsigned char *result = handle_oauth_query(state, inbuf);
        length = strlen(result);
        if (length > 32000) {
            err("auth_google: background: response is too big: %u", length);
        } else {
            memcpy(outbuf, &length, sizeof(length));
            memcpy(outbuf + sizeof(length), result, length);
            length += sizeof(length);
            if ((r = write(wfd, outbuf, length)) != length) {
                err("auth_google: background: invalid write: %d", r);
            }
        }
        free(result);
    }
    if (!r) return;
    if (r < 0) {
        err("auth_google: background: read failed: %s", os_ErrorMsg());
        _exit(1);
    }
    err("auth_google: background: invalid length length: %d", r);
    _exit(1);
}

static int
send_background_request(
        struct auth_google_state *state,
        const unsigned char *request_id,
        const unsigned char *request_code)
{
    int retval = -1;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    char *json_s = NULL;
    size_t json_z = 0;
    FILE *json_f = open_memstream(&json_s, &json_z);
    fprintf(json_f, "{ \"request_id\" = \"%s\"", json_armor_buf(&ab, request_id));
    fprintf(json_f, ", \"request_code\" = \"%s\" }", json_armor_buf(&ab, request_code));
    fclose(json_f); json_f = NULL;
    if (json_z > 30000) {
        err("auth_google: background: request is too large: %zu", json_z);
        goto done;
    }
    unsigned length = json_z;
    unsigned char buf[32768];
    memcpy(buf, &length, sizeof(length));
    memcpy(buf + sizeof(length), json_s, length);
    length += sizeof(length);
    int r = write(state->bg_w_fd, buf, length);
    if (r < 0 && errno == EAGAIN) {
        err("auth_google: background: PIPE IS FULL");
        goto done;
    }
    if (r < 0) {
        err("auth_google: background: write error: %s", os_ErrorMsg());
        goto done;
    }
    if (r != length) {
        err("auth_google: background: invalid write: %d", r);
        goto done;
    }
    retval = 0;

done:
    html_armor_free(&ab);
    free(json_s);
    return retval;
}

static void
fd_ready_handle(struct auth_google_state *state, const char *str)
{
    cJSON *root = NULL;
    const unsigned char *request_id = NULL;
    const char *error_message = "unknown error";
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    if (!(root = cJSON_Parse(str))) {
        err("auth_google: callback: fd_ready: json parse failed");
        goto done;
    }
    if (root->type != cJSON_Object) {
        err("auth_google: callback: fd_ready: root object expected");
        goto done;
    }
    cJSON *jid = cJSON_GetObjectItem(root, "request_id");
    if (!jid || jid->type != cJSON_String) {
        err("auth_google: callback: fd_ready: invalid request_id");
        goto done;
    }
    request_id = jid->valuestring;
    cJSON *jstate = cJSON_GetObjectItem(root, "request_state");
    if (!jstate || jstate->type != cJSON_Number) {
        error_message = "invalid request_state";
        goto save_error_to_db;
    }
    int request_state = jstate->valueint;
    if (request_state != 2 && request_state != 3) {
        error_message = "invalid request_state";
        goto save_error_to_db;
    }
    if (request_state == 2) {
        cJSON *jerrmsg = cJSON_GetObjectItem(root, "error_message");
        if (jerrmsg && jerrmsg->type == cJSON_String) {
            error_message = jerrmsg->valuestring;
        }
        goto save_error_to_db;
    }

    goto done;

save_error_to_db:
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "UPDATE %soauth_stage2 SET request_state = 2, error_message = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, cmd_f, "", error_message);
    fprintf(cmd_f, ", update_time = NOW() WHERE request_id = ");
    state->mi->write_escaped_string(state->md, cmd_f, "", request_id);
    fprintf(cmd_f, " ;");
    fclose(cmd_f); cmd_f = NULL;
    state->mi->simple_query(state->md, cmd_s, cmd_z); // error is ignored
    free(cmd_s); cmd_s = NULL;

done:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    if (root) cJSON_Delete(root);
}

static void
fd_ready_callback_func(
        int fd,
        void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;
    unsigned length;
    unsigned char buf[32768];

    while (1) {
        int r = read(fd, &length, sizeof(length));
        if (r < 0 && errno == EAGAIN) break;
        if (r < 0) {
            err("auth_google: callback: fd_ready: read error: %s", os_ErrorMsg());
            break;
        }
        if (!r) {
            err("auth_google: callback: fd_ready: unexpected EOF");
            break;
        }
        if (r != sizeof(length)) {
            err("auth_google: callback: fd_ready: invalid size %d", r);
            break;
        }
        r = read(fd, buf, length);
        if (r < 0) {
            err("auth_google: callback: fd_ready: read error: %s", os_ErrorMsg());
            break;
        }
        if (!r) {
            err("auth_google: callback: fd_ready: unexpected EOF");
            break;
        }
        if (r != length) {
            err("auth_google: callback: fd_ready: invalid size %d", r);
            break;
        }
        buf[r] = 0;

        fd_ready_handle(state, buf);
    }
}

static unsigned char *
process_auth_callback_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code,
        void (*fd_register_func)(int fd, void (*callback)(int fd, void *), void *data))
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    struct oauth_stage1_internal oas1 = {};
    struct oauth_stage2_internal oas2 = {};
    unsigned char rbuf[16];
    unsigned char ebuf[32] = {};

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "SELECT * FROM %soauth_stage1 WHERE state_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, ",", state_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;

    if (state->mi->query(state->md, req_s, req_z, OAUTH_STAGE1_ROW_WIDTH) < 0) goto fail;
    free(req_s); req_s = NULL; req_z = 0;

    if (state->md->row_count > 1) {
        err("auth_google: callback: row_count == %d", state->md->row_count);
        goto fail;
    }
    if (!state->md->row_count) {
        err("auth_google: callback: state_id '%s' does not exist", state_id);
        goto fail;
    }

    if (state->mi->next_row(state->md) < 0) goto fail;
    if (state->mi->parse_spec(state->md, state->md->field_count, state->md->row, state->md->lengths,
                              OAUTH_STAGE1_ROW_WIDTH, oauth_stage1_spec, &oas1) < 0)
        goto fail;
    state->mi->free_res(state->md);

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "DELETE FROM %soauth_stage1 WHERE state_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, ",", state_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;
    if (state->mi->simple_query(state->md, req_s, req_z) , 0)
        goto fail;
    free(req_s); req_s = NULL; req_z = 0;

    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), ebuf);
    ebuf[len] = 0;
    ASSERT(len == 43);

    oas2.request_id = ebuf;
    oas2.request_code = xstrdup(code);
    oas2.cookie = oas1.cookie; oas1.cookie = NULL;
    oas2.contest_id = oas1.contest_id;
    oas2.extra_data = oas1.extra_data; oas1.extra_data = NULL;
    oas2.create_time = time(NULL);

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "INSERT INTO %soauth_stage2 VALUES ( ", state->md->table_prefix);
    state->mi->unparse_spec(state->md, req_f, OAUTH_STAGE2_ROW_WIDTH, oauth_stage2_spec, &oas2);
    fprintf(req_f, ") ;");
    fclose(req_f); req_f = NULL;
    if (state->mi->simple_query(state->md, req_s, req_z) < 0) goto fail;
    free(req_s); req_s = NULL;

    if (state->bg_w_fd < 0) {
        int p1[2];
        if (pipe2(p1, O_CLOEXEC | O_NONBLOCK) < 0) {
            err("auth_google: callback: pipe2 failed: %s", os_ErrorMsg());
            goto remove_stage2_and_fail;
        }
        int p2[2];
        if (pipe2(p2, O_CLOEXEC | O_NONBLOCK) < 0) {
            close(p1[0]); close(p1[1]);
            err("auth_google: callback: pipe2 failed: %s", os_ErrorMsg());
            goto remove_stage2_and_fail;
        }
        int pid = fork();
        if (pid < 0) {
            close(p1[0]); close(p1[1]);
            close(p2[0]); close(p2[1]);
            err("auth_google: callback: fork() failed: %s", os_ErrorMsg());
            goto remove_stage2_and_fail;
        }
        if (!pid) {
            close(p1[1]); close(p2[0]);
            do_background_oauth_queries(state, p1[0], p2[1]);
            _exit(0);
        }

        close(p1[0]); close(p2[1]);
        state->bg_w_fd = p1[1];
        state->bg_r_fd = p2[0];
        state->bg_pid = pid;
        if (fd_register_func) {
            fd_register_func(state->bg_r_fd, fd_ready_callback_func, data);
        }
    }

    if (send_background_request(state, oas2.request_id, oas2.request_code) < 0) goto fail;

    free(oas1.state_id);
    free(oas1.provider);
    free(oas1.cookie);
    free(oas1.extra_data);
    free(oas2.request_code);
    free(oas2.cookie);
    free(oas2.extra_data);

    return xstrdup(oas2.request_code);

remove_stage2_and_fail:
    state->mi->simple_fquery(state->md, "DELETE FROM %soauth_stage2 WHERE request_id = '%s' ; ", state->md->table_prefix, ebuf);

fail:
    free(oas1.state_id);
    free(oas1.provider);
    free(oas1.cookie);
    free(oas1.extra_data);
    free(oas2.request_code);
    free(oas2.cookie);
    free(oas2.extra_data);
    state->mi->free_res(state->md);
    if (req_f) fclose(req_f);
    free(req_s);
    return NULL;
}
