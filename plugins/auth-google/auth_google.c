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
#include "../common-mysql/common_mysql.h"

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
static unsigned char *
get_redirect_url_func(
        void *data,
        const char *cookie,
        int contest_id,
        const char *extra_data);

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
};

struct auth_google_state
{
    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;
    // curl for auth endpoint discovery
    CURL *curl;
    char *authorization_endpoint;

    unsigned char *client_id;
    unsigned char *redirect_uri;
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_google_state *state;

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
    ASSERT(tree->tag == xml_err_spec->default_elem);
    ASSERT(!strcmp(tree->name[0], "config"));

    for (struct xml_tree *p = tree->first_down; p; p = p->right) {
        ASSERT(p->tag == xml_err_spec->default_elem);

        if (!strcmp(p->name[0], "client_id")) {
            if (xml_leaf_elem(p, &state->client_id, 1, 0) < 0) return -1;
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

    if (!state->md->conn) return -1;

    if (state->mi->simple_fquery(state->md, "SELECT config_val FROM %sconfig WHERE config_key = 'ga_version' ;", state->md->table_prefix) < 0) {
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
        if (state->mi->simple_fquery(state->md, "CREATE TABLE %sga_state ( state_id VARCHAR(64) NOT NULL PRIMARY KEY, cookie VARCHAR(64) NOT NULL, contest_id INT NOT NULL DEFAULT 0, extra_data VARCHAR(512) DEFAULT NULL, create_time DATETIME NOT NULL, expiry_time DATETIME NOT NULL ) DEFAULT CHARSET=utf8 COLLATE=utf8_bin;",
                                     state->md->table_prefix) < 0)
            return -1;
        if (state->mi->simple_fquery(state->md, "INSERT INTO %sconfig SET config_key='ga_version', config_val='%d';",
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
    fprintf(req_f, "INSERT INTO %sga_state VALUES (", state->md->table_prefix);
    fprintf(req_f, "'%s'", ebuf);
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
    fprintf(url_f, "&redirect_uri=%s", url_armor_buf(&ab, state->redirect_uri));
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
