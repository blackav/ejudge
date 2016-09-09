/* -*- mode: c -*- */

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/telegram.h"
#include "ejudge/ej_jobs.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#endif

#include <string.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

static void
packet_handler_telegram(int uid, int argc, char **argv);

static void
periodic_handler(void *user);

struct telegram_plugin_iface plugin_sn_telegram =
{
    { /* struct common_plugin_iface */
        { /* struct ejudge_plugin_iface */
            sizeof (struct telegram_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "sn",
            "telegram",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    TELEGRAM_PLUGIN_IFACE_VERSION,
};

struct telegram_plugin_data
{
    int dummy;
};

static struct common_plugin_data *
init_func(void)
{
    struct telegram_plugin_data *state = NULL;
    XCALLOC(state, 1);
    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;

  ej_jobs_add_handler("telegram", packet_handler_telegram);
  ej_jobs_add_periodic_handler(periodic_handler, state);
  return 0;
}

/*
 * [0] - "telegram"
 * [1] - auth
 * [2] - chat_id
 * [3] - text
 * [4] - parse_mode
 */
static void
packet_handler_telegram(int uid, int argc, char **argv)
{
    CURL *curl = NULL;
    char *url_s = NULL, *post_s = NULL, *s = NULL, *resp_s = NULL;
    size_t url_z = 0, post_z = 0, resp_z = 0;
    FILE *url_f = NULL, *post_f = NULL, *resp_f = NULL;
    CURLcode res = 0;

    curl = curl_easy_init();
    if (!curl) {
        err("cannot initialize curl");
        goto cleanup;
    }

    url_f = open_memstream(&url_s, &url_z);
    fprintf(url_f, "https://api.telegram.org/bot%s/%s", argv[1], "sendMessage");
    fclose(url_f); url_f = NULL;
    post_f = open_memstream(&post_s, &post_z);
    fprintf(post_f, "chat_id=");
    s = curl_easy_escape(curl, argv[2], 0);
    fprintf(stderr, "chat_id: %s\n", s);
    fprintf(post_f, "%s", s);
    free(s);
    fprintf(post_f, "&text=");
    s = curl_easy_escape(curl, argv[3], 0);
    fprintf(post_f, "%s", s);
    free(s);
    if (argc > 4 && argv[4] && argv[4][0]) {
        fprintf(post_f, "&parse_mode=");
        s = curl_easy_escape(curl, argv[4], 0);
        fprintf(post_f, "%s", s);
        free(s);
    }
    fclose(post_f); post_f = NULL;

    resp_f = open_memstream(&resp_s, &resp_z);

    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url_s);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*) post_s);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    res = curl_easy_perform(curl);
    fclose(resp_f); resp_f = NULL;
    if (res != CURLE_OK) {
        err("curl request failed");
        goto cleanup;
    }
    fprintf(stderr, ">%s<\n", resp_s);
    free(resp_s); resp_s = NULL;

 cleanup:
    if (post_f) {
        fclose(post_f);
    }
    free(post_s);
    if (url_f) {
        fclose(url_f);
    }
    free(url_s);
    if (resp_f) {
        fclose(resp_f);
    }
    free(resp_s);
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

static void
periodic_handler(void *user)
{
    err("TIMEOUT");
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
