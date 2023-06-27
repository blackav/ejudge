/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/notify_plugin.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <hiredis/hiredis.h>

#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

enum { REGISTERED_NUMBER = 1 };

struct notify_redis_plugin_data
{
    struct notify_plugin_data b;

    int show_queries;
    unsigned char *host;
    int port;
    unsigned char *passwd_file;

    unsigned char *user;
    unsigned char *passwd;

    redisContext *cntx;
};

extern struct notify_plugin_iface plugin_notify_redis;

static struct common_plugin_data *
init_func(void)
{
    struct notify_redis_plugin_data *state = NULL;
    XCALLOC(state, 1);
    state->b.vt = &plugin_notify_redis;
    return &state->b.b;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
read_string(
        FILE *f,
        unsigned char *buf,
        size_t size,
        const unsigned char *file,
        const unsigned char *name,
        int eof_is_ok)
{
    const unsigned char *fname = __FUNCTION__;

    if (!fgets(buf, size, f)) {
        if (eof_is_ok) return 0;
        err("%s: unexpected EOF reading %s from %s", fname, name, file);
        return -1;
    }

    int len = strlen(buf);
    if (len + 24 > (int) size) {
        err("%s: line %s is too long in file %s", fname, name, file);
        return -1;
    }
    while (len > 0 && isspace((unsigned char) buf[len - 1])) { --len; }
    buf[len] = 0;
    return 1;
}

static int
parse_passwd_file(
        struct notify_redis_plugin_data *nrpd,
        const unsigned char *file)
{
    unsigned char path[PATH_MAX];
    __attribute__((unused)) int _;
    FILE *f = NULL;
    const unsigned char *fname = __FUNCTION__;

    path[0] = 0;
    if (os_IsAbsolutePath(file)) {
        _ = snprintf(path, sizeof(path), "%s", file);
    }
#if defined EJUDGE_CONF_DIR
    if (!path[0]) {
        _ = snprintf(path, sizeof(path), "%s/%s", EJUDGE_CONF_DIR, file);
    }
#endif
    if (!path[0]) {
      _ = snprintf(path, sizeof(path), "%s", file);
    }

    if (!(f = fopen(path, "r"))) {
        err("%s: cannot open password file %s: %s", fname, path, os_ErrorMsg());
        goto cleanup;
    }

    unsigned char buser[1024];
    unsigned char bpwd[1024];
    unsigned char bhost[1024];
    unsigned char bport[1024];

    if (read_string(f, buser, sizeof(buser), path, "user", 0) < 0) {
        goto cleanup;
    }
    if (buser[0]) {
        nrpd->user = strdup(buser);
    }
    if (read_string(f, bpwd, sizeof(bpwd), path, "password", 0) < 0) {
        goto cleanup;
    }
    if (bpwd[0]) {
        nrpd->passwd = strdup(bpwd);
    }
    if (read_string(f, bhost, sizeof(bhost), path, "host", 1) > 0) {
        if (bhost[0]) {
            nrpd->host = strdup(bhost);
        }
        if (read_string(f, bport, sizeof(bport), path, "port", 1) > 0) {
            if (bport[0]) {
                errno = 0;
                char *eptr = NULL;
                long v = strtol(bport, &eptr, 10);
                if (errno || *eptr || (char*) bport == eptr || v < 0 || v >= 65536) {
                    err("%s: invalid port value in %s", fname, path);
                    goto cleanup;
                }
                nrpd->port = v;
            }
        }
    }
    fclose(f); f = NULL;

    return 0;

cleanup:;
    if (f) fclose(f);
    return -1;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct notify_redis_plugin_data *nrpd = (struct notify_redis_plugin_data*) data;
    __attribute__((unused)) const struct xml_parse_spec *spec = ejudge_cfg_get_spec();
    struct xml_tree *p = 0;
    const struct xml_attr *a = 0;

    ASSERT(tree->tag == spec->default_elem);
    ASSERT(!strcmp(tree->name[0], "config"));

    for (a = tree->first; a; a = a->next) {
        ASSERT(a->tag == spec->default_attr);
        if (!strcmp(a->name[0], "show_queries")) {
            if (xml_attr_bool(a, &nrpd->show_queries) < 0) return -1;
        } else {
            return xml_err_attr_not_allowed(tree, a);
        }
    }

    for (p = tree->first_down; p; p = p->right) {
        ASSERT(p->tag == spec->default_elem);
        if (!strcmp(p->name[0], "host")) {
            if (xml_leaf_elem(p, &nrpd->host, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "port")) {
            if (p->first) return xml_err_attrs(p);
            if (p->first_down) return xml_err_nested_elems(p);
            if (nrpd->port > 0) return xml_err_elem_redefined(p);
            if (xml_parse_int(NULL, "", p->line, p->column, p->text,
                              &nrpd->port) < 0) return -1;
        } else if (!strcmp(p->name[0], "password_file")) {
            if (xml_leaf_elem(p, &nrpd->passwd_file, 1, 0) < 0) return -1;
        } else {
            return xml_err_elem_not_allowed(p);
        }
    }

    if (nrpd->passwd_file && nrpd->passwd_file[0]) {
        if (parse_passwd_file(nrpd, nrpd->passwd_file) < 0) {
            return -1;
        }
    }

    if (!nrpd->host || !nrpd->host[0]) {
        free(nrpd->host);
        nrpd->host = strdup("localhost");
    }
    if (nrpd->port <= 0) {
        nrpd->port = 6379;
    }

    return 0;
}

static int
get_registered_number_func(
        struct notify_plugin_data *data)
{
    __attribute__((unused)) struct notify_redis_plugin_data *nrpd = (struct notify_redis_plugin_data*) data;

    return 1;
}

static int
notify_func(
        struct notify_plugin_data *data,
        const unsigned char *queue,
        const unsigned char *message)
{
    struct notify_redis_plugin_data *nrpd = (struct notify_redis_plugin_data*) data;
    const unsigned char *fname = __FUNCTION__;

    if (!nrpd->cntx) {
        nrpd->cntx = redisConnect(nrpd->host, nrpd->port);
        if (!nrpd->cntx) {
            err("%s: failed to allocate redis context", fname);
            return -1;
        }
        if (nrpd->cntx->err) {
            err("%s: redis connect error: %s", fname, nrpd->cntx->errstr);
            redisFree(nrpd->cntx); nrpd->cntx = NULL;
            return -1;
        }
        if (nrpd->passwd && nrpd->passwd[0]) {
            int auth_count = 1;
            const char *auth_args[4] =
            {
                "AUTH"
            };
            if (nrpd->user && nrpd->user[0]) {
                auth_args[1] = nrpd->user;
                auth_args[2] = nrpd->passwd;
                auth_args[3] = NULL;
                auth_count = 3;
                if (nrpd->show_queries) {
                    info("REDIS: (%s)(%s)(%s)", auth_args[0], auth_args[1], auth_args[2]);
                }
            } else {
                auth_args[1] = nrpd->passwd;
                auth_args[2] = NULL;
                auth_count = 2;
                if (nrpd->show_queries) {
                    info("REDIS: (%s)(%s)", auth_args[0], auth_args[1]);
                }
            }
            redisReply *ar = redisCommandArgv(nrpd->cntx, auth_count, auth_args, NULL);
            if (nrpd->cntx->err) {
                err("%s: redis auth error: %s", fname, nrpd->cntx->errstr);
                freeReplyObject(ar);
                redisFree(nrpd->cntx); nrpd->cntx = NULL;
                return -1;
            }
            if (ar == NULL) {
                err("%s: redis auth returned NULL", fname);
                freeReplyObject(ar);
                redisFree(nrpd->cntx); nrpd->cntx = NULL;
                return -1;
            }
            if (ar->type == REDIS_REPLY_ERROR) {
                err("%s: redis auth error: %s", fname, ar->str);
                freeReplyObject(ar);
                redisFree(nrpd->cntx); nrpd->cntx = NULL;
                return -1;
            }
            freeReplyObject(ar);
        }
    }

    int pub_count = 3;
    const char *pub_args[4] =
    {
        "PUBLISH",
        queue,
        message,
        NULL,
    };
    if (nrpd->show_queries) {
        info("REDIS: (%s)(%s)(%s)", pub_args[0], pub_args[1], pub_args[2]);
    }
    redisReply *r = redisCommandArgv(nrpd->cntx, pub_count, pub_args, NULL);
    if (nrpd->cntx->err) {
        err("%s: redis publish error: %s", fname, nrpd->cntx->errstr);
        freeReplyObject(r);
        return -1;
    }
    if (r == NULL) {
        err("%s: redis publish returned NULL", fname);
        freeReplyObject(r);
        return -1;
    }
    if (r->type == REDIS_REPLY_ERROR) {
        err("%s: redis publish error: %s", fname, r->str);
        freeReplyObject(r);
        return -1;
    }

    freeReplyObject(r);

    return 0;
}

struct notify_plugin_iface plugin_notify_redis =
{
    {
        {
            sizeof (struct notify_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "notify",
            "redis",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    NOTIFY_PLUGIN_IFACE_VERSION,
    get_registered_number_func,
    notify_func,
};
