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

#include "ejudge/common_plugin.h"
#include "ejudge/auth_plugin.h"
#include "ejudge/oauth.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <string.h>

struct ProviderInfo
{
    const unsigned char *name;
    struct auth_plugin_iface *i;
    void *d;
    int failed;
};

enum { PROVIDER_COUNT = 1 };

static struct ProviderInfo providers[PROVIDER_COUNT] =
{
    { "google" },
};

static oauth_register_fd_func_t oauth_register_fd_func = NULL;
static void *oauth_register_fd_data = NULL;

static struct ProviderInfo *
find_provider(const unsigned char *provider)
{
    for (int i = 0; i < PROVIDER_COUNT; ++i) {
        struct ProviderInfo *info = &providers[i];
        if (!strcmp(provider, info->name)) {
            return info;
        }
    }

    return NULL;
}

static struct ProviderInfo *
get_provider(
        const struct ejudge_cfg *config,
        const unsigned char *provider)
{
    if (!provider || !*provider) {
        err("oauth_get_provider: empty provider");
        return NULL;
    }

    struct ProviderInfo *info = find_provider(provider);
    if (!info) {
        err("oauth_get_provider: invalid provider '%s'", provider);
        return NULL;
    }
    if (info->failed) {
        err("oauth_get_provider: provider '%s' not available", provider);
        return NULL;
    }
    if (info->d) return info;

    const struct common_loaded_plugin *loaded_plugin = plugin_get("auth", provider);
    if (!loaded_plugin) {
        const struct xml_tree *p;
        const struct ejudge_plugin *plg;

        // find an appropriate plugin
        for (p = config->plugin_list; p; p = p->right) {
            plg = (const struct ejudge_plugin*) p;
            if (plg->load_flag && !strcmp(plg->type, "auth")
                && !strcmp(plg->name, provider))
                break;
        }
        if (!p) {
            err("oauth_get_provider: plugin '%s' not registered", provider);
            return NULL;
        }
        loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
        if (!loaded_plugin) {
            err("oauth_get_provider: cannot load plugin '%s'", provider);
            return NULL;
        }
    }
    info->i = (struct auth_plugin_iface *) loaded_plugin->iface;
    info->d = loaded_plugin->data;
    if (info->i->open(info->d) < 0) {
        err("oauth_get_provider: auth plugin for '%s' failed to open", provider);
        info->failed = 1;
        return NULL;
    }
    if (info->i->check(info->d) < 0) {
        err("oauth_get_provider: auth plugin for '%s' failed to check", provider);
        info->failed = 1;
        return NULL;
    }
    if (info->i->set_register_fd_func) {
        info->i->set_register_fd_func(info->d, oauth_register_fd_func, oauth_register_fd_data);
    }

    return info;
}

unsigned char *
oauth_get_redirect_url(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data)
{
    struct ProviderInfo *info = get_provider(config, provider);
    if (!info) return NULL;
    return info->i->get_redirect_url(info->d, cookie, provider, contest_id, extra_data);
}

void
oauth_set_register_fd_func(oauth_register_fd_func_t func, void *data)
{
    oauth_register_fd_func = func;
    oauth_register_fd_data = data;
}

unsigned char *
oauth_server_callback(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *state_id,
        const unsigned char *code)
{
    struct ProviderInfo *info = get_provider(config, provider);
    if (!info) return NULL;
    return info->i->process_auth_callback(info->d, state_id, code, oauth_register_fd_func);
}

void
oauth_free_result(struct OAuthLoginResult *res)
{
    xfree(res->provider);
    xfree(res->email);
    xfree(res->name);
    xfree(res->access_token);
    xfree(res->id_token);
    xfree(res->error_message);
}

struct OAuthLoginResult
oauth_get_result(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *job_id)
{
    return (struct OAuthLoginResult) { .status = 2, .error_message = xstrdup("unknown error") };
}
