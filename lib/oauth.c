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

#include "ejudge/common_plugin.h"
#include "ejudge/auth_plugin.h"
#include "ejudge/oauth.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"
#include "ejudge/job_packet.h"

#include <string.h>

struct ProviderInfo
{
    const unsigned char *name;
    struct auth_plugin_iface *i;
    void *d;
    int failed;
};

enum { PROVIDER_COUNT = 3 };

static struct ProviderInfo providers[PROVIDER_COUNT] =
{
    { "google" },
    { "vk" },
    { "yandex" },
};

static oauth_set_command_handler_t oauth_set_command_handler_func = NULL;
static void *oauth_set_command_handler_data = NULL;

static int
send_job_packet_fwd(void *self, unsigned char **args)
{
    return send_job_packet((const struct ejudge_cfg *) self, args);
}

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
        //err("oauth_get_provider: provider '%s' not available", provider);
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

    if (info->i->set_send_job_handler) {
        info->i->set_send_job_handler(info->d, send_job_packet_fwd, (void*) config);
    }

    if (info->i->set_set_command_handler && oauth_set_command_handler_func) {
        info->i->set_set_command_handler(info->d, oauth_set_command_handler_func, oauth_set_command_handler_data);
    }

    return info;
}

static struct ProviderInfo *
get_provider_num(
        const struct ejudge_cfg *config,
        unsigned long long provider_id)
{
    if (provider_id <= 0 || provider_id > PROVIDER_COUNT) {
        err("oauth_get_provider_num: invalid provider_id %llx", provider_id);
        return NULL;
    }
    return get_provider(config, providers[provider_id - 1].name);
}

unsigned char *
oauth_get_redirect_url(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *role,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data)
{
    struct ProviderInfo *info = get_provider(config, provider);
    if (!info) return NULL;
    return info->i->get_redirect_url(info->d, cookie, provider, role, contest_id, extra_data);
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
    return info->i->process_auth_callback(info->d, state_id, code);
}

unsigned char *
oauth_server_callback_num(
        const struct ejudge_cfg *config,
        unsigned long long provider_id,
        const unsigned char *state_id,
        const unsigned char *code)
{
    struct ProviderInfo *info = get_provider_num(config, provider_id);
    if (!info) return NULL;
    return info->i->process_auth_callback(info->d, state_id, code);
}

void
oauth_free_result(struct OAuthLoginResult *res)
{
    xfree(res->provider);
    xfree(res->role);
    xfree(res->cookie);
    xfree(res->extra_data);
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
    struct ProviderInfo *info = get_provider(config, provider);
    if (!info) return (struct OAuthLoginResult) { .status = 2, .error_message = xstrdup("invalid provider") };
    return info->i->get_result(info->d, job_id);
}

void
oauth_set_set_command_handler(
        oauth_set_command_handler_t handler,
        void *data)
{
    oauth_set_command_handler_func = handler;
    oauth_set_command_handler_data = data;
}

int
oauth_start_thread(
        const struct ejudge_cfg *config,
        const unsigned char *provider)
{
    struct ProviderInfo *info = get_provider(config, provider);
    if (!info || !info->i->start_thread) return -1;
    return info->i->start_thread(info->d);
}

const unsigned char *
oauth_get_provider(
        const struct ejudge_cfg *config,
        unsigned long long provider_id)
{
    struct ProviderInfo *info = get_provider_num(config, provider_id);
    if (!info) return NULL;
    return info->name;
}

int
oauth_is_available_num(
        const struct ejudge_cfg *config,
        unsigned long long provider_id)
{
    if (provider_id <= 0 || provider_id > PROVIDER_COUNT) {
        return 0;
    }
    if (providers[provider_id - 1].failed) {
        return 0;
    }
    if (providers[provider_id - 1].d) {
        return 1;
    }
    return get_provider(config, providers[provider_id - 1].name) != NULL;
}

int
oauth_is_configured(
        const struct ejudge_cfg *config,
        const unsigned char *provider)
{
    return ejudge_cfg_get_plugin_config(config, "auth", provider) != NULL;
}
