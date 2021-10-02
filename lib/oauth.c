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
get_provider(const unsigned char *provider)
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
        err("oauth_get_provider: auth plugin for '%s' failed to load", provider);
        info->failed = 1;
        return NULL;
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

    return info;
}

unsigned char *
oauth_get_redirect_url(
        const unsigned char *provider,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data)
{
    struct ProviderInfo *info = get_provider(provider);
    return info->i->get_redirect_url(info->d, cookie, contest_id, extra_data);
}
