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

#include "ejudge/session_cache.h"
#include "ejudge/metrics_contest.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

enum { XREHASH_OFFSET = 37 };

static const int primes[] =
{
  4099,
  8209,
  16411,
  32771,
  65537,
  131101,
  262147,
  524309,
  1048583,
  2097169,
  4194319,
  8388617,
  16777259,
  33554467,
  67108864,
  134217728,
  0,
};

static void
nsc_init(struct new_session_cache *nsc)
{
    memset(nsc, 0, sizeof(*nsc));
    nsc->res_index = 0;
    nsc->reserved = primes[nsc->res_index];
    nsc->rehash_threshold = nsc->reserved / 2;
    nsc->info = calloc(nsc->reserved, sizeof(nsc->info[0]));
}

static void
tc_init(struct token_cache *tc)
{
    memset(tc, 0, sizeof(*tc));
    tc->res_index = 0;
    tc->reserved = primes[tc->res_index];
    tc->rehash_threshold = tc->reserved / 2;
    tc->info = calloc(tc->reserved, sizeof(tc->info[0]));
}

void
idc_init(struct id_cache *idc)
{
    nsc_init(&idc->s);
    tc_init(&idc->t);
}

static inline int
nsc_initial_hash(uint64_t s, uint64_t k, int modulo)
{
    return (int) ((s ^ k) % modulo);
}

static inline int
tc_initial_hash(const unsigned char *p, unsigned int key_contest_id, int modulo)
{
    // 256-bit hash
    const uint64_t *p64 = (const uint64_t *) p;
    uint64_t v = p64[0] + p64[1] + p64[2] + p64[3] + (((unsigned long long) (key_contest_id)) << 32U);
    return (int) (v % modulo);
}

static void
nsc_rehash(struct new_session_cache *nsc)
{
    int new_reserved = primes[nsc->res_index + 1];
    struct new_session_info *new_info = calloc(new_reserved, sizeof(new_info[0]));
    for (int i = 0; i < nsc->reserved; ++i) {
        struct new_session_info *oi = &nsc->info[i];
        if (oi->session_id || oi->client_key) {
            int index = nsc_initial_hash(oi->session_id, oi->client_key, new_reserved);
            struct new_session_info *ni = &new_info[index];
            while (ni->session_id || ni->client_key) {
                index += XREHASH_OFFSET;
                if (index >= new_reserved) index -= new_reserved;
                ni = &new_info[index];
            }
            *ni = *oi;
        }
    }
    free(nsc->info);
    ++nsc->res_index;
    nsc->reserved = new_reserved;
    nsc->rehash_threshold = new_reserved / 2;
    nsc->info = new_info;
}

static void
nsc_rehash_chain(struct new_session_cache *nsc, int index)
{
    int count = 0;
    int cur_index = index;
    struct new_session_info *cur = &nsc->info[cur_index];
    while (cur->session_id || cur->client_key) {
        ++count;
        cur_index += XREHASH_OFFSET;
        if (cur_index >= nsc->reserved) cur_index -= nsc->reserved;
        cur = &nsc->info[cur_index];
    }
    if (count > 0) {
        int need_free = 0;
        struct new_session_info *saved = NULL;
        if (count < 0) {
            saved = alloca(count * sizeof(saved[0]));
        } else {
            saved = calloc(count, sizeof(saved[0]));
            need_free = 1;
        }
        int i = 0;
        cur = &nsc->info[index];
        cur_index = index;
        while (cur->session_id || cur->client_key) {
            saved[i++] = *cur;
            memset(cur, 0, sizeof(*cur));
            cur_index += XREHASH_OFFSET;
            if (cur_index >= nsc->reserved) cur_index -= nsc->reserved;
            cur = &nsc->info[cur_index];
        }
        for (i = 0; i < count; ++i) {
            int ii = nsc_initial_hash(saved[i].session_id, saved[i].client_key, nsc->reserved);
            struct new_session_info *ni = &nsc->info[ii];
            while (ni->session_id || ni->client_key) {
                ii += XREHASH_OFFSET;
                if (ii >= nsc->reserved) ii -= nsc->reserved;
                ni = &nsc->info[ii];
            }
            *ni = saved[i];
        }
        if (need_free) {
            free(saved);
        }
    }
}

struct new_session_info *
nsc_find(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key)
{
    int index = nsc_initial_hash(session_id, client_key, nsc->reserved);
    struct new_session_info *cur = &nsc->info[index];
    while (1) {
        if (!cur->session_id && !cur->client_key) return NULL;
        if (cur->session_id == session_id && cur->client_key == client_key) return cur;
        index += XREHASH_OFFSET;
        if (index >= nsc->reserved) index -= nsc->reserved;
        //index %= nsc->reserved;
        cur = &nsc->info[index];
    }
}

struct new_session_info *
nsc_insert(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key)
{
    if (nsc->used == nsc->rehash_threshold) {
        nsc_rehash(nsc);
    }
    int index = nsc_initial_hash(session_id, client_key, nsc->reserved);
    struct new_session_info *cur = &nsc->info[index];
    while (1) {
        if (!cur->session_id && !cur->client_key) break;
        if (cur->session_id == session_id && cur->client_key == client_key) return cur;
        index += XREHASH_OFFSET;
        if (index >= nsc->reserved) index -= nsc->reserved;
        cur = &nsc->info[index];
    }
    cur->session_id = session_id;
    cur->client_key = client_key;
    ++nsc->used;
    if (metrics.data) {
        metrics.data->cookie_cache_size = nsc->used;
    }
    return cur;
}

int
nsc_remove(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key, struct new_session_info *out)
{
    int index = nsc_initial_hash(session_id, client_key, nsc->reserved);
    struct new_session_info *cur = &nsc->info[index];
    while (1) {
        if (!cur->session_id && !cur->client_key) {
            // item not found
            return 0;
        }
        if (cur->session_id == session_id && cur->client_key == client_key) break;
        index += XREHASH_OFFSET;
        if (index >= nsc->reserved) index -= nsc->reserved;
        cur = &nsc->info[index];
    }
    --nsc->used;
    if (metrics.data) {
        metrics.data->cookie_cache_size = nsc->used;
    }
    if (out) {
        *out = *cur;
    }
    memset(cur, 0, sizeof(*cur));
    index += XREHASH_OFFSET;
    if (index >= nsc->reserved) index -= nsc->reserved;
    nsc_rehash_chain(nsc, index);
    return 1;
}

void
nsc_clear(struct new_session_cache *nsc)
{
    for (int i = 0; i < nsc->reserved; ++i) {
        free(nsc->info[i].login);
        free(nsc->info[i].name);
    }
    memset(nsc->info, 0, nsc->reserved * sizeof(nsc->info[0]));
    nsc->used = 0;
}

enum { REMOVE_EXPIRED_TIMEOUT = 12 * 60 * 60 };

void
nsc_remove_expired(struct new_session_cache *nsc, time_t cur_time)
{
    if (cur_time <= 0) cur_time = time(NULL);

    for (int i = 0; i < nsc->reserved; ) {
        struct new_session_info *nsi = &nsc->info[i];
        if ((nsi->session_id || nsi->client_key)
            && ((nsi->expire_time > 0 && nsi->expire_time <= cur_time)
                || nsi->access_time + REMOVE_EXPIRED_TIMEOUT <= cur_time)) {
            struct new_session_info rmitem;
            if (nsc_remove(nsc, nsi->session_id, nsi->client_key, &rmitem)) {
                free(rmitem.login);
                free(rmitem.name);
            }
        } else {
            ++i;
        }
    }
}

static void
tc_rehash(struct token_cache *tc)
{
    int new_reserved = primes[tc->res_index + 1];
    struct cached_token_info *new_info = calloc(new_reserved, sizeof(new_info[0]));
    for (int i = 0; i < tc->reserved; ++i) {
        struct cached_token_info *oi = &tc->info[i];
        if (oi->used) {
            int index = tc_initial_hash(oi->token, oi->key_contest_id, new_reserved);
            struct cached_token_info *ni = &new_info[index];
            while (ni->used) {
                index += XREHASH_OFFSET;
                if (index >= new_reserved) index -= new_reserved;
                ni = &new_info[index];
            }
            *ni = *oi;
        }
    }
    free(tc->info);
    ++tc->res_index;
    tc->reserved = new_reserved;
    tc->rehash_threshold = new_reserved / 2;
    tc->info = new_info;
}

static void
tc_rehash_chain(struct token_cache *tc, int index)
{
    int count = 0;
    int cur_index = index;
    struct cached_token_info *cur = &tc->info[cur_index];
    while (cur->used) {
        ++count;
        cur_index += XREHASH_OFFSET;
        if (cur_index >= tc->reserved) cur_index -= tc->reserved;
        cur = &tc->info[cur_index];
    }
    if (count > 0) {
        int need_free = 0;
        struct cached_token_info *saved = NULL;
        if (count < 128) {
            saved = alloca(count * sizeof(saved[0]));
        } else {
            saved = calloc(count, sizeof(saved[0]));
            need_free = 1;
        }
        int i = 0;
        cur = &tc->info[index];
        cur_index = index;
        while (cur->used) {
            saved[i++] = *cur;
            memset(cur, 0, sizeof(*cur));
            cur_index += XREHASH_OFFSET;
            if (cur_index >= tc->reserved) cur_index -= tc->reserved;
            cur = &tc->info[cur_index];
        }
        for (i = 0; i < count; ++i) {
            int ii = tc_initial_hash(saved[i].token, saved[i].key_contest_id, tc->reserved);
            struct cached_token_info *ni = &tc->info[ii];
            while (ni->used) {
                ii += XREHASH_OFFSET;
                if (ii >= tc->reserved) ii -= tc->reserved;
                ni = &tc->info[ii];
            }
            *ni = saved[i];
        }
        if (need_free) {
            free(saved);
        }
    }
}

struct cached_token_info *
tc_find(struct token_cache *tc, const unsigned char *token, unsigned int key_contest_id)
{
    int index = tc_initial_hash(token, key_contest_id, tc->reserved);
    struct cached_token_info *cur = &tc->info[index];
    while (1) {
        if (!cur->used) return NULL;
        if (!memcmp(token, cur->token, 32) && key_contest_id == cur->key_contest_id) return cur;
        index += XREHASH_OFFSET;
        if (index >= tc->reserved) index -= tc->reserved;
        cur = &tc->info[index];
    }
}

struct cached_token_info *
tc_insert(struct token_cache *tc, const unsigned char *token, unsigned int key_contest_id)
{
    if (tc->used == tc->rehash_threshold) {
        tc_rehash(tc);
    }
    int index = tc_initial_hash(token, key_contest_id, tc->reserved);
    struct cached_token_info *cur = &tc->info[index];
    while (1) {
        if (!cur->used) break;
        if (!memcmp(token, cur->token, 32) && key_contest_id == cur->key_contest_id) return cur;
        index += XREHASH_OFFSET;
        if (index >= tc->reserved) index -= tc->reserved;
        cur = &tc->info[index];
    }
    memcpy(cur->token, token, 32);
    cur->key_contest_id = key_contest_id;
    cur->used = 1;
    ++tc->used;
    if (metrics.data) {
        metrics.data->key_cache_size = tc->used;
    }
    return cur;
}

int
tc_remove(
        struct token_cache *tc,
        const unsigned char *token,
        unsigned int key_contest_id,
        struct cached_token_info *out)
{
    int index = tc_initial_hash(token, key_contest_id, tc->reserved);
    struct cached_token_info *cur = &tc->info[index];
    while (1) {
        if (!cur->used) {
            // item not found
            return 0;
        }
        if (!memcmp(cur->token, token, 32) && cur->key_contest_id == key_contest_id) break;
        index += XREHASH_OFFSET;
        if (index >= tc->reserved) index -= tc->reserved;
        cur = &tc->info[index];
    }
    --tc->used;
    if (metrics.data) {
        metrics.data->key_cache_size = tc->used;
    }
    if (out) {
        *out = *cur;
    }
    memset(cur, 0, sizeof(*cur));
    index += XREHASH_OFFSET;
    if (index >= tc->reserved) index -= tc->reserved;
    tc_rehash_chain(tc, index);
    return 1;
}

void
tc_clear(struct token_cache *tc)
{
    for (int i = 0; i < tc->reserved; ++i) {
        free(tc->info[i].login);
        free(tc->info[i].name);
    }
    memset(tc->info, 0, tc->reserved * sizeof(tc->info[0]));
    tc->used = 0;
}

enum { TOKEN_REMOVE_EXPIRED_TIMEOUT = 48 * 60 * 60 };

void
tc_remove_expired(struct token_cache *tc, time_t cur_time)
{
    if (cur_time <= 0) cur_time = time(NULL);

    for (int i = 0; i < tc->reserved; ) {
        struct cached_token_info *cti = &tc->info[i];
        if (cti->used
            && ((cti->expiry_time > 0 && cti->expiry_time <= cur_time)
                || cti->access_time + TOKEN_REMOVE_EXPIRED_TIMEOUT <= cur_time)) {
            struct cached_token_info rmitem;
            if (tc_remove(tc, cti->token, cti->key_contest_id, &rmitem)) {
                free(rmitem.login);
                free(rmitem.name);
            }
        } else {
            ++i;
        }
    }
}
