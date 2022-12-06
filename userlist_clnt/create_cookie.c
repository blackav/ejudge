/* -*- mode: c -*- */

/* Copyright (C) 2018-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "userlist_clnt/private.h"
#include "ejudge/userlist.h"

int
userlist_clnt_create_cookie(
        struct userlist_clnt *clnt,
        int cmd,
        const struct userlist_cookie *in_c,
        struct userlist_cookie *out_c)
{
    struct userlist_pk_cookie_login *out = NULL;
    size_t out_size = sizeof(*out);
    out = alloca(out_size);
    memset(out, 0, out_size);

    out->request_id = cmd;
    memcpy(&out->origin_ip, &in_c->ip, sizeof(out->origin_ip));
    out->ssl = in_c->ssl;
    out->contest_id = in_c->contest_id;
    out->locale_id = in_c->locale_id;
    out->cookie = in_c->cookie;           // ignored at the server side
    out->client_key = in_c->client_key;   // ignored at the server side
    out->role = in_c->role;               // ignored at the server side
    out->expire = in_c->expire;           // ignored at the server side
    out->user_id = in_c->user_id;
    out->priv_level = in_c->priv_level;   // ignored at the server side
    out->recovery = in_c->recovery;
    out->team_login = in_c->team_login;
    out->is_ws = in_c->is_ws;
    out->is_job = in_c->is_job;

    int r;
    if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) {
        return r;
    }

    void *void_in = NULL;
    size_t in_size = 0;
    if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0) {
        return r;
    }
    if (in_size < sizeof(struct userlist_packet)) {
        xfree(void_in);
        return -ULS_ERR_PROTOCOL;
    }
    struct userlist_packet *packet_in = (struct userlist_packet*) void_in;
    void_in = NULL;
    if (packet_in->id < 0) {
        if(in_size != sizeof(*packet_in)) {
            free(packet_in);
            return -ULS_ERR_PROTOCOL;
        }
        r = packet_in->id;
        xfree(packet_in);
        return r;
    }
    if (in_size < sizeof(struct userlist_pk_login_ok)) {
        free(packet_in);
        return -ULS_ERR_PROTOCOL;
    }
    if (packet_in->id != ULS_LOGIN_COOKIE) {
        free(packet_in);
        return -ULS_ERR_PROTOCOL;
    }
    struct userlist_pk_login_ok *login_in = (struct userlist_pk_login_ok*) packet_in;
    packet_in = NULL;
    if (sizeof(struct userlist_pk_login_ok) + login_in->login_len + login_in->name_len != in_size) {
        free(login_in);
        return -ULS_ERR_PROTOCOL;
    }

    memset(out_c, 0, sizeof(*out_c));
    out_c->user_id = login_in->user_id;
    out_c->cookie = login_in->cookie;
    out_c->client_key = login_in->client_key;
    out_c->contest_id = login_in->contest_id;
    out_c->locale_id = login_in->locale_id;
    out_c->priv_level = login_in->priv_level;
    out_c->role = login_in->role;
    out_c->team_login = login_in->team_login;
    out_c->expire = login_in->expire;
    out_c->is_ws = login_in->is_ws;
    out_c->is_job = login_in->is_job;

    r = login_in->reply_id;
    free(login_in);
    return r;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
