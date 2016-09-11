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

#include "ejudge/bson_utils.h"
#include "ejudge/xalloc.h"

#include "telegram_token.h"

#include <mongo.h>

struct telegram_token *
telegram_token_free(struct telegram_token *token)
{
    if (token) {
        xfree(token->_id);
        xfree(token->bot_id);
        xfree(token->user_login);
        xfree(token->user_name);
        xfree(token->token);
        xfree(token);
    }
    return NULL;
}

struct telegram_token *
telegram_token_parse_bson(struct _bson *bson)
{
    struct telegram_token *token = NULL;
    bson_cursor *bc = NULL;

    XCALLOC(token, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_string(bc, "_id", &token->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "bot_id")) {
            if (ej_bson_parse_string(bc, "bot_id", &token->bot_id) < 0) goto cleanup;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int(bc, "user_id", &token->user_id, 1, 1, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "user_login")) {
            if (ej_bson_parse_string(bc, "user_login", &token->user_login) < 0) goto cleanup;
        } else if (!strcmp(key, "user_name")) {
            if (ej_bson_parse_string(bc, "user_name", &token->user_name) < 0) goto cleanup;
        } else if (!strcmp(key, "token")) {
            if (ej_bson_parse_string(bc, "token", &token->token) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int(bc, "contest_id", &token->contest_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "locale_id")) {
            if (ej_bson_parse_int(bc, "locale_id", &token->locale_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "expiry_time")) {
            if (ej_bson_parse_utc_datetime(bc, "expiry_time", &token->expiry_time) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return token;

cleanup:
    telegram_token_free(token);
    return NULL;
}

struct telegram_token *
telegram_token_create(void)
{
    struct telegram_token *token = NULL;
    XCALLOC(token, 1);
    return token;
}

struct _bson *
telegram_token_unparse_bson(const struct telegram_token *token)
{
    if (!token) return NULL;

    bson *b = bson_new();
    if (token->_id && *token->_id) {
        bson_append_string(b, "_id", token->_id, strlen(token->_id));
    }
    if (token->bot_id && *token->bot_id) {
        bson_append_string(b, "bot_id", token->bot_id, strlen(token->bot_id));
    }
    if (token->user_id > 0) {
        bson_append_int32(b, "user_id", token->user_id);
    }
    if (token->user_login && *token->user_login) {
        bson_append_string(b, "user_login", token->user_login, strlen(token->user_login));
    }
    if (token->user_name && *token->user_name) {
        bson_append_string(b, "user_name", token->user_name, strlen(token->user_name));
    }
    if (token->token && *token->token) {
        bson_append_string(b, "token", token->token, strlen(token->token));
    }
    if (token->contest_id > 0) {
        bson_append_int32(b, "contest_id", token->contest_id);
    }
    if (token->locale_id > 0) {
        bson_append_int32(b, "locale_id", token->locale_id);
    }
    if (token->expiry_time > 0) {
        bson_append_utc_datetime(b, "expiry_time", 1000LL * token->expiry_time);
    }
    bson_finish(b);
    return b;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
