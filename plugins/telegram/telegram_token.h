/* -*- c -*- */
#ifndef __TELEGRAM_TOKEN_H__
#define __TELEGRAM_TOKEN_H__

/* Copyright (C) 2016-2019 Alexander Chernov <cher@ejudge.ru> */

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

#if HAVE_LIBMONGOC - 0 > 0
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
struct _bson;
typedef struct _bson ej_bson_t;
#endif

#include <time.h>

/* tokens for bot interaction */
struct telegram_token
{
    unsigned char _id[12]; // ObjectId

    unsigned char *bot_id;
    int user_id;
    unsigned char *user_login;
    unsigned char *user_name;
    unsigned char *token;
    int contest_id;
    unsigned char *contest_name;
    int locale_id;
    time_t expiry_time;
};

struct telegram_token *
telegram_token_free(struct telegram_token *token);
struct telegram_token *
telegram_token_parse_bson(const ej_bson_t *bson);
struct telegram_token *
telegram_token_create(void);
ej_bson_t *
telegram_token_unparse_bson(const struct telegram_token *token);

struct mongo_conn;

void
telegram_token_remove_expired(struct mongo_conn *conn, time_t current_time);
void
telegram_token_remove(struct mongo_conn *conn, const unsigned char *token);
int
telegram_token_fetch(struct mongo_conn *conn, const unsigned char *token_str, struct telegram_token **p_token);
int
telegram_token_save(struct mongo_conn *conn, const struct telegram_token *token);

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
