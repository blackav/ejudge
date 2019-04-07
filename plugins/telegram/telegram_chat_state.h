/* -*- c -*- */
#ifndef __TELEGRAM_CHAT_STATE_H__
#define __TELEGRAM_CHAT_STATE_H__

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

struct telegram_chat_state
{
    long long _id;

    unsigned char *command;
    unsigned char *token;
    int state;
    int review_flag;
    int reply_flag;
};

struct telegram_chat_state *
telegram_chat_state_free(struct telegram_chat_state *tcs);
struct telegram_chat_state *
telegram_chat_state_create(void);
void
telegram_chat_state_reset(struct telegram_chat_state *tcs);
struct telegram_chat_state *
telegram_chat_state_parse_bson(const ej_bson_t *bson);
ej_bson_t *
telegram_chat_state_unparse_bson(const struct telegram_chat_state *tcs);

struct mongo_conn;

struct telegram_chat_state *
telegram_chat_state_fetch(struct mongo_conn *conn, long long _id);
int
telegram_chat_state_save(struct mongo_conn *conn, const struct telegram_chat_state *tcs);

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
