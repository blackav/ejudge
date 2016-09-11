/* -*- c -*- */
#ifndef __TELEGRAM_CHAT_STATE_H__
#define __TELEGRAM_CHAT_STATE_H__

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

struct _bson;

struct telegram_chat_state
{
    long long _id;
};

struct telegram_chat_state *
telegram_chat_state_free(struct telegram_chat_state *tcs);
struct telegram_chat_state *
telegram_chat_state_create(void);
struct telegram_chat_state *
telegram_chat_state_parse_bson(struct _bson *bson);
struct _bson *
telegram_chat_state_unparse_bson(const struct telegram_chat_state *tcs);

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
