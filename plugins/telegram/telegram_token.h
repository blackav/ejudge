/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TELEGRAM_TOKEN_H__
#define __TELEGRAM_TOKEN_H__

/* Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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
telegram_token_create(void);

#endif
