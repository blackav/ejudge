/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TELEGRAM_CHAT_STATE_H__
#define __TELEGRAM_CHAT_STATE_H__

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

#include "ejudge/config.h"

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

#endif
