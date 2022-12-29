/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TELEGRAM_SUBSCRIPTION_H__
#define __TELEGRAM_SUBSCRIPTION_H__

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

#include <time.h>

/* subscriptions */
struct telegram_subscription
{
    unsigned char *_id;
    unsigned char *bot_id;
    int user_id;
    int contest_id;

    int review_flag;
    int reply_flag;
    long long chat_id;
};

struct telegram_subscription *
telegram_subscription_free(struct telegram_subscription *subscription);
struct telegram_subscription *
telegram_subscription_create(const unsigned char *bot_id, int user_id, int contest_id);

#endif
