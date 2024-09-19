/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "telegram_subscription.h"

#include "ejudge/xalloc.h"

#include <stdio.h>
#include <string.h>

struct telegram_subscription *
telegram_subscription_free(struct telegram_subscription *sub)
{
    if (sub) {
        xfree(sub->_id);
        xfree(sub->bot_id);
        memset(sub, 0xff, sizeof(*sub));
        xfree(sub);
    }
    return NULL;
}

struct telegram_subscription *
telegram_subscription_create(const unsigned char *bot_id, int user_id, int contest_id)
{
    struct telegram_subscription *sub = NULL;
    unsigned char buf[1024];

    if (!bot_id || !*bot_id || contest_id <= 0 || user_id <= 0) return NULL;
    snprintf(buf, sizeof(buf), "%s-%d-%d", bot_id, contest_id, user_id);

    XCALLOC(sub, 1);
    sub->_id = xstrdup(buf);
    sub->bot_id = xstrdup(bot_id);
    sub->user_id = user_id;
    sub->contest_id = contest_id;
    return sub;
}
