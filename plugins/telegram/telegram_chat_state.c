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

#include "telegram_chat_state.h"

#include "ejudge/xalloc.h"

#include <string.h>

struct telegram_chat_state *
telegram_chat_state_free(struct telegram_chat_state *tcs)
{
    if (tcs) {
        memset(tcs, 0xff, sizeof(*tcs));
        xfree(tcs);
    }
    return NULL;
}

struct telegram_chat_state *
telegram_chat_state_create(void)
{
    struct telegram_chat_state *tcs = NULL;
    XCALLOC(tcs, 1);
    return tcs;
}

void
telegram_chat_state_reset(struct telegram_chat_state *tcs)
{
    xfree(tcs->command); tcs->command = NULL;
    xfree(tcs->token); tcs->token = NULL;
    tcs->state = 0;
    tcs->review_flag = 0;
    tcs->reply_flag = 0;
}
