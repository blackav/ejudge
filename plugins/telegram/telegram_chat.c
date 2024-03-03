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

#include "telegram_chat.h"

#include "ejudge/xalloc.h"

#include <string.h>

struct telegram_chat *
telegram_chat_free(struct telegram_chat *tc)
{
    if (tc) {
        xfree(tc->type);
        xfree(tc->title);
        xfree(tc->username);
        xfree(tc->first_name);
        xfree(tc->last_name);
        memset(tc, 0xff, sizeof(*tc));
        xfree(tc);
    }
    return NULL;
}

struct telegram_chat *
telegram_chat_create(void)
{
    struct telegram_chat *tc = NULL;
    XCALLOC(tc, 1);
    return tc;
}
