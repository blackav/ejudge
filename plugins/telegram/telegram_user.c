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

#include "telegram_user.h"

#include "ejudge/xalloc.h"

#include <string.h>

struct telegram_user *
telegram_user_free(struct telegram_user *tu)
{
    if (tu) {
        xfree(tu->username);
        xfree(tu->first_name);
        xfree(tu->last_name);
        memset(tu, 0xff, sizeof(*tu));
        xfree(tu);
    }
    return NULL;
}

struct telegram_user *
telegram_user_create(void)
{
    struct telegram_user *tu = NULL;
    XCALLOC(tu, 1);
    return tu;
}
