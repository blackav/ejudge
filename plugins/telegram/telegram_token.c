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

#include "ejudge/xalloc.h"

#include "telegram_token.h"

struct telegram_token *
telegram_token_free(struct telegram_token *token)
{
    if (token) {
        xfree(token->bot_id);
        xfree(token->user_login);
        xfree(token->user_name);
        xfree(token->contest_name);
        xfree(token->token);
        xfree(token);
    }
    return NULL;
}

struct telegram_token *
telegram_token_create(void)
{
    struct telegram_token *token = NULL;
    XCALLOC(token, 1);
    return token;
}
