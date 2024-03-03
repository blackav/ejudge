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

#include "telegram_pbs.h"

struct telegram_pbs *
telegram_pbs_free(struct telegram_pbs *pbs)
{
    if (pbs) {
        xfree(pbs->_id);
        xfree(pbs);
    }
    return NULL;
}

struct telegram_pbs *
telegram_pbs_create(const unsigned char *_id)
{
    struct telegram_pbs *pbs = NULL;
    XCALLOC(pbs, 1);
    pbs->_id = xstrdup(_id);
    return pbs;
}
