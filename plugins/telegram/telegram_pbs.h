/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TELEGRAM_PBS_H__
#define __TELEGRAM_PBS_H__

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

/* persistent bot state for telegram bot */
struct telegram_pbs
{
    unsigned char *_id; // same as bot_id
    long long update_id;
};

struct telegram_pbs *
telegram_pbs_free(struct telegram_pbs *pbs);
struct telegram_pbs *
telegram_pbs_create(const unsigned char *_id);

#endif
