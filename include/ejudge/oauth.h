/* -*- c -*- */

#ifndef __OAUTH_H__
#define __OAUTH_H__

/* Copyright (C) 2021 Alexander Chernov <cher@ejudge.ru> */

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

unsigned char *
oauth_get_redirect_url(
        const unsigned char *provider,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data);

#endif /* __OAUTH_H__ */
