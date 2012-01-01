/* -*- c -*- */
/* $Id$ */

#ifndef __POLLFDS_H__
#define __POLLFDS_H__

/* Copyright (C) 2012 Alexander Chernov <cher@ejudge.ru> */

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

struct pollfds;
typedef struct pollfds pollfds_t;

pollfds_t *pollfds_create(void);
pollfds_t *pollfds_free(pollfds_t *pl);
void pollfds_clear(pollfds_t *pl);

typedef void (*pollfds_callback_t)(void *cntx, void *fd, void *user);

void pollfds_add(
        pollfds_t *pl,
        int fd,
        int events,
        pollfds_callback_t callback,
        void *user);

int
pollfds_poll(
        pollfds_t *pl,
        long timeout_ms,
        const void *mask);

void
pollfds_call_handlers(
        pollfds_t *pl,
        void *context);

#endif /* __POLLIST_H__ */
