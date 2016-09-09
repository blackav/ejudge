/* -*- c -*- */
#ifndef __EJ_JOBS_H__
#define __EJ_JOBS_H__

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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

void
ej_jobs_add_handler(
        const char *cmd,
        void (*handler)(int, int, char **, void *),
        void *user);
void
ej_jobs_remove_handler(const char *cmd);
void
ej_jobs_add_periodic_handler(
        void (*handler)(void *user),
        void *user);

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
