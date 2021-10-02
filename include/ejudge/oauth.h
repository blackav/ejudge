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
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data);

// callback called when this fd is ready for reading
typedef void (*oauth_fd_ready_callback_func)(int fd, void *data);

// function for registering callback
typedef void (*oauth_register_fd_func)(int fd, oauth_fd_ready_callback_func cb, void *data);

void
oauth_set_register_fd_func(oauth_register_fd_func func);

unsigned char *
oauth_server_callback(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *state_id,
        const unsigned char *code);

#endif /* __OAUTH_H__ */
