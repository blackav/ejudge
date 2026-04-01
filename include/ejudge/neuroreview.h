/* -*- c -*- */
#ifndef __NEUROREVIEW_H__
#define __NEUROREVIEW_H__

/* Copyright (C) 2000-2025 Alexander Chernov <cher@ejudge.ru> */

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


#include "ejudge/ej_types.h"
#include "ejudge/new-server.h"

struct neuroreview_review_state {
    const serve_state_t cs;
    int run_id;
    ej_uuid_t run_uuid;
    ej_ip_t ip;
    int ssl_flag;
    int run_user_id;
    int request_user_id;
    int locale_id;

    // fills automatically
    ej_uuid_t uuid;
};

void neuroreview_init_manager();

void neuroreview_stop_manager();


int neuroreview_send_review(struct neuroreview_review_state state, const char *prob_statement, const char *run_text);

#endif /* __NEUROREVIEW_H__ */
