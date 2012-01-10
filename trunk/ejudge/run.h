/* -*- c -*- */
/* $Id$ */
#ifndef __RUN_H__
#define __RUN_H__

/* Copyright (C) 2010-2012 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>

struct serve_state;
struct run_request_packet;
struct run_reply_packet;
struct section_global_data;
struct section_problem_data;
struct super_run_in_packet;

void
run_inverse_testing(
        struct serve_state *state,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        struct section_problem_data *prob,
        const unsigned char *pkt_name,
        unsigned char *report_path,
        size_t report_path_size,
        int utf8_mode,
        int scoring_system);

#endif /* __RUN_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
