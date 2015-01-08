/* -*- c -*- */
#ifndef __RUN_PACKET_H__
#define __RUN_PACKET_H__

/* Copyright (C) 2005-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>

struct run_reply_packet
{
  int judge_id;
  int contest_id;
  int run_id;
  int status;
  int failed_test;
  int tests_passed;
  int score;
  int notify_flag;
  int marked_flag;
  int has_user_score;
  int user_status;
  int user_tests_passed;
  int user_score;
  /* time when the compile request was queued by serve */
  int ts1;
  int ts1_us;
  /* time when the compile request was received by compile */
  int ts2;
  int ts2_us;
  /* time when the compile request was completed by compile */
  int ts3;
  int ts3_us;
  /* time when serve received compile reply and generated run request */
  int ts4;
  int ts4_us;
  /* time when the run request was received by run */
  int ts5;
  int ts5_us;
  /* time when the testing was completed by run */
  int ts6;
  int ts6_us;
  /* time when the report was generated */
  int ts7;
  int ts7_us;
  /* UUID of the run */
  ej_uuid_t uuid;
};

int
run_reply_packet_read(size_t in_size, const void *in_data,
                      struct run_reply_packet **p_out_data);

int
run_reply_packet_write(const struct run_reply_packet *in_data,
                       size_t *p_out_size, void **p_out_data);

struct run_reply_packet *
run_reply_packet_free(struct run_reply_packet *in_data);

void
run_reply_packet_dump(
        const struct run_reply_packet *in_data);

#endif /* __RUN_PACKET_H__ */
