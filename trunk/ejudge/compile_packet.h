/* -*- c -*- */
/* $Id$ */
#ifndef __COMPILE_PACKET_H__
#define __COMPILE_PACKET_H__

/* Copyright (C) 2005,2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "serve_state.h"

#include <stdlib.h>

struct compile_request_packet
{
  int judge_id;
  int contest_id;
  int run_id;
  int lang_id;
  int locale_id;
  int output_only;
  int ts1;
  int ts1_us;
  int run_block_len;
  void *run_block;
  int env_num;
  unsigned char **env_vars;
};

struct compile_reply_packet
{
  int judge_id;
  int contest_id;
  int run_id;
  int status;
  /* time when the compile request was queued by serve */
  int ts1;
  int ts1_us;
  /* time when the compile request was received by compile */
  int ts2;
  int ts2_us;
  /* time when the compile request was completed by compile */
  int ts3;
  int ts3_us;
  int run_block_len;
  void *run_block;
};

int
compile_request_packet_read(const serve_state_t,
                            size_t in_size, const void *in_data,
                            struct compile_request_packet **p_out_data);

int
compile_request_packet_write(const struct compile_request_packet *in_data,
                             size_t *p_out_size, void **p_out_data);

struct compile_request_packet *
compile_request_packet_free(struct compile_request_packet *in_data);

int
compile_reply_packet_read(size_t in_size, const void *in_data,
                          struct compile_reply_packet **p_out_data);

int
compile_reply_packet_write(const struct compile_reply_packet *in_data,
                           size_t *p_out_size, void **p_out_data);

struct compile_reply_packet *
compile_reply_packet_free(struct compile_reply_packet *in_data);

#endif /* __COMPILE_PACKET_H__ */
