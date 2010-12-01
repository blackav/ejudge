/* -*- c -*- */
/* $Id$ */
#ifndef __T3M_SUBMITS_H__
#define __T3M_SUBMITS_H__

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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

struct compile_reply_packet;
struct run_reply_packet;
struct submit_block_info;

typedef int (*submit_block_compile_result_handler_t)(
        void *data,
        struct submit_block_info *sb,
        struct compile_reply_packet *pkt,
        const unsigned char *report_txt,
        int report_len);
typedef int (*submit_block_run_result_handler_t)(
        void *data,
        struct submit_block_info *sb,
        struct run_reply_packet *pkt,
        const unsigned char *report_txt,
        int report_len);

struct submit_block_info
{
  struct submit_block_info *prev, *next;
  int contest_id;
  int first_run_id;
  int submit_count;

  // additional submit information
  submit_block_compile_result_handler_t compile_result_handler;
  submit_block_run_result_handler_t run_result_handler;
  void *data;
};

struct submit_block_state
{
  struct submit_block_info *first, *last;
};

struct submit_block_state *
submit_block_create(void);

void
submit_block_add(
        struct submit_block_state *state,
        int contest_id,
        int first_run_id,
        int submit_count,
        submit_block_compile_result_handler_t compile_result_handler,
        submit_block_run_result_handler_t run_result_handler,
        void *data);

void
submit_block_remove(
        struct submit_block_state *state,
        int contest_id,
        int first_run_id,
        int submit_count);

struct submit_block_info *
submit_block_find(
        struct submit_block_state *state,
        int contest_id,
        int run_id);

#endif /* __T3M_SUBMITS_H__ */
