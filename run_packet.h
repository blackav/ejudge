/* -*- c -*- */
/* $Id$ */
#ifndef __RUN_PACKET_H__
#define __RUN_PACKET_H__

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

struct run_request_packet
{
  int judge_id;                 /* unique identifier for each rejudge */
  int contest_id;
  int run_id;
  int problem_id;
  int accepting_mode;           /* accepting testing for OLYMPIAD contest */
  int locale_id;
  int scoring_system;           /* the scoring system */
  int team_enable_rep_view;     /* generate report for a team */
  int report_error_code;        /* report the exit code in the protocol */
  int variant;
  int accept_partial;           /* accept partially passed in OLYMPIAD mode */
  int user_id;                  /* the user identifier */
  int html_report;              /* generate judge protocol in HTML */
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
  unsigned char *exe_sfx;       /* suffix for executables */
  unsigned char *arch;          /* the architecture */
  unsigned char *user_spelling; /* spelling of the user name */
  unsigned char *prob_spelling; /* spelling of the problem name */
};

struct run_reply_packet
{
  int judge_id;
  int contest_id;
  int run_id;
  int status;
  int failed_test;
  int score;
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
  /* time when the run request was completed by run */
  int ts6;
  int ts6_us;
};

int
run_request_packet_read(size_t in_size, const void *in_data,
                        struct run_request_packet **p_out_data);

int
run_request_packet_write(const struct run_request_packet *in_data,
                         size_t *p_out_size, void **p_out_data);

struct run_request_packet *
run_request_packet_free(struct run_request_packet *in_data);

int
run_reply_packet_read(size_t in_size, const void *in_data,
                      struct run_reply_packet **p_out_data);

int
run_reply_packet_write(const struct run_reply_packet *in_data,
                       size_t *p_out_size, void **p_out_data);

struct run_reply_packet *
run_reply_packet_free(struct run_reply_packet *in_data);

#endif /* __RUN_PACKET_H__ */
