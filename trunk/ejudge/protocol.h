/* -*- c -*- */
/* $Id$ */

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <time.h>

#if !defined EJUDGE_SCORE_SYSTEM_DEFINED
#define EJUDGE_SCORE_SYSTEM_DEFINED
/* scoring systems */
enum { SCORE_ACM, SCORE_KIROV, SCORE_OLYMPIAD };
#endif /* EJUDGE_SCORE_SYSTEM_DEFINED */

#define PROT_SERVE_STATUS_MAGIC (0xe739aa02)
struct prot_serve_status
{
  unsigned int magic;
  time_t cur_time;
  time_t start_time;
  time_t sched_time;
  time_t duration;
  time_t stop_time;
  int total_runs;
  int total_clars;
  int download_interval;
  unsigned char clars_disabled;
  unsigned char team_clars_disabled;
  unsigned char standings_frozen;
  unsigned char score_system;
  unsigned char clients_suspended;
};

#define PROT_SERVE_PACKET_MAGIC (0xe342)
struct prot_serve_packet
{
  unsigned short magic;
  short id;
};

// client->serve requests
enum
  {
    SRV_CMD_PASS_FD = 1,
    SRV_CMD_GET_ARCHIVE,
    SRV_CMD_LIST_RUNS,
    SRV_CMD_LIST_CLARS,
    SRV_CMD_SHOW_CLAR,
    SRV_CMD_SHOW_SOURCE,
    SRV_CMD_SHOW_REPORT,
    SRV_CMD_SUBMIT_RUN,
    SRV_CMD_SUBMIT_CLAR,
    SRV_CMD_TEAM_PAGE,

    SRV_CMD_LAST
  };

// serve->client replies
enum
  {
    SRV_RPL_OK = 0,
    SRV_RPL_ARCHIVE_PATH = 1,

    SRV_RPL_LAST
  };

// serve error message codes
enum
  {
    SRV_ERR_NO_ERROR = 0,
    SRV_ERR_UNKNOWN_ERROR,
    SRV_ERR_BAD_SOCKET_NAME,
    SRV_ERR_SYSTEM_ERROR,
    SRV_ERR_CONNECT_FAILED,
    SRV_ERR_NOT_CONNECTED,
    SRV_ERR_PROTOCOL,
    SRV_ERR_EOF_FROM_SERVER,
    SRV_ERR_READ_FROM_SERVER,
    SRV_ERR_WRITE_TO_SERVER,
    SRV_ERR_NOT_SUPPORTED,
    SRV_ERR_ACCESS_DENIED,
    SRV_ERR_BAD_USER_ID,
    SRV_ERR_BAD_CONTEST_ID,
    SRV_ERR_CLARS_DISABLED,
    SRV_ERR_BAD_CLAR_ID,
    SRV_ERR_SOURCE_DISABLED,
    SRV_ERR_BAD_RUN_ID,
    SRV_ERR_BAD_PROB_ID,
    SRV_ERR_BAD_LANG_ID,
    SRV_ERR_REPORT_DISABLED,
    SRV_ERR_DOWNLOAD_DISABLED,
    SRV_ERR_DOWNLOAD_TOO_OFTEN,
    SRV_ERR_TRY_AGAIN,
    SRV_ERR_CONTEST_NOT_STARTED,
    SRV_ERR_CONTEST_FINISHED,
    SRV_ERR_QUOTA_EXCEEDED,
    SRV_ERR_SUBJECT_TOO_LONG,
    SRV_ERR_DUPLICATED_RUN,

    SRV_ERR_LAST
  };

struct prot_serve_pkt_get_archive
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
};

struct prot_serve_pkt_list_runs
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned int flags;
  int form_start_len;
  unsigned char data[1];
};

struct prot_serve_pkt_show_item
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  int item_id;
};

struct prot_serve_pkt_submit_run
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned long ip;
  int prob_id;
  int lang_id;
  int run_len;
  unsigned char data[1];
};

struct prot_serve_pkt_submit_clar
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned long ip;
  int subj_len;
  int text_len;
  unsigned char data[2];
};

struct prot_serve_pkt_team_page
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned long ip;
  unsigned int flags;
  int simple_form_len;
  int multi_form_len;
  unsigned char data[2];
};

struct prot_serve_pkt_archive_path
{
  struct prot_serve_packet b;

  int token;
  int path_len;
  unsigned char data[1];
};

unsigned char const *protocol_strerror(int n);

#endif /* __PROTOCOL_H__ */
