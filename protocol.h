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
  unsigned char clars_disabled;
  unsigned char team_clars_disabled;
  unsigned char standings_frozen;
  unsigned char score_system;
  unsigned char clients_suspended;
};

#endif /* __PROTOCOL_H__ */
