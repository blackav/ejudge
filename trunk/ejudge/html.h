/* -*- c -*- */
/* $Id$ */
#ifndef __HTML_H__
#define __HTML_H__

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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

#include <stdio.h>
#include <time.h>

void write_runs_table(int, int, char const *, char const *, int);
void write_clars_table(int, int, char const *, char const *, int);
void write_clar_view(int, char const *, char const *, char const *, int);
void write_team_statistics(int, int, int, char const *, char const *);
void write_standings(char const *, char const *, char const *, char const *);
void write_public_log(char const *, char const *, char const *, char const *);

void write_judge_allstat(int, int, int, char const *, char const *);

void write_judge_source_view(char const *, int);
void write_judge_report_view(char const *, int);
void write_judge_standings(char const *);
void write_judge_teams_view(char const *, int);
void write_judge_one_team_view(char const *, int);

void new_write_user_runs(FILE *, int, unsigned int, unsigned char const *);
void new_write_user_clars(FILE *, int, unsigned int, unsigned char const *);
int new_write_user_clar(FILE *, int, int);
int new_write_user_source_view(FILE *, int, int);
int new_write_user_report_view(FILE *, int, int);

void write_team_page(FILE *f,
                     int user_id,
                     int all_runs,
                     int all_clars,
                     unsigned char const *simple_form,
                     unsigned char const *multi_form,
                     time_t server_start,
                     time_t server_end);

#endif /* __HTML_H__ */
