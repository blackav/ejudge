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

void write_runs_table(int, int, char const *, char const *, int);
void write_clars_table(int, int, char const *, char const *, int);
void write_clar_view(int, char const *, char const *, char const *, int);
void write_team_statistics(int, int, int, char const *, char const *);
void write_team_clar(int, int, char const *, char const *, char const *);
void write_standings(char const *, char const *);
void write_judge_allstat(int, int, int, char const *, char const *);

void write_judge_source_view(char const *, int);
void write_judge_report_view(char const *, int);
void write_team_report_view(char const *, int, int);
void write_team_source_view(char const *, int, int);
void write_judge_standings(char const *);

#endif /* __HTML_H__ */
