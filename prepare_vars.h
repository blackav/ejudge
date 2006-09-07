/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_VARS_H__
#define __PREPARE_VARS_H__

/* Copyright (C) 2005-2006 Alexander Chernov <cher@ejudge.ru> */

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

struct generic_section_config;
struct section_global_data;
struct section_language_data;
struct section_problem_data;
struct section_tester_data;
struct contest_desc;
struct clarlog_state;

extern struct generic_section_config *config;
extern struct section_global_data    *global;

extern struct section_language_data *langs[];
extern struct section_problem_data  *probs[];
extern struct section_tester_data   *testers[];

extern int max_tester;
extern int max_lang;
extern int max_prob;

/* userlist-server interaction */
extern const struct contest_desc *cur_contest;

/* clarlog internal state */
extern struct clarlog_state *clarlog_state;

#endif /* __PREPARE_VARS_H__ */
