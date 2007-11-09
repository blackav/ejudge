/* -*- c -*- */
/* $Id$ */
#ifndef __SFORMAT_H__
#define __SFORMAT_H__

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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

struct section_global_data;
struct section_problem_data;
struct section_language_data;
struct section_tester_data;
struct teamdb_export;
struct userlist_user;
struct contest_desc;

struct sformat_extra_data
{
  int locale_id;
  unsigned long long sid;
  unsigned char *url;
  unsigned char *server_name;
  unsigned char *server_name_en;
  unsigned char *str1;
  int variant;
};

int sformat_message(char *, size_t, char const *,
                    const struct section_global_data *glob_data,
                    const struct section_problem_data *prob_data,
                    const struct section_language_data *lang_data,
                    const struct section_tester_data *tester_data,
                    const struct teamdb_export *team_data,
                    const struct userlist_user *user_data,
                    const struct contest_desc *cnts_data,
                    const struct sformat_extra_data *extra_data);

#endif /* __SFORMAT_H__ */
