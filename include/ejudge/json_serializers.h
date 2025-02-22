/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __JSON_SERIALIZERS_H__
#define __JSON_SERIALIZERS_H__

/* Copyright (C) 2023-2025 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/contests.h"
struct submit_entry;
struct testing_report_xml;
struct cJSON;
struct run_entry;
struct serve_state;

struct cJSON *
json_serialize_submit(
        const struct submit_entry *se,
        const struct testing_report_xml *tr);
struct cJSON *
json_serialize_run(
        struct serve_state *cs,
        const struct run_entry *re);

struct userlist_user;
struct userlist_user_info;
struct userlist_contest;

struct cJSON *
json_serialize_userlist_contest(
        int user_id,
        const struct userlist_contest *uc);

struct cJSON *
json_serialize_userlist_user(
        const struct userlist_user *u,
        const struct userlist_user_info *ui,
        const struct userlist_contest *uc);

struct section_language_data;
struct cJSON *
json_serialize_language(const struct section_language_data *lang, int final_mode);

struct userlist_cookie;
struct cJSON *
json_serialize_userlist_cookie(const struct userlist_cookie *c);

struct contest_desc;
struct cJSON *
json_serialize_contest_xml_full(const struct contest_desc *cnts, int date_mode);


#endif /* __JSON_SERIALIZERS_H__ */
