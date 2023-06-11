/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __JSON_SERIALIZERS_H__
#define __JSON_SERIALIZERS_H__

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

struct submit_entry;
struct testing_report_xml;
struct cJSON;

struct cJSON *
json_serialize_submit(
        const struct submit_entry *se,
        const struct testing_report_xml *tr);

#endif /* __JSON_SERIALIZERS_H__ */
