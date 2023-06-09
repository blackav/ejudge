/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2015-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/team_extra.h"
#include "ejudge/bson_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
struct _bson;
typedef struct _bson ej_bson_t;
#endif

#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

struct team_warning *
team_warning_bson_parse(ej_bson_t *b)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct team_warning *res = NULL;

    if (!b) goto fail;
    if (!bson_iter_init(&iter, b)) goto fail;
    XCALLOC(res, 1);

    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "date")) {
            if (ej_bson_parse_utc_datetime_new(bc, "date", &res->date) < 0) goto fail;
        } else if (!strcmp(key, "issuer_id")) {
            if (ej_bson_parse_int_new(bc, "issuer_id", &res->issuer_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "issuer_ip")) {
            if (ej_bson_parse_ip_new(bc, "issuer_ip", &res->issuer_ip) < 0) goto fail;
        } else if (!strcmp(key, "text")) {
            if (ej_bson_parse_string_new(bc, "text", &res->text) < 0) goto fail;
        } else if (!strcmp(key, "comment")) {
            if (ej_bson_parse_string_new(bc, "comment", &res->comment) < 0) goto fail;
        }
    }
    return res;

fail:;
    err("team_warning_bson_parse: failed");
    if (res) {
        xfree(res->text);
        xfree(res->comment);
        xfree(res);
    }
    return NULL;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct team_warning *res = NULL;
    bson_cursor *bc = NULL;

    if (!b) return NULL;

    XCALLOC(res, 1);
    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "date")) {
            if (ej_bson_parse_utc_datetime(bc, "date", &res->date) < 0) goto fail;
        } else if (!strcmp(key, "issuer_id")) {
            if (ej_bson_parse_int(bc, "issuer_id", &res->issuer_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "issuer_ip")) {
            if (ej_bson_parse_ip(bc, "issuer_ip", &res->issuer_ip) < 0) goto fail;
        } else if (!strcmp(key, "text")) {
            if (ej_bson_parse_string(bc, "text", &res->text) < 0) goto fail;
        } else if (!strcmp(key, "comment")) {
            if (ej_bson_parse_string(bc, "comment", &res->comment) < 0) goto fail;
        }
    }
    bson_cursor_free(bc);

    return res;

fail:
    if (res) {
        xfree(res->text);
        xfree(res->comment);
        xfree(res);
    }
    if (bc) bson_cursor_free(bc);
    return NULL;
#else
    return NULL;
#endif
}

struct team_extra *
team_extra_bson_parse(ej_bson_t *b)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct team_extra *res = NULL;
    bson_iter_t iter, * const bc = &iter;
    bson_t *arr = NULL;
    bson_t *doc = NULL;

    if (!b) goto fail;
    if (!bson_iter_init(&iter, b)) goto fail;
    XCALLOC(res, 1);

    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_uuid_new(bc, "_id", &res->uuid) < 0) goto fail;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int_new(bc, "contest_id", &res->contest_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int_new(bc, "user_id", &res->user_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "viewed_clars")) {
            if (ej_bson_parse_array_new(bc, "viewed_clars", &arr) < 0) goto fail;
            bson_iter_t iter2, * const bc2 = &iter2;
            if (!bson_iter_init(&iter2, arr)) goto fail;
            while (bson_iter_next(&iter2)) {
                int clar_id = 0;
                if (ej_bson_parse_int_new(bc2, "viewed_clars/clar_id", &clar_id, 1, 0, 0, 0) < 0) goto fail;
                if (clar_id >= res->clar_map_size) team_extra_extend_clar_map(res, clar_id);
                res->clar_map[clar_id / BPE] |= (1UL << clar_id % BPE);
            }
            bson_destroy(arr); arr = NULL;
        } else if (!strcmp(key, "clar_uuids")) {
            if (ej_bson_parse_array_new(bc, "clar_uuids", &arr) < 0) goto fail;
            bson_iter_t iter2, * const bc2 = &iter2;
            if (!bson_iter_init(&iter2, arr)) goto fail;
            while (bson_iter_next(&iter2)) {
                ej_uuid_t uuid;
                if (ej_bson_parse_uuid_new(bc2, "clar_uuids/uuid", &uuid) < 0) goto fail;
                team_extra_add_clar_uuid(res, &uuid);
            }
            bson_destroy(arr); arr = NULL;
        } else if (!strcmp(key, "disq_comment")) {
            if (ej_bson_parse_string_new(bc, "disq_comment", &res->disq_comment) < 0) goto fail;
        } else if (!strcmp(key, "problem_dir_prefix")) {
            if (ej_bson_parse_string_new(bc, "problem_dir_prefix", &res->problem_dir_prefix) < 0) goto fail;
        } else if (!strcmp(key, "warnings")) {
            if (ej_bson_parse_array_new(bc, "warnings", &arr) < 0) goto fail;
            bson_iter_t iter2, * const bc2 = &iter;
            while (bson_iter_next(&iter2)) {
                struct team_warning *tw = NULL;
                if (ej_bson_parse_document_new(bc2, "warnings/warning", &doc) < 0) goto fail;
                if (!(tw = team_warning_bson_parse(doc))) goto fail;
                if (res->warn_u == res->warn_a) {
                    if (!(res->warn_a *= 2)) res->warn_a = 16;
                    XREALLOC(res->warns, res->warn_a);
                }
                res->warns[res->warn_u++] = tw; tw = NULL;
                bson_destroy(doc); doc = NULL;
            }
            bson_destroy(arr); arr = NULL;
        } else if (!strcmp(key, "status")) {
            if (ej_bson_parse_int_new(bc, "status", &res->status, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "run_fields")) {
            if (ej_bson_parse_int64_new(bc, "run_fields", &res->run_fields) < 0) goto fail;
        }
    }

    return res;

fail:;
    err("team_extra_bson_parse: failed");
    if (doc) bson_destroy(doc);
    if (arr) bson_destroy(arr);
    team_extra_free(res);
    return NULL;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson_cursor *bc = NULL;
    bson_cursor *bc2 = NULL;
    struct team_extra *res = NULL;
    bson *arr = NULL;
    bson *doc = NULL;
    struct team_warning *tw = NULL;

    if (!b) return NULL;

    XCALLOC(res, 1);
    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_uuid(bc, "_id", &res->uuid) < 0) goto fail;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int(bc, "contest_id", &res->contest_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int(bc, "user_id", &res->user_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "viewed_clars")) {
            if (ej_bson_parse_array(bc, "viewed_clars", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                int clar_id = 0;
                if (ej_bson_parse_int(bc2, "viewed_clars/clar_id", &clar_id, 1, 0, 0, 0) < 0) goto fail;
                if (clar_id >= res->clar_map_size) team_extra_extend_clar_map(res, clar_id);
                res->clar_map[clar_id / BPE] |= (1UL << clar_id % BPE);
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "clar_uuids")) {
            if (ej_bson_parse_array(bc, "clar_uuids", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                ej_uuid_t uuid;
                if (ej_bson_parse_uuid(bc2, "clar_uuids/uuid", &uuid) < 0) goto fail;
                team_extra_add_clar_uuid(res, &uuid);
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "disq_comment")) {
            if (ej_bson_parse_string(bc, "disq_comment", &res->disq_comment) < 0) goto fail;
        } else if (!strcmp(key, "problem_dir_prefix")) {
            if (ej_bson_parse_string(bc, "problem_dir_prefix", &res->problem_dir_prefix) < 0) goto fail;
        } else if (!strcmp(key, "warnings")) {
            if (ej_bson_parse_array(bc, "warnings", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                if (ej_bson_parse_document(bc2, "warnings/warning", &doc) < 0) goto fail;
                if (!(tw = team_warning_bson_parse(doc))) goto fail;
                if (res->warn_u == res->warn_a) {
                    if (!(res->warn_a *= 2)) res->warn_a = 16;
                    XREALLOC(res->warns, res->warn_a);
                }
                res->warns[res->warn_u++] = tw; tw = NULL;
                bson_free(doc); doc = NULL;
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "status")) {
            if (ej_bson_parse_int(bc, "status", &res->status, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "run_fields")) {
            if (ej_bson_parse_int64(bc, "run_fields", &res->run_fields, 1, 0, 0, 0) < 0) goto fail;
        }
    }
    bson_cursor_free(bc);
    return res;

fail:
    team_extra_free(res);
    if (doc) bson_free(doc);
    if (arr) bson_free(arr);
    if (bc2) bson_cursor_free(bc2);
    if (bc) bson_cursor_free(bc);
    return NULL;
#else
    return NULL;
#endif
}

ej_bson_t *
team_warning_bson_unparse(const struct team_warning *tw)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_t *res = bson_new();
    long long utc_dt = (long long) tw->date * 1000;
    bson_append_date_time(res, "date", -1, utc_dt);
    bson_append_int32(res, "issuer_id", -1, tw->issuer_id);
    ej_bson_append_ip_new(res, "issuer_ip", &tw->issuer_ip);
    if (tw->text) {
        bson_append_utf8(res, "text", -1, tw->text, strlen(tw->text));
    }
    if (tw->comment) {
        bson_append_utf8(res, "comment", -1, tw->comment, strlen(tw->comment));
    }
    return res;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *res = bson_new();
    long long utc_dt = (long long) tw->date * 1000;
    bson_append_utc_datetime(res, "date", utc_dt);
    bson_append_int32(res, "issuer_id", tw->issuer_id);
    ej_bson_append_ip(res, "issuer_ip", &tw->issuer_ip);
    if (tw->text) {
        bson_append_string(res, "text", tw->text, strlen(tw->text));
    }
    if (tw->comment) {
        bson_append_string(res, "comment", tw->comment, strlen(tw->comment));
    }
    bson_finish(res);
    return res;
#else
    return NULL;
#endif
}

ej_bson_t *
team_warnings_bson_unparse(struct team_warning **tws, int count)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_t *res = bson_new();
    if (tws && count > 0) {
        for (int i = 0; i < count; ++i) {
            unsigned char buf[32];
            bson_t *w = NULL;
            sprintf(buf, "%d", i);
            bson_append_document(res, buf, -1, (w = team_warning_bson_unparse(tws[i])));
            bson_destroy(w);
        }
    }
    return res;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *res = bson_new();
    if (tws && count > 0) {
        for (int i = 0; i < count; ++i) {
            unsigned char buf[32];
            bson *w;
            sprintf(buf, "%d", i);
            bson_append_document(res, buf, (w = team_warning_bson_unparse(tws[i])));
            bson_free(w);
        }
    }
    bson_finish(res);
    return res;
#else
    return NULL;
#endif
}

ej_bson_t *
team_extra_bson_unparse(const struct team_extra *extra)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_t *res = bson_new();
    ej_bson_append_uuid_new(res, "_id", &extra->uuid);
    bson_append_int32(res, "user_id", -1, extra->user_id);
    bson_append_int32(res, "contest_id", -1, extra->contest_id);
    if (extra->disq_comment) {
        bson_append_utf8(res, "disq_comment", -1, extra->disq_comment, -1);
    }
    if (extra->problem_dir_prefix) {
        bson_append_utf8(res, "problem_dir_prefix", -1, extra->problem_dir_prefix, -1);
    }
    bson_append_int32(res, "status", -1, extra->status);
    bson_append_int64(res, "run_fields", -1, extra->run_fields);
    if (extra->clar_map_size > 0) {
        bson_t *arr = bson_new();
        for (int i = 0, j = 0; i < extra->clar_map_size; ++i) {
            if (extra->clar_map[i / BPE] & (1UL << i % BPE)) {
                unsigned char buf[32];
                sprintf(buf, "%d", j++);
                bson_append_int32(arr, buf, -1, i);
            }
        }
        bson_append_document(res, "viewed_clars", -1, arr);
        bson_destroy(arr); arr = NULL;
    }
    if (extra->clar_uuids_size > 0) {
        bson_t *arr = ej_bson_unparse_array_uuid_new(extra->clar_uuids, extra->clar_uuids_size);
        bson_append_array(res, "clar_uuids", -1, arr);
        bson_destroy(arr); arr = NULL;
    }
    if (extra->warn_u > 0) {
        bson_t *arr = team_warnings_bson_unparse(extra->warns, extra->warn_u);
        bson_append_array(res, "warnings", -1, arr);
        bson_destroy(arr); arr = NULL;
    }
    return res;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *res = bson_new();
    ej_bson_append_uuid(res, "_id", &extra->uuid);
    bson_append_int32(res, "user_id", extra->user_id);
    bson_append_int32(res, "contest_id", extra->contest_id);
    if (extra->disq_comment) {
        bson_append_string(res, "disq_comment", extra->disq_comment, strlen(extra->disq_comment));
    }
    if (extra->problem_dir_prefix) {
        bson_append_string(res, "problem_dir_prefix", extra->problem_dir_prefix, strlen(extra->problem_dir_prefix));
    }
    bson_append_int32(res, "status", extra->status);
    bson_append_int64(res, "run_fields", extra->run_fields);
    if (extra->clar_map_size > 0) {
        bson *arr = bson_new();
        for (int i = 0, j = 0; i < extra->clar_map_size; ++i) {
            if (extra->clar_map[i / BPE] & (1UL << i % BPE)) {
                unsigned char buf[32];
                sprintf(buf, "%d", j++);
                bson_append_int32(arr, buf, i);
            }
        }
        bson_finish(arr);
        bson_append_document(res, "viewed_clars", arr);
        bson_free(arr); arr = NULL;
    }
    if (extra->clar_uuids_size > 0) {
        bson *arr = NULL;
        bson_append_array(res, "clar_uuids", (arr = ej_bson_unparse_array_uuid(extra->clar_uuids, extra->clar_uuids_size)));
        bson_free(arr); arr = NULL;
    }
    if (extra->warn_u > 0) {
        bson *arr = team_warnings_bson_unparse(extra->warns, extra->warn_u);
        bson_append_array(res, "warnings", arr);
        bson_free(arr); arr = NULL;
    }
    bson_finish(res);
    return res;
#else
    return NULL;
#endif
}
