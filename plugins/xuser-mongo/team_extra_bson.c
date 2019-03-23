/* -*- mode: c -*- */

/* Copyright (C) 2015-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <mongo.h>

#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

struct team_warning *
team_warning_bson_parse(bson *b)
{
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
}

struct team_extra *
team_extra_bson_parse(bson *b)
{
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
            if (ej_bson_parse_int(bc, "run_fields", &res->run_fields, 1, 0, 0, 0) < 0) goto fail;
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
}

bson *
team_warning_bson_unparse(const struct team_warning *tw)
{
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
}

bson *
team_warnings_bson_unparse(struct team_warning **tws, int count)
{
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
}

bson *
team_extra_bson_unparse(const struct team_extra *extra)
{
    bson *res = bson_new();
    ej_bson_append_uuid(res, "_id", &extra->uuid);
    bson_append_int32(res, "user_id", extra->user_id);
    bson_append_int32(res, "contest_id", extra->contest_id);
    if (extra->disq_comment) {
        bson_append_string(res, "disq_comment", extra->disq_comment, strlen(extra->disq_comment));
    }
    bson_append_int32(res, "status", extra->status);
    bson_append_int32(res, "run_fields", extra->run_fields);
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
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
