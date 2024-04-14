/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2024 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/run_props.h"
#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/cJSON.h"

#include <stdio.h>

struct run_properties *
run_properties_free(struct run_properties *p)
{
    if (p) {
        xfree(p->start_cmd);
        for (int i = 0; p->start_args[i]; ++i) {
            xfree(p->start_args[i]);
        }
        xfree(p->start_args);
        xfree(p);
    }
    return NULL;
}

int
run_properties_parse_json_str(
        const unsigned char *str,
        struct run_properties **p_props,
        unsigned char **p_message)
{
    char *emsg = NULL;
    cJSON *j = cJSON_Parse(str);
    struct run_properties *props = NULL;
    if (!j) {
        asprintf(&emsg, "%s: JSON parse failed", __FUNCTION__);
        goto fail;
    }
    if (j->type != cJSON_Object) {
        asprintf(&emsg, "%s: object expected", __FUNCTION__);
        goto fail;
    }

    XCALLOC(props, 1);

    cJSON *jj = cJSON_GetObjectItem(j, "is_archive");
    if (jj) {
        if (jj->type != cJSON_False && jj->type != cJSON_True) {
            asprintf(&emsg, "%s: is_archive must be boolean", __FUNCTION__);
            goto fail;
        }
        if (jj->type == cJSON_True) {
            props->is_archive = 1;
        }
    }

    jj = cJSON_GetObjectItem(j, "start_cmd");
    if (jj) {
        if (jj->type != cJSON_String) {
            asprintf(&emsg, "%s: start_cmd must be string", __FUNCTION__);
            goto fail;
        }
        props->start_cmd = xstrdup(jj->valuestring);
    }

    jj = cJSON_GetObjectItem(j, "start_args");
    if (jj) {
        if (jj->type != cJSON_Array) {
            asprintf(&emsg, "%s: start_args must be array", __FUNCTION__);
            goto fail;
        }
        int size = cJSON_GetArraySize(jj);
        if (size < 0 || size > 1000) {
            asprintf(&emsg, "%s: start_args has invalid size %d", __FUNCTION__, size);
            goto fail;
        }
        XCALLOC(props->start_args, size + 1);
        for (int i = 0; i < size; ++i) {
            cJSON *jjj = cJSON_GetArrayItem(jj, i);
            if (!jjj || jjj->type == cJSON_NULL) {
                asprintf(&emsg, "%s: start_args must not contain nulls", __FUNCTION__);
                goto fail;
            }
            if (jjj->type != cJSON_String) {
                asprintf(&emsg, "%s: start_args must contain strings", __FUNCTION__);
                goto fail;
            }
            props->start_args[i] = xstrdup(jjj->valuestring);
        }
    }

    if (p_props) {
        *p_props = props;
        props = NULL;
    }
    run_properties_free(props);
    if (j) cJSON_Delete(j);
    return 0;

fail:;
    if (j) cJSON_Delete(j);
    if (p_props) *p_props = NULL;
    if (p_message) {
        *p_message = emsg; emsg = NULL;
    }
    xfree(emsg);
    run_properties_free(props);
    return -1;
}

int
run_properties_parse_json_file(
        const unsigned char *path,
        struct run_properties **p_props,
        unsigned char **p_message)
{
    char *emsg = NULL;
    FILE *fin = NULL;
    char *jt = NULL;
    size_t js = 0;
    FILE *jf = NULL;
    int c;
    int ret = -1;

    if (!(fin = fopen(path, "r"))) {
        asprintf(&emsg, "%s: failed to open '%s': %s", __FUNCTION__, path, os_ErrorMsg());
        goto fail;
    }
    jf = open_memstream(&jt, &js);
    while ((c = getc_unlocked(fin)) != EOF) {
        putc_unlocked(c, jf);
    }
    fclose(jf); jf = NULL;
    fclose(fin); fin = NULL;

    ret = run_properties_parse_json_str(jt, p_props, p_message);
    if (ret < 0) {
        goto fail;
    }
    free(jt); jt = NULL;

    return ret;

fail:;
    if (jf) fclose(jf);
    free(jt);
    if (fin) fclose(fin);
    if (p_message && emsg) {
        *p_message = emsg; emsg = NULL;
    }
    xfree(emsg);
    return ret;
}
