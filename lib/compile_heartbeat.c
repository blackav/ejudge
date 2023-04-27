/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/config.h"
#include "ejudge/compile_heartbeat.h"
#include "ejudge/xalloc.h"

struct compile_heartbeat_vector *
compile_heartbeat_vector_free(
        struct compile_heartbeat_vector *v,
        int free_v_flag)
{
    for (int i = 0; i < v->u; ++i) {
        struct compile_heartbeat_vector_item *item = v->v[i];
        xfree(item->queue);
        xfree(item->file);
        xfree(item->data);
        xfree(item);
    }
    xfree(v->v);

    if (free_v_flag) {
        xfree(v);
    }

    return NULL;
}
