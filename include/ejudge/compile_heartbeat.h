/* -*- mode: c; c-basic-offset:4 -*- */
#ifndef __COMPILE_HEARTBEAT_H__
#define __COMPILE_HEARTBEAT_H__

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/ej_types.h"

struct compile_heartbeat_vector_item
{
    unsigned char *queue;
    unsigned char *file;
    unsigned char *data;
    size_t size;
};

struct compile_heartbeat_vector
{
    int a, u;
    struct compile_heartbeat_vector_item **v;
};

struct compile_heartbeat_vector *
compile_heartbeat_vector_free(
        struct compile_heartbeat_vector *v,
        int free_v_flag);

void
compile_heartbeat_scan(
        const unsigned char *queue,
        const unsigned char *heartbeat_dir,
        struct compile_heartbeat_vector *v);

#endif /* __SUPER_RUN_STATUS_H__ */
