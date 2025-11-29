/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __AGENT_COMMON_H__
#define __AGENT_COMMON_H__

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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

#include <stddef.h>

typedef struct SpoolQueue
{
    int refcount;
    unsigned index;

    unsigned char *queue_id;
    unsigned char *spool_dir;
    unsigned char *queue_dir;
    unsigned char *queue_packet_dir;
    unsigned char *queue_out_dir;
    unsigned char *data_dir;
    unsigned char *heartbeat_dir;
    unsigned char *heartbeat_packet_dir;
    unsigned char *heartbeat_in_dir;
    unsigned char *config_dir;
    unsigned char *config_packet_dir;
    unsigned char *config_in_dir;

    void *extra;

    int mode;
} SpoolQueue;

typedef struct ContestSpool
{
    unsigned char *server;
    int contest_id;
    int mode;
    unsigned serial;

    unsigned char *server_dir;
    unsigned char *server_contest_dir;
    unsigned char *status_dir;
    unsigned char *report_dir;
    unsigned char *output_dir;
} ContestSpool;

typedef struct ContestSpools
{
    ContestSpool *v;
    size_t u;
    size_t a;
} ContestSpools;

typedef struct MappedFile
{
    unsigned char *data;
    size_t size;
} MappedFile;

int
spool_queue_init(
    SpoolQueue *q,
    const unsigned char *queue_id,
    int mode,
    unsigned index);

void
spool_queue_destroy(SpoolQueue *q);
int
spool_queue_read_packet(
        SpoolQueue *q,
        const unsigned char *pkt_name,
        char **p_data,
        size_t *p_size);

struct cJSON;
void
agent_add_file_to_object(
    struct cJSON *j,
    const char *data,
    size_t size);
int
agent_extract_file(
    const unsigned char *inst_id,
    struct cJSON *j,
    char **p_pkt_ptr,
    size_t *p_pkt_len);
int
agent_extract_file_result(
    struct cJSON *j,
    char **p_pkt_ptr,
    size_t *p_pkt_len);

ContestSpool *
contest_spool_get(
    ContestSpools *css,
    const unsigned char *server,
    int contest_id,
    int mode);

int
agent_save_to_spool(
    const unsigned char *inst_id,
    const unsigned char *spool_dir,
    const unsigned char *file_name,
    const unsigned char *data,
    size_t size);
int
agent_save_file(
    const unsigned char *dir,
    const unsigned char *name,
    const unsigned char *suffix,
    const unsigned char *data,
    size_t size);

void
agent_file_unmap(MappedFile *mf);
int
agent_file_map(MappedFile *mf, const unsigned char *path);

#endif /* __AGENT_COMMON_H__ */
