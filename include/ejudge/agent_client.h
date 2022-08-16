/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __AGENT_CLIENT_H__
#define __AGENT_CLIENT_H__

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

struct AgentClient;
struct Future;

struct AgentClientOps
{
    struct AgentClient *(*destroy)(struct AgentClient *ac);
    int (*init)(
        struct AgentClient *ac,
        const unsigned char *inst_id,
        const unsigned char *endpoint,
        const unsigned char *queue_id,
        int mode,
        int verbose_mode);
    int (*connect)(struct AgentClient *ac);
    void (*close)(struct AgentClient *ac);
    int (*is_closed)(struct AgentClient *ac);

    int (*poll_queue)(
        struct AgentClient *ac,
        unsigned char *pkt_name,
        size_t pkt_len,
        int random_mode);

    int (*get_packet)(
        struct AgentClient *ac,
        const unsigned char *pkt_name,
        char **p_pkt_ptr,
        size_t *p_pkt_len);

    int (*get_data)(
        struct AgentClient *ac,
        const unsigned char *pkt_name,
        const unsigned char *suffix,
        char **p_pkt_ptr,
        size_t *p_pkt_len);

    int (*put_reply)(
        struct AgentClient *ac,
        const unsigned char *contest_server_name,
        int contest_id,
        const unsigned char *run_name,
        const unsigned char *pkt_ptr,
        size_t pkt_len);

    int (*put_output)(
        struct AgentClient *ac,
        const unsigned char *contest_server_name,
        int contest_id,
        const unsigned char *run_name,
        const unsigned char *suffix,
        const unsigned char *pkt_ptr,
        size_t pkt_len);

    int (*put_output_2)(
        struct AgentClient *ac,
        const unsigned char *contest_server_name,
        int contest_id,
        const unsigned char *run_name,
        const unsigned char *suffix,
        const unsigned char *path);

    int (*async_wait_init)(
        struct AgentClient *ac,
        int notify_signal,
        int random_mode,
        unsigned char *pkt_name,
        size_t pkt_len,
        struct Future **p_future);

    int (*async_wait_complete)(
        struct AgentClient *ac,
        struct Future **p_future,
        unsigned char *pkt_name,
        size_t pkt_len);

    int (*add_ignored)(
        struct AgentClient *ac,
        const unsigned char *pkt_name);

    int (*put_packet)(
        struct AgentClient *ac,
        const unsigned char *pkt_name,
        const unsigned char *pkt_ptr,
        size_t pkt_len);

    int (*get_data_2)(
        struct AgentClient *ac,
        const unsigned char *pkt_name,
        const unsigned char *suffix,
        const unsigned char *dir,
        const unsigned char *name,
        const unsigned char *out_suffix);

    int (*put_heartbeat)(
        struct AgentClient *ac,
        const unsigned char *file_name,
        const void *data,
        size_t size,
        long long *p_last_saved_time_ms,
        long long *p_stop_flag,
        long long *p_down_flag);
};

struct AgentClient
{
    const struct AgentClientOps *ops;
};

struct AgentClient *agent_client_ssh_create(void);

#endif /* __AGENT_CLIENT_H__ */
