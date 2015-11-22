/* -*- c -*- */
#ifndef __SUPER_RUN_STATUS_H__
#define __SUPER_RUN_STATUS_H__

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

enum
{
    SRS_UNKNOWN, SRS_WAITING, SRS_TESTING, SRS_OFF
};

struct super_run_status
{
    unsigned char  signature[4]; // 0: signature magic
    unsigned char  endianness;   // 4: 1 - LE, 1 - BE
    unsigned char  pad1;
    unsigned short version;      // 6: packet version number (1, ...)
    unsigned short size;         // 8: packet size
    unsigned short strings_off;  // 10: offset of the string pool
    unsigned short str_lens;     // 12: length of all strings
    unsigned char  pad2[2];
    long long      timestamp;    // 16: status timestamp, milliseconds from the epoch
    long long      last_run_ts;  // 24: time of the last testing performed

    unsigned short inst_id_idx;  // 32: instance id index
    unsigned short local_ip_idx; // 34: internal IP address index
    unsigned short local_host_idx;// 36: internal host name index
    unsigned short public_ip_idx; // 38: external IP address index
    unsigned short public_host_idx;// 40: external host name index
    unsigned short queue_idx;    // 42: testing queue name
    unsigned short ej_ver_idx;   // 44: ejudge version string
    unsigned short super_run_idx;// 46: super_run_id index

    int            contest_id;   // 48: contest_id being tested
    int            run_id;       // 52: run_id being tested
    int            test_num;     // 56: test being tested
    short          status;       // 58: status
    unsigned short pkt_name_idx; // 62: packet name index
    unsigned short user_idx;     // 64: user login
    unsigned short prob_idx;     // 66: problem short name
    unsigned short lang_idx;     // 68: language short name

    short          super_run_pid;// 70: pid of ej-super-run
    long long      queue_ts;     // 72: time of creating a testing request
    long long      testing_start_ts; // 80: time when testing started
    int            max_test_num; // 88: number of tests for the problem
    unsigned char  stop_pending; // 92: pending stop
    unsigned char  down_pending; // 93: pending shutdown

    unsigned char  pad5[98];

    unsigned char  strings[320]; // string pool
};

#define super_run_status_get_str(psrs,field) (((const unsigned char*) (psrs)) + (psrs)->strings_off + (psrs)->field)

void
super_run_status_init(
        struct super_run_status *psrs);
int
super_run_status_add_str(
        struct super_run_status *psrs,
        const unsigned char *str);
int
super_run_status_check(
        const void *data,
        size_t size);

void
super_run_status_save(
        const unsigned char *heartbeat_dir,
        const unsigned char *file_name,
        const struct super_run_status *psrs,
        long long current_time_ms,
        long long *p_last_saved_time,
        long long timeout_ms,
        unsigned char *p_stop_flag,
        unsigned char *p_down_flag);

void
super_run_status_remove(
        const unsigned char *heartbeat_dir,
        const unsigned char *file_name);

struct super_run_status_vector_item
{
    struct super_run_status status;
    unsigned char *queue;
    unsigned char *file;
};

struct super_run_status_vector
{
    int a, u;
    struct super_run_status_vector_item **v;
};

struct super_run_status_vector *
super_run_status_vector_free(
        struct super_run_status_vector *v,
        int free_v_flag);

void
super_run_status_vector_add(
        struct super_run_status_vector *v,
        const struct super_run_status *s,
        const unsigned char *queue,
        const unsigned char *file);

void
super_run_status_scan(
        const unsigned char *queue,
        const unsigned char *heartbeat_dir,
        struct super_run_status_vector *v);

#endif /* __SUPER_RUN_STATUS_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
