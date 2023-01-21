/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __METRICS_CONTEST_H__
#define __METRICS_CONTEST_H__

/* Copyright (C) 2022-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdint.h>
#include <sys/time.h>

struct metrics_contest_data
{
    uint32_t size; // this struct size
    unsigned char pad0[12];
    struct timeval start_time;
    struct timeval update_time;
    long long client_serial;
    int loaded_contests;
    int runs_submitted;
    long long total_compile_time_ms;
    long long total_testing_time_ms;
};

struct metrics_desc
{
    unsigned char *path;
    struct metrics_contest_data *data;
};

extern struct metrics_desc metrics;

struct ejudge_cfg;
int setup_metrics_file(struct ejudge_cfg *config);

#endif /* __METRICS_CONTEST_H__ */
