/* -*- c -*- */

#ifndef __PROCESS_STATS_H__
#define __PROCESS_STATS_H__

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>

struct ej_process_stats
{
    long long utime;  // user time (ms)
    long long stime;  // sys time (ms)
    long long ptime;  // CPU time (user + sys)
    long long rtime;  // real world time
    long long maxvsz; // estimate of max virtual size
    long long maxrss;
    int       nvcsw;  // voluntary context switches
    int       nivcsw; // involuntary context switches
};

void
process_stats_init(struct ej_process_stats *ps);
void
process_stats_serialize(FILE *fout, const struct ej_process_stats *ps);
int
process_stats_from_string(const unsigned char *str, struct ej_process_stats *ps);

#endif /* __PROCESS_STATS_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
