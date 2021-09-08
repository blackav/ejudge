/* -*- c -*- */

/* Copyright (C) 2016-2021 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/process_stats.h"

#include <string.h>
#include <stdio.h>

void
process_stats_init(struct ej_process_stats *ps)
{
    memset(ps, -1, sizeof (*ps));
}

void
process_stats_serialize(FILE *fout, const struct ej_process_stats *ps)
{
    const char *sep2 = ", ";
    const char *sep = "";

    fprintf(fout, "{ ");
    if (ps->utime >= 0) {
        fprintf(fout, "%sutime=%lld", sep, ps->utime);
        sep = sep2;
    }
    if (ps->stime >= 0) {
        fprintf(fout, "%sstime=%lld", sep, ps->stime);
        sep = sep2;
    }
    if (ps->ptime >= 0) {
        fprintf(fout, "%sptime=%lld", sep, ps->ptime);
        sep = sep2;
    }
    if (ps->rtime >= 0) {
        fprintf(fout, "%srtime=%lld", sep, ps->rtime);
        sep = sep2;
    }
    if (ps->maxvsz >= 0) {
        fprintf(fout, "%smaxvsz=%lld", sep, ps->maxvsz);
        sep = sep2;
    }
    if (ps->maxrss >= 0) {
        fprintf(fout, "%smaxrss=%lld", sep, ps->maxrss);
        sep = sep2;
    }
    if (ps->nvcsw >= 0) {
        fprintf(fout, "%snvcsw=%d", sep, ps->nvcsw);
        sep = sep2;
    }
    if (ps->nivcsw >= 0) {
        fprintf(fout, "%snivcsw=%d", sep, ps->nivcsw);
        sep = sep2;
    }
    if (ps->cgroup_ptime_us > 0) {
        fprintf(fout, "%scgptimeus=%lld", sep, ps->cgroup_ptime_us);
        sep = sep2;
    }
    if (ps->cgroup_utime_us > 0) {
        fprintf(fout, "%scgutimeus=%lld", sep, ps->cgroup_utime_us);
        sep = sep2;
    }
    if (ps->cgroup_stime_us > 0) {
        fprintf(fout, "%scgstimeus=%lld", sep, ps->cgroup_stime_us);
        sep = sep2;
    }
    fprintf(fout, " }");
}

int
process_stats_from_string(const unsigned char *str, struct ej_process_stats *ps)
{
    // not implemented yet
    return -1;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
