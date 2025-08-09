/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/depgraph.h"
#include "ejudge/xalloc.h"

#include <stdio.h>
#include <string.h>

void
depgraph_free(struct depgraph *dgr)
{
    for (size_t i = 0; i < dgr->file_u; ++i) {
        struct depgraph_file *df = &dgr->files[i];
        xfree(df->path);
        xfree(df->deps);
    }
    xfree(dgr->files);
    xfree(dgr->sorted);
}

struct depgraph_file *
depgraph_add_file(struct depgraph *dgr, const unsigned char *path)
{
    for (size_t i = 1; i < dgr->file_u; ++i) {
        if (!strcmp(dgr->files[i].path, path)) {
            return &dgr->files[i];
        }
    }
    XEXPAND(dgr->files, dgr->file_a, dgr->file_u);
    if (!dgr->file_u) ++dgr->file_u;
    struct depgraph_file *df = &dgr->files[dgr->file_u];
    df->index = dgr->file_u;
    ++dgr->file_u;
    df->path = xstrdup(path);
    return df;
}

struct depgraph_file *
depgraph_find_file(struct depgraph *dgr, const unsigned char *path)
{
    for (size_t i = 1; i < dgr->file_u; ++i) {
        if (!strcmp(dgr->files[i].path, path)) {
            return &dgr->files[i];
        }
    }
    return NULL;
}

void
depgraph_add_dependency(struct depgraph_file *target, struct depgraph_file *source)
{
    for (size_t i = 0; i < target->dep_u; ++i) {
        if (target->deps[i] == source->index) {
            return;
        }
    }
    XEXPAND(target->deps, target->dep_a, target->dep_u);
    target->deps[target->dep_u++] = source->index;
}

static int
topological_sort_dfs(struct depgraph *dgr, unsigned char *marks, size_t *sorted_i, size_t i)
{
    if (marks[i] == 2) {
        return 0;
    }
    if (marks[i] == 1) {
        return -1;
    }

    marks[i] = 1;
    for (size_t j = 0; j < dgr->files[i].dep_u; ++j) {
        int r = topological_sort_dfs(dgr, marks, sorted_i, dgr->files[i].deps[j]);
        if (r < 0) return r;
    }
    marks[i] = 2;
    dgr->sorted[(*sorted_i)-- - 1] = i;
    return 0;
}

int
depgraph_topological_sort(struct depgraph *dgr)
{
    int retval = -1;
    unsigned char *marks = NULL;
    if (dgr->sorted) xfree(dgr->sorted);
    dgr->sorted = NULL;
    dgr->sorted_u = 0;
    if (dgr->file_u <= 1) return 0;

    dgr->sorted_u = dgr->file_u - 1;
    XCALLOC(dgr->sorted, dgr->sorted_u);
    XCALLOC(marks, dgr->file_u);
    size_t sorted_i = dgr->sorted_u;
    for (size_t i = 1; i < dgr->file_u; ++i) {
        if (!marks[i]) {
            if (topological_sort_dfs(dgr, marks, &sorted_i, i) < 0) {
                break;
            }
        }
    }

    retval = 0;
    xfree(marks);
    return retval;
}
