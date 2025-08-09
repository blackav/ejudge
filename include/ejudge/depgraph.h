/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __DEPGRAPH_H__
#define __DEPGRAPH_H__

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

#include <stdlib.h>

struct depgraph_file
{
    size_t index;
    unsigned char *path;
    size_t dep_a, dep_u;
    size_t *deps;
};

struct depgraph
{
    struct depgraph_file *files;
    size_t file_a, file_u;

    size_t sorted_u;
    size_t *sorted;
};

void depgraph_free(struct depgraph *dgr);
struct depgraph_file *depgraph_add_file(struct depgraph *dgr, const unsigned char *path);
struct depgraph_file *depgraph_find_file(struct depgraph *dgr, const unsigned char *path);

void depgraph_add_dependency(struct depgraph_file *target, struct depgraph_file *source);

int depgraph_topological_sort(struct depgraph *dgr);

 #endif /* __DEPGRAPH_H__ */
