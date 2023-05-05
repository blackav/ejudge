/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __SERVER_INFO_H__
#define __SERVER_INFO_H__

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

struct server_info_process
{
    unsigned char *name;
    int count;
    double cpu_time;
    long long vm_size;
    long long vm_rss;
};

struct server_info_process *
server_info_get_processes(void);

struct server_info_process *
server_info_free_processes(struct server_info_process *p);

#endif /* __SERVER_INFO_H__ */
