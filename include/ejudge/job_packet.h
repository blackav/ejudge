/* -*- c -*- */

#ifndef __JOB_PACKET_H__
#define __JOB_PACKET_H__ 1

/* Copyright (C) 2006-2021 Alexander Chernov <cher@ejudge.ru> */

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

struct ejudge_cfg;

int send_job_packet(
        const struct ejudge_cfg *config,
        unsigned char **args,
        unsigned char **p_path);

#endif
