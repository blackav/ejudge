/* -*- c -*- */
/* $Id$ */
#ifndef __POLYGON_PACKET_H__
#define __POLYGON_PACKET_H__

/* Copyright (C) 2012-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/parsecfg.h"

#include <time.h>

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

struct polygon_packet
{
    struct generic_section_config g META_ATTRIB((meta_hidden));

    int sleep_interval;
    ejintbool_t enable_max_stack_size;
    ejintbool_t create_mode;
    ejintbool_t ignore_solutions;
    int retry_count;
    ejintbool_t fetch_latest_available;

    unsigned char *polygon_url;
    unsigned char *login;
    unsigned char *password;
    unsigned char *user_agent;
    unsigned char *log_file;
    unsigned char *status_file;
    unsigned char *pid_file;
    unsigned char *download_dir;
    unsigned char *problem_dir;
    unsigned char *dir_mode;
    unsigned char *dir_group;
    unsigned char *file_mode;
    unsigned char *file_group;
    unsigned char *arch;
    unsigned char *working_dir;
    unsigned char *problem_xml_name;
    unsigned char *testset;
    unsigned char *language_priority;
    unsigned char *polygon_contest_id;

    char **id;
    char **ejudge_id;
    char **ejudge_short_name;
};

struct polygon_packet *
polygon_packet_alloc(void);
void
polygon_packet_free(struct generic_section_config *gp);
struct polygon_packet*
polygon_packet_parse(const unsigned char *path, FILE *f);
void
polygon_packet_unparse(FILE *out_f, const struct polygon_packet *p);

#endif /* __POLYGON_PACKET_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
