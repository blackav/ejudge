/* -*- c -*- */
/* $Id$ */
#ifndef __EJ_IMPORT_PACKET_H__
#define __EJ_IMPORT_PACKET_H__

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

struct ej_import_packet
{
    struct generic_section_config g META_ATTRIB((meta_hidden));

    int contest_id;
    int user_id;

    ejintbool_t require_master_solution;
    ejintbool_t require_test_checker;

    unsigned char *archive_file;
    unsigned char *content_type;
    unsigned char *log_file;
    unsigned char *status_file;
    unsigned char *pid_file;
    unsigned char *working_dir;
    unsigned char *remote_addr;
    unsigned char *user_login;
    unsigned char *user_name;

    char **required_solutions;
};

struct ej_import_packet *
ej_import_packet_alloc(void);
void
ej_import_packet_free(struct generic_section_config *gp);
struct ej_import_packet*
ej_import_packet_parse(const unsigned char *path, FILE *f);

#endif /* __EJ_IMPORT_PACKET_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
