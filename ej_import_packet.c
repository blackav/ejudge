/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2012-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_import_packet.h"
#include "ejudge/meta/ej_import_packet_meta.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

void
ej_import_packet_init(struct generic_section_config *gp)
{
}

struct ej_import_packet *
ej_import_packet_alloc(void)
{
    struct ej_import_packet *p = NULL;
    XCALLOC(p, 1);
    ej_import_packet_init((struct generic_section_config *) p);
    return p;
}

void
ej_import_packet_free(struct generic_section_config *gp)
{
    if (gp) {
        meta_destroy_fields(&meta_ej_import_packet_methods, gp);
        xfree(gp);
    }
}

static struct config_section_info ej_import_packet_info[] =
{
    { "global", sizeof(struct ej_import_packet), NULL, NULL,
      ej_import_packet_init, ej_import_packet_free,
      &meta_ej_import_packet_methods },

    { NULL, 0 },
};

struct ej_import_packet*
ej_import_packet_parse(const unsigned char *path, FILE *f)
{
    struct generic_section_config *cfg = parse_param(path, f, ej_import_packet_info, 1, 0, 0, NULL);
    return (struct ej_import_packet*) cfg;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
