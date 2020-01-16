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

#include "ejudge/polygon_packet.h"
#include "ejudge/meta/polygon_packet_meta.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

void
polygon_packet_init(struct generic_section_config *gp)
{
}

struct polygon_packet *
polygon_packet_alloc(void)
{
    struct polygon_packet *p = NULL;
    XCALLOC(p, 1);
    polygon_packet_init((struct generic_section_config *) p);
    return p;
}

void
polygon_packet_free(struct generic_section_config *gp)
{
    if (gp) {
        meta_destroy_fields(&meta_polygon_packet_methods, gp);
        xfree(gp);
    }
}

static struct config_section_info polygon_packet_info[] =
{
    { "global", sizeof(struct polygon_packet), NULL, NULL,
      polygon_packet_init, polygon_packet_free,
      &meta_polygon_packet_methods },

    { NULL, 0 },
};

struct polygon_packet*
polygon_packet_parse(const unsigned char *path, FILE *f)
{
    struct generic_section_config *cfg = parse_param(path, f, polygon_packet_info, 1, 0, 0, NULL);
    return (struct polygon_packet*) cfg;
}

static struct polygon_packet default_values;

void
polygon_packet_unparse(FILE *out_f, const struct polygon_packet *p)
{
    if (p) {
        fprintf(out_f, "# -*- coding: utf-8 -*-\n\n");
        meta_unparse_cfg(out_f, &meta_polygon_packet_methods, p, &default_values);
    }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
