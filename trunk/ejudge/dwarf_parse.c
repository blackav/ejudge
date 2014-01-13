/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "dwarf_parse.h"

#include "reuse/xalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

typedef struct DieMapEntry
{
    Dwarf_Unsigned addr;
    TypeInfo *ti;
} DieMapEntry;

typedef struct DieMap
{
    int a, u;
    DieMapEntry *e;
} DieMap;

static DieMap *
die_map_init(void)
{
    DieMap *dm = NULL;
    XCALLOC(dm, 1);
    return dm;
}

static DieMap *
die_map_destroy(DieMap *dm)
{
    if (dm) {
        xfree(dm);
    }
    return NULL;
}

static TypeInfo *
die_map_get(DieMap *dm, Dwarf_Unsigned addr)
{
    int low = 0, high = dm->u, mid;
    while (low < high) {
        mid = (low + high) / 2;
        if (dm->e[mid].addr == addr) {
            return dm->e[mid].ti;
        } else if (dm->e[mid].addr < addr) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return NULL;
}

static void
die_map_put(DieMap *dm, Dwarf_Unsigned addr, TypeInfo *ti)
{
    int pos;
    if (dm->u <= 0) {
        pos = 0;
    } else if (addr < dm->e[0].addr) {
        pos = 0;
    } else if (addr > dm->e[dm->u - 1].addr) {
        pos = dm->u;
    } else {
    }

    if (dm->u == dm->a) {
        if (!(dm->a *= 2)) dm->a = 32;
        XREALLOC(dm->e, dm->a);
    }
    if (pos < dm->u) {
        memmove(dm->e + pos + 1, dm->e + pos, (dm->u - pos) * sizeof(dm->e[0]));
    }
    ++dm->u;
    memset(dm->e + pos, 0, sizeof(dm->e[0]));
    dm->e[pos].addr = addr;
    dm->e[pos].ti = ti;
}

static int
parse_cu(FILE *log_f, const unsigned char *path, Dwarf_Debug dbg, TypeContext *cntx)
{
    Dwarf_Die die = NULL;
    int retval = -1;
    Dwarf_Error dwe = NULL;
    DieMap *dm = die_map_init();

    if (dwarf_siblingof_b(dbg, NULL, 1, &die, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_siblingof_b failed: %s\n", path, dwarf_errmsg(dwe));
        goto done;
    }

done:
    dm = die_map_destroy(dm);
    return retval;
}

int
dwarf_parse(FILE *log_f, const unsigned char *path, TypeContext *cntx)
{
    int fd = -1;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error dwe = NULL;
    int retval = -1;
    int res;

    if ((fd = open(path, O_RDONLY, 0)) < 0) {
        fprintf(log_f, "cannot open file '%s': %s\n", path, strerror(errno));
        goto done;
    }

    if (dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: failed to initialize dwarf: %s\n", path, dwarf_errmsg(dwe));
        goto done;
    }

    Dwarf_Unsigned cu_header_length;
    Dwarf_Half version_stamp;
    Dwarf_Off abbrev_offset;
    Dwarf_Half address_size;
    Dwarf_Half length_size;
    Dwarf_Half extension_size;
    Dwarf_Sig8 type_signature;
    Dwarf_Unsigned typeoffset = 0;
    Dwarf_Unsigned next_cu_header_offset;
    while ((res = dwarf_next_cu_header_c(dbg, 1, &cu_header_length, &version_stamp,
                                         &abbrev_offset, &address_size, &length_size,
                                         &extension_size, &type_signature,
                                         &typeoffset, &next_cu_header_offset, &dwe)) == DW_DLV_OK) {
        if ((res = parse_cu(log_f, path, dbg, cntx)) < 0) {
            goto done;
        }
    }
    if (res != DW_DLV_NO_ENTRY) {
        fprintf(log_f, "%s: dwarf_next_cu_header_c failed: %s\n", path, dwarf_errmsg(dwe));
        goto done;
    }
    retval = 0;

done:
    // no reasonable strategy in case of dwarf_finish failure
    if (dbg != NULL) dwarf_finish(dbg, &dwe);
    dbg = NULL;

    if (fd >= 0) close(fd);
    fd = -1;
    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
