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
#include "reuse/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

typedef struct DieMapEntry
{
    Dwarf_Off addr;
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
        xfree(dm->e);
        memset(dm, 0, sizeof(*dm));
        xfree(dm);
    }
    return NULL;
}

static TypeInfo *
die_map_get(DieMap *dm, Dwarf_Off addr)
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
die_map_put(DieMap *dm, Dwarf_Off addr, TypeInfo *ti)
{
    int pos;
    if (dm->u <= 0) {
        pos = 0;
    } else if (addr < dm->e[0].addr) {
        pos = 0;
    } else if (addr > dm->e[dm->u - 1].addr) {
        pos = dm->u;
    } else {
        int low = 0, high = dm->u, mid;
        while (low < high) {
            if (dm->e[low].addr >= addr) {
                pos = low;
                break;
            }
            if (dm->e[high - 1].addr < addr) {
                pos = high;
                break;
            }
            mid = (low + high) / 2;
            if (dm->e[mid].addr == addr && dm->e[mid].ti == ti) return;
            ASSERT(dm->e[mid].addr != addr);
            if (dm->e[mid].addr < addr) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        ASSERT(low < high);
        if (dm->e[pos].addr == addr && dm->e[pos].ti == ti) return;
        ASSERT(dm->e[pos].addr != addr);
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
s_dwarf_die_CU_offset(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Die die,
        Dwarf_Off *offset);

static int
die_map_get_2(
        FILE *log_f,
        const unsigned char *path,
        DieMap *dm,
        Dwarf_Die die,
        TypeInfo **pti,
        Dwarf_Off *pdie_offset)
{
    Dwarf_Off die_offset = 0;
    if (s_dwarf_die_CU_offset(log_f, path, die, &die_offset) < 0) return -1;
    *pti = die_map_get(dm, die_offset);
    if (pdie_offset) *pdie_offset = die_offset;
    return *pti != NULL;
}

static int
s_dwarf_tag(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Die die,
        Dwarf_Half *ptag)
{
    Dwarf_Error dwe = NULL;
    if (dwarf_tag(die, ptag, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_tag failed: %s\n", path,
                dwarf_errmsg(dwe));
        return -1;
    }
    return 0;
}

static int
s_dwarf_sibling(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        Dwarf_Die *pdie)
{
    Dwarf_Error dwe = NULL;
    int res;
    if ((res = dwarf_siblingof_b(dbg, die, 1, pdie, &dwe)) == DW_DLV_OK)
        return 1;
    if (res == DW_DLV_NO_ENTRY) return 0;
    fprintf(log_f, "%s: dwarf_siblingof_b failed: %s\n", path, dwarf_errmsg(dwe));
    return -1;
}

static int
s_dwarf_child(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Die die,
        Dwarf_Die *pdie)
{
    Dwarf_Error dwe = NULL;
    int res;
    if ((res = dwarf_child(die, pdie, &dwe)) == DW_DLV_OK) return 1;
    if (res == DW_DLV_NO_ENTRY) return 0;
    fprintf(log_f, "%s: dwarf_child failed: %s\n", path, dwarf_errmsg(dwe));
    return -1;
}

static int
s_dwarf_die_CU_offset(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Die die,
        Dwarf_Off *offset)
{
    Dwarf_Error dwe = NULL;
    if (dwarf_die_CU_offset(die, offset, &dwe) == DW_DLV_OK) return 0;
    fprintf(log_f, "%s: dwarf_die_CU_offset failed: %s\n", path, dwarf_errmsg(dwe));
    return -1;
}

static int
s_dwarf_attr(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Die die,
        Dwarf_Half attr,
        Dwarf_Attribute *pattr)
{
    Dwarf_Error dwe = NULL;
    int ret;
    if ((ret = dwarf_attr(die, attr, pattr, &dwe)) == DW_DLV_OK) return 1;
    if (ret == DW_DLV_NO_ENTRY) return 0;
    fprintf(log_f, "%s: dwarf_attr failed: %s\n", path, dwarf_errmsg(dwe));
    return -1;
}

static int
s_dwarf_attr_2(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Die die,
        Dwarf_Half attr,
        Dwarf_Attribute *pattr)
{
    Dwarf_Error dwe = NULL;
    int ret;
    if ((ret = dwarf_attr(die, attr, pattr, &dwe)) == DW_DLV_OK) return 1;
    if (ret == DW_DLV_NO_ENTRY) {
        const char *s = NULL;
        dwarf_get_AT_name(attr, &s);
        fprintf(log_f, "%s: attribute %s is undefined\n", path, s);
        return 0;
    }
    fprintf(log_f, "%s: dwarf_attr failed: %s\n", path, dwarf_errmsg(dwe));
    return -1;
}

static int
s_dwarf_offdie(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Off offset,
        Dwarf_Die *pdie)
{
    Dwarf_Error dwe = NULL;
    if (dwarf_offdie_b(dbg, offset, 1, pdie, &dwe) == DW_DLV_OK) return 1;
    fprintf(log_f, "%s: dwarf_offdie_b failed: %s\n", path, dwarf_errmsg(dwe));
    return -1;
}

static int
s_dwarf_formstring(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Attribute attr,
        char **pstr)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Half form_num = 0;

    if (dwarf_whatform(attr, &form_num, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_whatform failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    if (form_num != DW_FORM_strp && form_num != DW_FORM_string) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: DW_FORM_strp expected, but %s obtained\n",
                path, s);
        return -1;
    }
    if (dwarf_formstring(attr, pstr, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formstring failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    return 0;
}

static int
s_dwarf_formudata(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Attribute attr,
        Dwarf_Unsigned *pvalue)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Half form_num = 0;

    if (dwarf_whatform(attr, &form_num, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_whatform failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    if (form_num != DW_FORM_data1 && form_num != DW_FORM_data2 && form_num != DW_FORM_data4 && form_num != DW_FORM_data8) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: DW_FORM_data1 expected, but %s obtained\n",
                path, s);
        return -1;
    }
    if (dwarf_formudata(attr, pvalue, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formudata failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    return 0;
}

static int
s_dwarf_formsdata(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Attribute attr,
        Dwarf_Signed *pvalue)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Half form_num = 0;

    if (dwarf_whatform(attr, &form_num, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_whatform failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    if (form_num != DW_FORM_sdata) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: DW_FORM_sdata expected, but %s obtained\n",
                path, s);
        return -1;
    }
    if (dwarf_formsdata(attr, pvalue, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formsdata failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    return 0;
}

static int
s_dwarf_formflag(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Attribute attr,
        Dwarf_Bool *pvalue)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Half form_num = 0;

    if (dwarf_whatform(attr, &form_num, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_whatform failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    if (form_num != DW_FORM_flag_present) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: DW_FORM_flag expected, but %s obtained\n",
                path, s);
        return -1;
    }
    if (dwarf_formflag(attr, pvalue, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formflag failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    return 0;
}

static int
s_dwarf_global_formref(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Attribute attr,
        Dwarf_Off *poff)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Half form_num = 0;

    if (dwarf_whatform(attr, &form_num, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: %d: dwarf_whatform failed: %s\n",
                path, __LINE__, dwarf_errmsg(dwe));
        return -1;
    }
    if (form_num != DW_FORM_ref4) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: DW_FORM_ref4 expected, but %s obtained\n",
                path, s);
        return -1;
    }
    if (dwarf_global_formref(attr, poff, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formref failed: %s\n",
                path, dwarf_errmsg(dwe));
        return -1;
    }
    return 0;
}

static void
dump_die(FILE *out, Dwarf_Debug dbg, Dwarf_Die die)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Off cu_offset = 0;
    Dwarf_Off offset = 0;

    if (dwarf_die_CU_offset(die, &cu_offset, &dwe) != DW_DLV_OK) goto fail;
    if (dwarf_dieoffset(die, &offset, &dwe) != DW_DLV_OK) goto fail;
    fprintf(out, "DIE information: CU_offset = %llu, offset = %llu\n", cu_offset, offset);

    Dwarf_Half tag = 0;
    const char *tag_name = NULL;

    if (dwarf_tag(die, &tag, &dwe) != DW_DLV_OK) goto fail;
    dwarf_get_TAG_name(tag, &tag_name);
    fprintf(out, "        %d (%s)\n", tag, tag_name);

    Dwarf_Attribute *attrs = NULL;
    Dwarf_Signed attr_count = 0;
    int r = dwarf_attrlist(die, &attrs, &attr_count, &dwe);
    if (r == DW_DLV_NO_ENTRY) return;
    if (r != DW_DLV_OK) goto fail;
    for (int i = 0; i < attr_count; ++i) {
        Dwarf_Half attr_num = 0;
        const char *attr_name = NULL;
        if (dwarf_whatattr(attrs[i], &attr_num, &dwe) != DW_DLV_OK) goto fail;
        dwarf_get_AT_name(attr_num, &attr_name);

        Dwarf_Half form_num = 0;
        const char *form_name = NULL;
        if (dwarf_whatform(attrs[i], &form_num, &dwe) != DW_DLV_OK) goto fail;
        dwarf_get_FORM_name(form_num, &form_name);

        if (form_num == DW_FORM_strp || form_num == DW_FORM_string) {
            char *value = NULL;
            if (dwarf_formstring(attrs[i], &value, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=<%s>\n", attr_name, form_name, value);
        } else if (form_num == DW_FORM_data1 || form_num == DW_FORM_data2 || form_num == DW_FORM_data4 || form_num == DW_FORM_data8) {
            Dwarf_Unsigned value = 0;
            if (dwarf_formudata(attrs[i], &value, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=<%llu>\n", attr_name, form_name, value);
        } else if (form_num == DW_FORM_sdata) {
            Dwarf_Signed value = 0;
            if (dwarf_formsdata(attrs[i], &value, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=<%lld>\n", attr_name, form_name, value);
        } else if (form_num == DW_FORM_ref4) {
            Dwarf_Off ref_cu_offset = 0;
            Dwarf_Off ref_offset = 0;
            if (dwarf_formref(attrs[i], &ref_cu_offset, &dwe) != DW_DLV_OK) goto fail;
            if (dwarf_global_formref(attrs[i], &ref_offset, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=%llu, global %llu\n", attr_name, form_name, ref_cu_offset, ref_offset);
        } else if (form_num == DW_FORM_flag_present) {
            Dwarf_Bool value = 0;
            if (dwarf_formflag(attrs[i], &value, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=%d\n", attr_name, form_name, value);
        } else if (form_num == DW_FORM_addr) {
            Dwarf_Addr value = 0;
            if (dwarf_formaddr(attrs[i], &value, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=%016llx\n", attr_name, form_name, value);
        } else {
            fprintf(out, "        %s,%s=VALUE UNHANDLED\n", attr_name, form_name);
        }
    }

    for (int i = 0; i < attr_count; ++i)
        dwarf_dealloc(dbg, attrs[i], DW_DLA_ATTR);
    dwarf_dealloc(dbg, attrs, DW_DLA_LIST);
    return;

fail:
    fprintf(stderr, "dump_die failed: %s\n", dwarf_errmsg(dwe));
}

typedef int (*parse_kind_func_t)(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info);

static int
parse_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm);

static int
parse_base_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    TypeInfo *ti = NULL;

    // DW_AT_byte_size, DW_FORM_data1
    // DW_AT_encoding, DW_FORM_data1
    // DW_AT_name, DW_FORM_strp

    Dwarf_Attribute bs_attr = NULL;
    Dwarf_Attribute enc_attr = NULL;
    Dwarf_Attribute name_attr = NULL;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_byte_size, &bs_attr) <= 0)
        goto done;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_encoding, &enc_attr) <= 0)
        goto done;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_name, &name_attr) <= 0)
        goto done;

    Dwarf_Unsigned bs = 0;
    Dwarf_Unsigned enc = 0;
    char *name = NULL;
    if (s_dwarf_formudata(log_f, path, bs_attr, &bs) < 0) goto done;
    if (s_dwarf_formudata(log_f, path, enc_attr, &enc) < 0) goto done;
    if (s_dwarf_formstring(log_f, path, name_attr, &name) < 0) goto done;

    if (bs == 1 && enc == DW_ATE_signed_char) {
        ti = tc_get_i8_type(cntx);
    } else if (bs == 1 && enc == DW_ATE_unsigned_char) {
        ti = tc_get_u8_type(cntx);
    } else if (bs == 2 && enc == DW_ATE_signed) {
        ti = tc_get_i16_type(cntx);
    } else if (bs == 2 && enc == DW_ATE_unsigned) {
        ti = tc_get_u16_type(cntx);
    } else if (bs == 4 && enc == DW_ATE_signed) {
        ti = tc_get_i32_type(cntx);
    } else if (bs == 4 && enc == DW_ATE_unsigned) {
        ti = tc_get_u32_type(cntx);
    } else if (bs == 8 && enc == DW_ATE_signed) {
        ti = tc_get_i64_type(cntx);
    } else if (bs == 8 && enc == DW_ATE_unsigned) {
        ti = tc_get_u64_type(cntx);
    } else if (bs == 4 && enc == DW_ATE_float) {
        ti = tc_get_f32_type(cntx);
    } else if (bs == 8 && enc == DW_ATE_float) {
        ti = tc_get_f64_type(cntx);
    } else if (bs == 12 && enc == DW_ATE_float) {
        ti = tc_get_f80_type(cntx);
    }

    const char *ate_name = NULL;
    dwarf_get_ATE_name(enc, &ate_name);

    if (!ti) {
        // unhandled base type
        fprintf(log_f, "Note: unhandled base type (%llu,%s,%s)\n",
                bs, ate_name, name);
        dump_die(log_f, dbg, die);
    }

    *p_info = ti;
    retval = 0;

done:
    return retval;
}

static int
parse_pointer_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    TypeInfo *ti = NULL;

    // DW_AT_byte_size,DW_FORM_data1
    // DW_AT_type,DW_FORM_ref4
    Dwarf_Attribute bs_attr = NULL;
    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_byte_size, &bs_attr) <= 0)
        goto done;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;

    Dwarf_Unsigned bs = 0;
    if (s_dwarf_formudata(log_f, path, bs_attr, &bs) < 0) goto done;

    if (!type_attr) {
        // void*
        ti = tc_get_i0_type(cntx);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
        // temp fix
        if (!ti) ti = tc_get_i0_type(cntx);
    }

    *p_info = ti;
    retval = 0;

done:
    return retval;
}

static int
parse_array_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    TypeInfo *ti = NULL;

    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;
    Dwarf_Off to = 0;
    if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
    Dwarf_Die die2 = NULL;
    if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
    if (parse_die(log_f, path, dbg, die2, cntx, dm) < 0) goto done;
    if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
    // temp fix
    if (!ti) ti = tc_get_i0_type(cntx);

    die2 = NULL;
    if (s_dwarf_child(log_f, path, die, &die2) < 0) goto done;
    Dwarf_Half tag2 = 0;
    if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
    if (tag2 != DW_TAG_subrange_type) {
        fprintf(log_f, "%s: DW_TAG_subrange_type expected\n", path);
        goto done;
    }
    // FIXME: handle type
    Dwarf_Attribute ub_attr = NULL;
    if (s_dwarf_attr(log_f, path, die2, DW_AT_upper_bound, &ub_attr) < 0) goto done;
    if (ub_attr == NULL) {
        ti = tc_get_open_array_type(cntx, ti);
    } else {
        Dwarf_Unsigned ub = 0;
        if (s_dwarf_formudata(log_f, path, ub_attr, &ub) < 0) goto done;
        if (ub >= INT_MAX) {
            fprintf(log_f, "%s: invalid upper bound: %llu\n", path, ub);
            goto done;
        }
        int r = 0;
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
        if (r > 0) {
            fprintf(log_f, "%s: array range has sibling\n", path);
            goto done;
        }
        ti = tc_get_array_type(cntx, ti, tc_get_u32(cntx, ub + 1));
    }

    *p_info = ti;
    retval = 0;

done:
    return retval;
}

static int
parse_const_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    TypeInfo *ti = NULL;
    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;
    if (type_attr == NULL) {
        fprintf(log_f, "DW_TAG_const_type: DW_AT_type missing\n");
        //dump_die(log_f, dbg, die);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
        // temp fix
    }
    if (!ti) ti = tc_get_i0_type(cntx);

    *p_info = tc_get_const_type(cntx, ti);
    retval = 0;

done:
    return retval;
}

static int
parse_typedef_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    TypeInfo *ti = NULL;

    Dwarf_Attribute name_attr = NULL;
    char *name = NULL;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_name, &name_attr) <= 0) goto done;
    if (s_dwarf_formstring(log_f, path, name_attr, &name) < 0) goto done;

    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;
    if (type_attr == NULL) {
        fprintf(log_f, "DW_TAG_typedef_type: DW_AT_type missing\n");
        //dump_die(log_f, dbg, die);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
        // temp fix
    }
    if (!ti) ti = tc_get_i0_type(cntx);

    *p_info = tc_get_typedef_type(cntx, ti, tc_get_ident(cntx, name));
    retval = 0;

done:
    return retval;
}

static int
parse_enum_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;

    Dwarf_Attribute name_attr = NULL;
    TypeInfo *name_info = NULL;
    int r = s_dwarf_attr(log_f, path, die, DW_AT_name, &name_attr);
    if (r < 0) goto done;
    if (!r) {
        name_info = tc_get_ident(cntx, "");
    } else {
        char *name_str = NULL;
        if (s_dwarf_formstring(log_f, path, name_attr, &name_str) < 0) goto done;
        name_info = tc_get_ident(cntx, name_str);
    }

    Dwarf_Attribute size_attr = NULL;
    Dwarf_Unsigned size_value = 0;
    TypeInfo *base_type = NULL;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_byte_size, &size_attr) <= 0) goto done;
    if (s_dwarf_formudata(log_f, path, size_attr, &size_value) < 0) goto done;
    if (size_value == 1) {
        base_type = tc_get_i8_type(cntx);
    } else if (size_value == 2) {
        base_type = tc_get_i16_type(cntx);
    } else if (size_value == 4) {
        base_type = tc_get_i32_type(cntx);
    } else if (size_value == 8) {
        base_type = tc_get_i64_type(cntx);
    } else {
        fprintf(log_f, "%s: no suitable base type for enumeration type\n", path);
        dump_die(log_f, dbg, die);
        goto done;
    }
    TypeInfo *size_info = tc_get_u32(cntx, (unsigned) size_value);

    // count the number of childrens
    Dwarf_Die die2 = NULL;
    int count = 0;
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        ++count;
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }
    if (count < 0 || count > 100000) {
        fprintf(log_f, "%s: too manu enumerated type constants\n", path);
        goto done;
    }

    TypeInfo **info = malloc(sizeof(info[0]) * (count + 4));
    memset(info, 0, sizeof(info[0]) * (count + 4));
    int idx = 0;
    info[idx++] = size_info;
    info[idx++] = name_info;
    info[idx++] = base_type;
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Attribute const_name_attr = NULL;
        char *const_name_str = NULL;
        TypeInfo *const_name_info = NULL;
        if (s_dwarf_attr_2(log_f, path, die2, DW_AT_name, &const_name_attr) <= 0) goto done;
        if (s_dwarf_formstring(log_f, path, const_name_attr, &const_name_str) < 0) goto done;
        const_name_info = tc_get_ident(cntx, const_name_str);

        Dwarf_Attribute const_value_attr = NULL;
        Dwarf_Signed const_value_value = 0;
        TypeInfo *const_value_info = NULL;
        if (s_dwarf_attr_2(log_f, path, die2, DW_AT_const_value, &const_value_attr) <= 0) goto done;
        if (s_dwarf_formsdata(log_f, path, const_value_attr, &const_value_value) < 0) goto done;
        const_value_info = tc_get_it(cntx, base_type, const_value_value);

        info[idx++] = tc_get_enum_const(cntx, size_info, const_name_info, const_value_info);

        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    *p_info = tc_get_enum_type(cntx, info);
    retval = 0;

done:
    return retval;
}

static int
parse_struct_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    int r;
    Dwarf_Die die2 = NULL;
    TypeInfo *ti = NULL;

    /*
    fprintf(log_f, "Structure DIE\n");
    dump_die(log_f, dbg, die);

    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        fprintf(log_f, "Structure child DIE\n");
        dump_die(log_f, dbg, die2);
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }
    */

    // DW_AT_name,DW_FORM_strp
    // DW_AT_byte_size,DW_FORM_data1

    Dwarf_Attribute name_attr = NULL;
    TypeInfo *name_info = NULL;
    r = s_dwarf_attr(log_f, path, die, DW_AT_name, &name_attr);
    if (r < 0) goto done;
    if (!r) {
        name_info = tc_get_ident(cntx, "");
    } else {
        char *name_str = NULL;
        if (s_dwarf_formstring(log_f, path, name_attr, &name_str) < 0) goto done;
        name_info = tc_get_ident(cntx, name_str);
    }

    Dwarf_Attribute declaration_attr = NULL;
    Dwarf_Bool declaration_value = 0;
    if ((r = s_dwarf_attr(log_f, path, die, DW_AT_declaration, &declaration_attr)) < 0) goto done;
    if (declaration_attr) {
        if (s_dwarf_formflag(log_f, path, declaration_attr, &declaration_value) < 0) goto done;
        if (declaration_value) {
            ASSERT(name_info->s.len > 0);
            ti = tc_find_struct_type(cntx, tag, name_info);
            if (ti != NULL) {
                *p_info = ti;
                retval = 0;
                goto done;
            }
            *p_info = tc_create_struct_type(cntx, tag, tc_get_u32(cntx, 0), name_info, tc_get_i1(cntx, 0));
            retval = 0;
            goto done;
        }
    }

    Dwarf_Attribute size_attr = NULL;
    Dwarf_Unsigned size_value = 0;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_byte_size, &size_attr) <= 0) goto done;
    if (s_dwarf_formudata(log_f, path, size_attr, &size_value) < 0) goto done;
    TypeInfo *size_info = tc_get_u32(cntx, (unsigned) size_value);

    /*
    Dwarf_Attribute decl_file_attr = NULL;
    Dwarf_Unsigned decl_file_value = 0;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_decl_file, &decl_file_attr) <= 0) goto done;
    if (s_dwarf_formudata(log_f, path, decl_file_attr, &decl_file_value) < 0) goto done;
    TypeInfo *decl_file_info = tc_get_u32(cntx, (unsigned) decl_file_value);

    Dwarf_Attribute decl_line_attr = NULL;
    Dwarf_Unsigned decl_line_value = 0;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_decl_line, &decl_line_attr) <= 0) goto done;
    if (s_dwarf_formudata(log_f, path, decl_line_attr, &decl_line_value) < 0) goto done;
    TypeInfo *decl_line_info = tc_get_u32(cntx, (unsigned) decl_line_value);
    */

    if (name_info->s.len > 0) {
        // named structure
        ti = tc_find_struct_type(cntx, tag, name_info);
        if (ti != NULL) {
            *p_info = ti;
            retval = 0;
            goto done;
        }
        ti = tc_create_struct_type(cntx, tag, size_info, name_info, tc_get_i1(cntx, 1));
    }

    int count = 0;
    die2 = NULL;
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        ++count;
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 != DW_TAG_member) {
            fprintf(log_f, "%s: DW_TAG_member expected\n", path);
            goto done;
        }
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }
    if (count <= 0) {
        // empty structure
        *p_info = ti;
        retval = 0;
        goto done;
    }

    TypeInfo **info = alloca(sizeof(info[0]) * (count + 4));
    memset(info, 0, sizeof(info[0]) * (count + 4));
    int idx = 0;
    info[idx++] = size_info;
    info[idx++] = name_info;
    info[idx++] = tc_get_i1(cntx, 1);

    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Attribute field_name_attr = NULL;
        char *field_name_str = NULL;
        if (s_dwarf_attr_2(log_f, path, die2, DW_AT_name, &field_name_attr) <= 0) goto done;
        if (s_dwarf_formstring(log_f, path, field_name_attr, &field_name_str) < 0) goto done;
        TypeInfo *field_name_info = tc_get_ident(cntx, field_name_str);

        Dwarf_Attribute field_type_attr = NULL;
        Dwarf_Off field_type_off = 0;
        Dwarf_Die field_type_die = NULL;
        TypeInfo *field_type_info = NULL;
        if (s_dwarf_attr_2(log_f, path, die2, DW_AT_type, &field_type_attr) <= 0) goto done;
        if (s_dwarf_global_formref(log_f, path, field_type_attr, &field_type_off) < 0) goto done;
        if (s_dwarf_offdie(log_f, path, dbg, field_type_off, &field_type_die) < 0) goto done;
        if (parse_die(log_f, path, dbg, field_type_die, cntx, dm) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, field_type_die, &field_type_info, NULL) < 0) goto done;
        if (!field_type_info) field_type_info = tc_get_i0_type(cntx);

        Dwarf_Attribute location_attr = NULL;
        Dwarf_Unsigned location_value = 0;
        TypeInfo *location_info = NULL;
        if ((r = s_dwarf_attr(log_f, path, die2, DW_AT_data_member_location, &location_attr)) < 0) goto done;
        if (location_attr != NULL) {
            if (s_dwarf_attr_2(log_f, path, die2, DW_AT_data_member_location, &location_attr) <= 0) goto done;
            if (s_dwarf_formudata(log_f, path, location_attr, &location_value) < 0) goto done;
            location_info = tc_get_u32(cntx, (unsigned) location_value);
        } else {
            location_info = tc_get_u32(cntx, 0);
        }

        info[idx++] = tc_get_field(cntx, field_type_info, field_name_info, location_info);

        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    if (ti) {
        ASSERT(ti->s.len > 0);
        type_info_set_info(ti, info);
    } else {
        ti = tc_get_anon_struct_type(cntx, tag, info);
    }

    *p_info = ti;
    retval = 0;

done:
    return retval;
}

static int
parse_function_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info)
{
    int retval = -1;
    int r = 0;
    Dwarf_Die die2 = NULL;

    fprintf(log_f, "Function DIE\n");
    dump_die(log_f, dbg, die);

    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        fprintf(log_f, "Structure child DIE\n");
        dump_die(log_f, dbg, die2);
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }


    *p_info = tc_get_i0_type(cntx);
    retval = 0;

done:
    return retval;
}

static int
parse_die_type(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        const unsigned char *type_str,
        parse_kind_func_t parse_func)
{
    int retval = -1;
    TypeInfo *ti = NULL;
    Dwarf_Off die_offset = 0;

    if (die_map_get_2(log_f, path, dm, die, &ti, &die_offset) < 0) goto done;
    if (ti) {
        fprintf(log_f, "Note: %s type at %llu already registered as %016llx\n",
                type_str, (long long) die_offset, (long long) (size_t) ti);
        retval = 0;
        goto done;
    }

    if (parse_func(log_f, path, dbg, die, cntx, dm, tag, &ti) < 0) goto done;

    fprintf(log_f, "Note: %s type %llu mapped to %016llx\n",
            type_str, die_offset, (unsigned long long) (size_t) ti);
    die_map_put(dm, die_offset, ti);
    retval = 0;

done:
    return retval;
}

struct TopDieParseTable
{
    Dwarf_Half tag;
    int kind;
    const char *comment;
    parse_kind_func_t handler;    
};
static const struct TopDieParseTable top_die_table[] =
{
    { DW_TAG_base_type, NODE_BASE_TYPE, "base", parse_base_type_die },
    { DW_TAG_pointer_type, NODE_POINTER_TYPE, "pointer", parse_pointer_type_die },
    { DW_TAG_array_type, NODE_ARRAY_TYPE, "array", parse_array_type_die },
    { DW_TAG_const_type, NODE_CONST_TYPE, "const", parse_const_type_die },
    { DW_TAG_typedef, NODE_TYPEDEF_TYPE, "typedef", parse_typedef_type_die },
    { DW_TAG_enumeration_type, NODE_ENUM_TYPE, "enum", parse_enum_type_die },
    { DW_TAG_structure_type, NODE_STRUCT_TYPE, "struct", parse_struct_type_die },
    { DW_TAG_union_type, NODE_UNION_TYPE, "union", parse_struct_type_die },
    { DW_TAG_subroutine_type, NODE_FUNCTION_TYPE, "function", parse_function_type_die },
    { DW_TAG_variable, 0, NULL, NULL },
    { DW_TAG_subprogram, 0, NULL, NULL },

    { 0 },
};

static int
parse_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm)
{
    int retval = -1;

    Dwarf_Half dtag = 0;
    if (s_dwarf_tag(log_f, path, die, &dtag) < 0) goto done;
    for (int i = 0; top_die_table[i].tag; ++i) {
        if (dtag != top_die_table[i].tag) continue;
        if (!top_die_table[i].kind) return 0;
        return parse_die_type(log_f, path, dbg, die, cntx, dm,
                              top_die_table[i].kind, top_die_table[i].comment,
                              top_die_table[i].handler);
    }

    dump_die(log_f, dbg, die);
    retval = 0;

done:
    return retval;
}

static int
parse_cu(FILE *log_f, const unsigned char *path, Dwarf_Debug dbg, TypeContext *cntx)
{
    Dwarf_Die die = NULL;
    int retval = -1;
    DieMap *dm = die_map_init();

    if (s_dwarf_sibling(log_f, path, dbg, NULL, &die) <= 0) goto done;
    Dwarf_Half dtag = 0;
    if (s_dwarf_tag(log_f, path, die, &dtag) < 0) goto done;
    if (dtag != DW_TAG_compile_unit) {
        const char *s = NULL;
        dwarf_get_TAG_name(dtag, &s);
        fprintf(log_f, "%s: DW_TAG_compile_unit expected, %s obtained\n",
                path, s);
        goto done;
    }
    if (s_dwarf_child(log_f, path, die, &die) <= 0) goto done;
    if (parse_die(log_f, path, dbg, die, cntx, dm) < 0) goto done;
    while (s_dwarf_sibling(log_f, path, dbg, die, &die) > 0) {
        if (parse_die(log_f, path, dbg, die, cntx, dm) < 0) goto done;
    }
    retval = 0;

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
