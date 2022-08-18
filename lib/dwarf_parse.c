/* -*- c -*- */

/* Copyright (C) 2014-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/dwarf_parse.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

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

#include <libdwarf-internal/dwarf.h>
#include <libdwarf-internal/libdwarf.h>

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
    int pos = 0;
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
    if ((res = dwarf_siblingof(dbg, die, pdie, &dwe)) == DW_DLV_OK)
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
    if (dwarf_offdie(dbg, offset, pdie, &dwe) == DW_DLV_OK) return 1;
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
    if (form_num == DW_FORM_sdata) {
        Dwarf_Signed tmp = 0;
        if (dwarf_formsdata(attr, pvalue, &dwe) != DW_DLV_OK) {
            fprintf(log_f, "%s: dwarf_formsdata failed: %s\n", path, dwarf_errmsg(dwe));
            return -1;
        }
        *pvalue = tmp;
        return 0;
    }
    if (form_num == DW_FORM_implicit_const) {
        Dwarf_Signed tmp = 0;
        if (dwarf_formsdata(attr, &tmp, &dwe) != DW_DLV_OK) {
            fprintf(log_f, "%s: dwarf_formsdata failed: %s\n", path, dwarf_errmsg(dwe));
            return -1;
        }
        *pvalue = tmp;
        return 0;
    }
    if (form_num == DW_FORM_block1 || form_num == DW_FORM_block2 || form_num == DW_FORM_block4) {
        Dwarf_Block *dwb = NULL;
        if (dwarf_formblock(attr, &dwb, &dwe) != DW_DLV_OK) {
            fprintf(log_f, "%s: dwarf_formblock failed: %s\n", path, dwarf_errmsg(dwe));
            return -1;
        }
        if (dwb->bl_len == 1) {
            const unsigned char *pp = (const unsigned char*) dwb->bl_data;
            *pvalue = *pp;
            return 0;
        } else if (dwb->bl_len == 2) {
            const unsigned short *pp = (const unsigned short*) dwb->bl_data;
            *pvalue = *pp;
            return 0;
        } else if (dwb->bl_len == 3) {
            const unsigned char *pp = (const unsigned char *) dwb->bl_data;
            // little-endian assumed
            *pvalue = pp[0] | (pp[1] << 8) | (pp[2] << 16);
            return 0;
        } else if (dwb->bl_len == 4) {
            const unsigned *pp = (const unsigned*) dwb->bl_data;
            *pvalue = *pp;
            return 0;
        } else {
            fprintf(log_f, "%s: %s: invalid block length %d\n", path, __FUNCTION__, (int) dwb->bl_len);
            return -1;
        }
    }
    if (form_num != DW_FORM_data1 && form_num != DW_FORM_data2 && form_num != DW_FORM_data4 && form_num != DW_FORM_data8) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: %s: DW_FORM_data* expected, but %s obtained\n", path, __FUNCTION__, s);
        return -1;
    }
    if (dwarf_formudata(attr, pvalue, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formudata failed: %s\n", path, dwarf_errmsg(dwe));
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
    __attribute__((unused));
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
        fprintf(log_f, "%s: %s: DW_FORM_sdata expected, but %s obtained\n",
                path, __FUNCTION__, s);
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
s_dwarf_formdata(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Attribute attr,
        Dwarf_Signed *pvalue)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Half form_num = 0;

    if (dwarf_whatform(attr, &form_num, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_whatform failed: %s\n", path, dwarf_errmsg(dwe));
        return -1;
    }
    if (form_num == DW_FORM_sdata) {
        if (dwarf_formsdata(attr, pvalue, &dwe) != DW_DLV_OK) {
            fprintf(log_f, "%s: dwarf_formsdata failed: %s\n", path, dwarf_errmsg(dwe));
            return -1;
        }
        return 0;
    }
    if (form_num == DW_FORM_implicit_const) {
        Dwarf_Signed tmp = 0;
        if (dwarf_formsdata(attr, &tmp, &dwe) != DW_DLV_OK) {
            fprintf(log_f, "%s: dwarf_formsdata failed: %s\n", path, dwarf_errmsg(dwe));
            return -1;
        }
        *pvalue = tmp;
        return 0;
    }
    if (form_num == DW_FORM_block1 || form_num == DW_FORM_block2 || form_num == DW_FORM_block4) {
        Dwarf_Block *dwb = NULL;
        if (dwarf_formblock(attr, &dwb, &dwe) != DW_DLV_OK) {
            fprintf(log_f, "%s: dwarf_formblock failed: %s\n", path, dwarf_errmsg(dwe));
            return -1;
        }
        if (dwb->bl_len == 1) {
            const unsigned char *pp = (const unsigned char*) dwb->bl_data;
            *pvalue = *pp;
            return 0;
        } else if (dwb->bl_len == 2) {
            const unsigned short *pp = (const unsigned short*) dwb->bl_data;
            *pvalue = *pp;
            return 0;
        } else if (dwb->bl_len == 3) {
            const unsigned char *pp = (const unsigned char *) dwb->bl_data;
            // little-endian assumed
            *pvalue = pp[0] | (pp[1] << 8) | (pp[2] << 16);
            return 0;
        } else if (dwb->bl_len == 4) {
            const unsigned *pp = (const unsigned*) dwb->bl_data;
            *pvalue = *pp;
            return 0;
        } else {
            fprintf(log_f, "%s: invalid block length %d\n", path, (int) dwb->bl_len);
            return -1;
        }
    }
    if (form_num != DW_FORM_data1 && form_num != DW_FORM_data2 && form_num != DW_FORM_data4 && form_num != DW_FORM_data8) {
        const char *s = NULL;
        dwarf_get_FORM_name(form_num, &s);
        fprintf(log_f, "%s: %s: DW_FORM_data* expected, but %s obtained\n", path, __FUNCTION__, s);
        return -1;
    }
    Dwarf_Unsigned tmp = 0;
    if (dwarf_formudata(attr, &tmp, &dwe) != DW_DLV_OK) {
        fprintf(log_f, "%s: dwarf_formudata failed: %s\n", path, dwarf_errmsg(dwe));
        return -1;
    }
    *pvalue = tmp;
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
    if (form_num != DW_FORM_flag_present && form_num != DW_FORM_flag) {
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

static Dwarf_Off
s_dwarf_dieoffset(Dwarf_Die die)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Off offset = 0;
    if (dwarf_dieoffset(die, &offset, &dwe) != DW_DLV_OK) {
        fprintf(stderr, "s_dwarf_dieoffset failed: %s\n", dwarf_errmsg(dwe));
        return 0;
    }
    return offset;
}

static __attribute__((unused)) int
die_get_attrcount(Dwarf_Die die)
{
    Dwarf_Attribute *attrs = NULL;
    Dwarf_Signed count = 0;
    Dwarf_Error err = 0;

    if (dwarf_attrlist(die, &attrs, &count, &err) != DW_DLV_OK)
        return -1;
    // FIXME: should we free attrs?
    return count;
}

static void
dump_die(FILE *out, Dwarf_Debug dbg, Dwarf_Die die)
{
    Dwarf_Error dwe = NULL;
    Dwarf_Off cu_offset = 0;
    Dwarf_Off offset = 0;

    if (dwarf_die_CU_offset(die, &cu_offset, &dwe) != DW_DLV_OK) goto fail;
    if (dwarf_dieoffset(die, &offset, &dwe) != DW_DLV_OK) goto fail;
    fprintf(out, "DIE information: CU_offset = %llu (0x%llx), offset = %llu (0x%llx)\n", cu_offset, cu_offset, offset, offset);

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
        } else if (form_num == DW_FORM_implicit_const) {
            Dwarf_Signed value = 0;
            if (dwarf_formsdata(attrs[i], &value, &dwe) != DW_DLV_OK) goto fail;
            fprintf(out, "        %s,%s=<%lld>\n", attr_name, form_name, value);
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

typedef struct ParseDieStack
{
    struct ParseDieStack *up;
    Dwarf_Off offset;
    TypeInfo *type_info;
} ParseDieStack;

static ParseDieStack *
die_stack_lookup(ParseDieStack *elem, Dwarf_Off offset)
{
    for (; elem; elem = elem->up) {
        if (elem->offset == offset)
            return elem;
    }
    return NULL;
}

typedef int (*parse_kind_func_t)(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope);

static int
parse_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        ParseDieStack *up,
        IdScope *global_scope);

static int
parse_type(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    *p_info = NULL;

    Dwarf_Attribute type_attr = NULL;
    int r = s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr);
    if (r < 0) return r;
    if (!r || !type_attr) return 0;

    Dwarf_Off type_off = 0;
    if (s_dwarf_global_formref(log_f, path, type_attr, &type_off) < 0) return -1;
    Dwarf_Die type_die = NULL;
    if (s_dwarf_offdie(log_f, path, dbg, type_off, &type_die) < 0) return -1;
    if (parse_die(log_f, path, dbg, type_die, cntx, dm, cur, global_scope) < 0) return -1;
    TypeInfo *type_info = NULL;
    if (die_map_get_2(log_f, path, dm, type_die, &type_info, NULL) < 0) return -1;
    if (!type_info) return 0;

    *p_info = type_info;
    return 1;
}

static int
parse_base_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
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
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_name, &name_attr) <= 0) {
        // this happens on Debian
        retval = 0;
        goto done;
    }

    Dwarf_Unsigned bs = 0;
    Dwarf_Unsigned enc = 0;
    char *name = NULL;
    if (s_dwarf_formudata(log_f, path, bs_attr, &bs) < 0) goto done;
    if (s_dwarf_formudata(log_f, path, enc_attr, &enc) < 0) goto done;
    if (s_dwarf_formstring(log_f, path, name_attr, &name) < 0) goto done;

    if (bs == 1 && enc == DW_ATE_boolean) {
        ti = tc_get_i1_type(cntx);
    } else if (bs == 1 && enc == DW_ATE_signed_char) {
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
    } else if (bs == 16 && enc == DW_ATE_signed) {
        // FIXME: create 128-bit type
        ti = tc_get_i64_type(cntx);
    } else if (bs == 16 && enc == DW_ATE_unsigned) {
        // FIXME: create 128-bit type
        ti = tc_get_u64_type(cntx);
    } else if (bs == 4 && enc == DW_ATE_float) {
        ti = tc_get_f32_type(cntx);
    } else if (bs == 8 && enc == DW_ATE_float) {
        ti = tc_get_f64_type(cntx);
    } else if (bs == 12 && enc == DW_ATE_float) {
        ti = tc_get_f80_type(cntx);
    } else if (bs == 16 && enc == DW_ATE_float) {
        // FIXME: f128?
        ti = tc_get_f80_type(cntx);
    } else if (enc == DW_ATE_complex_float) {
        ti = tc_get_f64_type(cntx);
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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    TypeInfo *ti = NULL;

    // clang does not generate DW_AT_byte_size, which is not used anyway...
    // DW_AT_byte_size,DW_FORM_data1
    // DW_AT_type,DW_FORM_ref4
    Dwarf_Attribute bs_attr = NULL;
    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_byte_size, &bs_attr) < 0)
        goto done;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;

    Dwarf_Unsigned bs = 0;
    if (bs_attr) {
        if (s_dwarf_formudata(log_f, path, bs_attr, &bs) < 0) {
            dump_die(log_f, dbg, die);
            goto done;
        }
    }

    if (!type_attr) {
        // void*
        ti = tc_get_i0_type(cntx);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm, cur, global_scope) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
        // temp fix
        if (!ti) ti = tc_get_i0_type(cntx);
    }

    *p_info = tc_get_ptr_type(cntx, ti);
    retval = 0;

done:
    return retval;
}

static int
parse_index_range_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        TypeInfo *base_info,
        TypeInfo **p_info)
{
    int retval = -1;
    Dwarf_Half tag = 0;
    int r;

    if (s_dwarf_tag(log_f, path, die, &tag) < 0) goto done;
    if (tag != DW_TAG_subrange_type) {
        fprintf(log_f, "%s: DW_TAG_subrange_type expected\n", path);
        dump_die(log_f, dbg, die);
        goto done;
    }

    Dwarf_Die die2 = NULL;
    if ((r = s_dwarf_sibling(log_f, path, dbg, die, &die2)) < 0) goto done;
    if (r > 0) {
        if (parse_index_range_die(log_f, path, dbg, die2, cntx, base_info, &base_info) < 0) goto done;
    }

    // FIXME: handle type
    Dwarf_Attribute ub_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_upper_bound, &ub_attr) < 0) goto done;
    if (ub_attr == NULL) {
        *p_info = tc_get_open_array_type(cntx, base_info);
    } else {
        Dwarf_Signed ub = 0;
        if (s_dwarf_formdata(log_f, path, ub_attr, &ub) < 0) goto done;
        if (ub == INT_MAX) {
            ub = 0;
        } else if (ub > INT_MAX) {
            //fprintf(log_f, "%s: invalid upper bound: %llu\n", path, ub);
            //dump_die(log_f, dbg, die);
            ub = 0;
        }
        *p_info = tc_get_array_type(cntx, base_info, tc_get_u32(cntx, ub + 1));
    }
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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
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
    if (parse_die(log_f, path, dbg, die2, cntx, dm, cur, global_scope) < 0) goto done;
    if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
    // temp fix
    if (!ti) ti = tc_get_i0_type(cntx);

    die2 = NULL;
    if (s_dwarf_child(log_f, path, die, &die2) < 0) goto done;

    if (parse_index_range_die(log_f, path, dbg, die2, cntx, ti, &ti) < 0) goto done;

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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    TypeInfo *ti = NULL;
    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;
    if (type_attr == NULL) {
        //fprintf(log_f, "DW_TAG_const_type: DW_AT_type missing\n");
        //dump_die(log_f, dbg, die);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm, cur, global_scope) < 0) goto done;
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
parse_volatile_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    TypeInfo *ti = NULL;
    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;
    if (type_attr == NULL) {
        //fprintf(log_f, "DW_TAG_const_type: DW_AT_type missing\n");
        //dump_die(log_f, dbg, die);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm, cur, global_scope) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
        // temp fix
    }
    if (!ti) ti = tc_get_i0_type(cntx);

    *p_info = tc_get_volatile_type(cntx, ti);
    retval = 0;

done:
    return retval;
}

static int
parse_restrict_type_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    TypeInfo *ti = NULL;
    Dwarf_Attribute type_attr = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_type, &type_attr) < 0)
        goto done;
    if (type_attr == NULL) {
        //fprintf(log_f, "DW_TAG_const_type: DW_AT_type missing\n");
        //dump_die(log_f, dbg, die);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm, cur, global_scope) < 0) goto done;
        if (die_map_get_2(log_f, path, dm, die2, &ti, NULL) < 0) goto done;
        // temp fix
    }
    if (!ti) ti = tc_get_i0_type(cntx);

    // FIXME: add support for 'restrict'?
    // *p_info = tc_get_volatile_type(cntx, ti);
    *p_info = ti;
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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
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
        //fprintf(log_f, "DW_TAG_typedef_type: DW_AT_type missing\n");
        //dump_die(log_f, dbg, die);
    } else {
        Dwarf_Off to = 0;
        if (s_dwarf_global_formref(log_f, path, type_attr, &to) < 0) goto done;
        Dwarf_Die die2 = NULL;
        if (s_dwarf_offdie(log_f, path, dbg, to, &die2) < 0) goto done;
        if (parse_die(log_f, path, dbg, die2, cntx, dm, cur, global_scope) < 0) goto done;
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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
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

    TypeInfo **info = alloca(sizeof(info[0]) * (count + 4));
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
        if (s_dwarf_formdata(log_f, path, const_value_attr, &const_value_value) < 0) goto done;
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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    int r;
    Dwarf_Die die2 = NULL;
    TypeInfo *ti = NULL;
    Dwarf_Off my_offset = s_dwarf_dieoffset(die);
    ParseDieStack *stk = die_stack_lookup(cur->up, my_offset);

    if (stk && stk->type_info) {
        if (p_info) *p_info = stk->type_info;
        retval = 0;
        goto done;
    }
    if (stk) {
        dump_die(log_f, dbg, die);
    }
    ASSERT(!stk);

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
        ASSERT(ti);
        cur->type_info = ti;
    }

    // process nested struct/unions
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_structure_type || tag2 == DW_TAG_union_type) {
            r = parse_struct_type_die(log_f, path, dbg, die2, cntx, dm, tag2, p_info, cur, global_scope);
            if (r < 0) goto done;
        }
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    if (name_info->s.len > 0) {
        *p_info = ti;
        retval = 0;
        goto done;
    }

    int count = 0;
    die2 = NULL;
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_structure_type || tag2 == DW_TAG_union_type) {
            // nothing
        } else if (tag2 == DW_TAG_member) {
            ++count;
        } else {
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
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_member) {
            Dwarf_Attribute field_name_attr = NULL;
            char *field_name_str = NULL;
            if ((r = s_dwarf_attr(log_f, path, die2, DW_AT_name, &field_name_attr)) < 0) goto done;
            if (r > 0) {
                if (s_dwarf_formstring(log_f, path, field_name_attr, &field_name_str) < 0) goto done;
            } else {
                field_name_str = "";
            }
            TypeInfo *field_name_info = tc_get_ident(cntx, field_name_str);

            Dwarf_Attribute field_type_attr = NULL;
            Dwarf_Off field_type_off = 0;
            Dwarf_Die field_type_die = NULL;
            TypeInfo *field_type_info = NULL;
            if (s_dwarf_attr_2(log_f, path, die2, DW_AT_type, &field_type_attr) <= 0) goto done;
            if (s_dwarf_global_formref(log_f, path, field_type_attr, &field_type_off) < 0) goto done;
            if (s_dwarf_offdie(log_f, path, dbg, field_type_off, &field_type_die) < 0) goto done;
            if (parse_die(log_f, path, dbg, field_type_die, cntx, dm, cur, global_scope) < 0) goto done;
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

            info[idx++] = tc_get_field(cntx, location_info, field_type_info, field_name_info);
        }

        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    if (ti) {
        ASSERT(ti->s.len > 0);
        type_info_set_info(ti, info);
        //fprintf(stderr, "Update type info for struct %s\n", ti->n.info[1]->s.str);
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
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    int r = 0;
    Dwarf_Die die2 = NULL;

    /*
    fprintf(log_f, "Function DIE\n");
    dump_die(log_f, dbg, die);

    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        fprintf(log_f, "Structure child DIE\n");
        dump_die(log_f, dbg, die2);
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }
    */

    TypeInfo *ret_type = NULL;
    if ((r = parse_type(log_f, path, dbg, die, cntx, dm, &ret_type, cur, global_scope)) < 0) goto done;
    if (!r || !ret_type) ret_type = tc_get_i0_type(cntx);

    int count = 0;
    die2 = NULL;
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        ++count;
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 != DW_TAG_formal_parameter && tag2 != DW_TAG_unspecified_parameters) {
            fprintf(log_f, "%s: DW_TAG_formal_parameter or DW_TAG_unspecified_parameters expected\n", path);
            dump_die(log_f, dbg, die2);
            goto done;
        }
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    TypeInfo **info = alloca(sizeof(info[0]) * (count + 3));
    memset(info, 0, sizeof(info[0]) * (count + 3));
    int idx = 0;
    info[idx++] = tc_get_u32(cntx, 0);
    info[idx++] = ret_type;

    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Half tag2 = 0;
        TypeInfo *par_type_info = NULL;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_unspecified_parameters) {
            info[idx++] = tc_get_anyseq_type(cntx);
        } else {
            if ((r = parse_type(log_f, path, dbg, die2, cntx, dm, &par_type_info, cur, global_scope)) < 0) goto done;
            if (!r || !par_type_info) par_type_info = tc_get_i0_type(cntx);
            info[idx++] = par_type_info;
        }

        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    *p_info = tc_get_function_type(cntx, info);
    retval = 0;

done:
    return retval;
}

static int
parse_subroutine_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        int tag,
        TypeInfo **p_info,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;

    /*
    fprintf(log_f, "Subroutine DIE\n");
    dump_die(log_f, dbg, die);
    */

    // support only external and prototyped subroutines
    Dwarf_Attribute external_attr = NULL;
    Dwarf_Attribute prototyped_attr = NULL;
    Dwarf_Bool external_flag = 0;
    Dwarf_Bool prototyped_flag = 0;
    if (s_dwarf_attr(log_f, path, die, DW_AT_external, &external_attr) < 0) goto done;
    if (s_dwarf_attr(log_f, path, die, DW_AT_prototyped, &prototyped_attr) < 0) goto done;
    if (!external_attr || !prototyped_attr) {
        retval = 0;
        goto done;
    }

    if (s_dwarf_formflag(log_f, path, external_attr, &external_flag) < 0) goto done;
    if (s_dwarf_formflag(log_f, path, prototyped_attr, &prototyped_flag) < 0) goto done;
    if (!external_flag || !prototyped_flag) {
        retval = 0;
        goto done;
    }

    Dwarf_Attribute name_attr = NULL;
    char *name_str = NULL;
    TypeInfo *name_info = NULL;
    if (s_dwarf_attr(log_f, path, die, DW_AT_name, &name_attr) < 0) goto done;
    if (!name_attr) {
        retval = 0;
        goto done;
    }
    if (s_dwarf_formstring(log_f, path, name_attr, &name_str) < 0) goto done;
    if (!name_str || !*name_str) {
        retval = 0;
        goto done;
    }
    name_info = tc_get_ident(cntx, name_str);

    TypeInfo *ret_type_info = NULL;
    if (parse_type(log_f, path, dbg, die, cntx, dm, &ret_type_info, cur, global_scope) < 0) goto done;
    if (!ret_type_info) ret_type_info = tc_get_i0_type(cntx);

    TypeInfo **info = alloca(sizeof(info[0]) * 4);
    int idx = 0;

    // create function type node
    info[idx++] = tc_get_u32(cntx, 0);
    info[idx++] = ret_type_info;
    info[idx++] = NULL;
    TypeInfo *func_type_info = tc_get_function_type(cntx, info);

    idx = 0;
    info[idx++] = tc_get_u32(cntx, 0);
    info[idx++] = func_type_info;
    info[idx++] = name_info;
    info[idx++] = NULL;
    *p_info = tc_get_function(cntx, info);

    tc_scope_add(global_scope, *p_info);
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
        parse_kind_func_t parse_func,
        ParseDieStack *cur,
        IdScope *global_scope)
{
    int retval = -1;
    TypeInfo *ti = NULL;
    Dwarf_Off die_offset = 0;

    if (die_map_get_2(log_f, path, dm, die, &ti, &die_offset) < 0) goto done;
    if (ti) {
        /*
        fprintf(log_f, "Note: %s type at %llu already registered as %016llx\n",
                type_str, (long long) die_offset, (long long) (size_t) ti);
        */
        retval = 0;
        goto done;
    }

    if (parse_func(log_f, path, dbg, die, cntx, dm, tag, &ti, cur, global_scope) < 0) goto done;

    /*
    fprintf(log_f, "Note: %s type %llu mapped to %016llx\n",
            type_str, die_offset, (unsigned long long) (size_t) ti);
    */
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
    { DW_TAG_volatile_type, NODE_VOLATILE_TYPE, "volatile", parse_volatile_type_die },
    { DW_TAG_restrict_type, 0, "restrict", parse_restrict_type_die },
    { DW_TAG_typedef, NODE_TYPEDEF_TYPE, "typedef", parse_typedef_type_die },
    { DW_TAG_enumeration_type, NODE_ENUM_TYPE, "enum", parse_enum_type_die },
    { DW_TAG_structure_type, NODE_STRUCT_TYPE, "struct", parse_struct_type_die },
    { DW_TAG_union_type, NODE_UNION_TYPE, "union", parse_struct_type_die },
    { DW_TAG_subroutine_type, NODE_FUNCTION_TYPE, "function", parse_function_type_die },
    { DW_TAG_variable, 0, NULL, NULL },
    { DW_TAG_subprogram, NODE_SUBROUTINE, "subprogram", parse_subroutine_die },
    { DW_TAG_dwarf_procedure, 0, NULL, NULL },
    { DW_TAG_atomic_type, 0, NULL, NULL },

    { 0 },
};

static int
parse_die(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        ParseDieStack *up,
        IdScope *global_scope)
{
    int retval = -1;
    Dwarf_Off my_offset = s_dwarf_dieoffset(die);
    ParseDieStack cur = { up, my_offset, NULL };

    Dwarf_Half dtag = 0;
    if (s_dwarf_tag(log_f, path, die, &dtag) < 0) goto done;
    for (int i = 0; top_die_table[i].tag; ++i) {
        if (dtag != top_die_table[i].tag) continue;
        if (!top_die_table[i].kind) return 0;
        return parse_die_type(log_f, path, dbg, die, cntx, dm,
                              top_die_table[i].kind, top_die_table[i].comment,
                              top_die_table[i].handler, &cur, global_scope);
    }

    dump_die(log_f, dbg, die);
    retval = 0;

done:
    return retval;
}

static int
parse_die_pass_0(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm)
{
    int retval = -1;
    Dwarf_Half tag = 0;
    int kind;
    int r;
    Dwarf_Die die2 = NULL;

    if (s_dwarf_tag(log_f, path, die, &tag) < 0) goto done;
    if (tag == DW_TAG_structure_type) {
        kind = NODE_STRUCT_TYPE;
    } else if (tag == DW_TAG_union_type) {
        kind = NODE_UNION_TYPE;
    } else {
        retval = 0;
        goto done;
    }

    Dwarf_Attribute name_attr = NULL;
    TypeInfo *name_info = NULL;
    if ((r = s_dwarf_attr(log_f, path, die, DW_AT_name, &name_attr)) < 0) goto done;
    if (!r) {
        // anonymous structure/union
        // still traverse nested structs/unions
        if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
        while (r > 0) {
            Dwarf_Half tag2 = 0;
            if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
            if (tag2 == DW_TAG_structure_type || tag2 == DW_TAG_union_type) {
                //fprintf(stderr, "DEBUG: parse_die_pass_0: struct/union nested in anonymous struct/union\n");
                if ((r = parse_die_pass_0(log_f, path, dbg, die2, cntx, dm)) < 0) goto done;
            }
            if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
        }

        retval = 0;
        goto done;
    }
    char *name_str = NULL;
    if (s_dwarf_formstring(log_f, path, name_attr, &name_str) < 0) goto done;
    name_info = tc_get_ident(cntx, name_str);

    Dwarf_Attribute size_attr = NULL;
    Dwarf_Unsigned size_value = 0;
    TypeInfo *size_info = NULL;
    if ((r = s_dwarf_attr(log_f, path, die, DW_AT_byte_size, &size_attr)) < 0) goto done;
    if (r > 0 && size_attr) {
        if (s_dwarf_formudata(log_f, path, size_attr, &size_value) < 0) goto done;
        size_info = tc_get_u32(cntx, (unsigned) size_value);
    } else {
        size_info = tc_get_u32(cntx, 0);
    }

    TypeInfo *ti = tc_find_struct_type(cntx, kind, name_info);
    if (ti != NULL) {
        // already registered
        if (!ti->n.info[0]->v.value.v.ct_uint && size_info->v.value.v.ct_uint > 0) {
            ti->n.info[0] = size_info;
        }

        // need to traverse childrens here?

        retval = 0;
        goto done;
    }

    ti = tc_create_struct_type(cntx, kind, size_info, name_info, tc_get_i1(cntx, 0));

    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_structure_type || tag2 == DW_TAG_union_type) {
            //fprintf(stderr, "DEBUG: parse_die_pass_0: struct/union nested in named struct/union\n");
            if ((r = parse_die_pass_0(log_f, path, dbg, die2, cntx, dm)) < 0) goto done;
        }
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    retval = 0;

done:
    return retval;
}

static int
parse_die_pass_2(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        Dwarf_Die die,
        TypeContext *cntx,
        DieMap *dm,
        IdScope *global_scope)
{
    int retval = -1;
    int kind;
    Dwarf_Half tag = 0;
    int r;
    Dwarf_Die die2 = NULL;

    if (s_dwarf_tag(log_f, path, die, &tag) < 0) goto done;
    if (tag == DW_TAG_structure_type) {
        kind = NODE_STRUCT_TYPE;
    } else if (tag == DW_TAG_union_type) {
        kind = NODE_UNION_TYPE;
    } else {
        retval = 0;
        goto done;
    }

    // handle nested structs/unions
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_structure_type || tag2 == DW_TAG_union_type) {
            if ((r = parse_die_pass_2(log_f, path, dbg, die2, cntx, dm, global_scope)) < 0) goto done;
        }
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    Dwarf_Attribute name_attr = NULL;
    TypeInfo *name_info = NULL;
    if ((r = s_dwarf_attr(log_f, path, die, DW_AT_name, &name_attr)) < 0) goto done;
    if (!r) {
        // anonymous structure/union
        retval = 0;
        goto done;
    }
    char *name_str = NULL;
    if (s_dwarf_formstring(log_f, path, name_attr, &name_str) < 0) goto done;
    name_info = tc_get_ident(cntx, name_str);

    TypeInfo *ti = tc_find_struct_type(cntx, kind, name_info);
    ASSERT(ti);
    if (ti->n.info[2] == tc_get_i1(cntx, 1)) {
        // structure already completed
        retval = 0;
        goto done;
    }

    Dwarf_Attribute declaration_attr = NULL;
    Dwarf_Bool declaration_value = 0;
    if ((r = s_dwarf_attr(log_f, path, die, DW_AT_declaration, &declaration_attr)) < 0) goto done;
    if (declaration_attr) {
        if (s_dwarf_formflag(log_f, path, declaration_attr, &declaration_value) < 0) goto done;
        if (declaration_value) {
            retval = 0;
            goto done;
        }
    }

    Dwarf_Attribute size_attr = NULL;
    Dwarf_Unsigned size_value = 0;
    if (s_dwarf_attr_2(log_f, path, die, DW_AT_byte_size, &size_attr) <= 0) goto done;
    if (s_dwarf_formudata(log_f, path, size_attr, &size_value) < 0) goto done;
    TypeInfo *size_info = tc_get_u32(cntx, (unsigned) size_value);

    // set "complete" flag
    ti->n.info[2] = tc_get_i1(cntx, 1);

    int count = 0;
    die2 = NULL;
    if ((r = s_dwarf_child(log_f, path, die, &die2)) < 0) goto done;
    while (r > 0) {
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_structure_type || tag2 == DW_TAG_union_type) {
            // nothing
        } else if (tag2 == DW_TAG_member) {
            ++count;
        } else {
            fprintf(log_f, "%s: DW_TAG_member expected\n", path);
            goto done;
        }
        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }
    if (count <= 0) {
        // empty structure
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
        Dwarf_Half tag2 = 0;
        if (s_dwarf_tag(log_f, path, die2, &tag2) < 0) goto done;
        if (tag2 == DW_TAG_member) {
            Dwarf_Attribute field_name_attr = NULL;
            char *field_name_str = NULL;
            if ((r = s_dwarf_attr(log_f, path, die2, DW_AT_name, &field_name_attr)) < 0) goto done;
            if (r > 0) {
                if (s_dwarf_formstring(log_f, path, field_name_attr, &field_name_str) < 0) goto done;
            } else {
                field_name_str = "";
            }
            TypeInfo *field_name_info = tc_get_ident(cntx, field_name_str);

            Dwarf_Attribute field_type_attr = NULL;
            Dwarf_Off field_type_off = 0;
            Dwarf_Die field_type_die = NULL;
            TypeInfo *field_type_info = NULL;
            if (s_dwarf_attr_2(log_f, path, die2, DW_AT_type, &field_type_attr) <= 0) goto done;
            if (s_dwarf_global_formref(log_f, path, field_type_attr, &field_type_off) < 0) goto done;
            if (s_dwarf_offdie(log_f, path, dbg, field_type_off, &field_type_die) < 0) goto done;
            if (parse_die(log_f, path, dbg, field_type_die, cntx, dm, NULL, global_scope) < 0) goto done;
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

            info[idx++] = tc_get_field(cntx, location_info, field_type_info, field_name_info);
        }

        if ((r = s_dwarf_sibling(log_f, path, dbg, die2, &die2)) < 0) goto done;
    }

    type_info_set_info(ti, info);
    retval = 0;

done:
    return retval;
}

static int
parse_cu(
        FILE *log_f,
        const unsigned char *path,
        Dwarf_Debug dbg,
        TypeContext *cntx,
        IdScope *global_scope)
{
    Dwarf_Die cu_die = NULL;
    int retval = -1;
    DieMap *dm = die_map_init();

    if (s_dwarf_sibling(log_f, path, dbg, NULL, &cu_die) <= 0) goto done;
    Dwarf_Half dtag = 0;
    if (s_dwarf_tag(log_f, path, cu_die, &dtag) < 0) goto done;
    if (dtag != DW_TAG_compile_unit) {
        const char *s = NULL;
        dwarf_get_TAG_name(dtag, &s);
        fprintf(log_f, "%s: DW_TAG_compile_unit expected, %s obtained\n",
                path, s);
        goto done;
    }

    // first pass: create named structure/union typeinfo without fields
    Dwarf_Die die = NULL;
    if (s_dwarf_child(log_f, path, cu_die, &die) <= 0) {
        retval = 0;
        goto done;
    }
    if (parse_die_pass_0(log_f, path, dbg, die, cntx, dm) < 0) goto done;
    while (s_dwarf_sibling(log_f, path, dbg, die, &die) > 0) {
        if (parse_die_pass_0(log_f, path, dbg, die, cntx, dm) < 0) goto done;
    }

    if (s_dwarf_child(log_f, path, cu_die, &die) <= 0) goto done;
    if (parse_die(log_f, path, dbg, die, cntx, dm, NULL, global_scope) < 0) goto done;
    while (s_dwarf_sibling(log_f, path, dbg, die, &die) > 0) {
        if (parse_die(log_f, path, dbg, die, cntx, dm, NULL, global_scope) < 0) goto done;
    }

    // third pass: finalize named structure/union typeinfo
    if (s_dwarf_child(log_f, path, cu_die, &die) <= 0) goto done;
    if (parse_die_pass_2(log_f, path, dbg, die, cntx, dm, global_scope) < 0) goto done;
    while (s_dwarf_sibling(log_f, path, dbg, die, &die) > 0) {
        if (parse_die_pass_2(log_f, path, dbg, die, cntx, dm, global_scope) < 0) goto done;
    }

    retval = 0;

done:
    dm = die_map_destroy(dm);
    return retval;
}

int
dwarf_parse(FILE *log_f, const unsigned char *path, TypeContext *cntx, IdScope *scope)
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
    Dwarf_Unsigned next_cu_header_offset;
    while ((res = dwarf_next_cu_header_b(dbg, &cu_header_length, &version_stamp,
                                         &abbrev_offset, &address_size, &length_size,
                                         &extension_size,
                                         &next_cu_header_offset, &dwe)) == DW_DLV_OK) {
        if ((res = parse_cu(log_f, path, dbg, cntx, scope)) < 0) {
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
