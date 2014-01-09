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

#include "type_info.h"

#include "reuse/xalloc.h"

typedef struct SignedIntStorage
{
} SignedIntStorage;
typedef struct UnsignedIntStorage
{
} UnsignedIntStorage;
typedef struct FloatStorage
{
} FloatStorage;
typedef struct StringStorage
{
} StringStorage;

struct TypeContext
{
    TypeInfo *b_values[2];
    TypeInfo *c_values[256];
    TypeInfo *uc_values[256];
    // for shorts ... longs
    SignedIntStorage s_values;
    SignedIntStorage i_values;
    SignedIntStorage l_values;
    SignedIntStorage ll_values;
    // for unsigned
    UnsignedIntStorage us_values;
    UnsignedIntStorage u_values;
    UnsignedIntStorage ul_values;
    UnsignedIntStorage ull_values;
    // for floats
    FloatStorage f_values;
    FloatStorage d_values;
    FloatStorage ld_values;
    // string pool
    StringStorage str_values;
    // for other nodes
};

TypeContext *
tc_create(void)
{
    TypeContext *cntx = NULL;
    XCALLOC(cntx, 1);
    return cntx;
}

TypeContext *
tc_free(TypeContext *cntx)
{
    return NULL;
}

TypeInfo *
tc_get_i1(TypeContext *cntx, int value)
{
    value = !!value;
    if (cntx->b_values[value]) return cntx->b_values[value];
    TypeInfo *ti = NULL;
    XCALLOC(ti, 1);
    ti->kind = NODE_INT_VALUE;
    ti->g.ops = NULL; // FIXME
    ti->v.value.tag = C_BOOL;
    ti->v.value.v.ct_bool = value;
    cntx->b_values[value] = ti;
    return ti;
}

TypeInfo *
tc_get_i8(TypeContext *cntx, int value)
{
    value &= 0xff;
    if (cntx->c_values[value]) return cntx->c_values[value];
    TypeInfo *ti = NULL;
    XCALLOC(ti, 1);
    ti->kind = NODE_INT_VALUE;
    ti->g.ops = NULL; // FIXME
    ti->v.value.tag = C_SCHAR;
    ti->v.value.v.ct_schar = value;
    cntx->c_values[value] = ti;
    return ti;
}

TypeInfo *
tc_get_u8(TypeContext *cntx, int value)
{
    value &= 0xff;
    if (cntx->uc_values[value]) return cntx->uc_values[value];
    TypeInfo *ti = NULL;
    XCALLOC(ti, 1);
    ti->kind = NODE_INT_VALUE;
    ti->g.ops = NULL; // FIXME
    ti->v.value.tag = C_UCHAR;
    ti->v.value.v.ct_schar = value;
    cntx->uc_values[value] = ti;
    return ti;
}

TypeInfo *
tc_get_i16(TypeContext *cntx, int value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_u16(TypeContext *cntx, int value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_i32(TypeContext *cntx, int value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_u32(TypeInfo *cntx, unsigned value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_i64(TypeInfo *cntx, long long value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_u64(TypeInfo *cntx, unsigned long long value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_float(TypeInfo *cntx, float value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_double(TypeInfo *cntx, double value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_long_double(TypeInfo *cntx, long double value)
{
    // FIXME
    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
