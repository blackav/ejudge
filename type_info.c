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
#include "reuse/logger.h"

#include <string.h>

typedef struct ValueTreeNode
{
    struct ValueTreeNode *left, *right;
    TypeInfo *value;
} ValueTreeNode;

typedef struct ValueTree
{
    ValueTreeNode *root;
    int count;
} ValueTree;

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

static int
vt_count_nodes(ValueTreeNode *root)
{
    if (!root) return 0;
    return 1 + vt_count_nodes(root->left) + vt_count_nodes(root->right);
}

static int
vt_add_to_arr(ValueTreeNode *root, ValueTreeNode **nodes, int cur)
{
    if (!root) return cur;
    cur = vt_add_to_arr(root->left, nodes, cur);
    nodes[cur++] = root;
    return vt_add_to_arr(root->right, nodes, cur);
}

static ValueTreeNode *
vt_build_from_arr(ValueTreeNode **nodes, int low, int high)
{
    if (low >= high) return NULL;
    int mid = (low + high) / 2;
    nodes[mid]->left = vt_build_from_arr(nodes, low, mid);
    nodes[mid]->right = vt_build_from_arr(nodes, mid + 1, high);
    return nodes[mid];
}

ValueTreeNode *
vt_build_balanced(ValueTreeNode *root)
{
    int count = vt_count_nodes(root);
    if (count <= 0) return root;

    ValueTreeNode **nodes = xcalloc(count, sizeof(nodes[0]));
    vt_add_to_arr(root, nodes, 0);
    ValueTreeNode *new_root = vt_build_from_arr(nodes, 0, count);
    xfree(nodes);
    return new_root;
}

int
vt_compare(c_value_t *pv1, c_value_t *pv2)
{
    ASSERT(pv1);
    ASSERT(pv2);
    ASSERT(pv1->tag == pv2->tag);

    switch (pv1->tag) {
    case C_BOOL:
        if (pv1->v.ct_bool < pv2->v.ct_bool) return -1;
        if (pv1->v.ct_bool > pv2->v.ct_bool) return 1;
        return 0;
    case C_CHAR:
        if (pv1->v.ct_char < pv2->v.ct_char) return -1;
        if (pv1->v.ct_char > pv2->v.ct_char) return 1;
        return 0;
    case C_SCHAR:
        if (pv1->v.ct_schar < pv2->v.ct_schar) return -1;
        if (pv1->v.ct_schar > pv2->v.ct_schar) return 1;
        return 0;
    case C_UCHAR:
        if (pv1->v.ct_uchar < pv2->v.ct_uchar) return -1;
        if (pv1->v.ct_uchar > pv2->v.ct_uchar) return 1;
        return 0;
    case C_SHORT:
        if (pv1->v.ct_short < pv2->v.ct_short) return -1;
        if (pv1->v.ct_short > pv2->v.ct_short) return 1;
        return 0;
    case C_USHORT:
        if (pv1->v.ct_ushort < pv2->v.ct_ushort) return -1;
        if (pv1->v.ct_ushort > pv2->v.ct_ushort) return 1;
        return 0;
    case C_INT:
        if (pv1->v.ct_int < pv2->v.ct_int) return -1;
        if (pv1->v.ct_int > pv2->v.ct_int) return 1;
        return 0;
    case C_UINT:
        if (pv1->v.ct_uint < pv2->v.ct_uint) return -1;
        if (pv1->v.ct_uint > pv2->v.ct_uint) return 1;
        return 0;
    case C_LONG:
        if (pv1->v.ct_lint < pv2->v.ct_lint) return -1;
        if (pv1->v.ct_lint > pv2->v.ct_lint) return 1;
        return 0;
    case C_ULONG:
        if (pv1->v.ct_ulint < pv2->v.ct_ulint) return -1;
        if (pv1->v.ct_ulint > pv2->v.ct_ulint) return 1;
        return 0;
    case C_LLONG:
        if (pv1->v.ct_llint < pv2->v.ct_llint) return -1;
        if (pv1->v.ct_llint > pv2->v.ct_llint) return 1;
        return 0;
    case C_ULLONG:
        if (pv1->v.ct_ullint < pv2->v.ct_ullint) return -1;
        if (pv1->v.ct_ullint > pv2->v.ct_ullint) return 1;
        return 0;
    case C_FLOAT:
        return memcmp(&pv1->v.ct_float, &pv2->v.ct_float, sizeof(float));
    case C_DOUBLE:
        return memcmp(&pv1->v.ct_double, &pv2->v.ct_double, sizeof(double));
    case C_LDOUBLE:
        return memcmp(&pv1->v.ct_ldouble, &pv2->v.ct_ldouble, sizeof(long double));
    default:
        abort();
    }
    return 0;
}

ValueTreeNode *
vt_find(ValueTree *pt, const c_value_t *pv)
{
    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
