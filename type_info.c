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
#include <limits.h>

TypeInfo *
type_info_alloc(int kind);

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

ValueTreeNode *
vt_insert(ValueTree *pt, const c_value_t *pv, int kind);

enum { IN_DIRECT_LOW = -2, IN_DIRECT_HIGH = 30 };
enum { UN_DIRECT_HIGH = 32 };

typedef struct SignedIntStorage
{
    TypeInfo *direct[UN_DIRECT_HIGH]; // [-2;30)
    ValueTree tree;
} SignedIntStorage;
typedef struct UnsignedIntStorage
{
    TypeInfo *direct[UN_DIRECT_HIGH]; // [0;32)
    ValueTree tree;
} UnsignedIntStorage;
typedef struct FloatStorage
{
    ValueTree tree;
} FloatStorage;
typedef struct StringStorage
{
} StringStorage;

struct TypeContext
{
    TypeInfo *i1_values[2];
    TypeInfo *i8_values[256];
    TypeInfo *u8_values[256];
    // for shorts ... longs
    SignedIntStorage i16_values;
    SignedIntStorage i32_values;
    SignedIntStorage i64_values;
    // for unsigned
    UnsignedIntStorage u16_values;
    UnsignedIntStorage u32_values;
    UnsignedIntStorage u64_values;
    // for floats
    FloatStorage f32_values;
    FloatStorage f64_values;
    FloatStorage f80_values;
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
    if (cntx->i1_values[value]) return cntx->i1_values[value];
    TypeInfo *ti = type_info_alloc(NODE_I1);
    ti->v.value.tag = C_BOOL;
    ti->v.value.v.ct_bool = value;
    cntx->i1_values[value] = ti;
    return ti;
}

TypeInfo *
tc_get_i8(TypeContext *cntx, int value)
{
    value &= 0xff;
    if (cntx->i8_values[value]) return cntx->i8_values[value];
    TypeInfo *ti = type_info_alloc(NODE_I8);
    ti->v.value.tag = C_SCHAR;
    ti->v.value.v.ct_schar = value;
    cntx->i8_values[value] = ti;
    return ti;
}

TypeInfo *
tc_get_u8(TypeContext *cntx, int value)
{
    value &= 0xff;
    if (cntx->u8_values[value]) return cntx->u8_values[value];
    TypeInfo *ti = type_info_alloc(NODE_U8);
    ti->v.value.tag = C_UCHAR;
    ti->v.value.v.ct_schar = value;
    cntx->u8_values[value] = ti;
    return ti;
}

static void
c_value_i16(c_value_t *cv, int value)
{
    cv->tag = C_SHORT;
    cv->v.ct_short = value;
}

TypeInfo *
tc_get_i16(TypeContext *cntx, int value)
{
    if (value < SHRT_MIN) value = SHRT_MIN;
    if (value > SHRT_MAX) value = SHRT_MAX;
    if (value >= IN_DIRECT_LOW && value < IN_DIRECT_HIGH) {
        if (cntx->i16_values.direct[value + IN_DIRECT_LOW])
            return cntx->i16_values.direct[value + IN_DIRECT_LOW];
        TypeInfo *ti = type_info_alloc(NODE_I16);
        c_value_i16(&ti->v.value, value);
        cntx->i16_values.direct[value + IN_DIRECT_LOW] = ti;
        return ti;
    } else {
        c_value_t cv = {};
        c_value_i16(&cv, value);
        ValueTreeNode *vtn = vt_insert(&cntx->i16_values.tree, &cv, NODE_I16);
        return vtn->value;
    }
}

static void
c_value_u16(c_value_t *cv, int value)
{
    cv->tag = C_USHORT;
    cv->v.ct_ushort = value;
}

TypeInfo *
tc_get_u16(TypeContext *cntx, int value)
{
    if (value < 0) value = 0;
    if (value > USHRT_MAX) value = USHRT_MAX;
    if (value < UN_DIRECT_HIGH) {
        if (cntx->u16_values.direct[value])
            return cntx->u16_values.direct[value];
        TypeInfo *ti = type_info_alloc(NODE_U16);
        c_value_u16(&ti->v.value, value);
        cntx->u16_values.direct[value] = ti;
        return ti;
    } else {
        c_value_t cv = {};
        c_value_u16(&cv, value);
        ValueTreeNode *vtn = vt_insert(&cntx->u16_values.tree, &cv, NODE_U16);
        return vtn->value;
    }
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
tc_get_f32(TypeInfo *cntx, float value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_f64(TypeInfo *cntx, double value)
{
    // FIXME
    return NULL;
}

TypeInfo *
tc_get_f80(TypeInfo *cntx, long double value)
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

static ValueTreeNode *
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

static int
vt_compare(const c_value_t *pv1, const c_value_t *pv2)
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

static ValueTreeNode *
vt_insert_node(ValueTreeNode *root, const c_value_t *pv, int kind, int *p_count)
{
    if (!root) {
        TypeInfo *ti = type_info_alloc(kind);
        ti->v.value = *pv;
        XCALLOC(root, 1);
        root->value = ti;
        ++(*p_count);
    } else {
        int c = vt_compare(&root->value->v.value, pv);
        if (c < 0) {
            root->right = vt_insert_node(root->right, pv, kind, p_count);
        } else if (c > 0) {
            root->left = vt_insert_node(root->left, pv, kind, p_count);
        }
    }
    return root;
}

ValueTreeNode *
vt_find(ValueTree *pt, const c_value_t *pv)
{
    ValueTreeNode *node = pt->root;
    while (node) {
        int c = vt_compare(&node->value->v.value, pv);
        if (!c) {
            break;
        } else if (c < 0) {
            node = node->right;
        } else if (c > 0) {
            node = node->left;
        }
    }
    return node;
}

ValueTreeNode *
vt_insert(ValueTree *pt, const c_value_t *pv, int kind)
{
    pt->root = vt_insert_node(pt->root, pv, kind, &pt->count);
    if (pt->count >= 31 && !((pt->count + 1) & pt->count)) {
        pt->root = vt_build_balanced(pt->root);
    }
    return pt->root;
}

TypeInfo *
type_info_alloc(int kind) //, TypeInfoOps *ops)
{
    TypeInfo *ti = NULL;
    XCALLOC(ti, 1);
    ti->kind = kind;
    ti->g.ops = NULL; // FIXME
    return ti;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
