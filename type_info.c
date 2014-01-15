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
#include <stddef.h>

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

struct TypeContext;

typedef int (*tree_compare_func_t)(const TypeInfo *p1, const void *p2);
typedef TypeInfo *(*tree_create_func_t)(struct TypeContext *cntx, int kind, const void *pv);
TypeInfo *
vt_insert_gen(TypeContext *cntx, ValueTree *pt, void *pv, int kind, tree_compare_func_t cmp, tree_create_func_t create);
ValueTreeNode *
vt_find_gen(ValueTree *pt, const void *pv, tree_compare_func_t cmp);

TypeInfo *
vt_insert(ValueTree *pt, const c_value_t *pv, int kind);
TypeInfo *
vt_insert_ident(ValueTree *pt, const unsigned char *str, int kind);

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
    ValueTree tree;
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
    StringStorage id_values;

    // basic types
    TypeInfo *i0_type; // for void * pointers
    TypeInfo *i1_type;
    TypeInfo *i8_type;
    TypeInfo *u8_type;
    TypeInfo *i16_type;
    TypeInfo *u16_type;
    TypeInfo *i32_type;
    TypeInfo *u32_type;
    TypeInfo *i64_type;
    TypeInfo *u64_type;
    TypeInfo *f32_type;
    TypeInfo *f64_type;
    TypeInfo *f80_type;

    ValueTree typedefs;
    ValueTree pointers;
    ValueTree arrays;
    ValueTree openarrays;
    ValueTree functions;
    ValueTree consts;

    ValueTree params;
    ValueTree enumconsts;
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
    // FIXME: complete
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
        return vt_insert(&cntx->i16_values.tree, &cv, NODE_I16);
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
        return vt_insert(&cntx->u16_values.tree, &cv, NODE_U16);
    }
}

static void
c_value_i32(c_value_t *cv, int value)
{
    cv->tag = C_INT;
    cv->v.ct_int = value;
}

TypeInfo *
tc_get_i32(TypeContext *cntx, int value)
{
    if (value >= IN_DIRECT_LOW && value < IN_DIRECT_HIGH) {
        if (cntx->i32_values.direct[value + IN_DIRECT_LOW])
            return cntx->i32_values.direct[value + IN_DIRECT_LOW];
        TypeInfo *ti = type_info_alloc(NODE_I32);
        c_value_i32(&ti->v.value, value);
        cntx->i32_values.direct[value + IN_DIRECT_LOW] = ti;
        return ti;
    } else {
        c_value_t cv = {};
        c_value_i32(&cv, value);
        return vt_insert(&cntx->i32_values.tree, &cv, NODE_I32);
    }
}

static void
c_value_u32(c_value_t *cv, unsigned value)
{
    cv->tag = C_UINT;
    cv->v.ct_uint = value;
}

TypeInfo *
tc_get_u32(TypeContext *cntx, unsigned value)
{
    if (value < UN_DIRECT_HIGH) {
        if (cntx->u32_values.direct[value])
            return cntx->u32_values.direct[value];
        TypeInfo *ti = type_info_alloc(NODE_U32);
        c_value_u32(&ti->v.value, value);
        cntx->u32_values.direct[value] = ti;
        return ti;
    } else {
        c_value_t cv = {};
        c_value_u32(&cv, value);
        return vt_insert(&cntx->u32_values.tree, &cv, NODE_U32);
    }
}

static void
c_value_i64(c_value_t *cv, long long value)
{
    cv->tag = C_LLONG;
    cv->v.ct_llint = value;
}

TypeInfo *
tc_get_i64(TypeContext *cntx, long long value)
{
    if (value >= IN_DIRECT_LOW && value < IN_DIRECT_HIGH) {
        if (cntx->i64_values.direct[value + IN_DIRECT_LOW])
            return cntx->i64_values.direct[value + IN_DIRECT_LOW];
        TypeInfo *ti = type_info_alloc(NODE_I64);
        c_value_i64(&ti->v.value, value);
        cntx->i64_values.direct[value + IN_DIRECT_LOW] = ti;
        return ti;
    } else {
        c_value_t cv = {};
        c_value_i64(&cv, value);
        return vt_insert(&cntx->i64_values.tree, &cv, NODE_I64);
    }
}

static void
c_value_u64(c_value_t *cv, unsigned long long value)
{
    cv->tag = C_UINT;
    cv->v.ct_uint = value;
}

TypeInfo *
tc_get_u64(TypeContext *cntx, unsigned long long value)
{
    if (value < UN_DIRECT_HIGH) {
        if (cntx->u64_values.direct[value])
            return cntx->u64_values.direct[value];
        TypeInfo *ti = type_info_alloc(NODE_U64);
        c_value_u64(&ti->v.value, value);
        cntx->u64_values.direct[value] = ti;
        return ti;
    } else {
        c_value_t cv = {};
        c_value_u64(&cv, value);
        return vt_insert(&cntx->u64_values.tree, &cv, NODE_U64);
    }
}

static void
c_value_f32(c_value_t *cv, float value)
{
    cv->tag = C_FLOAT;
    cv->v.ct_float = value;
}

TypeInfo *
tc_get_f32(TypeContext *cntx, float value)
{
    c_value_t cv = {};
    c_value_f32(&cv, value);
    return vt_insert(&cntx->f32_values.tree, &cv, NODE_F32);
}

static void
c_value_f64(c_value_t *cv, double value)
{
    cv->tag = C_DOUBLE;
    cv->v.ct_double = value;
}

TypeInfo *
tc_get_f64(TypeContext *cntx, double value)
{
    c_value_t cv = {};
    c_value_f64(&cv, value);
    return vt_insert(&cntx->f64_values.tree, &cv, NODE_F64);
}

static void
c_value_f80(c_value_t *cv, long double value)
{
    cv->tag = C_LDOUBLE;
    cv->v.ct_ldouble = value;
}

TypeInfo *
tc_get_f80(TypeContext *cntx, long double value)
{
    c_value_t cv = {};
    c_value_f80(&cv, value);
    return vt_insert(&cntx->f80_values.tree, &cv, NODE_F80);
}

TypeInfo *
tc_get_ident(TypeContext *cntx, const unsigned char *str)
{
    return vt_insert_ident(&cntx->id_values.tree, str, NODE_IDENT);
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
vt_insert_node(
        ValueTreeNode *root,
        const c_value_t *pv,
        int kind,
        int *p_count,
        TypeInfo **p_info)
{
    if (!root) {
        TypeInfo *ti = type_info_alloc(kind);
        ti->v.value = *pv;
        XCALLOC(root, 1);
        root->value = ti;
        ++(*p_count);
        if (p_info) *p_info = ti;
    } else {
        int c = vt_compare(&root->value->v.value, pv);
        if (!c) {
            if (p_info) *p_info = root->value;;
        } else if (c < 0) {
            root->right = vt_insert_node(root->right, pv, kind, p_count, p_info);
        } else if (c > 0) {
            root->left = vt_insert_node(root->left, pv, kind, p_count, p_info);
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

TypeInfo *
vt_insert(ValueTree *pt, const c_value_t *pv, int kind)
{
    TypeInfo *info = NULL;
    pt->root = vt_insert_node(pt->root, pv, kind, &pt->count, &info);
    if (pt->count >= 31 && !((pt->count + 1) & pt->count)) {
        pt->root = vt_build_balanced(pt->root);
    }
    return info;
}

static ValueTreeNode *
vt_insert_ident_node(ValueTreeNode *root, const unsigned char *str, int kind, int *p_count, TypeInfo **p_info)
{
    if (!root) {
        TypeInfo *ti = type_info_alloc(kind);
        ti->s.str = xstrdup(str);
        ti->s.len = strlen(str);
        XCALLOC(root, 1);
        root->value = ti;
        ++(*p_count);
        if (p_info) *p_info = ti;
    } else {
        int c = strcmp(root->value->s.str, str);
        if (!c) {
            if (p_info) *p_info = root->value;
        } else if (c < 0) {
            root->right = vt_insert_ident_node(root->right, str, kind, p_count, p_info);
        } else if (c > 0) {
            root->left = vt_insert_ident_node(root->left, str, kind, p_count, p_info);
        }
    }
    return root;
}

TypeInfo *
vt_insert_ident(ValueTree *pt, const unsigned char *str, int kind)
{
    TypeInfo *info = NULL;
    pt->root = vt_insert_ident_node(pt->root, str, kind, &pt->count, &info);
    if (pt->count >= 31 && !((pt->count + 1) & pt->count)) {
        pt->root = vt_build_balanced(pt->root);
    }
    return info;
}

ValueTreeNode *
vt_find_ident(ValueTree *pt, const unsigned char *str)
{
    ValueTreeNode *node = pt->root;
    while (node) {
        int c = strcmp(node->value->s.str, str);
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

TypeInfo *
type_info_alloc(int kind) //, TypeInfoOps *ops)
{
    TypeInfo *ti = NULL;
    XCALLOC(ti, 1);
    ti->kind = kind;
    ti->g.ops = NULL; // FIXME
    return ti;
}

TypeInfo *
type_info_alloc_node(int kind, ...)
{
    va_list args;
    int count = 0;
    TypeInfo *p;
    TypeInfo **info = NULL;

    va_start(args, kind);
    while ((p = va_arg(args, TypeInfo *))) {
        ++count;
    }
    va_end(args);

    XCALLOC(info, count + 1);
    count = 0;
    va_start(args, kind);
    while ((p = va_arg(args, TypeInfo* ))) {
        info[count++] = p;
    }
    va_end(args);

    TypeInfo *ti = type_info_alloc(kind);
    ti->n.count = count;
    ti->n.info = info;
    return ti;
}

TypeInfo *
type_info_alloc_node_2(int kind, TypeInfo **info)
{
    int count = 0;
    while (info[count]) ++count;

    TypeInfo **ninfo = NULL;
    XCALLOC(ninfo, count + 1);
    for (count = 0; info[count]; ++count) {
        ninfo[count] = info[count];
    }
    TypeInfo *ti = type_info_alloc(kind);
    ti->n.count = count;
    ti->n.info = ninfo;
    return ti;
}

TypeInfo *
type_info_alloc_basic_type(
        TypeContext *cntx,
        unsigned size,
        int is_float,
        int is_unsigned,
        const unsigned char *type_name)
{
    return type_info_alloc_node(NODE_BASE_TYPE, tc_get_u32(cntx, size), tc_get_i1(cntx, is_float),
                                tc_get_i1(cntx, is_unsigned), tc_get_ident(cntx, type_name), NULL);
}

TypeInfo *
tc_get_i0_type(TypeContext *cntx)
{
    if (!cntx->i0_type) {
        cntx->i0_type = type_info_alloc_basic_type(cntx, 0, 0, 0, "void");
    }
    return cntx->i0_type;
}

TypeInfo *
tc_get_i1_type(TypeContext *cntx)
{
    if (!cntx->i1_type) {
        cntx->i1_type = type_info_alloc_basic_type(cntx, 1, 0, 0, "_Bool");
    }
    return cntx->i1_type;
}

TypeInfo *
tc_get_i8_type(TypeContext *cntx)
{
    if (!cntx->i8_type) {
        cntx->i8_type = type_info_alloc_basic_type(cntx, 1, 0, 0, "char");
    }
    return cntx->i8_type;
}

TypeInfo *
tc_get_u8_type(TypeContext *cntx)
{
    if (!cntx->u8_type) {
        cntx->u8_type = type_info_alloc_basic_type(cntx, 1, 0, 1, "unsigned char");
    }
    return cntx->u8_type;
}

TypeInfo *
tc_get_i16_type(TypeContext *cntx)
{
    if (!cntx->i16_type) {
        cntx->i16_type = type_info_alloc_basic_type(cntx, 2, 0, 0, "short");
    }
    return cntx->i16_type;
}

TypeInfo *
tc_get_u16_type(TypeContext *cntx)
{
    if (!cntx->u16_type) {
        cntx->u16_type = type_info_alloc_basic_type(cntx, 2, 0, 1, "unsigned short");
    }
    return cntx->u16_type;
}

TypeInfo *
tc_get_i32_type(TypeContext *cntx)
{
    if (!cntx->i32_type) {
        cntx->i32_type = type_info_alloc_basic_type(cntx, 4, 0, 0, "int");
    }
    return cntx->i32_type;
}

TypeInfo *
tc_get_u32_type(TypeContext *cntx)
{
    if (!cntx->u32_type) {
        cntx->u32_type = type_info_alloc_basic_type(cntx, 4, 0, 1, "unsigned int");
    }
    return cntx->u32_type;
}

TypeInfo *
tc_get_i64_type(TypeContext *cntx)
{
    if (!cntx->i64_type) {
        cntx->i64_type = type_info_alloc_basic_type(cntx, 8, 0, 0, "long long");
    }
    return cntx->i64_type;
}

TypeInfo *
tc_get_u64_type(TypeContext *cntx)
{
    if (!cntx->u64_type) {
        cntx->u64_type = type_info_alloc_basic_type(cntx, 8, 0, 1, "unsigned long long");
    }
    return cntx->u64_type;
}

TypeInfo *
tc_get_f32_type(TypeContext *cntx)
{
    if (!cntx->f32_type) {
        cntx->f32_type = type_info_alloc_basic_type(cntx, 4, 1, 0, "float");
    }
    return cntx->f32_type;
}

TypeInfo *
tc_get_f64_type(TypeContext *cntx)
{
    if (!cntx->f64_type) {
        cntx->f64_type = type_info_alloc_basic_type(cntx, 8, 1, 0, "double");
    }
    return cntx->f64_type;
}

TypeInfo *
tc_get_f80_type(TypeContext *cntx)
{
    if (!cntx->f80_type) {
        cntx->f80_type = type_info_alloc_basic_type(cntx, 12, 1, 0, "long double");
    }
    return cntx->f80_type;
}

TypeInfo *
tc_get_it(TypeContext *cntx, TypeInfo *type, long long value)
{
    if (type == cntx->i1_type) return tc_get_i1(cntx, !!value);
    if (type == cntx->i8_type) return tc_get_i8(cntx, (signed char) value);
    if (type == cntx->u8_type) return tc_get_u8(cntx, (unsigned char) value);
    if (type == cntx->i16_type) return tc_get_i16(cntx, (short) value);
    if (type == cntx->u16_type) return tc_get_u16(cntx, (unsigned short) value);
    if (type == cntx->i32_type) return tc_get_i32(cntx, (int) value);
    if (type == cntx->u32_type) return tc_get_u32(cntx, (unsigned) value);
    if (type == cntx->i64_type) return tc_get_i64(cntx, value);
    if (type == cntx->u64_type) return tc_get_u64(cntx, (unsigned long long) value);
    abort();
}


static int
generic_cmp_1(const TypeInfo *ti, const void *p2)
{
    const TypeInfo **v2 = (const TypeInfo**) p2;

    /*
    fprintf(stderr, "Cmp: (");
    for (int i = 1; ti->n.info[i]; ++i) fprintf(stderr, " %p", ti->n.info[i]);
    fprintf(stderr, ") (");
    for (int i = 1; v2[i]; ++i) fprintf(stderr, " %p", v2[i]);
    fprintf(stderr, ")\n");
    */

    int i = 1;
    while (1) {
        if (!ti->n.info[i] && !v2[i]) return 0;
        if ((ptrdiff_t) ti->n.info[i] < (ptrdiff_t) v2[i]) return -1;
        if ((ptrdiff_t) ti->n.info[i] > (ptrdiff_t) v2[i]) return 1;
        ++i;
    }
}

static TypeInfo *
generic_create(TypeContext *cntx, int kind, const void *p2)
{
    return type_info_alloc_node_2(kind, (TypeInfo **) p2);
}

TypeInfo *
tc_get_typedef_type(TypeContext *cntx, TypeInfo *ntype, TypeInfo *name)
{
    TypeInfo *info[4] = { ntype->n.info[0], ntype, name, NULL };
    return vt_insert_gen(cntx, &cntx->typedefs, info, NODE_TYPEDEF_TYPE, generic_cmp_1, generic_create);
}

TypeInfo *
tc_get_ptr_type(TypeContext *cntx, TypeInfo *valtype)
{
    TypeInfo *info[3] = { tc_get_u32(cntx, sizeof(void*)), valtype, NULL };
    return vt_insert_gen(cntx, &cntx->pointers, info, NODE_POINTER_TYPE, generic_cmp_1, generic_create);
}

TypeInfo *
tc_get_array_type(TypeContext *cntx, TypeInfo *eltype, TypeInfo *count)
{
    TypeInfo *arrsize = tc_get_u32(cntx, eltype->n.info[0]->v.value.v.ct_uint * count->v.value.v.ct_uint);
    TypeInfo *info[4] = { arrsize, eltype, count, NULL };
    return vt_insert_gen(cntx, &cntx->arrays, info, NODE_ARRAY_TYPE, generic_cmp_1, generic_create);
}

TypeInfo *
tc_get_open_array_type(TypeContext *cntx, TypeInfo *eltype)
{
    TypeInfo *arrsize = tc_get_u32(cntx, 0);
    TypeInfo *info[3] = { arrsize, eltype, NULL };
    return vt_insert_gen(cntx, &cntx->openarrays, info, NODE_OPEN_ARRAY_TYPE, generic_cmp_1, generic_create);
}

TypeInfo *
tc_get_const_type(TypeContext *cntx, TypeInfo *eltype)
{
    TypeInfo *info[3] = { eltype->n.info[0], eltype, NULL };
    return vt_insert_gen(cntx, &cntx->consts, info, NODE_CONST_TYPE, generic_cmp_1, generic_create);
}

TypeInfo *
tc_get_param(TypeContext *cntx, TypeInfo *offset, TypeInfo *param_type, TypeInfo *param_name)
{
    TypeInfo *info[5] = { param_type->n.info[0], offset, param_type, param_name, NULL };
    return vt_insert_gen(cntx, &cntx->params, info, NODE_PARAM, generic_cmp_1, generic_create);
}

TypeInfo *
tc_get_enum_const(TypeContext *cntx, TypeInfo *size, TypeInfo *name, TypeInfo *value)
{
    TypeInfo *info[4] = { size, name, value, NULL };
    return vt_insert_gen(cntx, &cntx->enumconsts, info, NODE_ENUM_CONST, generic_cmp_1, generic_create);
}

static ValueTreeNode *
vt_insert_node_gen(
        TypeContext *cntx,
        ValueTreeNode *root,
        const void *pv,
        int kind,
        int *p_count,
        TypeInfo **p_info,
        tree_compare_func_t cmp,
        tree_create_func_t create)
{
    if (!root) {
        TypeInfo *ti = create(cntx, kind, pv);
        XCALLOC(root, 1);
        root->value = ti;
        ++(*p_count);
        if (p_info) *p_info = ti;
    } else {
        int c = cmp(root->value, pv);
        if (!c) {
            if (p_info) *p_info = root->value;
        } else if (c < 0) {
            root->right = vt_insert_node_gen(cntx, root->right, pv, kind, p_count, p_info, cmp, create);
        } else if (c > 0) {
            root->left = vt_insert_node_gen(cntx, root->left, pv, kind, p_count, p_info, cmp, create);
        }
    }
    return root;
}

TypeInfo *
vt_insert_gen(TypeContext *cntx, ValueTree *pt, void *pv, int kind, tree_compare_func_t cmp, tree_create_func_t create)
{
    TypeInfo *info = NULL;
    pt->root = vt_insert_node_gen(cntx, pt->root, pv, kind, &pt->count, &info, cmp, create);
    if (pt->count >= 31 && !((pt->count + 1) & pt->count)) {
        pt->root = vt_build_balanced(pt->root);
    }
    return info;
}

ValueTreeNode *
vt_find_gen(ValueTree *pt, const void *pv, tree_compare_func_t cmp)
{
    ValueTreeNode *node = pt->root;
    while (node) {
        int c = cmp(node->value, pv);
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

void
tc_print(FILE *out_f, TypeInfo *ti)
{
    if (ti == NULL) {
        fprintf(out_f, "nil");
        return;
    }
    switch (ti->kind) {
    case NODE_I1:
        fprintf(out_f, "%d", ti->v.value.v.ct_bool);
        break;
    case NODE_I8:
        fprintf(out_f, "%d", ti->v.value.v.ct_schar);
        break;
    case NODE_U8:
        fprintf(out_f, "%d", ti->v.value.v.ct_uchar);
        break;
    case NODE_I16:
        fprintf(out_f, "%d", ti->v.value.v.ct_short);
        break;
    case NODE_U16:
        fprintf(out_f, "%d", ti->v.value.v.ct_ushort);
        break;
    case NODE_I32:
        fprintf(out_f, "%d", ti->v.value.v.ct_int);
        break;
    case NODE_U32:
        fprintf(out_f, "%u", ti->v.value.v.ct_uint);
        break;
    case NODE_I64:
        fprintf(out_f, "%lld", ti->v.value.v.ct_llint);
        break;
    case NODE_U64:
        fprintf(out_f, "%llu", ti->v.value.v.ct_ullint);
        break;
    case NODE_F32:
        fprintf(out_f, "%a", ti->v.value.v.ct_float);
        break;
    case NODE_F64:
        fprintf(out_f, "%a", ti->v.value.v.ct_float);
        break;
    case NODE_F80:
        fprintf(out_f, "%La", ti->v.value.v.ct_ldouble);
        break;
    case NODE_IDENT:
        fprintf(out_f, "'%s'", ti->s.str);
        break;
    case NODE_STRING:
        fprintf(out_f, "'%s'", ti->s.str);
        break;
    default:
        fprintf(out_f, "(");
        fprintf(out_f, "%s", tc_get_kind_str(ti->kind));
        for (int i = 0; i < ti->n.count; ++i) {
            fprintf(out_f, " ");
            tc_print(out_f, ti->n.info[i]);
        }
        fprintf(out_f, ")");
        break;
    }
}

static const unsigned char * const node_names[] =
{
    NULL,
    "NODE_I1",
    "NODE_I8",
    "NODE_U8",
    "NODE_I16",
    "NODE_U16",
    "NODE_I32",
    "NODE_U32",
    "NODE_I64",
    "NODE_U64",
    "NODE_F32",
    "NODE_F64",
    "NODE_F80",
    "NODE_IDENT",
    "NODE_STRING",

    "NODE_BASE_TYPE",
    "NODE_TYPEDEF_TYPE",
    "NODE_POINTER_TYPE",
    "NODE_ARRAY_TYPE",
    "NODE_OPEN_ARRAY_TYPE",
    "NODE_FUNCTION_TYPE",
    "NODE_CONST_TYPE",

    "NODE_PARAM",
};

const unsigned char *
tc_get_kind_str(int kind)
{
    return node_names[kind];
}

static void
tc_dump_single_info(FILE *out_f, TypeInfo *info)
{
    if (!info) return;
    fprintf(out_f, "        %016llx ", (unsigned long long)(size_t) info);
    tc_print(out_f, info);
    fprintf(out_f, "\n");
}

static void
tc_dump_type_info_array(FILE *out_f, TypeInfo **info, int count)
{
    for (int i = 0; i < count; ++i) {
        tc_dump_single_info(out_f, info[i]);
    }
}

static void
tc_dump_value_tree_node(FILE *out_f, ValueTreeNode *root)
{
    if (!root) return;
    tc_dump_value_tree_node(out_f, root->left);
    tc_dump_single_info(out_f, root->value);
    tc_dump_value_tree_node(out_f, root->right);
}

static void
tc_dump_value_tree(FILE *out_f, ValueTree *pt)
{
    tc_dump_value_tree_node(out_f, pt->root);
}

static void
tc_dump_signed_int_storage(FILE *out_f, SignedIntStorage *store)
{
    tc_dump_type_info_array(out_f, store->direct, UN_DIRECT_HIGH);
    tc_dump_value_tree(out_f, &store->tree);
}

static void
tc_dump_unsigned_int_storage(FILE *out_f, UnsignedIntStorage *store)
{
    tc_dump_type_info_array(out_f, store->direct, UN_DIRECT_HIGH);
    tc_dump_value_tree(out_f, &store->tree);
}

static void
tc_dump_float_storage(FILE *out_f, FloatStorage *store)
{
    tc_dump_value_tree(out_f, &store->tree);
}

static void
tc_dump_string_storage(FILE *out_f, StringStorage *store)
{
    tc_dump_value_tree(out_f, &store->tree);
}

void
tc_dump_context(FILE *out_f, TypeContext *cntx)
{
    fprintf(out_f, "TypeContext dump\n");
    fprintf(out_f, "    i1 values\n");
    tc_dump_type_info_array(out_f, cntx->i1_values, 2);
    fprintf(out_f, "    i8 values\n");
    tc_dump_type_info_array(out_f, cntx->i8_values, 256);
    fprintf(out_f, "    u8 values\n");
    tc_dump_type_info_array(out_f, cntx->u8_values, 256);
    fprintf(out_f, "    i16 values\n");
    tc_dump_signed_int_storage(out_f, &cntx->i16_values);
    fprintf(out_f, "    i32 values\n");
    tc_dump_signed_int_storage(out_f, &cntx->i32_values);
    fprintf(out_f, "    i64 values\n");
    tc_dump_signed_int_storage(out_f, &cntx->i64_values);
    fprintf(out_f, "    u16 values\n");
    tc_dump_unsigned_int_storage(out_f, &cntx->u16_values);
    fprintf(out_f, "    u32 values\n");
    tc_dump_unsigned_int_storage(out_f, &cntx->u32_values);
    fprintf(out_f, "    u64 values\n");
    tc_dump_unsigned_int_storage(out_f, &cntx->u64_values);
    fprintf(out_f, "    f32 values\n");
    tc_dump_float_storage(out_f, &cntx->f32_values);
    fprintf(out_f, "    f64 values\n");
    tc_dump_float_storage(out_f, &cntx->f64_values);
    fprintf(out_f, "    f80 values\n");
    tc_dump_float_storage(out_f, &cntx->f80_values);
    fprintf(out_f, "    string values\n");
    tc_dump_string_storage(out_f, &cntx->str_values);
    fprintf(out_f, "    id values\n");
    tc_dump_string_storage(out_f, &cntx->id_values);
    fprintf(out_f, "    base types\n");
    tc_dump_single_info(out_f, cntx->i0_type);
    tc_dump_single_info(out_f, cntx->i1_type);
    tc_dump_single_info(out_f, cntx->i8_type);
    tc_dump_single_info(out_f, cntx->u8_type);
    tc_dump_single_info(out_f, cntx->i16_type);
    tc_dump_single_info(out_f, cntx->u16_type);
    tc_dump_single_info(out_f, cntx->i32_type);
    tc_dump_single_info(out_f, cntx->u32_type);
    tc_dump_single_info(out_f, cntx->i64_type);
    tc_dump_single_info(out_f, cntx->u64_type);
    tc_dump_single_info(out_f, cntx->f32_type);
    tc_dump_single_info(out_f, cntx->f64_type);
    tc_dump_single_info(out_f, cntx->f80_type);
    fprintf(out_f, "    typedefs\n");
    tc_dump_value_tree(out_f, &cntx->typedefs);
    fprintf(out_f, "    pointers\n");
    tc_dump_value_tree(out_f, &cntx->pointers);
    fprintf(out_f, "    arrays\n");
    tc_dump_value_tree(out_f, &cntx->arrays);
    fprintf(out_f, "    openarrays\n");
    tc_dump_value_tree(out_f, &cntx->openarrays);
    fprintf(out_f, "    functions\n");
    tc_dump_value_tree(out_f, &cntx->functions);
    fprintf(out_f, "    consts\n");
    tc_dump_value_tree(out_f, &cntx->consts);
    fprintf(out_f, "    params\n");
    tc_dump_value_tree(out_f, &cntx->params);
    fprintf(out_f, "    enumconsts\n");
    tc_dump_value_tree(out_f, &cntx->enumconsts);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
