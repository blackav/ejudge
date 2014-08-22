/* -*- c -*- */
/* $Id$ */
#ifndef __TYPE_INFO_H__
#define __TYPE_INFO_H__

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

#include "ejudge/c_value.h"

#include <stdio.h>

enum
{
    // literals
    NODE_I1 = 1,
    NODE_I8,
    NODE_U8,
    NODE_I16,
    NODE_U16,
    NODE_I32,
    NODE_U32,
    NODE_I64,
    NODE_U64,
    NODE_F32,
    NODE_F64,
    NODE_F80,
    NODE_IDENT,
    NODE_STRING,

    // composite nodes

    // u32 size, i1 float, i1 unsigned, str name
    NODE_BASE_TYPE,
    // u32 size, node base_type, str name
    NODE_TYPEDEF_TYPE,
    // u32 size, node base_type
    NODE_POINTER_TYPE,
    // u32 size, node base_type, u32 count
    NODE_ARRAY_TYPE,
    // u32 size, node base_type
    NODE_OPEN_ARRAY_TYPE,
    // u32 size, node ret_type, node args...
    NODE_FUNCTION_TYPE,
    // u32 size, node type
    NODE_CONST_TYPE,
    NODE_VOLATILE_TYPE,
    // u32 size, str name, node base_type, node consts...
    NODE_ENUM_TYPE,
    // u32 size, str name, bool complete, node fields...
    NODE_STRUCT_TYPE,
    NODE_UNION_TYPE,
    // u32 size == 0 --- sequence of any types, for ellipsis parameters
    NODE_ANYSEQ_TYPE, 

    // u32 size, i32 frame_offset, node type, str name
    NODE_PARAM,
    // u32 size, str name, value value
    NODE_ENUM_CONST,
    // u32 size, i32 offset, node type, str name
    NODE_FIELD,
    // u32 size, node type
    NODE_FORMAL_PARAM,
    // u32 size, node type, str name, node params
    NODE_SUBROUTINE,
    // u32 size, i32 frame_offset, node type, str name, node value
    NODE_LOCAL_VAR,
};

struct TypeInfoOps;
typedef struct TypeInfoOps TypeInfoOps;
union TypeInfo;

struct TypeInfoGenericNode
{
    int kind;
    TypeInfoOps *ops;
};

struct TypeInfoValueNode
{
    struct TypeInfoGenericNode b;
    c_value_t value;
};

struct TypeInfoStringNode
{
    struct TypeInfoGenericNode b;
    int len;
    unsigned char *str;
};

struct TypeInfoTreeNode
{
    struct TypeInfoGenericNode b;
    int count;
    union TypeInfo **info;
};

typedef union TypeInfo TypeInfo;
union TypeInfo
{
    int kind;
    struct TypeInfoGenericNode g;
    struct TypeInfoValueNode v;
    struct TypeInfoStringNode s;
    struct TypeInfoTreeNode n;
};

struct TypeContext;
typedef struct TypeContext TypeContext;

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

typedef int (*ValueTreeCompareFunc)(const TypeInfo *p1, const void *p2);
typedef TypeInfo *(*ValueTreeCreateFunc)(struct TypeContext *cntx, int kind, const void *pv);

typedef struct IdScope
{
    struct IdScope *up;
    ValueTree ids;
} IdScope;

/* TypeContext operations */
TypeContext *tc_create(void);
TypeContext *tc_free(TypeContext *cntx);

/* value operations */
TypeInfo *tc_get_i1(TypeContext *cntx, int value);
TypeInfo *tc_get_i8(TypeContext *cntx, int value);
TypeInfo *tc_get_u8(TypeContext *cntx, int value);
TypeInfo *tc_get_i16(TypeContext *cntx, int value);
TypeInfo *tc_get_u16(TypeContext *cntx, int value);
TypeInfo *tc_get_i32(TypeContext *cntx, int value);
TypeInfo *tc_get_u32(TypeContext *cntx, unsigned value);
TypeInfo *tc_get_i64(TypeContext *cntx, long long value);
TypeInfo *tc_get_u64(TypeContext *cntx, unsigned long long value);
TypeInfo *tc_get_f32(TypeContext *cntx, float value);
TypeInfo *tc_get_f64(TypeContext *cntx, double value);
TypeInfo *tc_get_f80(TypeContext *cntx, long double value);

TypeInfo *tc_get_it(TypeContext *cntx, TypeInfo *type, long long value);

TypeInfo *tc_get_string(TypeContext *cntx, const unsigned char *str, int len);
TypeInfo *tc_get_ident(TypeContext *cntx, const unsigned char *str);

/* basic types */
TypeInfo *tc_get_i0_type(TypeContext *cntx); // "void" type
TypeInfo *tc_get_i1_type(TypeContext *cntx);
TypeInfo *tc_get_i8_type(TypeContext *cntx);
TypeInfo *tc_get_u8_type(TypeContext *cntx);
TypeInfo *tc_get_i16_type(TypeContext *cntx);
TypeInfo *tc_get_u16_type(TypeContext *cntx);
TypeInfo *tc_get_i32_type(TypeContext *cntx);
TypeInfo *tc_get_u32_type(TypeContext *cntx);
TypeInfo *tc_get_i64_type(TypeContext *cntx);
TypeInfo *tc_get_u64_type(TypeContext *cntx);
TypeInfo *tc_get_f32_type(TypeContext *cntx);
TypeInfo *tc_get_f64_type(TypeContext *cntx);
TypeInfo *tc_get_f80_type(TypeContext *cntx);

TypeInfo *tc_get_anyseq_type(TypeContext *cntx);

/* composite types */
TypeInfo *tc_get_typedef_type(TypeContext *cntx, TypeInfo *ntype, TypeInfo *name);
TypeInfo *tc_get_ptr_type(TypeContext *cntx, TypeInfo *valtype);
TypeInfo *tc_get_array_type(TypeContext *cntx, TypeInfo *eltype, TypeInfo *count);
TypeInfo *tc_get_open_array_type(TypeContext *cntx, TypeInfo *eltype);
TypeInfo *tc_get_openarray_type(TypeContext *cntx, TypeInfo *eltype);
TypeInfo *tc_get_const_type(TypeContext *cntx, TypeInfo *eltype);
TypeInfo *tc_get_volatile_type(TypeContext *cntx, TypeInfo *eltype);
TypeInfo *tc_get_enum_type(TypeContext *cntx, TypeInfo **info);
TypeInfo *tc_get_function_type(TypeContext *cntx, TypeInfo **info);
TypeInfo *tc_get_function(TypeContext *cntx, TypeInfo **info);
TypeInfo *tc_get_local_var(TypeContext *cntx, TypeInfo *offset, TypeInfo *type, TypeInfo *name, TypeInfo *value);

TypeInfo *tc_find_struct_type(TypeContext *cntx, int tag, TypeInfo *name);
TypeInfo *tc_create_struct_type(TypeContext *cntx, int tag, TypeInfo *size, TypeInfo *name, TypeInfo *flag);
TypeInfo *tc_get_anon_struct_type(TypeContext *cntx, int tag, TypeInfo **info);

TypeInfo *tc_get_param(TypeContext *cntx, TypeInfo *offset, TypeInfo *param_type, TypeInfo *param_name);
TypeInfo *tc_get_enum_const(TypeContext *cntx, TypeInfo *size, TypeInfo *name, TypeInfo *value);
TypeInfo *tc_get_field(TypeContext *cntx, TypeInfo *field_type, TypeInfo *field_name, TypeInfo *field_offset);
TypeInfo *tc_get_formal_param(TypeContext *cntx, TypeInfo *param_type);

TypeInfo *tc_find_typedef_type(TypeContext *cntx, TypeInfo *name);
TypeInfo *tc_find_enum_type(TypeContext *cntx, TypeInfo *name);

const unsigned char *tc_get_kind_str(int kind);

void tc_print(FILE *out_f, TypeInfo *ti);
void tc_print_2(FILE *out_f, TypeInfo *ti, int depth);
void tc_dump_context(FILE *out_f, TypeContext *cntx);

void type_info_set_info(TypeInfo *ti, TypeInfo **info);

int tc_is_c_keyword(TypeContext *cntx, TypeInfo *ident);

/* ValueTree functions */
TypeInfo *
vt_insert(
        TypeContext *cntx,
        ValueTree *pt,
        const void *pv,
        int kind,
        ValueTreeCompareFunc cmp,
        ValueTreeCreateFunc create);
ValueTreeNode *
vt_find(
        ValueTree *pt,
        const void *pv,
        ValueTreeCompareFunc cmp);
void
vt_free_2(ValueTree *t);

TypeInfo *
tc_get_name_node(const TypeInfo *ti);
TypeInfo *
tc_skip_tcv(TypeInfo *ti);
TypeInfo *
tc_promote(TypeContext *cntx, TypeInfo *t);
TypeInfo *
tc_balance(TypeContext *cntx, TypeInfo *t1, TypeInfo *t2);
TypeInfo *
tc_find_field(TypeInfo *t, TypeInfo *id);

IdScope *
tc_scope_create(void);
IdScope *
tc_scope_destroy(IdScope *cur);
void
tc_scope_add(IdScope *scope, TypeInfo *def);
TypeInfo *
tc_scope_find_local(IdScope *scope, TypeInfo *id);
TypeInfo *
tc_scope_find(IdScope *cur, TypeInfo *id);

#endif /* __TYPE_INFO_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
