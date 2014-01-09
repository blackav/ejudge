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

#include "reuse/c_value.h"

enum
{
    NODE_INT_VALUE = 1,
    NODE_FLOAT_VALUE = 2,
    NODE_STRING = 3,
};

struct TypeInfoOps;
typedef struct TypeInfoOps TypeInfoOps;

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

typedef union TypeInfo TypeInfo;
union TypeInfo
{
    int kind;
    struct TypeInfoGenericNode g;
    struct TypeInfoValueNode v;
};

struct TypeContext;
typedef struct TypeContext TypeContext;

#endif /* __TYPE_INFO_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
