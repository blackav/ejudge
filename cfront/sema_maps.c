/* -*- mode: c -*- */

/* Copyright (C) 2003-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "tree.h"

#include "ejudge/c_value.h"
#include "ejudge/logger.h"

#define ARRSIZE(arr) ((sizeof(arr))/(sizeof((arr)[0])))

static int binop_to_c_operation_map [] =
{
  ['='] = COP_ASSIGN,
  [TOK_MULASSIGN] = COP_MULASSIGN,
  [TOK_DIVASSIGN] = COP_DIVASSIGN,
  [TOK_MODASSIGN] = COP_MODASSIGN,
  [TOK_ADDASSIGN] = COP_ADDASSIGN,
  [TOK_SUBASSIGN] = COP_SUBASSIGN,
  [TOK_LSHASSIGN] = COP_ASLASSIGN,
  [TOK_RSHASSIGN] = COP_ASRASSIGN,
  [TOK_ANDASSIGN] = COP_ANDASSIGN,
  [TOK_XORASSIGN] = COP_XORASSIGN,
  [TOK_ORASSIGN] = COP_ORASSIGN,
  [','] = COP_COMMA,
  [TOK_LOGOR] = COP_LOGOR,
  [TOK_LOGAND] = COP_LOGAND,
  ['|'] = COP_BITOR,
  ['^'] = COP_BITXOR,
  ['&'] = COP_BITAND,
  [TOK_EQ] = COP_EQ,
  [TOK_NEQ] = COP_NE,
  ['<'] = COP_LT,
  ['>'] = COP_GT,
  [TOK_LEQ] = COP_LE,
  [TOK_GEQ] = COP_GE,
  [TOK_RSHIFT] = COP_ASR,
  [TOK_LSHIFT] = COP_ASL,
  ['+'] = COP_ADD,
  ['-'] = COP_SUB,
  ['*'] = COP_MUL,
  ['/'] = COP_DIV,
  ['%'] = COP_MOD,
};
int
sema_binop_to_c_operation(int op)
{
  ASSERT(op > 0);
  ASSERT(op < ARRSIZE(binop_to_c_operation_map));
  ASSERT(binop_to_c_operation_map[op] > 0);
  return binop_to_c_operation_map[op];
}

static int unop_to_c_operation_map [] =
{
  [TOK_INCR] = COP_PREINC,
  [TOK_DECR] = COP_PREDEC,
  [TOK_SIZEOF] = COP_SIZEOF,
  ['*'] = COP_DEREF,
  ['&'] = COP_ADDRESS,
  ['+'] = COP_PLUS,
  ['-'] = COP_MINUS,
  ['~'] = COP_BITNOT,
  ['!'] = COP_LOGNOT,
};
int
sema_unop_to_c_operation(int op)
{
  ASSERT(op > 0);
  ASSERT(op < ARRSIZE(unop_to_c_operation_map));
  ASSERT(unop_to_c_operation_map[op] > 0);
  return unop_to_c_operation_map[op];
}

static int postop_to_c_operation_map [] =
{
  [TOK_INCR] = COP_POSTINC,
  [TOK_DECR] = COP_POSTDEC,
  ['.'] = COP_FIELD,
  [TOK_ARROW] = COP_FIELDREF,
};
int
sema_postop_to_c_operation(int op)
{
  ASSERT(op > 0);
  ASSERT(op < ARRSIZE(postop_to_c_operation_map));
  ASSERT(postop_to_c_operation_map[op] > 0);
  return postop_to_c_operation_map[op];
}
