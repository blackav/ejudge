/* -*- mode: C -*- */
/* $Id$ */

#ifndef __REUSE_C_VALUE_OPS_H__
#define __REUSE_C_VALUE_OPS_H__

/* Copyright (C) 1999-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/* Group of operations */
enum
  {
    VO_OP_UNKNOWN,
    VO_OP_TO_TYPE,
    VO_OP_FITS_TYPE,
    VO_OP_PREDICATE,
    VO_OP_RELATION,
    VO_OP_LOGIC_BINARY,
    VO_OP_BINARY,
    VO_OP_LOGIC_UNARY,
    VO_OP_UNARY,
    VO_OP_UPDATE,

    VO_OP_LAST_CLASS
  };
int c_operation_to_VO_OP(int);
char const *VO_OP_to_str(int);

/* Enumeration for predicates */
enum
  {
    VO_IS_TRUE,
    VO_IS_FALSE,
    VO_IS_ZERO,
    VO_IS_POSITIVE,
    VO_IS_NEGATIVE,
    VO_IS_INTEGRAL,
    VO_IS_LARGE,

    VO_PREDICATE_LAST
  };
char const *VO_IS_to_str(int);

/* logical binary operations */

enum
  {
    VO_EQ,
    VO_NE,
    VO_LT,
    VO_GT,
    VO_LE,
    VO_GE,
    VO_CMP,

    VO_LOGIC_BINARY_LAST
  };
int c_operation_is_relation(int);
int c_operation_to_VO_LB(int);
int VO_LB_to_c_operation(int);
char const *VO_LB_to_str(int);

/* binary operations */
enum
  {
    VO_BITOR,
    VO_BITXOR,
    VO_BITAND,
    VO_ASR,
    VO_ASL,
    VO_ADD,
    VO_SUB,
    VO_MUL,
    VO_DIV,
    VO_MOD,

    VO_BINARY_LAST
  };
int c_operation_is_binary(int);
int c_operation_to_VO_BIN(int);
int VO_BIN_to_c_operation(int);
char const *VO_BIN_to_str(int);

/* logical unary operations */
enum
  {
    VO_LOGNOT,

    VO_LOGIC_UNARY_LAST
  };
int c_operation_is_logic_unary(int);
int c_operation_to_VO_LU(int);
int VO_LU_to_c_operation(int);
char const *VO_LU_to_str(int);

/* unary operations */
enum
  {
    VO_PLUS,
    VO_MINUS,
    VO_BITNOT,

    VO_UNARY_LAST
  };
int c_operation_is_unary(int);
int c_operation_to_VO_UN(int);
int VO_UN_to_c_operation(int);
char const *VO_UN_to_str(int);

/* increment/decrements */
enum
  {
    VO_INCR,
    VO_DECR,

    VO_UPDATE_LAST
  };
int c_operation_is_update(int);
int c_operation_to_VO_UPD(int);
int VO_UPD_to_c_operation(int);
char const *VO_UPD_to_str(int);

int vo_run_cast(int, const void *, int, void *);
int vo_run_range_check(int, int, const void *);
int vo_run_predicate(int, int, const void *);
int vo_run_relation(int, int, const void *, const void *);
int vo_run_binary(int, int, const void *, const void *, void *);
int vo_run_logic_binary(int, int, const void *, const void *, void *);
int vo_run_unary(int, int, const void *, void *);
int vo_run_logic_unary(int, int, const void *, void *);
int vo_run_update(int, int, void *);

#endif /* __REUSE_C_VALUE_OPS_H__ */
