/* -*- mode: C -*- */
/* $Id$ */

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

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/integral.h"
#include "ejudge/c_value.h"
#include "ejudge/c_value_ops.h"
#include "ejudge/logger.h"
#include "ejudge/xalloc.h"

#include <stdio.h>
#include <limits.h>
#include <math.h>

typedef int (*p_generic_f_t)();
typedef int (*p_to_type_f_t)(void const *src, void *dst);
typedef int (*p_fits_type_f_t)(void const *src);
typedef int (*p_predicate_f_t)(void const *src);
typedef int (*p_relation_f_t)(void const *s1, void const *s2);
typedef int (*p_logic_binary_f_t)(void const *s1, void const *s2, void *dst);
typedef int (*p_binary_f_t)(void const *s1, void const *s2, void *dst);
typedef int (*p_logic_unary_f_t)(void const *src, void *dst);
typedef int (*p_unary_f_t)(void const *src, void *dst);
typedef int (*p_update_f_t)(void *dst);

struct value_operations
{
  p_to_type_f_t      to_types[C_LAST_ARITH];
  p_fits_type_f_t    fits_type[C_LAST_ARITH];
  p_predicate_f_t    predicates[VO_PREDICATE_LAST];
  p_relation_f_t     relations[VO_LOGIC_BINARY_LAST];
  p_logic_binary_f_t logic_binary[VO_LOGIC_BINARY_LAST];
  p_binary_f_t       binary[VO_BINARY_LAST];
  p_logic_unary_f_t  logic_unary[VO_LOGIC_UNARY_LAST];
  p_unary_f_t        unary[VO_UNARY_LAST];
  p_update_f_t       update[VO_UPDATE_LAST];
};

#define to_types_OFFSET XOFFSET(struct value_operations, to_types)
#define fits_type_OFFSET XOFFSET(struct value_operations, fits_type)
#define predicates_OFFSET XOFFSET(struct value_operations, predicates)
#define relations_OFFSET XOFFSET(struct value_operations, relations)
#define logic_binary_OFFSET XOFFSET(struct value_operations, logic_binary)
#define binary_OFFSET XOFFSET(struct value_operations, binary)
#define logic_unary_OFFSET XOFFSET(struct value_operations, logic_unary)
#define unary_OFFSET XOFFSET(struct value_operations, unary)
#define update_OFFSET XOFFSET(struct value_operations, update)

struct value_operations_access
{
  int first;
  int afterlast;
  unsigned int offset;
  const char *(*verb_op)(int);
};
static struct value_operations_access value_operations_access_table[] =
  {
    /*[VO_OP_UNKNOWN]*/      { 0, 0, 0, 0 },
    /*[VO_OP_TO_TYPE]*/      { C_FIRST_ARITH, C_LAST_ARITH + 1,
                               to_types_OFFSET, c_builtin_str },
    /*[VO_OP_FITS_TYPE]*/    { C_FIRST_ARITH, C_LAST_ARITH + 1,
                               fits_type_OFFSET, c_builtin_str },
    /*[VO_OP_PREDICATE]*/    { 0, VO_PREDICATE_LAST,
                               predicates_OFFSET, VO_IS_to_str },
    /*[VO_OP_RELATION]*/     { 0, VO_LOGIC_BINARY_LAST,
                               relations_OFFSET, VO_LB_to_str },
    /*[VO_OP_LOGIC_BINARY]*/ { 0, VO_LOGIC_BINARY_LAST,
                               logic_binary_OFFSET, VO_LB_to_str },
    /*[VO_OP_BINARY]*/       { 0, VO_BINARY_LAST,
                               binary_OFFSET, VO_BIN_to_str },
    /*[VO_OP_LOGIC_UNARY]*/  { 0, VO_LOGIC_UNARY_LAST,
                               logic_unary_OFFSET, VO_LU_to_str },
    /*[VO_OP_UNARY]*/        { 0, VO_UNARY_LAST,
                               unary_OFFSET, VO_UN_to_str },
    /*[VO_OP_UPDATE]*/       { 0, VO_UPDATE_LAST,
                               update_OFFSET, VO_UPD_to_str }
  };

struct op_descr
{
  int c1, c2;
};
static const struct op_descr op_descrs[] =
{
  { 0, 0 },                     /* COP_NONE */
  { 0, 0 },                     /* COP_ASSIGN */
  { 0, 0 },                     /* COP_MULASSIGN */
  { 0, 0 },                     /* COP_DIVASSIGN */
  { 0, 0 },                     /* COP_MODASSIGN */
  { 0, 0 },                     /* COP_ADDASSIGN */
  { 0, 0 },                     /* COP_SUBASSIGN */
  { 0, 0 },                     /* COP_ASLASSIGN */
  { 0, 0 },                     /* COP_ASRASSIGN */
  { 0, 0 },                     /* COP_ANDASSIGN */
  { 0, 0 },                     /* COP_XORASSIGN */
  { 0, 0 },                     /* COP_ORASSIGN */
  { 0, 0 },                     /* COP_COMMA */
  { 0, 0 },                     /* COP_COND */
  { 0, 0 },                     /* COP_LOGOR */
  { 0, 0 },                     /* COP_LOGAND */
  { VO_OP_BINARY, VO_BITOR },   /* COP_BITOR */
  { VO_OP_BINARY, VO_BITXOR },  /* COP_BITXOR */
  { VO_OP_BINARY, VO_BITAND },  /* COP_BITAND */
  { VO_OP_LOGIC_BINARY, VO_EQ }, /* COP_EQ */
  { VO_OP_LOGIC_BINARY, VO_NE }, /* COP_NE */
  { VO_OP_LOGIC_BINARY, VO_LT }, /* COP_LT */
  { VO_OP_LOGIC_BINARY, VO_GT }, /* COP_GT */
  { VO_OP_LOGIC_BINARY, VO_LE }, /* COP_LE */
  { VO_OP_LOGIC_BINARY, VO_GE }, /* COP_GE */
  { VO_OP_BINARY, VO_ASR },     /* COP_ASR */
  { VO_OP_BINARY, VO_ASL },     /* COP_ASL */
  { VO_OP_BINARY, VO_ADD },     /* COP_ADD */
  { VO_OP_BINARY, VO_SUB },     /* COP_SUB */
  { VO_OP_BINARY, VO_MUL },     /* COP_MUL */
  { VO_OP_BINARY, VO_DIV },     /* COP_DIV */
  { VO_OP_BINARY, VO_MOD },     /* COP_MOD */
  { 0, 0 },  /* COP_CAST */
  { VO_OP_UPDATE, VO_INCR },    /* COP_PREINC */
  { VO_OP_UPDATE, VO_DECR },    /* COP_PREDEC */
  { 0, 0 },  /* COP_SIZEOF */
  { 0, 0 },  /* COP_DEREF */
  { 0, 0 },  /* COP_ADDRESS */
  { VO_OP_UNARY, VO_PLUS },     /* COP_PLUS */
  { VO_OP_UNARY, VO_MINUS },    /* COP_MINUS */
  { VO_OP_UNARY, VO_BITNOT },   /* COP_BITNOT */
  { VO_OP_LOGIC_UNARY, VO_LOGNOT }, /* COP_LOGNOT */
  { VO_OP_UPDATE, VO_INCR },    /* COP_POSTINC */
  { VO_OP_UPDATE, VO_DECR },    /* COP_POSTDEC */
  { 0, 0 },  /* COP_FIELD */
  { 0, 0 },  /* COP_FIELDREF */
};
int c_operation_to_VO_OP(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  return op_descrs[teop].c1;
}
char const *VO_OP_to_str(int voop)
{
  static char const * const t[] =
    {
      "unknown",
      "to type",
      "fits type",
      "predicate",
      "relation",
      "logic binary",
      "binary",
      "logic unary",
      "unary",
      "update"
    };
  if (voop < 0 || voop >= VO_OP_LAST_CLASS) return "?";
  return t[voop];
}

char const *VO_IS_to_str(int vois)
{
  static char const * const t[] =
    {
      "is_true",
      "is_false",
      "is_zero",
      "is_positive",
      "is_negative",
      "is_integral",
      "is_large"
    };
  if (vois < 0 || vois >= VO_PREDICATE_LAST) return "?";
  return t[vois];
}
int c_operation_is_relation(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  return op_descrs[teop].c1 == VO_OP_LOGIC_BINARY;
}
int c_operation_to_VO_LB(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  ASSERT(op_descrs[teop].c1 == VO_OP_LOGIC_BINARY);
  return op_descrs[teop].c2;
}
int VO_LB_to_c_operation(int volb)
{
  static int const t[] =
    {
      COP_EQ,
      COP_NE,
      COP_LT,
      COP_GT,
      COP_LE,
      COP_GE
    };
  ASSERT(volb >= 0 && volb < VO_LOGIC_BINARY_LAST);
  return t[volb];
}
char const *VO_LB_to_str(int volb)
{
  static char const * const t[] =
    {
      "==", "!=", "<", ">", "<=", ">=", "<=>"
    };
  if (volb < 0 || volb >= VO_LOGIC_BINARY_LAST) return "?";
  return t[volb];
}
int c_operation_is_binary(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  return op_descrs[teop].c1 == VO_OP_BINARY;
}
int c_operation_to_VO_BIN(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  ASSERT(op_descrs[teop].c1 == VO_OP_BINARY);
  return op_descrs[teop].c2;
}
int VO_BIN_to_c_operation(int vob)
{
  static const int t[] =
    {
      COP_BITOR, COP_BITXOR, COP_BITAND, COP_ASR, COP_ASL,
      COP_ADD, COP_SUB, COP_MUL, COP_DIV, COP_MOD
    };
  ASSERT(vob >= 0 && vob < VO_BINARY_LAST);
  return t[vob];
}
char const *VO_BIN_to_str(int vob)
{
  static const char * const t[] =
    {
      "|", "^", "&", "<<", ">>", "+", "-", "*", "/", "%"
    };
  if (vob < 0 || vob >= VO_BINARY_LAST) return "?";
  return t[vob];
}
int c_operation_is_logic_unary(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  return op_descrs[teop].c1 == VO_OP_LOGIC_UNARY;
}
int c_operation_to_VO_LU(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  ASSERT(op_descrs[teop].c1 == VO_OP_LOGIC_UNARY);
  return op_descrs[teop].c2;
}
int VO_LU_to_c_operation(int volu)
{
  static const int t[] =
    {
      COP_LOGNOT
    };
  ASSERT(volu >= 0 && volu < VO_LOGIC_UNARY_LAST);
  return t[volu];
}
char const *VO_LU_to_str(int volu)
{
  static const char * const t[] =
    {
      "!"
    };
  if (volu < 0 || volu >= VO_LOGIC_UNARY_LAST) return "?";
  return t[volu];
}
int c_operation_is_unary(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  return op_descrs[teop].c1 == VO_OP_UNARY;
}
int c_operation_to_VO_UN(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  ASSERT(op_descrs[teop].c1 == VO_OP_UNARY);
  return op_descrs[teop].c2;
}
int VO_UN_to_c_operation(int voun)
{
  static const int t[] =
    {
      COP_PLUS, COP_MINUS, COP_BITNOT
    };
  ASSERT(voun >= 0 && voun < VO_UNARY_LAST);
  return t[voun];
}
char const *VO_UN_to_str(int voun)
{
  static const char * const t[] =
    {
      "+ (1)", "- (1)", "~"
    };
  if (voun < 0 || voun >= VO_UNARY_LAST) return "?";
  return t[voun];
}
int c_operation_is_update(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  return op_descrs[teop].c1 == VO_OP_UPDATE;
}
int c_operation_to_VO_UPD(int teop)
{
  ASSERT(teop >= 0 && teop < COP_LAST);
  ASSERT(op_descrs[teop].c1 == VO_OP_UPDATE);
  return op_descrs[teop].c2;
}
int VO_UPD_to_c_operation(int voupd)
{
  static const int t[] =
    {
      COP_PREINC, COP_PREDEC
    };
  ASSERT(voupd >= 0 && voupd < VO_UPDATE_LAST);
  return t[voupd];
}
char const *VO_UPD_to_str(int voupd)
{
  static const char * const t[] =
    {
      "++", "--"
    };
  if (voupd < 0 || voupd >= VO_UPDATE_LAST) return "?";
  return t[voupd];
}

/*
static const struct value_operations <type>_operations =
{
  { 
    &<t>_to_b, &<t>_to_c, &<t>_to_sc, &<t>_to_uc, &<t>_to_s, &<t>_to_us,
    &<t>_to_i, &<t>_to_ui, &<t>_to_l, &<t>_to_ul, &<t>_to_ll, &<t>_to_ull,
    &<t>_to_f, &<t>_to_d, &<t>_to_ld, &<t>_to_qd,
    &<t>_to_fi, &<t>_to_di, &<t>_to_li, &<t>_to_qi,
    &<t>_to_fo, &<t>_to_do, &<t>_to_lo, &<t>_to_qo,
  },
  {
    &<t>_fits_b, &<t>_fits_c, &<t>_fits_sc, &<t>_fits_uc,
    &<t>_fits_s, &<t>_fits_us, &<t>_fits_i, &<t>_fits_ui,
    &<t>_fits_l, &<t>_fits_ui, &<t>_fits_ll, &<t>_fits_ull,
    &<t>_fits_f, &<t>_fits_d, &<t>_fits_ld, &<t>_fits_qd,
    &<t>_fits_fi, &<t>_fits_di, &<t>_fits_li, &<t>_fits_qi,
    &<t>_fits_fo, &<t>_fits_do, &<t>_fits_lo, &<t>_fits_qo,
  },
  {
    &<t>_is_true, &<t>_is_false, &<t>_is_zero,
    &<t>_is_positive, &<t>_is_negative,
    &<t>_is_integral, &<t>_is_large
  },
  {
    &<t>_is_eq, &<t>_is_ne, &<t>_is_lt, &<t>_is_gt, &<t>_is_le, &<t>_is_ge,
    &<t>_cmp
  },
  {
    &<t>_eq, &<t>_ne, &<t>_lt, &<t>_gt, &<t>_le, &<t>_ge,
  },
  {
    &<t>_bitor, &<t>_bitxor, &<t>_bitand, &<t>_asr, &<t>_asl,
    &<t>_add, &<t>_sub, &<t>_mul, &<t>_div, &<t>_mod
  },
  {
    &<t>_lognot,
  },
  {
    &<t>_plus, &<t>_minus, &<t>_bitnot,
  },
  {
    &<t>_inc, &<t>_dec
  }
};
*/

typedef signed char myc_t;
typedef unsigned char myuc_t;
typedef unsigned short myus_t;
typedef unsigned int myu_t;
typedef unsigned long myul_t;

static int ret1(void const *pv)
{
  return 1;
}
static int ret0(void const *pv)
{
  return 0;
}

#define CONVERT(st,dt) *(dt*) d = (dt) *(const st*) s
#define COMPARE(t,op) ((*(const t*) (s1)) op (*(const t*) (s2)))
#define RELOP(t,op) *(int*) d = ((*(const t*)s1) op (*(const t*)s2))
#define BINOP(t,op) *(t*) d = ((*(const t*)s1) op (*(const t*)s2))
#define LOGUNARY(t,op) *(int*) d = (op (*(const t*)s))
#define UNARY(t,op) *(t*) d = (op (*(const t*)s))
#define INCOP(t,op) (*(t*) d) op

static int c_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(signed char*) s) *(unsigned char*) d = 1;
  return 0;
}
static int c_to_c(void const *s, void *d)
{
  CONVERT(signed char, signed char);
  return 0;
}
static int c_to_uc(void const *s, void *d)
{
  CONVERT(signed char, unsigned char);
  return 0;
}
static int c_to_s(void const *s, void *d)
{
  CONVERT(signed char, short);
  return 0;
}
static int c_to_us(void const *s, void *d)
{
  CONVERT(signed char, unsigned short);
  return 0;
}
static int c_to_i(void const *s, void *d)
{
  CONVERT(signed char, int);
  return 0;
}
static int c_to_ui(void const *s, void *d)
{
  CONVERT(signed char, unsigned int);
  return 0;
}
static int c_to_l(void const *s, void *d)
{
  CONVERT(signed char, long);
  return 0;
}
static int c_to_ul(void const *s, void *d)
{
  CONVERT(signed char, unsigned long);
  return 0;
}
static int c_to_ll(void const *s, void *d)
{
  CONVERT(signed char, rllong_t);
  return 0;
}
static int c_to_ull(void const *s, void *d)
{
  CONVERT(signed char, rullong_t);
  return 0;
}
static int c_to_f(void const *s, void *d)
{
  CONVERT(signed char, float);
  return 0;
}
static int c_to_d(void const *s, void *d)
{
  CONVERT(signed char, double);
  return 0;
}
static int c_to_ld(void const *s, void *d)
{
  CONVERT(signed char, long double);
  return 0;
}
static int c_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const signed char*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int c_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const signed char*) s;
  dd->d_im = 0.0;
  return 0;
}
static int c_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const signed char*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int c_fits_uc(void const *s)
{
  signed char val = *(signed char const *) s;
  return val >= 0;
}

static int c_is_true(void const *s)
{
  return *(signed char const *) s != 0;
}
static int c_is_false(void const *s)
{
  return *(signed char const *) s == 0;
}
static int c_is_zero(void const *s)
{
  return *(signed char const *) s == 0;
}
static int c_is_positive(void const *s)
{
  return *(signed char const *) s > 0;
}
static int c_is_negative(void const *s)
{
  return *(signed char const *) s < 0;
}

static const struct value_operations char_operations =
  {
    { 
      c_to_b, &c_to_c, &c_to_c, &c_to_uc, &c_to_s, &c_to_us, &c_to_i, &c_to_ui,
      &c_to_l, &c_to_ul, &c_to_ll, &c_to_ull,
      &c_to_f, &c_to_d, &c_to_ld, 0 /*c_to_qd*/,
      c_to_f, c_to_d, c_to_ld, 0 /*c_to_qi*/,
      c_to_fo, c_to_do, c_to_lo, 0 /*c_to_qo*/,
    },
    { 
      ret1, &ret1, &ret1, &c_fits_uc, &ret1, &ret1, &ret1, &ret1, 
      &ret1, &ret1, &ret1, &ret1,
      &ret1, &ret1, &ret1, 0 /*c_fits_qd*/,
      ret1, ret1, ret1, 0 /*c_fits_qi*/,
      ret1, ret1, ret1, 0 /*c_fits_qo*/,
    },
    {
      &c_is_true, &c_is_false, &c_is_zero,
      &c_is_positive, &c_is_negative,
      &ret1, &ret0
    },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 }
  };

static int uc_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const unsigned char*) d) *(unsigned char*) d = 1;
  return 0;
}
static int uc_to_c(void const *s, void *d)
{
  CONVERT(unsigned char, signed char);
  return 0;
}
static int uc_to_uc(void const *s, void *d)
{
  CONVERT(unsigned char, unsigned char);
  return 0;
}
static int uc_to_s(void const *s, void *d)
{
  CONVERT(unsigned char, short);
  return 0;
}
static int uc_to_us(void const *s, void *d)
{
  CONVERT(unsigned char, unsigned short);
  return 0;
}
static int uc_to_i(void const *s, void *d)
{
  CONVERT(unsigned char, int);
  return 0;
}
static int uc_to_ui(void const *s, void *d)
{
  CONVERT(unsigned char, unsigned int);
  return 0;
}
static int uc_to_l(void const *s, void *d)
{
  CONVERT(unsigned char, long);
  return 0;
}
static int uc_to_ul(void const *s, void *d)
{
  CONVERT(unsigned char, unsigned long);
  return 0;
}
static int uc_to_ll(void const *s, void *d)
{
  CONVERT(unsigned char, rllong_t);
  return 0;
}
static int uc_to_ull(void const *s, void *d)
{
  CONVERT(unsigned char, rullong_t);
  return 0;
}
static int uc_to_f(void const *s, void *d)
{
  CONVERT(unsigned char, float);
  return 0;
}
static int uc_to_d(void const *s, void *d)
{
  CONVERT(unsigned char, double);
  return 0;
}
static int uc_to_ld(void const *s, void *d)
{
  CONVERT(unsigned char, long double);
  return 0;
}
static int uc_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const unsigned char*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int uc_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const unsigned char*) s;
  dd->d_im = 0.0;
  return 0;
}
static int uc_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const unsigned char*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int uc_fits_c(void const *s)
{
  unsigned char val = *(unsigned char const *) s;
  return val <= CHAR_MAX;
}

static int uc_is_true(void const *s)
{
  return *(unsigned char const *) s != 0;
}
static int uc_is_false(void const *s)
{
  return *(unsigned char const *) s == 0;
}
static int uc_is_zero(void const *s)
{
  return *(unsigned char const *) s == 0;
}
static int uc_is_positive(void const *s)
{
  return *(unsigned char const *) s > 0;
}

static const struct value_operations uchar_operations =
  {
    { 
      uc_to_b, &uc_to_c, &uc_to_c, &uc_to_uc, &uc_to_s, &uc_to_us,
      &uc_to_i, &uc_to_ui, &uc_to_l, &uc_to_ul, &uc_to_ll, &uc_to_ull,
      &uc_to_f, &uc_to_d, &uc_to_ld, 0 /*uc_to_qd*/,
      uc_to_f, uc_to_d, uc_to_ld, 0 /*uc_to_qi*/,
      uc_to_fo, uc_to_do, uc_to_lo, 0 /*uc_to_qo*/,
    },
    {
      ret1, &uc_fits_c, &uc_fits_c, &ret1, &ret1, &ret1, &ret1, &ret1, 
      &ret1, &ret1, &ret1, &ret1,
      &ret1, &ret1, &ret1, 0 /*uc_fits_qd*/,
      ret1, ret1, ret1, 0 /*uc_fits_qi*/,
      ret1, ret1, ret1, 0 /*uc_fits_qo*/,
    },
    {
      &uc_is_true, &uc_is_false, &uc_is_zero,
      &uc_is_positive, &ret0,
      &ret1, &ret0
    },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 }
  };

static int s_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const short*) d) *(unsigned char*) d = 1;
  return 0;
}
static int s_to_c(void const *s, void *d)
{
  CONVERT(short, signed char);
  return 0;
}
static int s_to_uc(void const *s, void *d)
{
  CONVERT(short, unsigned char);
  return 0;
}
static int s_to_s(void const *s, void *d)
{
  CONVERT(short, short);
  return 0;
}
static int s_to_us(void const *s, void *d)
{
  CONVERT(short, unsigned short);
  return 0;
}
static int s_to_i(void const *s, void *d)
{
  CONVERT(short, int);
  return 0;
}
static int s_to_ui(void const *s, void *d)
{
  CONVERT(short, unsigned int);
  return 0;
}
static int s_to_l(void const *s, void *d)
{
  CONVERT(short, long);
  return 0;
}
static int s_to_ul(void const *s, void *d)
{
  CONVERT(short, unsigned long);
  return 0;
}
static int s_to_ll(void const *s, void *d)
{
  CONVERT(short, rllong_t);
  return 0;
}
static int s_to_ull(void const *s, void *d)
{
  CONVERT(short, rullong_t);
  return 0;
}
static int s_to_f(void const *s, void *d)
{
  CONVERT(short, float);
  return 0;
}
static int s_to_d(void const *s, void *d)
{
  CONVERT(short, double);
  return 0;
}
static int s_to_ld(void const *s, void *d)
{
  CONVERT(short, long double);
  return 0;
}
static int s_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const short*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int s_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const short*) s;
  dd->d_im = 0.0;
  return 0;
}
static int s_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const short*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int s_fits_c(void const *s)
{
  short val = *(short const *) s;
  return val >= CHAR_MIN && val <= CHAR_MAX;
}
static int s_fits_uc(void const *s)
{
  short val = *(short const *) s;
  return val >= 0 && val <= UCHAR_MAX;
}
static int s_fits_us(void const *s)
{
  short val = *(short const *) s;
  return val >= 0;
}

static int s_is_true(void const *s)
{
  return *(short const *) s != 0;
}
static int s_is_false(void const *s)
{
  return *(short const *) s == 0;
}
static int s_is_zero(void const *s)
{
  return *(short const *) s == 0;
}
static int s_is_positive(void const *s)
{
  return *(short const *) s > 0;
}
static int s_is_negative(void const *s)
{
  return *(short const *) s < 0;
}

static const struct value_operations short_operations =
  {
    { 
      s_to_b, &s_to_c, &s_to_c, &s_to_uc, &s_to_s, &s_to_us,
      &s_to_i, &s_to_ui, &s_to_l, &s_to_ul, &s_to_ll, &s_to_ull,
      &s_to_f, &s_to_d, &s_to_ld, 0 /*s_to_qd*/,
      s_to_f, s_to_d, s_to_ld, 0 /*s_to_qi*/,
      s_to_fo, s_to_do, s_to_lo, 0 /*s_to_qo*/,
    },
    {
      ret1, &s_fits_c, &s_fits_c, &s_fits_uc, &ret1, &s_fits_us, &ret1, &ret1,
      &ret1, &ret1, &ret1, &ret1,
      &ret1, &ret1, &ret1, 0 /*s_fits_qd*/,
      ret1, ret1, ret1, 0 /*s_fits_qi*/,
      ret1, ret1, ret1, 0 /*s_fits_qo*/,
    },
    {
      &s_is_true, &s_is_false, &s_is_zero,
      &s_is_positive, &s_is_negative,
      &ret1, &ret0
    },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 }
  };

static int us_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const unsigned short*) d) *(unsigned char*) d = 1;
  return 0;
}
static int us_to_c(void const *s, void *d)
{
  CONVERT(unsigned short, signed char);
  return 0;
}
static int us_to_uc(void const *s, void *d)
{
  CONVERT(unsigned short, unsigned char);
  return 0;
}
static int us_to_s(void const *s, void *d)
{
  CONVERT(unsigned short, short);
  return 0;
}
static int us_to_us(void const *s, void *d)
{
  CONVERT(unsigned short, unsigned short);
  return 0;
}
static int us_to_i(void const *s, void *d)
{
  CONVERT(unsigned short, int);
  return 0;
}
static int us_to_ui(void const *s, void *d)
{
  CONVERT(unsigned short, unsigned int);
  return 0;
}
static int us_to_l(void const *s, void *d)
{
  CONVERT(unsigned short, long);
  return 0;
}
static int us_to_ul(void const *s, void *d)
{
  CONVERT(unsigned short, unsigned long);
  return 0;
}
static int us_to_ll(void const *s, void *d)
{
  CONVERT(unsigned short, rllong_t);
  return 0;
}
static int us_to_ull(void const *s, void *d)
{
  CONVERT(unsigned short, rullong_t);
  return 0;
}
static int us_to_f(void const *s, void *d)
{
  CONVERT(unsigned short, float);
  return 0;
}
static int us_to_d(void const *s, void *d)
{
  CONVERT(unsigned short, double);
  return 0;
}
static int us_to_ld(void const *s, void *d)
{
  CONVERT(unsigned short, long double);
  return 0;
}
static int us_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const unsigned short*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int us_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const unsigned short*) s;
  dd->d_im = 0.0;
  return 0;
}
static int us_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const unsigned short*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int us_fits_c(void const *s)
{
  unsigned short val = *(unsigned short const *) s;
  return val <= CHAR_MAX;
}
static int us_fits_uc(void const *s)
{
  unsigned short val = *(unsigned short const *) s;
  return val <= UCHAR_MAX;
}
static int us_fits_s(void const *s)
{
  unsigned short val = *(unsigned short const *) s;
  return val <= SHRT_MAX;
}

static int us_is_true(void const *s)
{
  return *(unsigned short const *) s != 0;
}
static int us_is_false(void const *s)
{
  return *(unsigned short const *) s == 0;
}
static int us_is_zero(void const *s)
{
  return *(unsigned short const *) s == 0;
}
static int us_is_positive(void const *s)
{
  return *(unsigned short const *) s > 0;
}

static const struct value_operations ushort_operations =
  {
    { 
      us_to_b, &us_to_c, &us_to_c, &us_to_uc, &us_to_s, &us_to_us,
      &us_to_i, &us_to_ui, &us_to_l, &us_to_ul, &us_to_ll, &us_to_ull,
      &us_to_f, &us_to_d, &us_to_ld, 0 /*us_to_qd*/,
      us_to_f, us_to_d, us_to_ld, 0 /*us_to_qi*/,
      us_to_fo, us_to_do, us_to_lo, 0 /*us_to_qo*/,
    },
    {
      ret1, &us_fits_c, &us_fits_c, &us_fits_uc, &us_fits_s, &ret1,
      &ret1, &ret1, &ret1, &ret1, &ret1, &ret1,
      &ret1, &ret1, &ret1, 0 /*us_fits_qd*/,
      ret1, ret1, ret1, 0 /*us_fits_qi*/,
      ret1, ret1, ret1, 0 /*us_fits_qo*/,
    },
    {
      &us_is_true, &us_is_false, &us_is_zero,
      &us_is_positive, &ret0,
      &ret1, &ret0
    },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 }
  };

static int i_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const int*) d) *(unsigned char*) d = 1;
  return 0;
}
static int i_to_c(void const *s, void *d)
{
  CONVERT(int, signed char);
  return 0;
}
static int i_to_uc(void const *s, void *d)
{
  CONVERT(int, unsigned char);
  return 0;
}
static int i_to_s(void const *s, void *d)
{
  CONVERT(int, short);
  return 0;
}
static int i_to_us(void const *s, void *d)
{
  CONVERT(int, unsigned short);
  return 0;
}
static int i_to_i(void const *s, void *d)
{
  CONVERT(int, int);
  return 0;
}
static int i_to_ui(void const *s, void *d)
{
  CONVERT(int, unsigned int);
  return 0;
}
static int i_to_l(void const *s, void *d)
{
  CONVERT(int, long);
  return 0;
}
static int i_to_ul(void const *s, void *d)
{
  CONVERT(int, unsigned long);
  return 0;
}
static int i_to_ll(void const *s, void *d)
{
  CONVERT(int, rllong_t);
  return 0;
}
static int i_to_ull(void const *s, void *d)
{
  CONVERT(int, rullong_t);
  return 0;
}
static int i_to_f(void const *s, void *d)
{
  CONVERT(int, float);
  return 0;
}
static int i_to_d(void const *s, void *d)
{
  CONVERT(int, double);
  return 0;
}
static int i_to_ld(void const *s, void *d)
{
  CONVERT(int, long double);
  return 0;
}
static int i_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const int*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int i_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const int*) s;
  dd->d_im = 0.0;
  return 0;
}
static int i_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const int*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int i_fits_c(void const *s)
{
  int val = *(int const *) s;
  return val >= CHAR_MIN && val <= CHAR_MAX;
}
static int i_fits_uc(void const *s)
{
  int val = *(int const *) s;
  return val >= 0 && val <= UCHAR_MAX;
}
static int i_fits_s(void const *s)
{
  int val = *(int const *) s;
  return val >= SHRT_MIN && val <= SHRT_MAX;
}
static int i_fits_us(void const *s)
{
  int val = *(int const *) s;
  return val >= 0 && val <= USHRT_MAX;
}
static int i_fits_ui(void const *s)
{
  int val = *(int const *) s;
  return val >= 0;
}

static int i_is_true(void const *s)
{
  return *(int const *) s != 0;
}
static int i_is_false(void const *s)
{
  return *(int const *) s == 0;
}
static int i_is_zero(void const *s)
{
  return *(int const *) s == 0;
}
static int i_is_positive(void const *s)
{
  return *(int const *) s > 0;
}
static int i_is_negative(void const *s)
{
  return *(int const *) s < 0;
}

static int i_is_eq(void const *s1, void const *s2)
{
  return *(int *) s1 == *(int *) s2;
}
static int i_is_ne(void const *s1, void const *s2)
{
  return *(int *) s1 != *(int *) s2;
}
static int i_is_lt(void const *s1, void const *s2)
{
  return *(int *) s1 < *(int *) s2;
}
static int i_is_gt(void const *s1, void const *s2)
{
  return *(int *) s1 > *(int *) s2;
}
static int i_is_le(void const *s1, void const *s2)
{
  return *(int *) s1 <= *(int *) s2;
}
static int i_is_ge(void const *s1, void const *s2)
{
  return *(int *) s1 >= *(int *) s2;
}
static int i_cmp(void const *s1, void const *s2)
{
  int v1 = *(int const*) s1;
  int v2 = *(int const*) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int i_eq(void const *s1, void const *s2, void *d)
{
  *(int *) d = (*(int *) s1 == *(int *) s2);
  return 0;
}
static int i_ne(void const *s1, void const *s2, void *d)
{
  *(int *) d = (*(int *) s1 != *(int *) s2);
  return 0;
}
static int i_lt(void const *s1, void const *s2, void *d)
{
  *(int *) d = (*(int *) s1 < *(int *) s2);
  return 0;
}
static int i_gt(void const *s1, void const *s2, void *d)
{
  *(int *) d = (*(int *) s1 > *(int *) s2);
  return 0;
}
static int i_le(void const *s1, void const *s2, void *d)
{
  *(int *) d = (*(int *) s1 <= *(int *) s2);
  return 0;
}
static int i_ge(void const *s1, void const *s2, void *d)
{
  *(int *) d = (*(int *) s1 >= *(int *) s2);
  return 0;
}

static int i_bitor(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 | *(int *) s2;
  return 0;
}
static int i_bitxor(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 ^ *(int *) s2;
  return 0;
}
static int i_bitand(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 & *(int *) s2;
  return 0;
}
static int i_asr(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 >> *(int *) s2;
  return 0;
}
static int i_asl(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 << *(int *) s2;
  return 0;
}
static int i_add(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 + *(int *) s2;
  return 0;
}
static int i_sub(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 - *(int *) s2;
  return 0;
}
static int i_mul(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 * *(int *) s2;
  return 0;
}
static int i_div(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 / *(int *) s2;
  return 0;
}
static int i_mod(void const *s1, void const *s2, void *d)
{
  *(int *) d = *(int *) s1 % *(int *) s2;
  return 0;
}

static int i_plus(void const *s, void *d)
{
  *(int *) d = + *(int *) s;
  return 0;
}
static int i_minus(void const *s, void *d)
{
  *(int *) d = - *(int *) s;
  return 0;
}
static int i_bitnot(void const *s, void *d)
{
  *(int *) d = ~ *(int *) s;
  return 0;
}
static int i_lognot(void const *s, void *d)
{
  *(int *) d = ! *(int *) s;
  return 0;
}

static int i_inc(void *d)
{
  (*(int *) d)++;
  return 0;
}
static int i_dec(void *d)
{
  (*(int *) d)--;
  return 0;
}

static const struct value_operations int_operations =
  {
    { 
      i_to_b, &i_to_c, &i_to_c, &i_to_uc, &i_to_s, &i_to_us, &i_to_i, &i_to_ui,
      &i_to_l, &i_to_ul, &i_to_ll, &i_to_ull,
      &i_to_f, &i_to_d, &i_to_ld, 0 /*i_to_qd*/,
      i_to_f, i_to_d, i_to_ld, 0 /*i_to_qi*/,
      i_to_fo, i_to_do, i_to_lo, 0 /*i_to_qo*/,
    },
    {
      ret1, &i_fits_c, &i_fits_c, &i_fits_uc, &i_fits_s, &i_fits_us,
      &ret1, &i_fits_ui, &ret1, &i_fits_ui, &ret1, &ret1,
      &ret1, &ret1, &ret1, 0 /*i_fits_qd*/,
      ret1, ret1, ret1, 0 /*i_fits_qi*/,
      ret1, ret1, ret1, 0 /*i_fits_qo*/,
    },
    {
      &i_is_true, &i_is_false, &i_is_zero,
      &i_is_positive, &i_is_negative,
      &ret1, &ret0
    },
    {
      &i_is_eq, &i_is_ne, &i_is_lt, &i_is_gt, &i_is_le, &i_is_ge, &i_cmp
    },
    {
      &i_eq, &i_ne, &i_lt, &i_gt, &i_le, &i_ge,
    },
    {
      &i_bitor, &i_bitxor, &i_bitand, &i_asr, &i_asl,
      &i_add, &i_sub, &i_mul, &i_div, &i_mod
    },
    {
      &i_lognot,
    },
    {
      &i_plus, &i_minus, &i_bitnot,
    },
    {
      &i_inc, &i_dec
    }
  };

static int ui_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const unsigned int*) d) *(unsigned char*) d = 1;
  return 0;
}
static int ui_to_c(void const *s, void *d)
{
  CONVERT(unsigned int, signed char);
  return 0;
}
static int ui_to_uc(void const *s, void *d)
{
  CONVERT(unsigned int, unsigned char);  
  return 0;
}
static int ui_to_s(void const *s, void *d)
{
  CONVERT(unsigned int, short);  
  return 0;
}
static int ui_to_us(void const *s, void *d)
{
  CONVERT(unsigned int, unsigned short);  
  return 0;
}
static int ui_to_i(void const *s, void *d)
{
  CONVERT(unsigned int, int);  
  return 0;
}
static int ui_to_ui(void const *s, void *d)
{
  CONVERT(unsigned int, unsigned int);  
  return 0;
}
static int ui_to_l(void const *s, void *d)
{
  CONVERT(unsigned int, long);  
  return 0;
}
static int ui_to_ul(void const *s, void *d)
{
  CONVERT(unsigned int, unsigned long);  
  return 0;
}
static int ui_to_ll(void const *s, void *d)
{
  CONVERT(unsigned int, rllong_t);  
  return 0;
}
static int ui_to_ull(void const *s, void *d)
{
  CONVERT(unsigned int, rullong_t);  
  return 0;
}
static int ui_to_f(void const *s, void *d)
{
  CONVERT(unsigned int, float);  
  return 0;
}
static int ui_to_d(void const *s, void *d)
{
  CONVERT(unsigned int, double);  
  return 0;
}
static int ui_to_ld(void const *s, void *d)
{
  CONVERT(unsigned int, long double);  
  return 0;
}
static int ui_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const unsigned int*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int ui_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const unsigned int*) s;
  dd->d_im = 0.0;
  return 0;
}
static int ui_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const unsigned int*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int ui_fits_c(void const *s)
{
  unsigned int val = *(unsigned int const *) s;
  return val <= CHAR_MAX;
}
static int ui_fits_uc(void const *s)
{
  unsigned int val = *(unsigned int const *) s;
  return val <= UCHAR_MAX;
}
static int ui_fits_s(void const *s)
{
  unsigned int val = *(unsigned int const *) s;
  return val <= SHRT_MAX;
}
static int ui_fits_us(void const *s)
{
  unsigned int val = *(unsigned int const *) s;
  return val <= USHRT_MAX;
}
static int ui_fits_i(void const *s)
{
  unsigned int val = *(unsigned int const *) s;
  return val <= INT_MAX;
}

static int ui_is_true(void const *s)
{
  return *(unsigned int const *) s != 0;
}
static int ui_is_false(void const *s)
{
  return *(unsigned int const *) s == 0;
}
static int ui_is_zero(void const *s)
{
  return *(unsigned int const *) s == 0;
}
static int ui_is_positive(void const *s)
{
  return *(unsigned int const *) s > 0;
}
static int ui_is_large(void const *s)
{
  unsigned int val = *(unsigned int const*) s;
  return (val >= 0x80000000u);
}

static int ui_is_eq(void const *s1, void const *s2)
{
  return *(unsigned int *) s1 == *(unsigned int *) s2;
}
static int ui_is_ne(void const *s1, void const *s2)
{
  return *(unsigned int *) s1 != *(unsigned int *) s2;
}
static int ui_is_lt(void const *s1, void const *s2)
{
  return *(unsigned int *) s1 < *(unsigned int *) s2;
}
static int ui_is_gt(void const *s1, void const *s2)
{
  return *(unsigned int *) s1 > *(unsigned int *) s2;
}
static int ui_is_le(void const *s1, void const *s2)
{
  return *(unsigned int *) s1 <= *(unsigned int *) s2;
}
static int ui_is_ge(void const *s1, void const *s2)
{
  return *(unsigned int *) s1 >= *(unsigned int *) s2;
}
static int ui_cmp(void const *s1, void const *s2)
{
  unsigned int v1 = *(unsigned int const *) s1;
  unsigned int v2 = *(unsigned int const *) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int ui_eq(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = (*(unsigned int *) s1 == *(unsigned int *) s2);
  return 0;
}
static int ui_ne(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = (*(unsigned int *) s1 != *(unsigned int *) s2);
  return 0;
}
static int ui_lt(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = (*(unsigned int *) s1 < *(unsigned int *) s2);
  return 0;
}
static int ui_gt(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = (*(unsigned int *) s1 > *(unsigned int *) s2);
  return 0;
}
static int ui_le(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = (*(unsigned int *) s1 <= *(unsigned int *) s2);
  return 0;
}
static int ui_ge(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = (*(unsigned int *) s1 >= *(unsigned int *) s2);
  return 0;
}

static int ui_bitor(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 | *(unsigned int *) s2;
  return 0;
}
static int ui_bitxor(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 ^ *(unsigned int *) s2;
  return 0;
}
static int ui_bitand(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 & *(unsigned int *) s2;
  return 0;
}
static int ui_asr(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 >> *(unsigned int *) s2;
  return 0;
}
static int ui_asl(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 << *(unsigned int *) s2;
  return 0;
}
static int ui_add(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 + *(unsigned int *) s2;
  return 0;
}
static int ui_sub(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 - *(unsigned int *) s2;
  return 0;
}
static int ui_mul(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 * *(unsigned int *) s2;
  return 0;
}
static int ui_div(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 / *(unsigned int *) s2;
  return 0;
}
static int ui_mod(void const *s1, void const *s2, void *d)
{
  *(unsigned int *) d = *(unsigned int *) s1 % *(unsigned int *) s2;
  return 0;
}

static int ui_plus(void const *s, void *d)
{
  *(unsigned int *) d = + *(unsigned int *) s;
  return 0;
}
static int ui_minus(void const *s, void *d)
{
  *(unsigned int *) d = - *(unsigned int *) s;
  return 0;
}
static int ui_bitnot(void const *s, void *d)
{
  *(unsigned int *) d = ~ *(unsigned int *) s;
  return 0;
}
static int ui_lognot(void const *s, void *d)
{
  *(int *) d = ! *(unsigned int *) s;
  return 0;
}

static int ui_inc(void *d)
{
  (*(unsigned int *) d)++;
  return 0;
}
static int ui_dec(void *d)
{
  (*(unsigned int *) d)--;
  return 0;
}

static const struct value_operations uint_operations =
  {
    { 
      ui_to_b, ui_to_c, ui_to_c, ui_to_uc, ui_to_s, ui_to_us,
      ui_to_i, ui_to_ui, ui_to_l, ui_to_ul, ui_to_ll, ui_to_ull,
      &ui_to_f, &ui_to_d, &ui_to_ld, 0 /*ui_to_qd*/,
      ui_to_f, ui_to_d, ui_to_ld, 0 /*ui_to_qi*/,
      ui_to_fo, ui_to_do, ui_to_lo, 0 /*ui_to_qo*/,
    },
    {
      ret1, &ui_fits_c, &ui_fits_c, &ui_fits_uc, &ui_fits_s, &ui_fits_us,
      &ui_fits_i,&ret1, &ui_fits_i, &ret1, &ret1, &ret1,
      &ret1, &ret1, &ret1, 0 /*ui_fits_qd*/,
      ret1, ret1, ret1, 0 /*ui_fits_qi*/,
      ret1, ret1, ret1, 0 /*ui_fits_qo*/,
    },
    {
      &ui_is_true, &ui_is_false, &ui_is_zero,
      &ui_is_positive, &ret0,
      &ret1, &ui_is_large
    },
    {
      &ui_is_eq, &ui_is_ne, &ui_is_lt, &ui_is_gt, &ui_is_le, &ui_is_ge,
      &ui_cmp
    },
    {
      &ui_eq, &ui_ne, &ui_lt, &ui_gt, &ui_le, &ui_ge,
    },
    {
      &ui_bitor, &ui_bitxor, &ui_bitand, &ui_asr, &ui_asl,
      &ui_add, &ui_sub, &ui_mul, &ui_div, &ui_mod
    },
    {
      &ui_lognot,
    },
    {
      &ui_plus, &ui_minus, &ui_bitnot,
    },
    {
      &ui_inc, &ui_dec
    }
  };

static int ll_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const long long*) d) *(unsigned char*) d = 1;
  return 0;
}
static int ll_to_c(void const *s, void *d)
{
  CONVERT(rllong_t, signed char);
  return 0;
}
static int ll_to_uc(void const *s, void *d)
{
  CONVERT(rllong_t, unsigned char);
  return 0;
}
static int ll_to_s(void const *s, void *d)
{
  CONVERT(rllong_t, short);
  return 0;
}
static int ll_to_us(void const *s, void *d)
{
  CONVERT(rllong_t, unsigned short);
  return 0;
}
static int ll_to_i(void const *s, void *d)
{
  CONVERT(rllong_t, int);
  return 0;
}
static int ll_to_ui(void const *s, void *d)
{
  CONVERT(rllong_t, unsigned int);
  return 0;
}
static int ll_to_l(void const *s, void *d)
{
  CONVERT(rllong_t, long);
  return 0;
}
static int ll_to_ul(void const *s, void *d)
{
  CONVERT(rllong_t, unsigned long);
  return 0;
}
static int ll_to_ll(void const *s, void *d)
{
  CONVERT(rllong_t, rllong_t);
  return 0;
}
static int ll_to_ull(void const *s, void *d)
{
  CONVERT(rllong_t, rullong_t);
  return 0;
}
static int ll_to_f(void const *s, void *d)
{
  CONVERT(rllong_t, float);
  return 0;
}
static int ll_to_d(void const *s, void *d)
{
  CONVERT(rllong_t, double);
  return 0;
}
static int ll_to_ld(void const *s, void *d)
{
  CONVERT(rllong_t, long double);
  return 0;
}
static int ll_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const long long*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int ll_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const long long*) s;
  dd->d_im = 0.0;
  return 0;
}
static int ll_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const long long*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int ll_fits_c(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= CHAR_MIN && val <= CHAR_MAX;
}
static int ll_fits_uc(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= 0 && val <= UCHAR_MAX;
}
static int ll_fits_s(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= SHRT_MIN && val <= SHRT_MAX;
}
static int ll_fits_us(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= 0 && val <= USHRT_MAX;
}
static int ll_fits_i(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= INT_MAX && val <= INT_MAX;
}
static int ll_fits_ui(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= 0 && val <= UINT_MAX;
}
static int ll_fits_ull(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return val >= 0;
}

static int ll_is_true(void const *s)
{
  return *(rllong_t const *) s != 0;
}
static int ll_is_false(void const *s)
{
  return *(rllong_t const *) s == 0;
}
static int ll_is_zero(void const *s)
{
  return *(rllong_t const *) s == 0;
}
static int ll_is_positive(void const *s)
{
  return *(rllong_t const *) s > 0;
}
static int ll_is_negative(void const *s)
{
  return *(rllong_t const *) s < 0;
}
static int ll_is_large(void const *s)
{
  rllong_t val = *(rllong_t const *) s;
  return (val >= 0x80000000u);
}

static int ll_is_eq(void const *s1, void const *s2)
{
  return *(rllong_t *) s1 == *(rllong_t *) s2;
}
static int ll_is_ne(void const *s1, void const *s2)
{
  return *(rllong_t *) s1 != *(rllong_t *) s2;
}
static int ll_is_lt(void const *s1, void const *s2)
{
  return *(rllong_t *) s1 < *(rllong_t *) s2;
}
static int ll_is_gt(void const *s1, void const *s2)
{
  return *(rllong_t *) s1 > *(rllong_t *) s2;
}
static int ll_is_le(void const *s1, void const *s2)
{
  return *(rllong_t *) s1 <= *(rllong_t *) s2;
}
static int ll_is_ge(void const *s1, void const *s2)
{
  return *(rllong_t *) s1 >= *(rllong_t *) s2;
}
static int ll_cmp(void const *s1, void const *s2)
{
  rllong_t v1 = *(rllong_t const *) s1;
  rllong_t v2 = *(rllong_t const *) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int ll_eq(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = (*(rllong_t *) s1 == *(rllong_t *) s2);
  return 0;
}
static int ll_ne(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = (*(rllong_t *) s1 != *(rllong_t *) s2);
  return 0;
}
static int ll_lt(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = (*(rllong_t *) s1 < *(rllong_t *) s2);
  return 0;
}
static int ll_gt(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = (*(rllong_t *) s1 > *(rllong_t *) s2);
  return 0;
}
static int ll_le(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = (*(rllong_t *) s1 <= *(rllong_t *) s2);
  return 0;
}
static int ll_ge(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = (*(rllong_t *) s1 >= *(rllong_t *) s2);
  return 0;
}

static int ll_bitor(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 | *(rllong_t *) s2;
  return 0;
}
static int ll_bitxor(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 ^ *(rllong_t *) s2;
  return 0;
}
static int ll_bitand(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 & *(rllong_t *) s2;
  return 0;
}
static int ll_asr(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 >> *(rllong_t *) s2;
  return 0;
}
static int ll_asl(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 << *(rllong_t *) s2;
  return 0;
}
static int ll_add(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 + *(rllong_t *) s2;
  return 0;
}
static int ll_sub(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 - *(rllong_t *) s2;
  return 0;
}
static int ll_mul(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 * *(rllong_t *) s2;
  return 0;
}
static int ll_div(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 / *(rllong_t *) s2;
  return 0;
}
static int ll_mod(void const *s1, void const *s2, void *d)
{
  *(rllong_t *) d = *(rllong_t *) s1 % *(rllong_t *) s2;
  return 0;
}

static int ll_plus(void const *s, void *d)
{
  *(rllong_t *) d = + *(rllong_t *) s;
  return 0;
}
static int ll_minus(void const *s, void *d)
{
  *(rllong_t *) d = - *(rllong_t *) s;
  return 0;
}
static int ll_bitnot(void const *s, void *d)
{
  *(rllong_t *) d = ~ *(rllong_t *) s;
  return 0;
}
static int ll_lognot(void const *s, void *d)
{
  *(int *) d = ! *(rllong_t *) s;
  return 0;
}

static int ll_inc(void *d)
{
  (*(rllong_t *) d)++;
  return 0;
}
static int ll_dec(void *d)
{
  (*(rllong_t *) d)--;
  return 0;
}

static const struct value_operations llong_operations =
  {
    { 
      ll_to_b, ll_to_c, ll_to_c, ll_to_uc, ll_to_s, ll_to_us,
      ll_to_i, ll_to_ui, ll_to_l, ll_to_ul, ll_to_ll, ll_to_ull,
      &ll_to_f, &ll_to_d, &ll_to_ld, 0 /*ll_to_qd*/,
      ll_to_f, ll_to_d, ll_to_ld, 0 /*ll_to_qi*/,
      ll_to_fo, ll_to_do, ll_to_lo, 0 /*ll_to_qo*/,
    },
    {
      ret1, &ll_fits_c, &ll_fits_c, &ll_fits_uc, &ll_fits_s, &ll_fits_us,
      &ll_fits_i, &ll_fits_ui, &ll_fits_i, &ll_fits_ui, &ret1, &ll_fits_ull,
      &ret1, &ret1, &ret1, 0 /*ll_fits_qd*/,
      ret1, ret1, ret1, 0 /*ll_fits_qi*/,
      ret1, ret1, ret1, 0 /*ll_fits_qo*/,
    },
    {
      &ll_is_true, &ll_is_false, &ll_is_zero,
      &ll_is_positive, &ll_is_negative,
      &ret1, &ll_is_large
    },
    {
      &ll_is_eq, &ll_is_ne, &ll_is_lt, &ll_is_gt, &ll_is_le, &ll_is_ge,
      &ll_cmp
    },
    {
      &ll_eq, &ll_ne, &ll_lt, &ll_gt, &ll_le, &ll_ge,
    },
    {
      &ll_bitor, &ll_bitxor, &ll_bitand, &ll_asr, &ll_asl,
      &ll_add, &ll_sub, &ll_mul, &ll_div, &ll_mod
    },
    {
      &ll_lognot,
    },
    {
      &ll_plus, &ll_minus, &ll_bitnot,
    },
    {
      &ll_inc, &ll_dec
    }
  };

static int ull_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const unsigned long long*) d) *(unsigned char*) d = 1;
  return 0;
}
static int ull_to_c(void const *s, void *d)
{
  CONVERT(rullong_t, signed char);
  return 0;
}
static int ull_to_uc(void const *s, void *d)
{
  CONVERT(rullong_t, unsigned char);
  return 0;
}
static int ull_to_s(void const *s, void *d)
{
  CONVERT(rullong_t, short);
  return 0;
}
static int ull_to_us(void const *s, void *d)
{
  CONVERT(rullong_t, unsigned short);
  return 0;
}
static int ull_to_i(void const *s, void *d)
{
  CONVERT(rullong_t, int);
  return 0;
}
static int ull_to_ui(void const *s, void *d)
{
  CONVERT(rullong_t, unsigned int);
  return 0;
}
static int ull_to_l(void const *s, void *d)
{
  CONVERT(rullong_t, long);
  return 0;
}
static int ull_to_ul(void const *s, void *d)
{
  CONVERT(rullong_t, unsigned long);
  return 0;
}
static int ull_to_ll(void const *s, void *d)
{
  CONVERT(rullong_t, rllong_t);
  return 0;
}
static int ull_to_ull(void const *s, void *d)
{
  CONVERT(rullong_t, rullong_t);
  return 0;
}
static int ull_to_f(void const *s, void *d)
{
#ifdef _MSC_VER
  /* Visual C sucks! */
  rllong_t ll = *(rllong_t const *) s;
  float f;
  if (ll < 0) {
    f = 18446744073709551616.0f + (float) ll;
  } else {
    f = (float) ll;
  }
  *(float *) d = f;
#else
  CONVERT(rullong_t, float);
#endif /* M$ Visual C */
  return 0;
}
static int ull_to_d(void const *s, void *d)
{
#ifdef _MSC_VER
  rllong_t ll = *(rllong_t const *) s;
  double f;
  if (ll < 0) {
    f = 18446744073709551616.0 + (double) ll;
  } else {
    f = (double) ll;
  }
  *(double *) d = f;
#else
  CONVERT(rullong_t, double);
#endif /* M$ Visual C */
  return 0;
}
static int ull_to_ld(void const *s, void *d)
{
#ifdef _MSC_VER
  rllong_t ll = *(rllong_t const *) s;
  long double f;
  if (ll < 0) {
    f = 18446744073709551616.0l + (long double) ll;
  } else {
    f = (long double) ll;
  }
  *(long double *) d = f;
#else
  CONVERT(rullong_t, long double);
#endif /* M$ Visual C */
  return 0;
}
static int ull_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const unsigned long long*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int ull_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const unsigned long long*) s;
  dd->d_im = 0.0;
  return 0;
}
static int ull_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const unsigned long long*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int ull_fits_c(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= CHAR_MAX;
}
static int ull_fits_uc(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= UCHAR_MAX;
}
static int ull_fits_s(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= SHRT_MAX;
}
static int ull_fits_us(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= USHRT_MAX;
}
static int ull_fits_i(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= INT_MAX;
}
static int ull_fits_ui(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= UINT_MAX;
}
static int ull_fits_ll(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return val <= R_LONG_LONG_MAX;
}

static int ull_is_true(void const *s)
{
  return *(rullong_t const *) s != 0;
}
static int ull_is_false(void const *s)
{
  return *(rullong_t const *) s == 0;
}
static int ull_is_zero(void const *s)
{
  return *(rullong_t const *) s == 0;
}
static int ull_is_positive(void const *s)
{
  return *(rullong_t const *) s > 0;
}
static int ull_is_large(void const *s)
{
  rullong_t val = *(rullong_t const *) s;
  return (val >= 0x80000000u);
}

static int ull_is_eq(void const *s1, void const *s2)
{
  return *(rullong_t *) s1 == *(rullong_t *) s2;
}
static int ull_is_ne(void const *s1, void const *s2)
{
  return *(rullong_t *) s1 != *(rullong_t *) s2;
}
static int ull_is_lt(void const *s1, void const *s2)
{
  return *(rullong_t *) s1 < *(rullong_t *) s2;
}
static int ull_is_gt(void const *s1, void const *s2)
{
  return *(rullong_t *) s1 > *(rullong_t *) s2;
}
static int ull_is_le(void const *s1, void const *s2)
{
  return *(rullong_t *) s1 <= *(rullong_t *) s2;
}
static int ull_is_ge(void const *s1, void const *s2)
{
  return *(rullong_t *) s1 >= *(rullong_t *) s2;
}
static int ull_cmp(const void *s1, const void *s2)
{
  rullong_t v1 = *(rullong_t const *) s1;
  rullong_t v2 = *(rullong_t const *) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int ull_eq(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = (*(rullong_t *) s1 == *(rullong_t *) s2);
  return 0;
}
static int ull_ne(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = (*(rullong_t *) s1 != *(rullong_t *) s2);
  return 0;
}
static int ull_lt(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = (*(rullong_t *) s1 < *(rullong_t *) s2);
  return 0;
}
static int ull_gt(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = (*(rullong_t *) s1 > *(rullong_t *) s2);
  return 0;
}
static int ull_le(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = (*(rullong_t *) s1 <= *(rullong_t *) s2);
  return 0;
}
static int ull_ge(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = (*(rullong_t *) s1 >= *(rullong_t *) s2);
  return 0;
}

static int ull_bitor(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 | *(rullong_t *) s2;
  return 0;
}
static int ull_bitxor(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 ^ *(rullong_t *) s2;
  return 0;
}
static int ull_bitand(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 & *(rullong_t *) s2;
  return 0;
}
static int ull_asr(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 >> *(rullong_t *) s2;
  return 0;
}
static int ull_asl(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 << *(rullong_t *) s2;
  return 0;
}
static int ull_add(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 + *(rullong_t *) s2;
  return 0;
}
static int ull_sub(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 - *(rullong_t *) s2;
  return 0;
}
static int ull_mul(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 * *(rullong_t *) s2;
  return 0;
}
static int ull_div(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 / *(rullong_t *) s2;
  return 0;
}
static int ull_mod(void const *s1, void const *s2, void *d)
{
  *(rullong_t *) d = *(rullong_t *) s1 % *(rullong_t *) s2;
  return 0;
}

static int ull_plus(void const *s, void *d)
{
  *(rullong_t *) d = + *(rullong_t *) s;
  return 0;
}
static int ull_minus(void const *s, void *d)
{
  *(rullong_t *) d = - *(rullong_t *) s;
  return 0;
}
static int ull_bitnot(void const *s, void *d)
{
  *(rullong_t *) d = ~ *(rullong_t *) s;
  return 0;
}
static int ull_lognot(void const *s, void *d)
{
  *(int *) d = ! *(rullong_t *) s;
  return 0;
}

static int ull_inc(void *d)
{
  (*(rullong_t *) d)++;
  return 0;
}
static int ull_dec(void *d)
{
  (*(rullong_t *) d)--;
  return 0;
}

static const struct value_operations ullong_operations =
  {
    { 
      ull_to_b, &ull_to_c, &ull_to_c, &ull_to_uc, &ull_to_s, &ull_to_us,
      &ull_to_i, &ull_to_ui, &ull_to_l, &ull_to_ul, &ull_to_ll, &ull_to_ull,
      &ull_to_f, &ull_to_d, &ull_to_ld, 0 /*ull_to_qd*/,
      ull_to_f, ull_to_d, ull_to_ld, 0 /*ull_to_qi*/,
      ull_to_fo, ull_to_do, ull_to_lo, 0 /*ull_to_qo*/,
    },
    {
      ret1, &ull_fits_c, &ull_fits_c, &ull_fits_uc, &ull_fits_s, &ull_fits_us,
      &ull_fits_i, &ull_fits_ui,
      &ull_fits_i, &ull_fits_ui, &ull_fits_ll, &ret1,
      &ret1, &ret1, &ret1, 0 /* ull_fits_qd */,
      ret1, ret1, ret1, 0 /*ull_fits_qi*/,
      ret1, ret1, ret1, 0 /*ull_fits_qo*/,
    },
    {
      &ull_is_true, &ull_is_false, &ull_is_zero,
      &ull_is_positive, &ret0,
      &ret1, &ull_is_large
    },
    {
      &ull_is_eq, &ull_is_ne, &ull_is_lt, &ull_is_gt, &ull_is_le, &ull_is_ge,
      &ull_cmp
    },
    {
      &ull_eq, &ull_ne, &ull_lt, &ull_gt, &ull_le, &ull_ge,
    },
    {
      &ull_bitor, &ull_bitxor, &ull_bitand, &ull_asr, &ull_asl,
      &ull_add, &ull_sub, &ull_mul, &ull_div, &ull_mod
    },
    {
      &ull_lognot,
    },
    {
      &ull_plus, &ull_minus, &ull_bitnot,
    },
    {
      &ull_inc, &ull_dec
    }
  };

static int f_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const float*) d) *(unsigned char*) d = 1;
  return 0;
}
static int f_to_c(void const *s, void *d)
{
  CONVERT(float, signed char);
  return 0;
}
static int f_to_uc(void const *s, void *d)
{
  CONVERT(float, unsigned char);
  return 0;
}
static int f_to_s(void const *s, void *d)
{
  CONVERT(float, short);
  return 0;
}
static int f_to_us(void const *s, void *d)
{
  CONVERT(float, unsigned short);
  return 0;
}
static int f_to_i(void const *s, void *d)
{
  CONVERT(float, int);
  return 0;
}
static int f_to_ui(void const *s, void *d)
{
  CONVERT(float, unsigned int);
  return 0;
}
static int f_to_l(void const *s, void *d)
{
  CONVERT(float, long);
  return 0;
}
static int f_to_ul(void const *s, void *d)
{
  CONVERT(float, unsigned long);
  return 0;
}
static int f_to_ll(void const *s, void *d)
{
  CONVERT(float, rllong_t);
  return 0;
}
static int f_to_ull(void const *s, void *d)
{
  CONVERT(float, rullong_t);
  return 0;
}
static int f_to_f(void const *s, void *d)
{
  CONVERT(float, float);
  return 0;
}
static int f_to_d(void const *s, void *d)
{
  CONVERT(float, double);
  return 0;
}
static int f_to_ld(void const *s, void *d)
{
  CONVERT(float, long double);
  return 0;
}
static int f_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const float*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int f_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const float*) s;
  dd->d_im = 0.0;
  return 0;
}
static int f_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const float*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int f_is_true(void const *s)
{
  return *(float const *) s != 0.0f;
}
static int f_is_false(void const *s)
{
  return *(float const *) s == 0.0f;
}
static int f_is_zero(void const *s)
{
  return *(float const *) s == 0.0f;
}
static int f_is_positive(void const *s)
{
  return *(float const *) s > 0.0f;
}
static int f_is_negative(void const *s)
{
  return *(float const *) s < 0.0f;
}

static int f_is_eq(void const *s1, void const *s2)
{
  return COMPARE(float, ==);
}
static int f_is_ne(void const *s1, void const *s2)
{
  return COMPARE(float, !=);
}
static int f_is_lt(void const *s1, void const *s2)
{
  return COMPARE(float, <);
}
static int f_is_gt(void const *s1, void const *s2)
{
  return COMPARE(float, >);
}
static int f_is_le(void const *s1, void const *s2)
{
  return COMPARE(float, <=);
}
static int f_is_ge(void const *s1, void const *s2)
{
  return COMPARE(float, >=);
}
static int f_cmp(void const *s1, void const *s2)
{
  float v1 = *(const float *) s1;
  float v2 = *(const float *) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int f_eq(void const *s1, void const *s2, void *d)
{
  RELOP(float, ==);
  return 0;
}
static int f_ne(void const *s1, void const *s2, void *d)
{
  RELOP(float, !=);
  return 0;
}
static int f_lt(void const *s1, void const *s2, void *d)
{
  RELOP(float, <);
  return 0;
}
static int f_gt(void const *s1, void const *s2, void *d)
{
  RELOP(float, >);
  return 0;
}
static int f_le(void const *s1, void const *s2, void *d)
{
  RELOP(float, <=);
  return 0;
}
static int f_ge(void const *s1, void const *s2, void *d)
{
  RELOP(float, >=);
  return 0;
}

static int f_add(void const *s1, void const *s2, void *d)
{
  BINOP(float, +);
  return 0;
}
static int f_sub(void const *s1, void const *s2, void *d)
{
  BINOP(float, -);
  return 0;
}
static int f_mul(void const *s1, void const *s2, void *d)
{
  BINOP(float, *);
  return 0;
}
static int f_div(void const *s1, void const *s2, void *d)
{
  BINOP(float, /);
  return 0;
}

static int f_lognot(void const *s, void *d)
{
  LOGUNARY(float, !);
  return 0;
}

static int f_plus(void const *s, void *d)
{
  UNARY(float, +);
  return 0;
}
static int f_minus(void const *s, void *d)
{
  UNARY(float, -);
  return 0;
}

static int f_inc(void *d)
{
  INCOP(float, ++);
  return 0;
}
static int f_dec(void *d)
{
  INCOP(float, --);
  return 0;
}

static const struct value_operations float_operations =
  {
    { 
      f_to_b, &f_to_c, &f_to_c, &f_to_uc, &f_to_s, &f_to_us, &f_to_i, &f_to_ui,
      &f_to_l, &f_to_ul, &f_to_ll, &f_to_ull,
      &f_to_f, &f_to_d, &f_to_ld, 0 /*f_to_qd*/,
      f_to_f, f_to_d, f_to_ld, 0 /*f_to_qi*/,
      f_to_fo, f_to_do, f_to_lo, 0 /*f_to_qo*/,
    },
    { 0 },
    {
      &f_is_true, &f_is_false, &f_is_zero,
      &f_is_positive, &f_is_negative,
      &ret0 /* is_integral */, 0 /* is_large */
    },
    {
      0/*is_eq*/, 0/*is_ne*/, 0/*is_lt*/, 0/*is_gt*/, 0/*is_le*/, 0/*is_ge*/,
    },
    {
      0 /*eq*/, 0 /*ne*/, 0 /*lt*/, 0 /*gt*/, 0 /*le*/, 0 /*ge*/,
    },
    {
      0 /*bitor*/, 0/*bitxor*/, 0/*bitand*/, 0/*asr*/, 0/*asl*/,
      0 /*add*/, 0 /*sub*/, 0 /*mul*/, 0 /*div*/, 0/*mod*/
    },
    {
      0 /*lognot*/,
    },
    {
      0 /*plus*/, 0 /*minus*/, 0 /*bitnot*/,
    },
    {
      &f_inc, &f_dec
    }
  };

static int d_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const double*) d) *(unsigned char*) d = 1;
  return 0;
}
static int d_to_c(void const *s, void *d)
{
  CONVERT(double, signed char);
  return 0;
}
static int d_to_uc(void const *s, void *d)
{
  CONVERT(double, unsigned char);
  return 0;
}
static int d_to_s(void const *s, void *d)
{
  CONVERT(double, short);
  return 0;
}
static int d_to_us(void const *s, void *d)
{
  CONVERT(double, unsigned short);
  return 0;
}
static int d_to_i(void const *s, void *d)
{
  CONVERT(double, int);
  return 0;
}
static int d_to_ui(void const *s, void *d)
{
  CONVERT(double, unsigned int);
  return 0;
}
static int d_to_l(void const *s, void *d)
{
  CONVERT(double, long);
  return 0;
}
static int d_to_ul(void const *s, void *d)
{
  CONVERT(double, unsigned long);
  return 0;
}
static int d_to_ll(void const *s, void *d)
{
  CONVERT(double, rllong_t);
  return 0;
}
static int d_to_ull(void const *s, void *d)
{
  CONVERT(double, rullong_t);
  return 0;
}
static int d_to_f(void const *s, void *d)
{
  CONVERT(double, float);
  return 0;
}
static int d_to_d(void const *s, void *d)
{
  CONVERT(double, double);
  return 0;
}
static int d_to_ld(void const *s, void *d)
{
  CONVERT(double, long double);
  return 0;
}
static int d_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const double*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int d_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const double*) s;
  dd->d_im = 0.0;
  return 0;
}
static int d_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const double*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int d_is_true(void const *s)
{
  return *(double const *) s != 0.0;
}
static int d_is_false(void const *s)
{
  return *(double const *) s == 0.0;
}
static int d_is_zero(void const *s)
{
  return *(double const *) s == 0.0;
}
static int d_is_positive(void const *s)
{
  return *(double const *) s > 0.0;
}
static int d_is_negative(void const *s)
{
  return *(double const *) s < 0.0;
}

static int d_is_eq(void const *s1, void const *s2)
{
  return COMPARE(double, ==);
}
static int d_is_ne(void const *s1, void const *s2)
{
  return COMPARE(double, !=);
}
static int d_is_lt(void const *s1, void const *s2)
{
  return COMPARE(double, <);
}
static int d_is_gt(void const *s1, void const *s2)
{
  return COMPARE(double, >);
}
static int d_is_le(void const *s1, void const *s2)
{
  return COMPARE(double, <=);
}
static int d_is_ge(void const *s1, void const *s2)
{
  return COMPARE(double, >=);
}
static int d_cmp(void const *s1, void const *s2)
{
  double v1 = *(double const *) s1;
  double v2 = *(double const *) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int d_eq(void const *s1, void const *s2, void *d)
{
  RELOP(double, ==);
  return 0;
}
static int d_ne(void const *s1, void const *s2, void *d)
{
  RELOP(double, !=);
  return 0;
}
static int d_lt(void const *s1, void const *s2, void *d)
{
  RELOP(double, <);
  return 0;
}
static int d_gt(void const *s1, void const *s2, void *d)
{
  RELOP(double, >);
  return 0;
}
static int d_le(void const *s1, void const *s2, void *d)
{
  RELOP(double, <=);
  return 0;
}
static int d_ge(void const *s1, void const *s2, void *d)
{
  RELOP(double, >=);
  return 0;
}

static int d_add(void const *s1, void const *s2, void *d)
{
  BINOP(double, +);
  return 0;
}
static int d_sub(void const *s1, void const *s2, void *d)
{
  BINOP(double, -);
  return 0;
}
static int d_mul(void const *s1, void const *s2, void *d)
{
  BINOP(double, *);
  return 0;
}
static int d_div(void const *s1, void const *s2, void *d)
{
  BINOP(double, /);
  return 0;
}

static int d_lognot(void const *s, void *d)
{
  LOGUNARY(double, !);
  return 0;
}

static int d_plus(void const *s, void *d)
{
  UNARY(double, +);
  return 0;
}
static int d_minus(void const *s, void *d)
{
  UNARY(double, -);
  return 0;
}

static int d_inc(void *d)
{
  INCOP(double, ++);
  return 0;
}
static int d_dec(void *d)
{
  INCOP(double, --);
  return 0;
}

static const struct value_operations double_operations = 
  {
    { 
      d_to_b, &d_to_c, &d_to_c, &d_to_uc, &d_to_s, &d_to_us, &d_to_i, &d_to_ui,
      &d_to_l, &d_to_ul, &d_to_ll, &d_to_ull,
      &d_to_f, &d_to_d, &d_to_ld, 0 /*d_to_qd*/,
      d_to_f, d_to_d, d_to_ld, 0 /*d_to_qi*/,
      d_to_fo, d_to_do, d_to_lo, 0 /*d_to_qo*/,
    },
    { 0 },
    {
      &d_is_true, &d_is_false, &d_is_zero,
      &d_is_positive, &d_is_negative,
      &ret0 /* is_integral */, 0 /* is_large */
    },
    {
      &d_is_eq, &d_is_ne, &d_is_lt, &d_is_gt, &d_is_le, &d_is_ge,
      &d_cmp
    },
    {
      &d_eq, &d_ne, &d_lt, &d_gt, &d_le, &d_ge,
    },
    {
      0 /*bitor*/, 0/*bitxor*/, 0/*bitand*/, 0/*asr*/, 0/*asl*/,
      &d_add, &d_sub, &d_mul, &d_div, 0/*mod*/
    },
    {
      &d_lognot,
    },
    {
      &d_plus, &d_minus, 0 /*bitnot*/,
    },
    {
      &d_inc, &d_dec
    }
  };

static int ld_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const long double*) d) *(unsigned char*) d = 1;
  return 0;
}
static int ld_to_c(void const *s, void *d)
{
  CONVERT(long double, signed char);
  return 0;
}
static int ld_to_uc(void const *s, void *d)
{
  CONVERT(long double, unsigned char);
  return 0;
}
static int ld_to_s(void const *s, void *d)
{
  CONVERT(long double, short);
  return 0;
}
static int ld_to_us(void const *s, void *d)
{
  CONVERT(long double, unsigned short);
  return 0;
}
static int ld_to_i(void const *s, void *d)
{
  CONVERT(long double, int);
  return 0;
}
static int ld_to_ui(void const *s, void *d)
{
  CONVERT(long double, unsigned int);
  return 0;
}
static int ld_to_l(void const *s, void *d)
{
  CONVERT(long double, long);
  return 0;
}
static int ld_to_ul(void const *s, void *d)
{
  CONVERT(long double, unsigned long);
  return 0;
}
static int ld_to_ll(void const *s, void *d)
{
  CONVERT(long double, rllong_t);
  return 0;
}
static int ld_to_ull(void const *s, void *d)
{
  CONVERT(long double, rullong_t);
  return 0;
}
static int ld_to_f(void const *s, void *d)
{
  CONVERT(long double, float);
  return 0;
}
static int ld_to_d(void const *s, void *d)
{
  CONVERT(long double, double);
  return 0;
}
static int ld_to_ld(void const *s, void *d)
{
  CONVERT(long double, long double);
  return 0;
}
static int ld_to_fo(void const *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) *(const long double*) s;
  dd->f_im = 0.0f;
  return 0;
}
static int ld_to_do(void const *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) *(const long double*) s;
  dd->d_im = 0.0;
  return 0;
}
static int ld_to_lo(void const *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) *(const long double*) s;
  dd->l_im = 0.0L;
  return 0;
}

static int ld_is_true(void const *s)
{
  return *(long double const *) s != 0.0L;
}
static int ld_is_false(void const *s)
{
  return *(long double const *) s == 0.0L;
}
static int ld_is_zero(void const *s)
{
  return *(long double const *) s == 0.0L;
}
static int ld_is_positive(void const *s)
{
  return *(long double const *) s > 0.0L;
}
static int ld_is_negative(void const *s)
{
  return *(long double const *) s < 0.0L;
}

static int ld_is_eq(void const *s1, void const *s2)
{
  return COMPARE(long double, ==);
}
static int ld_is_ne(void const *s1, void const *s2)
{
  return COMPARE(long double, !=);
}
static int ld_is_lt(void const *s1, void const *s2)
{
  return COMPARE(long double, <);
}
static int ld_is_gt(void const *s1, void const *s2)
{
  return COMPARE(long double, >);
}
static int ld_is_le(void const *s1, void const *s2)
{
  return COMPARE(long double, <=);
}
static int ld_is_ge(void const *s1, void const *s2)
{
  return COMPARE(long double, >=);
}
static int ld_cmp(void const *s1, void const *s2)
{
  long double v1 = *(long double const *) s1;
  long double v2 = *(long double const *) s2;
  if (v1 < v2) return -1;
  if (v1 > v2) return 1;
  return 0;
}

static int ld_eq(void const *s1, void const *s2, void *d)
{
  RELOP(long double, ==);
  return 0;
}
static int ld_ne(void const *s1, void const *s2, void *d)
{
  RELOP(long double, !=);
  return 0;
}
static int ld_lt(void const *s1, void const *s2, void *d)
{
  RELOP(long double, <);
  return 0;
}
static int ld_gt(void const *s1, void const *s2, void *d)
{
  RELOP(long double, >);
  return 0;
}
static int ld_le(void const *s1, void const *s2, void *d)
{
  RELOP(long double, <=);
  return 0;
}
static int ld_ge(void const *s1, void const *s2, void *d)
{
  RELOP(long double, >=);
  return 0;
}

static int ld_add(void const *s1, void const *s2, void *d)
{
  BINOP(long double, +);
  return 0;
}
static int ld_sub(void const *s1, void const *s2, void *d)
{
  BINOP(long double, -);
  return 0;
}
static int ld_mul(void const *s1, void const *s2, void *d)
{
  BINOP(long double, *);
  return 0;
}
static int ld_div(void const *s1, void const *s2, void *d)
{
  BINOP(long double, /);
  return 0;
}

static int ld_lognot(void const *s, void *d)
{
  LOGUNARY(long double, !);
  return 0;
}

static int ld_plus(void const *s, void *d)
{
  UNARY(long double, +);
  return 0;
}
static int ld_minus(void const *s, void *d)
{
  UNARY(long double, -);
  return 0;
}

static int ld_inc(void *d)
{
  INCOP(long double, ++);
  return 0;
}
static int ld_dec(void *d)
{
  INCOP(long double, --);
  return 0;
}

static const struct value_operations ldouble_operations =
  {
    { 
      ld_to_b, ld_to_c, ld_to_c, ld_to_uc, ld_to_s, ld_to_us,
      ld_to_i, ld_to_ui, ld_to_l, ld_to_ul, ld_to_ll, ld_to_ull,
      &ld_to_f, &ld_to_d, &ld_to_ld, 0 /*ld_to_qd*/,
      ld_to_f, ld_to_d, ld_to_ld, 0 /*ld_to_qi*/,
      ld_to_fo, ld_to_do, ld_to_lo, 0 /*ld_to_qo*/,
    },
    { 0 },
    {
      &ld_is_true, &ld_is_false, &ld_is_zero,
      &ld_is_positive, &ld_is_negative,
      &ret0 /* is_integral */, 0 /* is_large */
    },
    {
      &ld_is_eq, &ld_is_ne, &ld_is_lt, &ld_is_gt, &ld_is_le, &ld_is_ge,
      &ld_cmp
    },
    {
      &ld_eq, &ld_ne, &ld_lt, &ld_gt, &ld_le, &ld_ge,
    },
    {
      0 /*bitor*/, 0/*bitxor*/, 0/*bitand*/, 0/*asr*/, 0/*asl*/,
      &ld_add, &ld_sub, &ld_mul, &ld_div, 0/*mod*/
    },
    {
      &ld_lognot,
    },
    {
      &ld_plus, &ld_minus, 0 /*bitnot*/,
    },
    {
      &ld_inc, &ld_dec
    }
  };

static int p_to_b(void const *s, void *d)
{
  *(unsigned char*) d = 0;
  if (*(const void**) d) *(unsigned char*) d = 1;
  return 0;
}
static int p_to_c(const void *s, void *d)
{
  *(char *) d = (char) (long) *(const void **) s;
  return 0;
}
static int p_to_sc(const void *s, void *d)
{
  *(signed char *) d = (signed char) (long) *(const void **) s;
  return 0;
}
static int p_to_uc(const void *s, void *d)
{
  *(unsigned char *) d = (unsigned char) (long) *(const void **) s;
  return 0;
}
static int p_to_s(const void *s, void *d)
{
  *(short *) d = (short) (long) *(const void **) s;
  return 0;
}
static int p_to_us(const void *s, void *d)
{
  *(unsigned short *) d = (unsigned short) (long) *(const void **) s;
  return 0;
}
static int p_to_i(const void *s, void *d)
{
  *(int *) d = (int) (long) *(const void **) s;
  return 0;
}
static int p_to_ui(const void *s, void *d)
{
  *(unsigned int *) d = (unsigned int) (unsigned long) *(const void **) s;
  return 0;
}
static int p_to_l(const void *s, void *d)
{
  *(long *) d = (long) *(const void **) s;
  return 0;
}
static int p_to_ul(const void *s, void *d)
{
  *(unsigned long *) d = (unsigned long) *(const void **) s;
  return 0;
}
static int p_to_ll(const void *s, void *d)
{
  *(long long *) d = (long long) (long) *(const void **) s;
  return 0;
}
static int p_to_ull(const void *s, void *d)
{
  *(unsigned long long *) d = (unsigned long long) (unsigned long) *(const void **) s;
  return 0;
}

static int p_is_eq(const void *p1, const void *p2)
{
  return (*(const void **) p1 == *(const void **) p2);
}
static int p_is_ne(const void *p1, const void *p2)
{
  return (*(const void **) p1 == *(const void **) p2);
}

static int p_eq(const void *s1, const void *s2, void *d)
{
  *(int *) d = (*(const void **) s1 == *(const void **) s2);
  return 0;
}
static int p_ne(const void *s1, const void *s2, void *d)
{
  *(int *) d = (*(const void **) s1 != *(const void **) s2);
  return 0;
}

static int p_is_true(const void *s)
{
  return *(const void **) s != 0;
}
static int p_is_false(const void *s)
{
  return *(const void **) s == 0;
}
static int p_is_zero(const void *s)
{
  return *(const void **) s == 0;
}

static const struct value_operations pointer_operations =
  {
    { 
      p_to_b, &p_to_c, &p_to_sc, &p_to_uc, &p_to_s, &p_to_us,
      &p_to_i, &p_to_ui, &p_to_l, &p_to_ul, &p_to_ll, &p_to_ull,
      0 /*p_to_f*/, 0 /*p_to_d*/, 0 /*p_to_ld*/, 0 /*p_to_qd*/,
      0 /*p_to_fi*/, 0 /*p_to_di*/, 0 /*p_to_li*/, 0 /*p_to_qi*/,
      0 /*p_to_fo*/, 0 /*p_to_do*/, 0 /*p_to_lo*/, 0 /*p_to_qo*/,
    },
    {
      0 /*p_fits_b*/,
      0 /*fits_c*/, 0 /*fits_sc*/, 0 /*fits_uc*/, 0 /*fits_s*/, 0 /*fits_us*/,
      0 /*p_fits_i*/, 0 /*p_fits_ui*/,
      0 /*p_fits_l*/, 0 /*p_fits_ui*/, 0 /*p_fits_ll*/, 0 /*p_fits_ull*/,
      0 /*p_fits_f*/, 0 /*p_fits_d*/, 0 /*p_fits_ld*/, 0 /*p_fits_qd*/,
      0 /*p_fits_fi*/, 0 /*p_fits_di*/, 0 /*p_fits_li*/, 0 /*p_fits_qi*/,
      0 /*p_fits_fo*/, 0 /*p_fits_do*/, 0 /*p_fits_lo*/, 0 /*p_fits_qo*/,
    },
    {
      &p_is_true, &p_is_false, &p_is_zero,
      0 /* is_positive */, 0 /* is_negative */,
      0 /* is_integral */, 0 /* is_large */
    },
    {
      &p_is_eq, &p_is_ne, 0 /*is_lt*/, 0 /*is_gt*/,0 /*is_le*/,0 /*is_ge*/,
      0 /* cmp */
    },
    {
      &p_eq, &p_ne, 0 /* lt */, 0 /* gt */, 0 /* le */, 0 /* ge */,
    },
    {
      0 /* bitor */, 0 /* bitxor */, 0 /* bitand */, 0 /* asr */, 0 /* asl */,
      0 /* add */, 0 /* sub */, 0 /* mul */, 0 /* div */, 0 /* mod */
    },
    {
      0 /* lognot */,
    },
    {
      0 /* plus */, 0 /* minus */, 0 /* bitnot */,
    },
    {
      0 /* inc */, 0 /* dec */
    }
  };

static int b_to_b(const void *s, void *d)
{
  CONVERT(unsigned char, unsigned char);
  return 0;
}
static int b_to_c(const void *s, void *d)
{
  CONVERT(unsigned char, signed char);
  return 0;
}
static int b_to_uc(const void *s, void *d)
{
  CONVERT(unsigned char, unsigned char);
  return 0;
}
static int b_to_s(const void *s, void *d)
{
  CONVERT(unsigned char, short);
  return 0;
}
static int b_to_us(const void *s, void *d)
{
  CONVERT(unsigned char, unsigned short);
  return 0;
}
static int b_to_i(const void *s, void *d)
{
  CONVERT(unsigned char, int);
  return 0;
}
static int b_to_ui(const void *s, void *d)
{
  CONVERT(unsigned char, unsigned int);
  return 0;
}
static int b_to_l(const void *s, void *d)
{
  CONVERT(unsigned char, long);
  return 0;
}
static int b_to_ul(const void *s, void *d)
{
  CONVERT(unsigned char, unsigned long);
  return 0;
}
static int b_to_ll(const void *s, void *d)
{
  CONVERT(unsigned char, long long);
  return 0;
}
static int b_to_ull(const void *s, void *d)
{
  CONVERT(unsigned char, unsigned long long);
  return 0;
}
static int b_to_f(const void *s, void *d)
{
  CONVERT(unsigned char, float);
  return 0;
}
static int b_to_d(const void *s, void *d)
{
  CONVERT(unsigned char, double);
  return 0;
}
static int b_to_ld(const void *s, void *d)
{
  CONVERT(unsigned char, long double);
  return 0;
}
static int b_to_fo(const void *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = (float) (*(const unsigned char *) s);
  dd->f_im = 0.0f;
  return 0;
}
static int b_to_do(const void *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) (*(const unsigned char *) s);
  dd->d_im = 0.0;
  return 0;
}
static int b_to_lo(const void *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) (*(const unsigned char *) s);
  dd->l_im = 0.0L;
  return 0;
}

static int b_is_true(const void *s)
{
  return *(const unsigned char*) s;
}
static int b_is_false(const void *s)
{
  return !*(const unsigned char*) s;
}

static const struct value_operations bool_operations =
{
  { 
    b_to_b, b_to_c, b_to_c, b_to_uc, b_to_s, b_to_us,
    b_to_i, b_to_ui, b_to_l, b_to_ul, b_to_ll, b_to_ull,
    b_to_f, b_to_d, b_to_ld, 0 /*b_to_qd*/,
    b_to_f, b_to_d, b_to_ld, 0 /*b_to_qd*/,
    b_to_fo, b_to_do, b_to_lo, 0 /*b_to_qo*/,
  },
  {
    ret1, ret1, ret1, ret1, ret1, ret1,
    ret1, ret1, ret1, ret1, ret1, ret1,
    ret1, ret1, ret1, 0 /*b_fits_qd*/,
    ret1, ret1, ret1, 0 /*b_fits_qi*/,
    ret1, ret1, ret1, 0 /*b_fits_qo*/,
  },
  {
    b_is_true, b_is_false, b_is_false /*b_is_zero*/,
    b_is_true /*b_is_positive*/, ret0 /*b_is_negative*/,
    ret1 /*b_is_integral*/, ret0 /*b_is_large*/,
  },
  {
    0 /*b_is_eq*/,0 /*b_is_ne*/,
    0 /*b_is_lt*/,0 /*b_is_gt*/, 0 /*b_is_le*/, 0 /*b_is_ge*/,
    0 /*b_cmp*/
  },
  {
    0 /*b_eq*/, 0 /*b_ne*/, 0 /*b_lt*/, 0 /*b_gt*/, 0 /*b_le*/, 0 /*b_ge*/,
  },
  {
    0 /*b_bitor*/, 0 /*b_bitxor*/, 0 /*b_bitand*/, 0 /*b_asr*/, 0 /*b_asl*/,
    0 /*b_add*/, 0 /*b_sub*/, 0 /*b_mul*/, 0 /*b_div*/, 0 /*b_mod*/
  },
  {
    0 /*b_lognot*/,
  },
  {
    0 /*b_plus*/, 0 /*b_minus*/, 0/*b_bitnot*/,
  },
  {
    0 /*b_inc*/, 0 /*b_dec*/
  }
};

static int fi_to_fo(const void *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = 0.0f;
  dd->f_im = *(const float *) s;
  return 0;
}
static int fi_to_do(const void *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = 0.0;
  dd->d_im = *(const float *) s;
  return 0;
}
static int fi_to_lo(const void *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = 0.0L;
  dd->l_im = *(const float *) s;
  return 0;
}

static const struct value_operations fimaginary_operations =
{
  { 
    f_to_b, f_to_c, f_to_c, f_to_uc, f_to_s, f_to_us,
    f_to_i, f_to_ui, f_to_l, f_to_ul, f_to_ll, f_to_ull,
    f_to_f, f_to_d, f_to_ld, 0 /*fi_to_qd*/,
    f_to_f, f_to_d, f_to_ld, 0 /*fi_to_qi*/,
    fi_to_fo, fi_to_do, fi_to_lo, 0 /*fi_to_qo*/,
  },
  { 0 },
  {
    f_is_true, f_is_false, f_is_zero,
    f_is_positive, f_is_negative,
    ret0 /*fi_is_integral*/, 0 /*fi_is_large*/
  },
  {
    f_is_eq, f_is_ne, f_is_lt, f_is_gt, f_is_le, f_is_ge, f_cmp
  },
  {
    f_eq, f_ne, f_lt, f_gt, f_le, f_ge,
  },
  {
    0 /*bitor*/, 0 /*bitxor*/, 0 /*bitand*/, 0 /*asr*/, 0 /*asl*/,
    f_add, f_sub, f_mul, f_div, 0 /*mod*/
  },
  {
    f_lognot,
  },
  {
    f_plus, f_minus, 0 /*bitnot*/,
  },
  {
    f_inc, f_dec
  }
};

static int di_to_fo(const void *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = 0.0f;
  dd->f_im = (float) *(const double *) s;
  return 0;
}
static int di_to_do(const void *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = 0.0;
  dd->d_im = *(const double *) s;
  return 0;
}
static int di_to_lo(const void *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = 0.0L;
  dd->l_im = *(const double *) s;
  return 0;
}

static const struct value_operations dimaginary_operations =
{
  { 
    d_to_b, d_to_c, d_to_c, d_to_uc, d_to_s, d_to_us,
    d_to_i, d_to_ui, d_to_l, d_to_ul, d_to_ll, d_to_ull,
    d_to_f, d_to_d, d_to_ld, 0 /*di_to_qd*/,
    d_to_f, d_to_d, d_to_ld, 0 /*di_to_qi*/,
    di_to_fo, di_to_do, di_to_lo, 0 /*di_to_qo*/,
  },
  { 0 },
  {
    d_is_true, d_is_false, d_is_zero,
    d_is_positive, d_is_negative,
    ret0 /*fi_is_integral*/, 0 /*fi_is_large*/
  },
  {
    d_is_eq, d_is_ne, d_is_lt, d_is_gt, d_is_le, d_is_ge, d_cmp
  },
  {
    d_eq, d_ne, d_lt, d_gt, d_le, d_ge,
  },
  {
    0 /*bitor*/, 0 /*bitxor*/, 0 /*bitand*/, 0 /*asr*/, 0 /*asl*/,
    d_add, d_sub, d_mul, d_div, 0 /*mod*/
  },
  {
    d_lognot,
  },
  {
    d_plus, d_minus, 0 /*bitnot*/,
  },
  {
    d_inc, d_dec
  }
};

static int li_to_fo(const void *s, void *d)
{
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = 0.0f;
  dd->f_im = (float) *(const long double *) s;
  return 0;
}
static int li_to_do(const void *s, void *d)
{
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = 0.0;
  dd->d_im = (double) *(const long double *) s;
  return 0;
}
static int li_to_lo(const void *s, void *d)
{
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = 0.0L;
  dd->l_im = *(const long double *) s;
  return 0;
}

static const struct value_operations limaginary_operations =
{
  { 
    ld_to_b, ld_to_c, ld_to_c, ld_to_uc, ld_to_s, ld_to_us,
    ld_to_i, ld_to_ui, ld_to_l, ld_to_ul, ld_to_ll, ld_to_ull,
    ld_to_f, ld_to_d, ld_to_ld, 0 /*li_to_qd*/,
    ld_to_f, ld_to_d, ld_to_ld, 0 /*li_to_qi*/,
    li_to_fo, li_to_do, li_to_lo, 0 /*li_to_qo*/,
  },
  { 0 },
  {
    ld_is_true, ld_is_false, ld_is_zero,
    ld_is_positive, ld_is_negative,
    ret0 /*li_is_integral*/, 0 /*li_is_large*/
  },
  {
    ld_is_eq, ld_is_ne, ld_is_lt, ld_is_gt, ld_is_le, ld_is_ge, ld_cmp
  },
  {
    ld_eq, ld_ne, ld_lt, ld_gt, ld_le, ld_ge,
  },
  {
    0 /*bitor*/, 0 /*bitxor*/, 0 /*bitand*/, 0 /*asr*/, 0 /*asl*/,
    ld_add, ld_sub, ld_mul, ld_div, 0 /*mod*/
  },
  {
    ld_lognot,
  },
  {
    ld_plus, ld_minus, 0 /*bitnot*/,
  },
  {
    ld_inc, ld_dec
  }
};

static int fo_to_b(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(unsigned char*) d = 0;
  if (ss->f_re || ss->f_im) *(unsigned char*) d = 1;
  return 0;
}
static int fo_to_c(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(signed char*) d = (signed char) ss->f_re;
  return 0;
}
static int fo_to_uc(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(unsigned char*) d = (unsigned char) ss->f_re;
  return 0;
}
static int fo_to_s(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(short*) d = (short) ss->f_re;
  return 0;
}
static int fo_to_us(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(unsigned short*) d = (unsigned short) ss->f_re;
  return 0;
}
static int fo_to_i(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(int*) d = (int) ss->f_re;
  return 0;
}
static int fo_to_ui(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(unsigned int*) d = (unsigned int) ss->f_re;
  return 0;
}
static int fo_to_ll(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(long long*) d = (long long) ss->f_re;
  return 0;
}
static int fo_to_ull(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(unsigned long long*) d = (unsigned long long) ss->f_re;
  return 0;
}
static int fo_to_f(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(float*) d = (float) ss->f_re;
  return 0;
}
static int fo_to_d(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(double*) d = (double) ss->f_re;
  return 0;
}
static int fo_to_ld(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(long double*) d = (long double) ss->f_re;
  return 0;
}
static int fo_to_fi(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(float*) d = (float) ss->f_im;
  return 0;
}
static int fo_to_di(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(double*) d = (double) ss->f_im;
  return 0;
}
static int fo_to_li(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(long double*) d = (long double) ss->f_im;
  return 0;
}
static int fo_to_fo(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = ss->f_re;
  dd->f_im = ss->f_im;
  return 0;
}
static int fo_to_do(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) ss->f_re;
  dd->d_im = (double) ss->f_im;
  return 0;
}
static int fo_to_lo(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) ss->f_re;
  dd->l_im = (long double) ss->f_im;
  return 0;
}

static int fo_is_true(const void *s)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  return ss->f_re || ss->f_im;
}
static int fo_is_false(const void *s)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  return !ss->f_re && !ss->f_im;
}

static int fo_is_eq(const void *s1, const void *s2)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  return ss1->f_re == ss2->f_re && ss1->f_im == ss2->f_im;
}
static int fo_is_ne(const void *s1, const void *s2)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  return ss1->f_re != ss2->f_re || ss1->f_im != ss2->f_im;
}

static int fo_eq(const void *s1, const void *s2, void *d)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  *(int*) d = ss1->f_re == ss2->f_re && ss1->f_im == ss2->f_im;
  return 0;
}
static int fo_ne(const void *s1, const void *s2, void *d)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  *(int*) d = ss1->f_re != ss2->f_re || ss1->f_im != ss2->f_im;
  return 0;
}

static int fo_add(const void *s1, const void *s2, void *d)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  struct r_fcomplex *dd = (struct r_fcomplex *) d;
  dd->f_re = ss1->f_re + ss2->f_re;
  dd->f_im = ss1->f_im + ss2->f_im;
  return 0;
}
static int fo_sub(const void *s1, const void *s2, void *d)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  struct r_fcomplex *dd = (struct r_fcomplex *) d;
  dd->f_re = ss1->f_re - ss2->f_re;
  dd->f_im = ss1->f_im - ss2->f_im;
  return 0;
}
static int fo_mul(const void *s1, const void *s2, void *d)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  struct r_fcomplex *dd = (struct r_fcomplex *) d;
  dd->f_re = ss1->f_re * ss2->f_re - ss1->f_im * ss2->f_im;
  dd->f_im = ss1->f_re * ss2->f_im + ss1->f_im * ss2->f_re;
  return 0;
}
static int fo_div(const void *s1, const void *s2, void *d)
{
  const struct r_fcomplex *ss1 = (const struct r_fcomplex*) s1;
  const struct r_fcomplex *ss2 = (const struct r_fcomplex*) s2;
  struct r_fcomplex *dd = (struct r_fcomplex *) d;
  float ff = sqrtf(ss2->f_re * ss2->f_re + ss2->f_im * ss2->f_im);
  dd->f_re = (ss1->f_re * ss2->f_re + ss1->f_im * ss2->f_im) / ff;
  dd->f_im = (-ss1->f_re * ss2->f_im + ss1->f_im * ss2->f_re) / ff;
  return 0;
}

static int fo_lognot(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  *(int*) d = ss->f_re == 0 && ss->f_im == 0;
  return 0;
}

static int fo_plus(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = ss->f_re;
  dd->f_im = ss->f_im;
  return 0;
}
static int fo_minus(const void *s, void *d)
{
  const struct r_fcomplex *ss = (const struct r_fcomplex*) s;
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = -ss->f_re;
  dd->f_im = -ss->f_im;
  return 0;
}

static const struct value_operations fcomplex_operations =
{
  { 
    fo_to_b, fo_to_c, fo_to_c, fo_to_uc, fo_to_s, fo_to_us,
    fo_to_i, fo_to_ui, fo_to_i, fo_to_ui, fo_to_ll, fo_to_ull,
    fo_to_f, fo_to_d, fo_to_ld, 0 /*fo_to_qd*/,
    fo_to_fi, fo_to_di, fo_to_li, 0 /*fo_to_qi*/,
    fo_to_fo, fo_to_do, fo_to_lo, 0 /*fo_to_qo*/,
  },
  { 0 },
  {
    fo_is_true, fo_is_false, fo_is_false /*is_zero*/,
    0 /*is_positive*/, 0 /*is_negative*/,
    ret0 /*is_integral*/, 0 /*is_large*/
  },
  {
    fo_is_eq, fo_is_ne, 0 /*is_lt*/, 0 /*is_gt*/, 0 /*is_le*/, 0 /*is_ge*/,
    0 /*cmp*/
  },
  {
    fo_eq, fo_ne, 0 /*lt*/, 0 /*gt*/, 0 /*le*/, 0 /*ge*/,
  },
  {
    0 /*bitor*/, 0 /*bitxor*/, 0 /*bitand*/, 0 /*asr*/, 0 /*asl*/,
    fo_add, fo_sub, fo_mul, fo_div, 0 /*mod*/
  },
  {
    fo_lognot,
  },
  {
    fo_plus, fo_minus, 0 /*bitnot*/,
  },
  {
    0 /*inc*/, 0 /*dec*/
  }
};

static int do_to_b(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(unsigned char*) d = 0;
  if (ss->d_re || ss->d_im) *(unsigned char*) d = 1;
  return 0;
}
static int do_to_c(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(signed char*) d = (signed char) ss->d_re;
  return 0;
}
static int do_to_uc(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(unsigned char*) d = (unsigned char) ss->d_re;
  return 0;
}
static int do_to_s(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(short*) d = (short) ss->d_re;
  return 0;
}
static int do_to_us(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(unsigned short*) d = (unsigned short) ss->d_re;
  return 0;
}
static int do_to_i(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(int*) d = (int) ss->d_re;
  return 0;
}
static int do_to_ui(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(unsigned int*) d = (unsigned int) ss->d_re;
  return 0;
}
static int do_to_ll(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(long long*) d = (long long) ss->d_re;
  return 0;
}
static int do_to_ull(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(unsigned long long*) d = (unsigned long long) ss->d_re;
  return 0;
}
static int do_to_f(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(float*) d = (float) ss->d_re;
  return 0;
}
static int do_to_d(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(double*) d = (double) ss->d_re;
  return 0;
}
static int do_to_ld(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(long double*) d = (long double) ss->d_re;
  return 0;
}
static int do_to_fi(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(float*) d = (float) ss->d_im;
  return 0;
}
static int do_to_di(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(double*) d = (double) ss->d_im;
  return 0;
}
static int do_to_li(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(long double*) d = (long double) ss->d_im;
  return 0;
}
static int do_to_fo(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = ss->d_re;
  dd->f_im = ss->d_im;
  return 0;
}
static int do_to_do(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = (double) ss->d_re;
  dd->d_im = (double) ss->d_im;
  return 0;
}
static int do_to_lo(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) ss->d_re;
  dd->l_im = (long double) ss->d_im;
  return 0;
}

static int do_is_true(const void *s)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  return ss->d_re || ss->d_im;
}
static int do_is_false(const void *s)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  return !ss->d_re && !ss->d_im;
}

static int do_is_eq(const void *s1, const void *s2)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  return ss1->d_re == ss2->d_re && ss1->d_im == ss2->d_im;
}
static int do_is_ne(const void *s1, const void *s2)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  return ss1->d_re != ss2->d_re || ss1->d_im != ss2->d_im;
}

static int do_eq(const void *s1, const void *s2, void *d)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  *(int*) d = ss1->d_re == ss2->d_re && ss1->d_im == ss2->d_im;
  return 0;
}
static int do_ne(const void *s1, const void *s2, void *d)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  *(int*) d = ss1->d_re != ss2->d_re || ss1->d_im != ss2->d_im;
  return 0;
}

static int do_add(const void *s1, const void *s2, void *d)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  struct r_dcomplex *dd = (struct r_dcomplex *) d;
  dd->d_re = ss1->d_re + ss2->d_re;
  dd->d_im = ss1->d_im + ss2->d_im;
  return 0;
}
static int do_sub(const void *s1, const void *s2, void *d)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  struct r_dcomplex *dd = (struct r_dcomplex *) d;
  dd->d_re = ss1->d_re - ss2->d_re;
  dd->d_im = ss1->d_im - ss2->d_im;
  return 0;
}
static int do_mul(const void *s1, const void *s2, void *d)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  struct r_dcomplex *dd = (struct r_dcomplex *) d;
  dd->d_re = ss1->d_re * ss2->d_re - ss1->d_im * ss2->d_im;
  dd->d_im = ss1->d_re * ss2->d_im + ss1->d_im * ss2->d_re;
  return 0;
}
static int do_div(const void *s1, const void *s2, void *d)
{
  const struct r_dcomplex *ss1 = (const struct r_dcomplex*) s1;
  const struct r_dcomplex *ss2 = (const struct r_dcomplex*) s2;
  struct r_dcomplex *dd = (struct r_dcomplex *) d;
  double ff = sqrt(ss2->d_re * ss2->d_re + ss2->d_im * ss2->d_im);
  dd->d_re = (ss1->d_re * ss2->d_re + ss1->d_im * ss2->d_im) / ff;
  dd->d_im = (-ss1->d_re * ss2->d_im + ss1->d_im * ss2->d_re) / ff;
  return 0;
}

static int do_lognot(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  *(int*) d = ss->d_re == 0 && ss->d_im == 0;
  return 0;
}

static int do_plus(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = ss->d_re;
  dd->d_im = ss->d_im;
  return 0;
}
static int do_minus(const void *s, void *d)
{
  const struct r_dcomplex *ss = (const struct r_dcomplex*) s;
  struct r_dcomplex *dd = (struct r_dcomplex*) d;
  dd->d_re = -ss->d_re;
  dd->d_im = -ss->d_im;
  return 0;
}

static const struct value_operations dcomplex_operations =
{
  { 
    do_to_b, do_to_c, do_to_c, do_to_uc, do_to_s, do_to_us,
    do_to_i, do_to_ui, do_to_i, do_to_ui, do_to_ll, do_to_ull,
    do_to_f, do_to_d, do_to_ld, 0 /*fo_to_qd*/,
    do_to_fi, do_to_di, do_to_li, 0 /*fo_to_qi*/,
    do_to_fo, do_to_do, do_to_lo, 0 /*fo_to_qo*/,
  },
  { 0 },
  {
    do_is_true, do_is_false, do_is_false /*is_zero*/,
    0 /*is_positive*/, 0 /*is_negative*/,
    ret0 /*is_integral*/, 0 /*is_large*/
  },
  {
    do_is_eq, do_is_ne, 0 /*is_lt*/, 0 /*is_gt*/, 0 /*is_le*/, 0 /*is_ge*/,
    0 /*cmp*/
  },
  {
    do_eq, do_ne, 0 /*lt*/, 0 /*gt*/, 0 /*le*/, 0 /*ge*/,
  },
  {
    0 /*bitor*/, 0 /*bitxor*/, 0 /*bitand*/, 0 /*asr*/, 0 /*asl*/,
    do_add, do_sub, do_mul, do_div, 0 /*mod*/
  },
  {
    do_lognot,
  },
  {
    do_plus, do_minus, 0 /*bitnot*/,
  },
  {
    0 /*inc*/, 0 /*dec*/
  }
};

static int lo_to_b(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(unsigned char*) d = 0;
  if (ss->l_re || ss->l_im) *(unsigned char*) d = 1;
  return 0;
}
static int lo_to_c(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(signed char*) d = (signed char) ss->l_re;
  return 0;
}
static int lo_to_uc(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(unsigned char*) d = (unsigned char) ss->l_re;
  return 0;
}
static int lo_to_s(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(short*) d = (short) ss->l_re;
  return 0;
}
static int lo_to_us(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(unsigned short*) d = (unsigned short) ss->l_re;
  return 0;
}
static int lo_to_i(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(int*) d = (int) ss->l_re;
  return 0;
}
static int lo_to_ui(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(unsigned int*) d = (unsigned int) ss->l_re;
  return 0;
}
static int lo_to_ll(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(long long*) d = (long long) ss->l_re;
  return 0;
}
static int lo_to_ull(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(unsigned long long*) d = (unsigned long long) ss->l_re;
  return 0;
}
static int lo_to_f(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(float*) d = (float) ss->l_re;
  return 0;
}
static int lo_to_d(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(double*) d = (double) ss->l_re;
  return 0;
}
static int lo_to_ld(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(long double*) d = (long double) ss->l_re;
  return 0;
}
static int lo_to_fi(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(float*) d = (float) ss->l_im;
  return 0;
}
static int lo_to_di(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(double*) d = (double) ss->l_im;
  return 0;
}
static int lo_to_li(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(long double*) d = (long double) ss->l_im;
  return 0;
}
static int lo_to_fo(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  struct r_fcomplex *dd = (struct r_fcomplex*) d;
  dd->f_re = ss->l_re;
  dd->f_im = ss->l_im;
  return 0;
}
static int lo_to_do(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (double) ss->l_re;
  dd->l_im = (double) ss->l_im;
  return 0;
}
static int lo_to_lo(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = (long double) ss->l_re;
  dd->l_im = (long double) ss->l_im;
  return 0;
}

static int lo_is_true(const void *s)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  return ss->l_re || ss->l_im;
}
static int lo_is_false(const void *s)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  return !ss->l_re && !ss->l_im;
}

static int lo_is_eq(const void *s1, const void *s2)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  return ss1->l_re == ss2->l_re && ss1->l_im == ss2->l_im;
}
static int lo_is_ne(const void *s1, const void *s2)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  return ss1->l_re != ss2->l_re || ss1->l_im != ss2->l_im;
}

static int lo_eq(const void *s1, const void *s2, void *d)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  *(int*) d = ss1->l_re == ss2->l_re && ss1->l_im == ss2->l_im;
  return 0;
}
static int lo_ne(const void *s1, const void *s2, void *d)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  *(int*) d = ss1->l_re != ss2->l_re || ss1->l_im != ss2->l_im;
  return 0;
}

static int lo_add(const void *s1, const void *s2, void *d)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  struct r_lcomplex *dd = (struct r_lcomplex *) d;
  dd->l_re = ss1->l_re + ss2->l_re;
  dd->l_im = ss1->l_im + ss2->l_im;
  return 0;
}
static int lo_sub(const void *s1, const void *s2, void *d)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  struct r_lcomplex *dd = (struct r_lcomplex *) d;
  dd->l_re = ss1->l_re - ss2->l_re;
  dd->l_im = ss1->l_im - ss2->l_im;
  return 0;
}
static int lo_mul(const void *s1, const void *s2, void *d)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  struct r_lcomplex *dd = (struct r_lcomplex *) d;
  dd->l_re = ss1->l_re * ss2->l_re - ss1->l_im * ss2->l_im;
  dd->l_im = ss1->l_re * ss2->l_im + ss1->l_im * ss2->l_re;
  return 0;
}
static int lo_div(const void *s1, const void *s2, void *d)
{
  const struct r_lcomplex *ss1 = (const struct r_lcomplex*) s1;
  const struct r_lcomplex *ss2 = (const struct r_lcomplex*) s2;
  struct r_lcomplex *dd = (struct r_lcomplex *) d;
  long double ff = sqrtl(ss2->l_re * ss2->l_re + ss2->l_im * ss2->l_im);
  dd->l_re = (ss1->l_re * ss2->l_re + ss1->l_im * ss2->l_im) / ff;
  dd->l_im = (-ss1->l_re * ss2->l_im + ss1->l_im * ss2->l_re) / ff;
  return 0;
}

static int lo_lognot(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  *(int*) d = ss->l_re == 0 && ss->l_im == 0;
  return 0;
}

static int lo_plus(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = ss->l_re;
  dd->l_im = ss->l_im;
  return 0;
}
static int lo_minus(const void *s, void *d)
{
  const struct r_lcomplex *ss = (const struct r_lcomplex*) s;
  struct r_lcomplex *dd = (struct r_lcomplex*) d;
  dd->l_re = -ss->l_re;
  dd->l_im = -ss->l_im;
  return 0;
}

static const struct value_operations lcomplex_operations =
{
  { 
    lo_to_b, lo_to_c, lo_to_c, lo_to_uc, lo_to_s, lo_to_us,
    lo_to_i, lo_to_ui, lo_to_i, lo_to_ui, lo_to_ll, lo_to_ull,
    lo_to_f, lo_to_d, lo_to_ld, 0 /*fo_to_qd*/,
    lo_to_fi, lo_to_di, lo_to_li, 0 /*fo_to_qi*/,
    lo_to_fo, lo_to_do, lo_to_lo, 0 /*fo_to_qo*/,
  },
  { 0 },
  {
    lo_is_true, lo_is_false, lo_is_false /*is_zero*/,
    0 /*is_positive*/, 0 /*is_negative*/,
    ret0 /*is_integral*/, 0 /*is_large*/
  },
  {
    lo_is_eq, lo_is_ne, 0 /*is_lt*/, 0 /*is_gt*/, 0 /*is_le*/, 0 /*is_ge*/,
    0 /*cmp*/
  },
  {
    lo_eq, lo_ne, 0 /*lt*/, 0 /*gt*/, 0 /*le*/, 0 /*ge*/,
  },
  {
    0 /*bitor*/, 0 /*bitxor*/, 0 /*bitand*/, 0 /*asr*/, 0 /*asl*/,
    lo_add, lo_sub, lo_mul, lo_div, 0 /*mod*/
  },
  {
    lo_lognot,
  },
  {
    lo_plus, lo_minus, 0 /*bitnot*/,
  },
  {
    0 /*inc*/, 0 /*dec*/
  }
};

static struct value_operations const *const c_type_operations[C_TYPES_TOTAL] = 
  {
    &bool_operations,           /* C_BOOL */
    &char_operations,           /* C_CHAR */
    &char_operations,           /* C_SCHAR */
    &uchar_operations,          /* C_UCHAR */
    &short_operations,          /* C_SHORT */
    &ushort_operations,         /* C_USHORT */
    &int_operations,            /* C_INT */
    &uint_operations,           /* C_UINT */
    &int_operations,            /* C_LONG */
    &uint_operations,           /* C_ULONG */
    &llong_operations,          /* C_LLONG */
    &ullong_operations,         /* C_ULLONG */
    &float_operations,          /* C_FLOAT */
    &double_operations,         /* C_DOUBLE */
    &ldouble_operations,        /* C_LDOUBLE */
    0,                          /* C_QDOUBLE */
    &fimaginary_operations,     /* C_FIMAGINARY */
    &dimaginary_operations,     /* C_DIMAGINARY */
    &limaginary_operations,     /* C_LIMAGINARY */
    0,                          /* C_QIMAGINARY */
    &fcomplex_operations,       /* C_FCOMPLEX */
    &dcomplex_operations,       /* C_DCOMPLEX */
    &lcomplex_operations,       /* C_LCOMPLEX */
    0,                          /* C_QCOMPLEX */
    0,                          /* C_VOID */
    &pointer_operations,        /* C_VA_LIST */
    &pointer_operations,        /* C_POINTER */
  };

static p_generic_f_t
check_type_operations(int t, int cat, int op)
{
  int t2;
  struct value_operations_access *pva = 0;
  int op2;
  p_generic_f_t *fv;
  

  ASSERT(t >= C_FIRST_ARITH && t < C_TYPES_TOTAL);
  ASSERT(cat >= VO_OP_TO_TYPE && cat <= VO_OP_UPDATE);

  t2 = t - C_FIRST_ARITH;
  pva = &value_operations_access_table[cat];
  ASSERT(op >= pva->first && op < pva->afterlast);
  op2 = op - pva->first;

  if (!c_type_operations[t2]) {
    SWERR(("c_type_operations for %d (%s) not implemented",
           t, c_builtin_str(t)));
  }
  fv = XPDEREF(p_generic_f_t,c_type_operations[t2],pva->offset);
  if (!fv[op2]) {
    SWERR(("unimplemented: %d(%s), %d(%s), %d(%s)",
           t, c_builtin_str(t), cat, VO_OP_to_str(cat), op, pva->verb_op(op)));
  }
  return fv[op2];
}

int
vo_run_cast(int ts, const void *pvs, int td, void *pvd)
{
  p_to_type_f_t f = 0;
  f = (p_to_type_f_t) check_type_operations(ts, VO_OP_TO_TYPE, td);
  return (*f)(pvs, pvd);
}
int
vo_run_range_check(int ts, int td, const void *pvs)
{
  p_fits_type_f_t f = 0;
  f = (p_fits_type_f_t) check_type_operations(ts, VO_OP_FITS_TYPE, td);
  return (*f)(pvs);
}
int
vo_run_predicate(int it, int code, const void *pv)
{
  p_predicate_f_t f = 0;
  f = (p_predicate_f_t) check_type_operations(it, VO_OP_PREDICATE, code);
  return (*f)(pv);
}
int
vo_run_relation(int it, int code, const void *s1, const void *s2)
{
  p_relation_f_t f = 0;
  f = (p_relation_f_t) check_type_operations(it, VO_OP_RELATION, code);
  return (*f)(s1, s2);
}
int
vo_run_binary(int it, int code, const void *s1, const void *s2, void *d)
{
  p_binary_f_t f = 0;
  f = (p_binary_f_t) check_type_operations(it, VO_OP_BINARY, code);
  return (*f)(s1, s2, d);
}
int
vo_run_logic_binary(int it, int code, const void *s1, const void *s2, void *d)
{
  p_logic_binary_f_t f = 0;
  f = (p_logic_binary_f_t) check_type_operations(it, VO_OP_LOGIC_BINARY, code);
  return (*f)(s1, s2, d);
}
int
vo_run_unary(int it, int code, const void *s1, void *d)
{
  p_unary_f_t f = 0;
  f = (p_unary_f_t) check_type_operations(it, VO_OP_UNARY, code);
  return (*f)(s1, d);
}
int
vo_run_logic_unary(int it, int code, const void *s1, void *d)
{
  p_logic_unary_f_t f = 0;
  f = (p_logic_unary_f_t) check_type_operations(it, VO_OP_LOGIC_UNARY, code);
  return (*f)(s1, d);
}
int
vo_run_update(int it, int code, void *d)
{
  p_update_f_t f = 0;
  f = (p_update_f_t) check_type_operations(it, VO_OP_UPDATE, code);
  return (*f)(d);
}
