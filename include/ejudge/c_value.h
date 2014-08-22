/* -*- mode:c -*- */
/* $Id$ */

#ifndef __REUSE_C_VALUE_H__
#define __REUSE_C_VALUE_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/integral.h"

/* C Built-in types */
typedef enum c_builtin_t
{
  C_FIRST_ARITH = 1,
  C_FIRST_INT = C_FIRST_ARITH,
  C_BOOL = C_FIRST_INT,         /* 1: ISO C99 _Bool */
  C_CHAR,                       /* 2: signed 8-bit integral type */
  C_SCHAR,                      /* 3 */
  C_UCHAR,                      /* 4 */
  C_SHORT,                      /* 5 */
  C_USHORT,                     /* 6 */
  C_INT,                        /* 7 */
  C_UINT,                       /* 8 */
  C_LONG,                       /* 9 */
  C_ULONG,                      /* 10 */
  C_LLONG,                      /* 11 */
  C_ULLONG,                     /* 12 */
  C_LAST_INT = C_ULLONG,
  C_FIRST_FLT,
  C_FLOAT = C_FIRST_FLT,        /* 13 */
  C_DOUBLE,                     /* 14 */
  C_LDOUBLE,                    /* 15 */
  C_QDOUBLE,                    /* 16: quad double: future extension */
  C_FIMAGINARY,                 /* 17: ISO C99 float _Imaginary */
  C_DIMAGINARY,                 /* 18: ISO C99 double _Imaginary */
  C_LIMAGINARY,                 /* 19: ISO C99 long double _Imaginary */
  C_QIMAGINARY,                 /* 20: future extension */
  C_FCOMPLEX,                   /* 21: ISO C99 float _Complex */
  C_DCOMPLEX,                   /* 22: ISO C99 double _Complex */
  C_LCOMPLEX,                   /* 23: ISO C99 long double _Complex */
  C_QCOMPLEX,                   /* 24: future extension */
  C_LAST_FLT = C_QCOMPLEX,
  C_LAST_ARITH = C_LAST_FLT,
  C_VOID,                       /* 25 */
  C_VA_LIST,                    /* 26 */
  C_POINTER,                    /* 27 */
  C_TYPES_TOTAL
} c_builtin_t;

struct r_fcomplex
{
  float f_re, f_im;
};
struct r_dcomplex
{
  double d_re, d_im;
};
struct r_lcomplex
{
  long double l_re, l_im;
};

union s_cvalue
{
  unsigned char       ct_bool;
  char                ct_char;
  signed char         ct_schar;
  unsigned char       ct_uchar;
  short               ct_short;
  unsigned short      ct_ushort;
  int                 ct_int;
  unsigned int        ct_uint;
  long                ct_lint;
  unsigned long       ct_ulint;
#if R_HAS_INT64 - 0 == 1
  rllong_t            ct_llint;
  rullong_t           ct_ullint;
#endif /* R_HAS_INT64 */
  float               ct_float;
  double              ct_double;
  long double         ct_ldouble;
  /* long long double ct_qdouble; */
  float               ct_fimaginary;
  double              ct_dimaginary;
  long double         ct_limaginary;
  /* long long double ct_qimaginary; */
  struct r_fcomplex   ct_fcomplex;
  struct r_dcomplex   ct_dcomplex;
  struct r_lcomplex   ct_lcomplex;
  /* struct r_qcomplex ct_qcomplex; */
};

typedef struct s_c_value
{
  c_builtin_t tag;
  union s_cvalue v;
} c_value_t, *pc_value_t;

typedef enum c_operation_t
{
  COP_NONE = 0,                 /* 0  */ /* Error? */

  COP_ASSIGN,                   /*  1 */ /* '=' */
  COP_MULASSIGN,                /*  2 */ /* '*=' */
  COP_DIVASSIGN,                /*  3 */ /* '/=' */
  COP_MODASSIGN,                /*  4 */ /* '%=' */
  COP_ADDASSIGN,                /*  5 */ /* '+=' */
  COP_SUBASSIGN,                /*  6 */ /* '-=' */
  COP_ASLASSIGN,                /*  7 */ /* '<<=' */
  COP_ASRASSIGN,                /*  8 */ /* '>>=' */
  COP_ANDASSIGN,                /*  9 */ /* '&=' */
  COP_XORASSIGN,                /* 10 */ /* '^=' */
  COP_ORASSIGN,                 /* 11 */ /* '|=' */

  COP_COMMA,                    /* 12 */ /* ',' */

  COP_COND,                     /* 13 */ /* '?' ':' */

  COP_LOGOR,                    /* 14 */ /* '||' */
  COP_LOGAND,                   /* 15 */ /* '&&' */

  COP_BITOR,                    /* 16 */ /* '|' */
  COP_BITXOR,                   /* 17 */ /* '^' */
  COP_BITAND,                   /* 18 */ /* '&' */

  COP_EQ,                       /* 19 */ /* '==' */
  COP_NE,                       /* 20 */ /* '!=' */
  COP_LT,                       /* 21 */ /* '<' */
  COP_GT,                       /* 22 */ /* '>' */
  COP_LE,                       /* 23 */ /* '<=' */
  COP_GE,                       /* 24 */ /* '>=' */

  COP_ASR,                      /* 25 */ /* '>>' */
  COP_ASL,                      /* 26 */ /* '<<' */

  COP_ADD,                      /* 27 */ /* '+' */
  COP_SUB,                      /* 28 */ /* '-' */
  
  COP_MUL,                      /* 29 */ /* '*' */
  COP_DIV,                      /* 30 */ /* '/' */
  COP_MOD,                      /* 31 */ /* '%' */

  COP_CAST,                     /* 32 */ /* '(' type_name ')' */

  COP_PREINC,                   /* 33 */ /* '++' */
  COP_PREDEC,                   /* 34 */ /* '--' */
  COP_SIZEOF,                   /* 35 */ /* 'sizeof' '(' type_name ')' */
  COP_DEREF,                    /* 36 */ /* '*' */
  COP_ADDRESS,                  /* 37 */ /* '&' */
  COP_PLUS,                     /* 38 */ /* '+' */
  COP_MINUS,                    /* 39 */ /* '-' */
  COP_BITNOT,                   /* 40 */ /* '~' */
  COP_LOGNOT,                   /* 41 */ /* '!' */
  COP_POSTINC,                  /* 42 */ /* '++' */
  COP_POSTDEC,                  /* 43 */ /* '--' */

  COP_FIELD,                    /* 44 */ /* '.' */
  COP_FIELDREF,                 /* 45 */ /* '->' */

  COP_LAST
} c_operation_t;

void         c_value_print(/* (c_value_t *, FILE *) */);
int          c_value_sprint(char *, c_value_t *);
unsigned int c_value_size(c_value_t *);

int c_value_cast(c_value_t *, int, c_value_t *);
int c_value_balanced_type(c_value_t *, c_value_t *);

int c_value_operation(void *, int, c_value_t *, c_value_t *,
                      c_value_t *, c_value_t *);

int c_value_fits(c_value_t *, int);
int c_value_compare(c_value_t *, c_value_t *);

int c_value_is_false(c_value_t *);
int c_value_is_true(c_value_t *);
int c_value_is_zero(c_value_t *);
int c_value_is_positive(c_value_t *);
int c_value_is_negative(c_value_t *);
int c_value_is_integral(c_value_t *);
int c_value_is_large(c_value_t *);

int c_get_balanced_type(int, int, int);
int c_is_unsigned_type(int);

void c_value_enable_float_arith(void);

char const *c_builtin_str(int);
char const *c_operation_str(int);

#endif /* __REUSE_C_VALUE_H__ */
