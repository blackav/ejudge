/* -*- mode: C -*- */
/* $Id$ */

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

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/c_value.h"
#include "ejudge/c_value_ops.h"
#include "ejudge/logger.h"
#include "ejudge/positions.h"
#include "ejudge/xalloc.h"
#include "ejudge/errors.h"

#include <string.h>

static char const * const Builtin_Names[]=
{
  "(none)",
  /*[C_BOOL]*/    "_Bool",
  /*[C_CHAR]*/    "char",
  /*[C_SCHAR]*/   "signed char",
  /*[C_UCHAR]*/   "unsigned char",
  /*[C_SHORT]*/   "short",
  /*[C_USHORT]*/  "unsigned short",
  /*[C_INT]*/     "int",
  /*[C_UINT]*/    "unsigned",
  /*[C_LONG]*/    "long",
  /*[C_ULONG]*/   "unsigned long",
  /*[C_LLONG]*/   "long long",
  /*[C_ULLONG]*/  "unsigned long long",
  /*[C_FLOAT]*/   "float",
  /*[C_DOUBLE]*/  "double",
  /*[C_LDOUBLE]*/ "long double",
  /*[C_QDOUBLE]*/ "long long double",
  /*[C_FIMAGINARY]*/ "float _Imaginary",
  /*[C_DIMAGINARY]*/ "double _Imaginary",
  /*[C_LIMAGINARY]*/ "long double _Imaginary",
  /*[C_QIMAGINARY]*/ "long long double _Imaginary",
  /*[C_FCOMPLEX]*/ "float _Complex",
  /*[C_DCOMPLEX]*/ "double _Complex",
  /*[C_LCOMPLEX]*/ "long double _Complex",
  /*[C_QCOMPLEX]*/ "long long double _Complex",
  /*[C_VOID]*/    "void",
  /*[C_VA_LIST]*/ "va_list"
};

const char *
c_builtin_str(int t)
{
  ASSERT(t >= C_FIRST_ARITH && t < C_TYPES_TOTAL);
  return Builtin_Names[t];
}

void
c_value_print(c_value_t *val, FILE *f)
{
  int tag = val->tag;
  ASSERT(tag >= C_FIRST_ARITH && tag <= C_LAST_ARITH);
  switch (tag)
    {
    case C_BOOL:
      fprintf(f, "(%s)%d", Builtin_Names[tag], val->v.ct_bool);
      break;
    case C_CHAR:
      fprintf(f, "(%s)%d", Builtin_Names[tag], val->v.ct_char);
      break;
    case C_SCHAR:
      fprintf(f, "(%s)%d", Builtin_Names[tag], val->v.ct_schar);
      break;
    case C_UCHAR:
      fprintf(f,"(%s)%u", Builtin_Names[tag], val->v.ct_uchar);
      break;
    case C_SHORT:
      fprintf(f, "(%s)%d", Builtin_Names[tag], val->v.ct_short);
      break;
    case C_USHORT:
      fprintf(f, "(%s)%u", Builtin_Names[tag], val->v.ct_ushort);
      break;
    case C_INT:
      fprintf(f, "(%s)%d", Builtin_Names[tag], val->v.ct_int);
      break;
    case C_UINT:
      fprintf(f, "(%s)%u", Builtin_Names[tag], val->v.ct_uint);
      break;
    case C_LONG:
      fprintf(f, "(%s)%ld", Builtin_Names[tag], val->v.ct_lint);
      break;
    case C_ULONG:
      fprintf(f, "(%s)%lu", Builtin_Names[tag], val->v.ct_ulint);
      break;
    case C_LLONG:
      fprintf(f, "(%s)", Builtin_Names[tag]);
      break;
    case C_ULLONG:
      fprintf(f, "(%s)", Builtin_Names[tag]);
      break;
    case C_FLOAT:
      fprintf(f, "(%s)", Builtin_Names[tag]);
      break;
    case C_DOUBLE:
      fprintf(f, "(%s)", Builtin_Names[tag]);
      break;
    case C_LDOUBLE:
      fprintf(f, "(%s)", Builtin_Names[tag]);
      break;
    case C_QDOUBLE:
    case C_FIMAGINARY:
    case C_DIMAGINARY:
    case C_LIMAGINARY:
    case C_QIMAGINARY:
    case C_FCOMPLEX:
    case C_DCOMPLEX:
    case C_LCOMPLEX:
    case C_QCOMPLEX:
      fprintf(f, "(%s)", Builtin_Names[tag]);
      break;
    default:
      SWERR(("bad val->tag"));
    }
}

  int
c_value_sprint(char *buf, c_value_t *val)
{
  int tag = val->tag;
  int res = 0;

  ASSERT(tag >= C_FIRST_ARITH && tag <= C_LAST_ARITH);
  switch (tag)
    {
    case C_BOOL:
      res = sprintf(buf, "(%s)%d", Builtin_Names[tag], val->v.ct_bool);
      break;
    case C_CHAR:
      res = sprintf(buf, "(%s)%d", Builtin_Names[tag], val->v.ct_char);
      break;
    case C_SCHAR:
      res = sprintf(buf, "(%s)%d", Builtin_Names[tag], val->v.ct_schar);
      break;
    case C_UCHAR:
      res = sprintf(buf, "(%s)%u", Builtin_Names[tag], val->v.ct_uchar);
      break;
    case C_SHORT:
      res = sprintf(buf, "(%s)%d", Builtin_Names[tag], val->v.ct_short);
      break;
    case C_USHORT:
      res = sprintf(buf, "(%s)%u", Builtin_Names[tag], val->v.ct_ushort);
      break;
    case C_INT:
      res = sprintf(buf, "(%s)%d", Builtin_Names[tag], val->v.ct_int);
      break;
    case C_UINT:
      res = sprintf(buf, "(%s)%u", Builtin_Names[tag], val->v.ct_uint);
      break;
    case C_LONG:
      res = sprintf(buf, "(%s)%ld", Builtin_Names[tag], val->v.ct_lint);
      break;
    case C_ULONG:
      res = sprintf(buf, "(%s)%lu", Builtin_Names[tag], val->v.ct_ulint);
      break;
    case C_LLONG:
      res = sprintf(buf, "(%s)", Builtin_Names[tag]);
      break;
    case C_ULLONG:
      res = sprintf(buf, "(%s)", Builtin_Names[tag]);
      break;
    case C_FLOAT:
      res = sprintf(buf, "(%s)", Builtin_Names[tag]);
      break;
    case C_DOUBLE:
      res = sprintf(buf, "(%s)", Builtin_Names[tag]);
      break;
    case C_LDOUBLE:
      res = sprintf(buf, "(%s)", Builtin_Names[tag]);
      break;
    case C_QDOUBLE:
    case C_FIMAGINARY:
    case C_DIMAGINARY:
    case C_LIMAGINARY:
    case C_QIMAGINARY:
    case C_FCOMPLEX:
    case C_DCOMPLEX:
    case C_LCOMPLEX:
    case C_QCOMPLEX:
      res = sprintf(buf, "(%s)", Builtin_Names[tag]);
      break;
    default:
      SWERR(("bad val->tag"));
    }

  return res;
}

int
c_is_unsigned_type(int idx)
{
  switch (idx) {
  case C_CHAR:
  case C_SCHAR:
  case C_SHORT:
  case C_INT:
  case C_LONG:
  case C_LLONG:
    return 0;
  case C_BOOL:
  case C_UCHAR:
  case C_USHORT:
  case C_UINT:
  case C_ULONG:
  case C_ULLONG:
    return 1;
  default:
    SWERR(("invalid argument: %d", idx));
  }
}

unsigned int
c_value_size(c_value_t *val)
{
  return sizeof(c_value_t);
}

#define qB  C_BOOL
#define qC  C_CHAR
#define qSC C_SCHAR
#define qUC C_UCHAR
#define qS  C_SHORT
#define qUS C_USHORT
#define qI  C_INT
#define qUI C_UINT
#define qL  C_LONG
#define qUL C_ULONG
#define qQ  C_LLONG
#define qUQ C_ULLONG
#define qF  C_FLOAT
#define qD  C_DOUBLE
#define qE  C_LDOUBLE
#define qG  C_QDOUBLE
#define qFM C_FIMAGINARY
#define qDM C_DIMAGINARY
#define qLM C_LIMAGINARY
#define qQM C_QIMAGINARY
#define qFO C_FCOMPLEX
#define qDO C_DCOMPLEX
#define qLO C_LCOMPLEX
#define qQO C_QCOMPLEX

/* balancing table for +, -, *, /, >=, <=, >, <, ==, != */
static signed char balance_table_0[C_LAST_ARITH][C_LAST_ARITH] =
{
  /*      B   C   SC  UC  S   US, I   UI  L   UL  Q   UQ  F   D   E   G   FM  DM  LM  QM  FO  DO  LO  QO   */
  /* B*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* C*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*SC*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*UC*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* S*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*US*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* I*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*UI*/{ qUI,qUI,qUI,qUI,qUI,qUI,qUI,qUI,qUL,qUL,qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* L*/{ qL, qL, qL, qL, qL, qL, qL,qUL, qL,qUL, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*UL*/{ qUL,qUL,qUL,qUL,qUL,qUL,qUL,qUL,qUL,qUL,qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* Q*/{ qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ,qUQ, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*UQ*/{ qUL,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* F*/{ qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qE, qG, qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /* D*/{ qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qD, qE, qG, qDO,qDO,qLO,qQO,qDO,qDO,qLO,qQO },
  /* E*/{ qE, qE, qE, qE, qE, qE, qE, qE, qE, qE, qE, qE, qE, qE, qE, qG, qLO,qLO,qLO,qQO,qLO,qLO,qLO,qQO },
  /* G*/{ qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qG, qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO },
  /*FM*/{ qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qDO,qLO,qQO,qFM,qDM,qLM,qQM,qFO,qDO,qLO,qQO },
  /*DM*/{ qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qLO,qQO,qDM,qDM,qLM,qQM,qDO,qDO,qLO,qQO },
  /*LM*/{ qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qQO,qLM,qLM,qLM,qQM,qLO,qLO,qLO,qQO },
  /*QM*/{ qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQM,qQM,qQM,qQM,qQO,qQO,qQO,qQO },
  /*FO*/{ qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO,qFO,qDO,qLO,qQO },
  /*DO*/{ qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qDO,qLO,qQO,qDO,qDO,qLO,qQO,qDO,qDO,qLO,qQO },
  /*LO*/{ qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qLO,qQO,qLO,qLO,qLO,qQO,qLO,qLO,qLO,qQO },
  /*QO*/{ qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO,qQO },
};

/* balancing table for <<, >>, &, |, ^, % */
static signed char balance_table_1[C_LAST_ARITH][C_LAST_ARITH] =
{
  /*      B   C   SC  UC  S   US, I   UI  L   UL  Q   UQ  F   D   E   G   FM  DM  LM  QM  FO  DO  LO  QO   */
  /* B*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* C*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*SC*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*UC*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* S*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*US*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* I*/{ qI, qI, qI, qI, qI, qI, qI,qUI, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*UI*/{ qUI,qUI,qUI,qUI,qUI,qUI,qUI,qUI,qUL,qUL,qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* L*/{ qL, qL, qL, qL, qL, qL, qL,qUL, qL,qUL, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*UL*/{ qUL,qUL,qUL,qUL,qUL,qUL,qUL,qUL,qUL,qUL,qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* Q*/{ qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ, qQ,qUQ, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*UQ*/{ qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,qUQ,-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* F*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* D*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* E*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /* G*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*FM*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*DM*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*LM*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*QM*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*FO*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*DO*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*LO*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  /*QO*/{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
};

/* "balancing" table for pointer assignments */
static signed char balance_table_2[C_LAST_ARITH][C_LAST_ARITH] =
{
  /*      B   C   SC  UC  S   US, I   UI  L   UL  Q   UQ  F   D   E   G   FM  DM  LM  QM  FO  DO  LO  QO   */
  /* B*/{  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* C*/{  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*SC*/{  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UC*/{  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* S*/{  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*US*/{  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* I*/{  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UI*/{  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* L*/{  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UL*/{  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* Q*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UQ*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* F*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* D*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* E*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* G*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*FM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0 },
  /*DM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0 },
  /*LM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0 },
  /*QM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0 },
  /*FO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0 },
  /*DO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0 },
  /*LO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0 },
  /*QO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1 },
};

/* "balancing" table for pointer comparisons */
static signed char balance_table_3[C_LAST_ARITH][C_LAST_ARITH] =
{
  /*      B   C   CS  UC  S   US, I   UI  L   UL  Q   UQ  F   D   E   G   FM  DM  LM  QM  FO  DO  LO  QO   */
  /* B*/{  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* C*/{  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*SC*/{  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UC*/{  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* S*/{  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*US*/{  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* I*/{  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UI*/{  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* L*/{  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UL*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* Q*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*UQ*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* F*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* D*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* E*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
  /* G*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  0 },
  /*FM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0 },
  /*DM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0 },
  /*LM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0 },
  /*QM*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0 },
  /*FO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0 },
  /*DO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0,  0 },
  /*LO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  0 },
  /*QO*/{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1 },
};

static signed char (*balance_tables[4])[C_LAST_ARITH][C_LAST_ARITH] =
{
  &balance_table_0,
  &balance_table_1,
  &balance_table_2,
  &balance_table_3
};

int
c_get_balanced_type(int n, int t1, int t2)
{
  ASSERT(t1 >= C_FIRST_ARITH && t1 <= C_LAST_ARITH);
  ASSERT(t2 >= C_FIRST_ARITH && t2 <= C_LAST_ARITH);
  ASSERT(n >= 0 && n < 4);

  return (*balance_tables[n])[t1 - C_FIRST_ARITH][t2 - C_FIRST_ARITH];
}

int
c_value_balanced_type(c_value_t *pv1, c_value_t *pv2)
{
  int newtype;

  newtype = c_get_balanced_type(0, pv1->tag, pv2->tag);
  ASSERT(newtype >= C_FIRST_ARITH && newtype <= C_LAST_ARITH);
  return newtype;
}

void
c_value_enable_float_arith(void)
{
  int i;

  for (i = C_BOOL; i <= C_FLOAT; i++) {
    balance_table_0[i - C_FIRST_ARITH][C_FLOAT - C_FIRST_ARITH] = C_FLOAT;
    balance_table_0[C_FLOAT - C_FIRST_ARITH][i - C_FIRST_ARITH] = C_FLOAT;
  }
}

int
c_value_cast(c_value_t *val, int type, c_value_t *out)
{
  int r;

  ASSERT(val);
  ASSERT(out);

  if (val == out) {
    if (val->tag == type) return 0;
    {
      c_value_t tout;
      memset(&tout, 0, sizeof(tout));
      r = vo_run_cast(val->tag, &val->v, type, &tout.v);
      if (r < 0) return r;
      tout.tag = type;
      memmove(out, &tout, sizeof(tout));
      return 0;
    }
  }

  XMEMZERO(out, 1);
  r = vo_run_cast(val->tag, &val->v, type, &out->v);
  if (r < 0) return r;
  out->tag = type;
  return 0;
}

int
c_value_fits(c_value_t *val, int type)
{
  ASSERT(val);
  return vo_run_range_check(val->tag, type, &val->v);
}

int
c_value_is_false(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_FALSE, &pv->v);
}
int
c_value_is_true(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_TRUE, &pv->v);
}
int
c_value_is_zero(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_ZERO, &pv->v);
}
int
c_value_is_positive(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_POSITIVE, &pv->v);
}
int
c_value_is_negative(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_NEGATIVE, &pv->v);
}
int
c_value_is_integral(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_INTEGRAL, &pv->v);
}
int
c_value_is_large(c_value_t *pv)
{
  return vo_run_predicate(pv->tag, VO_IS_LARGE, &pv->v);
}

int
c_value_compare(c_value_t *pv1, c_value_t *pv2)
{
  ASSERT(pv1);
  ASSERT(pv2);
  ASSERT(pv1->tag == pv2->tag);
  return vo_run_relation(pv1->tag, VO_CMP, &pv1->v, &pv2->v);
}

int
c_value_operation(void *vpos, int opcode,
                  c_value_t *pv1, c_value_t *pv2, c_value_t *pv3,
                  c_value_t *pres)
{
  tPosition *ppos = (tPosition*) vpos;
  c_value_t tv1, tv2;
  int cl;
  int bt, op;
  int r;

  XMEMZERO(pres, 1);
  XMEMZERO(&tv1, 1);
  XMEMZERO(&tv2, 1);

  ASSERT(opcode > 0 && opcode < COP_LAST);
  cl = c_operation_to_VO_OP(opcode);

  switch (cl) {
  case 0: break;
  case VO_OP_BINARY:
    if ((bt = c_value_balanced_type(pv1, pv2)) < 0) return bt;
    op = c_operation_to_VO_BIN(opcode);
    if ((r = c_value_cast(pv1, bt, &tv1)) < 0) return r;
    if ((r = c_value_cast(pv2, bt, &tv2)) < 0) return r;
    if ((r = vo_run_binary(bt, op, &tv1.v, &tv2.v, &pres->v)) < 0) return r;
    pres->tag = bt;
    return 0;

  case VO_OP_LOGIC_BINARY:
    if ((bt = c_value_balanced_type(pv1, pv2)) < 0) return bt;
    op = c_operation_to_VO_LB(opcode);
    if ((r = c_value_cast(pv1, bt, &tv1)) < 0) return r;
    if ((r = c_value_cast(pv2, bt, &tv2)) < 0) return r;
    if ((r = vo_run_logic_binary(bt, op, &tv1.v, &tv2.v, &pres->v)) < 0)
      return r;
    pres->tag = C_INT;
    return 0;

  case VO_OP_UNARY:
    if ((bt = c_value_balanced_type(pv1, pv1)) < 0) return bt;
    op = c_operation_to_VO_UN(opcode);
    if ((r = c_value_cast(pv1, bt, &tv1)) < 0) return r;
    if ((r = vo_run_unary(bt, op, &tv1.v, &pres->v)) < 0) return r;
    pres->tag = bt;
    return 0;

  case VO_OP_LOGIC_UNARY:
    if ((bt = c_value_balanced_type(pv1, pv1)) < 0) return bt;
    op = c_operation_to_VO_LU(opcode);
    if ((r = c_value_cast(pv1, bt, &tv1)) < 0) return r;
    if ((r = vo_run_logic_unary(bt, op, &tv1.v, &pres->v)) < 0) return r;
    pres->tag = C_INT;
    return 0;

  case VO_OP_UPDATE:
    err_psWrite(ERC_ERROR, ppos,
                "constant expression expected");
    return -1;
  default:
    SWERR(("unknown operation class: %d", cl));
  }

  /* certain operation handled separately */
  switch (opcode) {
  default:
    SWERR(("unhandled opcode %d (%s)", opcode, c_operation_str(opcode)));
  }
  return 0;
}

static char const * const copctable[COP_LAST] =
{
  /*[COP_NONE]*/ 0,

  /*[COP_ASSIGN]*/    "=",          /*  1 */
  /*[COP_MULASSIGN]*/ "*=",         /*  2 */
  /*[COP_DIVASSIGN]*/ "/=",         /*  3 */
  /*[COP_MODASSIGN]*/ "%=",         /*  4 */
  /*[COP_ADDASSIGN]*/ "+=",         /*  5 */
  /*[COP_SUBASSIGN]*/ "-=",         /*  6 */
  /*[COP_ASLASSIGN]*/ "<<=",        /*  7 */
  /*[COP_ASRASSIGN]*/ ">>=",        /*  8 */
  /*[COP_ANDASSIGN]*/ "&=",         /*  9 */
  /*[COP_XORASSIGN]*/ "^=",         /* 10 */
  /*[COP_ORASSIGN]*/  "|=",         /* 11 */

  /*[COP_COMMA]*/     ",",          /* 12 */

  /*[COP_COND]*/      "?:",         /* 13 */

  /*[COP_LOGOR]*/     "||",         /* 14 */
  /*[COP_LOGAND]*/    "&&",         /* 15 */

  /*[COP_BITOR]*/     "|",          /* 16 */
  /*[COP_BITXOR]*/    "^",          /* 17 */
  /*[COP_BITAND]*/    "&",          /* 18 */

  /*[COP_EQ]*/        "==",         /* 19 */
  /*[COP_NE]*/        "!=",         /* 20 */
  /*[COP_LT]*/        "<",          /* 21 */
  /*[COP_GT]*/        ">",          /* 22 */
  /*[COP_LE]*/        "<=",         /* 23 */
  /*[COP_GE]*/        ">=",         /* 24 */

  /*[COP_ASR]*/       ">>",         /* 25 */
  /*[COP_ASL]*/       "<<",         /* 26 */

  /*[COP_ADD]*/       "+",          /* 27 */
  /*[COP_SUB]*/       "-",          /* 28 */
  
  /*[COP_MUL]*/       "*",          /* 29 */
  /*[COP_DIV]*/       "/",          /* 30 */
  /*[COP_MOD]*/       "%",          /* 31 */

  /*[COP_CAST]*/      "(cast)",     /* 32 */

  /*[COP_PREINC]*/    "++",         /* 33 */
  /*[COP_PREDEC]*/    "--",         /* 34 */
  /*[COP_SIZEOF]*/    "sizeof",     /* 35 */
  /*[COP_DEREF]*/     "*",          /* 36 */
  /*[COP_ADDRESS]*/   "&",          /* 37 */
  /*[COP_PLUS]*/      "+",          /* 38 */
  /*[COP_MINUS]*/     "-",          /* 39 */
  /*[COP_BITNOT]*/    "~",          /* 40 */
  /*[COP_LOGNOT]*/    "!",          /* 41 */
  /*[COP_POSTINC]*/   "++",         /* 42 */
  /*[COP_POSTDEC]*/   "--",         /* 43 */

  /*[COP_FIELD]*/     ".",          /* 44 */
  /*[COP_FIELDREF]*/  "->",         /* 45 */
};

const char *
c_operation_str(int cop)
{
  ASSERT(cop >= 1 && cop < COP_LAST);
  return copctable[cop];
}
