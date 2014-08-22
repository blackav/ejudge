/* -*- mode:c -*- */
#ifndef __TREE_H__
#define __TREE_H__

/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "pos.h"

#include "ejudge/hash.h"
#include "ejudge/c_value.h"

#include <stdlib.h>
#include <wchar.h>

#ifndef RCC_SEMAINFO_T_DEFINED
#define RCC_SEMAINFO_T_DEFINED 1
typedef union s_semainfo *semainfo_t;
#endif /* RCC_SEMAINFO_T_DEFINED */

#ifndef RCC_AFACCESS_T_DEFINED
#define RCC_AFACCESS_T_DEFINED 1
typedef struct s_afaccess *afaccess_t;
#endif /* RCC_AFACCESS_T_DEFINED */

#ifndef RCC_MIFELEM_T_DEFINED
#define RCC_MIFELEM_T_DEFINED 1
union s_mifelem;
typedef union s_mifelem *mifelem_t;
#endif /* RCC_MIFELEM_T_DEFINED */

union u_tree;

struct tree_gen
{
  int kind;
  dpos_t pos;
};

/* tree node */
struct tree_regnode
{
  int kind;
  dpos_t pos;
  int serial;
  semainfo_t sema;
  int nrefs;
  union u_tree *refs[1];
};

struct tree_toknode
{
  int kind;
  dpos_t pos;
};

struct tree_valnode
{
  int kind;
  dpos_t pos;
  c_value_t val;
};

struct tree_idnode
{
  int kind;
  dpos_t pos;
  ident_t id;
};

struct tree_strnode
{
  int kind;
  dpos_t pos;
  size_t len;
  unsigned char *val;
};

struct tree_lstrnode
{
  int kind;
  dpos_t pos;
  size_t len;
  wchar_t *val;
};

struct tree_sema_arr
{
  afaccess_t chain;
};
struct tree_sema_field
{
  afaccess_t  chain;
  void       *def;
};
struct tree_sema_ident
{
  unsigned char *function;
  mifelem_t      elem;
};
struct tree_sema_expr
{
  union u_tree * original_node;
  union u_tree * from_cast;
};
struct tree_sema_string
{
  mifelem_t      elem;
};
struct tree_sema_asm
{
  void *param;
};

union u_tree_sema
{
  struct tree_sema_arr arr;
  struct tree_sema_field field;
  struct tree_sema_ident ident;
  struct tree_sema_expr expr;
  struct tree_sema_string string;
  struct tree_sema_asm sema_asm;
};

struct tree_semanode
{
  int kind;
  dpos_t pos;
  union u_tree_sema sema;
};

union u_tree
{
  int kind;
  struct tree_gen      gen;
  struct tree_regnode  node;
  struct tree_toknode  tok;
  struct tree_valnode  val;
  struct tree_idnode   id;
  struct tree_strnode  str;
  struct tree_lstrnode lstr;
  struct tree_semanode sema;
};

#if !defined RCC_TREE_T_DEFINED
#define RCC_TREE_T_DEFINED 1
union u_tree;
typedef union u_tree *tree_t;
#endif /* RCC_TREE_T_DEFINED */

typedef tree_t YYSTYPE;
#define YYSTYPE_IS_DECLARED 1
#define YYSTYPE_IS_TRIVIAL 1

#include "parser.h"

enum node_kinds
  {
    NODE_FIRST = TOK_LAST + 1,

    NODE_ROOT = NODE_FIRST,

    NODE_DECLFUNC,
    NODE_DECL,
    NODE_ELLIPSIS,
    NODE_ANNOT,

    NODE_DSSTDTYPE,
    NODE_DSTYPENAME,
    NODE_DSSTORAGE,
    NODE_DSQUAL,
    NODE_DSFUNCSPEC,
    NODE_DSENUM,
    NODE_DSAGGREG,
    NODE_DSTYPEOF,

    NODE_ENUMERATOR,

    NODE_INITDECLR,
    NODE_STRUCTDECLR,

    NODE_DECLR,

    NODE_POINTER,

    NODE_DIRDECLR1,
    NODE_DIRDECLR2,
    NODE_DIRDECLR3,
    NODE_DIRDECLR4,
    NODE_DIRDECLR5,

    NODE_IDENTS,

    NODE_INITEXPR,
    NODE_INITBLOCK,

    NODE_DESARRAY,
    NODE_DESFIELD,

    NODE_LABID,
    NODE_LABCASE,
    NODE_LABDEFAULT,

    NODE_STLABEL,
    NODE_STBLOCK,
    NODE_STSUBBLOCK,
    NODE_STEXPR,
    NODE_STIF,
    NODE_STSWITCH,
    NODE_STWHILE,
    NODE_STDO,
    NODE_STFOR,
    NODE_STDECLFOR,
    NODE_STGOTO,
    NODE_STCONTINUE,
    NODE_STBREAK,
    NODE_STRETURN,

    NODE_EXPRFIRST,
    NODE_EXPRTERNARY = NODE_EXPRFIRST,
    NODE_EXPRBINARY,
    NODE_EXPRCAST,
    NODE_EXPRSIZEOF,
    NODE_EXPRUNARY,
    NODE_EXPRARRAY,
    NODE_EXPRCALL,
    NODE_EXPRFIELD,
    NODE_EXPRPOSTFIX,
    NODE_EXPRBRACKETS,
    NODE_EXPRIDENT,
    NODE_EXPRCONST,
    NODE_EXPRSTRING,
    NODE_EXPRLSTRING,
    NODE_EXPRVASTART,
    NODE_EXPRVAARG,
    NODE_EXPRVAEND,
    NODE_EXPRINIT,
    NODE_EXPRASM,
    NODE_EXPRASSERT,
    NODE_EXPRSTMT,
    NODE_EXPRLAST = NODE_EXPRSTMT,

    NODE_ASMARG,
    NODE_ATTRIBUTE,
    NODE_ATTRITEM,

    NODE_LAST,

    NODE_SEMA = NODE_LAST,
  };

void *tree_alloc(size_t);

tree_t tree_make_string(int kind, pos_t const *pst, pos_t const *pen,
                        unsigned char const *str, size_t sz);
tree_t tree_make_lstring(int kind, const pos_t *pst, const pos_t *pen,
                         const wchar_t *lstr, size_t sz);
tree_t tree_make_value(int kind, pos_t const *pst, pos_t const *pen);
tree_t tree_make_token(int kind, pos_t const *pst, pos_t const *pen);
tree_t tree_make_ident(int kind, const pos_t *pst, const pos_t *pen,
                       ident_t id);
tree_t tree_make_sema(void);
tree_t tree_make_node(int kind, int num, int fpos, int lpos, ...);
tree_t tree_make_node3(int kind, int num, ...);
tree_t tree_merge(tree_t, tree_t, tree_t);
void   tree_fix_pos(tree_t, int fpos, int lpos);

tree_t tree_get_ident_node(tree_t p);
int tree_get_node_serial(void);
const unsigned char *tree_get_node_name(int kind);

int    parser_parse(tree_t *pp);

void tree_dump(FILE *fout, tree_t root);

#endif /* __TREE_H__ */
