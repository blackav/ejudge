/* -*- mode: c -*- */
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

#include "tree.h"

#include "ejudge/mempage.h"
#include "ejudge/logger.h"

#include <string.h>
#include <stdarg.h>

static tPageDesc *mem = 0;

void *
tree_alloc(size_t size)
{
  if (!mem) {
    pgInitModule();
    mem = pgCreate(0);
  }
  return pgCalloc(mem, 1, size);
}

tree_t
tree_make_string(int kind,
                 pos_t const *pst,
                 pos_t const *pen,
                 unsigned char const *str,
                 size_t sz)
{
  unsigned char *nstr;
  tree_t p;

  nstr = (unsigned char*) tree_alloc(sz + 1);
  memset(nstr, 0, sz + 1);
  memcpy(nstr, str, sz);
  p = (tree_t) tree_alloc(sizeof(struct tree_strnode));
  p->kind = kind;
  p->str.pos.beg = *pst;
  p->str.pos.end = *pen;
  p->str.len = sz;
  p->str.val = nstr;
  return p;
}

tree_t
tree_make_lstring(int kind,
                  const pos_t *pst,
                  const pos_t *pen,
                  const wchar_t *lstr,
                  size_t sz)
{
  wchar_t *nstr;
  tree_t p;

  nstr = (wchar_t*) tree_alloc((sz + 1) * sizeof(nstr[0]));
  memset(nstr, 0, (sz + 1) * sizeof(nstr[0]));
  memcpy(nstr, lstr, sz * sizeof(nstr[0]));
  p = (tree_t) tree_alloc(sizeof(struct tree_strnode));
  p->kind = kind;
  p->lstr.pos.beg = *pst;
  p->lstr.pos.end = *pen;
  p->lstr.len = sz;
  p->lstr.val = nstr;
  return p;
}

tree_t
tree_make_value(int kind,
                const pos_t *pst,
                const pos_t *pen)
{
  tree_t p;

  p = (tree_t) tree_alloc(sizeof(struct tree_valnode));
  p->kind = kind;
  p->val.pos.beg = *pst;
  p->val.pos.end = *pen;
  return p;
}

tree_t
tree_make_token(int kind,
                const pos_t *pst,
                const pos_t *pen)
{
  tree_t p;

  p = (tree_t) tree_alloc(sizeof(struct tree_toknode));
  p->kind = kind;
  p->tok.pos.beg = *pst;
  p->tok.pos.end = *pen;
  return p;
}

tree_t
tree_make_ident(int kind,
                const pos_t *pst,
                const pos_t *pen,
                ident_t id)
{
  tree_t p;

  p = (tree_t) tree_alloc(sizeof(struct tree_idnode));
  p->kind = kind;
  p->id.pos.beg = *pst;
  p->id.pos.end = *pen;
  p->id.id = id;
  return p;
}

tree_t
tree_make_sema(void)
{
  tree_t p;

  p = (tree_t) tree_alloc(sizeof(struct tree_semanode));
  p->kind = NODE_SEMA;
  return p;
}

static int tree_make_node_serial = 1;

int
tree_get_node_serial(void)
{
  return tree_make_node_serial;
}

tree_t
tree_make_node(int kind, int nch, int fpos, int lpos, ...)
{
  tree_t p;
  int i;
  va_list args;

  if (nch > 1) {
    p = (tree_t) tree_alloc(sizeof(struct tree_regnode) + sizeof(tree_t) * (nch - 1));
  } else {
    p = (tree_t) tree_alloc(sizeof(struct tree_regnode));
  }

  p->kind = kind;
  p->node.serial = tree_make_node_serial++;
  p->node.nrefs = nch;
  va_start(args, lpos);
  for (i = 0; i < nch; i++) {
    p->node.refs[i] = va_arg(args, tree_t);
  }
  va_end(args);

  for (i = fpos; i < nch && !p->node.refs[i]; i++);
  if (i < nch && p->node.refs[i]) {
    p->node.pos.beg = p->node.refs[i]->gen.pos.beg;
  }

  for (i = lpos; i >= 0 && !p->node.refs[i]; i--);
  if (i >= 0 && p->node.refs[i]) {
    p->node.pos.end = p->node.refs[i]->gen.pos.end;
  }
  return p;
}

tree_t
tree_make_node3(int kind, int nch, ...)
{
  tree_t p;
  int i;
  va_list args;

  ASSERT(nch > 3);
  p = (tree_t) tree_alloc(sizeof(struct tree_regnode) + sizeof(tree_t) * (nch - 1));

  p->kind = kind;
  p->node.serial = tree_make_node_serial++;
  p->node.nrefs = nch;
  va_start(args, nch);
  p->node.refs[0] = 0;
  p->node.refs[1] = 0;
  p->node.refs[2] = 0;
  for (i = 3; i < nch; i++) {
    p->node.refs[i] = va_arg(args, tree_t);
  }
  va_end(args);

  for (i = 3; i < nch && !p->node.refs[i]; i++);
  if (i < nch && p->node.refs[i]) {
    p->node.pos.beg = p->node.refs[i]->gen.pos.beg;
  }

  for (i = nch - 1; i >= 3 && !p->node.refs[i]; i--);
  if (i >= 3 && p->node.refs[i]) {
    p->node.pos.end = p->node.refs[i]->gen.pos.end;
  }
  return p;
}

tree_t
tree_merge(tree_t l1, tree_t sep, tree_t l2)
{
  if (!l1) return l2;
  if (!l2) return l1;
  if (sep) {
    l2->node.refs[2] = sep;
  }
  if (!l1->node.refs[0] && !l2->node.refs[0]) {
    l1->node.refs[0] = l2;
    l1->node.refs[1] = l2;
  } else if (!l1->node.refs[0]) {
    l1->node.refs[0] = l2;
    l1->node.refs[1] = l2->node.refs[1];
  } else if (!l2->node.refs[0]) {
    l1->node.refs[1]->node.refs[0] = l2;
    l1->node.refs[1] = l2;
  } else {
    l1->node.refs[1]->node.refs[0] = l2;
    l1->node.refs[1] = l2->node.refs[1];
  }
  return l1;
}

void
tree_fix_pos(tree_t p, int fpos, int lpos)
{
  int i;

  ASSERT(p);
  ASSERT(fpos >= 3);
  ASSERT(lpos < p->node.nrefs);
  ASSERT(fpos <= lpos);

  for (i = fpos; i <= lpos && !p->node.refs[i]; i++);
  if (i <= lpos) p->node.pos.beg = p->node.refs[i]->gen.pos.beg;

  for (i = lpos; i >= fpos && !p->node.refs[i]; i--);
  if (i >= fpos) p->node.pos.end = p->node.refs[i]->gen.pos.end;
}

tree_t
tree_get_ident_node(tree_t p)
{
  while (p) {
    switch (p->kind) {
    case TOK_IDENT:
    case TOK_TYPENAME:
      return p;
    case NODE_INITDECLR:
    case NODE_STRUCTDECLR:
      p = p->node.refs[3];
      break;
    case NODE_DECLR:
      p = p->node.refs[4];
      break;
    case NODE_DIRDECLR1:
      return p->node.refs[3];
    case NODE_DIRDECLR2:
      p = p->node.refs[4];
      break;
    case NODE_DIRDECLR3:
    case NODE_DIRDECLR4:
    case NODE_DIRDECLR5:
      p = p->node.refs[3];
      break;
    default:
      SWERR(("tree_get_ident_node: unhandled node"));
    }
  }
  return 0;
}

static unsigned char *node_names[] =
{
  [TOK_INCR] "TOK_INCR",
  [TOK_DECR] "TOK_DECR",
  [TOK_LSHIFT] "TOK_LSHIFT",
  [TOK_RSHIFT] "TOK_RSHIFT",
  [TOK_LEQ] "TOK_LEQ",
  [TOK_GEQ] "TOK_GEQ",
  [TOK_EQ] "TOK_EQ",
  [TOK_NEQ] "TOK_NEQ",
  [TOK_LOGAND] "TOK_LOGAND",
  [TOK_LOGOR] "TOK_LOGOR",
  [TOK_LOGXOR] "TOK_LOGXOR",
  [TOK_ELLIPSIS] "TOK_ELLIPSIS",
  [TOK_MULASSIGN] "TOK_MULASSIGN",
  [TOK_DIVASSIGN] "TOK_DIVASSIGN",
  [TOK_MODASSIGN] "TOK_MODASSIGN",
  [TOK_ADDASSIGN] "TOK_ADDASSIGN",
  [TOK_SUBASSIGN] "TOK_SUBASSIGN",
  [TOK_LSHASSIGN] "TOK_LSHASSIGN",
  [TOK_RSHASSIGN] "TOK_RSHASSIGN",
  [TOK_ANDASSIGN] "TOK_ANDASSIGN",
  [TOK_XORASSIGN] "TOK_XORASSIGN",
  [TOK_ORASSIGN] "TOK_ORASSIGN",
  [TOK_ARROW] "TOK_ARROW",
  [TOK_AUTO] "TOK_AUTO",
  [TOK_BREAK] "TOK_BREAK",
  [TOK_CASE] "TOK_CASE",
  [TOK_CHAR] "TOK_CHAR",
  [TOK_CONST] "TOK_CONST",
  [TOK_CONTINUE] "TOK_CONTINUE",
  [TOK_DEFAULT] "TOK_DEFAULT",
  [TOK_DO] "TOK_DO",
  [TOK_DOUBLE] "TOK_DOUBLE",
  [TOK_ELSE] "TOK_ELSE",
  [TOK_ENUM] "TOK_ENUM",
  [TOK_EXTERN] "TOK_EXTERN",
  [TOK_FLOAT] "TOK_FLOAT",
  [TOK_FOR] "TOK_FOR",
  [TOK_GOTO] "TOK_GOTO",
  [TOK_IF] "TOK_IF",
  [TOK_INLINE] "TOK_INLINE",
  [TOK_INT] "TOK_INT",
  [TOK_LONG] "TOK_LONG",
  [TOK_REGISTER] "TOK_REGISTER",
  [TOK_RESTRICT] "TOK_RESTRICT",
  [TOK_RETURN] "TOK_RETURN",
  [TOK_SHORT] "TOK_SHORT",
  [TOK_SIGNED] "TOK_SIGNED",
  [TOK_SIZEOF] "TOK_SIZEOF",
  [TOK_STATIC] "TOK_STATIC",
  [TOK_STRUCT] "TOK_STRUCT",
  [TOK_SWITCH] "TOK_SWITCH",
  [TOK_TYPEDEF] "TOK_TYPEDEF",
  [TOK_UNION] "TOK_UNION",
  [TOK_UNSIGNED] "TOK_UNSIGNED",
  [TOK_VOID] "TOK_VOID",
  [TOK_VOLATILE] "TOK_VOLATILE",
  [TOK_WHILE] "TOK_WHILE",
  [TOK__BOOL] "TOK__BOOL",
  [TOK__COMPLEX] "TOK__COMPLEX",
  [TOK__IMAGINARY] "TOK__IMAGINARY",
  [TOK_IDENT] "TOK_IDENT",
  [TOK_TYPENAME] "TOK_TYPENAME",
  [TOK_CONSTANT] "TOK_CONSTANT",
  [TOK_STRING] "TOK_STRING",
  [TOK_VA_LIST] "TOK_VA_LIST",
  [TOK_VA_START] "TOK_VA_START",
  [TOK_VA_ARG] "TOK_VA_ARG",
  [TOK_VA_END] "TOK_VA_END",
  [TOK_TYPEOF] "TOK_TYPEOF",
  [TOK_ASM] "TOK_ASM",
  [NODE_ROOT] "NODE_ROOT",
  [NODE_DECLFUNC] "NODE_DECLFUNC",
  [NODE_DECL] "NODE_DECL",
  [NODE_ELLIPSIS] "NODE_ELLIPSIS",
  [NODE_DSSTDTYPE] "NODE_DSSTDTYPE",
  [NODE_DSTYPENAME] "NODE_DSTYPENAME",
  [NODE_DSSTORAGE] "NODE_DSSTORAGE",
  [NODE_DSQUAL] "NODE_DSQUAL",
  [NODE_DSFUNCSPEC] "NODE_DSFUNCSPEC",
  [NODE_DSENUM] "NODE_DSENUM",
  [NODE_DSAGGREG] "NODE_DSAGGREG",
  [NODE_DSTYPEOF] "NODE_DSTYPEOF",
  [NODE_ENUMERATOR] "NODE_ENUMERATOR",
  [NODE_INITDECLR] "NODE_INITDECLR",
  [NODE_STRUCTDECLR] "NODE_STRUCTDECLR",
  [NODE_DECLR] "NODE_DECLR",
  [NODE_POINTER] "NODE_POINTER",
  [NODE_DIRDECLR1] "NODE_DIRDECLR1",
  [NODE_DIRDECLR2] "NODE_DIRDECLR2",
  [NODE_DIRDECLR3] "NODE_DIRDECLR3",
  [NODE_DIRDECLR4] "NODE_DIRDECLR4",
  [NODE_DIRDECLR5] "NODE_DIRDECLR5",
  [NODE_IDENTS] "NODE_IDENTS",
  [NODE_INITEXPR] "NODE_INITEXPR",
  [NODE_INITBLOCK] "NODE_INITBLOCK",
  [NODE_DESARRAY] "NODE_DESARRAY",
  [NODE_DESFIELD] "NODE_DESFIELD",
  [NODE_LABID] "NODE_LABID",
  [NODE_LABCASE] "NODE_LABCASE",
  [NODE_LABDEFAULT] "NODE_LABDEFAULT",
  [NODE_STLABEL] "NODE_STLABEL",
  [NODE_STBLOCK] "NODE_STBLOCK",
  [NODE_STSUBBLOCK] "NODE_STSUBBLOCK",
  [NODE_STEXPR] "NODE_STEXPR",
  [NODE_STIF] "NODE_STIF",
  [NODE_STSWITCH] "NODE_STSWITCH",
  [NODE_STWHILE] "NODE_STWHILE",
  [NODE_STDO] "NODE_STDO",
  [NODE_STFOR] "NODE_STFOR",
  [NODE_STDECLFOR] "NODE_STDECLFOR",
  [NODE_STGOTO] "NODE_STGOTO",
  [NODE_STCONTINUE] "NODE_STCONTINUE",
  [NODE_STBREAK] "NODE_STBREAK",
  [NODE_STRETURN] "NODE_STRETURN",
  [NODE_EXPRTERNARY] "NODE_EXPRTERNARY",
  [NODE_EXPRBINARY] "NODE_EXPRBINARY",
  [NODE_EXPRCAST] "NODE_EXPRCAST",
  [NODE_EXPRSIZEOF] "NODE_EXPRSIZEOF",
  [NODE_EXPRUNARY] "NODE_EXPRUNARY",
  [NODE_EXPRARRAY] "NODE_EXPRARRAY",
  [NODE_EXPRCALL] "NODE_EXPRCALL",
  [NODE_EXPRFIELD] "NODE_EXPRFIELD",
  [NODE_EXPRPOSTFIX] "NODE_EXPRPOSTFIX",
  [NODE_EXPRBRACKETS] "NODE_EXPRBRACKETS",
  [NODE_EXPRIDENT] "NODE_EXPRIDENT",
  [NODE_EXPRCONST] "NODE_EXPRCONST",
  [NODE_EXPRSTRING] "NODE_EXPRSTRING",
  [NODE_EXPRVASTART] "NODE_EXPRVASTART",
  [NODE_EXPRVAARG] "NODE_EXPRVAARG",
  [NODE_EXPRVAEND] "NODE_EXPRVAEND",
  [NODE_EXPRINIT] "NODE_EXPRINIT",
  [NODE_EXPRASM] "NODE_EXPRASM",
  [NODE_EXPRASSERT] "NODE_EXPRASSERT",
  [NODE_ASMARG] "NODE_ASMARG",
  [NODE_ATTRIBUTE] "NODE_ATTRIBUTE",
  [NODE_ATTRITEM] "NODE_ATTRITEM",
  [NODE_SEMA] "NODE_SEMA",
};

const unsigned char *
tree_get_node_name(int kind)
{
  static unsigned char buf[64];

  if (kind <= 0 || kind >= (sizeof(node_names) / sizeof(node_names[0]))) {
    snprintf(buf, sizeof(buf), "(%d)", kind);
    return buf;
  }
  if (kind <= ' ' || (kind >= 127 && kind < 258)) {
    snprintf(buf, sizeof(buf), "(%d)", kind);
    return buf;
  }
  if (kind < 256) {
    snprintf(buf, sizeof(buf), "'%c'", kind);
    return buf;
  }
  if (!node_names[kind]) {
    snprintf(buf, sizeof(buf), "(%d)", kind);
    return buf;
  }
  return node_names[kind];
}
