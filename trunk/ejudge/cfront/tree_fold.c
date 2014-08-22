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

#include "tree_fold.h"
#include "sema_data.h"
#include "sema_maps.h"
#include "sema_func.h"
#include "builtin_idents.h"

#include "ejudge/logger.h"

#include <string.h>

#if defined __MINGW32__
#include <malloc.h>
#endif

int
tree_fold(tree_t node, c_value_t *pval)
{
  semainfo_t si;
  struct sema_def *def;
  c_value_t v1, v2;
  int opcode;
  size_t size;
  typeinfo_t tt;
  tree_t decl;

  if (!node) goto failure;

  switch (node->kind) {
  case NODE_EXPRTERNARY:
    if (tree_fold(node->node.refs[3], &v1) < 0) goto failure;
    if (c_value_is_true(&v1)) {
      if (tree_fold(node->node.refs[5], pval) < 0) goto failure;
    } else {
      if (tree_fold(node->node.refs[7], pval) < 0) goto failure;
    }
    break;

  case NODE_EXPRBINARY:
    opcode = sema_binop_to_c_operation(node->node.refs[4]->kind);

    switch (opcode) {
    case COP_ASSIGN:
    case COP_MULASSIGN:
    case COP_DIVASSIGN:
    case COP_MODASSIGN:
    case COP_ADDASSIGN:
    case COP_SUBASSIGN:
    case COP_ASLASSIGN:
    case COP_ASRASSIGN:
    case COP_ANDASSIGN:
    case COP_XORASSIGN:
    case COP_ORASSIGN:
      goto failure;

    case COP_COMMA:
      if (tree_fold(node->node.refs[3], &v1) < 0) goto failure;
      if (tree_fold(node->node.refs[5], pval) < 0) goto failure;
      break;

    case COP_LOGAND:
      if (tree_fold(node->node.refs[3], &v1) < 0) goto failure;
      if (c_value_is_false(&v1)) goto set_false_value;
      if (tree_fold(node->node.refs[5], &v2) < 0) goto failure;
      if (c_value_is_false(&v2)) goto set_false_value;
      goto set_true_value;

    case COP_LOGOR:
      if (tree_fold(node->node.refs[3], &v1) < 0) goto failure;
      if (c_value_is_true(&v1)) goto set_true_value;
      if (tree_fold(node->node.refs[5], &v2) < 0) goto failure;
      if (c_value_is_true(&v2)) goto set_true_value;
      goto set_false_value;

    case COP_BITOR:
    case COP_BITXOR:
    case COP_BITAND:
    case COP_EQ:
    case COP_NE:
    case COP_LT:
    case COP_GT:
    case COP_LE:
    case COP_GE:
    case COP_ASR:
    case COP_ASL:
    case COP_ADD:
    case COP_SUB:
    case COP_MUL:
    case COP_DIV:
    case COP_MOD:
      break;

    default:
      SWERR(("tree_fold: unhandled binary opcode: %d", opcode));
    }

    if (tree_fold(node->node.refs[3], &v1) < 0) goto failure;
    if (tree_fold(node->node.refs[5], &v2) < 0) goto failure;
    if (c_value_operation(0, opcode, &v1, &v2, 0, pval) < 0) goto failure;
    break;

  case NODE_EXPRCAST:
    if (tree_fold(node->node.refs[6], &v1) < 0) goto failure;
    tt = sema_get_expr_type(node->node.refs[6]);
    ASSERT(tt);
    if (tt->tag != CPT_ARITH && tt->tag != CPT_ENUM) goto failure;
    tt = sema_get_expr_type(node);
    if (tt->tag != CPT_ARITH) goto failure;
    if (c_value_cast(&v1, sema_typeinfo_to_index(tt), pval) < 0) goto failure;
    break;

  case NODE_EXPRSIZEOF:
    decl = node->node.refs[5];
    if (!decl) goto failure;
    ASSERT(decl->kind == NODE_DECL);
    si = decl->node.sema;
    if (!si) goto failure;
    ASSERT(si->tag == ST_TYPE);
    tt = si->s_type.type;
    size = sema_get_type_size(tt);
    if (size == SEMA_NO_SIZE) goto failure;
    memset(pval, 0, sizeof(*pval));
    pval->tag = C_ULONG;
    pval->v.ct_ulint = size;
    break;

  case NODE_EXPRUNARY:
    opcode = sema_unop_to_c_operation(node->node.refs[3]->kind);

    switch (opcode) {
    case COP_PREINC:
    case COP_PREDEC:
      goto failure;

    case COP_SIZEOF:
      tt = sema_get_expr_type(node->node.refs[4]);
      size = sema_get_type_size(tt);
      if (size == SEMA_NO_SIZE) goto failure;
      memset(pval, 0, sizeof(*pval));
      pval->tag = C_ULONG;
      pval->v.ct_ulint = size;
      break;

    case COP_DEREF:
    case COP_ADDRESS:
      goto failure;

    case COP_PLUS:
    case COP_MINUS:
    case COP_BITNOT:
    case COP_LOGNOT:
      if (tree_fold(node->node.refs[4], &v1) < 0) goto failure;
      if (c_value_operation(0, opcode, &v1, 0, 0, pval) < 0) goto failure;
      break;

    default:
      SWERR(("tree_fold: unhandled unary opcode: %d", opcode));
    }
    break;

  case NODE_EXPRARRAY:
  case NODE_EXPRCALL:
  case NODE_EXPRFIELD:
  case NODE_EXPRPOSTFIX:
    return -1;

  case NODE_EXPRBRACKETS:
    return tree_fold(node->node.refs[4], pval);

  case NODE_EXPRIDENT:
    si = node->node.sema;
    if (!si) goto failure;
    ASSERT(si->tag == ST_IDUSE);
    def = si->s_iduse.def;
    ASSERT(def->type);
    if (def->type->tag != CPT_ENUM) goto failure;
    if (!SSC_IS_ENUMCONST(def->flags)) goto failure;
    memset(pval, 0, sizeof(*pval));
    memcpy(pval, def->value, sizeof(c_value_t));
    break;

  case NODE_EXPRCONST:
    memset(pval, 0, sizeof(*pval));
    memcpy(pval, &node->node.refs[3]->val.val, sizeof(c_value_t));
    break;

  case NODE_EXPRSTRING:
  case NODE_EXPRVASTART:
  case NODE_EXPRVAARG:
  case NODE_EXPRVAEND:
  case NODE_EXPRINIT:
  case NODE_EXPRASM:
    return -1;
  default:
    SWERR(("tree_fold: bad node: kind == %d", node->kind));
  }
  return 0;

 failure:
  memset(pval, 0, sizeof(*pval));
  pval->tag = C_INT;
  return -1;

 set_false_value:
  memset(pval, 0, sizeof(*pval));
  pval->tag = C_INT;
  return 0;

 set_true_value:
  memset(pval, 0, sizeof(*pval));
  pval->tag = C_INT;
  pval->v.ct_int = 1;
  return 0;
}

#define RR(ind) do { sema_fold_some_operations(p[ind],pp[ind]); p[ind] = 0; } while (0)

static void
try_fold_cast(tree_t node, tree_t *pp1)
{
  typeinfo_t tdst;
  typeinfo_t tsrc;
  int isrc, idst;
  c_value_t vout, tval;
  int stat;
  tree_t psrc;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRCAST);
  if (!pp1) return;

  tdst = sema_get_expr_type(node);
  psrc = node->node.refs[6];
  if (!psrc) return;
  if (psrc->kind == NODE_EXPRSTRING) {
    // if cast to another char * type, ignore it
    if (tdst->tag != CPT_POINTER) return;
    if (!sema_is_character_type(tdst->t_pointer.type)) return;
    psrc->node.sema = sinfo_create_type(tdst);
    *pp1 = psrc;
    psrc->node.refs[0] = node->node.refs[0];
    return;
  }
  if (psrc->kind == NODE_EXPRIDENT 
      && builtin_lookup(psrc->node.refs[3]->id.id) == C_BUILTIN_FUNCTION) {
    if (tdst->tag != CPT_POINTER) return;
    if (!sema_is_character_type(tdst->t_pointer.type)) return;
    psrc->node.sema = sinfo_create_type(tdst);
    *pp1 = psrc;
    psrc->node.refs[0] = node->node.refs[0];
    return;
  }
  if (psrc->kind != NODE_EXPRCONST) return;
  tsrc = sema_get_expr_type(psrc);

  memset(&vout, 0, sizeof(vout));
  if (tdst->tag == CPT_POINTER && tsrc->tag == CPT_POINTER) {
    tval = psrc->node.refs[3]->val.val;
    // FIXME: this is ugly hack, because c_value lacks NULL pointer checks
    tval.tag = C_INT;
    if (!c_value_is_zero(&tval)) return;
    vout.tag = C_POINTER;
  } else if (tdst->tag == CPT_POINTER && tsrc->tag == CPT_ARITH
      && c_value_is_zero(&psrc->node.refs[3]->val.val)) {
    vout.tag = C_POINTER;
  } else if (tdst->tag == CPT_ARITH && tsrc->tag == CPT_ARITH) {
    isrc = sema_typeinfo_to_index(tsrc);
    ASSERT(isrc >= C_FIRST_ARITH && isrc <= C_LAST_ARITH);
    idst = sema_typeinfo_to_index(tdst);
    ASSERT(idst >= C_FIRST_ARITH && idst <= C_LAST_ARITH);
    stat = c_value_cast(&psrc->node.refs[3]->val.val, idst, &vout);
    (void) stat;
  } else {
    return;
  }
  psrc->node.refs[3]->val.val = vout;
  psrc->node.sema = sinfo_create_type(tdst);
  *pp1 = psrc;
  psrc->node.refs[0] = node->node.refs[0];
}

static void
try_fold_unary(tree_t node, int cop, tree_t *pp1)
{
  tree_t psrc;
  typeinfo_t tsrc;
  int isrc;
  c_value_t vout;
  int stat = 0;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRUNARY);
  if (!pp1) return;
  if (cop != COP_PLUS && cop != COP_MINUS) return;

  psrc = node->node.refs[4];
  if (!psrc || psrc->kind != NODE_EXPRCONST) return;
  tsrc = sema_get_expr_type(psrc);

  if (tsrc->tag != CPT_ARITH) return;
  isrc = sema_typeinfo_to_index(tsrc);
  ASSERT(isrc >= C_FIRST_ARITH && isrc <= C_LAST_ARITH);

  if (cop == COP_MINUS) {
    stat = c_value_operation(0, COP_MINUS,
                             &psrc->node.refs[3]->val.val, 0, 0, &vout);
    psrc->node.refs[3]->val.val = vout;
    (void) stat;
  }

  *pp1 = psrc;
  psrc->node.refs[0] = node->node.refs[0];
}

void
sema_fold_some_operations(tree_t node, tree_t *pp1)
{
  int n = 0, i = 0;
  tree_t *p = 0, **pp = 0;
  int cop;

  if (!node) return;
  if (node->kind < NODE_FIRST || node->kind >= NODE_LAST) return;

  /* make a copy of refs array so we would modify it */
  n = node->node.nrefs;
  if (n) {
    p = (tree_t*) alloca(n * sizeof(p[0]));
    memcpy(p, node->node.refs, sizeof(p[0]) * n);
    pp = (tree_t**) alloca(n * sizeof(pp[0]));
    memset(pp, 0, n * sizeof(pp[0]));
    for (i = 3; i < n; i++)
      pp[i] = &node->node.refs[i];
  }

  switch (node->kind) {
  case NODE_STEXPR:
    RR(3);
    break;
  case NODE_STIF:
    RR(5);
    break;
  case NODE_STSWITCH:
    RR(5);
    break;
  case NODE_STWHILE:
    RR(5);
    break;
  case NODE_STDO:
    RR(7);
    break;
  case NODE_STFOR:
    RR(5);
    RR(7);
    RR(9);
    break;
  case NODE_STRETURN:
    RR(4);
    break;
  case NODE_INITEXPR:
    RR(5);
    break;
  case NODE_EXPRFIELD:
    RR(3);
    break;
  case NODE_EXPRCALL:
    RR(3);
    {
      tree_t pc, *ppc1;

      ppc1 = &node->node.refs[5];
      pc = *ppc1;
      while (pc) {
        sema_fold_some_operations(pc, ppc1);
        pc = *ppc1;
        ppc1 = &pc->node.refs[0];
        pc = *ppc1;
      }
      p[5] = 0;
    }
    break;
  case NODE_EXPRARRAY:
    RR(3);
    RR(5);
    break;
  case NODE_EXPRPOSTFIX:
    RR(3);
    break;
  case NODE_EXPRUNARY:
    RR(4);
    cop = sema_get_expr_opcode(node, 0, 0);
    try_fold_unary(node, cop, pp1);
    break;
  case NODE_EXPRBINARY:
    RR(3);
    RR(5);
    break;
  case NODE_EXPRTERNARY:
    RR(3);
    RR(5);
    RR(7);
    break;
  case NODE_EXPRCAST:
    RR(6);
    try_fold_cast(node, pp1);
    break;
  case NODE_EXPRBRACKETS:
    RR(4);
    break;
  }

  /* run on children nodes */
  for (i = 3; i < n; i++) {
    sema_fold_some_operations(p[i], 0);
  }
  sema_fold_some_operations(p[0], 0);
}
