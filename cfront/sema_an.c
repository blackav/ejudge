/* -*- mode: C -*- */

/* Copyright (C) 1999-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "sema_data.h"
#include "sema_an.h"
#include "sema_func.h"
#include "sema_maps.h"
#include "tree.h"
#include "c_errors.h"
#include "tree_fold.h"
#include "attribute_names.h"
#include "builtin_idents.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/hash.h"

#include <ctype.h>
#include <string.h>

#if defined __MINGW32__
#include <malloc.h>
#endif

#if defined __GNUC__ || defined __REPC__
# define  ALLOC(p) ((p) = (typeof(p)) tree_alloc(sizeof(*(p))))
#else
# define  ALLOC(p) ((p) = tree_alloc(sizeof(*(p))))
#endif

#define ARRSIZE(arr) ((sizeof(arr))/(sizeof((arr)[0])))

#define BADNODE(x) SWERR(("%s: %s->kind == %d", __FUNCTION__, #x, x->kind))

struct scopes_info
{
  struct sema_scope *ret_scope;
  struct sema_scope *br_scope;
  struct sema_scope *cont_scope;
};

extern short sema_option_float_arith;
extern short sema_option_aggreg_return;
extern short sema_option_warn_register_param;

static void analyze_file(tree_t, struct sema_scope *);
static void detect_undefined_globals(struct sema_scope*);
static void warn_unused_statics(struct sema_scope *);
static void fix_forward_iduses(tree_t);

static typeinfo_t make_typeinfo(tree_t,struct sema_scope*,
                                struct sema_scope *, typeinfo_t,tree_t,
                                int, int, tree_t *);
void       print_typeinfo(typeinfo_t, FILE *, char *, int);
void       print_scope(struct sema_scope *, FILE *);

static int analyze_expr(tree_t, struct sema_scope*, int cntx,
                        afaccess_t *pafacc, struct scopes_info *jmp_scopes);
static tree_t make_cast_node(tree_t node, int type, tree_t *pp1);

static void put_builtin_prototypes(struct sema_scope *);

static void
drop_last_pointer(tree_t node)
{
  int i;

  if (!node) return;
  if (node->kind < NODE_FIRST || node->kind >= NODE_LAST) return;
  if (node->node.nrefs <= 1) return;

  node->node.refs[1] = 0;
  for (i = 3; i < node->node.nrefs; i++) {
    drop_last_pointer(node->node.refs[i]);
  }
  drop_last_pointer(node->node.refs[0]);
}

void
sema_analyze(tree_t tree)
{
  struct sema_scope *global = 0;
  if (!tree) return;

  if (sema_option_float_arith) {
    c_value_enable_float_arith();
  }

  /* attach sema_scope to the top-level tree node */
  ASSERT(tree->kind == NODE_ROOT);
  global = sema_scope_create(NULL);
  tree->node.sema = sinfo_create_scope(global);

  /* clear refs[1], since we will use it for sema pointer */
  drop_last_pointer(tree);

  put_builtin_prototypes(global);
  analyze_file(tree->node.refs[3], global);
  fix_forward_iduses(tree);
  detect_undefined_globals(global);
  warn_unused_statics(global);

  /* fold some expressions like `(char) 1' or `-2' */
  if (!c_err_get_count()) {
    sema_fold_some_operations(tree, 0);
  }

  /* uncomment this to debug */
  //print_scope(tree->TranslUnit.sema, stdout);
}

static char *
sema_SSC_to_string(int flags)
{
  if (flags == SSC_TYPEDEF) return "typedef";
  switch (SSC_GET_SCLASS(flags)) {
  case SSC_GLOBAL:   return "/*global*/";
  case SSC_EXTERN:   return "extern";
  case SSC_STATIC:   return "static";
  case SSC_LOCAL:    return "auto";
  case SSC_REGISTER: return "register";
  default:
    SWERR(("invalid storage class: %d", SSC_GET_SCLASS(flags)));
  }
}

static int
sema_get_storclass(tree_t node, pos_t **pppos)
{
  int    stclass = 0;
  int    newclass;

  for (; node; node = node->node.refs[0]) {
    ASSERT(node->kind >= NODE_DSSTDTYPE && node->kind <= NODE_DSTYPEOF);
    if (node->kind == NODE_DSSTORAGE) {
      if (pppos) *pppos = &node->gen.pos.beg;
      if (!node->node.refs[3]) continue;
      switch (node->node.refs[3]->kind) {
      case TOK_TYPEDEF:  newclass = SSC_TYPEDEF;  break;
      case TOK_EXTERN:   newclass = SSC_EXTERN;   break;
      case TOK_STATIC:   newclass = SSC_STATIC;   break;
      case TOK_AUTO:     newclass = SSC_LOCAL;    break;
      case TOK_REGISTER: newclass = SSC_REGISTER; break;
      default:
        SWERR(("bad StorageClass.Spec: %d", node->node.refs[3]->kind));
      }
      if (stclass && newclass != stclass) {
        c_err(&node->gen.pos.beg,
              "conflicting storage classes `%s' and `%s'",
              sema_SSC_to_string(stclass), sema_SSC_to_string(newclass));
        return 0;
      } else if (stclass && newclass == stclass) {
        c_warn(&node->gen.pos.beg,
               "duplicated storage class `%s'", sema_SSC_to_string(stclass));
      }
      stclass = newclass;
    }
  }
  return stclass;
}

enum
{
  SSC_PUT_FIRST    = 1,
  SSC_PUT_BUT_LAST = 2
};

static struct sema_def *
sema_put_ident(struct sema_scope *scope,
               int                flags,
               ident_t            ident,
               pos_t             *ppos,
               typeinfo_t         type,
               int                mode,
               struct sema_scope *nest,
               tree_t             tree)
{
  struct sema_deflist *lst;
  struct sema_def     *def;

  switch ((flags & SSC_NSPACE_MASK)) {
  case SSC_REGULAR:   lst = &scope->reg; break;
  case SSC_STRUCT:    lst = &scope->tags; break;
  case SSC_UNION:     lst = &scope->tags; break;
  case SSC_ENUM:      lst = &scope->tags; break;
  case SSC_LABEL:     lst = &scope->labels; break;
  default:
    SWERR(("bad namespace: 0x%08x", (flags & SSC_NSPACE_MASK)));
  }

  ALLOC(def);
  def->next  = NULL;
  def->flags = flags;
  def->name  = ident;
  def->type  = type;
  def->tree  = tree;
  def->nest  = nest;
  def->ppos  = ppos;
  def->scope = scope;

  if (mode == SSC_PUT_BUT_LAST) {
    if (!lst->first) {
      lst->first = lst->last = def;
    } else if (!lst->first->next) {
      def->next = lst->first;
      lst->first = def;
    } else {
      struct sema_def *p = lst->first;
      while (p->next->next) {
        p = p->next;
      }
      def->next = p->next;
      p->next = def;
    }
  } else if (mode == SSC_PUT_FIRST) {
    if (!lst->first) {
      lst->first = lst->last = def;
    } else {
      def->next = lst->first;
      lst->first = def;
    }
  } else {
    if (!lst->last) {
      lst->first = lst->last = def;
    } else {
      lst->last->next = def;
      lst->last = def;
    }
  }

  return def;
}

static struct sema_def *
sema_put_ident2(struct sema_scope *scope,
                struct sema_scope *outer_scope,
                int                flags,
                ident_t            ident,
                pos_t             *ppos,
                typeinfo_t         type,
                struct sema_scope *nest,
                tree_t             tree)
{
  if (outer_scope)
    return sema_put_ident(outer_scope, flags, ident, ppos, type,
                          SSC_PUT_BUT_LAST, nest, tree);
  return sema_put_ident(scope, flags, ident, ppos, type, 0, nest, tree);
}

static struct sema_def *
sema_search_scope(ident_t id, struct sema_scope *scope, int flags)
{
  struct sema_def *ptr = NULL;
  int              saved_flags = flags;

  ASSERT(id != ident_empty);

  while (scope) {
    flags = saved_flags;
    while (flags) {
      if ((flags & SSC_REGULAR)) {
        ptr = scope->reg.first;
        flags &= ~SSC_REGULAR;
      } else if ((flags & SSC_STRUCT)) {
        ptr = scope->tags.first;
        flags &= ~SSC_TAG;
      } else if ((flags & SSC_UNION)) {
        ptr = scope->tags.first;
        flags &= ~SSC_TAG;
      } else if ((flags & SSC_ENUM)) {
        ptr = scope->tags.first;
        flags &= ~SSC_TAG;
      } else if ((flags & SSC_LABEL)) {
        ptr = scope->labels.first;
        flags &= ~SSC_LABEL;
      } else {
        SWERR(("bad flags: 0x%08x", flags));
      }
      
      for (; ptr; ptr = ptr->next) {
        if (ptr->name == id) return ptr;
      }
    }
    scope = scope->up;
  }

  return NULL;
}

static struct sema_def *
sema_search_this_scope(ident_t id, struct sema_scope *scope, int flags)
{
  struct sema_def *ptr = NULL;
  int orig_flags = flags;

  ASSERT(id != ident_empty);

  while (flags) {
    if ((flags & SSC_REGULAR)) {
      ptr = scope->reg.first;
      flags &= ~SSC_REGULAR;
    } else if ((flags & SSC_STRUCT)) {
      ptr = scope->tags.first;
      flags &= ~SSC_TAG;
    } else if ((flags & SSC_UNION)) {
      ptr = scope->tags.first;
      flags &= ~SSC_TAG;
    } else if ((flags & SSC_ENUM)) {
      ptr = scope->tags.first;
      flags &= ~SSC_TAG;
    } else if ((flags & SSC_LABEL)) {
      ptr = scope->labels.first;
      flags &= ~SSC_LABEL;
    } else {
      SWERR(("bad flags: 0x%08x", flags));
    }
      
    for (; ptr; ptr = ptr->next) {
      if (ptr->name == id) return ptr;
    }
  }

  if (scope->same_scope)
    return sema_search_this_scope(id, scope->same_scope, orig_flags);

  return NULL;
}

static struct sema_def *
sema_search_this_scope2(ident_t id, struct sema_scope *scope,
                        struct sema_scope *outer_scope,
                        int flags)
{
  if (outer_scope)
    return sema_search_this_scope(id, outer_scope, flags);
  return sema_search_this_scope(id, scope, flags);
}

int
sema_is_void_type(typeinfo_t t)
{
  return t->tag == CPT_BUILTIN && t->t_builtin.ind == C_VOID;
}

int
sema_is_character_type(typeinfo_t t)
{
  return t->tag == CPT_ARITH
    && (t->t_builtin.ind == C_CHAR
        || t->t_builtin.ind == C_SCHAR
        || t->t_builtin.ind == C_UCHAR);
}

int
sema_is_wchar_type(typeinfo_t t)
{
  return t->tag == CPT_ARITH
    && (t->t_builtin.ind == C_INT
        || t->t_builtin.ind == C_UINT
        || t->t_builtin.ind == C_LONG
        || t->t_builtin.ind == C_ULONG);
}

int
sema_is_va_list_type(typeinfo_t t)
{
  return t->tag == CPT_BUILTIN && t->t_builtin.ind == C_VA_LIST;
}

int
sema_is_void_array_type(typeinfo_t t)
{
  if (t->tag != CPT_ARRAY) return 0;
  if (sema_is_void_type(t->t_array.type)) return 1;
  return sema_is_void_array_type(t->t_array.type);
}

int
sema_is_string_type(typeinfo_t t)
{
  if (t->tag == CPT_ARRAY) {
    t = t->t_array.type;
  } else if (t->tag == CPT_POINTER) {
    t = t->t_pointer.type;
  } else {
    return 0;
  }
  return t->tag == CPT_ARITH
    && (t->t_builtin.ind == C_CHAR
        || t->t_builtin.ind == C_SCHAR
        || t->t_builtin.ind == C_UCHAR);
}

int
sema_is_wstring_type(typeinfo_t t)
{
  if (t->tag == CPT_ARRAY) {
    t = t->t_array.type;
  } else if (t->tag == CPT_POINTER) {
    t = t->t_pointer.type;
  } else {
    return 0;
  }
  return sema_is_wchar_type(t);
}

int
sema_is_varsize_type(typeinfo_t t)
{
  ASSERT(t);
  while (1) {
    switch (t->tag) {
    case CPT_ARITH:
    case CPT_BUILTIN:
    case CPT_ENUM:
    case CPT_POINTER:
    case CPT_FUNCTION:
      return 0;
    case CPT_AGGREG:
      /* variable-sized structures are not yet supported */
      return 0;
    case CPT_ARRAY:
      if (t->t_array.size_expr) return 1;
      t = t->t_array.type;
      break;
    default:
      SWERR(("sema_is_varsize_type: unhandled tag %d", t->tag));
    }
  }
  return 0;
}

size_t
sema_get_base_type_align(int t)
{
  switch (t) {
  case C_BOOL:
  case C_CHAR:
  case C_SCHAR:
  case C_UCHAR:
    return 1;
  case C_SHORT:
  case C_USHORT:
    return 2;
  case C_INT:
  case C_UINT:
  case C_LONG:
  case C_ULONG:
  case C_VA_LIST:
  case C_POINTER:
  case C_FLOAT:
  case C_FIMAGINARY:
  case C_FCOMPLEX:
    return 4;
  case C_LLONG:
  case C_ULLONG:
  case C_DOUBLE:
  case C_LDOUBLE:
  case C_DIMAGINARY:
  case C_LIMAGINARY:
  case C_DCOMPLEX:
  case C_LCOMPLEX:
    return 8;
  default:
    SWERR(("invalid built-in type: %d", t));
  }
  return 0;
}

size_t
sema_get_type_align(typeinfo_t t)
{
  ASSERT(t);
  switch (t->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
    return sema_get_base_type_align(t->t_builtin.ind);
  case CPT_ENUM:
    ASSERT(t->t_enum.def->align);
    return t->t_enum.def->align;
  case CPT_POINTER:
    return sema_get_base_type_align(C_POINTER);
  case CPT_ARRAY:
    return sema_get_type_align(t->t_array.type);
  case CPT_AGGREG:
    ASSERT(t->t_aggreg.def->align);
    return t->t_aggreg.def->align;
  default:
    SWERR(("invalid typeinfo tag: %d\n", t->tag));
  }
  return 0;
}

size_t
sema_to_next_align(size_t cur, size_t align)
{
  ASSERT(align);
  if (!(cur % align)) return cur;
  return (cur / align + 1) * align;
}

static int
err_void_not_ignored(pos_t *ppos)
{
  c_err(ppos, "void value is not ignored");
  return -1;
}

int
check_array_size(typeinfo_t ti, ident_t id, pos_t *ppos, int flag)
{
  struct sema_def *par;

  ASSERT(ti);
  switch (ti->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
  case CPT_ENUM:
    return 0;
  case CPT_POINTER:
    return check_array_size(ti->t_pointer.type, id, ppos, 1);
  case CPT_ARRAY:
    if (ti->t_array.elnum == SEMA_NO_SIZE && !flag
        && !ti->t_array.size_expr) {
      c_err(ppos, "array size missing in `%s'", ident_get(id));
      return -1;
    }
    if (ti->t_array.elnum == 0 && !flag) {
      c_err(ppos, "array size is 0 in `%s'", ident_get(id));
      return -1;
    }
    return check_array_size(ti->t_array.type, id, ppos, 0);
  case CPT_FUNCTION:
    if (check_array_size(ti->t_function.ret_type, id, ppos, 0) < 0)
      return -1;
    if (ti->t_function.par_scope
        && ti->t_function.par_scope == ti->t_function.impl_par_scope) {
      for (par = ti->t_function.par_scope->reg.first; par; par = par->next)
        if (check_array_size(par->type, id, ppos, 0) < 0)
          return -1;
    } else {
      if (ti->t_function.par_scope) {
        for (par = ti->t_function.par_scope->reg.first; par; par = par->next)
          if (check_array_size(par->type, id, ppos, 0) < 0)
            return -1;
      }
      if (ti->t_function.impl_par_scope) {
        for (par = ti->t_function.impl_par_scope->reg.first;par;par=par->next)
          if (check_array_size(par->type, id, ppos, 0) < 0)
            return -1;
      }
    }
    return 0;
  case CPT_AGGREG:
    return 0;
  default:
    SWERR(("bad typeinfo"));
  }
  return 0;
}

static int
sema_are_types_compatible(typeinfo_t t1, typeinfo_t t2)
{
  ASSERT(t1 && t2);
  if (t1->tag != t2->tag) return 0;

  switch (t1->tag) {
  case CPT_ARITH:
    if ((t1->t_builtin.bits&~STI_LMASK) != (t2->t_builtin.bits&~STI_LMASK))
      return 0;
    return c_get_balanced_type(3, t1->t_builtin.ind, t2->t_builtin.ind);
  case CPT_BUILTIN:
    if ((t1->t_builtin.bits&~STI_LMASK) != (t2->t_builtin.bits&~STI_LMASK))
      return 0;
    return t1->t_builtin.ind == t2->t_builtin.ind;
  case CPT_ENUM:
    if ((t1->t_enum.bits & ~STI_LMASK) != (t2->t_enum.bits & ~STI_LMASK))
      return 0;
    if (t1->t_enum.def != t2->t_enum.def) return 0;
    return 1;
  case CPT_POINTER:
    if (STI_GET_CV(t1->t_pointer.bits) != STI_GET_CV(t2->t_pointer.bits))
      return 0;
    if (!sema_are_types_compatible(t1->t_pointer.type, t2->t_pointer.type))
      return 0;
    return 1;
  case CPT_ARRAY:
    if (!sema_are_types_compatible(t1->t_array.type, t2->t_array.type))
      return 0;
    return 1;
  case CPT_FUNCTION:
    {
      struct s_function *f1 = &t1->t_function;
      struct s_function *f2 = &t2->t_function;
      struct sema_def   *p1, *p2;

      if (!sema_are_types_compatible(f1->ret_type, f2->ret_type))
        return 0;

      /* f1() ~ f2(args, ...) */
      if (STI_IS_FKR(f1->bits) && STI_IS_FVAR(f2->bits)) return 0;
      /* f1() ~ f2(?) */
      if (STI_IS_FKR(f1->bits)) return 1;
      /* f1(args, ...) ~ f2() */
      if (STI_IS_FVAR(f1->bits) && STI_IS_FKR(f2->bits)) return 0;
      /* f1(?) ~ f2() */
      if (STI_IS_FKR(f2->bits)) return 1;

      if (STI_IS_FVOID(f1->bits) && STI_IS_FVOID(f2->bits)) return 1;
      if (STI_IS_FVOID(f1->bits) || STI_IS_FVOID(f2->bits)) return 0;

      ASSERT(STI_IS_FNORM(f1->bits) || STI_IS_FVAR(f1->bits));
      ASSERT(STI_IS_FNORM(f2->bits) || STI_IS_FVAR(f2->bits));
      ASSERT(f1->par_scope->reg.first);
      ASSERT(f2->par_scope->reg.first);

      if (STI_GET_FFLAGS(f1->bits) != STI_GET_FFLAGS(f2->bits)) return 0;

      for (p1 = f1->par_scope->reg.first, p2 = f2->par_scope->reg.first;
           p1 && p2;
           p1 = p1->next, p2 = p2->next) {
        if (!sema_are_types_compatible(p1->type, p2->type)) return 0;
      }
      if (p1 || p2) return 0;

      return 1;
    }
  case CPT_AGGREG:
    if (!t1->t_aggreg.def || !t2->t_aggreg.def) return 0;
    return t1->t_aggreg.def == t2->t_aggreg.def;
  default:
    SWERR(("bad typeinfo"));
  }
}

static int
sema_types_compatible_no_CV(typeinfo_t t1, typeinfo_t t2)
{
  ASSERT(t1 && t2);
  if (t1->tag != t2->tag) return 0;

  switch (t1->tag) {
  case CPT_ARITH:
    return c_get_balanced_type(3, t1->t_builtin.ind, t2->t_builtin.ind);
  case CPT_BUILTIN:
    return t1->t_builtin.ind == t2->t_builtin.ind;
  case CPT_ENUM:
    if (t1->t_enum.def != t2->t_enum.def) return 0;
    return 1;
  case CPT_POINTER:
    if (!sema_types_compatible_no_CV(t1->t_pointer.type,t2->t_pointer.type))
      return 0;
    return 1;
  case CPT_ARRAY:
    if (!sema_types_compatible_no_CV(t1->t_array.type, t2->t_array.type))
      return 0;
    return 1;
  case CPT_FUNCTION:
    {
      struct s_function *f1 = &t1->t_function;
      struct s_function *f2 = &t2->t_function;
      struct sema_def   *p1, *p2;

      if (!sema_types_compatible_no_CV(f1->ret_type, f2->ret_type))
        return 0;

      if (STI_IS_FKR(f1->bits) && STI_IS_FVAR(f2->bits)) return 0;
      if (STI_IS_FKR(f1->bits)) return 1;
      if (STI_IS_FVAR(f1->bits) && STI_IS_FKR(f2->bits)) return 0;
      if (STI_IS_FKR(f2->bits)) return 1;

      if (STI_IS_FVOID(f1->bits) && STI_IS_FVOID(f2->bits)) return 1;
      if (STI_IS_FVOID(f1->bits) || STI_IS_FVOID(f2->bits)) return 0;

      ASSERT(STI_IS_FNORM(f1->bits) || STI_IS_FVAR(f1->bits));
      ASSERT(STI_IS_FNORM(f2->bits) || STI_IS_FVAR(f2->bits));
      ASSERT(f1->par_scope->reg.first);
      ASSERT(f2->par_scope->reg.first);

      if (STI_GET_FFLAGS(f1->bits) != STI_GET_FFLAGS(f2->bits)) return 0;

      for (p1 = f1->par_scope->reg.first, p2 = f2->par_scope->reg.first;
           p1 && p2;
           p1 = p1->next, p2 = p2->next) {
        if (!sema_types_compatible_no_CV(p1->type, p2->type)) return 0;
      }
      if (p1 || p2) return 0;

      return 1;
    }
  case CPT_AGGREG:
    if (!t1->t_aggreg.def || !t2->t_aggreg.def) return 0;
    return t1->t_aggreg.def == t2->t_aggreg.def;
  default:
    SWERR(("bad typeinfo"));
  }
}

static int
are_pointers_assignable(typeinfo_t l, typeinfo_t r)
{
  int b1, b2;

  ASSERT(l && l->tag == CPT_POINTER);
  ASSERT(r && r->tag == CPT_POINTER);
  if (sema_is_void_pointer(r)) return 1;
  if (sema_is_void_pointer(l)) return 1;

  // if pointers are not to primitive types, do generic check
  if (!l->t_pointer.type || l->t_pointer.type->tag != CPT_ARITH
      || !r->t_pointer.type || r->t_pointer.type->tag != CPT_ARITH)
    return sema_are_types_compatible(l, r);

  b1 = sema_typeinfo_to_index(l->t_pointer.type);
  b2 = sema_typeinfo_to_index(r->t_pointer.type);

  return c_get_balanced_type(2, b1, b2);
}

static int same_type_without_CV(typeinfo_t, typeinfo_t);

static int
does_discard_qualifier(typeinfo_t l, typeinfo_t r)
{
  int q1 = 0, q2 = 0;

  ASSERT(l && l->tag == CPT_POINTER);
  ASSERT(r && r->tag == CPT_POINTER);

  if (!same_type_without_CV(l->t_pointer.type, r->t_pointer.type)) return 0;
  if (!l->t_pointer.type || !l->t_pointer.type) return 0;
  q1 = typeinfo_get_cv(l->t_pointer.type);
  q2 = typeinfo_get_cv(r->t_pointer.type);

  // q2 must be subset of q1
  return !((q1 & q2) == q2);
}

static int same_type(typeinfo_t, typeinfo_t);
static int
same_type_without_CV(typeinfo_t t1, typeinfo_t t2)
{
  ASSERT(t1);
  ASSERT(t2);

  if (t1->tag != t2->tag) return 0;
  switch (t1->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
    return t1->t_builtin.ind == t2->t_builtin.ind;
  case CPT_ENUM:
    if (!t1->t_enum.def || !t2->t_enum.def) return 0;
    return t1->t_enum.def == t2->t_enum.def;
  case CPT_POINTER:
    return same_type(t1->t_pointer.type, t2->t_pointer.type);
  case CPT_ARRAY:
    return same_type(t1, t2);
  case CPT_FUNCTION:
    return same_type(t1, t2);
  case CPT_AGGREG:
    if (!t1->t_aggreg.def || !t2->t_aggreg.def) return 0;
    return t1->t_aggreg.def == t2->t_aggreg.def;
  default:
    SWERR(("unhandled typeinfo tag: %d", t1->tag));
  }
}

static int
same_type(typeinfo_t t1, typeinfo_t t2)
{
  struct sema_def *p1, *p2;

  ASSERT(t1);
  ASSERT(t2);

  if (t1->tag != t2->tag) return 0;
  switch (t1->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
    if (STI_GET_CV(t1->t_builtin.bits) != STI_GET_CV(t2->t_builtin.bits))
      return 0;
    return t1->t_builtin.ind == t2->t_builtin.ind;
  case CPT_ENUM:
    if (STI_GET_CV(t1->t_enum.bits) != STI_GET_CV(t2->t_enum.bits))
      return 0;
    if (!t1->t_enum.def || !t2->t_enum.def) return 0;
    return t1->t_enum.def == t2->t_enum.def;
  case CPT_POINTER:
    if ((t1->t_pointer.bits & ~STI_LMASK) != (t2->t_pointer.bits & ~STI_LMASK))
      return 0;
    return same_type(t1->t_pointer.type, t2->t_pointer.type);
  case CPT_ARRAY:
    return same_type(t1->t_array.type, t2->t_array.type);
  case CPT_FUNCTION:
    if (!same_type(t1->t_function.ret_type, t2->t_function.ret_type))
      return 0;
    if ((t1->t_function.bits&STI_FMASK) != (t2->t_function.bits&STI_FMASK))
      return 0;
    if (STI_IS_FVOID(t1->t_function.bits)) return 1;
    if (STI_IS_FKR(t1->t_function.bits)) return 1;
    for (p1 = t1->t_function.par_scope->reg.first,
           p2 = t2->t_function.par_scope->reg.first;
         p1 && p2;
         p1 = p1->next, p2 = p2->next) {
      if (p1->flags != p2->flags) return 0;
      if (!same_type(p1->type, p2->type)) return 0;
    }
    if (p1 || p2) return 0;
    return 1;
  case CPT_AGGREG:
    if (STI_GET_CV(t1->t_aggreg.bits) != STI_GET_CV(t2->t_aggreg.bits))
      return 0;
    if (!t1->t_aggreg.def || !t2->t_aggreg.def) return 0;
    return t1->t_aggreg.def == t2->t_aggreg.def;
  default:
    SWERR(("unhandled typeinfo tag: %d", t1->tag));
  }
}

static int
is_kr_compatible_types(typeinfo_t t1, typeinfo_t t2)
{
  int new_ind_2;
  struct sema_def *p1, *p2;

  ASSERT(t1);
  ASSERT(t2);

  /* t1 - prototype, t2 - implementation */
  if (t1->tag != t2->tag) return 0;
  switch (t1->tag) {
  case CPT_ARITH:
    if (STI_GET_CV(t1->t_builtin.bits) != STI_GET_CV(t2->t_builtin.bits))
      return 0;
    if (t1->t_builtin.ind == t2->t_builtin.ind) return 1;
    new_ind_2 = c_get_balanced_type(0, t2->t_builtin.ind, t2->t_builtin.ind);
    return t1->t_builtin.ind == new_ind_2;
  case CPT_BUILTIN:
    if (STI_GET_CV(t1->t_builtin.bits) != STI_GET_CV(t2->t_builtin.bits))
      return 0;
    return t1->t_builtin.ind == t2->t_builtin.ind;
  case CPT_ENUM:
    if (STI_GET_CV(t1->t_enum.bits) != STI_GET_CV(t2->t_enum.bits))
      return 0;
    if (!t1->t_enum.def || !t2->t_enum.def) return 0;
    return t1->t_enum.def == t2->t_enum.def;
  case CPT_POINTER:
    if ((t1->t_pointer.bits & ~STI_LMASK) != (t2->t_pointer.bits & ~STI_LMASK))
      return 0;
    return same_type(t1->t_pointer.type, t2->t_pointer.type);
  case CPT_ARRAY:
    return same_type(t1->t_array.type, t2->t_array.type);
  case CPT_FUNCTION:
    if (!same_type(t1->t_function.ret_type, t2->t_function.ret_type))
      return 0;
    if ((t1->t_function.bits&STI_FMASK) != (t2->t_function.bits&STI_FMASK))
      return 0;
    if (STI_IS_FVOID(t1->t_function.bits)) return 1;
    if (STI_IS_FKR(t1->t_function.bits)) return 1;
    for (p1 = t1->t_function.par_scope->reg.first,
           p2 = t2->t_function.par_scope->reg.first;
         p1 && p2;
         p1 = p1->next, p2 = p2->next) {
      if (p1->flags != p2->flags) return 0;
      if (!same_type(p1->type, p2->type)) return 0;
    }
    if (p1 || p2) return 0;
    return 1;
  case CPT_AGGREG:
    if (STI_GET_CV(t1->t_aggreg.bits) != STI_GET_CV(t2->t_aggreg.bits))
      return 0;
    if (!t1->t_aggreg.def || !t2->t_aggreg.def) return 0;
    return t1->t_aggreg.def == t2->t_aggreg.def;
  default:
    SWERR(("unhandled typeinfo tag: %d", t1->tag));
  }
}

static int
match_prototype(typeinfo_t *t1, int is_def_1, void **vp1,
                typeinfo_t *t2, int is_def_2, void **vp2)
{
  struct s_function *sf1, *sf2;
  struct sema_def   *p1, *p2;

  ASSERT(t1 && *t1);
  ASSERT(t2 && *t2);
  if ((*t1)->tag != CPT_FUNCTION || (*t2)->tag != CPT_FUNCTION) {
    return 0;
  }

  /* a function may be defined only once */
  if (is_def_1 && is_def_2) {
    return 0;
  }

  /* check return type */
  sf1 = &(*t1)->t_function;
  sf2 = &(*t2)->t_function;
  if (!same_type(sf1->ret_type, sf2->ret_type)) return 0;

  /* the following cases are possible
   *  K&R prototype (i.e. f()) and K&R implementation
   *    prototype is unchanged and is not checked against implementation
   *  K&R prototype and ANSI implementation
   *    implementation parameters are checked to be K&R compatible
   *    prototype is updated to parameters
   *  ANSI prototype and K&R implementation
   *    ANSI prototype is checked for compatibility and preserved
   *  ANSI prototype and implementation
   *  K&R prototype and K&R prototype
   *    nothing to do
   *  K&R prototype and ANSI prototype
   *    set ANSI prototype
   *  ANSI prototype and K&R prototype
   *    preserve ANSI prototype
   *  ANSI prototype and ANSI prototype
   *    check correspondence
   */

  if (!STI_IS_FKR(sf1->bits) && !STI_IS_FKR(sf2->bits)) {
    /* strictly compare prototypes */
    if (STI_GET_FFLAGS(sf1->bits) != STI_GET_FFLAGS(sf2->bits)) {
      return 0;
    }
    if (STI_IS_FVOID(sf1->bits)) {
      return 1;
    }
    for (p1 = sf1->par_scope->reg.first, p2 = sf2->par_scope->reg.first;
         p1 && p2; p1 = p1->next, p2 = p2->next) {
      if (!same_type(p1->type, p2->type))
        return 0;
    }
    if (p1 || p2) return 0;
    return 1;
  }
  if (STI_IS_FKR(sf1->bits) && STI_IS_FKR(sf2->bits)) {
    return 1;
  }

  if (is_def_1) {
    /* implementation vs. prototype */
    if (STI_IS_FKR(sf1->bits)) {
      // K&R implementation followed by ANSI prototype
      // the K&R implementation must be compatible in 
      // default promotions with the prototype
      if ((!sf1->impl_par_scope || !sf1->impl_par_scope->reg.first)
          && STI_IS_FVOID(sf2->bits)) {
        // both functions are void
        sf1->bits &= ~STI_FMASK;
        sf1->bits |= STI_FVOID;
        sf1->par_scope->reg.first = 0;
        return 1;
      }
      if ((!sf1->impl_par_scope || !sf1->impl_par_scope->reg.first)
          || STI_IS_FVOID(sf2->bits)) {
        return 0;
      }

      for (p1 = sf1->impl_par_scope->reg.first,
             p2 = sf2->par_scope->reg.first; p1 && p2;
           p1 = p1->next, p2 = p2->next) {
        if (!is_kr_compatible_types(p2->type, p1->type))
          return 0;
      }
      if (p1 || p2) return 0;
      sf1->bits &= ~STI_FMASK;
      sf1->bits |= STI_GET_FFLAGS(sf2->bits);
      sf1->par_scope = sf2->par_scope;
      return 1;
    } else /*if (STI_IS_FKR(sf2->bits))*/ {
      // prefer the implementation
      *t2 = *t1;
      if (vp1 && vp2) *vp2 = *vp1;
      return 1;
    }
  } if (is_def_2) { 
    /* prototype vs. implementation */
    if (STI_IS_FKR(sf1->bits)) {
      // prefer the implementation
      *t1 = *t2;
      if (vp1 && vp2) *vp1 = *vp2;
      return 1;
    } else /*if (STI_IS_FKR(sf2->bits))*/ {
      // ANSI prototype and K&R implementation
      // the K&R implementation must be compatible in 
      // default promotions with the prototype
      if (STI_IS_FVOID(sf1->bits) &&
          (!sf2->impl_par_scope || !sf2->impl_par_scope->reg.first)) {
        // both functions are void
        sf2->bits &= ~STI_FMASK;
        sf2->bits |= STI_FVOID;
        sf2->par_scope->reg.first = sf2->impl_par_scope->reg.first = 0;
        return 1;
      }
      if (STI_IS_FVOID(sf1->bits) ||
          (!sf2->impl_par_scope || !sf2->impl_par_scope->reg.first)) {
        return 0;
      }

      for (p1 = sf1->par_scope->reg.first, p2 = sf2->impl_par_scope->reg.first;
           p1 && p2; p1 = p1->next, p2 = p2->next) {
        if (!is_kr_compatible_types(p1->type, p2->type))
          return 0;
      }
      if (p1 || p2) return 0;
      sf2->bits &= ~STI_FMASK;
      sf2->bits |= STI_GET_FFLAGS(sf1->bits);
      sf2->par_scope = sf1->par_scope;
      return 1;
    }
  } else {
    /* prototype vs. prototype */
    if (STI_IS_FKR(sf1->bits)) {
      /* prefer the second prototype */
      *t1 = *t2;
      if (vp1 && vp2) *vp1 = *vp2;
      return 1;
    } else /*if (STI_IS_FKR(sf2->bits))*/ {
      /* prefer the first prototype */
      *t2 = *t1;
      if (vp1 && vp2) *vp2 = *vp1;
      return 1;
    }
  }

  /*
  if (STI_IS_FKR(sproto->bits)) return 1;
  if (STI_IS_FKR(sfunc->bits)) {
    if (!is_func) return 1;
    if (STI_IS_FVAR(sproto->bits)) return 0;
    if (STI_IS_FVOID(sproto->bits)) {
      if (!sfunc->par_scope->reg.first) {
        sfunc->params = 0;
        sfunc->bits &= ~STI_FKR;
        sfunc->bits |= STI_FVOID;
        return 1;
      }
      return 0;
    }
    ASSERT(STI_IS_FNORM(sproto->bits));
    p1 = sproto->params;
    q = sfunc->par_scope->reg.first;
    for (; p1 && q; p1 = p1->next, q = q->next) {
      if (!same_type(p1->type, q->type)) return 0;
    }
    if (p1 || q) return 0;
    sfunc->bits &= ~STI_FKR;
    sfunc->bits |= STI_FNORMAL;
    sfunc->params = sproto->params;
    return 1;
  }

  if (STI_GET_FFLAGS(sproto->bits) != STI_GET_FFLAGS(sfunc->bits))
    return 0;
  if (STI_IS_FVOID(sproto->bits)) return 1;
  for (p1 = sproto->params, p2 = sfunc->params;
       p1 && p2;
       p1 = p1->next, p2 = p2->next) {
    if (p1->stclass != p2->stclass) return 0;
    if (!same_type(p1->type, p2->type)) return 0;
  }
  if (p1 || p2) return 0;
  */
  abort();
}

static int enum_fit_types[] =
  {
    C_CHAR, C_UCHAR,
    C_SHORT, C_USHORT,
    C_INT, C_UINT,
    C_LONG, C_ULONG,
    C_LLONG, C_ULLONG,
    0
  };

static typeinfo_t
analyze_enum(tree_t node, struct sema_scope *scope,
             struct sema_scope *outer_scope,
             int dobj_flag, int use_only_flag, typeinfo_t base)
{
  pos_t *ppos;
  struct sema_def *d, *ed, *ed2;
  struct sema_scope *pitems;
  tree_t enumr;
  typeinfo_t eti, p;
  ident_t eid;
  c_value_t *prevval = 0, *curval = 0;
  c_value_t oneval, tmpval;
  int     tti;
  int ind, teind;
  int has_base_type = 0;
  int fp_enum = 0;

  ASSERT(node);
  ASSERT(node->kind == NODE_DSENUM);

  ppos = &node->node.pos.beg;
  if (node->node.refs[4]) {
    p = typeinfo_create_enum(0, node->node.refs[4]->id.id, 0);
  } else {
    p = typeinfo_create_enum(0, ident_empty, 0);
  }
  if (p->t_enum.id == ident_empty) {
    /* anonymous enumeration must define enumeration constants */
    if (!node->node.refs[6] && !node->node.refs[5]) {
      c_err(ppos, "Anonymous enumeration must define enumeration constants");
      return 0;
    }
    if (!node->node.refs[6]) {
      c_warn(ppos, "Empty anonymous enumeration");
      return 0;
    }
  }

  if (base && base->tag != CPT_ARITH) {
    c_err(ppos, "invalid enumeration base type");
    base = 0;
  }
  if (base
      && (base->t_builtin.ind < C_FIRST_ARITH
          || base->t_builtin.ind > C_LAST_ARITH)) {
    c_err(ppos, "invalid enumeration base type");
    base = 0;
  }
  if (base && base->t_builtin.ind >= C_FIRST_FLT
      && base->t_builtin.ind <= C_LAST_FLT) {
    fp_enum = 1;
    if (p->t_enum.id != ident_empty) {
      c_err(ppos, "floating-point enumeration must be anonymous");
      base = 0;
      fp_enum = 0;
    }
  }
  if (base) has_base_type = 1;

  /* enum bar ...; case */
  if (!node->node.refs[6]) {
    if (!dobj_flag) {
      /* enum bar; --- forward enumeration declaration (GNUism) */
      /* if such enum already defined in the current scope, do nothing
       * else, create yet empty enumeration
       */
      if (use_only_flag) {
        d = sema_search_scope(p->t_enum.id, scope, SSC_TAG);
      } else {
        d = sema_search_this_scope2(p->t_enum.id, scope, outer_scope, SSC_TAG);
      }
      if (!d) {
        d = sema_put_ident2(scope, outer_scope, SSC_ENUM, p->t_enum.id,
                            ppos, NULL, NULL, node);
        // also, if we are at param definition level, issue a warning
        if (scope->g.tag == SSC_ARG_SCOPE) {
          c_err(ppos, "`enum %s' defined inside parameter list",
                ident_get(p->t_enum.id));
        }
      }
    } else {
      /* enum bar foo; --- definition of enumerate variables */
      /*
       * search for this enumerated type in all scopes
       */
      d = sema_search_scope(p->t_enum.id, scope, SSC_TAG);
      if (!d) {
        // hmm, according to GNU C we need to add enum at this level
        d = sema_put_ident(scope, SSC_ENUM, p->t_enum.id,
                           ppos, NULL, 0, NULL, node);
        // also, if we are at param definition level, issue a warning
        if (scope->g.tag == SSC_ARG_SCOPE) {
          c_err(ppos, "`enum %s' defined inside parameter list",
                ident_get(p->t_enum.id));
        }
      }
    }
    ASSERT(d);
    if (!(d->flags & SSC_ENUM)) {
      c_err(ppos, "`%s' defined as wrong kind of tag",
            ident_get(p->t_enum.id));
      return 0;
    }

    p->t_enum.def = d;
    return p;
  }

  d = NULL;
  if (p->t_enum.id != ident_empty) {
    /* check, that enumeration tag is not yet defined */
    d = sema_search_this_scope2(p->t_enum.id, scope, outer_scope, SSC_TAG);
    if (d && (d->flags & SSC_ENUM) && d->nest) {
      c_err(ppos, "redeclaration of `enum %s'", ident_get(p->t_enum.id));
      return 0;
    }
    if (d && !(d->flags & SSC_ENUM)) {
      c_err(ppos, "`%s' defined as wrong kind of tag",
            ident_get(p->t_enum.id));
      return 0;
    }
  }

  /* issue warning if inside parameter list */
  if (scope->g.tag == SSC_ARG_SCOPE) {
    if (p->t_enum.id == ident_empty) {
      c_warn(ppos, "enum defined inside parameter list");
    } else {
      c_warn(ppos, "`enum %s' defined inside parameter list",
             ident_get(p->t_enum.id));
    }
  }

  /* add definition of enumerated type itself */
  pitems = sema_scope_create(scope);
  if (!d) {
    d = sema_put_ident2(scope, outer_scope, SSC_ENUM, p->t_enum.id,
                        ppos, NULL, NULL, node);
  }
  ASSERT(d);
  ASSERT(!d->nest);
  d->nest = pitems;
  d->type = base;
  /* FIXME! Need a better algorithm of enumerated type detection... */
  if (!d->type) d->type = sema_index_to_typeinfo(C_INT);

  memset(&oneval, 0, sizeof(oneval));
  oneval.tag = C_INT;
  oneval.v.ct_int = 1;

  if (has_base_type && p->t_enum.id == ident_empty) {
    d->align = sema_get_type_align(d->type);
    d->size = sema_get_type_size(d->type);
    ind = sema_typeinfo_to_index(d->type);

    for (enumr = node->node.refs[6]; enumr; enumr = enumr->node.refs[0]) {
      ASSERT(enumr->kind == NODE_ENUMERATOR);
      if (!enumr->node.refs[3]) continue;
      ppos = &enumr->node.pos.beg;
      eid = enumr->node.refs[3]->id.id;

      /* calculate its value */
      if (enumr->node.refs[5]) {
        if (analyze_expr(enumr->node.refs[5], scope, EK_VALUE, 0, 0) < 0)
          continue;
        ALLOC(curval);

        if (fp_enum) {
          if (tree_fold(enumr->node.refs[5], curval) < 0) {
            c_err(ppos, "enumerator value must be constant");
            continue;
          }
          if (curval->tag < C_FIRST_ARITH || curval->tag > C_LAST_ARITH) {
            c_err(ppos, "invalid enumerator type");
            continue;
          }
        } else {
          if (tree_fold(enumr->node.refs[5], curval) < 0
              || !c_value_is_integral(curval)) {
            c_err(ppos, "enumerator value for `%s' not integer constant",
                  ident_get(eid));
            continue;
          }
        }
      } else {
        if (fp_enum) {
          c_err(ppos, "all floating-point enumerators must be explicit");
          continue;
        }

        if (!prevval) {
          ALLOC(curval);
          memset(curval, 0, sizeof(*curval));
          curval->tag = C_INT;
          curval->v.ct_int = 0;
        } else {
          ALLOC(curval);
          if (c_value_operation(ppos,COP_ADD,prevval,&oneval,0,curval)<0) {
            SWERR(("tValue_operation failed"));
          }
        }
      }

      /* cast the curval to the base type */
      tmpval = *curval;
      c_value_cast(&tmpval, ind, curval);
      prevval = curval;

      /* check, that the constant is already defined in this enum */
      ed = sema_search_this_scope(eid, pitems, SSC_REGULAR);
      if (ed) {
        c_err(ppos, "redeclaration of `%s'", ident_get(eid));
        c_err(ed->ppos, "`%s' previously declared here", ident_get(eid));
        continue;
      }
      ed = sema_search_this_scope2(eid, scope, outer_scope, SSC_REGULAR);
      if (ed) {
        if (!ed->type || ed->type->tag != CPT_ENUM) {
          c_err(ppos, "`%s' redeclared as different kind of symbol",
                ident_get(eid));
          c_err(ed->ppos, "previous declaration of `%s'", ident_get(eid));
          continue;
        }
        if (!(ed2 = ed->type->t_enum.def) || !ed2->type
            || ed2->name != ident_empty
            || ed2->type->tag != CPT_ARITH
            || ed2->type->t_builtin.ind != ind) {
          c_err(ppos, "conflicting types for `%s'", ident_get(eid));
          c_err(ed->ppos, "previous declaration of `%s'", ident_get(eid));
          continue;
        }
        if (!ed->value || c_value_compare(ed->value, curval) != 0) {
          c_err(ppos, "conflicting values for `%s'", ident_get(eid));
          c_err(ed->ppos, "previous declaration of `%s'", ident_get(eid));
          continue;
        }

        c_warn(ppos, "`%s' is already declared", ident_get(eid));
        c_warn(ed->ppos, "previous declaration of `%s'", ident_get(eid));
        //eti = typeinfo_create_enum(STI_CONST, p->t_enum.id, d);
        eti = typeinfo_create_enum(0, p->t_enum.id, d);
        ed = sema_put_ident(pitems, SSC_REGULAR, enumr->node.refs[3]->id.id,
                            ppos, eti, 0, NULL, enumr);
        ed->host = d;
        ed->flags |= SSC_ENUMCONST;
        ed->value = curval;
        ed->nomif_flag = 1;
        continue;
      }

      //eti = typeinfo_create_enum(STI_CONST, p->t_enum.id, d);
      eti = typeinfo_create_enum(0, p->t_enum.id, d);
      ed = sema_put_ident(pitems, SSC_REGULAR, enumr->node.refs[3]->id.id,
                          ppos, eti, 0, NULL, enumr);
      ed->host = d;
      ed->flags |= SSC_ENUMCONST;
      ed->value = curval;
      //eti = typeinfo_create_enum(STI_CONST, p->t_enum.id, d);
      eti = typeinfo_create_enum(0, p->t_enum.id, d);
      ed2 = sema_put_ident2(scope, outer_scope, SSC_REGULAR,
                            enumr->node.refs[3]->id.id,
                            ppos, eti, NULL, enumr);
      ed2->link = ed;
      ed->link = ed2;
      ed2->host = d;
      ed2->flags |= SSC_ENUMCONST;
      ed2->value = curval;
    }
    p->t_enum.def = d;
    return p;
  }

  for (enumr = node->node.refs[6]; enumr; enumr = enumr->node.refs[0]) {
    ASSERT(enumr->kind == NODE_ENUMERATOR);
    if (!enumr->node.refs[3]) continue;
    ppos = &enumr->node.pos.beg;
    eid = enumr->node.refs[3]->id.id;

    /*
     * Check, that this constant already defined
     */
    /* check the same type */
    ed = sema_search_this_scope(eid, pitems, SSC_REGULAR);
    if (ed) {
      c_err(ppos, "redeclaration of `%s'", ident_get(eid));
      c_err(ed->ppos, "`%s' previously declared here", ident_get(eid));
      continue;
    }
    /* check other types at the same scope */
    ed = sema_search_this_scope2(eid, scope, outer_scope, SSC_REGULAR);
    if (ed) {
      if (ed->type && ed->type->tag == CPT_ENUM) {
        c_err(ppos, "conflicting types for `%s'", ident_get(eid));
      } else {
        c_err(ppos, "`%s' redeclared as different kind of symbol",
              ident_get(eid));
      }
      c_err(ed->ppos, "previous declaration of `%s'", ident_get(eid));
      continue;
    }

    if (enumr->node.refs[5]) {
      if (analyze_expr(enumr->node.refs[5], scope, EK_VALUE, 0, 0) < 0)
        continue;
      ALLOC(curval);

      if (tree_fold(enumr->node.refs[5], curval) < 0
          || !c_value_is_integral(curval)) {
        c_err(ppos, "enumerator value for `%s' not integer constant",
              ident_get(eid));
        continue;
      }
      prevval = curval;
    } else {
      if (!prevval) {
        ALLOC(curval);
        memset(curval, 0, sizeof(*curval));
        curval->tag = C_INT;
        curval->v.ct_int = 0;
        prevval = curval;
      } else {
        ALLOC(curval);
        if (c_value_operation(ppos,COP_ADD,prevval,&oneval,0,curval)<0) {
          SWERR(("tValue_operation failed"));
        }
        prevval = curval;
      }
    }

    //eti = typeinfo_create_enum(STI_CONST, p->t_enum.id, d);
    eti = typeinfo_create_enum(0, p->t_enum.id, d);
    ed = sema_put_ident(pitems, SSC_REGULAR, enumr->node.refs[3]->id.id,
                        ppos, eti, 0, NULL, enumr);
    ed->host = d;
    ed->flags |= SSC_ENUMCONST;
    ed->value = curval;
    //eti = typeinfo_create_enum(STI_CONST, p->t_enum.id, d);
    eti = typeinfo_create_enum(0, p->t_enum.id, d);
    ed2 = sema_put_ident2(scope, outer_scope, SSC_REGULAR,
                          enumr->node.refs[3]->id.id,
                          ppos, eti, NULL, enumr);
    ed2->link = ed;
    ed->link = ed2;
    ed2->host = d;
    ed2->flags |= SSC_ENUMCONST;
    ed2->value = curval;
  }

  if (!has_base_type) {
    /* rescan the enumerated constants and find the best type */
    for (tti = 0; enum_fit_types[tti]; tti++) {
      for (ed = pitems->reg.first; ed; ed = ed->next) {
        if (!ed->value) continue;
        if (!c_value_fits(ed->value, enum_fit_types[tti]))
          break;
      }
      if (!ed) break;
    }
    teind = enum_fit_types[tti];
    ASSERT(teind);
    ind = teind;
    d->type = sema_index_to_typeinfo(ind);
  }

  d->align = sema_get_type_align(d->type);
  d->size = sema_get_type_size(d->type);
  teind = ind = sema_typeinfo_to_index(d->type);

  /* cast all enumerated constants to the selected type */
  for (ed = pitems->reg.first; ed; ed = ed->next) {
    if (!ed->value) {
      ALLOC(curval);
      curval->tag = teind;
      ed->value = curval;
      ed->link->value = curval;
    } else {
      curval = ed->value;
      oneval = *curval;
      c_value_cast(&oneval, teind, curval);
    }
  }

  p->t_enum.def = d;
  return p;
}

static typeinfo_t make_declspec(tree_t, struct sema_scope *,
                                struct sema_scope *, int, int);

static int
analyze_field_definition(tree_t node, struct sema_def *struct_def,
                         struct sema_scope *scope,
                         struct sema_scope *outer_scope,
                         typeinfo_t ti)
{
  ident_t id = ident_empty;
  pos_t *idp = 0, *ppos = 0;
  int bits = -1;
  typeinfo_t tt;
  struct sema_def *d = 0;
  tree_t idnode;

  ASSERT(node);
  ASSERT(node->kind == NODE_STRUCTDECLR);

  idnode = tree_get_ident_node(node->node.refs[3]);
  if (idnode) {
    id = idnode->id.id;
    idp = &idnode->id.pos.beg;
  }
  tt = make_typeinfo(NULL, scope, outer_scope, ti, node->node.refs[3],1,0,0);
  if (!tt) return -1;

  /* if ti is an anonymous enum, immediately set the type to the base type */
  if (tt->tag == CPT_ENUM && !tt->t_enum.def->name) {
    tt = tt->t_enum.def->type;
  }

  if (check_array_size(tt, id, idp, 1) < 0) return -1;
  if (tt->tag == CPT_FUNCTION) {
    c_err(idp, "field `%s' declared as a function", ident_get(id));
    return -1;
  }
  if (sema_is_void_type(tt)) {
    c_err(idp, "`%s' defined as void object", ident_get(id));
    return -1;
  }
  if (sema_is_void_array_type(tt)) {
    c_err(idp, "`%s' defined as array of voids", ident_get(id));
    return -1;
  }
  if (sema_get_type_size(tt) == SEMA_NO_SIZE) {
    c_err(idp, "storage size of `%s' isn't known", ident_get(id));
    return -1;
  }

  while (node->node.refs[5]) {
    c_value_t val, val1;
    int idx = 0;
    /* calculate bitfield width */
    ppos = &node->node.refs[5]->gen.pos.beg;
    if (analyze_expr(node->node.refs[5], scope, EK_VALUE, 0, 0) < 0) {
      c_err(ppos, "constant expression expected");
      break;
    }
    if (tree_fold(node->node.refs[5], &val) < 0) {
      c_err(ppos, "constant expression expected");
      break;
    }
    if (!c_value_is_integral(&val)) {
      c_err(ppos, "bitfield size has non-integer type");
      break;
    }
    if (c_value_is_negative(&val)) {
      c_err(ppos, "bitfield size is negative");
      break;
    }
    if (c_value_is_large(&val)) {
      c_err(ppos, "bitfield size is too large");
      break;
    }
    c_value_cast(&val, C_ULONG, &val1);
    bits = (int) val1.v.ct_ulint;
    if (bits > 64) {
      c_warn(ppos, "bitfield size exceeds 64 bits (truncated)");
      bits = 64;
    }
    if (!bits) {
      c_err(ppos, "bitfield size is 0");
      bits = 0;
      break;
    }
    if (tt->tag != CPT_ARITH) {
      c_err(ppos, "bitfield has invalid type");
      bits = 0;
      break;
    }
    idx = sema_typeinfo_to_index(tt);
    if (idx < C_FIRST_INT || idx > C_LAST_INT) {
      c_err(ppos, "bitfield has invalid type");
      bits  = 0;
      break;
    }
    /* FIXME: hard-coded integer type sizes!!! */
    if (idx == C_LLONG || idx == C_ULLONG) break;
    if (bits > 32) {
      if (c_is_unsigned_type(idx)) idx = C_ULLONG;
      else idx = C_LLONG;
      c_warn(ppos, "width of `%s' exceeds its type (`%s' assumed)",
             ident_get(id), c_builtin_str(idx));
      tt = sema_index_to_typeinfo(idx);
      break;
    }
    if (idx == C_INT || idx == C_UINT || idx == C_LONG || idx == C_ULONG)
      break;
    if (bits > 16) {
      if (c_is_unsigned_type(idx)) idx = C_UINT;
      else idx = C_INT;
      c_warn(ppos, "width of `%s' exceeds its type (`%s' assumed)",
             ident_get(id), c_builtin_str(idx));
      tt = sema_index_to_typeinfo(idx);
      break;
    }
    if (idx == C_SHORT || idx == C_USHORT) break;
    if (bits > 8) {
      if (c_is_unsigned_type(idx)) idx = C_USHORT;
      else idx = C_SHORT;
      c_warn(ppos, "width of `%s' exceeds its type (`%s' assumed)",
             ident_get(id), c_builtin_str(idx));
      tt = sema_index_to_typeinfo(idx);
      break;
    }    
    break;
  }

  /* check redefinition cases, etc */
  if (id != ident_empty) {
    d = sema_search_this_scope(id, scope, SSC_REGULAR);
    if (d) {
      c_err(idp, "duplicate field `%s'", ident_get(id));
      return -1;
    }
  }
  d = sema_put_ident(scope, SSC_REGULAR, id, idp, tt, 0, NULL, node);
  d->host = struct_def;
  if (bits > 0) {
    d->bit_num = bits;
  }
  node->node.sema = sinfo_create_iduse(d);
  return 0;
}

static typeinfo_t
analyze_struct(tree_t node, struct sema_scope *scope,
               struct sema_scope *outer_scope,
               int dobj_flag, int use_only_flag)
{
  pos_t *ppos = 0;
  int nspace = 0, sti = 0;
  struct sema_def *d = 0, *fd;
  ident_t id = ident_empty;
  char const *aggn = "";
  tree_t pf, fdeclr;
  int count;
  int stclass;
  typeinfo_t fti;
  struct sema_scope *inner = 0;
  size_t cursz, curalign;

  ASSERT(node);
  ASSERT(node->kind == NODE_DSAGGREG);

  ppos = &node->node.pos.beg;
  if (node->node.refs[4]) {
    id = node->node.refs[4]->id.id;
  }
  switch (node->node.refs[3]->kind) {
  case TOK_UNION: 
    nspace = SSC_UNION;  sti = STI_UNION;  aggn = "union";  break;
  case TOK_STRUCT:
    nspace = SSC_STRUCT; sti = STI_STRUCT; aggn = "struct"; break;
  default:
    SWERR(("unhandled aggregate tag: %d", node->node.refs[3]->kind));
  }
  if (!node->node.refs[5]) {
    /* struct name [vars]; */
    if (!node->node.refs[4]) {
      /* actually, this is a syntax error */
      c_err(ppos, "anonymous structure must contain fields");
      return 0;
    }

    if (!dobj_flag) {
      /* struct name;*/
      if (use_only_flag) {
        d = sema_search_scope(id, scope, SSC_TAG);
      } else {
        d = sema_search_this_scope2(id, scope, outer_scope, SSC_TAG);
      }
      if (d) {
        if (SSC_GET_NSPACE(d->flags) != nspace) {
          c_err(ppos, "`%s %s' declared as different kind of tag",
                aggn, ident_get(id));
          return 0;
        }
        return typeinfo_create_aggreg(sti, id, d);
      }
      d = sema_put_ident2(scope,outer_scope,nspace,id,ppos,NULL,NULL,node);
      if (scope->g.tag == SSC_ARG_SCOPE) {
        c_warn(ppos, "`%s %s' defined inside parameter list",
               aggn, ident_get(id));
      }
      return typeinfo_create_aggreg(sti, id, d);
    }

    /* struct name var; */
    d = sema_search_scope(id, scope, SSC_TAG);
    if (d) {
      if (SSC_GET_NSPACE(d->flags) != nspace) {
        c_err(ppos, "`%s %s' declared as different kind of tag",
              aggn, ident_get(id));
        return 0;
      }
      return typeinfo_create_aggreg(sti, id, d);
    }
    /*
    c_warn(ppos, "`%s %s' was not previously declared", aggn, ident_get(id));
    */
    if (scope->g.tag == SSC_ARG_SCOPE) {
      c_warn(ppos, "`%s %s' defined inside parameter list",
             aggn, ident_get(id));
    }
    d = sema_put_ident2(scope,outer_scope,nspace,id,ppos,NULL,NULL,node);
    return typeinfo_create_aggreg(sti, id, d);
  }

  /* struct [name] { fields } [var]; */
  if (id != ident_empty) {
    d = sema_search_this_scope2(id, scope, outer_scope, SSC_TAG);
  }
  if (d && SSC_GET_NSPACE(d->flags) != nspace) {
    c_err(ppos, "`%s %s' redeclared as different kind of tag",
          aggn, ident_get(id));
    return 0;
  }
  if (d && d->nest) {
    c_err(ppos, "`%s %s' redeclared", aggn, ident_get(id));
    return 0;
  }
  if (!d) {
    if (scope->g.tag == SSC_ARG_SCOPE) {
      c_warn(ppos, "`%s %s' defined inside parameter list",
             aggn, ident_get(id));
    }
    d = sema_put_ident2(scope, outer_scope, nspace, id, ppos, NULL,NULL, node);
  }

  ASSERT(d);
  inner = sema_scope_create(scope);
  d->nest = inner;
  if (!outer_scope) outer_scope = scope;

  for (pf = node->node.refs[6]; pf; ) {
    ASSERT(pf->kind == NODE_DECL);

    stclass = sema_get_storclass(pf->node.refs[3], 0);
    if (stclass) {
      c_err(&pf->node.pos.beg,
            "storage class is not allowed inside aggregate types");
      stclass = 0;
    }

    count = 0;
    fdeclr = pf->node.refs[4];
    while (fdeclr) {
      ASSERT(fdeclr->kind == NODE_STRUCTDECLR);
      count++;
      fdeclr = fdeclr->node.refs[0];
    }

    if (!count) {
      make_declspec(pf->node.refs[3], scope, outer_scope, 0, 0);
      pf = pf->node.refs[0];
      continue;
    }

    fti = make_declspec(pf->node.refs[3], scope, outer_scope, 1, 0);
    if (fti) {
      fdeclr = pf->node.refs[4];
      while (fdeclr) {
        analyze_field_definition(fdeclr, d, inner, outer_scope, fti);
        fdeclr = fdeclr->node.refs[0];
      }
    }

    pf = pf->node.refs[0];
  }

  /* calculate size and alignment of structure */
  cursz = curalign = 0;
  for (fd = inner->reg.first; fd; fd = fd->next) {
    size_t t;

    t = sema_get_type_align(fd->type);
    if (t > curalign) curalign = t;
    cursz = sema_to_next_align(cursz, t);
    t = sema_get_type_size(fd->type);
    cursz += t;
  }
  if (curalign == 0) curalign = 4;
  cursz = sema_to_next_align(cursz, curalign);
  if (cursz == 0) cursz = 4;
  d->size = cursz;
  d->align = curalign;

  return typeinfo_create_aggreg(sti, id, d);
}

static void
make_integral(typeinfo_t p, int short_count, int long_count,
              int signed_flag, int unsigned_flag,
              int imag_flag, int compl_flag)
{
  ASSERT(p);
  ASSERT(p->tag == CPT_ARITH);

  if (!p->t_builtin.ind) p->t_builtin.ind = C_INT;
  if (unsigned_flag) {
    if (p->t_builtin.ind == C_CHAR) p->t_builtin.ind = C_UCHAR;
    else if (p->t_builtin.ind == C_INT) {
      if (short_count) p->t_builtin.ind = C_USHORT;
      else if (long_count == 1) p->t_builtin.ind = C_ULONG;
      else if (long_count == 2) p->t_builtin.ind = C_ULLONG;
      else p->t_builtin.ind = C_UINT;
    } else {
      SWERR(("unexpected ind: %d", p->t_builtin.ind));
    }
  } else {
    if (p->t_builtin.ind == C_CHAR) {
      if (signed_flag) p->t_builtin.ind = C_SCHAR;
    } else if (p->t_builtin.ind == C_INT) {
      if (short_count) p->t_builtin.ind = C_SHORT;
      else if (long_count == 1) p->t_builtin.ind = C_LONG;
      else if (long_count == 2) p->t_builtin.ind = C_LLONG;
    } else if (p->t_builtin.ind == C_FLOAT) {
      if (imag_flag) p->t_builtin.ind = C_FIMAGINARY;
      else if (compl_flag) p->t_builtin.ind = C_FCOMPLEX;
    } else if (p->t_builtin.ind == C_DOUBLE) {
      if (long_count) {
        if (imag_flag) p->t_builtin.ind = C_LIMAGINARY;
        else if (compl_flag) p->t_builtin.ind = C_LCOMPLEX;
        else p->t_builtin.ind = C_LDOUBLE;
      } else {
        if (imag_flag) p->t_builtin.ind = C_DIMAGINARY;
        else if (compl_flag) p->t_builtin.ind = C_DCOMPLEX;
      }
    }
  }
}

static typeinfo_t
make_declspec(tree_t declspec, struct sema_scope *scope,
              struct sema_scope *outer_scope,
              int decl_obj_flag, int use_only_flag)
{
  typeinfo_t      p = NULL;
  int node_count = 0;
  int useful_count = 0;
  int cv_bits = 0, cv = 0;
  int short_count = 0;
  int long_count = 0;
  int signed_flag = 0;
  int unsigned_flag = 0;
  int compl_flag = 0;
  int imag_flag = 0;
  struct sema_def *td = 0;
  pos_t *ppos = 0;

  if (declspec) {
    ppos = &declspec->node.pos.beg;
  }

  /* scan declaration specifier to extract bits */
  while (1) {
    if (!declspec) break;

    switch (declspec->kind) {
    case NODE_DSSTORAGE:
      node_count++;
      break;

    case NODE_DSQUAL:
      node_count++;
      if (declspec->node.refs[3]->kind == TOK_CONST) {
        cv_bits |= STI_CONST;
      }
      if (declspec->node.refs[3]->kind == TOK_VOLATILE) {
        cv_bits |= STI_VOLATILE;
      } 
      if (declspec->node.refs[3]->kind == TOK_RESTRICT) {
        cv_bits |= STI_RESTRICT;
      } 
      break;

    case NODE_DSSTDTYPE:
      node_count++;

      switch (declspec->node.refs[3]->kind) {
      case TOK_SHORT:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (short_count || long_count) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        if (p->t_builtin.ind && p->t_builtin.ind != C_INT) goto bad_declspec;
        short_count++;
        break;
      case TOK_LONG:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (short_count || long_count > 1) goto bad_declspec;
        if (p->t_builtin.ind && p->t_builtin.ind != C_INT
            && p->t_builtin.ind != C_DOUBLE)
          goto bad_declspec;
        if (long_count > 0 && p->t_builtin.ind == C_DOUBLE)
          goto bad_declspec;
        long_count++;
        break;
      case TOK_SIGNED:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (unsigned_flag) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        if (p->t_builtin.ind && p->t_builtin.ind != C_INT
            && p->t_builtin.ind != C_CHAR)
          goto bad_declspec;
        signed_flag = 1;
        break;
      case TOK_UNSIGNED:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (signed_flag) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        if (p->t_builtin.ind && p->t_builtin.ind != C_INT
            && p->t_builtin.ind != C_CHAR)
          goto bad_declspec;
        unsigned_flag = 1;
        break;
      case TOK_VOID:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (p) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        if (short_count || long_count) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        p = typeinfo_create_builtin(0, C_VOID);
        break;
      case TOK_VA_LIST:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (p) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        if (short_count || long_count) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        p = typeinfo_create_builtin(0, C_VA_LIST);
        break;
      case TOK_CHAR:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (short_count || long_count) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        p->t_builtin.ind = C_CHAR;
        break;
      case TOK_INT:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        p->t_builtin.ind = C_INT;
        break;
      case TOK_FLOAT:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (short_count || long_count) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        p->t_builtin.ind = C_FLOAT;
        break;
      case TOK_DOUBLE:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (short_count || long_count > 1) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        p->t_builtin.ind = C_DOUBLE;
        break;
      case TOK__BOOL:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (p && p->t_builtin.ind) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (short_count || long_count) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        p->t_builtin.ind = C_BOOL;
        break;
      case TOK__IMAGINARY:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (p->t_builtin.ind && p->t_builtin.ind != C_FLOAT
            && p->t_builtin.ind != C_DOUBLE)
          goto bad_declspec;
        if (short_count || long_count > 1) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        imag_flag = 1;
        break;
      case TOK__COMPLEX:
        if (p && p->tag != CPT_ARITH) goto bad_declspec;
        if (!p) p = typeinfo_create_arith(0, 0);
        if (p->t_builtin.ind && p->t_builtin.ind != C_FLOAT
            && p->t_builtin.ind != C_DOUBLE)
          goto bad_declspec;
        if (short_count || long_count > 1) goto bad_declspec;
        if (signed_flag || unsigned_flag) goto bad_declspec;
        if (compl_flag || imag_flag) goto bad_declspec;
        compl_flag = 1;
        break;

      default:
        SWERR(("bad type: %d", declspec->node.refs[3]->kind));
      }
      break;

    case NODE_DSTYPENAME:
      node_count++;
      if (p) goto bad_declspec;
      p = typeinfo_create_typedef(0, declspec->node.refs[3]->id.id, 0);
      break;

    case NODE_DSAGGREG:
      node_count++;
      useful_count++;
      if (p) goto bad_declspec;
      p = analyze_struct(declspec, scope, outer_scope, decl_obj_flag,
                         use_only_flag);
      if (!p) return 0;
      break;

    case NODE_DSENUM:
      node_count++;
      useful_count++;
      if (p && p->tag != CPT_ARITH) goto bad_declspec;
      if (p) {
        make_integral(p, short_count, long_count, signed_flag, unsigned_flag,
                      imag_flag, compl_flag);
      }
      p = analyze_enum(declspec, scope, outer_scope, decl_obj_flag,
                       use_only_flag, p);
      if (!p) return 0;
      break;

    case NODE_DSTYPEOF:
      node_count++;
      useful_count++;
      if (p) goto bad_declspec;
      if (analyze_expr(declspec->node.refs[5], scope, EK_VALUE, 0, 0) < 0)
        return 0;
      p = typeinfo_clone(sema_get_expr_type(declspec->node.refs[5]), 0);
      if (!p) return 0;
      break;

      /* FIXME: handle inline... */
    case NODE_DSFUNCSPEC:
      break;

    default:
      BADNODE(declspec);
    }
    declspec = declspec->node.refs[0];
  }

  if (!decl_obj_flag && node_count > 0 && !useful_count) {
    c_warn(ppos, "empty declaration");
  }

  if (!p && (imag_flag || compl_flag)) {
    p = typeinfo_create_arith(0, C_DOUBLE);
  }
  if (p && !p->t_builtin.ind && (imag_flag || compl_flag)) {
    p->t_builtin.ind = C_DOUBLE;
  }
  if (!p) p = typeinfo_create_arith(0, C_INT);
  if (p->tag == CPT_ARITH) {
    make_integral(p, short_count, long_count, signed_flag, unsigned_flag,
                  imag_flag, compl_flag);
  }
  typeinfo_set_bits(p, cv_bits);
  if (p->tag != CPT_TYPEDEF) return p;

  ASSERT(p->t_typedef.id != ident_empty);
  td = sema_search_scope(p->t_typedef.id, scope, SSC_REGULAR);
  if (!td) {
    // actually, typedefs are detected at the parse level,
    // so, if a typedef declaration does not exist, we should
    // get parse error.
    c_err(ppos, "type `%s' is not defined", ident_get(p->t_typedef.id));
    return NULL;
  }

  ASSERT(td->name == p->t_typedef.id);
  ASSERT(td->flags == (SSC_TYPEDEF | SSC_REGULAR));
  cv = typeinfo_get_cv(td->type);
  if ((cv & STI_CONST) && (cv_bits & STI_CONST)) {
    c_warn(ppos, "duplicated `const'");
  }
  if ((cv & STI_VOLATILE) && (cv_bits & STI_VOLATILE)) {
    c_warn(ppos, "duplicated `volatile'");
  }
  if ((cv & STI_RESTRICT) && (cv_bits & STI_RESTRICT)) {
    c_warn(ppos, "duplicated `restrict'");
  }
  p = typeinfo_clone(td->type, cv_bits);
  return p;

 bad_declspec:
  c_err(ppos, "invalid declaration specifier");
  return NULL;
}

static typeinfo_t
make_pointers(tree_t tree, typeinfo_t in)
{
  tree_t      s;
  typeinfo_t  p;

  if (!tree) return in;
  ASSERT(tree->kind == NODE_POINTER);

  ALLOC(p);
  p->tag = CPT_POINTER;
  p->t_pointer.type = in;

  for (s = tree->node.refs[4]; s; s = s->node.refs[0]) {
    ASSERT(s->kind == NODE_DSQUAL);
    switch (s->node.refs[3]->kind) {
    case TOK_CONST:
      p->t_pointer.bits |= STI_CONST;
      break;
    case TOK_VOLATILE:
      p->t_pointer.bits |= STI_VOLATILE;
      break;
    case TOK_RESTRICT:
      p->t_pointer.bits |= STI_RESTRICT;
      break;
    default:
      SWERR(("bad type qualifier: %d", s->node.refs[3]->kind));
    }
  }

  if (!(in = make_pointers(tree->node.refs[5], p))) return NULL;

  return in;
}

static int
make_kr_params(typeinfo_t t, tree_t ids, tree_t *pdecls)
{
  tree_t p;
  pos_t *ppos;
  ident_t id;
  struct sema_def *def;
  struct sema_scope *scope;
  int parnum = 0;
  tree_t decls = 0;

  ASSERT(t);
  ASSERT(t->tag == CPT_FUNCTION);
  ASSERT(STI_IS_FKR(t->t_function.bits));
  //ASSERT(t->t_function._par_scope);
  scope = t->t_function.par_scope;
  if (pdecls) decls = *pdecls;

  for (p = ids; p; p = p->node.refs[0]) {
    ASSERT(p->kind == NODE_IDENTS);
    parnum++;
    id = p->node.refs[3]->id.id;
    ASSERT(id != ident_empty);
    ppos = &p->node.pos.beg;
    def = sema_search_this_scope(id, scope, SSC_REGULAR);
    if (def) {
      c_err(ppos, "redeclaration of `%s'", ident_get(id));
      c_err(def->ppos, "`%s' previously declared here", ident_get(id));
      continue;
    }
    def = sema_put_ident(scope, SSC_REGULAR, id, ppos, 0, 0, 0, p);
  }

  if (parnum && !pdecls) {
    c_warn(&ids->node.pos.beg,
           "parameter names without types in function declaration");
    // this is K&R function
    t->t_function.par_scope = 0;
    return 0;
  }

  for (p = decls; p; p = p->node.refs[0]) {
    tree_t declspec, ideclrs, q;
    pos_t *scp = 0;
    int nn = 0;
    int stclass = 0;
    typeinfo_t ti, tt;

    ASSERT(p->kind == NODE_DECL);
    declspec = p->node.refs[3];
    ideclrs = p->node.refs[4];
    for (q = ideclrs; q; q = q->node.refs[0]) {
      nn++;
    }

    if (!nn) {
      stclass = sema_get_storclass(declspec, &scp);
      if (stclass == SSC_REGISTER) {
        c_warn(scp, "useless storage class in parameter definition");
        stclass = 0;
      }
      if (stclass != 0) {
        c_err(scp, "storage class in parameter definition");
        stclass = 0;
      }
      make_typeinfo(declspec, scope, 0, 0, 0, 0, 0, 0);
      continue;
    }

    stclass = sema_get_storclass(declspec, &scp);
    if (stclass && stclass != SSC_REGISTER) {
      c_err(scp, "storage class in parameter definition");
      stclass = 0;
    }
    ti = make_declspec(declspec, scope, NULL, 1, 0);
    if (!ti) continue;

    for (q = ideclrs; q; q = q->node.refs[0]) {
      tree_t declr, init, idnode;

      ASSERT(q->kind == NODE_INITDECLR);
      declr = q->node.refs[3];
      init = q->node.refs[5];
      ASSERT(!init);

      idnode = tree_get_ident_node(declr);
      id = idnode->id.id;
      ppos = &idnode->id.pos.beg;
      if (id == ident_empty) {
        // normally its a parse error
        continue;
      }

      tt = make_typeinfo(declspec, scope, NULL, ti, declr, 1, 0, 0);
      if (!tt) continue;

      if (tt->tag == CPT_FUNCTION) {
        tt = typeinfo_create_pointer(0, tt);
      }
      if (tt->tag == CPT_ARRAY) {
        if (sema_is_void_array_type(tt)) {
          c_err(ppos, "parameter `%s' declared as array of voids",
                ident_get(id));
          tt = sema_index_to_typeinfo(C_INT);
        } else {
          tt = typeinfo_create_pointer(0, tt->t_array.type);
        }
      }
      if (sema_is_void_type(tt)) {
        c_err(ppos, "parameter `%s' declared as void object", ident_get(id));
        tt = sema_index_to_typeinfo(C_INT);
      }
      if (sema_get_type_size(tt) == SEMA_NO_SIZE) {
        c_err(ppos, "storage size of parameter `%s' is not known",
              ident_get(id));
        tt = sema_index_to_typeinfo(C_INT);
      }
#if 0
      if (tt->tag == CPT_ARITH) {
        int idx = sema_typeinfo_to_index(tt);
        if ((idx >= C_FIRST_INT && idx < C_INT) || idx == C_FLOAT) {
          c_warn(ppos, "K&R parameter `%s' should not have type `%s'",
                 ident_get(id), c_builtin_str(idx));
        }
        /*
        if (idx >= C_FIRST_INT && idx < C_INT) {
          tt = sema_index_to_typeinfo(C_INT);
        }
        if (idx == C_FLOAT) {
          tt = sema_index_to_typeinfo(C_DOUBLE);
        }
        */
      }
#endif

      def = sema_search_this_scope(id, scope, SSC_REGULAR);
      if (!def) {
        c_err(ppos, "declaration for parameter `%s' but no such parameter",
              ident_get(id));
        continue;
      }
      if (def->type) {
        c_err(ppos, "redeclaration of `%s'", ident_get(id));
        c_err(def->ppos, "`%s' previously declared here", ident_get(id));
        continue;
      }
      typeinfo_set_bits(tt, STI_LVALUE | STI_ADDRESS);
      def->type = tt;
      def->ppos = ppos;
    }
  }

  if (scope) {
    for (def = scope->reg.first; def; def = def->next) {
      if (!def->type) {
        def->type = sema_index_to_typeinfo(C_INT);
      }
    }
  }

  return 0;
}

static int
is_valid_param_typeinfo(typeinfo_t t, pos_t *ppos, int arrdepth)
{
  struct sema_def *d;
  const unsigned char *aggred_type = 0;

  ASSERT(t);
  switch (t->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
  case CPT_POINTER:
  case CPT_FUNCTION:
    return 0;
  case CPT_ENUM:
    d = t->t_enum.def;
    if (!d->nest) {
      c_err(ppos, "`enum %s' is not defined", ident_get(d->name));
      return -1;
    }
    return 0;
  case CPT_ARRAY:
    if (t->t_array.elnum == SEMA_NO_SIZE && !t->t_array.size_expr
        && arrdepth > 0) {
      c_err(ppos, "array size is not defined");
      return -1;
    }
    is_valid_param_typeinfo(t->t_array.type, ppos, arrdepth + 1);
    return 0;
  case CPT_AGGREG:
    d = t->t_aggreg.def;
    aggred_type = "struct";
    if ((d->flags & SSC_UNION)) aggred_type = "union";
    if (!d->nest) {
      c_err(ppos, "`%s %s' is not defined", aggred_type, ident_get(d->name));
      return -1;
    }
    return 0;
  case CPT_TYPEDEF:
  default:
    SWERR(("is_valid_global_typeinfo: unhandled typeinfo %d", t->tag));
  }
  return -1;
}

static int
make_params(tree_t tree, struct sema_scope *param_scope,
            int *flags, pos_t *ppos)
{
  tree_t  declspec = NULL;
  tree_t  declr = NULL;
  tree_t  idnode;
  pos_t  *scp = 0;
  typeinfo_t type;
  ident_t id;
  int stclass;
  struct sema_def *def;

  while (1) {
    if (!tree) return 0;
    if (tree->kind == NODE_ELLIPSIS) {
      *flags |= STI_FVAR;
      return 0;
    }

    ASSERT(tree->kind == NODE_DECL);
    scp = &tree->node.pos.beg;

    /* set declspec and declr */
    declspec = tree->node.refs[3];
    declr = tree->node.refs[4];
    if (declr) {
      ASSERT(declr->kind == NODE_INITDECLR);
      declr = declr->node.refs[3];
    }

    idnode = tree_get_ident_node(declr);
    id = ident_empty;
    if (idnode) {
      id = idnode->id.id;
    }

    type = make_typeinfo(declspec, param_scope, NULL, NULL, declr, 1, 0, 0);
    if (is_valid_param_typeinfo(type, scp, 0) < 0) return -1;
    stclass = sema_get_storclass(declspec, &scp);
    if (stclass && stclass != SSC_REGISTER) {
      c_err(scp, "storage class specified in parameter");
      stclass = 0;
    }
    if (stclass == SSC_REGISTER) {
      if (sema_option_warn_register_param)
        c_warn(scp, "`register' ignored in parameters");
      stclass = 0;
    }

    if (!type) {
      tree = tree->node.refs[0];
      continue;
    }
    if (type->tag == CPT_FUNCTION) {
      type = typeinfo_create_pointer(0, type);
    } else if (type->tag == CPT_ARRAY) {
      if (sema_is_void_array_type(type)) {
        c_err(ppos, "parameter declared as array of voids");
      }
      type = typeinfo_create_pointer(0, type->t_array.type);
    } else if (sema_is_void_type(type)) {
      c_err(ppos, "parameter has `void' type");
      type = typeinfo_create_arith(0, C_INT);
    }
    typeinfo_set_bits(type, STI_LVALUE | STI_ADDRESS);

    if (id != ident_empty) {
      for (def = param_scope->reg.first; def; def = def->next)
        if (def->name == id) break;
      if (def) {
        c_err(scp, "redefinition of `%s'", ident_get(id));
        c_err(&def->tree->node.pos.beg, "`%s' previously declared here",
              ident_get(id));
      }
    }

    sema_put_ident(param_scope, SSC_REGULAR, id, ppos, type, 0, NULL, tree);

    tree = tree->node.refs[0];
  }
}

static typeinfo_t make_declr(tree_t, struct sema_scope *, typeinfo_t, tree_t*);

/* check, that the function is (void) function */
static int
is_void_parameters(tree_t tree)
{
  ASSERT(tree);
  ASSERT(tree->kind == NODE_DECL || tree->kind == NODE_ELLIPSIS);

  if (tree->node.kind == NODE_ELLIPSIS) return 0;
  if (tree->node.refs[0]) return 0;
  if (tree->node.refs[2]) return 0;
  if (tree->node.refs[4]) return 0;
  if (tree->node.refs[5]) return 0;
  tree = tree->node.refs[3];
  if (!tree) return 0;
  if (tree->kind != NODE_DSSTDTYPE) return 0;
  if (tree->node.refs[0]) return 0;
  tree = tree->node.refs[3];
  if (!tree) return 0;
  if (tree->kind != TOK_VOID) return 0;
  //fprintf(stderr, "(void) function\n");
  return 1;
}

static typeinfo_t
make_dirdeclr(tree_t tree, struct sema_scope *scope, typeinfo_t in,
              tree_t *pkr_par)
{
  typeinfo_t       t = NULL, res = 0;
  pos_t       *ppos;

  if (!tree) return in;

  switch (tree->kind) {
  case NODE_DIRDECLR1:
    return in;

  case NODE_DIRDECLR2:
    return make_declr(tree->node.refs[4], scope, in, pkr_par);

  case NODE_DIRDECLR3:
    ALLOC(t);
    ppos = &tree->node.pos.beg;
    t->tag = CPT_ARRAY;
    t->t_array.type = in;
    if (in && in->tag == CPT_FUNCTION) {
      c_err(ppos, "type declared as array of functions");
      t->t_array.type = sema_index_to_typeinfo(C_INT);
    }
    t->t_array.elnum = SEMA_NO_SIZE;
    if (tree->node.refs[7]) {
      c_value_t val, val1;

      if (analyze_expr(tree->node.refs[7], scope, EK_VALUE, 0, 0) < 0) {
        //c_err(ppos, "constant expression expected");
        return 0;
      }
      if (tree_fold(tree->node.refs[7], &val) < 0) {
        /*
        if (!vararray_flag) {
          c_err(ppos, "constant expression expected");
          return 0;
        }
        */
        typeinfo_t st = sema_get_expr_type(tree->node.refs[7]);
        if (!st || st->tag != CPT_ARITH ||
            st->t_builtin.ind < C_FIRST_ARITH
            || st->t_builtin.ind > C_LAST_ARITH) {
          c_err(ppos, "integral expression expected");
          return 0;
        }
        if (st->t_builtin.ind != C_ULONG) {
          make_cast_node(tree->node.refs[7], C_ULONG, &tree->node.refs[7]);
        }
        t->t_array.size_expr = tree->node.refs[7];
        t->t_array.size_def = t;
        t = make_dirdeclr(tree->node.refs[3], scope, t, pkr_par);
        /*
        if (pkr_par && *pkr_par) {
          c_err(ppos, "invalid function declarator (1)");
          return 0;
        }
        */
        return t;
      }
      if (!c_value_is_integral(&val)) {
        c_err(ppos, "size of array has non-integer type");
        return 0;
      }
      if (c_value_is_negative(&val)) {
        c_err(ppos, "size of array is negative");
        return 0;
      }
      if (c_value_is_large(&val)) {
        c_err(ppos, "size of array is too large");
        return 0;
      }
      c_value_cast(&val, C_ULONG, &val1);
      t->t_array.elnum = val1.v.ct_ulint;
    }
    t = make_dirdeclr(tree->node.refs[3], scope, t, pkr_par);
    /*
    if (pkr_par && *pkr_par) {
      c_err(ppos, "invalid function declarator (2)");
      return 0;
    }
    */
    return t;
    
  case NODE_DIRDECLR4:
    ppos = &tree->node.pos.beg;
    if (in && in->tag == CPT_FUNCTION) {
      c_err(ppos, "type declared as function returning a function");
      in = sema_index_to_typeinfo(C_INT);
    }
    if (in && in->tag == CPT_AGGREG && !sema_option_aggreg_return) {
      c_err(ppos, "type declared as function returning an aggregate");
      in = sema_index_to_typeinfo(C_INT);
    }
    if (in && in->tag == CPT_ARRAY) {
      c_err(ppos, "type declared as function returning an array");
      in = sema_index_to_typeinfo(C_INT);
    }
    if (sema_is_void_type(in) && STI_GET_CV(in->t_builtin.bits)) {
      c_warn(ppos, "useless qualifier for `void' return type");
      in->t_builtin.bits &= ~STI_CVMASK;
    }
    ALLOC(t);
    t->tag = CPT_FUNCTION;
    t->t_function.ret_type = in;
    t->t_function.par_scope = sema_scope_create(scope);
    t->t_function.par_scope->g.tag = SSC_ARG_SCOPE;
    if (is_void_parameters(tree->node.refs[5])) {
      t->t_function.bits |= STI_FVOID;
    } else if (!tree->node.refs[5]) {
      /* actually, () case is DIRDECLR5 */
      t->t_function.bits |= STI_FKR;
    } else if (tree->node.refs[5]->kind == NODE_ELLIPSIS
               && !tree->node.refs[5]->node.refs[0]) {
      t->t_function.bits |= STI_FVAR;
    } else {
      if (make_params(tree->node.refs[5], t->t_function.par_scope,
                      &t->t_function.bits, ppos) < 0)
        return NULL;
    }
    t = make_dirdeclr(tree->node.refs[3], scope, t, pkr_par);
    if (pkr_par && *pkr_par) {
      c_err(ppos, "invalid function declarator");
      return 0;
    }
    return t;

  case NODE_DIRDECLR5:
    ppos = &tree->node.pos.beg;
    if (in && in->tag == CPT_FUNCTION) {
      c_err(ppos, "type declared as function returning a function");
      in = sema_index_to_typeinfo(C_INT);
    }
    if (in && in->tag == CPT_AGGREG && !sema_option_aggreg_return) {
      c_err(ppos, "type declared as function returning an aggregate");
      in = sema_index_to_typeinfo(C_INT);
    }
    if (in && in->tag == CPT_ARRAY) {
      c_err(ppos, "type declared as function returning an array");
      in = sema_index_to_typeinfo(C_INT);
    }
    if (sema_is_void_type(in) && STI_GET_CV(in->t_builtin.bits)) {
      c_err(ppos, "useless qualifier for `void' return type");
      in->t_builtin.bits &= ~STI_CVMASK;
    }
    ALLOC(t);
    t->tag = CPT_FUNCTION;
    t->t_function.ret_type = in;
    if (tree->node.refs[5]) {
      t->t_function.par_scope = sema_scope_create(scope);
      t->t_function.par_scope->g.tag = SSC_ARG_SCOPE;
    }
    t->t_function.bits = STI_FKR;
    res = make_dirdeclr(tree->node.refs[3], scope, t, pkr_par);
    if (make_kr_params(t, tree->node.refs[5], pkr_par) < 0)
      return NULL;
    if (pkr_par) *pkr_par = 0;
    return res;

  default:
    SWERR(("bad DirDeclr node: kind == %d", tree->kind));
  }
  return NULL;
}

static typeinfo_t
make_declr(tree_t declr, struct sema_scope *scope, typeinfo_t in,
           tree_t *pkr_par)
{
  if (!declr) return in;
  ASSERT(declr->kind == NODE_DECLR);

  in = make_pointers(declr->node.refs[3], in);
  in = make_dirdeclr(declr->node.refs[4], scope, in, pkr_par);

  return in;
}

static typeinfo_t
make_typeinfo(tree_t declspec, struct sema_scope *scope,
              struct sema_scope *outer_scope,
              typeinfo_t old_ti, tree_t declr,
              int decl_obj_flag,
              int use_only_flag, tree_t *pkr_par)
{
  typeinfo_t plain = NULL;
  typeinfo_t ti = NULL;

  if (old_ti) {
    plain = typeinfo_clone(old_ti, 0);
  } else {
    plain = make_declspec(declspec, scope, outer_scope,
                          decl_obj_flag, use_only_flag);
    if (!plain) return NULL;
  }

  ti = make_declr(declr, scope, plain, pkr_par);
  return ti;
}

typeinfo_t
sema_get_value_type(c_value_t *pv)
{
  ASSERT(pv != NULL);
  ASSERT(pv->tag >= C_FIRST_ARITH && pv->tag <= C_LAST_ARITH);
  return typeinfo_create_arith(0, pv->tag);
}

static void analyze_declarations(tree_t, struct sema_scope *);
typeinfo_t sema_get_expr_typeinfo(tree_t, int);

typeinfo_t
sema_get_expr_type(tree_t node)
{
  semainfo_t psema = node->node.sema;
  struct sema_def *def = 0, *dd;

  ASSERT(psema);
  switch (psema->tag) {
  case ST_IDUSE:
    def = psema->s_iduse.def;
    ASSERT(def);
    if (def->type && def->type->tag == CPT_ENUM) {
      dd = def->type->t_enum.def;
      // for anonymous enums return the base type
      if (!dd->name) return dd->type;
    }
    return def->type;
  case ST_TYPE:
    return psema->s_type.type;
  default:
    SWERR(("bad semainfo tag: %d", psema->tag));
  }
}

/* returns the table index for size_t type */
static int
get_size_t_index(void)
{
  return C_ULONG;
}

/* returns the table index for pointer types */
static int
get_pointer_index(void)
{
  return C_ULONG;
}

/* returns the table index for ptrdiff_t type */
static int
get_ptrdiff_t_index(void)
{
  return C_LONG;
}

/* returns the table index for wchar_t type */
static int
get_wchar_t_index(void)
{
  return C_LONG;
}

int
sema_typeinfo_to_index(typeinfo_t ti)
{
  ASSERT(ti);
  ASSERT(ti->tag == CPT_ARITH);
  return ti->t_builtin.ind;
}

typeinfo_t
sema_index_to_typeinfo(int idx)
{
  ASSERT(idx >= C_FIRST_ARITH && idx <= C_LAST_ARITH);
  return typeinfo_create_arith(0, idx);
}

/* assumption: type sizes are equal to the host compiler's type sizes */
static unsigned long base_type_sizes[] =
{
  [C_BOOL]    = sizeof(unsigned char),
  [C_CHAR]    = sizeof(char),
  [C_SCHAR]   = sizeof(signed char),
  [C_UCHAR]   = sizeof(unsigned char),
  [C_SHORT]   = sizeof(short),
  [C_USHORT]  = sizeof(unsigned short),
  [C_INT]     = sizeof(int),
  [C_UINT]    = sizeof(unsigned int),
  [C_LONG]    = sizeof(long),
  [C_ULONG]   = sizeof(unsigned long),
  [C_LLONG]   = sizeof(long long),
  [C_ULLONG]  = sizeof(unsigned long long),
  [C_FLOAT]   = sizeof(float),
  [C_DOUBLE]  = sizeof(double),
  [C_LDOUBLE] = sizeof(long double),
  [C_FIMAGINARY] = sizeof(float),
  [C_DIMAGINARY] = sizeof(double),
  [C_LIMAGINARY] = sizeof(long double),
  [C_FCOMPLEX] = sizeof(struct r_fcomplex),
  [C_DCOMPLEX] = sizeof(struct r_dcomplex),
  [C_LCOMPLEX] = sizeof(struct r_lcomplex),
};

unsigned long
sema_get_type_size(typeinfo_t t)
{
  unsigned long ss;
  struct sema_def *dd = 0;

  switch (t->tag) {
  case CPT_ARITH:
    ASSERT(t->t_builtin.ind >= C_FIRST_ARITH && t->t_builtin.ind <= C_LAST_ARITH);
    return base_type_sizes[t->t_builtin.ind];
  case CPT_BUILTIN:
    if (t->t_builtin.ind == C_VOID) return SEMA_NO_SIZE;
    if (t->t_builtin.ind == C_VA_LIST) return sizeof(void*);
    SWERR(("bad builtin type: %d", t->t_builtin.ind));
  case CPT_ENUM:
    dd = t->t_enum.def;
    if (!dd) return SEMA_NO_SIZE;
    if (!dd->type) return SEMA_NO_SIZE;
    if (!dd->nest) return SEMA_NO_SIZE;
    if (!dd->nest->reg.first) return SEMA_NO_SIZE;
    ASSERT(dd->size);
    return dd->size;
  case CPT_POINTER:
    return sizeof(void*);
  case CPT_ARRAY:
    if (t->t_array.elnum == SEMA_NO_SIZE) return SEMA_NO_SIZE;
    if ((ss = sema_get_type_size(t->t_array.type)) == SEMA_NO_SIZE)
      return SEMA_NO_SIZE;
    return ss * t->t_array.elnum;
  case CPT_FUNCTION:
    SWERR(("attempt to take size of function"));
  case CPT_AGGREG:
    dd = t->t_aggreg.def;
    if (!dd) return SEMA_NO_SIZE;
    if (!dd->nest) return SEMA_NO_SIZE;
    ASSERT(dd->size);
    return dd->size;
  default:
    SWERR(("unhandled typeinfo tag: %d", t->tag));
  }
}

static tree_t
make_void_cast_node(tree_t node, tree_t *pp1)
{
  tree_t t = 0;

  ASSERT(node);
  t = tree_make_token(TOK_VOID, &node->gen.pos.beg, &node->gen.pos.end);
  t = tree_make_node3(NODE_DSSTDTYPE, 4, t);
  t = tree_make_node3(NODE_DECL, 6, t, NULL, NULL);
  t = tree_make_node3(NODE_EXPRCAST, 6, t, NULL, node);
  t->node.sema = sinfo_create_type(typeinfo_create_builtin(0, C_VOID));

  t->node.refs[0] = node->node.refs[0];
  node->node.refs[0] = 0;
  if (pp1) *pp1 = t;

  return t;
}

static tree_t
make_cast_node(tree_t node, int type, tree_t *pp1)
{
  tree_t t = 0, tt = 0;
  pos_t *pb, *pe = 0;

  ASSERT(node);
  pb = &node->gen.pos.beg;
  pe = &node->gen.pos.end;

  switch (type) {
  case C_BOOL:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__BOOL, pb, pe));
    break;
  case C_CHAR:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_CHAR, pb, pe));
    break;
  case C_SCHAR:
    tt = tree_merge(tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_SIGNED, pb, pe)),
                    0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_CHAR, pb, pe)));
    break;
  case C_UCHAR:
    tt = tree_merge(tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_UNSIGNED, pb, pe)),
                    0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_CHAR, pb, pe)));
    break;
  case C_SHORT:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_SIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_SHORT, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_USHORT:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_UNSIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_SHORT, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_INT:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_SIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_UINT:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_UNSIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_LONG:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_SIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_ULONG:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_UNSIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_LLONG:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_SIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_ULLONG:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_UNSIGNED, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_INT, pb, pe)));
    break;
  case C_FLOAT:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_FLOAT, pb, pe));
    break;
  case C_DOUBLE:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_DOUBLE, pb, pe));
    break;
  case C_LDOUBLE:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK_LONG, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_DOUBLE, pb, pe)));
    break;
  case C_FIMAGINARY:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__IMAGINARY, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_FLOAT, pb, pe)));
    break;
  case C_DIMAGINARY:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__IMAGINARY, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_DOUBLE, pb, pe)));
    break;
  case C_LIMAGINARY:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__IMAGINARY, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_DOUBLE, pb, pe)));
    break;
  case C_FCOMPLEX:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__COMPLEX, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_FLOAT, pb, pe)));
    break;
  case C_DCOMPLEX:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__COMPLEX, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_DOUBLE, pb, pe)));
    break;
  case C_LCOMPLEX:
    tt = tree_make_node3(NODE_DSSTDTYPE, 4,
                         tree_make_token(TOK__COMPLEX, pb, pe));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_LONG, pb, pe)));
    tt = tree_merge(tt, 0,
                    tree_make_node3(NODE_DSSTDTYPE, 4,
                                    tree_make_token(TOK_DOUBLE, pb, pe)));
    break;
  default:
    SWERR(("unhandled type index: %d", type));
  }
  tt = tree_make_node3(NODE_DECL, 6, tt, NULL, NULL);
  t = tree_make_node3(NODE_EXPRCAST, 7, NULL, tt, NULL, node);
  t->node.sema = sinfo_create_type(sema_index_to_typeinfo(type));

  t->node.refs[0] = node->node.refs[0];
  node->node.refs[0] = 0;

  if (pp1) *pp1 = t;
  return t;
}

static tree_t
make_address_node(tree_t node, typeinfo_t type, tree_t *pp1)
{
  typeinfo_t nt;
  tree_t     nn;

  if (type->tag == CPT_ARRAY) {
    nt = typeinfo_create_pointer(0, typeinfo_clone(type->t_array.type, 0));
  } else {
    nt = typeinfo_create_pointer(0, typeinfo_clone(type, 0));
  }

  nn = tree_make_node3(NODE_EXPRUNARY, 5,
                       tree_make_token('&', &node->gen.pos.beg,
                                       &node->gen.pos.end),
                       node);
  nn->node.sema = sinfo_create_type(nt);

  nn->node.refs[0] = node->node.refs[0];
  node->node.refs[0] = 0;

  if (pp1) *pp1 = nn;
  return nn;
}

static tree_t
make_deref_node(tree_t node, typeinfo_t type, tree_t *pp1)
{
  typeinfo_t nt;
  tree_t     nn;

  ASSERT(type->tag == CPT_ARRAY || type->tag == CPT_POINTER);
  if (type->tag == CPT_ARRAY) {
    nt = typeinfo_clone(type->t_array.type, 0);
  } else {
    nt = typeinfo_clone(type->t_pointer.type, 0);
  }

  nn = tree_make_node3(NODE_EXPRUNARY, 5,
                       tree_make_token('*', &node->gen.pos.beg,
                                       &node->gen.pos.end),
                       node);
  nn->node.sema = sinfo_create_type(nt);

  nn->node.refs[0] = node->node.refs[0];
  node->node.refs[0] = 0;
  if (pp1) *pp1 = nn;
  return nn;
}

static tree_t
make_cast_node2(tree_t node, typeinfo_t type, tree_t *pp1)
{
  tree_t t;

  // FIXME: we do not fill Decl field of ExprCast node...
  t = tree_make_node3(NODE_EXPRCAST, 7, NULL, NULL, NULL, node);
  t->node.sema = sinfo_create_type(type);
  t->node.refs[0] = node->node.refs[0];
  node->node.refs[0] = 0;
  if (pp1) *pp1 = t;
  return t;
}

static void
cast_enum_to_integral(tree_t *pnode, typeinfo_t *pt, int *pidx, tree_t *pp1)
{
  tree_t           node = *pnode;
  typeinfo_t       t = *pt;
  struct sema_def *ed = 0;

  ASSERT(pt);
  if (t->tag != CPT_ENUM) return;
  ed = t->t_enum.def;
  ASSERT(ed);
  t = typeinfo_clone(ed->type, 0);
  node = make_cast_node2(node, t, pp1);
  t = sema_get_expr_type(node);
  if (pidx) *pidx = sema_typeinfo_to_index(t);
  *pnode = node;
  *pt = t;
}

static tree_t
make_array_cast_node(tree_t node, typeinfo_t type, tree_t *pp1)
{
  typeinfo_t nt;

  ASSERT(type->tag == CPT_ARRAY);
  nt = typeinfo_create_pointer(0, typeinfo_clone(type->t_array.type, 0));
  return make_cast_node2(node, nt, pp1);
}

static int inv_binop(pos_t *ppos, char const *opstr)
{
  c_err(ppos, "invalid operands to binary %s", opstr);
  return -1;
}

static int inv_unop(pos_t *ppos, char const *opstr)
{
  c_err(ppos, "invalid operand to unary %s", opstr);
  return -1;
}

static int
is_literal_0(tree_t t)
{
  if (!t) return 0;
  if (t->kind == NODE_EXPRCONST) {
    c_value_t *pv = &t->node.refs[3]->val.val;
    return c_value_is_zero(pv);
  } else if (t->kind == NODE_EXPRCAST) {
    return is_literal_0(t->node.refs[6]);
  } else return 0;
}

int
sema_is_void_pointer(typeinfo_t type)
{
  ASSERT(type);
  if (type->tag != CPT_POINTER) return 0;
  type = type->t_pointer.type;
  return sema_is_void_type(type);
}

static void
cast_to_pointer(tree_t *pt, typeinfo_t *pi, tree_t *pp1)
{
  if ((*pi)->tag == CPT_ARRAY) {
    *pi = typeinfo_create_pointer(0, typeinfo_clone((*pi)->t_array.type, 0));
    *pt = make_cast_node2(*pt, *pi, 0);
    *pp1 = *pt;
    return;
  }
  if ((*pi)->tag == CPT_FUNCTION) {
    tree_t nt = make_address_node(*pt, *pi, pp1);
    *pi = sema_get_expr_type(nt);
    *pt = nt;
      /*
    *pi = typeinfo_create_pointer(0, *pi);
    *pt = make_cast_node2(*pt, *pi, 0);
    *pp1 = *pt;
    */
    return;
  }
}

static void
cast_to_int(int ind, tree_t *pt, typeinfo_t *pi, tree_t *pp1)
{
  int ind2 = 0;

  cast_enum_to_integral(pt, pi, 0, pp1);
  if ((*pi)->tag == CPT_ARITH) {
    ind2 = sema_typeinfo_to_index(*pi);
    if (ind != ind2) {
      *pt = make_cast_node(*pt, ind, pp1);
    }
    *pi = sema_get_expr_type(*pt);
    return;
  }
  if ((*pi)->tag == CPT_POINTER) {
    *pt = make_cast_node(*pt, ind, pp1);
    *pi = sema_get_expr_type(*pt);
  }
}

static int
are_comparable_pointers(typeinfo_t t1, typeinfo_t t2)
{
  /* 1. const and volatile type qualifiers are not considered */
  /* 2. any pointer may have type void* */
  ASSERT(t1->tag == CPT_POINTER);
  ASSERT(t2->tag == CPT_POINTER);
  if (sema_is_void_pointer(t1)) return 1;
  if (sema_is_void_pointer(t2)) return 1;
  return !!sema_types_compatible_no_CV(t1, t2);
}

int
sema_get_expr_opcode(tree_t expr, pos_t **pppos, char const **pstr)
{
  int cop;
  tree_t top = 0;

  ASSERT(expr);
  switch (expr->kind) {
  case NODE_EXPRBINARY:
    top = expr->node.refs[4];
    ASSERT(top);
    cop = sema_binop_to_c_operation(top->kind);
    break;
  case NODE_EXPRUNARY:
    top = expr->node.refs[3];
    ASSERT(top);
    cop = sema_unop_to_c_operation(top->kind);
    break;
  case NODE_EXPRFIELD:
    top = expr->node.refs[4];
    ASSERT(top);
    cop = sema_postop_to_c_operation(top->kind);
    break;
  case NODE_EXPRPOSTFIX:
    top = expr->node.refs[4];
    ASSERT(top);
    cop = sema_postop_to_c_operation(top->kind);
    break;
  default:
    BADNODE(expr);
  }
  if (pppos) *pppos = &top->gen.pos.beg;
  if (pstr) *pstr = c_operation_str(cop);
  return cop;
}

static int
balance_arithmetic(int promote_table_number,
                   int elaborate_int_flag,
                   char const *opstr,
                   pos_t *ppos,
                   tree_t node,
                   tree_t t1, tree_t t2,
                   typeinfo_t i1, typeinfo_t i2)
{
  int ind1, ind2, indr;

  cast_enum_to_integral(&t1, &i1, 0, &node->node.refs[3]);
  cast_enum_to_integral(&t2, &i2, 0, &node->node.refs[5]);
  if (i1->tag != CPT_ARITH || i2->tag != CPT_ARITH)
    return inv_binop(ppos, opstr);

  ind1 = sema_typeinfo_to_index(i1);
  ind2 = sema_typeinfo_to_index(i2);
  indr = c_get_balanced_type(promote_table_number, ind1, ind2);
  ASSERT(indr <= C_LAST_ARITH);
  if (indr < C_FIRST_ARITH) {
    return inv_binop(ppos, opstr);
  }

  if (ind1 != indr) {
    t1 = make_cast_node(t1, indr, &node->node.refs[3]);
  }
  if (ind2 != indr) {
    t2 = make_cast_node(t2, indr, &node->node.refs[5]);
  }
  if (elaborate_int_flag) indr = C_INT;
  node->node.sema = sinfo_create_type(sema_index_to_typeinfo(indr));
  return 0;
}

/*
 * lht - the type of the left-hand side of the assignment
 * rht - the type of the right-hand side of the assignment
 * pp1 - pointer to the RHS node pointer
 *       used to insert casts
 * rhs - the RHS of the assignment expression
 * psema - the pointer to the semantic info pointer of the
 *         resulting tree node (may be NULL)
 * ppos - position to report errors
 * favor_const - 1, if CONST specifier in lht should be favored
 * favor_lvalue - 1, if LVALUE specifier in lht should be favored
 * place_descr - additional string to describe place of assignment
 */
static int
do_assignment(typeinfo_t lht, typeinfo_t rht,
              tree_t *pp1, tree_t rhs, semainfo_t *psema,
              pos_t *ppos, int favor_const, int favor_lvalue,
              char const *place_descr)
{
  int ind1, ind2;

  if (favor_lvalue && !STI_IS_LVALUE(typeinfo_get_bits(lht)))
    goto _invalid_lvalue;
  if (lht->tag == CPT_ARRAY || lht->tag == CPT_FUNCTION)
    goto _invalid_lvalue;

  if (lht->tag == CPT_AGGREG && rht->tag != CPT_AGGREG)
    goto _incompatible_types;
  if (lht->tag != CPT_AGGREG && rht->tag == CPT_AGGREG)
    goto _incompatible_types;
  if (lht->tag == CPT_AGGREG && rht->tag == CPT_AGGREG) {
    if (!lht->t_aggreg.def || !rht->t_aggreg.def)
      goto _incompatible_types;
    if (lht->t_aggreg.def != rht->t_aggreg.def)
      goto _incompatible_types;
    if (psema) *psema = sinfo_create_type(typeinfo_clone(lht, 0));
    return 0;
  }

  /* FIXME: va_list should be treated as `void *' */
  if (sema_is_va_list_type(lht)) {
    if (!sema_is_va_list_type(rht)) goto _incompatible_types;
    if (psema) *psema = sinfo_create_type(typeinfo_clone(lht, 0));
    return 0;
  }
  if (sema_is_va_list_type(rht)) goto _incompatible_types;

  if (lht->tag == CPT_ARITH || lht->tag == CPT_ENUM) {
    if (lht->tag == CPT_ENUM) {
      struct sema_def *ed = lht->t_enum.def;
      ind1 = sema_typeinfo_to_index(ed->type);
    } else {
      ind1 = sema_typeinfo_to_index(lht);
    }

    if (favor_const && STI_IS_CONST(typeinfo_get_cv(lht))) {
      c_warn(ppos, "assignment to read-only location");
      return -1;
    }

    if (ind1 >= C_FIRST_FLT && ind1 <= C_LAST_FLT) {
      cast_enum_to_integral(&rhs, &rht, 0, pp1);
      if (rht->tag != CPT_ARITH) goto _incompatible_types;
      ind2 = sema_typeinfo_to_index(rht);
      if (ind1 != ind2) {
        rhs = make_cast_node(rhs, ind1, pp1);
      }
      if (psema) *psema = sinfo_create_type(sema_index_to_typeinfo(ind1));
      return 0;
    }

    ASSERT(ind1 >= C_FIRST_INT && ind1 <= C_LAST_INT);

    if (rht->tag == CPT_FUNCTION) {
      // take address of function
      rhs = make_address_node(rhs, rht, pp1);
      rht = sema_get_expr_type(rhs);
      /*
      c_warn(ppos, "%s implicitly takes address of function", place_descr);
      */
    }
    if (rht->tag == CPT_ARRAY) {
      rhs = make_array_cast_node(rhs, rht, pp1);
      rht = sema_get_expr_type(rhs);
    }

    if (rht->tag == CPT_POINTER) {
      rhs = make_cast_node(rhs, ind1, pp1);
      rht = sema_get_expr_type(rhs);
      c_warn(ppos, "%s makes integer from pointer without a cast",
             place_descr);
    }
    if (rht->tag == CPT_ENUM && lht->tag == CPT_ENUM
        && lht->t_enum.def == rht->t_enum.def) {
      if (psema) *psema = sinfo_create_type(typeinfo_clone(lht, 0));
      return 0;
    }
    if (rht->tag == CPT_ENUM) {
      struct sema_def *ed = rht->t_enum.def;
      ASSERT(ed->type);
      ind2 = sema_typeinfo_to_index(ed->type);
      rhs = make_cast_node(rhs, ind2, pp1);
      rht = sema_get_expr_type(rhs);
    }
    if (rht->tag != CPT_ARITH) goto _incompatible_types;
    ind2 = sema_typeinfo_to_index(rht);
    if (ind1 != ind2) {
      rhs = make_cast_node(rhs, ind1, pp1);
    }
    if (lht->tag == CPT_ENUM) {
      rhs = make_cast_node2(rhs, typeinfo_clone(lht, 0), pp1);
      rht = sema_get_expr_type(rhs);
      if (psema) *psema = sinfo_create_type(typeinfo_clone(lht, 0));
      return 0;
    }
    if (psema) *psema = sinfo_create_type(sema_index_to_typeinfo(ind1));
    return 0;
  }

  ASSERT(lht->tag == CPT_POINTER);

  cast_enum_to_integral(&rhs, &rht, 0, pp1);
  if (rht->tag == CPT_ARITH) {
    ind2 = sema_typeinfo_to_index(rht);
    if (ind2 >= C_FIRST_FLT && ind2 <= C_LAST_FLT)
      goto _incompatible_types;
    ASSERT(ind2 >= C_FIRST_INT && ind2 <= C_LAST_INT);
    if (!is_literal_0(rhs)) {
      c_warn(ppos, "%s makes pointer from integer without a cast",
             place_descr);
    }
    /* FIXME: arch dependance... */
    if (ind2 != C_LONG && ind2 != C_ULONG
        && ind2 != C_INT && ind2 != C_UINT) {
      rhs = make_cast_node(rhs, C_ULONG, pp1);
      rht = sema_get_expr_type(rhs);
    }
    make_cast_node2(rhs, typeinfo_clone(lht, 0), pp1);
    rht = sema_get_expr_type(rhs);
    if (psema) *psema = sinfo_create_type(typeinfo_clone(lht, 0));
    return 0;
  }

  if (rht->tag == CPT_FUNCTION) {
    rhs = make_address_node(rhs, rht, pp1);
    rht = sema_get_expr_type(rhs);
    /*
    c_warn(ppos, "%s implicitly takes address of function", place_descr);
    */
  }
  if (rht->tag == CPT_ARRAY) {
    rhs = make_array_cast_node(rhs, rht, pp1);
    rht = sema_get_expr_type(rhs);
  }

  ASSERT(rht->tag == CPT_POINTER);

  if (!are_pointers_assignable(rht, lht)) {
    c_warn(ppos, "%s from incompatible pointer type", place_descr);
    rhs = make_cast_node2(rhs, typeinfo_clone(lht, 0), pp1);
    rht = sema_get_expr_type(rhs);
  }
  if (sema_is_void_pointer(rht) && !sema_is_void_pointer(lht)) {
    /*
    c_warn(ppos, "assignment from void * should have a cast", place_descr);
    */
    rhs = make_cast_node2(rhs, typeinfo_clone(lht, 0), pp1);
    rht = sema_get_expr_type(rhs);
  }
  if (does_discard_qualifier(lht, rht)) {
    c_warn(ppos, "%s discards qualifiers from pointer target type",
           place_descr);
    rhs = make_cast_node2(rhs, typeinfo_clone(lht, 0), pp1);
    rht = sema_get_expr_type(rhs);
  }

  if (!same_type(lht, rht)) {
    rhs = make_cast_node2(rhs, typeinfo_clone(lht, 0), pp1);
    rht = sema_get_expr_type(rhs);
  }

  if (psema) *psema = sinfo_create_type(typeinfo_clone(lht, 0));

  // FIXME: the return type of assignment expression should obey standard
  // C type promotions...
  return 0;

 _invalid_lvalue:
    c_err(ppos, "invalid lvalue in %s", place_descr);
    return -1;

 _incompatible_types:
    c_err(ppos, "incompatible types in %s", place_descr);
    return -1;
}
              

static int
analyze_arithmetic_opassign(tree_t node, struct sema_scope *scope, int tab)
{
  typeinfo_t i1, i2, i1_old;
  tree_t t1, t2;
  int cop, ind1, ind2;
  pos_t *ppos = 0;
  char const *opstr = 0;
  tree_t *pps[2];

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRBINARY);
  t1 = node->node.refs[3];
  i1 = sema_get_expr_type(t1);
  t2 = node->node.refs[5];
  i2 = sema_get_expr_type(t2);
  cop = sema_get_expr_opcode(node, &ppos, &opstr);
  (void) cop;

  pps[0] = &node->node.refs[3];
  pps[1] = &node->node.refs[5];

  if (!STI_IS_LVALUE(typeinfo_get_bits(i1))) {
    c_err(ppos, "invalid lvalue in assignment");
    return -1;
  }
  if (STI_IS_CONST(typeinfo_get_cv(i1))) {
    c_err(ppos, "assignment to read-only location");
  }

  i1_old = i1;
  node->node.refs[1] = tree_make_sema();
  node->node.refs[1]->sema.sema.expr.original_node = t1;

  if (balance_arithmetic(tab, 0, opstr, ppos, node, t1, t2, i1, i2) < 0)
    return -1;

  t1 = node->node.refs[3];
  i1 = sema_get_expr_type(t1);
  t2 = node->node.refs[5];
  i2 = sema_get_expr_type(t2);
  node->node.refs[1]->sema.sema.expr.from_cast = t1;

  /* cast the result back to the lh-type */
  if (i1_old->tag == CPT_ENUM) {
    ind1 = sema_typeinfo_to_index(i1_old->t_enum.def->type);
  } else {
    ind1 = sema_typeinfo_to_index(i1_old);
  }
  ind2 = sema_typeinfo_to_index(i2);
  if (ind1 != ind2) {
    t1 = make_cast_node(t1, ind1, pps[0]);
  }
  if (i1_old->tag == CPT_ENUM) {
    make_cast_node2(t1, typeinfo_clone(i1_old, 0), pps[0]);
  }
  
  node->node.sema = sinfo_create_type(typeinfo_clone(i1_old, 0));
  return 0;
}

static int
analyze_binop(tree_t node, struct sema_scope *scope,
              struct scopes_info *jmp_scopes)
{
  tree_t t1, t2;
  int cop;
  typeinfo_t i1, i2, rt = 0;
  pos_t *ppos = 0;
  char const *opstr;
  int ind1, ind2;
  tree_t *pps[2];

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRBINARY);
  t1 = node->node.refs[3];
  t2 = node->node.refs[5];
  cop = sema_get_expr_opcode(node, &ppos, &opstr);

  pps[0] = &node->node.refs[3];
  pps[1] = &node->node.refs[5];

  switch (cop) {
  case COP_ASSIGN:
    if (analyze_expr(t1, scope, EK_LVALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);
    return do_assignment(i1, i2, pps[1],
                         t2, (semainfo_t *) &node->node.sema,
                         ppos, 1, 1, "assignment");

  case COP_MULASSIGN:
  case COP_DIVASSIGN:
    if (analyze_expr(t1, scope, EK_LVALUE, 0, jmp_scopes) < 0) return -1;
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);
    return analyze_arithmetic_opassign(node, scope, 0);

  case COP_ADDASSIGN:
  case COP_SUBASSIGN:
    if (analyze_expr(t1, scope, EK_LVALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    if (i1->tag == CPT_ARITH || i1->tag == CPT_ENUM) {
      return analyze_arithmetic_opassign(node, scope, 0);
    }
    if (i1->tag != CPT_POINTER) return inv_binop(ppos, opstr);
    cast_enum_to_integral(&t2, &i2, 0, pps[1]);
    if (i2->tag != CPT_ARITH) return inv_binop(ppos, opstr);

    if (sema_is_void_pointer(i1)) {
      c_warn(ppos, "`void *' pointer is used in arithmetic");
    }
    if (!STI_IS_LVALUE(typeinfo_get_bits(i1))) {
      c_err(ppos, "invalid lvalue in assignment");
      return -1;
    }
    if (STI_IS_CONST(typeinfo_get_cv(i1))) {
      c_err(ppos, "assignment to read-only location");
    }

    ind2 = sema_typeinfo_to_index(i2);
    if (ind2 < C_FIRST_INT || ind2 > C_LAST_INT) return inv_binop(ppos, opstr);
    ind1 = get_ptrdiff_t_index();
    if (ind2 != ind1) {
      make_cast_node(t2, ind1, pps[1]);
    }
    rt = typeinfo_clone(i1, 0);
    node->node.sema = sinfo_create_type(rt);
    return 0;

  case COP_ASLASSIGN:
  case COP_ASRASSIGN:
  case COP_MODASSIGN:
  case COP_ANDASSIGN:
  case COP_XORASSIGN:
  case COP_ORASSIGN:
    if (analyze_expr(t1, scope, EK_LVALUE, 0, jmp_scopes) < 0) return -1;
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);
    return analyze_arithmetic_opassign(node, scope, 1);

  case COP_COMMA:
    if (analyze_expr(t1, scope, EK_VOID, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VOID, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    /* no constraints */
    rt = typeinfo_clone(i2, 0);
    node->node.sema = sinfo_create_type(rt);
    return 0;

  case COP_LOGOR:
  case COP_LOGAND:
    if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    /* no constraints imposed */
    rt = sema_index_to_typeinfo(C_INT);
    node->node.sema = sinfo_create_type(rt);
    return 0;

  case COP_EQ:
  case COP_NE:
  case COP_LT:
  case COP_GT:
  case COP_LE:
  case COP_GE:
    if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);
  
    cast_enum_to_integral(&t1, &i1, 0, pps[0]);
    cast_enum_to_integral(&t2, &i2, 0, pps[1]);

    opstr = c_operation_str(cop);
    if (i1->tag == CPT_ARITH && i2->tag == CPT_ARITH) {
      return balance_arithmetic(0, 1, opstr, ppos, node, t1, t2, i1, i2);
    } 

    cast_to_pointer(&t1, &i1, &node->node.refs[3]);
    cast_to_pointer(&t2, &i2, &node->node.refs[5]);

    if (i1->tag == CPT_POINTER && i2->tag == CPT_POINTER) {
      if (cop == COP_LT || cop == COP_GT || cop == COP_LE || cop == COP_GE) {
        if (sema_is_void_pointer(i1) || sema_is_void_pointer(i2)) {
          c_warn(ppos, "`void *' pointer is used in arithmetic");
        }
      }
      if (!are_comparable_pointers(i1, i2)) {
        c_warn(ppos, "comparison of distinct pointer types lacks a cast");
      }
      if (!same_type(i1, i2)) {
        // cast both arguments to char *
        typeinfo_t ct = typeinfo_create_pointer(0, typeinfo_create_arith(0, C_CHAR));
        if (!same_type(i1, ct)) {
          t1 = make_cast_node2(t1, ct, &node->node.refs[3]);
          i1 = sema_get_expr_type(t1);
          ct = 0;
        }
        if (!ct) ct = typeinfo_create_pointer(0, typeinfo_create_arith(0, C_CHAR));
        if (!same_type(i2, ct)) {
          t2 = make_cast_node2(t2, ct, &node->node.refs[5]);
          i2 = sema_get_expr_type(t2);
        }
      }
      rt = sema_index_to_typeinfo(C_INT);
      node->node.sema = sinfo_create_type(rt);
      return 0;
    }
    if (i1->tag == CPT_POINTER && i2->tag == CPT_ARITH) {
      if (is_literal_0(t2)) {
        t2 = make_cast_node2(t2, typeinfo_clone(i1, 0), &node->node.refs[5]);
        i2 = sema_get_expr_type(t2);

        rt = sema_index_to_typeinfo(C_INT);
        node->node.sema = sinfo_create_type(rt);
        return 0;
      }

      // cast the pointer to unsigned int, then do balance arithm.
      ind2 = sema_typeinfo_to_index(i2);
      if (ind2 < C_FIRST_INT || ind2 > C_LAST_INT)
        return inv_binop(ppos, opstr);
      // FIXME: exception is NULL
      c_warn(ppos, "comparison between pointer and integer");
      cast_to_int(C_UINT, &t1, &i1, &node->node.refs[3]);
      return balance_arithmetic(0, 1, opstr, ppos, node, t1, t2, i1, i2);
    }
    if (i2->tag == CPT_POINTER && i1->tag == CPT_ARITH) {
      if (is_literal_0(t1)) {
        t1 = make_cast_node2(t1, typeinfo_clone(i2, 0), &node->node.refs[3]);
        i1 = sema_get_expr_type(t1);

        rt = sema_index_to_typeinfo(C_INT);
        node->node.sema = sinfo_create_type(rt);
        return 0;
      }

      ind2 = sema_typeinfo_to_index(i1);
      if (ind2 < C_FIRST_INT || ind2 > C_LAST_INT)
        return inv_binop(ppos, opstr);
      c_warn(ppos, "comparison between pointer and integer");
      cast_to_int(C_UINT, &t2, &i2, &node->node.refs[5]);
      return balance_arithmetic(0, 1, opstr, ppos, node, t1, t2, i1, i2);
    }

    return inv_binop(ppos, opstr);

  case COP_ADD:
    if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    cast_enum_to_integral(&t1, &i1, 0, pps[0]);
    cast_enum_to_integral(&t2, &i2, 0, pps[1]);

    if (i1->tag == CPT_ARITH && i2->tag == CPT_ARITH) {
      return balance_arithmetic(0, 0, "+", ppos, node, t1, t2, i1, i2);
    }

    if (i1->tag == CPT_ARITH
        && (i2->tag == CPT_POINTER || i2->tag == CPT_ARRAY)) {
      // swap t1 and t2
      node->node.refs[3] = t2;
      node->node.refs[5] = t1;
      t1 = node->node.refs[3];
      t2 = node->node.refs[5];
      i1 = sema_get_expr_type(t1);
      i2 = sema_get_expr_type(t2);
    }

    if ((i1->tag == CPT_POINTER || i1->tag == CPT_ARRAY)
        && i2->tag == CPT_ARITH) {
      int idx;

      cast_to_pointer(&t1, &i1, &node->node.refs[3]);
      if (sema_is_void_pointer(i1)) {
        c_warn(ppos, "`void *' pointer is used in arithmetic");
      }
      idx = sema_typeinfo_to_index(i2);
      if (idx >= C_FLOAT && idx <= C_DOUBLE) {
        return inv_binop(ppos, "+");
      }
      if (idx != get_ptrdiff_t_index()) {
        t2 = make_cast_node(t2, get_ptrdiff_t_index(), &node->node.refs[5]);
        i2 = sema_get_expr_type(t1);
      }
      rt = typeinfo_clone(i1, 0);
      node->node.sema = sinfo_create_type(rt);
      return 0;
    }

    return inv_binop(ppos, "+");

  case COP_SUB:
    if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    cast_enum_to_integral(&t1, &i1, 0, pps[0]);
    cast_enum_to_integral(&t2, &i2, 0, pps[1]);

    if (i1->tag == CPT_ARITH && i2->tag == CPT_ARITH) {
      return balance_arithmetic(0, 0, "-", ppos, node, t1, t2, i1, i2);
    }
    
    if ((i1->tag == CPT_POINTER || i1->tag == CPT_ARRAY)
        && (i2->tag == CPT_POINTER || i2->tag == CPT_ARRAY)) {
      cast_to_pointer(&t1, &i1, &node->node.refs[3]);
      cast_to_pointer(&t2, &i2, &node->node.refs[5]);
      if (i1->t_pointer.type->tag == CPT_FUNCTION) return inv_binop(ppos, "-");
      if (i2->t_pointer.type->tag == CPT_FUNCTION) return inv_binop(ppos, "-");
      if (!sema_types_compatible_no_CV(i1, i2)) {
        return inv_binop(ppos, "-");
      }
      if (sema_is_void_pointer(i1) || sema_is_void_pointer(i2)) {
        c_warn(ppos, "`void *' pointer is used in arithmetic");
      }
      if (!same_type(i1, i2)) {
        t2 = make_cast_node2(t2, typeinfo_clone(i1, 0), pps[1]);
        i2 = sema_get_expr_type(t2);
      }
      rt = sema_index_to_typeinfo(get_ptrdiff_t_index());
      node->node.sema = sinfo_create_type(rt);
      return 0;
    }

    if (i1->tag == CPT_POINTER || i1->tag == CPT_ARRAY) {
      int idx;

      cast_to_pointer(&t1, &i1, &node->node.refs[3]);
      if (i2->tag != CPT_ARITH) {
        return inv_binop(ppos, "-");
      }
      idx = sema_typeinfo_to_index(i2);
      if (idx >= C_FLOAT && idx <= C_DOUBLE) {
        return inv_binop(ppos, "-");
      }
      if (sema_is_void_pointer(i1)) {
        c_warn(ppos, "`void *' pointer is used in arithmetic");
      }
      if (idx != get_ptrdiff_t_index()) {
        t2 = make_cast_node(t2, get_ptrdiff_t_index(), &node->node.refs[5]);
        i2 = sema_get_expr_type(t1);
      }
      rt = typeinfo_clone(i1, 0);
      node->node.sema = sinfo_create_type(rt);
      return 0;
    }

    return inv_binop(ppos, "-");

  case COP_MUL:
  case COP_DIV:
    if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    opstr = c_operation_str(cop);
    return balance_arithmetic(0, 0, opstr, ppos, node, t1, t2, i1, i2);

  case COP_ASR:
  case COP_ASL:
  case COP_BITOR:
  case COP_BITXOR:
  case COP_BITAND:
  case COP_MOD:
    if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i1 = sema_get_expr_type(t1);
    if (analyze_expr(t2, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    i2 = sema_get_expr_type(t2);

    opstr = c_operation_str(cop);
    return balance_arithmetic(1, 0, opstr, ppos, node, t1, t2, i1, i2);

  default:
    SWERR(("Bad binary operation: %d", cop));
  }

  if (rt) {
    node->node.sema = sinfo_create_type(rt);
  }

  return 0;
}

static int
analyze_postfix_op(tree_t node, struct sema_scope *scope,
                   struct scopes_info *jmp_scopes)
{
  tree_t t1;
  int cop;
  typeinfo_t i1, rt = 0;
  const char *opstr;
  pos_t *ppos;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRPOSTFIX);

  t1 = node->node.refs[3];
  cop = sema_get_expr_opcode(node, &ppos, &opstr);

  if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
  i1 = sema_get_expr_type(t1);

  switch (cop) {
  case COP_POSTINC:
  case COP_POSTDEC:
    if (!STI_IS_LVALUE(typeinfo_get_bits(i1))) {
      c_err(ppos, "lvalue required");
      return -1;
    }
    if (STI_IS_CONST(typeinfo_get_bits(i1))) {
      c_err(ppos, "attempt to modify read-only storage");
      return -1;
    }

    if (i1->tag == CPT_ENUM || i1->tag == CPT_ARITH) {
      rt = typeinfo_clone(i1, 0);
      break;
    }
    if (i1->tag == CPT_POINTER) {
      if (sema_is_void_pointer(i1)) {
        c_warn(ppos, "`void *' pointer is used in arithmetic");
      }
      rt = typeinfo_clone(i1, 0);
      break;
    }

    return inv_unop(ppos, opstr);
  default:
    SWERR(("Bad postfix operation: %d", cop));
  }

  if (rt) {
    node->node.sema = sinfo_create_type(rt);
  }
  return 0;
}

static int
analyze_unop(tree_t node, struct sema_scope *scope,
             struct scopes_info *jmp_scopes)
{
  tree_t t1;
  int cop;
  typeinfo_t i1, rt = 0;
  char const *opstr;
  pos_t *ppos;
  int ind1;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRUNARY);
  t1 = node->node.refs[4];
  cop = sema_get_expr_opcode(node, &ppos, &opstr);

  if (analyze_expr(t1, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
  ASSERT(t1->node.sema);
  i1 = sema_get_expr_type(t1);

  switch (cop) {
  case COP_PREINC:
  case COP_PREDEC:
    if (!STI_IS_LVALUE(typeinfo_get_bits(i1))) {
      c_err(ppos, "lvalue required");
      return -1;
    }
    if (STI_IS_CONST(typeinfo_get_bits(i1))) {
      c_err(ppos, "attempt to modify read-only storage");
      return -1;
    }

    if (i1->tag == CPT_ENUM || i1->tag == CPT_ARITH) {
      rt = typeinfo_clone(i1, 0);
      break;
    }
    if (i1->tag == CPT_POINTER) {
      if (sema_is_void_pointer(i1)) {
        c_warn(ppos, "`void *' pointer is used in arithmetic");
      }
      rt = typeinfo_clone(i1, 0);
      break;
    }

    return inv_unop(ppos, opstr);

  case COP_SIZEOF:
    /* normally, these errors are cought in subexpression */
    if (sema_is_void_type(i1)) {
      c_err(ppos, "sizeof applied to void type");
      return -1;
    }
    if (sema_is_void_array_type(i1)) {
      c_err(ppos, "sizeof applied to array of voids");
      return -1;
    }
    if (sema_get_type_size(i1) == SEMA_NO_SIZE) {
      c_err(ppos, "sizeof applied to an incomplete type");
      return -1;
    }
    rt = sema_index_to_typeinfo(get_size_t_index());
    break;

  case COP_DEREF:
    if (i1->tag == CPT_ARRAY) {
      // FIXME: maybe insert cast?
      rt = typeinfo_clone(i1->t_array.type, 0);
      typeinfo_set_bits(rt, STI_ADDRESS | STI_LVALUE);
    } else if (i1->tag == CPT_POINTER) {
      rt = typeinfo_clone(i1->t_pointer.type, 0);
      typeinfo_set_bits(rt, STI_ADDRESS | STI_LVALUE);
    } else if (i1->tag == CPT_FUNCTION) {
      rt = typeinfo_clone(i1, 0);
      typeinfo_set_bits(rt, STI_ADDRESS | STI_LVALUE);
    } else {
      return inv_unop(ppos, opstr);
    }

    if (sema_is_void_type(rt)) {
      c_err(ppos, "dereferencing `void *' pointer");
      return -1;
    }
    if (rt->tag == CPT_FUNCTION) {
      break;
    }
    if (rt->tag == CPT_ARRAY) {
      break;
    }
    if (sema_get_type_size(rt) == SEMA_NO_SIZE) {
      c_err(ppos, "dereferencing pointer to incomplete type");
      return -1;
    }
    break;

  case COP_ADDRESS:
    if (!STI_IS_ADDRESS(typeinfo_get_bits(i1)))
      return inv_unop(ppos, "&");
    if (i1->tag == CPT_ARRAY) {
      //rt = typeinfo_create_pointer(STI_CONST, i1->t_array.type);
      rt = typeinfo_create_pointer(0, i1);
    } else {
      rt = typeinfo_create_pointer(0, i1);
    }
    break;

  case COP_PLUS:   
  case COP_MINUS:
    cast_enum_to_integral(&t1, &i1, 0, &node->node.refs[4]);
    if (i1->tag != CPT_ARITH) return inv_unop(ppos, opstr);
    ind1 = sema_typeinfo_to_index(i1);
    if (ind1 < C_INT) {
      t1 = make_cast_node(t1, C_INT, 0);
      node->node.refs[4] = t1;
      i1 = sema_get_expr_type(t1);
      ind1 = C_INT;
    }
    if (ind1 == C_FLOAT && !sema_option_float_arith) {
      t1 = make_cast_node(t1, C_DOUBLE, 0);
      node->node.refs[4] = t1;
      i1 = sema_get_expr_type(t1);
      ind1 = C_DOUBLE;
    }
    rt = sema_index_to_typeinfo(ind1);
    break;

  case COP_LOGNOT:
    // FIXME: check for some pathological cases
    rt = sema_index_to_typeinfo(C_INT);
    break;

  case COP_BITNOT:
    cast_enum_to_integral(&t1, &i1, 0, &node->node.refs[4]);
    if (i1->tag != CPT_ARITH) return inv_unop(ppos, "~");
    ind1 = sema_typeinfo_to_index(i1);
    if (ind1 >= C_FLOAT) return inv_unop(ppos, "~");
    if (ind1 < C_INT) {
      t1 = make_cast_node(t1, C_INT, 0);
      node->node.refs[4] = t1;
      i1 = sema_get_expr_type(t1);
    }
    rt = sema_index_to_typeinfo(ind1);
    break;
  default:
    SWERR(("Bad unary operation: %d", cop));
  }

  if (rt) {
    node->node.sema = sinfo_create_type(rt);
  }

  return 0;
}

static int
process_kr_arguments(tree_t node, tree_t par, tree_t *pp1,
                     struct sema_scope *scope, struct scopes_info *jmp_scopes)
{
  typeinfo_t tipar;
  int idxpar;

  if (!par) {
    ASSERT(node);
    ASSERT(node->kind == NODE_EXPRCALL);
    par = node->node.refs[5];
    pp1 = &node->node.refs[5];
  }
  while (par) {
    if (analyze_expr(par, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
    tipar = sema_get_expr_type(par);
    if (tipar->tag == CPT_ARITH || tipar->tag == CPT_ENUM) {
      if (tipar->tag == CPT_ENUM) {
        struct sema_def *ed = tipar->t_enum.def;
        ASSERT(ed->flags & SSC_ENUM);
        idxpar = sema_typeinfo_to_index(ed->type);
        par = make_cast_node(par, idxpar, pp1);
      } else {
        idxpar = sema_typeinfo_to_index(tipar);
      }
      if (idxpar < C_INT) {
        par = make_cast_node(par, C_INT, pp1);
      } else if (idxpar == C_FLOAT && !sema_option_float_arith) {
        par = make_cast_node(par, C_DOUBLE, pp1);
      }
    } else if (tipar->tag == CPT_ARRAY || tipar->tag == CPT_FUNCTION) {
      cast_to_pointer(&par, &tipar, pp1);
    }

    pp1 = &par->node.refs[0];
    par = *pp1;
  }

  return 0;
}

static int
analyze_funcall(tree_t node, struct sema_scope *scope, int cntx,
                struct scopes_info *jmp_scopes)
{
  pos_t *ppos;
  tree_t fexpr;
  tree_t params, parj, prevparj;
  typeinfo_t iexpr, ipar, rt, iform;
  struct sema_def *formj;
  tree_t *pp1;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRCALL);

  ppos = &node->node.pos.beg;
  fexpr = node->node.refs[3];
  params = node->node.refs[5];

  if (fexpr && fexpr->kind == NODE_EXPRIDENT) {
    struct sema_def *d = 0;

    d = sema_search_scope(fexpr->node.refs[3]->id.id, scope, SSC_REGULAR);
    // go to root definition
    if (d && d->root) d = d->root;
    // advance to implementation, if such exists
    if (d && d->impl) d = d->impl;

    if (!d) {
      /* implicit function definition */
      struct sema_scope *gs = scope;
      typeinfo_t ti = NULL;

      while (gs->up) gs = gs->up;
      ti = typeinfo_create_arith(0, C_INT);
      ti = typeinfo_create_function(STI_FKR | STI_LVALUE, ti,
                                    NULL, //sema_scope_create(gs),
                                    NULL);
      typeinfo_set_bits(ti, STI_ADDRESS);
        
      sema_put_ident(gs,
                     SSC_EXTERN | SSC_PROTO | SSC_REGULAR,
                     fexpr->node.refs[3]->id.id, 0,
                     ti, SSC_PUT_FIRST,
                     NULL, NULL);

      c_warn(ppos, "implicit declaration of function `%s'",
             ident_get(fexpr->node.refs[3]->id.id));
    }
  }

  if (analyze_expr(fexpr, scope, EK_LVALUE, 0, jmp_scopes) < 0) return -1;
  iexpr = sema_get_expr_type(fexpr);

  if (iexpr->tag == CPT_POINTER) {
    fexpr = make_deref_node(fexpr, iexpr, &node->node.refs[3]);
    iexpr = sema_get_expr_type(fexpr);
  }

  if (iexpr->tag != CPT_FUNCTION) {
    c_err(ppos, "called object is not a function");
    return -1;
  }

  if (STI_IS_FKR(iexpr->t_function.bits) ||
      (STI_IS_FVAR(iexpr->t_function.bits) && !iexpr->t_function.par_scope->reg.first)) {
    // either old style function, or f(...) function
    // we do not attempt to check types of parameters

    // FIXME: ???
    if (process_kr_arguments(node, 0, &node->node.refs[0], scope,
                             jmp_scopes)) return -1;
                         
  } else {
    // do strict parameter checking
    formj = 0;
    if (iexpr->t_function.par_scope) {
      formj = iexpr->t_function.par_scope->reg.first;
    }
    for (parj = params, prevparj = 0; parj && formj; formj = formj->next) {
      if (analyze_expr(parj, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
      ipar = sema_get_expr_type(parj);
      iform = formj->type;

      if (prevparj) {
        pp1 = &prevparj->node.refs[0];
      } else {
        pp1 = &node->node.refs[5];
      }

      if (do_assignment(iform, ipar, pp1, parj, 0, ppos, 0, 0,
                        "function call") < 0) return -1;
      prevparj = *pp1;
      parj = prevparj->node.refs[0];
    }

    if (formj && !parj) {
      c_err(ppos, "too few arguments to function call");
      return -1;
    } else if (STI_IS_FVAR(iexpr->t_function.bits) && !formj
               && parj) {
      ASSERT(prevparj);
      if (process_kr_arguments(node, parj, &prevparj->node.refs[0],
                               scope, jmp_scopes) < 0) {
        return -1;
      }
    } else if (!formj && parj) {
      c_err(ppos, "too many arguments to function call");
      return -1;
    }
  }

  rt = typeinfo_clone(iexpr->t_function.ret_type, 0);
  node->node.sema = sinfo_create_type(rt);

  if (cntx != EK_VOID && sema_is_void_type(rt))
    return err_void_not_ignored(ppos);

  return 0;
}

static int
analyze_array(tree_t node, struct sema_scope *scope, afaccess_t *pafacc,
              struct scopes_info *jmp_scopes)
{
  pos_t  *ppos;
  tree_t      arr, ind;
  typeinfo_t  tarr, tind, rt, size_def = 0;
  int         ii, mult = 0;
  afaccess_t  afprev = 0, taf = 0;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRARRAY);

  ppos = &node->node.pos.beg;
  arr = node->node.refs[3];
  ind = node->node.refs[5];

  if (analyze_expr(arr, scope, EK_LVALUE, &afprev, jmp_scopes) < 0) return -1;
  if (analyze_expr(ind, scope, EK_VALUE, 0, jmp_scopes) < 0) return -1;
  tarr = sema_get_expr_type(arr);
  tind = sema_get_expr_type(ind);

  if (tind->tag == CPT_ARRAY || tind->tag == CPT_POINTER) {
    node->node.refs[3] = ind;
    node->node.refs[5] = arr;
    arr = node->node.refs[3];
    ind = node->node.refs[5];
    tarr = sema_get_expr_type(arr);
    tind = sema_get_expr_type(ind);
  }

  if (tarr->tag != CPT_ARRAY && tarr->tag != CPT_POINTER) {
    c_err(ppos, "subscipted value is neither array nor pointer");
    return -1;
  }
  cast_enum_to_integral(&ind, &tind, 0, &node->node.refs[5]);
  if (tind->tag != CPT_ARITH) {
    c_err(ppos, "array subsript is not an integer");
    return -1;
  }
  ii = sema_typeinfo_to_index(tind);
  if (ii >= C_FLOAT) {
    c_err(ppos, "array subsript is not an integer");
    return -1;
  }
  if (ii == C_CHAR) {
    c_warn(ppos, "array subscript has type `char'");
  }
  if (ii != C_INT && ii != C_UINT) {
    ind = make_cast_node(ind, C_INT, 0);
    node->node.refs[5] = ind;
    tind = sema_get_expr_type(ind);
  }

  if (tarr->tag == CPT_ARRAY && tarr->t_array.size_expr) {
    ASSERT(tarr->t_array.size_def);
    rt = typeinfo_clone(tarr->t_array.type, 0);
    mult = (unsigned) -1;
    size_def = tarr->t_array.size_def;
  } else if (tarr->tag == CPT_ARRAY) {
    rt = typeinfo_clone(tarr->t_array.type, 0);
    mult = tarr->t_array.elnum;
  } else {
    rt = typeinfo_clone(tarr->t_pointer.type, 0);
    afprev = 0;
    mult = (unsigned) -1;
  }
  ALLOC(taf);
  taf->tag = SAF_ARRAY;
  taf->tree_expr = node;
  taf->type = rt;
  taf->prev = afprev;
  taf->mult = mult;
  taf->type = rt;
  taf->size_def = size_def;
  if (afprev) {
    afprev->next = taf;
  } else {
    if (!node->node.refs[1]) {
      node->node.refs[1] = tree_make_sema();
    }
    node->node.refs[1]->sema.sema.arr.chain = taf;
  }
  if (pafacc) *pafacc = taf;
  typeinfo_set_bits(rt, STI_ADDRESS | STI_LVALUE);
  node->node.sema = sinfo_create_type(rt);
  return 0;
}

static int
analyze_ternary(tree_t node, struct sema_scope *scope, int cntx,
                struct scopes_info *jmp_scopes)
{
  pos_t *ppos;
  tree_t t1, t2, t3;
  typeinfo_t i1, i2, i3;
  semainfo_t *psema;
  int idx2 = -1, idx3 = -1, indr = -1;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRTERNARY);
  psema = &node->node.sema;
  ppos = &node->node.pos.beg;
  t1 = node->node.refs[3];
  t2 = node->node.refs[5];
  t3 = node->node.refs[7];
  if (analyze_expr(t1, scope, EK_TEST, 0, jmp_scopes) < 0) return -1;
  if (analyze_expr(t2, scope, cntx, 0, jmp_scopes) < 0) return -1;
  if (analyze_expr(t3, scope, cntx, 0, jmp_scopes) < 0) return -1;
  i1 = sema_get_expr_type(t1);
  (void) i1;
  i2 = sema_get_expr_type(t2);
  (void) i2;
  i3 = sema_get_expr_type(t3);
  (void) i3;

  if (sema_is_void_type(i2) && sema_is_void_type(i3)) {
    *psema = sinfo_create_type(typeinfo_create_builtin(0, C_VOID));
    return 0;
  }
  if (sema_is_void_type(i2)) {
    // we need cast the third expression to void type
    make_void_cast_node(t3, &node->node.refs[7]);
    *psema = sinfo_create_type(typeinfo_create_builtin(0, C_VOID));
    return 0;
  }
  if (sema_is_void_type(i3)) {
    // we need cast the second expression to void type
    make_void_cast_node(t2, &node->node.refs[5]);
    *psema = sinfo_create_type(typeinfo_create_builtin(0, C_VOID));
    return 0;
  }

  /* cast arrays and functions to pointers */
  cast_to_pointer(&t2, &i2, &node->node.refs[5]);
  cast_to_pointer(&t3, &i3, &node->node.refs[7]);
  if (i2->tag == CPT_POINTER && i3->tag == CPT_POINTER) {
    // the both pointers must have the same type
    if (!are_comparable_pointers(i2, i3)) {
      c_warn(ppos, "pointer type mismatch in conditional expression");
      make_cast_node2(t2, ti_create_void_pointer(), &node->node.refs[5]);
      make_cast_node2(t3, ti_create_void_pointer(), &node->node.refs[7]);
      *psema = sinfo_create_type(ti_create_void_pointer());
      return 0;
    }
    if (!same_type(i2, i3)) {
      make_cast_node2(t3, typeinfo_clone(i2, 0), &node->node.refs[7]);
    }
    *psema = sinfo_create_type(typeinfo_clone(i2, 0));
    //    *psema = sinfo_create_type(typeinfo_create_pointer(0, typeinfo_clone(i2->t_pointer.type, 0)));
    return 0;
  }

  // if both expressions are of the same enumerated type, should
  // we get the whole type as enumerated, or as corresponding integral?
  if (i2->tag == CPT_ENUM && i3->tag == CPT_ENUM
      && i2->t_enum.def && i2->t_enum.def == i3->t_enum.def) {
    *psema = sinfo_create_type(typeinfo_clone(i2, 0));
    return 0;
  }

  cast_enum_to_integral(&t2, &i2, 0, &node->node.refs[5]);
  cast_enum_to_integral(&t3, &i3, 0, &node->node.refs[7]);

  if (i2->tag == CPT_ARITH) idx2 = sema_typeinfo_to_index(i2);
  if (i3->tag == CPT_ARITH) idx3 = sema_typeinfo_to_index(i3);
  
  if (i2->tag == CPT_POINTER) {
    if (idx3 >= C_FIRST_INT && idx3 <= C_LAST_INT) {
      if (is_literal_0(t3)) {
        i3 = typeinfo_clone(i2, 0);
        t3 = make_cast_node2(t3, i3, &node->node.refs[7]);
        i3 = sema_get_expr_type(t3);
        *psema = sinfo_create_type(typeinfo_clone(i2, 0));
        return 0;
      } else {
        c_warn(ppos,
               "pointer/integer type mismatch in conditional expression");
        idx2 = get_pointer_index();
        t2 = make_cast_node(t2, idx2,&node->node.refs[5]);
      }
    } else {
      c_err(ppos, "type mismatch in conditional expression");
      return -1;
    }
  }
  if (i3->tag == CPT_POINTER) {
    if (idx2 >= C_FIRST_INT && idx2 <= C_LAST_INT) {
      if (is_literal_0(t2)) {
        i2 = typeinfo_clone(i3, 0);
        t2 = make_cast_node2(t2, i2, &node->node.refs[5]);
        i2 = sema_get_expr_type(t2);
        *psema = sinfo_create_type(typeinfo_clone(i3, 0));
        return 0;
      } else {
        c_warn(ppos,
               "pointer/integer type mismatch in conditional expression");
        idx3 = get_pointer_index();
        t3 = make_cast_node(t3, idx3,&node->node.refs[7]);
        i3 = sema_get_expr_type(t3);
      }
    } else {
      c_err(ppos, "type mismatch in conditional expression");
      return -1;
    }
  }

  if (idx2 != -1 && idx3 != -1) {
    indr = c_get_balanced_type(0, idx2, idx3);
    if (indr <= 0) {
      c_err(ppos, "type mismatch in conditional expression");
      return -1;
    }
    if (idx2 != indr) {
      t2 = make_cast_node(t2, indr, &node->node.refs[5]);
    }
    if (idx3 != indr) {
      t3 = make_cast_node(t3, indr, &node->node.refs[7]);
    }
    *psema = sinfo_create_type(sema_index_to_typeinfo(indr));
    return 0;
  }

  if (!same_type(i2, i3)) {
    c_err(ppos, "type mismatch in conditional expression");
    return -1;
  }
  *psema = sinfo_create_type(typeinfo_clone(i3, 0));
  return 0;
}

int
sema_is_nop_typecast(typeinfo_t t1, typeinfo_t t2)
{
  int idx1, idx2;

  if (t1->tag != CPT_ARITH || t2->tag != CPT_ARITH) return 0;
  idx1 = sema_typeinfo_to_index(t1);
  idx2 = sema_typeinfo_to_index(t2);
  if (idx1 == C_INT && idx2 == C_LONG) return 1;
  if (idx1 == C_LONG && idx2 == C_INT) return 1;
  if (idx1 == C_UINT && idx2 == C_ULONG) return 1;
  if (idx1 == C_ULONG && idx2 == C_UINT) return 1;
  return 0;
}

static int
analyze_cast(tree_t node, struct sema_scope *scope, int cntx,
             struct scopes_info *jmp_scopes)
{
  tree_t     d1 = 0, d2 = 0, d3 = 0, d4 = 0, d5 = 0;
  typeinfo_t t1, t2;
  pos_t *ppos;

  ppos = &node->node.pos.beg;
  d1 = node->node.refs[4];
  ASSERT(d1 && d1->kind == NODE_DECL);
  d2 = d1->node.refs[3];
  d3 = d1->node.refs[4];
  ASSERT(!d3 || d3->kind == NODE_INITDECLR);
  if (d3 && d3->kind == NODE_INITDECLR) {
    d4 = d3->node.refs[3];
    d5 = d3->node.refs[5];
  }
  ASSERT(!d5);
  t1 = make_typeinfo(d2, scope, NULL, 0, d4, 1, 1, 0);
  ASSERT(t1);

  if (sema_is_void_type(t1)) {
    /* any expression can be casted to void */
    if (STI_GET_CV(t1->t_builtin.bits)) {
      c_warn(ppos, "useless qualifier in `void' cast");
      t1->t_builtin.bits &= ~STI_CVMASK;
    }

    if (analyze_expr(node->node.refs[6], scope, EK_VOID, 0,
                     jmp_scopes) < 0) return -1;
    node->node.sema = sinfo_create_type(t1);
    return 0;
  }

  if (analyze_expr(node->node.refs[6], scope, EK_VALUE, 0,
                   jmp_scopes) < 0) return -1;
  t2 = sema_get_expr_type(node->node.refs[6]);

  if (t1->tag == CPT_FUNCTION) {
    c_err(ppos, "cast specifies function type");
    return -1;
  }
  if (t1->tag == CPT_ARRAY) {
    c_err(ppos, "cast specifies array type");
    return -1;
  }
  if (t1->tag == CPT_AGGREG) {
    c_err(ppos, "cast specifies aggregate type");
    return -1;
  }
  if (t2->tag == CPT_AGGREG) {
    c_err(ppos, "aggregate type cannot be casted");
    return -1;
  }

  /* FIXME: not all the combinations are available */

  node->node.sema = sinfo_create_type(t1);
  return 0;
}

static int
analyze_sizeof(tree_t node, struct sema_scope *scope, int cntx)
{
  tree_t     d1 = 0, d2 = 0, d3 = 0, d4 = 0, d5 = 0;
  typeinfo_t ti;
  pos_t *ppos;

  ppos = &node->node.pos.beg;
  d1 = node->node.refs[5];
  ASSERT(d1 && d1->kind == NODE_DECL);
  d2 = d1->node.refs[3];
  d3 = d1->node.refs[4];
  if (d3 && d3->kind == NODE_INITDECLR) {
    d4 = d3->node.refs[3];
    d5 = d3->node.refs[5];
  }
  ASSERT(!d5);
  ti = make_typeinfo(d2, scope, NULL, 0, d4, 1, 1, 0);
  if (sema_is_void_type(ti)) {
    c_err(ppos, "sizeof applied to void type");
    return -1;
  }
  if (sema_is_void_array_type(ti)) {
    c_err(ppos, "sizeof applied to array of voids");
    return -1;
  }
  if (sema_get_type_size(ti) == SEMA_NO_SIZE) {
    c_err(ppos, "sizeof applied to an incomplete type");
    return -1;
  }
  ASSERT(!d1->node.sema);
  d1->node.sema = sinfo_create_type(ti);
  node->node.sema = sinfo_create_type(sema_index_to_typeinfo(get_size_t_index()));
  return 0;
}

static int
analyze_field(tree_t node, struct sema_scope *scope, int cntx,
              afaccess_t *pafacc, struct scopes_info *jmp_scopes)
{
  typeinfo_t ti, t2;
  int op, cv;
  pos_t *ppos;
  struct sema_def *sdef = 0, *fdef = 0;
  afaccess_t paflist = 0, aft = 0;

  ASSERT(node);
  ASSERT(node->kind == NODE_EXPRFIELD);
  if (pafacc) *pafacc = 0;

  if (analyze_expr(node->node.refs[3], scope, EK_LVALUE, &paflist,
                   jmp_scopes) < 0)
    return -1;
  ti = sema_get_expr_type(node->node.refs[3]);

  op = sema_get_expr_opcode(node, &ppos, 0);
  ASSERT(op == COP_FIELD || op == COP_FIELDREF);

  if (op == COP_FIELDREF) {
    if (ti->tag == CPT_POINTER) {
      ti = ti->t_pointer.type;
    } else if (ti->tag == CPT_ARRAY) {
      ti = ti->t_array.type;
    } else {
      c_err(ppos, "left side of `->' is not a pointer to structure or union");
      return -1;
    }
    if (ti->tag != CPT_AGGREG) {
      c_err(ppos, "left side of `->' is not a pointer to structure or union");
      return -1;
    }
    paflist = 0;
  } else {
    if (ti->tag != CPT_AGGREG) {
      c_err(ppos, "left side of `.' is not a structure or union");
      return -1;
    }
  }
  ASSERT(ti->tag == CPT_AGGREG);
  cv = typeinfo_get_cv(ti);
  sdef = ti->t_aggreg.def;

  if (!sdef->nest) {
    c_err(ppos, "access to incomplete structure or union");
    return -1;
  }
  fdef = sema_search_this_scope(node->node.refs[5]->id.id,
                                sdef->nest, SSC_REGULAR);
  if (!fdef) {
    c_err(ppos, "structure or union does not have field `%s'",
          ident_get(node->node.refs[5]->id.id));
    return -1;
  }
  ASSERT(fdef->type);
  node->node.refs[1] = tree_make_sema();
  node->node.refs[1]->sema.sema.field.def = fdef;
  ALLOC(aft);
  aft->tag = SAF_FIELD;
  aft->tree_expr = fdef;
  aft->type = fdef->type;
  aft->mult = 1;
  if (fdef->bit_num) {
    aft->mult = 0;
  }
  if (paflist) {
    paflist->next = aft;
    aft->prev = paflist;
    if (paflist->tag == SAF_FIELD && !fdef->bit_num)
      aft->mult = paflist->mult + 1;
  } else {
    if (!node->node.refs[1]) {
      node->node.refs[1] = tree_make_sema();
    }
    node->node.refs[1]->sema.sema.field.chain = aft;
  }
  if (pafacc) *pafacc = aft;
  if (fdef->type->tag != CPT_ARITH || !fdef->bit_num) {
    cv |= STI_ADDRESS;
  }
  t2 = typeinfo_clone(fdef->type, 0);
  typeinfo_set_bits(t2, cv | STI_LVALUE);
  node->node.sema = sinfo_create_type(t2);

  return 0;
}

static int
count_string_length(tree_t node)
{
  int len = 0;

  if (!node) return 0;
  ASSERT(node->kind == NODE_EXPRSTRING);
  len = count_string_length(node->node.refs[3]);
  len += node->node.refs[4]->str.len - 1;
  return len;
}
static int
copy_to_string_buf(tree_t node, char *buf, int pos)
{
  tree_t strnode;

  if (!node) return pos;
  ASSERT(node->kind == NODE_EXPRSTRING);

  strnode = node->node.refs[4];
  pos = copy_to_string_buf(node->node.refs[3], buf, pos);
  memcpy(buf + pos, strnode->str.val, strnode->str.len);
  return pos + strnode->str.len - 1;
}
static void
analyze_string(tree_t node)
{
  typeinfo_t t;

  ASSERT(node->kind == NODE_EXPRSTRING);

  if (node->node.refs[3]) {
    size_t len;
    unsigned char *buf;

    len = count_string_length(node);
    buf = (unsigned char*) tree_alloc(len + 1);
    memset(buf, 0, len + 1);
    copy_to_string_buf(node, buf, 0);
    node->node.refs[4]->str.len = len + 1;
    node->node.refs[4]->str.val = buf;
    node->node.refs[3] = 0;
  }

  t = typeinfo_create_arith(0, C_CHAR);
  t = typeinfo_create_pointer(0, t);
  node->node.sema = sinfo_create_type(t);
  // lvalue? addressable?
}

static int
count_lstring_length(tree_t node)
{
  int len = 0;
  tree_t tok;

  if (!node) return 0;
  ASSERT(node->kind == NODE_EXPRLSTRING);
  tok = node->node.refs[4];
  ASSERT(tok && tok->kind == TOK_LSTRING);
  len = count_lstring_length(node->node.refs[3]);
  len += tok->lstr.len - 1;
  return len;
}
static int
copy_to_lstring_buf(tree_t node, wchar_t *buf, int pos)
{
  tree_t strnode;

  if (!node) return pos;
  ASSERT(node->kind == NODE_EXPRLSTRING);

  strnode = node->node.refs[4];
  pos = copy_to_lstring_buf(node->node.refs[3], buf, pos);
  memcpy(buf + pos, strnode->lstr.val, strnode->lstr.len * sizeof(buf[0]));
  return pos + strnode->lstr.len - 1;
}
static void
analyze_lstring(tree_t node)
{
  typeinfo_t t;

  ASSERT(node->kind == NODE_EXPRLSTRING);

  if (node->node.refs[3]) {
    size_t len;
    wchar_t *buf;

    len = count_lstring_length(node);
    buf = (wchar_t*) tree_alloc((len + 1) * sizeof(buf[0]));
    memset(buf, 0, (len + 1) * sizeof(buf[0]));
    copy_to_lstring_buf(node, buf, 0);
    node->node.refs[4]->lstr.len = len + 1;
    node->node.refs[4]->lstr.val = buf;
    node->node.refs[3] = 0;
  }

  t = sema_index_to_typeinfo(get_wchar_t_index());
  t = typeinfo_create_pointer(0, t);
  node->node.sema = sinfo_create_type(t);
  // lvalue? addressable?
}

static int
analyze_va_start(tree_t node, struct sema_scope *scope, int cntx,
                 struct scopes_info *jmp_scopes)
{
  typeinfo_t t;
  pos_t *ppos = 0;
  tree_t e2 = 0;
  semainfo_t s2 = 0;
  struct sema_def *idef = 0;
  struct sema_scope *iscope = 0;
  struct sema_def *fdef = 0;
  typeinfo_t ft;

  ppos = &node->node.pos.beg;
  if (analyze_expr(node->node.refs[5], scope, EK_LVALUE, 0, jmp_scopes) < 0)
    return -1;
  if (analyze_expr(node->node.refs[7], scope, EK_VALUE, 0, jmp_scopes) < 0)
    return -1;
  t = sema_get_expr_type(node->node.refs[5]);
  ASSERT(t);
  if (t->tag != CPT_BUILTIN) goto _invalid_argument;
  if (t->t_builtin.ind != C_VA_LIST) goto _invalid_argument;
  if (!STI_IS_LVALUE(t->t_builtin.bits)) goto _invalid_argument;
  if (STI_IS_CONST(t->t_builtin.bits)) goto _invalid_argument;

  /* check second argument */
  e2 = node->node.refs[7];
  ASSERT(e2);
  /* second parameter must be identifier */
  if (e2->kind != NODE_EXPRIDENT) goto _invalid_par;
  s2 = e2->node.sema;
  ASSERT(s2);
  ASSERT(s2->tag == ST_IDUSE);
  idef = s2->s_iduse.def;
  ASSERT(idef);
  iscope = idef->scope;
  ASSERT(iscope);
  /* second parameter must be function argument */
  if (iscope->g.tag != SSC_ARG_SCOPE) goto _invalid_par;
  fdef = iscope->def;
  ASSERT(fdef);
  ft = fdef->type;
  ASSERT(ft);
  ASSERT(ft->tag == CPT_FUNCTION);
  /* function must have variable parameter list */
  if (!STI_IS_FVAR(ft->t_function.bits)) goto _invalid_par;
  /* second parameter must be the last parameter */
  if (idef->next != NULL) goto _invalid_par;

  t = typeinfo_create_builtin(0, C_VOID);
  node->node.sema = sinfo_create_type(t);
  return 0;

 _invalid_argument:
  c_err(ppos, "invalid first argument to `va_start'");
  return -1;

 _invalid_par:
  c_err(ppos, "invalid second argument to `va_start'");
  return -1;
}
static int
analyze_va_arg(tree_t node, struct sema_scope *scope, int cntx,
               struct scopes_info *jmp_scopes)
{
  typeinfo_t t;
  pos_t *ppos = 0;
  typeinfo_t t1;
  tree_t d1 = 0, d2 = 0, d3 = 0, d4 = 0, d5 = 0;
  int idx = C_INT;

  ppos = &node->node.pos.beg;
  if (analyze_expr(node->node.refs[5], scope, EK_LVALUE, 0,
                   jmp_scopes) < 0) return -1;
  t = sema_get_expr_type(node->node.refs[5]);
  ASSERT(t);
  if (t->tag != CPT_BUILTIN) goto _invalid_argument;
  if (t->t_builtin.ind != C_VA_LIST) goto _invalid_argument;
  if (!STI_IS_LVALUE(t->t_builtin.bits)) goto _invalid_argument;
  if (STI_IS_CONST(t->t_builtin.bits)) goto _invalid_argument;

  d1 = node->node.refs[7];
  ASSERT(d1 && d1->kind == NODE_DECL);
  d2 = d1->node.refs[3];
  d3 = d1->node.refs[4];
  if (d3 && d3->kind == NODE_INITDECLR) {
    d4 = d3->node.refs[3];
    d5 = d3->node.refs[5];
  }
  ASSERT(!d5);
  t1 = make_typeinfo(d2, scope, NULL, 0, d4, 1, 1, 0);
  if (!t1) return -1;

  if (t1->tag == CPT_FUNCTION) goto _invalid_type;
  if (t1->tag == CPT_ARRAY) goto _invalid_type;
  if (sema_is_void_type(t1)) goto _invalid_type;
  if (t1->tag == CPT_ENUM)  goto _invalid_type;
  if (t1->tag == CPT_ARITH) {
    idx = sema_typeinfo_to_index(t1);
    if (idx >= C_FIRST_INT && idx < C_INT) goto _invalid_type;
    if (idx == C_FLOAT) goto _invalid_type;
  }

  node->node.sema = sinfo_create_type(t1);
  return 0;

 _invalid_argument:
  c_err(ppos, "invalid first argument to `va_arg'");
  return -1;

 _invalid_type:
  c_err(ppos, "invalid type to `va_arg'");
  return -1;
}
static int
analyze_va_end(tree_t node, struct sema_scope *scope, int cntx,
               struct scopes_info *jmp_scopes)
{
  typeinfo_t t;
  pos_t *ppos = 0;

  ppos = &node->node.pos.beg;
  if (analyze_expr(node->node.refs[5], scope, EK_LVALUE, 0,
                   jmp_scopes) < 0) return -1;
  t = sema_get_expr_type(node->node.refs[5]);
  ASSERT(t);
  if (t->tag != CPT_BUILTIN) goto _invalid_argument;
  if (t->t_builtin.ind != C_VA_LIST) goto _invalid_argument;
  if (!STI_IS_LVALUE(t->t_builtin.bits)) goto _invalid_argument;
  if (STI_IS_CONST(t->t_builtin.bits)) goto _invalid_argument;

  t = typeinfo_create_builtin(0, C_VOID);
  node->node.sema = sinfo_create_type(t);
  return 0;

 _invalid_argument:
  c_err(ppos, "invalid argument to `va_end'");
  return -1;
}

static int
analyze___FUNCTION__(tree_t node, struct sema_scope *scope)
{
  pos_t *ppos;
  typeinfo_t t = 0;
  struct sema_def *def;
  unsigned char *idstr = 0;
  unsigned char *idstr2 = 0;

  ppos = &node->node.pos.beg;
  if (!scope || !scope->func) {
    c_err(ppos, "__FUNCTION__ must be used only inside functions");
    return -1;
  }
  scope = scope->func;
  def = scope->def;
  ASSERT(def);
  idstr = ident_get(def->name);
  node->node.refs[1] = tree_make_sema();
  idstr2 = tree_alloc(strlen(idstr) + 1);
  strcpy(idstr2, idstr);
  node->node.refs[1]->sema.sema.ident.function = idstr2;
  t = typeinfo_create_arith(0, C_CHAR);
  t = typeinfo_create_pointer(0, t);
  node->node.sema = sinfo_create_type(t);
  return 0;
}

static int
analyze___builtin_retval(tree_t node, struct sema_scope *scope)
{
  pos_t *ppos;
  typeinfo_t t = 0, ft;
  struct sema_def *def;

  ppos = &node->node.pos.beg;
  if (!scope) goto invalid_position;

  def = scope->def;
  if (def && !scope->func) {
    // function prototype?
    ASSERT(def->type);
    ft = def->type;
    if (ft->tag != CPT_FUNCTION) goto invalid_position;
  } else {
    if (!def && !scope->func) goto invalid_position;
    scope = scope->func;
    def = scope->def;
    ASSERT(def);
    ft = def->type;
    ASSERT(ft->tag == CPT_FUNCTION);
  }

  ft = ft->t_function.ret_type;
  if (ft->tag == CPT_BUILTIN && ft->t_builtin.ind == C_VOID) {
    c_err(ppos, "__builtin_retval cannot be used in `void' function");
    return -1;
  }

  t = typeinfo_clone(ft, 0);
  node->node.sema = sinfo_create_type(t);
  return 0;

 invalid_position:
  c_err(ppos, "__builtin_retval must be used only inside functions");
  return -1;
}

static int
analyze_asmargs(tree_t node, struct sema_scope *scope, int expr_allowed,
                struct scopes_info *jmp_scopes)
{
  tree_t p;

  for (p = node; p; p = p->node.refs[0]) {
    if (!p->node.refs[5]) continue;
    if (analyze_expr(p->node.refs[5], scope, EK_VALUE, 0,
                     jmp_scopes) < 0) return -1;
    if (expr_allowed) continue;
    if (p->node.refs[5]->kind == NODE_EXPRIDENT) continue;
    c_err(&node->node.pos.beg, "asm argument must be identifier here");
  }
  return 0;
}

static int
analyze_asm(tree_t node, struct sema_scope *scope, int cntx,
            struct scopes_info *jmp_scopes)
{
  if (analyze_asmargs(node->node.refs[7], scope, 0, jmp_scopes) < 0) return -1;
  if (analyze_asmargs(node->node.refs[9], scope, 1, jmp_scopes) < 0) return -1;

  node->node.sema = sinfo_create_type(typeinfo_create_builtin(0, C_VOID));
  return 0;
}

static void analyze_stmt_list(tree_t, struct sema_scope *, struct sema_def *,
                              struct scopes_info *, int);

static int
analyze_exprstmt(tree_t node, struct sema_scope *scope, int cntx,
                 struct scopes_info *jmp_scopes)
{
  struct sema_scope *new_scope, **p;
  tree_t pexpr, lastexpr = 0;

  if (cntx == EK_LVALUE) {
    c_err(&node->node.pos.beg, "invalid lvalue");
    return -1;
  }
  if (!jmp_scopes) {
    c_err(&node->node.pos.beg, "expression statement is invalid here");
    return -1;
  }

  /* the last statement in the nesting compound statement must be
     the expression statement */

  new_scope = sema_scope_create(scope);
  for (p = &scope->nest; *p; p = &(*p)->next);
  (*p) = new_scope;

  if (cntx == EK_VOID) {
    analyze_stmt_list(node->node.refs[5], new_scope, 0, jmp_scopes, 0);
    // maybe we should find the last statement, and copy its type?
    node->node.sema = sinfo_create_type(typeinfo_create_builtin(0, C_VOID));
    return 0;
  }

  analyze_stmt_list(node->node.refs[5], new_scope, 0, jmp_scopes, 0);

  // find the last statement in the list
  for (pexpr = node->node.refs[5]; pexpr; pexpr = pexpr->node.refs[0]) {
    lastexpr = pexpr;
    (void) lastexpr;
  }

  abort();

  // TODO complete

  /*
  if (jmp_scopes) {
    new_jmp_sc = *jmp_scopes;
  } else {
    memset(&new_jmp_sc, 0, sizeof(new_jmp_sc));
    new_jmp_sc.ret_scope = new_scope;
  }

      node->node.sema = sinfo_create_scope(new_scope);
  */
}

static int
analyze_expr(tree_t node, struct sema_scope *scope, int cntx,
             afaccess_t *pafacc, struct scopes_info *jmp_scopes)
{
  //struct sema_scope *s;
  semainfo_t *psema;
  struct sema_def   *d;
  typeinfo_t t;

  if (!node) return 0;
  psema = &node->node.sema;
  (void) psema;

  switch (node->kind) {
  case NODE_EXPRSTRING:
    analyze_string(node);
    break;

  case NODE_EXPRLSTRING:
    analyze_lstring(node);
    break;

  case NODE_EXPRCONST:
    t = sema_get_value_type(&node->node.refs[3]->val.val);
    node->node.sema = sinfo_create_type(t);
    break;

  case NODE_EXPRIDENT:
    switch (builtin_lookup(node->node.refs[3]->id.id)) {
    case C_BUILTIN_FUNCTION:
    case C_BUILTIN_FUNC:
      return analyze___FUNCTION__(node, scope);
    case C_BUILTIN_RETVAL:
      return analyze___builtin_retval(node, scope);
    }
    d = sema_search_scope(node->node.refs[3]->id.id, scope, SSC_REGULAR);
    if (d && d->root) d = d->root;
    // advance to implementation, if such exists
    if (d && d->impl) d = d->impl;
    if (!d) {
      c_err(&node->node.pos.beg, "Identifier `%s' is not declared",
            ident_get(node->node.refs[3]->id.id));
      return -1;
    }
    if (d->root) {
      d = d->root;
    }
    d->use_cntr++;
    node->node.sema = sinfo_create_iduse(d);
    break;

  case NODE_EXPRBINARY:
    return analyze_binop(node, scope, jmp_scopes);

  case NODE_EXPRUNARY:
    return analyze_unop(node, scope, jmp_scopes);

  case NODE_EXPRPOSTFIX:
    return analyze_postfix_op(node, scope, jmp_scopes);

  case NODE_EXPRBRACKETS:
    if (analyze_expr(node->node.refs[4], scope, cntx, pafacc, jmp_scopes) < 0)
      return -1;
    t = sema_get_expr_type(node->node.refs[4]);
    if (t) {
      typeinfo_t old = t;
      t = typeinfo_clone(old, 0);
      // inherit LVALUE and ADDRESS flags
      typeinfo_set_bits(t, typeinfo_get_bits(old) & STI_LMASK);
    }
    node->node.sema = sinfo_create_type(t);
    break;

  case NODE_EXPRCALL:
    return analyze_funcall(node, scope, cntx, jmp_scopes);

  case NODE_EXPRARRAY:
    return analyze_array(node, scope, pafacc, jmp_scopes);

  case NODE_EXPRSIZEOF:
    return analyze_sizeof(node, scope, cntx);

  case NODE_EXPRCAST:
    return analyze_cast(node, scope, cntx, jmp_scopes);

  case NODE_EXPRTERNARY:
    return analyze_ternary(node, scope, cntx, jmp_scopes);

  case NODE_EXPRFIELD:
    return analyze_field(node, scope, cntx, pafacc, jmp_scopes);

  case NODE_EXPRVASTART:
    return analyze_va_start(node, scope, cntx, jmp_scopes);
  case NODE_EXPRVAARG:
    return analyze_va_arg(node, scope, cntx, jmp_scopes);
  case NODE_EXPRVAEND:
    return analyze_va_end(node, scope, cntx, jmp_scopes);
  case NODE_EXPRASM:
    return analyze_asm(node, scope, cntx, jmp_scopes);
  case NODE_EXPRSTMT:
    return analyze_exprstmt(node, scope, cntx, jmp_scopes);

  default:
    BADNODE(node);
  }
  return 0;
}

static struct sema_scope_list *
build_scope_list(struct sema_scope *s, struct sema_scope *d)
{
  struct sema_scope *spi, *dpi, *cs;
  struct sema_scope_list *list = 0, **pp = &list, *t;

  /* find a common scope */
  for (spi = s; spi; spi = spi->up) {
    for (dpi = d; dpi; dpi = dpi->up) {
      if (spi == dpi) break;
    }
    if (dpi) break;
  }
  ASSERT(spi);
  ASSERT(spi == dpi);
  ASSERT(spi->up);
  ASSERT(spi->g.tag != SSC_ARG_SCOPE);
  cs = spi;

  for (dpi = d; dpi != cs; dpi = dpi->up) {
    ALLOC(t);
    t->mode = ST_SCOPE_ENTRY;
    t->scope = dpi;
    t->next = list;
    list = t;
  }

  for (spi = s; spi != cs; spi = spi->up) {
    ALLOC(t);
    t->mode = ST_SCOPE_EXIT;
    t->scope = spi;
    t->next = *pp;
    *pp = t;
    pp = &t->next;
  }

  return list;
}

static void
finalize_gotos(struct sema_scope *f_scope)
{
  struct sema_def *def;
  struct sema_list *gotos;
  semainfo_t si;

  def = f_scope->labels.first;
  while (def) {
    if (!def->tree) {
      c_err(def->ppos, "label `%s' used but not defined",
            ident_get(def->name));
    } else if (!def->use_cntr) {
      c_warn(def->ppos, "label `%s' defined but not used",
             ident_get(def->name));
    }
    def = def->next;
  }

  for (gotos = f_scope->gotos; gotos; gotos = gotos->next) {
    si = (semainfo_t) gotos->item;
    ASSERT(si->tag == ST_GOTO);
    if (!si->s_goto.def) continue;
    if (!si->s_goto.def->tree) continue;
    si->s_goto.scopes = build_scope_list(si->s_goto.use_scope,
                                         si->s_goto.def->scope);
  }
}

static void
analyze_goto(tree_t node, struct sema_scope *scope)
{
  struct sema_scope *f_scope;
  ident_t            lab_id = ident_empty;
  pos_t             *ppos = 0;
  struct sema_def   *def;
  semainfo_t        *psema;
  tree_t             def_node = 0;

  ASSERT(node);
  ASSERT(node->kind == NODE_LABID || node->kind == NODE_STGOTO);

  f_scope = scope->func;
  psema = &node->node.sema;
  switch (node->kind) {
  case NODE_LABID:
    lab_id = node->node.refs[3]->id.id;
    ppos = &node->node.pos.beg;
    def_node = node;
    break;
  case NODE_STGOTO: 
    lab_id = node->node.refs[4]->id.id;
    ppos = &node->node.pos.beg;
    def_node = 0;
    break;
  }
  ASSERT(lab_id != ident_empty);

  /* scan the label definition for duplicates */
  def = f_scope->labels.first;
  while (def) {
    if (def->name == lab_id) break;
    def = def->next;
  }

  if (def) {
    // label is redefined
    if (def_node && def->tree) {
      c_err(ppos, "duplicate label `%s'", ident_get(lab_id));
    } else if (!def->tree) {
      def->tree = def_node;
    }
  } else {
    def = sema_put_ident(f_scope, SSC_LABEL, lab_id, ppos, 0, 0, 0, def_node);
  }
  if (node->kind == NODE_STGOTO) {
    *psema = sinfo_create_goto(def, scope, 0);
    sema_add_to_gotos(f_scope, *psema);
    def->use_cntr++;
  } else {
    def->scope = scope;
    *psema = sinfo_create_iduse(def);
  }
}

static void
analyze_labels(tree_t node, struct sema_scope *scope)
{
  struct sema_scope *sw_scope;
  pos_t *ppos;
  struct sema_switem *sw;
  c_value_t *pval;
  int bt;

  switch (node->kind) {
  case NODE_LABID:            /* ident ":" */
    analyze_goto(node, scope);
    break;
    
  case NODE_LABCASE:            /* "case" expr ":" */
    ppos = &node->node.pos.beg;
    for (sw_scope = scope; sw_scope; sw_scope = sw_scope->up) {
      if (sw_scope->swlab) break;
    }
    if (!sw_scope) {
      c_err(ppos, "`case' label not in switch statement");
      return;
    }
    if (analyze_expr(node->node.refs[4], scope, EK_VALUE, 0, 0) < 0)
      return;
    ALLOC(pval);
    if (tree_fold(node->node.refs[4], pval) < 0) {
      c_err(ppos, "constant expression expected");
      return;
    }
    if (pval->tag < C_FIRST_INT || pval->tag > C_LAST_INT) {
      c_err(ppos, "integer expression expected");
      return;
    }
    if (node->node.refs[6]) {
      c_value_t vdiff, v1, vmax, vcur, vtemp;
      struct sema_switem *gsw = 0;
      
      /* case A ... B : */
      memset(&vmax, 0, sizeof(vmax));
      if (analyze_expr(node->node.refs[6], scope, EK_VALUE, 0, 0) < 0)
        return;
      if (tree_fold(node->node.refs[6], &vmax) < 0) {
        c_err(ppos, "constant expression expected");
        return;
      }
      if (vmax.tag < C_FIRST_INT || vmax.tag > C_LAST_INT) {
        c_err(ppos, "integer expression expected");
        return;
      }
      bt = c_value_balanced_type(pval, &vmax);
      c_value_cast(pval, bt, pval);
      c_value_cast(&vmax, bt, &vmax);
      ASSERT(pval->tag == vmax.tag);
      if (c_value_compare(pval, &vmax) > 0) {
        c_err(ppos, "empty case range");
        return;
      }
      memset(&vdiff, 0, sizeof(vdiff));
      c_value_operation(ppos, COP_SUB, &vmax, pval, 0, &vdiff);
      if (c_value_is_large(&vdiff)) {
        c_err(ppos, "case range is too large");
        return;
      }
      c_value_cast(&vdiff, C_ULONG, &vdiff);
      ASSERT(vdiff.tag == C_ULONG);
      if (vdiff.v.ct_ulint > 10000) {
        c_err(ppos, "case range is too large");
        return;
      }
      memset(&v1, 0, sizeof(v1));
      v1.tag = C_UINT;
      v1.v.ct_uint = 1;
      c_value_cast(&v1, bt, &v1);
      vcur = *pval;
      sw = 0;
      while (1) {
        if (!pval) ALLOC(pval);
        *pval = vcur;
        ALLOC(sw);
        sw->next = sw_scope->swlab->case_labels;
        sw_scope->swlab->case_labels = sw;
        sw->gnext = gsw;
        gsw = sw;
        sw->ppos = ppos;
        sw->tree = node;
        sw->scope = scope;
        sw->sw_scope = sw_scope;
        sw->val = pval;
        pval = 0;
        if (!c_value_compare(&vcur, &vmax)) break;
        memset(&vtemp, 0, sizeof(vtemp));
        c_value_operation(ppos, COP_ADD, &vcur, &v1, 0, &vtemp);
        vcur = vtemp;
      }
    } else {
      ALLOC(sw);
      sw->next = sw_scope->swlab->case_labels;
      sw_scope->swlab->case_labels = sw;
      sw->ppos = ppos;
      sw->tree = node;
      sw->scope = scope;
      sw->sw_scope = sw_scope;
      sw->val = pval;
    }
    node->node.sema = sinfo_create_swlab(sw);
    break;
  case NODE_LABDEFAULT:            /* "default" ":" */
    ppos = &node->node.pos.beg;
    for (sw_scope = scope; sw_scope; sw_scope = sw_scope->up) {
      if (sw_scope->swlab) break;
    }
    if (!sw_scope) {
      c_err(ppos, "`default' not in switch statement");
      return;
    }
    if (sw_scope->swlab->default_label) {
      if (!sw_scope->swlab->default_def) {
        c_err(sw_scope->swlab->default_label->ppos, "duplicate `default'");
      }
      sw_scope->swlab->default_def++;
      c_err(ppos, "duplicate `default'");
    }
    ALLOC(sw);
    sw_scope->swlab->default_label = sw;
    sw->ppos = ppos;
    sw->tree = node;
    sw->scope = scope;
    sw->sw_scope = sw_scope;
    node->node.sema = sinfo_create_swlab(sw);
    break;
  }
}

static void
analyze_return(tree_t node, struct sema_scope *scope,
               struct scopes_info *jmp_scopes)
{
  struct sema_scope *fs;
  typeinfo_t ft;
  typeinfo_t rt, rvt;
  pos_t *ppos;
  semainfo_t si;

  ASSERT(node);
  ASSERT(node->kind == NODE_STRETURN);
  ASSERT(jmp_scopes);
  ASSERT(jmp_scopes->ret_scope);

  ppos = &node->node.pos.beg;
  ASSERT(ppos);
  ASSERT(scope->func);
  fs = scope->func;
  ASSERT(fs->def);
  ft = fs->def->type;
  ASSERT(ft);
  ASSERT(ft->tag == CPT_FUNCTION);
  rt = ft->t_function.ret_type;
  ASSERT(rt);

  if (sema_is_void_type(rt) && node->node.refs[4]) {
    if (analyze_expr(node->node.refs[4], scope, EK_VOID, 0, jmp_scopes) < 0)
      return;
    if (!sema_is_void_type(sema_get_expr_type(node->node.refs[4]))) {
      c_warn(ppos, "`return' with a value, in function returning void");
    }
    goto _exit;
  }
  if (sema_is_void_type(rt) && !node->node.refs[4]) {
    goto _exit;
  }
  if (!node->node.refs[4]) {
    c_warn(ppos, "`return' with no value, in function returning non-void");
    goto _exit;
  }
  if (analyze_expr(node->node.refs[4], scope, EK_VALUE, 0, jmp_scopes) < 0)
    return;
  rvt = sema_get_expr_type(node->node.refs[4]);
  if (do_assignment(rt, rvt, &node->node.refs[4], node->node.refs[4],
                    NULL, ppos, 0, 0, "return") < 0)
    return;

 _exit:
  si = sinfo_create_goto(0, scope,
                         build_scope_list(scope, jmp_scopes->ret_scope));
  sema_add_to_gotos(jmp_scopes->ret_scope, si);
  node->node.sema = si;
}

static void analyze_break(tree_t node, struct sema_scope * scope, 
                          struct scopes_info *jmp_scopes)
{
  semainfo_t si;
  pos_t *ppos;

  ASSERT(node);
  ASSERT(node->kind == NODE_STBREAK);
  ASSERT(jmp_scopes);
  ppos = &node->node.pos.beg;

  if (!jmp_scopes->br_scope) {
    c_err(ppos, "break statement not within loop or switch");
    return;
  }

  si = sinfo_create_goto(0, scope,
                         build_scope_list(scope, jmp_scopes->br_scope));
  sema_add_to_gotos(jmp_scopes->ret_scope, si);
  node->node.sema = si;
}
static void analyze_continue(tree_t node, struct sema_scope * scope, 
                             struct scopes_info *jmp_scopes)
{
  semainfo_t si;
  pos_t *ppos;

  ASSERT(node);
  ASSERT(node->kind == NODE_STCONTINUE);
  ASSERT(jmp_scopes);
  ppos = &node->node.pos.beg;

  if (!jmp_scopes->cont_scope) {
    c_err(ppos, "continue statement not within loop");
    return;
  }

  si = sinfo_create_goto(0, scope,
                         build_scope_list(scope, jmp_scopes->cont_scope));
  sema_add_to_gotos(jmp_scopes->ret_scope, si);
  node->node.sema = si;
}

static int
case_label_sort_func(const void *vp1, const void *vp2)
{
  struct sema_switem *p1, *p2;
  int r;

  p1 = *(struct sema_switem**) vp1;
  p2 = *(struct sema_switem**) vp2;
  if (vp1 == vp2) return 0;
  if ((r = c_value_compare(p1->val, p2->val))) return r;
  if ((char*) vp1 < (char*) vp2) return -1;
  return 1;
}

static void
analyze_switch(tree_t node, struct sema_scope *scope,
               struct scopes_info *jmp_scopes)
{
  typeinfo_t etype;
  pos_t *ppos;
  tree_t     enode;
  c_value_t *val1;
  int i, tot;
  struct sema_scope *new_scope;
  struct sema_scope **p;
  int idx, idx2;
  struct sema_switem *swlab;
  struct sema_switem **psw;
  int dup_ind;
  struct scopes_info new_jmp_scopes;

  ASSERT(node);
  ASSERT(node->kind == NODE_STSWITCH);
  ppos = &node->node.pos.beg;
  enode = node->node.refs[5];

  if (analyze_expr(enode, scope, EK_VALUE, 0, jmp_scopes) < 0) return;
  etype = sema_get_expr_type(node->node.refs[5]);
  cast_enum_to_integral(&enode, &etype, 0, &node->node.refs[5]);
  if (etype->tag != CPT_ARITH || etype->t_builtin.ind < C_FIRST_ARITH
      || etype->t_builtin.ind > C_ULLONG) {
    c_err(ppos, "switch quantity is not an integer");
    return;
  }
  idx = sema_typeinfo_to_index(etype);
  idx2 = c_get_balanced_type(0, idx, idx);
  if (idx2 != idx) {
    // promote expression
    enode = make_cast_node(enode, idx2, &node->node.refs[5]);
    etype = sema_get_expr_type(enode);
    idx = idx2;
  }

  /* create a new scope for switch labels */
  new_scope = sema_scope_create(scope);
  for (p = &scope->nest; *p; p = &(*p)->next);
  (*p) = new_scope;
  ALLOC(new_scope->swlab);
  new_scope->swlab->type = sema_index_to_typeinfo(idx);

  new_jmp_scopes = *jmp_scopes;
  new_jmp_scopes.br_scope = scope;
  analyze_stmt_list(node->node.refs[7], new_scope, 0, &new_jmp_scopes, 0);

  /* cast all values to the expression type */
  for (swlab = new_scope->swlab->case_labels; swlab; swlab = swlab->next) {
    ASSERT(swlab->val);
    ASSERT(swlab->val->tag >= C_FIRST_INT && swlab->val->tag <= C_LAST_INT);
    if (swlab->val->tag == idx) continue;
    ALLOC(val1);
    c_value_cast(swlab->val, idx, val1);
    swlab->val = val1;
  }

  /* count the number of labels */
  i = 0;
  for (swlab = new_scope->swlab->case_labels; swlab; swlab = swlab->next) {
    i++;
  }

  /* create an array */
  if (i > 0) {
    new_scope->swlab->nlabel = i;
    new_scope->swlab->sorted_labels = (struct sema_switem**) tree_alloc(i * sizeof(struct sema_switem *));
  }
  i = 0;
  for (swlab = new_scope->swlab->case_labels; swlab; swlab = swlab->next) {
    new_scope->swlab->sorted_labels[i] = swlab;
    i++;
  }

  qsort(new_scope->swlab->sorted_labels, new_scope->swlab->nlabel,
        sizeof(struct sema_switem *), case_label_sort_func);

  /* find and report duplicates */
  dup_ind = 0;
  tot = new_scope->swlab->nlabel;
  psw = new_scope->swlab->sorted_labels;
  for (i = 1; i < tot; i++) {
    if (!c_value_compare(psw[dup_ind]->val, psw[i]->val)) {
      if (i == dup_ind + 1) {
        c_err(psw[dup_ind]->ppos, "duplicate case label");
      }
      c_err(psw[i]->ppos, "duplicate case label");
    } else {
      dup_ind = i;
    }
  }

  /* calculate scopes to enter */
  for (swlab = new_scope->swlab->case_labels; swlab; swlab = swlab->next) {
    swlab->scopes = build_scope_list(new_scope, swlab->scope);
  }
  swlab = new_scope->swlab->default_label;
  if (swlab) {
    swlab->scopes = build_scope_list(new_scope, swlab->scope);
  }

  node->node.sema = sinfo_create_scope(new_scope);
}

static void
analyze_stmt_list(tree_t node, struct sema_scope *scope,
                  struct sema_def *fdef,
                  struct scopes_info *jmp_scopes,
                  int cont_flag)
{
  struct sema_scope  *new_scope;
  struct sema_scope **p;
  struct scopes_info new_jmp_sc;

  while (node) {
    switch (node->kind) {
    case NODE_DECL:
      analyze_declarations(node, scope);
      break;

    case NODE_STEXPR:
      analyze_expr(node->node.refs[3], scope, EK_VOID, 0, jmp_scopes);
      break;
    case NODE_STRETURN:
      analyze_return(node, scope, jmp_scopes);
      break;
    case NODE_STBREAK:
      analyze_break(node, scope, jmp_scopes);
      break;
    case NODE_STCONTINUE:
      analyze_continue(node, scope, jmp_scopes);
      break;
    case NODE_STGOTO:
      analyze_goto(node, scope);
      break;

    case NODE_STBLOCK:
    case NODE_STSUBBLOCK:
      if (fdef) {
        new_scope = sema_function_scope_create(scope, fdef);
      } else {
        new_scope = sema_scope_create(scope);
      }
      if (node->kind == NODE_STSUBBLOCK) {
        new_scope->same_scope = scope;
      }
      for (p = &scope->nest; *p; p = &(*p)->next);
      (*p) = new_scope;
      if (jmp_scopes) {
        new_jmp_sc = *jmp_scopes;
        if (cont_flag) new_jmp_sc.cont_scope = new_scope;
      } else {
        memset(&new_jmp_sc, 0, sizeof(new_jmp_sc));
        new_jmp_sc.ret_scope = new_scope;
      }
      analyze_stmt_list(node->node.refs[4], new_scope, 0, &new_jmp_sc, 0);

      node->node.sema = sinfo_create_scope(new_scope);
      break;
    case NODE_STLABEL:
      analyze_labels(node->node.refs[3], scope);
      analyze_stmt_list(node->node.refs[4], scope, 0, jmp_scopes, 0);
      break;
    case NODE_STIF:
      analyze_expr(node->node.refs[5], scope, EK_TEST, 0, jmp_scopes);
      analyze_stmt_list(node->node.refs[7], scope, 0, jmp_scopes, 0);
      analyze_stmt_list(node->node.refs[9], scope, 0, jmp_scopes, 0);
      break;
    case NODE_STWHILE:
      analyze_expr(node->node.refs[5], scope, EK_TEST, 0, jmp_scopes);
      new_jmp_sc = *jmp_scopes;
      new_jmp_sc.br_scope = scope;
      new_jmp_sc.cont_scope = scope;
      analyze_stmt_list(node->node.refs[7], scope, 0, &new_jmp_sc, 1);
      break;
    case NODE_STDO:
      new_jmp_sc = *jmp_scopes;
      new_jmp_sc.br_scope = scope;
      new_jmp_sc.cont_scope = scope;
      analyze_stmt_list(node->node.refs[4], scope, 0, &new_jmp_sc, 1);
      analyze_expr(node->node.refs[7], scope, EK_TEST, 0, jmp_scopes);
      break;
    case NODE_STFOR:
      analyze_expr(node->node.refs[5], scope, EK_VOID, 0, jmp_scopes);
      analyze_expr(node->node.refs[7], scope, EK_TEST, 0, jmp_scopes);
      analyze_expr(node->node.refs[9], scope, EK_VOID, 0, jmp_scopes);
      new_jmp_sc = *jmp_scopes;
      new_jmp_sc.br_scope = scope;
      new_jmp_sc.cont_scope = scope;
      analyze_stmt_list(node->node.refs[11], scope, 0, &new_jmp_sc, 1);
      break;
    case NODE_STSWITCH:
      analyze_switch(node, scope, jmp_scopes);
      break;
    default:
      BADNODE(node);
    }

    cont_flag = 0;
    node = node->node.refs[0];
  }
}

static int
is_valid_attr_expr(tree_t node)
{
  int op;

  ASSERT(node);
  switch (node->kind) {
  case NODE_EXPRTERNARY:
    if (!is_valid_attr_expr(node->node.refs[3])) return 0;
    if (!is_valid_attr_expr(node->node.refs[5])) return 0;
    return is_valid_attr_expr(node->node.refs[7]);
  case NODE_EXPRBINARY:
    if (!is_valid_attr_expr(node->node.refs[3])) return 0;
    if (!is_valid_attr_expr(node->node.refs[5])) return 0;
    op = node->node.refs[4]->kind;
    if (op == '=' || op == TOK_MULASSIGN || op == TOK_DIVASSIGN
        || op == TOK_MODASSIGN || op == TOK_ADDASSIGN || op == TOK_SUBASSIGN
        || op == TOK_LSHASSIGN || op == TOK_RSHASSIGN
        || op == TOK_ANDASSIGN || op == TOK_ORASSIGN || op == TOK_XORASSIGN)
      return 0;
    return 1;
  case NODE_EXPRCAST:
    return is_valid_attr_expr(node->node.refs[6]);
  case NODE_EXPRSIZEOF:
    return 1;
  case NODE_EXPRUNARY:
    if (!is_valid_attr_expr(node->node.refs[4])) return 0;
    op = node->node.refs[3]->kind;
    if (op == TOK_INCR || op == TOK_DECR) return 0;
    return 1;
  case NODE_EXPRARRAY:
    if (!is_valid_attr_expr(node->node.refs[3])) return 0;
    return is_valid_attr_expr(node->node.refs[5]);
  case NODE_EXPRCALL:
    return 0;
  case NODE_EXPRFIELD:
    return is_valid_attr_expr(node->node.refs[3]);
  case NODE_EXPRPOSTFIX:
    return 0;
  case NODE_EXPRBRACKETS:
    return is_valid_attr_expr(node->node.refs[4]);
  case NODE_EXPRIDENT:
  case NODE_EXPRCONST:
  case NODE_EXPRSTRING:
    return 1;
  case NODE_EXPRVASTART:
  case NODE_EXPRVAARG:
  case NODE_EXPRVAEND:
  case NODE_EXPRINIT:
  case NODE_EXPRASM:
    return 0;
  default:
    SWERR(("unhandled node %d", node->kind));
  }
}

static void
analyze_attributes(struct sema_def *def,
                   tree_t node, /* function node */
                   struct sema_scope *scope, /* the global scope */
                   tree_t attrs, /* function attributes */
                   struct sema_scope *par_scope) /* the parameter scope */
{
  tree_t ai, id, ee;
  int attr_id;
  pos_t *ppos;
  const unsigned char *attr_str;
  tree_t attr_pars[32];
  size_t attr_pars_n;
  typeinfo_t tt;
  int tind;

  if (!attrs) return;

  /*
  print_scope(scope, stderr);
  if (par_scope) {
    print_scope(par_scope, stderr);
  }
  */

  ASSERT(attrs->kind == NODE_ATTRIBUTE);
  for (ai = attrs->node.refs[6]; ai; ai = ai->node.refs[0]) {
    ASSERT(ai->kind == NODE_ATTRITEM);
    ppos = &ai->node.pos.beg;
    id = ai->node.refs[3];
    attr_str = ident_get(id->id.id);
    ASSERT(id);
    ASSERT(id->kind == TOK_IDENT);
    attr_id = attribute_lookup(id->id.id);
    if (attr_id <= 0 || attr_id >= C_ATTR_LAST) {
      c_err(ppos, "unknown attribute `%s'", attr_str);
      continue;
    }
    attr_pars_n = 0;
    for (ee = ai->node.refs[5]; ee && attr_pars_n < 32; ee=ee->node.refs[0]) {
      ASSERT(ee->kind >= NODE_EXPRFIRST && ee->kind <= NODE_EXPRLAST);
      attr_pars[attr_pars_n++] = ee;
    }
    if (ee && attr_pars_n >= 32) goto too_many_parameters;

    switch (attr_id) {
    case C_ATTR_NORETURN:
    case C_ATTR_PURE:
    case C_ATTR_CONST:
    case C_ATTR_NOTHROW:
      if (attr_pars_n > 0) goto too_many_parameters;
      break;
    case C_ATTR_STRING_PRE:
      /* __attribute__((string_pre(lvalue[,length_expr]))) */
      if (attr_pars_n < 1) goto too_few_parameters;
      if (attr_pars_n > 2) goto too_many_parameters;
      /* lvalue must be of some char * type */
      if (analyze_expr(attr_pars[0], par_scope, EK_LVALUE, 0, 0) < 0)
        continue;
      tt = sema_get_expr_type(attr_pars[0]);
      if (!sema_is_string_type(tt)) goto invalid_type;
      if (!is_valid_attr_expr(attr_pars[0])) goto invalid_expr;
      if (attr_pars_n == 2) {
        /* length_expr must be of some integral type */
        if (analyze_expr(attr_pars[1], par_scope, EK_VALUE, 0, 0) < 0)
          continue;
        tt = sema_get_expr_type(attr_pars[1]);
        if (tt->tag != CPT_ARITH) goto invalid_type;
        tind = sema_typeinfo_to_index(tt);
        if (tind < C_FIRST_INT || tind > C_LAST_INT) goto invalid_type;
        if (!is_valid_attr_expr(attr_pars[1])) goto invalid_expr;
      }
      break;
    case C_ATTR_BUFFER_PRE:
      /* __attribute__((buffer_pre(lvalue,length_expr))) */
      if (attr_pars_n < 2) goto too_few_parameters;
      if (attr_pars_n > 2) goto too_many_parameters;
      /* lvalue must be of some char * type */
      if (analyze_expr(attr_pars[0], par_scope, EK_LVALUE, 0, 0) < 0)
        continue;
      tt = sema_get_expr_type(attr_pars[0]);
      if (tt->tag != CPT_POINTER && tt->tag != CPT_ARRAY) goto invalid_type;
      if (!is_valid_attr_expr(attr_pars[0])) goto invalid_expr;
      /* length_expr must be of some integral type */
      if (analyze_expr(attr_pars[1], par_scope, EK_VALUE, 0, 0) < 0)
        continue;
      tt = sema_get_expr_type(attr_pars[1]);
      if (tt->tag != CPT_ARITH) goto invalid_type;
      tind = sema_typeinfo_to_index(tt);
      if (tind < C_FIRST_INT || tind > C_LAST_INT) goto invalid_type;
      if (!is_valid_attr_expr(attr_pars[1])) goto invalid_expr;
      break;
    case C_ATTR_MALLOC:
    case C_ATTR_ALLOCA:
      /* __attribute__((malloc(lvalue))) */
      if (attr_pars_n < 1) goto too_few_parameters;
      if (attr_pars_n > 1) goto too_many_parameters;
      if (analyze_expr(attr_pars[0], par_scope, EK_LVALUE, 0, 0) < 0)
        continue;
      tt = sema_get_expr_type(attr_pars[0]);
      if (tt->tag != CPT_POINTER && tt->tag != CPT_ARRAY) goto invalid_type;
      if (!is_valid_attr_expr(attr_pars[0])) goto invalid_expr;
      break;
    case C_ATTR_FORMAT:
      // ignore it
      break;
    default:
      SWERR(("unandled attribute `%s'", ident_get(id->id.id)));
    }

    switch (attr_id) {
    case C_ATTR_NORETURN:
      def->attr_flags |= C_BIT_NORETURN;
      break;
    }
    continue;
  too_many_parameters:
    c_err(ppos, "too many parameters for attribute `%s'", attr_str);
    continue;
  too_few_parameters:
    c_err(ppos, "too few parameters for attribute `%s'", attr_str);
    continue;
  invalid_type:
    c_err(ppos, "invalid parameter type for attribute `%s'", attr_str);
    continue;
  invalid_expr:
    c_err(ppos, "invalid parameter for attribute `%s'", attr_str);
    continue;
  }
}

static void
analyze_function(tree_t node, struct sema_scope *scope)
{
  tree_t             declspec, declr;
  typeinfo_t         ti;
  typeinfo_t         ret_type;
  ident_t            id;
  struct sema_def   *dnode, *fdef = 0;
  int                stclass;
  struct sema_scope *par_scope;
  pos_t         *idp;
  pos_t         *scp = 0;
  struct sema_def   *params;
  tree_t             kr_par = 0;
  tree_t             idnode, fdeclr = 0;
  tree_t func_attrs = 0;

  ASSERT(node->kind == NODE_DECLFUNC);
  declspec = node->node.refs[3];
  declr = node->node.refs[4];
  kr_par = node->node.refs[5];
  func_attrs = declr->node.refs[5];

  fdeclr = declr;
  while (fdeclr) {
    switch (fdeclr->kind) {
    case NODE_DECLR:
      fdeclr = fdeclr->node.refs[4];
      break;
    case NODE_DIRDECLR1:
      goto search_fdeclr_out;
    case NODE_DIRDECLR2:
      fdeclr = fdeclr->node.refs[4];
      break;
    case NODE_DIRDECLR3:
    case NODE_DIRDECLR4:
    case NODE_DIRDECLR5:
      if (!fdeclr->node.refs[3] || fdeclr->node.refs[3]->kind==NODE_DIRDECLR1)
        goto search_fdeclr_out;
      fdeclr = fdeclr->node.refs[3];
      break;
    default:
      BADNODE(fdeclr);
    }
  }
 search_fdeclr_out:
  ;

  if (!fdeclr ||
      (fdeclr->kind != NODE_DIRDECLR4 && fdeclr->kind != NODE_DIRDECLR5)
      || !fdeclr->node.refs[3]
      || fdeclr->node.refs[3]->kind != NODE_DIRDECLR1) {
    c_err(&node->node.pos.beg, "invalid function declarator");
    return;
  }

  /* extract the type information of the function */
  ti = make_typeinfo(declspec, scope, NULL, 0, declr, 1, 0, &kr_par);
  if (!ti) return;
  idnode = tree_get_ident_node(declr);
  id = idnode->id.id;
  idp = &idnode->id.pos.beg;
  stclass = sema_get_storclass(declspec, &scp);

  if (id == ident_empty) {
    c_err(0, "function has no name");
    return;
  }
  ASSERT(idp);
  ret_type = ti->t_function.ret_type;
  ASSERT(ret_type);
  if (check_array_size(ti, id, idp, 0) < 0) return;

  if (kr_par) {
    c_err(idp, "invalid function declarator");
    return;
  }
  if (scope->up) {
    c_err(idp, "attempt to define a nested function");
    return;
  }

  if (stclass==SSC_TYPEDEF || stclass==SSC_LOCAL || stclass==SSC_REGISTER) {
    c_err(scp, "function definition declared `%s'",
          sema_SSC_to_string(stclass));
    stclass = 0;
  }
  if (stclass == SSC_EXTERN) {
    c_warn(scp, "function definition declared `extern'");
    stclass = 0;
  }
  ASSERT(!stclass || stclass == SSC_STATIC);

  /* check the typeinfo */
  ASSERT(ti);
  if (ti->tag != CPT_FUNCTION) {
    c_err(idp, "invalid function declarator");
    return;
  }

  /* if the function is declared as foo() { }, mark it as void */
  if (STI_IS_FKR(ti->t_function.bits) &&
      (!ti->t_function.par_scope || !ti->t_function.par_scope->reg.first)) {
    ti->t_function.bits &= ~STI_FMASK;
    ti->t_function.bits |= STI_FVOID;
  }

  if (STI_IS_FKR(ti->t_function.bits)) {
    ti->t_function.impl_par_scope = ti->t_function.par_scope;
    ti->t_function.par_scope = 0;
    /*
    fprintf(stderr, ">>0x%08x, 0x%08x\n",
            (unsigned) ti->t_function.impl_params,
            (unsigned) ti->t_function.impl_par_scope);
    */
  }

  if (STI_IS_FNORM(ti->t_function.bits) || STI_IS_FVAR(ti->t_function.bits)) {
    ti->t_function.impl_par_scope = ti->t_function.par_scope;

    params = ti->t_function.par_scope->reg.first;
    for (; params; params = params->next) {
      if (params->name == ident_empty) {
        c_err(idp, "parameter name omitted");
        /* FIXME: need recovery */
        return;
      }
    }
  }

  if (!ti->t_function.impl_par_scope) {
    ti->t_function.impl_par_scope = sema_scope_create(scope);
  }
  par_scope = ti->t_function.impl_par_scope;
  ASSERT(par_scope);

  if (!sema_is_void_type(ret_type) &&
      sema_get_type_size(ret_type) == SEMA_NO_SIZE) {
    c_err(idp, "return type is an incomplete type");
  }

  // search the function in the scope
  dnode = sema_search_scope(id, scope, SSC_REGULAR);

  if (dnode) {
    int dstcl = 0;
    if (SSC_IS_FUNCTION(dnode->flags)) {
      c_err(idp, "redefinition of `%s'", ident_get(id));
      return;
    }
    if (!SSC_IS_PROTO(dnode->flags)) {
      c_err(idp, "`%s' redefined as different kind of symbol", ident_get(id));
      return;
    }
    if (dnode->impl) {
      c_err(idp, "redefinition of `%s'", ident_get(id));
      return;
    }
    dstcl = SSC_GET_SCLASS(dnode->flags);
    ASSERT(dstcl == SSC_EXTERN || dstcl == SSC_STATIC);
    if (stclass == SSC_STATIC && dstcl != SSC_STATIC) {
      c_warn(idp, "static definition of `%s' follows non-static declaration",
             ident_get(id));
      dnode->flags = (dnode->flags ^ dstcl) | SSC_STATIC;
    } else if (stclass == 0 && dstcl == SSC_STATIC) {
      c_warn(idp, "non-static definition of `%s' follows static declaration",
             ident_get(id));
      dnode->flags = (dnode->flags ^ dstcl);
    }

    if (!match_prototype(&dnode->type, 0, (void *) &dnode->tree,
                         &ti, 1, 0)) {
      c_err(idp, "definition of `%s' does not match prototype", ident_get(id));
    } else if (!STI_IS_FKR(dnode->type->t_function.bits)
               && STI_IS_FKR(ti->t_function.bits)) {
      c_err(idp, "definition of `%s' does not match prototype", ident_get(id));
    }

    fdef = sema_put_ident(scope,
                          SSC_REGULAR | SSC_FUNCTION | stclass,
                          id, idp, ti, 0, par_scope, node);
    dnode->impl = fdef;
    typeinfo_set_bits(ti, STI_ADDRESS);
  } else {
    fdef = sema_put_ident(scope, SSC_REGULAR | SSC_FUNCTION | stclass, id, idp,
                          ti, 0, par_scope, node);
    typeinfo_set_bits(ti, STI_ADDRESS);
  }

  ASSERT(fdef);
  /* create function scope */
  par_scope->def = fdef;
  analyze_stmt_list(node->node.refs[6], par_scope, fdef, 0, 0);

  /* check gotos */
  finalize_gotos(par_scope->nest);

  analyze_attributes(fdef, node, scope, func_attrs, par_scope);

  if (IS_C_BIT_NORETURN(fdef) && !sema_is_void_type(ret_type)) {
    c_err(idp, "only `void' function can have `noreturn' attribute");
  }
}

static sema_init_t analyze_global_init(tree_t *init, struct sema_def *def,
                                       struct sema_scope *scope);

static int
get_scalar_initializer(tree_t init, pos_t *idp, tree_t * p_init_expr,
                       int nest_level, int excess_warn, int no_designator)
{
  tree_t ii, jj;

  if (!init) {
    c_err(idp, "scalar initializer expected");
    return -1;
  }

  for (jj = init; jj; jj = jj->node.refs[0]) {
    ASSERT(jj->kind == NODE_INITEXPR || jj->kind == NODE_INITBLOCK);
    if (jj->node.refs[3]) {
      if (!no_designator)
        c_err(idp, "designator is not allowed");
      no_designator = 1;
      jj->node.refs[3] = 0;
    }
  }
  if (init->node.refs[0]) {
    if (!excess_warn)
      c_warn(idp, "excess elements in scalar initializer");
    excess_warn = 1;
    init->node.refs[0] = 0;
  }

  if (init->kind == NODE_INITEXPR) {
    if (nest_level > 1)
      c_warn(idp, "braces around scalar initializer");
    ASSERT(p_init_expr);
    *p_init_expr = init;
    return 0;
  } else if (init->kind == NODE_INITBLOCK) {
    if (!(ii = init->node.refs[6])) {
      c_err(idp, "scalar initializer expected");
      return -1;
    }
    for (jj = ii ;jj; jj = jj->node.refs[0]) {
      ASSERT(jj->kind == NODE_INITEXPR || jj->kind == NODE_INITBLOCK);
      if (jj->node.refs[3]) {
        if (!no_designator)
          c_err(idp, "designator is not allowed");
        no_designator = 1;
        jj->node.refs[3] = 0;
      }
    }
    if (ii->node.refs[0]) {
      if (!excess_warn)
        c_warn(idp, "excess elements in scalar initializer");
      excess_warn = 1;
      ii->node.refs[0] = 0;
    }
    return get_scalar_initializer(ii, idp, p_init_expr, 
                                  nest_level + 1, excess_warn, no_designator);
  }

  abort();
}

static tree_t
get_first_initexpr(tree_t init)
{
  if (!init) return 0;
  switch (init->kind) {
  case NODE_INITEXPR:
    return init;
  case NODE_INITBLOCK:
    return get_first_initexpr(init->node.refs[6]);
  default:
    abort();
  }
}

/*
 * init - tree for the initializer, should be NODE_INITEXPR, NODE_INITBLOCK
 * scope - the current scope
 * global - the global scope
 * ti - the type being initialized
 * id - the identifier being initialized
 * idp - the identifier position
 * d - the identifier definition entry
 *
 */
static int
analyze_local_init(tree_t init, struct sema_scope *scope,
                   struct sema_scope *global,
                   typeinfo_t ti, ident_t id, pos_t *idp,
                   struct sema_def *d)
  __attribute__((unused));
static int
analyze_local_init(tree_t init, struct sema_scope *scope,
                   struct sema_scope *global,
                   typeinfo_t ti, ident_t id, pos_t *idp,
                   struct sema_def *d)
{
  tree_t p_scalar_init = 0;
  tree_t p1, p2;
  sema_init_t ii;

  if (!init) return 0;

  if (CPT_IS_SCALAR(ti->tag)) {
    if (get_scalar_initializer(init, idp, &p_scalar_init, 0, 0, 0) < 0) {
      return -1;
    }
    ASSERT(p_scalar_init && p_scalar_init->kind == NODE_INITEXPR);
    init = p_scalar_init;

    if (analyze_expr(init->node.refs[5], scope, EK_VALUE, 0, 0) < 0) {
      return -1;
    }
    if (do_assignment(ti, sema_get_expr_type(init->node.refs[5]),
                      &init->node.refs[5], init->node.refs[5], 0,
                      idp, 0, 0, "initializer") < 0) {
      return -1;
    }

    /*
     * even if the expression is a constant expression, we
     * shall not fold it
     */

    /* generate an assignment expression and put a pointer to it
     * into the assign_expr field
     */
    ALLOC(ii);
    ii->type = ti;
    ii->tree_init = init;
    ii->assign_expr = tree_make_node3(NODE_EXPRBINARY, 6,
                                      tree_make_node3(NODE_EXPRIDENT, 4,
                                                      tree_make_ident(TOK_IDENT,  &init->gen.pos.beg, &init->gen.pos.end, d->name)),
                                      tree_make_token('=', &init->gen.pos.beg, &init->gen.pos.end),
                                      init->node.refs[5]);
    /*
     * we want to analyze the newly constructed expression, but in a
     * way to 1) do not reanalyze RHS, 2) bind the LHS variable
     * without considering the current scope state
     */
    d->use_cntr++;
    ii->assign_expr->node.refs[3]->node.sema = sinfo_create_iduse(d);
    if (do_assignment(ti, sema_get_expr_type(init->node.refs[5]),
                      &init->node.refs[5], init->node.refs[5], 
                      &ii->assign_expr->node.sema,
                      idp, 0, 0, "initializer") < 0) {
      // oops, it should not happen
      abort();
    }
    // make sure, that rhs expression has not changed
    ASSERT(ii->assign_expr->node.refs[5] == init->node.refs[5]);

    /* that's it */
    return 0;
  }

  if (!CPT_IS_AGGREG(ti->tag)) {
    c_err(idp, "initializer is not allowed here");
    return -1;
  }

  /* array of chars is in somewhat different */
  if (sema_is_string_type(ti)) {
    if (!(p1 = get_first_initexpr(init)) || !(p2 = p1->node.refs[5])) {
      c_err(idp, "initializer expected");
      return -1;
    }
    if (p2->kind == NODE_EXPRSTRING) {
      // char foo[] = "XXX";
      ASSERT(ti->tag == CPT_ARRAY);
      if (ti->t_array.elnum == SEMA_NO_SIZE) {
        ti->t_array.elnum = p2->node.refs[4]->str.len;
      }
      if (p2->node.refs[4]->str.len > ti->t_array.elnum) {
        c_warn(idp, "initializer-string for array of chars is too long");
      }
      if (get_scalar_initializer(init, idp, &p_scalar_init, 0, 0, 0) < 0) {
        return -1;
      }
      ASSERT(p_scalar_init && p_scalar_init->kind == NODE_INITEXPR);
      init = p_scalar_init;
      if (analyze_expr(init->node.refs[5], scope, EK_VALUE, 0, 0) < 0) {
        return -1;
      }
      ASSERT(sema_is_string_type(sema_get_expr_type(init->node.refs[5])));
      ALLOC(ii);
      ii->type = ti;
      ii->tree_init = init;
      return 0;
    }
  }

  /* array of wide chars is different as well */
  if (sema_is_wstring_type(ti)) {
    if (!(p1 = get_first_initexpr(init)) || !(p2 = p1->node.refs[5])) {
      c_err(idp, "initializer expected");
      return -1;
    }
    if (p2->kind == NODE_EXPRLSTRING) {
      // wchar_t foo[] = L"ZZZ";
      ASSERT(ti->tag == CPT_ARRAY);
      if (ti->t_array.elnum == SEMA_NO_SIZE) {
        ti->t_array.elnum = p2->node.refs[4]->lstr.len;
      }
      if (p2->node.refs[4]->lstr.len > ti->t_array.elnum) {
        c_warn(idp, "initializer-string for array of wide chars is too long");
      }
      if (get_scalar_initializer(init, idp, &p_scalar_init, 0, 0, 0) < 0) {
        return -1;
      }
      ASSERT(p_scalar_init && p_scalar_init->kind == NODE_INITEXPR);
      init = p_scalar_init;
      if (analyze_expr(init->node.refs[5], scope, EK_VALUE, 0, 0) < 0) {
        return -1;
      }
      ASSERT(sema_is_wstring_type(sema_get_expr_type(init->node.refs[5])));
      ALLOC(ii);
      ii->type = ti;
      ii->tree_init = init;
      return 0;
    }
  }

  /* initializer for compound data type */
  if (init->kind != NODE_INITBLOCK) {
    c_err(idp, "invalid initializer");
    return -1;
  }

  /* possible cases: structure, array of unspecified number of elements */
  abort();
}

static int
analyze_local_declaration(tree_t node, struct sema_scope *scope,
                          struct sema_scope *global,
                          typeinfo_t ti, tree_t declspec, int stclass)
{
  tree_t declr;
  ident_t id;
  pos_t *idp;
  struct sema_def *d;
  struct sema_def *dg;
  int oldst;
  unsigned long size;
  tree_t idnode;

  ASSERT(node && node->kind == NODE_INITDECLR);
  ASSERT(ti);

  declr = node->node.refs[3];
  ti = make_typeinfo(declspec, scope, NULL, ti, declr, 1, 0, 0);
  if (!ti) return -1;
  idnode = tree_get_ident_node(declr);
  id = idnode->id.id;
  idp = &idnode->id.pos.beg;
  if (id == ident_empty) return 0;

  /* if ti is an anonymous enum, immediately set the type to the base type */
  if (ti->tag == CPT_ENUM && !ti->t_enum.def->name) {
    ti = ti->t_enum.def->type;
  }

  if (stclass == SSC_EXTERN && node->node.refs[5]) {
    c_warn(idp, "`%s' initialized and declared `extern'", ident_get(id));
    stclass = 0;
  }
  if (stclass == SSC_TYPEDEF && node->node.refs[5]) {
    c_err(idp, "`%s' initialized and declared `typedef'", ident_get(id));
    node->node.refs[5] = 0;
  }

  if (stclass != SSC_TYPEDEF) {
    if (check_array_size(ti, id, idp, 1) < 0) return -1;
    if (ti->tag != CPT_FUNCTION) {
      if (sema_is_void_type(ti)) {
        c_err(idp, "`%s' defined as void object", ident_get(id));
        return -1;
      }
      if (sema_is_void_array_type(ti)) {
        c_err(idp, "`%s' defined as array of voids", ident_get(id));
        return -1;
      }
    }
  }

  d = sema_search_this_scope(id, scope, SSC_REGULAR);
  if (d) {
    // check various redefinition cases
    if (stclass == SSC_TYPEDEF) goto _redefinition;
    else if (ti && ti->tag == CPT_FUNCTION) {
      oldst = SSC_GET_SCLASS(d->flags);
      /* only prototype may be on local level */
      ASSERT(SSC_IS_FUNCTION(d->flags));
      if (stclass == SSC_LOCAL || stclass == SSC_REGISTER) {
        c_err(idp, "invalid storage class specifier");
        return -1;
      }
      if (!SSC_IS_PROTO(d->flags)) goto _redefinition;
      if (SSC_IS_FUNCTION(d->flags)) {
        if (oldst == SSC_STATIC && stclass != SSC_STATIC) {
          c_warn(idp, "static function definition redeclared non-static");
        } else if (oldst != SSC_STATIC && stclass == SSC_STATIC) {
          c_warn(idp, "non-static function definition redeclared static");
        }
        if (!same_type(ti, d->type)) goto _confl_types;
      } else {
        ASSERT(SSC_IS_PROTO(d->flags));
        ASSERT(oldst == SSC_EXTERN || oldst == SSC_STATIC);
        if (oldst == SSC_STATIC && stclass != SSC_STATIC) {
          c_warn(idp, "static function declaration redeclared non-static");
        } else if (oldst != SSC_STATIC && stclass == SSC_STATIC) {
          c_warn(idp, "non-static function declaration redeclared static");
        }
        if (!match_prototype(&d->type, 0, (void*) &d->tree, &ti, 0, 0))
          goto _confl_types;
        dg = sema_search_this_scope(id, global, SSC_REGULAR);
        // if we have function proto definition at local level,
        // it must be at global level as well
        ASSERT(dg);
        return 0;
      }
    } else {
      oldst = SSC_GET_SCLASS(d->flags);
      if (!SSC_IS_PLAIN(d->flags)) goto _redefinition;
      if (oldst == SSC_EXTERN) {
        dg = sema_search_this_scope(id, global, SSC_REGULAR);
        // extern variable must be duplicated at the global level
        ASSERT(dg);
        if (stclass != SSC_EXTERN) goto _redefinition;
        if (!same_type(ti, d->type)) goto _confl_types;
        ASSERT(d->root == dg);
        //return -1;
      } else {
        goto _redefinition;
      }
    }
  } else {
    // add new definition
    if (stclass == SSC_TYPEDEF) {
      d = sema_put_ident(scope, SSC_REGULAR | SSC_TYPEDEF,
                         id, idp, ti, 0, NULL, node);
    } else if (ti && ti->tag == CPT_FUNCTION) {
      if (stclass == SSC_LOCAL || stclass == SSC_REGISTER) {
        c_err(idp, "invalid storage class specifier");
        return -1;
      }

      dg = sema_search_this_scope(id, global, SSC_REGULAR);
      if (dg) {
        oldst = SSC_GET_SCLASS(dg->flags);
        if (!SSC_IS_PROTO(dg->flags) && !SSC_IS_FUNCTION(dg->flags))
          goto _redefinition;
        if (SSC_IS_FUNCTION(dg->flags)) {
          if (oldst == SSC_STATIC && stclass != SSC_STATIC) {
            c_warn(idp, "static function definition redeclared as non-static");
          } else if (oldst != SSC_STATIC && stclass == SSC_STATIC) {
            c_warn(idp, "non-static function definition redeclared as static");
          }
          if (!same_type(ti, dg->type)) goto _confl_types;
        } else {
          ASSERT(SSC_IS_PROTO(dg->flags));
          ASSERT(oldst == SSC_EXTERN || oldst == SSC_STATIC);
          if (oldst == SSC_STATIC && stclass != SSC_STATIC) {
            c_warn(idp, "static function declaration redeclared as non-static");
          } else if (oldst != SSC_STATIC && stclass == SSC_STATIC) {
            c_warn(idp, "non-static function declaration redeclared as static");
          }
          if (!match_prototype(&dg->type, 0, (void*) &dg->tree, &ti, 0, 0))
            goto _confl_types;
        }

        if (!SSC_GET_SCLASS(stclass)) stclass |= SSC_EXTERN;
        d = sema_put_ident(scope, SSC_REGULAR | SSC_PROTO | stclass,
                           id, idp, ti, 0, NULL, node);
        d->root = dg;
        typeinfo_set_bits(ti, STI_ADDRESS);
      } else {
        if (!SSC_GET_SCLASS(stclass)) stclass |= SSC_EXTERN;
        dg = sema_put_ident(global, SSC_REGULAR | SSC_PROTO | stclass,
                            id, idp, ti, SSC_PUT_BUT_LAST, NULL, node);
        d = sema_put_ident(scope, SSC_REGULAR | SSC_PROTO | stclass,
                           id, idp, ti, 0, NULL, node);
        d->root = dg;
        typeinfo_set_bits(ti, STI_ADDRESS);
      }
    } else {
      if (stclass == SSC_EXTERN &&
          (dg = sema_search_this_scope(id, global, SSC_REGULAR))) {

        if (!SSC_IS_PLAIN(stclass)) goto _confl_types;
        if (!same_type(ti, dg->type)) goto _confl_types;
        if (SSC_IS_STATIC(dg->flags)) {
          c_warn(idp, "extern object redeclared as static");
        }

        d = sema_put_ident(scope, SSC_REGULAR | SSC_PLAIN | stclass,
                           id, idp, ti, 0, NULL, node);
        d->root = dg;
        typeinfo_set_bits(ti, STI_ADDRESS | STI_LVALUE);
      } else {
        d = sema_put_ident(scope, SSC_REGULAR | SSC_PLAIN | stclass,
                           id, idp, ti, 0, NULL, node);
        if (stclass == SSC_EXTERN) {
          dg = sema_put_ident(global, SSC_REGULAR | SSC_PLAIN | stclass,
                              id, idp, ti, SSC_PUT_BUT_LAST, NULL, node);
          d->root = dg;
        }
        typeinfo_set_bits(ti, STI_LVALUE);
        if (stclass != SSC_REGISTER) {
          typeinfo_set_bits(ti, STI_ADDRESS);
        }
      }
    }
  }

  /* create semainfo node */
  node->node.sema = sinfo_create_iduse(d);

  if (stclass == SSC_TYPEDEF) return 0;

  if (d->type && d->type->tag == CPT_ARRAY && sema_is_varsize_type(d->type)) {
    scope->varsized = 1;
    d->display_type = typeinfo_create_pointer(0, d->type->t_array.type);
  }

  /* now process initializers */
  if (SSC_IS_STATIC(d->flags)) {
    // statics are initialized like global variables
    d->init = analyze_global_init(&node->node.refs[5], d, scope);
  } else {
    tree_t tinit = node->node.refs[5];
    tree_t iexpr;
    typeinfo_t rht;

    if (!tinit) goto _check_size;
    switch (tinit->kind) {
    case NODE_INITEXPR:
      iexpr = tinit->node.refs[5];
      /*
       * ti - typeinfo for the left-hand side
       */
      if (ti->tag == CPT_ARRAY) {
        // special case: char xxx[] = "zzz";
        //               wchar_t yyy[] = L"xxx";
        typeinfo_t bti = ti->t_array.type;

        if (sema_is_character_type(bti)) {
          if (analyze_expr(iexpr, scope, EK_VALUE, 0, 0) < 0) {
            return -1;
          }
          rht = sema_get_expr_type(iexpr);
          if (!iexpr || iexpr->kind != NODE_EXPRSTRING)
            goto invalid_initializer;
          if (ti->t_array.elnum == SEMA_NO_SIZE) {
            ti->t_array.elnum = iexpr->node.refs[4]->str.len;
          } else {
            if (iexpr->node.refs[4]->str.len > ti->t_array.elnum) {
              c_warn(idp, "initializer-string for array of chars is too long");
            }
          }
          goto _check_size;
        } else if (sema_is_wchar_type(bti)) {
          if (analyze_expr(iexpr, scope, EK_VALUE, 0, 0) < 0) {
            return -1;
          }
          rht = sema_get_expr_type(iexpr);
          if (!iexpr || iexpr->kind != NODE_EXPRLSTRING)
            goto invalid_initializer;
          if (ti->t_array.elnum == SEMA_NO_SIZE) {
            ti->t_array.elnum = iexpr->node.refs[4]->lstr.len;
          } else {
            if (iexpr->node.refs[4]->lstr.len > ti->t_array.elnum) {
              c_warn(idp, "initializer-string for array of chars is too long");
            }
          }
          goto _check_size;
        }

      invalid_initializer:
        c_err(idp, "invalid initializer");
        return -1;
      }
      if (ti->tag == CPT_ARRAY || ti->tag == CPT_FUNCTION) {
        c_err(idp, "invalid initializer");
        return -1;
      }
      if (analyze_expr(iexpr, scope, EK_VALUE, 0, 0) < 0) {
        return -1;
      }
      rht = sema_get_expr_type(iexpr);
      if (do_assignment(ti, rht, &tinit->node.refs[5],
                        iexpr, NULL, idp,
                        0, 1, "initialization") < 0)
        return -1;
      goto _check_size;
    case NODE_INITBLOCK:
      d->init = analyze_global_init(&node->node.refs[5], d, scope);
      goto _check_size;
    default:
      BADNODE(node);
    }
  }

 _check_size:
  if (ti->tag == CPT_ARRAY && !SSC_IS_EXTERN(d->flags)
      && ti->t_array.elnum == SEMA_NO_SIZE) {
    if (!ti->t_array.size_expr) {
      c_err(idp, "array `%s' is assumed to have one element", ident_get(id));
      ti->t_array.elnum = 1;
    }
  } else if (ti->tag != CPT_FUNCTION && !SSC_IS_EXTERN(d->flags)) {
    if ((size = sema_get_type_size(ti)) == SEMA_NO_SIZE) {
      c_err(idp, "storage size of `%s' is not known", ident_get(id));
    }
  }

  return 0;
    
 _redefinition:
  c_err(idp, "redefinition of `%s'", ident_get(id));
  return -1;
 _confl_types:
  c_err(idp, "conflicting types for `%s'", ident_get(id));
  return -1;
}

static void
analyze_declarations(tree_t node, struct sema_scope *scope)
{
  typeinfo_t         ti = NULL;
  tree_t             declspec, idclr;
  int                stclass;
  int                count = 0;
  pos_t         *scp = 0;
  struct sema_scope *global;

  ASSERT(scope);
  global = scope;
  while (global->up) global = global->up;
  ASSERT(global != scope);
  ASSERT(node->kind == NODE_DECL);

  /* we need to count how much objects are declared here */
  for (idclr = node->node.refs[4]; 
       idclr && idclr->kind == NODE_INITDECLR;
       idclr = idclr->node.refs[0]) {
    count++;
  }
  ASSERT(!idclr);

  if (!count) {
    declspec = node->node.refs[3];
    stclass = sema_get_storclass(declspec, &scp);

    if (stclass != 0) {
      c_warn(scp, "useless storage class in empty declaration");
    }
    make_typeinfo(declspec, scope, NULL, NULL, NULL, 0, 0, 0);
    return;
  }

  declspec = node->node.refs[3];
  stclass = sema_get_storclass(declspec, &scp);
  ti = make_declspec(declspec, scope, NULL, 1, 0);
  if (!ti) return;

  for (idclr = node->node.refs[4]; 
       idclr && idclr->kind == NODE_INITDECLR;
       idclr = idclr->node.refs[0]) {

    analyze_local_declaration(idclr, scope, global, ti, declspec, stclass);
  }
  ASSERT(!idclr);
}

/* addr_mode: 0 - value, 1 - address, 2 - array */
static int
is_static_init_expr(tree_t expr, int addr_mode)
{
  int op = 0;
  struct sema_def *def;
  semainfo_t si;
  typeinfo_t t;

  if (!expr) return 1;
  switch (expr->kind) {
  case NODE_EXPRIDENT:
    si = expr->node.sema;
    ASSERT(si);
    ASSERT(si->tag == ST_IDUSE);
    def = si->s_iduse.def;
    ASSERT(def);
    ASSERT(def->type);
    if (def->type->tag == CPT_FUNCTION && addr_mode != 2) return 1;
    if (def->type->tag == CPT_FUNCTION) return 0;
    if (def->type->tag == CPT_ARRAY && !addr_mode) addr_mode = 1;
    if (!addr_mode) {
      if (SSC_IS_ENUMCONST(def->flags)) return 1;
      return 0;
    }
    /* address mode */
    if (addr_mode == 2 && def->type->tag != CPT_ARRAY) return 0;
    ASSERT(SSC_IS_PLAIN(def->flags));
    if (SSC_IS_LOCAL(def->flags) || SSC_IS_REGISTER(def->flags)) return 0;
    return 1;
  case NODE_EXPRCONST:
    return 1;
  case NODE_EXPRSTRING:
    return 1;
  case NODE_EXPRLSTRING:
    return 1;
  case NODE_EXPRFIELD:
    if (!addr_mode) return 0;
    op = sema_get_expr_opcode(expr, 0, 0);
    if (op == COP_FIELDREF) {
      return is_static_init_expr(expr->node.refs[3], 0);
    }
    if (!is_static_init_expr(expr->node.refs[3], 1)) return 0;
    if (addr_mode == 2) {
      t = sema_get_expr_type(expr);
      if (t->tag != CPT_ARRAY) return 0;
    }
    return 1;
  case NODE_EXPRCALL:
    return 0;
  case NODE_EXPRARRAY:
    t = sema_get_expr_type(expr);
    if (t->tag == CPT_ARRAY) addr_mode = 2;
    if (!addr_mode) return 0;
    if (!is_static_init_expr(expr->node.refs[3], 2)) return 0;
    if (!is_static_init_expr(expr->node.refs[5], 0)) return 0;
    if (addr_mode == 2) {
      t = sema_get_expr_type(expr);
      if (t->tag != CPT_ARRAY) return 0;
    }
    return 1;
  case NODE_EXPRUNARY:
    op = sema_get_expr_opcode(expr, 0, 0);
    switch (op) {
    case COP_PREINC:
    case COP_PREDEC:
    case COP_DEREF:
      return 0;
    case COP_SIZEOF:
      return 1;
    case COP_ADDRESS:
      return is_static_init_expr(expr->node.refs[4], 1);
    case COP_PLUS:
    case COP_MINUS:
    case COP_BITNOT:
    case COP_LOGNOT:
      if (addr_mode) return 0;
      return is_static_init_expr(expr->node.refs[4], 0);
    default:
      SWERR(("invalid unary operation: %d", op));
    }
    return 0;
  case NODE_EXPRBINARY:
    op = sema_get_expr_opcode(expr, 0, 0);
    switch (op) {
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
      return 0;
    case COP_COMMA:
    case COP_LOGOR:
    case COP_LOGAND:
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
      if (addr_mode) return 0;
      if (!is_static_init_expr(expr->node.refs[3], addr_mode)) return 0;
      return is_static_init_expr(expr->node.refs[5], addr_mode);
    default:
      SWERR(("invalid binary operation: %d", op));
    }
    return 0;
  case NODE_EXPRTERNARY:
    if (addr_mode) return 0;
    if (!is_static_init_expr(expr->node.refs[3], addr_mode)) return 0;
    if (!is_static_init_expr(expr->node.refs[5], addr_mode)) return 0;
    return is_static_init_expr(expr->node.refs[7], addr_mode);
  case NODE_EXPRSIZEOF:
    return 1;
  case NODE_EXPRCAST:
    return is_static_init_expr(expr->node.refs[6], addr_mode);
  case NODE_EXPRBRACKETS:
    return is_static_init_expr(expr->node.refs[4], addr_mode);
  case NODE_EXPRVASTART:
  case NODE_EXPRVAARG:
  case NODE_EXPRVAEND:
    return 0;
#if 0
  case kExprAsm:
    return 0;
#endif
  default:
    BADNODE(expr);
  }
  return 0;
}

static sema_init_t
analyze_global_init_assign(typeinfo_t type, struct sema_scope *scope,
                           tree_t init, pos_t *ppos, tree_t *pp1)
{
  typeinfo_t et;
  sema_init_t ii;
  tree_t expr;

  ASSERT(init);
  ASSERT(init->kind == NODE_INITEXPR);
  expr = init->node.refs[5];

  if (!expr) return 0;
  if (analyze_expr(expr, scope, EK_VALUE, 0, 0) < 0) return 0;
  et = sema_get_expr_type(expr);
  if (!is_static_init_expr(expr, 0)) {
    c_err(ppos, "initializer element is not constant");
    return 0;
  }
  if (type->tag == CPT_AGGREG || type->tag == CPT_FUNCTION) goto _inv_init;
  if (type->tag == CPT_ARRAY) {
    if (sema_is_character_type(type->t_array.type)) {
      if (expr->kind != NODE_EXPRSTRING) goto _inv_init;
      if (type->t_array.elnum == SEMA_NO_SIZE) {
        type->t_array.elnum = expr->node.refs[4]->str.len;
      } else {
        if (expr->node.refs[4]->str.len > type->t_array.elnum) {
          c_warn(ppos, "initializer-string for array of chars is too long");
        }
      }
    } else if (sema_is_wchar_type(type->t_array.type)) {
      if (expr->kind != NODE_EXPRLSTRING) goto _inv_init;
      if (type->t_array.elnum == SEMA_NO_SIZE) {
        type->t_array.elnum = expr->node.refs[4]->lstr.len;
      } else {
        if (expr->node.refs[4]->lstr.len > type->t_array.elnum) {
          c_warn(ppos, "initializer-string for array of chars is too long");
        }
      }
    } else goto _inv_init;

    ALLOC(ii);
    ii->type = type;
    ii->tree_init = init;
    return ii;
  }

  ASSERT(type->tag != CPT_TYPEDEF);
  if (do_assignment(type, et, pp1, expr, 0, ppos, 0, 0,
                    "initialization") < 0) return 0;
  ALLOC(ii);
  ii->type = type;
  ii->tree_init = init;
  return ii;

 _inv_init:
  c_err(ppos, "invalid initializer");
  return 0;
}

static sema_init_t analyze_global_init_struct(typeinfo_t type,
                                              struct sema_scope *scope,
                                              pos_t *ppos,
                                              tree_t init, tree_t *init_out);

static sema_init_t
analyze_global_init_array(typeinfo_t type,
                          struct sema_scope *scope,
                          pos_t *ppos,
                          tree_t init, tree_t *init_out)
{
  sema_init_t ii = 0;
  sema_init_t *ppi = 0, *newp;
  int a = 0, u = 0, newa = 0;
  int is_resizable = 0;
  int is_index_allowed = 0;
  int was_excess_warn = 0;
  int is_first = 1;
  tree_t wi, newwi, subexpr;
  unsigned idx, maxidx, newidx;
  c_value_t val;
  pos_t *ip = 0;
  typeinfo_t subtype;

  ASSERT(type);
  ASSERT(type->tag == CPT_ARRAY);
  ASSERT(init);
  ASSERT(init->kind == NODE_INITEXPR || init->kind == NODE_INITBLOCK);

  subtype = type->t_array.type;
  ASSERT(subtype);

  if (sema_is_character_type(subtype) && init->kind == NODE_INITEXPR
      && init->node.refs[5] && init->node.refs[5]->kind == NODE_EXPRSTRING) {
    ALLOC(ii);
    ii->type = type;
    ii->tree_init = init;
    if (init_out) *init_out = init->node.refs[0];
    return ii;
  }

  if (type->t_array.elnum == SEMA_NO_SIZE) {
    if (init->kind == NODE_INITEXPR) {
      c_err(ppos, "invalid initializer");
      return 0;
    }
    is_resizable = 1;
    maxidx = (unsigned) -1;
  } else {
    a = u = maxidx = type->t_array.elnum;
    if (!a) a = 1;
    ppi = (sema_init_t *) tree_alloc(a * sizeof(ppi[0]));
    is_resizable = 0;
  }

  if (init->kind == NODE_INITBLOCK) {
    is_index_allowed = 1;
    wi = init->node.refs[6];
  } else {
    wi = init;
  }
  idx = 0;

  while (1) {
    newidx = (unsigned) -1;
    if (!wi) break;
    ASSERT(wi->kind == NODE_INITEXPR || wi->kind == NODE_INITBLOCK);
    if (!is_index_allowed && wi->node.refs[3]) {
      c_err(&wi->node.pos.beg, "initializer index not allowed here");
      wi->node.refs[3] = 0;
    }
    while (wi->node.refs[3]) {
      ASSERT(wi->node.refs[3]->kind == NODE_DESARRAY);
      if (!wi->node.refs[3]->node.refs[4]) {
        wi->node.refs[3] = 0;
        break;
      }

      ip = &wi->node.pos.beg;
      if (analyze_expr(wi->node.refs[3]->node.refs[4], scope, EK_VALUE,
                       0, 0) < 0) {
        wi->node.refs[3] = 0;
        break;
      }
      memset(&val, 0, sizeof(val));
      if (tree_fold(wi->node.refs[3]->node.refs[4], &val) < 0) {
        c_err(ip, "constant expression expected");
        wi->node.refs[3] = 0;
        break;
      }
      if (val.tag < C_FIRST_INT || val.tag > C_LAST_INT) {
        c_err(ip, "integral expression expected");
        wi->node.refs[3] = 0;
        break;
      }
      if (c_value_is_negative(&val)) {
        c_err(ip, "index must be positive number");
        wi->node.refs[3] = 0;
        break;
      }
      if (c_value_is_large(&val)) {
        c_err(ip, "expression is too large");
        wi->node.refs[3] = 0;
        break;
      }
      c_value_cast(&val, C_UINT, &val);
      newidx = val.v.ct_uint;
      if (!is_resizable && newidx >= maxidx) {
        c_err(ip, "index is out of bounds");
        newidx = (unsigned) -1;
        wi->node.refs[3] = 0;
        break;
      }
      break;
    }
    if (newidx == (unsigned) -1) {
      if (is_first) {
        idx = 0;
      } else {
        idx++;
      }
      is_first = 0;
      if (idx == maxidx && !is_index_allowed) break;
      if (!is_resizable && idx >= maxidx) {
        if (!was_excess_warn) {
          c_warn(ppos, "excess elements in array initializer");
        }
        was_excess_warn = 1;
        wi = wi->node.refs[0];
        continue;
      }
    } else {
      is_first = 0;
      idx = newidx;
    }
    if (is_resizable && idx >= a) {
      newa = a;
      if (!newa) newa = 16;
      while (idx >= newa)
        newa *= 2;
      newp = (sema_init_t*) tree_alloc(newa * sizeof(newp[0]));
      memcpy(newp, ppi, a * sizeof(ppi[0]));
      ppi = newp;
      a = newa;
    }
    if (is_resizable && idx >= u) {
      u = idx + 1;
    }
    if (ppi[idx]) {
      c_err(ppos, "duplicated initializer for [%u]", idx);
      wi = wi->node.refs[0];
      continue;
    }

    switch (wi->kind) {
    case NODE_INITEXPR:
      if (subtype->tag == CPT_ARRAY) {
        ppi[idx] = analyze_global_init_array(subtype, scope, ppos,
                                             wi, &newwi);
        if (wi == newwi) {
          c_err(ppos, "zero-size initializer");
          wi = wi->node.refs[0];
        } else {
          wi = newwi;
        }
      } else if (subtype->tag == CPT_AGGREG) {
        ppi[idx] = analyze_global_init_struct(subtype, scope, ppos,
                                             wi, &newwi);
        if (wi == newwi) {
          c_err(ppos, "zero-size initializer");
          wi = wi->node.refs[0];
        } else {
          wi = newwi;
        }
      } else {
        subexpr = wi->node.refs[5];
        ppi[idx] = analyze_global_init_assign(subtype, scope,
                                              wi,
                                              &subexpr->node.pos.beg,
                                              &wi->node.refs[5]);
        wi = wi->node.refs[0];
      }
      break;
    case NODE_INITBLOCK:
      if (subtype->tag == CPT_ARRAY) {
        ppi[idx] = analyze_global_init_array(subtype, scope,
                                             &wi->node.pos.beg,
                                             wi, 0);
      } else if (subtype->tag == CPT_AGGREG) {
        ppi[idx] = analyze_global_init_struct(subtype, scope,
                                              &wi->node.pos.beg,
                                              wi, 0);
      } else {
        c_err(ppos, "invalid initializer");
      }
      wi = wi->node.refs[0];
      break;
    }
  }

  if (type->t_array.elnum == SEMA_NO_SIZE) {
    type->t_array.elnum = u;
  }
  ALLOC(ii);
  ii->type = type;
  ii->nitem = u;
  ii->inits = ppi;

  if (init_out) {
    if (init->kind == NODE_INITBLOCK) {
      *init_out = init->node.refs[0];
    } else {
      *init_out = wi;
    }
  }
  return ii;
}

static sema_init_t
analyze_global_init_struct(typeinfo_t type,
                           struct sema_scope *scope,
                           pos_t *ppos,
                           tree_t init, tree_t *init_out)
{
  int n = 0, i;
  struct sema_def *di = 0;
  struct sema_def *agd = 0;
  typeinfo_t *types, subtype;
  sema_init_t ii;
  tree_t wi, newwi;
  int is_subinit = 0;
  int was_excess_warn = 0;

  (void) was_excess_warn;
  agd = type->t_aggreg.def;
  ASSERT(agd);
  if (!agd->nest) {
    c_err(ppos, "initialization of incomplete structure or union");
    return 0;
  }
  if (agd->flags & SSC_UNION) {
    for (di = agd->nest->reg.first; di; di = di->next) {
      if (di->name != ident_empty) break;
    }
    if (!di) {
      c_err(ppos, "initialization of empty union");
      return 0;
    }
    n = 1;
    types = (typeinfo_t*) alloca(n * sizeof(types[0]));
    types[0] = di->type;
  } else {
    for (di = agd->nest->reg.first; di; di = di->next) {
      if (di->name == ident_empty) continue;
      n++;
    }
    if (!n) {
      c_err(ppos, "initialization of empty structure");
      return 0;
    }
    types = (typeinfo_t*) alloca(n * sizeof(types[0]));
    for (di = agd->nest->reg.first, i = 0; di; di = di->next) {
      if (di->name == ident_empty) continue;
      types[i++] = di->type;
    }
    ASSERT(i == n);
  }
  ALLOC(ii);
  ii->type = type;
  ii->nitem = n;
  ii->inits = (sema_init_t*) tree_alloc(n * sizeof(sema_init_t));

  i = 0;
  if (init->kind == NODE_INITBLOCK) {
    wi = init->node.refs[6];
    is_subinit = 1;
  } else {
    wi = init;
  }

  while (1) {
    if (!wi) break;
    ASSERT(wi->kind == NODE_INITEXPR || wi->kind == NODE_INITBLOCK);
    if (i == n && is_subinit) break;
    if (i == n) {
      /*
      if (was_excess_warn) {
        c_err(ppos, "excess elements in structure initializer");
      }
      */
      was_excess_warn = 1;
      break;
      //continue;
    }
    if (wi->node.refs[3]) {
      c_err(ppos, "initializer index not allowed here");
      wi->node.refs[3] = 0;
    }

    subtype = types[i];
    ASSERT(subtype);
    switch (wi->kind) {
    case NODE_INITEXPR:
      if (subtype->tag == CPT_ARRAY) {
        ii->inits[i] = analyze_global_init_array(subtype, scope, &wi->node.pos.beg, wi, &newwi);
      } else if (subtype->tag == CPT_AGGREG) {
        ii->inits[i] = analyze_global_init_struct(subtype, scope, &wi->node.pos.beg, wi, &newwi);
      } else {
        ii->inits[i] = analyze_global_init_assign(subtype, scope, wi, &wi->node.pos.beg, &wi->node.refs[5]);
        newwi = wi->node.refs[0];
      }
      if (wi == newwi) {
        c_err(ppos, "zero-size initializer");
        wi = wi->node.refs[0];
      } else {
        wi = newwi;
      }
      break;
    case NODE_INITBLOCK:
      if (subtype->tag == CPT_ARRAY) {
        ii->inits[i] = analyze_global_init_array(subtype, scope, &wi->node.pos.beg, wi, 0);
      } else if (subtype->tag == CPT_AGGREG) {
        ii->inits[i] = analyze_global_init_struct(subtype, scope, &wi->node.pos.beg, wi, 0);
      } else {
        c_err(ppos, "invalid initializer");
      }
      wi = wi->node.refs[0];
      break;
    }

    if (!ii->inits[i]) {
      ALLOC(ii->inits[i]);
      ii->inits[i]->type = subtype;
    }
    if (i < n) i++;
  }

  for (; i < n; i++) {
    ALLOC(ii->inits[i]);
    ii->inits[i]->type = types[i];
  }

  if (init_out) {
    if (init->kind == NODE_INITBLOCK) {
      *init_out = init->node.refs[0];
    } else {
      *init_out = wi;
    }
  }

  return ii;
}

static tree_t
get_scalar_init_expr(tree_t node, int w1_flag, int w2_flag)
{
  if (!node) return 0;
  switch (node->kind) {
  case NODE_INITEXPR:
    if (node->node.refs[0] && !w2_flag) {
      c_warn(&node->node.refs[0]->node.pos.beg,
             "excess elements in scalar initializer");
    }
    return node;
  case NODE_INITBLOCK:
    if (!w1_flag) {
      c_warn(&node->node.pos.beg,
             "braces around scalar initializer");
      w1_flag = 1;
    }
    if (node->node.refs[0]) {
      c_warn(&node->node.refs[0]->node.pos.beg,
             "excess elements in scalar initializer");
      w2_flag = 1;
    }
    return get_scalar_init_expr(node->node.refs[6], w1_flag, w2_flag);
  default:
    BADNODE(node);
  }
}

static sema_init_t
analyze_global_init(tree_t *pinit, struct sema_def *def,
                    struct sema_scope *scope)
{
  tree_t init = *pinit;
  pos_t *ppos = 0;

  if (!init) return 0;
  ppos = &init->node.pos.beg;

  if (init->kind == NODE_INITBLOCK && def->type->tag != CPT_ARRAY
      && def->type->tag != CPT_AGGREG) {
    init = get_scalar_init_expr(init->node.refs[6], 0, 0);
    if (!init) return 0;
    init->node.refs[0] = 0;
    *pinit = init;
  }

  switch (init->kind) {
  case NODE_INITEXPR:
    return analyze_global_init_assign(def->type, scope, init,
                                      ppos, &init->node.refs[5]);
  case NODE_INITBLOCK:
    if (def->type->tag == CPT_ARRAY) {
      return analyze_global_init_array(def->type, scope, ppos, init, 0);
    } else if (def->type->tag == CPT_AGGREG) {
      return analyze_global_init_struct(def->type, scope, ppos, init, 0);
    } else {
      c_err(ppos, "invalid initializer");
      return 0;
    }
  default:
    BADNODE(init);
  }
}

static int
analyze_global_declaration(tree_t node, struct sema_scope *scope,
                           typeinfo_t ti, tree_t declspec, int stclass)
{
  tree_t declr;
  ident_t id;
  pos_t *idp;
  struct sema_def *d;
  int oldst;
  sema_init_t newinit;
  tree_t idnode;
  tree_t attrs;
  struct sema_scope *par_scope = 0;

  ASSERT(node && node->kind == NODE_INITDECLR);
  ASSERT(ti);

  declr = node->node.refs[3];
  attrs = declr->node.refs[5];
  ti = make_typeinfo(declspec, scope, NULL, ti, declr, 1, 0, 0);
  if (!ti) return -1;
  idnode = tree_get_ident_node(declr);
  id = idnode->id.id;
  idp = &idnode->id.pos.beg;
  if (id == ident_empty) return 0;

  /* if ti is an anonymous enum, immediately set the type to the base type */
  if (ti->tag == CPT_ENUM && !ti->t_enum.def->name) {
    ti = ti->t_enum.def->type;
  }

  if (stclass == SSC_EXTERN && node->node.refs[5]) {
    c_warn(idp, "`%s' initialized and declared `extern'", ident_get(id));
    stclass = 0;
  }
  if (stclass == SSC_TYPEDEF && node->node.refs[5]) {
    c_err(idp, "`%s' initialized and declared `typedef'", ident_get(id));
    node->node.refs[5] = 0;
  }

  if (stclass != SSC_TYPEDEF) {
    if (check_array_size(ti, id, idp, 1) < 0) return -1;
    if (ti->tag != CPT_FUNCTION) {
      if (sema_is_void_type(ti)) {
        c_err(idp, "`%s' defined as void object", ident_get(id));
        return -1;
      }
      if (sema_is_void_array_type(ti)) {
        c_err(idp, "`%s' defined as array of voids", ident_get(id));
        return -1;
      }
    }
  }

  /*
   * Rules for variable redefinition are actually loose...
   */
  d = sema_search_this_scope(id, scope, SSC_REGULAR);
  if (d) {
    // check various redefinition cases
    if (stclass == SSC_TYPEDEF) goto _redefinition;
    else if (ti && ti->tag == CPT_FUNCTION) {
      /* two function prototypes */
      oldst = SSC_GET_SCLASS(d->flags);
      if (!SSC_IS_PROTO(d->flags) && !SSC_IS_FUNCTION(d->flags))
        goto _redefinition;
      if (SSC_IS_FUNCTION(d->flags)) {
        if (oldst == SSC_STATIC && stclass != SSC_STATIC) {
          c_warn(idp, "static function definition redeclared as non-static");
        } else if (oldst != SSC_STATIC && stclass == SSC_STATIC) {
          c_warn(idp, "non-static function definition redeclared as static");
        }
        if (!same_type(ti, d->type)) goto _confl_types;
        goto _process_initializers;
      }
      ASSERT(SSC_IS_PROTO(d->flags));
      ASSERT(oldst == SSC_EXTERN || oldst == SSC_STATIC||oldst == SSC_BUILTIN);
      if (oldst == SSC_STATIC && stclass != SSC_STATIC) {
        c_warn(idp, "static function declaration redeclared non-static");
      } else if (oldst != SSC_STATIC && stclass == SSC_STATIC) {
        c_warn(idp, "non-static function declaration redeclared static");
      } else if (oldst == SSC_BUILTIN) {
        c_warn(idp, "redefinition of built-in function");
      }
      if (!match_prototype(&d->type, 0, (void*) &d->tree, &ti, 0, 0))
        goto _confl_types;
      goto _process_initializers;
    } else {
      /* two regular variables */
      if (!same_type(ti, d->type)) goto _confl_types;
      if (!SSC_IS_PLAIN(d->flags)) goto _redefinition;
      oldst = SSC_GET_SCLASS(d->flags);
      if (stclass == SSC_EXTERN) {
        if (!oldst || oldst == SSC_EXTERN || oldst == SSC_GLOBAL) {
          if (ti->tag == CPT_ARRAY && d->type->tag == CPT_ARRAY) {
            unsigned long int e1 = ti->t_array.elnum;
            unsigned long int e2 = d->type->t_array.elnum;
            if (e1 != (unsigned) -1 && e2 != (unsigned) -1 && e1 != e2)
              goto _confl_types;
            if (e2 == (unsigned) -1) {
              d->type->t_array.elnum = e1;
            }
          }
          goto _process_initializers;
        }
        ASSERT(oldst == SSC_STATIC);
        goto _redefinition;
      }
      if (stclass == SSC_STATIC) {
        if (!oldst || oldst == SSC_EXTERN || oldst == SSC_GLOBAL)
          goto _redefinition;
        ASSERT(oldst == SSC_STATIC);
        if (d->init && node->node.refs[5])
          goto _redefinition;
        if (ti->tag == CPT_ARRAY && d->type->tag == CPT_ARRAY) {
          unsigned long int e1 = ti->t_array.elnum;
          unsigned long int e2 = d->type->t_array.elnum;
          if (e1 != (unsigned) -1 && e2 != (unsigned) -1 && e1 != e2)
            goto _confl_types;
          if (e2 == (unsigned) -1) {
            d->type->t_array.elnum = e1;
          }
        }
        goto _process_initializers;
      }
      ASSERT(!stclass || stclass == SSC_GLOBAL);
      if (oldst == SSC_STATIC) goto _redefinition;
      if (oldst == SSC_EXTERN) {
        d->flags = SSC_SET_SCLASS(d->flags, stclass);
        if (ti->tag == CPT_ARRAY && d->type->tag == CPT_ARRAY) {
          unsigned long int e1 = ti->t_array.elnum;
          unsigned long int e2 = d->type->t_array.elnum;
          if (e1 != (unsigned) -1 && e2 != (unsigned) -1 && e1 != e2)
            goto _confl_types;
          if (e2 == (unsigned) -1) {
            d->type->t_array.elnum = e1;
          }
        }
        goto _process_initializers;
      }
      ASSERT(!oldst || oldst == SSC_GLOBAL);
      if (d->init && node->node.refs[5])
        goto _redefinition;
      if (ti->tag == CPT_ARRAY && d->type->tag == CPT_ARRAY) {
        unsigned long int e1 = ti->t_array.elnum;
        unsigned long int e2 = d->type->t_array.elnum;
        if (e1 != (unsigned) -1 && e2 != (unsigned) -1 && e1 != e2)
          goto _confl_types;
        if (e2 == (unsigned) -1) {
          d->type->t_array.elnum = e1;
        }
      }
      goto _process_initializers;
    }
  } else {
    // add new definition
    if (stclass == SSC_TYPEDEF) {
      d = sema_put_ident(scope, SSC_REGULAR | SSC_TYPEDEF,
                         id, idp, ti, 0, NULL, node);
    } else if (ti && ti->tag == CPT_FUNCTION) {
      if (!SSC_GET_SCLASS(stclass)) stclass |= SSC_EXTERN;
      d = sema_put_ident(scope, SSC_REGULAR | SSC_PROTO | stclass,
                         id, idp, ti, 0, NULL, node);
      typeinfo_set_bits(ti, STI_ADDRESS);
    } else {
      d = sema_put_ident(scope, SSC_REGULAR | SSC_PLAIN | stclass,
                         id, idp, ti, 0, NULL, node);
      typeinfo_set_bits(ti, STI_ADDRESS | STI_LVALUE);
    }
  }

 _process_initializers:
  if (stclass == SSC_TYPEDEF) return 0;

  newinit = analyze_global_init(&node->node.refs[5], d, scope);
  ASSERT(!newinit || !d->init);
  if (!d->init) d->init = newinit;
  ti = d->type;
  /*
  if (ti->tag == CPT_ARRAY && stclass != SSC_EXTERN
      && ti->t_array.elnum == SEMA_NO_SIZE) {
    c_err(idp, "array `%s' is assumed to have one element", ident_get(id));
    ti->t_array.elnum = 1;
  }
  */
  /*
  if (ti->tag != CPT_FUNCTION && stclass != SSC_EXTERN
      && sema_get_type_size(ti) == SEMA_NO_SIZE) {
    c_err(idp, "storage size of `%s' is not known", ident_get(id));
    return -1;
  }
  */

  if (ti->tag == CPT_FUNCTION) {
    par_scope = ti->t_function.par_scope;
    if (par_scope) {
      par_scope->def = d;
    }
  }

  analyze_attributes(d, node, scope, attrs, par_scope);

  if (IS_C_BIT_NORETURN(d) && !sema_is_void_type(ti->t_function.ret_type)) {
    c_err(idp, "only `void' function can have `noreturn' attribute");
  }

  return 0;
    
 _redefinition:
  c_err(idp, "redefinition of `%s'", ident_get(id));
  return -1;
 _confl_types:
  c_err(idp, "conflicting types for `%s'", ident_get(id));
  return -1;
}

static void
analyze_global_declarations(tree_t node, struct sema_scope *scope)
{
  typeinfo_t       ti = NULL;
  tree_t           declspec, idclr;
  int              count = 0;
  int              stclass;
  pos_t       *scp = 0;

  ASSERT(node->kind == NODE_DECL);
  ASSERT(scope->up == NULL);

  /* count the number of defined or declared objects */
  for (idclr = node->node.refs[4]; 
       idclr && idclr->kind == NODE_INITDECLR;
       idclr = idclr->node.refs[0]) {
    count++;
  }
  ASSERT(!idclr);

  if (!count) {
    /* declaration that does not introduce an object */
    declspec = node->node.refs[3];
    stclass = sema_get_storclass(declspec, &scp);

    if (stclass != 0) {
      c_warn(scp, "useless storage class in empty declaration");
    }
    make_typeinfo(declspec, scope, NULL, NULL, NULL, 0, 0, 0);
    return;
  }

  declspec = node->node.refs[3];
  stclass = sema_get_storclass(declspec, &scp);
  ti = make_declspec(declspec, scope, NULL, 1, 0);
  if (!ti) return;

  if (stclass == SSC_REGISTER) {
    c_err(scp, "top-level declaration specifies `register'");
    stclass = 0;
  }
  if (stclass == SSC_LOCAL) {
    c_err(scp, "top-level declaration specifies `auto'");
    stclass = 0;
  }

  for (idclr = node->node.refs[4]; 
       idclr && idclr->kind == NODE_INITDECLR;
       idclr = idclr->node.refs[0]) {
    analyze_global_declaration(idclr, scope, ti, declspec, stclass);
  }
  ASSERT(!idclr);
}

static void
analyze_file(tree_t node, struct sema_scope *scope)
{
  while (1) {
    if (!node) return;
    switch (node->kind) {
    case NODE_DECLFUNC:
      /* function introduces its own scope */
      analyze_function(node, scope);
      node = node->node.refs[0];
      break;
    case NODE_DECL:
      analyze_global_declarations(node, scope);
      node = node->node.refs[0];
      break;
    case NODE_ANNOT:
      node = node->node.refs[0];
      break;
    default:
      SWERR(("unhandled node: %d", node->kind));
    }
  }
}

static void
fix_forward_iduses(tree_t node)
{
  semainfo_t *psi, si;
  int n, i;
  tree_t *p;

  if (!node) return;
  if (node->kind < NODE_FIRST || node->kind >= NODE_LAST) return;

  psi = &node->node.sema;
  if (psi && *psi) {
    si = *psi;
    switch (si->tag) {
    case ST_IDUSE:
      if (si->s_iduse.def && si->s_iduse.def->impl) {
        si->s_iduse.def->use_cntr--;
        si->s_iduse.def = si->s_iduse.def->impl;
        si->s_iduse.def->use_cntr++;
        
      }
      break;
    }
  }

  n = node->node.nrefs;
  p = node->node.refs;

  for (i = 3; i < n; i++) {
    fix_forward_iduses(p[i]);
  }
  fix_forward_iduses(p[0]);
}

static void
warn_unused_statics(struct sema_scope *scope)
{
  struct sema_def *pd;

  ASSERT(scope);
  for (pd = scope->reg.first; pd; pd = pd->next) {
    if (SSC_IS_TYPEDEF(pd->flags)) continue;
    if (SSC_IS_PROTO(pd->flags)) {
      if (SSC_IS_STATIC(pd->flags) && pd->use_cntr > 0) {
        c_warn((pos_t*) pd->ppos, "`%s' used but never defined",
               ident_get(pd->name));
        pd->flags = SSC_SET_SCLASS(pd->flags, SSC_EXTERN);
      }
    } else {
      if (SSC_IS_STATIC(pd->flags) && !pd->use_cntr) {
        c_warn((pos_t*) pd->ppos, "`%s' defined but never used",
               ident_get(pd->name));
      }
    }
  }
}

static void
is_valid_global_typeinfo(typeinfo_t t, pos_t *ppos)
{
  struct sema_def *d;
  const unsigned char *aggred_type = 0;

  ASSERT(t);
  switch (t->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
  case CPT_POINTER:
    return;
  case CPT_ENUM:
    d = t->t_enum.def;
    if (!d->nest)
      c_err(ppos, "`enum %s' is not defined", ident_get(d->name));
    return;
  case CPT_ARRAY:
    if (t->t_array.elnum == SEMA_NO_SIZE && t->t_array.size_expr) {
      c_err(ppos, "constant expression expected");
    } else if (t->t_array.elnum == SEMA_NO_SIZE) {
      c_err(ppos, "array size is not defined");
    }
    is_valid_global_typeinfo(t->t_array.type, ppos);
    return;
  case CPT_AGGREG:
    d = t->t_aggreg.def;
    aggred_type = "struct";
    if ((d->flags & SSC_UNION)) aggred_type = "union";
    if (!d->nest)
      c_err(ppos, "`%s %s' is not defined", aggred_type, ident_get(d->name));
    return;
  case CPT_FUNCTION:
  case CPT_TYPEDEF:
  default:
    SWERR(("is_valid_global_typeinfo: unhandled typeinfo %d", t->tag));
  }
}

static void
detect_undefined_globals(struct sema_scope *scope)
{
  struct sema_def *pd;

  if (!scope) return;
  for (pd = scope->reg.first; pd; pd = pd->next) {
    if (SSC_IS_TYPEDEF(pd->flags)) continue;
    if (SSC_IS_PROTO(pd->flags)) continue;
    if (SSC_IS_FUNCTION(pd->flags)) continue;
    if (SSC_IS_EXTERN(pd->flags)) continue;
    if (SSC_IS_ENUMCONST(pd->flags)) continue;
    is_valid_global_typeinfo(pd->type, pd->ppos);
  }
}

static void
put_builtin_prototypes(struct sema_scope *scope)
{
  typeinfo_t tsize = sema_index_to_typeinfo(get_size_t_index());
  typeinfo_t rtype;
  typeinfo_t ftype;
  struct sema_scope *par_scope;
  struct sema_def *par_def;
  struct sema_def *func_def;

  builtin_initialize();

  /* void *__builtin_alloca(size_t size); */
  par_scope = sema_scope_create(scope);
  par_def = sema_put_ident(par_scope, SSC_REGULAR, ident_empty, 0, tsize, 0,
                           0, 0);
  (void) par_def;
  rtype = typeinfo_create_pointer(0, typeinfo_create_builtin(0, C_VOID));
  ftype = typeinfo_create_function(STI_FNORMAL | STI_LVALUE, rtype,
                                   par_scope, 0);
  func_def = sema_put_ident(scope, SSC_REGULAR | SSC_PROTO | SSC_BUILTIN,
                            builtin_get_ident(C_BUILTIN_ALLOCA),
                            0, ftype, 0, 0, 0);
  (void) func_def;
}

static char *print_builtin(struct s_builtin *, char *);
static void  do_print_typeinfo(typeinfo_t, char *, char *, int);

static void
print_params(struct sema_def *p, char *buf)
{
  char  b[256];

  buf[0] = 0;

  for (; p; p = p->next) {
    if (buf[0]) {
      strcat(buf, ",");
    }

    sprint_typeinfo(p->type, b, 256, ident_get(p->name));
    strcat(buf, b);
  }
}

static void
do_print_typeinfo(typeinfo_t p,
                  char *beg_buf, /* the first part of the declarator */
                  char *end_buf, /* the second part of the declarator */
                  int   ptag)
{
  char  tmp[512];
  char  tmp2[512];
  char *s = "";
  char *pp;

  ASSERT(p);
  switch (p->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
    print_builtin(&p->t_builtin, tmp);
    strcpy(tmp2, beg_buf);
    if (tmp2[0]) {
      sprintf(beg_buf, "%s %s", tmp, tmp2);
    } else {
      strcpy(beg_buf, tmp);
    }
    return;

  case CPT_POINTER:
    pp = tmp;
    pp += sprintf(pp, "*"); s = "";
    if ((p->t_pointer.bits & STI_CONST)) {
      pp += sprintf(pp, "%sconst", s); s = " ";
    }
    if ((p->t_pointer.bits & STI_VOLATILE)) {
      pp += sprintf(pp, "%svolatile", s);
    }

    strcpy(tmp2, beg_buf);
    sprintf(beg_buf, "%s%s", tmp, tmp2);
    do_print_typeinfo(p->t_pointer.type, beg_buf, end_buf, CPT_POINTER);
    return;

  case CPT_ARRAY:
    tmp[0] = 0;
    if (p->t_array.elnum != SEMA_NO_SIZE)
      sprintf(tmp, "%lu", p->t_array.elnum);
    if (ptag == CPT_POINTER) {
      strcpy(tmp2, beg_buf);
      sprintf(beg_buf, "(%s", tmp2);
      strcat(end_buf, ")");
    }
    strcat(end_buf, "["); strcat(end_buf, tmp); strcat(end_buf, "]");
    do_print_typeinfo(p->t_array.type, beg_buf, end_buf, CPT_ARRAY);
    return;

  case CPT_FUNCTION:
    if (ptag == CPT_POINTER) {
      strcpy(tmp2, beg_buf);
      sprintf(beg_buf, "(%s", tmp2);
      strcat(end_buf, ")(");
    } else {
      strcat(end_buf, "(");
    }
    if (STI_IS_FKR(p->t_function.bits)) {
      *tmp = 0;
      // DO NOTHING
    } else if (STI_IS_FVOID(p->t_function.bits)) {
      strcpy(tmp, "void");
    } else {
      print_params(p->t_function.par_scope->reg.first, tmp);
      if (STI_IS_FVAR(p->t_function.bits)) {
        if (p->t_function.par_scope && p->t_function.par_scope->reg.first)
          strcat(tmp, ",");
        strcat(tmp, "...");
      }
    }
    strcat(end_buf, tmp);
    strcat(end_buf, ")");
    do_print_typeinfo(p->t_function.ret_type, beg_buf, end_buf, CPT_FUNCTION);
    return;

  default:
    SWERR(("unhandled typeinfo tag: %d\n", p->tag));
  }
}

static int
myidchar(int c) {
  return isalnum(c) || c == '_' || c == '@';
}

char *
sprint_typeinfo(typeinfo_t p, char *buf, int buflen, char *v)
{
  char  beg_buf[256] = "";
  char  end_buf[256] = "";
  int   len;
  char *s = "";
  
  ASSERT(p);
  do_print_typeinfo(p, beg_buf, end_buf, -1);

  len = strlen(beg_buf);
  if (len > 0 && myidchar((unsigned char) beg_buf[len - 1])
      && myidchar((unsigned char) v[0])) {
    s = " ";
  }
  snprintf(buf, buflen, "%s%s%s%s", beg_buf, s, v, end_buf);
  return buf;
}

void
print_typeinfo(typeinfo_t p, FILE *f, char *v, int banner_flag)
{
  char  buf[256];

  if (!v) v = "";

  if (banner_flag) {
    fprintf(f, "typeinfo: ");
    if (!p) {
      fprintf(f, "(NULL)\n");
      return;
    }
  }

  ASSERT(p);
  fprintf(f, "%s", sprint_typeinfo(p, buf, 256, v));

  if (banner_flag) {
    fprintf(f, "\n");
  }
}

static char *
print_builtin(struct s_builtin *p, char *ss)
{
  char *s = "";

  /* FIXME: print declaration specifier */
  if ((p->bits & STI_VOLATILE)) {
    ss += sprintf(ss, "%svolatile", s); s = " ";
  }
  if ((p->bits & STI_CONST)) {
    ss += sprintf(ss, "%sconst", s); s = " ";
  }
  ss += sprintf(ss, "%s%s", s, c_builtin_str(p->ind));
  s = " ";
  return s;
}

static void do_print_scope(struct sema_scope *, FILE *, char *);
static void
print_deflist(struct sema_def *p, FILE *f, char *indent)
{
  char bbuf[32];

  while (p) {
    fprintf(f, "%s0x%08x ", indent, p->flags);
    print_typeinfo(p->type, f, ident_get(p->name), 0);
    fprintf(f, "\n");

    if (p->nest) {
      strcpy(bbuf, indent); strcat(bbuf, "  ");
      do_print_scope(p->nest, f, bbuf);
    }

    p = p->next;
  }
}

static void
print_caselabels(struct sema_swarr *p, FILE *f, char *indent)
{
  /*
  int  i;
  char buf[64];

  if (p->u > 0 && p->v[0].tree) {
    fprintf(f, "%sdefault:\n", indent);
  }
  for (i = 1; i < p->u; i++) {
    tValue_sprint(buf, p->v[i].val);
    fprintf(f, "%scase %2d: %s\n", indent, i, buf);
  }
  */
}

static void
do_print_scope(struct sema_scope *scope, FILE *f, char *indent)
{
  char subindent[256];

  strcpy(subindent, indent); strcat(subindent, "  ");

  fprintf(f, "%s{\n", indent);
  if (scope->reg.first) {
    fprintf(f, "%sregular:\n", indent);
    print_deflist(scope->reg.first, f, subindent);
  }
  /*
  if (scope->aggreg.first) {
    fprintf(f, "%saggregs:\n", indent);
    print_deflist(scope->aggreg.first, f, subindent);
  }
  if (scope->enums.first) {
    fprintf(f, "%senums:\n", indent);
    print_deflist(scope->enums.first, f, subindent);
  }
  */
  if (scope->tags.first) {
    fprintf(f, "%stags:\n", indent);
    print_deflist(scope->tags.first, f, subindent);
  }
  if (scope->labels.first) {
    fprintf(f, "%slabels:\n", indent);
    print_deflist(scope->labels.first, f, subindent);
  }
  if (scope->swlab) {
    fprintf(f, "%scase labels:\n", indent);
    print_caselabels(scope->swlab, f, subindent);
  }
  if (scope->nest) {
  fprintf(f, "%sscopes:\n", indent);
    do_print_scope(scope->nest, f, subindent);
  }
  fprintf(f, "%s}\n", indent);
  if (scope->next) {
    do_print_scope(scope->next, f, indent);
  }
}

void
print_scope(struct sema_scope *scope, FILE *f)
{
  do_print_scope(scope, f, "");
}
