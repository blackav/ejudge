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

#include "sema_data.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/hash.h"

struct sema_scope *
sema_scope_create(struct sema_scope *up)
{
  struct sema_scope *ptr = (struct sema_scope*) tree_alloc(sizeof (*ptr));
  ptr->up = up;
  ptr->size = 0;
  if (up) {
    ptr->func = up->func;
  }

  return ptr;
}

struct sema_scope *
sema_function_scope_create(struct sema_scope *up, struct sema_def *def)
{
  struct sema_scope *ptr = 0;

  ASSERT(up);
  ASSERT(!up->func);

  ptr = (struct sema_scope*) tree_alloc(sizeof (*ptr));
  ptr->up = up;
  ptr->size = 0;
  ptr->func = ptr;
  ptr->def = def;

  return ptr;
}

void
sema_add_to_gotos(struct sema_scope *scope, void *ptr)
{
  struct sema_list *p = (struct sema_list*) tree_alloc(sizeof (*p));
  p->next = scope->gotos;
  p->item = ptr;
  scope->gotos = p;
}

semainfo_t
sinfo_create_scope(struct sema_scope *scope)
{
  semainfo_t ptr = (semainfo_t) tree_alloc(sizeof (*ptr));
  ptr->tag = ST_SCOPE;
  ptr->s_scope.scope = scope;
  return ptr;
}

semainfo_t
sinfo_create_iduse(struct sema_def *def)
{
  semainfo_t ptr = (semainfo_t) tree_alloc(sizeof(struct s_iduse));
  ptr->tag = ST_IDUSE;
  ptr->s_iduse.def = def;
  return ptr;
}

semainfo_t
sinfo_create_goto(struct sema_def *def, struct sema_scope *use_scope,
                  struct sema_scope_list *scopes)
{
  semainfo_t ptr = (semainfo_t) tree_alloc(sizeof(struct s_goto));
  ptr->tag = ST_GOTO;
  ptr->s_goto.def = def;
  ptr->s_goto.use_scope = use_scope;
  ptr->s_goto.scopes = scopes;
  return ptr;
}

semainfo_t
sinfo_create_swlab(struct sema_switem *def)
{
  semainfo_t ptr = (semainfo_t) tree_alloc(sizeof(struct s_swlab));
  ptr->tag = ST_SWLAB;
  ptr->s_swlab.def = def;
  return ptr;
}

semainfo_t
sinfo_create_type(typeinfo_t t)
{
  semainfo_t ptr = (semainfo_t) tree_alloc(sizeof(struct s_type));
  ptr->tag = ST_TYPE;
  ptr->s_type.type = t;
  return ptr;
}

typeinfo_t
typeinfo_create_arith(int bits, int ind)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_builtin));
  np->tag = CPT_ARITH;
  np->t_builtin.bits = bits;
  np->t_builtin.ind = ind;
  return np;
}

typeinfo_t
typeinfo_create_builtin(int bits, int ind)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_builtin));
  np->tag = CPT_BUILTIN;
  np->t_builtin.bits = bits;
  np->t_builtin.ind = ind;
  return np;
}

typeinfo_t
typeinfo_create_enum(int bits, ident_t id, struct sema_def *def)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_enum));
  np->tag = CPT_ENUM;
  np->t_enum.bits = bits;
  np->t_enum.id = id;
  np->t_enum.def = def;
  return np;
}

typeinfo_t
typeinfo_create_typedef(int bits, ident_t id, struct sema_def *def)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_typedef));
  np->tag = CPT_TYPEDEF;
  np->t_typedef.bits = bits;
  np->t_typedef.id = id;
  np->t_typedef.def = def;
  return np;
}

typeinfo_t
typeinfo_create_pointer(int bits, typeinfo_t type)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_pointer));
  np->tag = CPT_POINTER;
  np->t_pointer.bits = bits;
  np->t_pointer.type = type;
  np->t_pointer.size = 4;
  return np;
}

typeinfo_t
typeinfo_create_function(int bits, typeinfo_t ret_type,
                         struct sema_scope *par_scope,
                         struct sema_scope *impl_par_scope)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_function));
  np->tag = CPT_FUNCTION;
  np->t_function.bits = bits;
  np->t_function.ret_type = ret_type;
  np->t_function.par_scope = par_scope;
  np->t_function.impl_par_scope = impl_par_scope;
  np->t_function.size = (unsigned long) -1;
  return np;
}

typeinfo_t
typeinfo_create_array(typeinfo_t type, rulong_t elnum, typeinfo_t size_def)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_array));
  np->tag = CPT_ARRAY;
  np->t_array.type = type;
  np->t_array.elnum = elnum;
  np->t_array.size_def = size_def;
  return np;
}

typeinfo_t
typeinfo_create_aggreg(int bits, ident_t id, struct sema_def *def)
{
  typeinfo_t np = (typeinfo_t) tree_alloc(sizeof(struct s_aggreg));
  np->tag = CPT_AGGREG;
  np->t_aggreg.bits = bits;
  np->t_aggreg.id = id;
  np->t_aggreg.def = def;
  return np;
}

typeinfo_t
ti_create_void_pointer(void)
{
  return typeinfo_create_pointer(0, typeinfo_create_builtin(0, C_VOID));
}

typeinfo_t
typeinfo_clone(typeinfo_t ptr, int flags)
{
  ASSERT(!(flags & ~STI_CLONE_SETABLE));
  ASSERT(ptr);

  switch (ptr->tag) {
  case CPT_ARITH:
    return typeinfo_create_arith((ptr->t_builtin.bits & ~STI_CLONE_CLEAR) | flags, ptr->t_builtin.ind);

  case CPT_BUILTIN:
    return typeinfo_create_builtin((ptr->t_builtin.bits & ~STI_CLONE_CLEAR) | flags, ptr->t_builtin.ind);

  case CPT_ENUM:
    return typeinfo_create_enum((ptr->t_enum.bits & ~STI_CLONE_CLEAR) | flags, ptr->t_enum.id, ptr->t_enum.def);

  case CPT_POINTER:
    return typeinfo_create_pointer((ptr->t_pointer.bits & ~STI_CLONE_CLEAR) | flags,
                                   ptr->t_pointer.type);

  case CPT_ARRAY:
    {
      typeinfo_t tmpt = 0;
      tmpt = typeinfo_create_array(typeinfo_clone(ptr->t_array.type, flags),
                                   ptr->t_array.elnum,
                                   ptr->t_array.size_def);
      tmpt->t_array.size_expr = ptr->t_array.size_expr;
      tmpt->t_array.size_reg = ptr->t_array.size_reg;
      return tmpt;
    }

  case CPT_FUNCTION:
    return typeinfo_create_function(ptr->t_function.bits,
                                    typeinfo_clone(ptr->t_function.ret_type,
                                                   flags),
                                    ptr->t_function.par_scope,
                                    ptr->t_function.impl_par_scope);
                                    
  case CPT_AGGREG:
    return typeinfo_create_aggreg((ptr->t_aggreg.bits & ~STI_CLONE_CLEAR) | flags, ptr->t_aggreg.id, ptr->t_aggreg.def);

  default:
    SWERR(("bad typeinfo tag: %d", ptr->tag));
  }
}

void
typeinfo_set_bits(typeinfo_t ptr, int bits)
{
  ASSERT(ptr);
  switch (ptr->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
    ptr->t_builtin.bits |= bits;
    break;
  case CPT_ENUM:
    ptr->t_enum.bits |= bits;
    break;
  case CPT_POINTER:
    ptr->t_pointer.bits |= bits;
    break;
  case CPT_ARRAY:
    ptr->t_array.bits |= bits;
    break;
  case CPT_FUNCTION:
    ptr->t_function.bits |= bits;
    break;
  case CPT_AGGREG:
    ptr->t_aggreg.bits |= bits;
    break;
  case CPT_TYPEDEF:
    ptr->t_typedef.bits |= bits;
    break;
  default:
    SWERR(("bad typeinfo tag: %d", ptr->tag));
  }
}

void
typeinfo_clear_bits(typeinfo_t ptr, int bits)
{
  ASSERT(ptr);
  switch (ptr->tag) {
  case CPT_ARITH:
  case CPT_BUILTIN:
    ptr->t_builtin.bits &= ~bits;
    break;
  case CPT_ENUM:
    ptr->t_enum.bits &= ~bits;
    break;
  case CPT_POINTER:
    ptr->t_pointer.bits &= ~bits;
    break;
  case CPT_ARRAY:
    ptr->t_array.bits &= ~bits;
    break;
  case CPT_FUNCTION:
    ptr->t_function.bits &= ~bits;
    break;
  case CPT_AGGREG:
    ptr->t_aggreg.bits &= ~bits;
    break;
  default:
    SWERR(("bad typeinfo tag: %d", ptr->tag));
  }
}

int
typeinfo_get_bits(typeinfo_t ptr)
{
  ASSERT(ptr);
  switch (ptr->tag) {
  case CPT_ARITH:    return ptr->t_builtin.bits;
  case CPT_BUILTIN:  return ptr->t_builtin.bits;
  case CPT_ENUM:     return ptr->t_enum.bits;
  case CPT_POINTER:  return ptr->t_pointer.bits;
  case CPT_ARRAY:    return ptr->t_array.bits;
  case CPT_FUNCTION: return ptr->t_function.bits;
  case CPT_AGGREG:   return ptr->t_aggreg.bits;
  default:
    SWERR(("bad typeinfo tag: %d", ptr->tag));
  }
  return 0;
}

int
typeinfo_get_cv(typeinfo_t ptr)
{
  return typeinfo_get_bits(ptr) & STI_CVMASK;
}
