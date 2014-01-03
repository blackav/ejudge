/* -*- mode:c -*- */
#ifndef __TREE_FOLD_H__
#define __TREE_FOLD_H__

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

int  tree_fold(tree_t node, c_value_t *pval);
void sema_fold_some_operations(tree_t node, tree_t *pp1);

#endif /* __TREE_FOLD_H__ */
