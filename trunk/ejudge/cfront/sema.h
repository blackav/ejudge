/* -*- mode:c -*- */
#ifndef __SEMA_H__
#define __SEMA_H__

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

#include "ejudge/getopt.h"

#if !defined RCC_TREE_T_DEFINED
#define RCC_TREE_T_DEFINED 1
union u_tree;
typedef union u_tree *tree_t;
#endif /* RCC_TREE_T_DEFINED */

extern optrec_t sema_options[];

int main_sema_analyze(tree_t);

#endif /* __SEMA_H__ */

