/* -*- c -*- */
/* $Id$ */

#ifndef __ITERATORS_H__
#define __ITERATORS_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

struct int_iterator;
typedef struct int_iterator *int_iterator_t;
struct int_iterator
{
  int (*has_next)(int_iterator_t);
  int (*get)(int_iterator_t);
  void (*next)(int_iterator_t);
  void (*destroy)(int_iterator_t);
};

struct ptr_iterator;
typedef struct ptr_iterator *ptr_iterator_t;
struct ptr_iterator
{
  int (*has_next)(ptr_iterator_t);
  const void *(*get)(ptr_iterator_t);
  void (*next)(ptr_iterator_t);
  void (*destroy)(ptr_iterator_t);
};

#endif /* __ITERATORS_H__ */
