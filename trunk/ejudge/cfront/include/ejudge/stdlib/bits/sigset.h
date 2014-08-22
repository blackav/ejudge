/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_BITS_SIGSET_H__
#define __RCC_BITS_SIGSET_H__

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef __RCC_SIG_ATOMIC_T_DEFINED__
#define __RCC_SIG_ATOMIC_T_DEFINED__
typedef int sig_atomic_t;
#endif /* __RCC_SIG_ATOMIC_T_DEFINED__ */

/* A `sigset_t' has a bit for each signal.  */
int enum { _SIGSET_NWORDS = (1024 / (8 * sizeof (unsigned long int))) };
typedef struct
{
  unsigned long int __val[_SIGSET_NWORDS];
} sigset_t;

#endif /* __RCC_BITS_SIGSET_H__ */
