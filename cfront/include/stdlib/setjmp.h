/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SETJMP_H__
#define __RCC_SETJMP_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>

#ifndef RCC_SIGSET_T_DEFINED
#define RCC_SIGSET_T_DEFINED 1
typedef struct
{
  unsigned long int __val[1024 / (8 * sizeof (unsigned long))];
} __sigset_t;
#endif /* RCC_SIGSET_T_DEFINED */

typedef int __jmp_buf[6];
typedef struct __jmp_buf_tag
{
  __jmp_buf __jmpbuf;
  int __mask_was_saved;
  __sigset_t __saved_mask;
} jmp_buf[1];
typedef jmp_buf sigjmp_buf;

int sigsetjmp(jmp_buf, int);
int setjmp(jmp_buf);

void longjmp(jmp_buf, int) __attribute__((noreturn));
void siglongjmp(sigjmp_buf, int) __attribute__((noreturn));

#endif /* __RCC_SETJMP_H__ */
