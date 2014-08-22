/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_MCHECK_H__
#define __RCC_MCHECK_H__

/* Copyright (C) 2003-2004 Alexander Chernov <cher@ispras.ru> */

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

enum mcheck_status
{
  MCHECK_DISABLED = -1,
  MCHECK_OK,
  MCHECK_FREE,
  MCHECK_HEAD,
  MCHECK_TAIL
};

int mcheck(void (*abortfunc)(enum mcheck_status));
int mcheck_pedantic(void (*abortfunc)(enum mcheck_status));
void mcheck_check_all(void);
enum mcheck_status mprobe(void *ptr);
void mtrace(void);
void muntrace(void);

#endif /* __RCC_MCHECK_H__ */
