/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_TIMEB_H__
#define __RCC_SYS_TIMEB_H__

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
#include <time.h>

struct timeb
{
  time_t time;
  unsigned short int millitm;
  short int timezone;
  short int dstflag;
};

int ftime(struct timeb *);

#endif /* __RCC_SYS_TIMEB_H__ */
