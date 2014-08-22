/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_LINUX_PARAM_H__
#define __RCC_LINUX_PARAM_H__

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

#ifndef HZ
int enum { HZ = 100 };
#define HZ HZ
#endif

int enum { EXEC_PAGESIZE = 4096 };
#define EXEC_PAGESIZE EXEC_PAGESIZE

#ifndef NGROUPS
int enum { NGROUPS = 32 };
#define NGROUPS NGROUPS
#endif

#ifndef NOGROUP
int enum { NOGROUP = (-1) };
#define NOGROUP NOGROUP
#endif

int enum { MAXHOSTNAMELEN = 64 };
#define MAXHOSTNAMELEN MAXHOSTNAMELEN

#endif /* __RCC_LINUX_PARAM_H__ */
