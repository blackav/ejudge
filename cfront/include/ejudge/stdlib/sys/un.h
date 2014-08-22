/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_SYS_UN_H__
#define __RCC_SYS_UN_H__	1

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
#include <bits/sockaddr.h>

struct sockaddr_un
{
  __SOCKADDR_COMMON (sun_);
  char sun_path[108];		/* Path name.  */
};

#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) + strlen ((ptr)->sun_path))

#endif /* __RCC_SYS_UN_H__ */
