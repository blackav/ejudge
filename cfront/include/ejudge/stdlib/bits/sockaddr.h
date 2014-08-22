/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_BITS_SOCKADDR_H__
#define __RCC_BITS_SOCKADDR_H__

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

#ifndef __RCC_SA_FAMILY_T_DEFINED
#define __RCC_SA_FAMILY_T_DEFINED
typedef unsigned short int sa_family_t;
#endif

#define	__SOCKADDR_COMMON(sa_prefix) sa_family_t sa_prefix##family
#define __SOCKADDR_COMMON_SIZE	     (sizeof (unsigned short int))

#endif /* __RCC_BITS_SOCKADDR_H__ */
