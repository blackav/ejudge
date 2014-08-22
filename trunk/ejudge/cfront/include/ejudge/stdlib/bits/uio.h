/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_BITS_UIO_H__
#define __RCC_BITS_UIO_H__

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

#include <sys/types.h>

enum { UIO_MAXIOV = 1024 };
#define UIO_MAXIOV UIO_MAXIOV

struct iovec
{
  void *iov_base;
  size_t iov_len;
};

#endif /* __RCC_BITS_UIO_H__ */
