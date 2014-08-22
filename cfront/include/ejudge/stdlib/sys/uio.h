/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_UIO_H__
#define __RCC_SYS_UIO_H__

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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
#include <sys/types.h>
#include <bits/uio.h>

ssize_t readv(int fd, const struct iovec *vector, int count);
ssize_t writev (int fd, const struct iovec *vector, int count);

#endif /* __RCC_SYS_UIO_H__ */
