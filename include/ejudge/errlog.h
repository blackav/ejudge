/* -*- c -*- */
/* $Id$ */
#ifndef __ERRLOG_H__
#define __ERRLOG_H__

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdarg.h>

extern void vverr(char const *, va_list args);
extern void err(char const *, ...) __attribute__((format(printf, 1, 2)));
extern void info(char const *, ...) __attribute__((format(printf, 1, 2)));
extern void do_err_r(char const *func, char const *txt, ...);

#endif /* __ERRLOG_H__ */
