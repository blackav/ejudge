/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_ERROR_H__
#define __RCC_ERROR_H__ 1

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

void error(int status, int errnum, const char *format, ...);

void error_at_line(int status, int errnum, const char *fname,
                   unsigned int lineno, const char *format, ...);
void (*error_print_progname)(void);

extern unsigned int error_message_count;
extern int error_one_per_line;

#endif /* __RCC_ERROR_H__ */
