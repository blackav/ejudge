/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_CTYPE_H__
#define __RCC_CTYPE_H__

/* Copyright (C) 2001-2004 Alexander Chernov <cher@ispras.ru> */

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

int isalnum(int);
int isalpha(int);
int iscntrl(int);
int isdigit(int);
int islower(int);
int isgraph(int);
int isprint(int);
int ispunct(int);
int isspace(int);
int isupper(int);
int isxdigit(int);
int isascii(int);

int tolower(int);
int toupper(int);
int toascii(int);

#endif /* __RCC_CTYPE_H__ */
