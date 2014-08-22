/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_P2C_H__
#define __RCC_P2C_H__

/* Copyright (C) 2001 Alexander Chernov */

/*
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define Static static
typedef int boolean;
typedef char Char;
typedef unsigned char uchar;
typedef long LONGINT;
#define true 1
#define false 0

extern int FileNotFound;

extern int PASCAL_MAIN(int argc, char *argv[]);

int assign(FILE *, char const *);
int rewind(FILE *);

int _EscIO(int);

extern Char    **P_argv;
extern int     P_argc;

#endif /* __RCC_P2C_H__ */
