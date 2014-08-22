/* $Id$ */

#ifndef __REUSE_XFILE_H__
#define __REUSE_XFILE_H__

/* Copyright (C) 1998-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1998-04-22 22:07:15 cher> */

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

#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

FILE *xfopen(char *name, char *flags);
int   xferror(FILE *f);
int   xfclose(FILE *f);

int   reuse_set_binary_stderr(void);
int   reuse_set_binary_stdout(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_XFILE_H__ */
