/* $Id$ */

#ifndef __REUSE_TEMPFILE_H__
#define __REUSE_TEMPFILE_H__

/* Copyright (C) 1998-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1998-01-20 19:09:40 cher> */

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

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

char *temp_Create(const char *dir, const char *pfx, const char *sfx);
void  temp_Remove(const char *path);
void  temp_Finalize(void);
void  temp_Initialize(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_TEMPFILE_H__ */
