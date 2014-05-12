/* -*- mode: c -*- */
/* $Id$ */

#ifndef __REUSE_STR_UTILS_H__
#define __REUSE_STR_UTILS_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

int reuse_strncasecmp(char const *, char const *, size_t);
int reuse_strcasecmp(char const *, char const *);

size_t reuse_strncatx(char *, size_t, size_t, char const *);
size_t reuse_strnput0(char *, size_t, size_t);
size_t reuse_strnlen(char const *, size_t);
size_t strlcpy(char *dst, const char *src, size_t siz);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_STR_UTILS_H__ */
