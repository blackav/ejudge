/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_STRING_H__
#define __RCC_STRING_H__

/* Copyright (C) 1999-2004 Alexander Chernov <cher@ispras.ru> */

/*
 * library is free software; you can redistribute it and/or
 * it under the terms of the GNU Lesser General Public
 * as published by the Free Software Foundation; either
 * 2 of the License, or (at your option) any later version.
 *
 * library is distributed in the hope that it will be useful,
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <features.h>

#if !defined NULL
#define NULL 0L
#endif

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

void *memchr(const void *, int, size_t);
int   memcmp(const void *, const void *, size_t);
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);

char   *strcat(char *, const char *);
char   *strchr(const char *, int);
int     strcmp(char const *, char const *);
int     strcoll(const char *, const char *);
char   *strcpy(char *, const char *);
size_t  strcspn(const char *, const char *);
char   *strerror(int);
int     strerror_r(int, char *, size_t);
char   *strsignal(int);
size_t  strlen(char const *);
size_t  strnlen(char const *, size_t);
char   *strncat(char *, const char *, size_t);
int     strncmp(const char *, const char *, size_t);
char   *strncpy(char *, const char *, size_t);
char   *strpbrk(const char *, const char *);
char   *strrchr(const char *, int);
size_t  strspn(const char *, const char *);
char   *strstr(const char *, const char *);
char   *strtok(char *, const char *);
size_t  strxfrm(char *, const char *, size_t);

/* popular extension to ANSI/ISO C standard */
char *strdup(char const *);
char *strndup(const char *, size_t);
char *strdupa(const char *);
char *strndupa(const char *, size_t);

int strcasecmp(char const *, char const *);
int strncasecmp(char const *, char const *, size_t);

char *stpcpy(char *, char const *);

char *index(const char *s, int c);
char *rindex(const char *s, int c);

void *memmem(const void *haystack, size_t haystacklen,
             const void *needle, size_t needlelen);
void *__mempcpy(void *dest, const void *src, size_t n);
void *mempcpy(void *dest, const void *src, size_t n);

#endif /* __RCC_STRING_H__ */

