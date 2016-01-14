/* Copyright (C) 1996-2016 Alexander Chernov <cher@ejudge.ru> */

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

/**
 * FILE:    utils/xalloc.c
 * PURPOSE: safe memory allocation routines
 */

/* Created: Fri Nov  1 19:01:06 1996 by cher (Alexander Chernov) */

#include "xalloc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * NAME:    out_of_mem
 * PURPOSE: report out of virtual memory condition
 */
void
reuse_out_of_mem(void)
{
  fputs("Failed to allocate more memory!\n", stderr);
  abort();
}

/**
 * NAME:    null_size
 * PURPOSE: report 0 size allocation error
 */
void
reuse_null_size(void)
{
  fputs("Null size allocation requested!\n", stderr);
  abort();
}

/**
 * NAME:    xmalloc
 * PURPOSE: wrapper over malloc function call
 * NOTE:    xmalloc never returns NULL
 */
void *
xmalloc(size_t size)
{
  void *ptr;

  if (size == 0) reuse_null_size();
  ptr = malloc(size);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}

/**
 * NAME:    xcalloc
 * PURPOSE: wrapper over calloc function
 * NOTE:    xcalloc never returns NULL
 */
void *
xcalloc(size_t nitems, size_t elsize)
{
  void *ptr;

  if (nitems == 0 || elsize == 0) reuse_null_size();
  ptr = calloc(nitems, elsize);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}

/**
 * NAME:    xrealloc
 * PURPOSE: wrapper over realloc function
 * NOTE:    if ptr == NULL,  realloc = malloc
 *          if size == NULL, realloc = free
 *          if ptr == NULL && size == NULL, ?
 */
void *
xrealloc(void *ptr, size_t size)
{
  if (ptr == NULL && size == 0) reuse_null_size();
  ptr = realloc(ptr,size);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}

/**
 * NAME:    xfree
 * PURPOSE: wrapper over free function
 * NOTE:    accepts NULL pointer as argument
 */
void
xfree(void *ptr)
{
  if (ptr == NULL) return;
  free(ptr);
}

/**
 * NAME:    xstrdup
 * PURPOSE: wrapper over strdup function
 * NOTE:    strdup(NULL) returns ""
 */
char *
xstrdup(char const*str)
{
  char *ptr;

  if (str == NULL) str = "";
  ptr = strdup(str);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}

/**
 * NAME:    xmemdup
 * PURPOSE: returns a copy of the string in the heap
 * ARGS:    str  - string to copy (might not be \0 terminated)
 *          size - string length
 * RETURN:  copy of the string str with \0 terminator added
 */
char *
xmemdup(char const *str, size_t size)
{
  char *ptr;

  if (str == NULL) str = "";
  ptr = xmalloc (size + 1);
  if (ptr == NULL) reuse_out_of_mem();
  memcpy (ptr, str, size);
  ptr[size] = 0;
  return ptr;
}

/**
 * NAME:    xexpand
 * PURPOSE: expand expandable array of strings
 * ARGS:    arr - pointer to expandable array structure
 */
void
xexpand(strarray_t *arr)
{
  if (arr->u < arr->a) return;

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = (char**) xcalloc(arr->a, sizeof(char **));
      return;
    }

  arr->v = (char**) xrealloc(arr->v, arr->a * sizeof(char**) * 2);
  memset(arr->v + arr->a, 0, arr->a * sizeof(char**));
  arr->a *= 2;
}

/**
 * NAME:    xexpand2
 * PURPOSE: expand generic expandable array
 * ARGS:    arr    - pointer to expandable array structure
 *          elsize - size of an element of the array
 */
void
xexpand2(arr, elsize)
     genarray_t  *arr;
     size_t       elsize;
{
  if (!arr) return;

  if (elsize <= 0) elsize = sizeof(int);
  if (arr->u < arr->a) return;

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = xcalloc(arr->a, elsize);
      return;
    }

  arr->v = (void*) xrealloc(arr->v, arr->a * elsize * 2);
  memset((char*) arr->v + arr->a * elsize, 0, arr->a * elsize);
  arr->a *= 2;
}

/**
 * NAME:    xexpand3
 * PURPOSE: unconditionally expand the array
 * ARGS:    arr    - array to expand
 *          elsize - element size
 */
void
xexpand3(arr, elsize)
     genarray_t  *arr;
     size_t       elsize;
{
  if (!arr) return;

  if (elsize <= 0) elsize = sizeof(int);

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = xcalloc(arr->a, elsize);
      return;
    }

  arr->v = (void*) xrealloc(arr->v, arr->a * elsize * 2);
  memset((char*) arr->v + arr->a * elsize, 0, arr->a * elsize);
  arr->a *= 2;
}

/**
 * NAME:    xexpand4
 * PURPOSE: unconditionally expand the array
 * ARGS:    arr     - array to expand
 *          elsize  - element size
 *          newsize - new size of the array
 */
void
xexpand4(arr, elsize, newsize)
     genarray_t *arr;
     size_t      elsize;
     int         newsize;
{
  int newsz;

  if (!arr) return;
  if (newsize <= arr->a) return;

  if (elsize <= 0) elsize = sizeof(int);
  newsz = arr->a;
  if (!newsz) newsz = 32;
  while (newsz < newsize)
    newsz *= 2;

  arr->v = (void*) xrealloc(arr->v, newsz * elsize);
  memset((char*) arr->v + arr->a * elsize, 0, (newsz - arr->a) * elsize);
  arr->a = newsz;
}

void
xstrarrayfree(strarray_t *a)
{
  int i;

  if (!a) return;

  for (i = 0; i < a->u; i++) {
    xfree(a->v[i]);
  }
  xfree(a->v);
  a->u = a->a = 0;
  a->v = 0;
}

/**
 * NAME:    xstrmerge0
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings (allocated in heap)
 * NOTE:    str1 and str2 are freed via xfree call after concatenation
 */
  char *
xstrmerge0(char *str1, char *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    {
      return NULL;
    }

  if (str1 == NULL)
    {
      return str2;
    }

  if (str2 == NULL)
    {
      return str1;
    }

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str1);
  xfree(str2);
  return res;
}

/**
 * NAME:    xstrmerge1
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - freed after concatenation
 *          str2 - not freed
 */
  char *
xstrmerge1(char *str1, char const *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    return NULL;

  if (str1 == NULL)
    return xstrdup(str2);

  if (str2 == NULL)
    return str1;

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str1);
  return res;
}

/**
 * NAME:    xstrmerge2
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - not freed after concatenation
 *          str2 - not freed
 */
  char *
xstrmerge2(char const *str1, char const *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    return NULL;

  if (str1 == NULL)
    return xstrdup(str2);

  if (str2 == NULL)
    return xstrdup(str1);

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  return res;
}

/**
 * NAME:    xstrmerge3
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - not freed
 *          str2 - freed after concatenation
 */
char *
xstrmerge3(char const *str1, char *str2)
{
  char *res;

  if (!str1 && !str2) return 0;
  if (!str1)          return str2;
  if (!str2)          return xstrdup(str1);

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str2);
  return res;
}
