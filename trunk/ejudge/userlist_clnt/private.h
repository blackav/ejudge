/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_CLNT_PRIVATE_H__
#define __USERLIST_CLNT_PRIVATE_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#if defined PYTHON
#include <Python.h>
#endif

#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/pathutl.h"

/* for python bindings we don't want reuse stuff... */
#if !defined PYTHON
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct userlist_clnt
{
  int fd;
  void (*notification_callback)(void *, int);
  void *notification_user_data;
};

#if defined PYTHON
#define xfree(x) free(x)
#define xcalloc(a,b) calloc(a,b)
#define xstrdup(s) strdup(s)
#endif

#endif /* __USERLIST_CLNT_PRIVATE_H__ */
