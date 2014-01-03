/* -*- mode:c -*- */
#ifndef __C_ERRORS_H__
#define __C_ERRORS_H__

/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "pos.h"

void c_err(pos_t *ppos, char const *, ...)
#ifdef __GNUC__
  __attribute__((format(printf, 2, 3)))
#endif
;

void c_warn(pos_t *ppos, char const *, ...)
#ifdef __GNUC__
  __attribute__((format(printf, 2, 3)))
#endif
;

int c_err_get_count(void);

void fancy_swerr(pos_t *ppos, char *file, int lineno, char *txt, ...)
#ifdef __GNUC__
  __attribute__((noreturn, format(printf,4,5)))
#endif
;

#if !defined RELEASE
#define CASSERT(p,e) do { if (!(e)) fancy_swerr((p), __FILE__, __LINE__, "assertion failed: %s", #e); } while(0)
#else
#define CASSERT(p,e)
#endif /* RELEASE */

#define CSWERR(p,a, ...) fancy_swerr((p), __FILE__, __LINE__, a, ## __VA_ARGS__)

#endif /* __C_ERRORS_H__ */
