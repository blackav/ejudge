/* -*- mode: c -*- */

/* Copyright (C) 2003-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

#include "l10n_impl.h"

void *
xrealloc(void *ptr, size_t size)
{
  void *newptr = realloc(ptr, size);
  if (!newptr) fatal_CF(_("Out of heap memory: realloc(...,%zu) failed"), size);
  return newptr;
}
