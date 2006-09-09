/* -*- c -*- */
/* $Id$ */

#ifndef __DIFF_H__
#define __DIFF_H__

/* Copyright (C) 2004,2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "serve_state.h"

#include <stdio.h>

int compare_runs(const serve_state_t, FILE *fout, int run_id1, int run_id2);

#endif /* __DIFF_H__ */
