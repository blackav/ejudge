/* -*- c -*- */
/* $Id$ */

#ifndef __PRINTING_H__
#define __PRINTING_H__

/* Copyright (C) 2004, 2006 Alexander Chernov <cher@ejudge.ru> */

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

int priv_print_run(serve_state_t state, int run_id, int user_id);
int team_print_run(serve_state_t state, int run_id, int user_id);

#endif /* __PRINTING_H__ */
