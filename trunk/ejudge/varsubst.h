/* -*- c -*- */
/* $Id$ */
#ifndef __VARSUBST_H__
#define __VARSUBST_H__

/* Copyright (C) 2004-2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "prepare.h"
#include "serve_state.h"

unsigned char *varsubst_heap(const serve_state_t, unsigned char *in_str,
                             int free_flag,
                             const struct config_parse_info *global_vars,
                             const struct config_parse_info *problem_vars,
                             const struct config_parse_info *language_vars,
                             const struct config_parse_info *tester_vars);

unsigned char *
config_var_substitute_heap(unsigned char *txt);
unsigned char *
config_var_substitute_buf(unsigned char *buf, size_t bufsize);

#endif /* __VARSUBST_H__ */
