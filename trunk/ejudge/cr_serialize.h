/* -*- c -*- */
/* $Id$ */

#ifndef __CR_SERIALIZE_H__
#define __CR_SERIALIZE_H__

/* Copyright (C) 2002, 2006 Alexander Chernov <cher@ejudge.ru> */

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

int cr_serialize_init(const serve_state_t);
int cr_serialize_lock(const serve_state_t);
int cr_serialize_unlock(const serve_state_t);

#endif /* __CR_SERIALIZE_H__ */
