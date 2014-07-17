/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_SERVE_PI_H__
#define __SUPER_SERVE_PI_H__

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"

#include "ejudge/external_action.h"

#include <time.h>

typedef struct CspNewMainPage
{
    PageInterface b;
} CspNewMainPage;

void super_serve_pi_init(void);

#endif /* __SUPER_SERVE_PI_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
