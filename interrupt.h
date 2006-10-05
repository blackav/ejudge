/* -*- c -*- */
/* $Id$ */

#ifndef __INTERRUPT_H__
#define __INTERRUPT_H__

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

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

void interrupt_init(void);

void interrupt_enable(void);
void interrupt_disable(void);

int interrupt_get_status(void);
int interrupt_restart_requested(void);

#endif /* __INTERRUPT_H__ */
