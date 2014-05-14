/* -*- c -*- */
/* $Id$ */
#ifndef __CPU_H__
#define __CPU_H__

/* Copyright (C) 2005-2012 Alexander Chernov <cher@ejudge.ru> */

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

int cpu_get_bogomips(void);
void cpu_get_performance_info(unsigned char **p_model, unsigned char **p_mhz);

#endif /* __CPU_H__ */
