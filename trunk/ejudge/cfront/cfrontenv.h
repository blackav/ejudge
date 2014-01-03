/* -*- c -*- */
/* $Id$ */

#ifndef __CFRONTENV_H__
#define __CFRONTENV_H__

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

const unsigned char *get_PRJ_HOME(void);
const unsigned char *get_PRJ_CONFIG(void);

//int os_GuessProjectEnv(const unsigned char *path, const unsigned char *prefix);

#endif /* __CFRONTENV_H__ */
