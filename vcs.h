/* -*- c -*- */
/* $Id$ */

#ifndef __VCS_H__
#define __VCS_H__

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

int vcs_add(const unsigned char *path, unsigned char **p_log_txt);
int vcs_commit(const unsigned char *path, unsigned char **p_log_txt);

#endif /* __VCS_H__ */
