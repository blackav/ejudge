/* -*- c -*- */
/* $Id$ */
#ifndef __SFORMAT_H__
#define __SFORMAT_H__

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "prepare.h"
#include "teamdb.h"

#include <stdlib.h>

int sformat_message(char *, size_t, char const *,
                    struct section_global_data *glob_data,
                    struct section_problem_data *prob_data,
                    struct section_language_data *lang_data,
                    struct section_tester_data *tester_data,
                    struct teamdb_export *team_data);

#endif /* __SFORMAT_H__ */
