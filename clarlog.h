/* -*- c -*- */
/* $Id$ */
#ifndef __CLARLOG_H__
#define __CLARLOG_H__

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ispras.ru> */

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

#include <time.h>
#include <stdlib.h>

#define CLAR_MAX_SUBJ_LEN     24
#define CLAR_MAX_SUBJ_TXT_LEN 18
#define CLAR_MAX_IP_LEN       15

enum
  {
    CLAR_LOG_READONLY = 1,
  };

int clar_open(char const *path, int flags);
int clar_add_record(time_t         time,
                    size_t         size,
                    char const    *ip,
                    int            from,
                    int            to,
                    int            flags,
                    int            j_from,
                    char const    *subj);
int clar_get_record(int            id,
                    time_t        *ptime,
                    size_t        *psize,
                    char          *ip,
                    int           *pfrom,
                    int           *pto,
                    int           *pflags,
                    int           *pj_from,
                    char          *subj);
int clar_update_flags(int id, int flags);
int clar_get_total(void);

void clar_get_team_usage(int, int *, size_t *);
char *clar_flags_html(int, int, int, char *, int);
void clar_reset(void);
void clar_clear_variables(void);

#endif /* __CLARLOG_H__ */
