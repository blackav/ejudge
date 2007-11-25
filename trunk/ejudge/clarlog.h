/* -*- c -*- */
/* $Id$ */
#ifndef __CLARLOG_H__
#define __CLARLOG_H__

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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

struct clarlog_state;
typedef struct clarlog_state *clarlog_state_t;

enum { CLAR_ENTRY_SUBJ_SIZE = 32 };

struct clar_entry_v1
{
  int id;                       /* 4 */
  ej_size_t size;               /* 4 */
  ej_time64_t time;             /* 8 */
  int nsec;                     /* 4 */
  int from;                     /* 4 */
  int to;                       /* 4 */
  int j_from;                   /* 4 */
  unsigned int flags;           /* 4 */
  unsigned char ip6_flag;       /* 1 */
  unsigned char hide_flag;      /* 1 */
  unsigned char ssl_flag;       /* 1 */
  unsigned char appeal_flag;    /* 1 */
  union
  {
    ej_ip_t ip;
    unsigned char ip6[16];
  } a;                          /* 16 */
  unsigned short locale_id;     /* 2 */
  unsigned char _pad2[2];       /* 2 */
  int in_reply_to;              /* 4 */ /* 1 means in clar_id 0! */
  unsigned char _pad3[32];
  unsigned char subj[CLAR_ENTRY_SUBJ_SIZE];
};                              /* 128 */

clarlog_state_t clar_init(void);
clarlog_state_t clar_destroy(clarlog_state_t state);
int clar_open(clarlog_state_t state, char const *path, int flags);
int clar_add_record(clarlog_state_t state,
                    time_t         time,
                    size_t         size,
                    char const    *ip,
                    int            from,
                    int            to,
                    int            flags,
                    int            j_from,
                    int            hide_flag,
                    char const    *subj);
int clar_add_record_new(clarlog_state_t state,
                        time_t         time,
                        int            nsec,
                        size_t         size,
                        ej_ip_t        ip,
                        int            ssl_flag,
                        int            from,
                        int            to,
                        int            flags,
                        int            j_from,
                        int            hide_flag,
                        int            locale_id,
                        int            in_reply_to,
                        int            appeal_flag,
                        int            utf8_mode,
                        const unsigned char *subj);
int clar_get_record(clarlog_state_t state,
                    int            id,
                    time_t        *ptime,
                    size_t        *psize,
                    char          *ip,
                    int           *pfrom,
                    int           *pto,
                    int           *pflags,
                    int           *pj_from,
                    int           *p_hide_flag,
                    char          *subj);
int clar_update_flags(clarlog_state_t state, int id, int flags);
int clar_get_total(clarlog_state_t state);
int clar_get_record_new(clarlog_state_t state,
                        int clar_id,
                        struct clar_entry_v1 *pclar);

void clar_get_team_usage(clarlog_state_t, int, int *, size_t *);
char *clar_flags_html(clarlog_state_t, int, int, int, char *, int);
void clar_reset(clarlog_state_t);
void clar_clear_variables(clarlog_state_t);

#endif /* __CLARLOG_H__ */
