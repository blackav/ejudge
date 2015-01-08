/* -*- c -*- */
#ifndef __CLARLOG_H__
#define __CLARLOG_H__

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include <time.h>
#include <stdlib.h>

enum
  {
    CLAR_LOG_READONLY = 1,
  };

struct clarlog_state;
typedef struct clarlog_state *clarlog_state_t;

enum
{
  CLAR_FIELD_ID,
  CLAR_FIELD_UUID,
  CLAR_FIELD_SIZE,
  CLAR_FIELD_TIME,
  CLAR_FIELD_NSEC,
  CLAR_FIELD_FROM,
  CLAR_FIELD_TO,
  CLAR_FIELD_J_FROM,
  CLAR_FIELD_FLAGS,
  CLAR_FIELD_HIDE_FLAG,
  CLAR_FIELD_SSL_FLAG,
  CLAR_FIELD_APPEAL_FLAG,
  CLAR_FIELD_IP,
  CLAR_FIELD_LOCALE_ID,
  CLAR_FIELD_IN_REPLY_TO,
  CLAR_FIELD_IN_REPLY_UUID,
  CLAR_FIELD_RUN_ID,
  CLAR_FIELD_RUN_UUID,
  CLAR_FIELD_OLD_RUN_STATUS,
  CLAR_FIELD_NEW_RUN_STATUS,
  CLAR_FIELD_CHARSET,
  CLAR_FIELD_SUBJECT,

  CLAR_FIELD_LAST,
};

enum { CLAR_ENTRY_V2_SUBJ_SIZE = 96, CLAR_ENTRY_V2_CHARSET_SIZE = 16 };

struct clar_entry_v2
{
  int id;                       /* 4 */
  ej_uuid_t uuid;               /* 16 */
  ej_size_t size;               /* 4 */
  ej_time64_t time;             /* 8 */
  int nsec;                     /* 4 */
  int from;                     /* 4 */
  int to;                       /* 4 */
  int j_from;                   /* 4 */
  unsigned int flags;           /* 4 */
  unsigned char ipv6_flag;      /* 1 */
  unsigned char hide_flag;      /* 1 */
  unsigned char ssl_flag;       /* 1 */
  unsigned char appeal_flag;    /* 1 */
  union
  {
    ej_ip4_t ip;
    unsigned char ipv6[16];
  } a;                          /* 16 */
  unsigned short locale_id;     /* 2 */
  unsigned char old_run_status; /* 1 */ /* 1 means OK */
  unsigned char new_run_status; /* 1 */ /* 1 means OK */
  int in_reply_to;              /* 4 */ /* 1 means in clar_id 0! */
  ej_uuid_t in_reply_uuid;      /* 16 */
  int run_id;                   /* 4 */ /* 1 means run_id 0! */
  ej_uuid_t run_uuid;           /* 16 */
  unsigned char _pad3[28];      /* 28 */
  unsigned char charset[CLAR_ENTRY_V2_CHARSET_SIZE];
  unsigned char subj[CLAR_ENTRY_V2_SUBJ_SIZE];
};

struct full_clar_entry
{
  struct clar_entry_v2 e;
  unsigned char *text; // size+1 allocation, \0-terminated
  size_t size;
};

struct full_clar_entry_vector
{
  int a, u;
  struct full_clar_entry *v;
};

struct ejudge_cfg;
struct contest_desc;
struct section_global_data;

clarlog_state_t clar_init(void);
clarlog_state_t clar_destroy(clarlog_state_t state);
int clar_open(
        clarlog_state_t state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags);
int clar_add_record(
        clarlog_state_t state,
        time_t          time,
        int             nsec,
        size_t          size,
        const ej_ip_t   *pip,
        int             ssl_flag,
        int             from,
        int             to,
        int             flags,
        int             j_from,
        int             hide_flag,
        int             locale_id,
        int             in_reply_to,
        const ej_uuid_t *pin_reply_uuid,
        int             run_id,
        const ej_uuid_t *prun_uuid,
        int             appeal_flag,
        int             old_run_status,
        int             new_run_status,
        int             utf8_mode,
        const unsigned char *charset,
        const unsigned char *subj,
        ej_uuid_t       *puuid);
int clar_update_flags(clarlog_state_t state, int id, int flags);
int clar_set_charset(
        clarlog_state_t state,
        int id,
        const unsigned char *charset);
int clar_get_total(clarlog_state_t state);
int clar_get_record(
        clarlog_state_t state,
        int clar_id,
        struct clar_entry_v2 *pclar);
int clar_put_record(
        clarlog_state_t state,
        int clar_id,
        const struct clar_entry_v2 *pclar);
int clar_get_charset_id(
        clarlog_state_t state,
        int clar_id);
const unsigned char *clar_get_subject(
        clarlog_state_t state,
        int clar_id);

void clar_get_user_usage(
        clarlog_state_t state,
        int from,
        int *pn,
        size_t *pz);
char *clar_flags_html(
        clarlog_state_t state,
        int flags,
        int from,
        int to,
        char *buf,
        int len);
void clar_reset(clarlog_state_t state);
int clar_get_text(
        clarlog_state_t state,
        int clar_id,
        unsigned char **p_txt,
        size_t *p_size);
int clar_get_raw_text(
        clarlog_state_t state,
        int clar_id,
        unsigned char **p_txt,
        size_t *p_size);
int
clar_add_text(
        clarlog_state_t state,
        int clar_id,
        const ej_uuid_t *puuid,
        const unsigned char *text,
        size_t size);
int
clar_modify_text(
        clarlog_state_t state,
        int clar_id,
        unsigned char *text,
        size_t size);
int
clar_modify_record(
        clarlog_state_t state,
        int clar_id,
        int mask,
        const struct clar_entry_v2 *pclar);

void
clar_entry_to_ipv6(
        const struct clar_entry_v2 *pe,
        ej_ip_t *pip);
void
ipv6_to_clar_entry(
        const ej_ip_t *pip,
        struct clar_entry_v2 *pe);

int
clar_fetch_run_messages(
        clarlog_state_t state,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry_vector *pfcev);

void
clar_free_fcev(struct full_clar_entry_vector *pfcev);

#endif /* __CLARLOG_H__ */
