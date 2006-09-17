/* -*- c -*- */
/* $Id$ */
#ifndef __CLNTUTIL_H__
#define __CLNTUTIL_H__

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"

#include <stdio.h>
#include <time.h>

extern time_t server_cur_time;
extern time_t server_start_time;
extern time_t server_sched_time;
extern time_t server_duration;
extern time_t server_stop_time;
extern time_t server_freeze_time;
extern time_t server_finish_time;
extern int    server_total_runs;
extern int    server_total_clars;
extern int    server_clars_disabled;
extern int    server_team_clars_disabled;
extern int    server_standings_frozen;
extern int    server_score_system;
extern int    server_clients_suspended;
extern int    server_testing_suspended;
extern int    server_download_interval;
extern int    server_is_virtual;
extern int    server_continuation_enabled;
extern int    server_printing_enabled;
extern int    server_printing_suspended;
extern int    server_always_show_problems;
extern int    server_accepting_mode;

extern time_t client_cur_time;

extern char program_name[];
extern char form_header_simple[];
extern char form_header_multipart[];

int   client_lookup_ip(char const *, char const *);
int   client_check_source_ip(int, char const *, char const *);
char *client_time_to_str(char *, time_t);
void  client_access_denied(char const *, int locale_id) __attribute__((noreturn));
void  client_not_configured(char const*,char const*, int locale_id) __attribute__((noreturn));
int   client_check_server_status(char const *, char const *, int, int);
int   client_print_server_status(int, char const *, char const *);

void  client_make_form_headers(unsigned char const *);

void  client_put_header(FILE *out, unsigned char const *template,
                        unsigned char const *content_type,
                        unsigned char const *charset,
                        int http_flag, int locale_id, 
                        char const *format, ...)
  __attribute__((format(printf, 7, 8)));
void  client_put_footer(FILE *out, unsigned char const *template);
ej_ip_t parse_client_ip(void);

#endif /* __CLNTUTIL_H__ */
/**
 * Local variables:
 *  compile-command: "make"
 * End:
 */
