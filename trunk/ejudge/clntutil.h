/* -*- c -*- */
/* $Id$ */
#ifndef __CLNTUTIL_H__
#define __CLNTUTIL_H__

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

extern unsigned long server_cur_time;
extern unsigned long server_start_time;
extern unsigned long server_sched_time;
extern unsigned long server_duration;
extern unsigned long server_stop_time;
extern int           server_total_runs;
extern int           server_total_clars;

extern unsigned long client_cur_time;
extern char          client_pipe_dir[];
extern char          client_cmd_dir[];

extern char program_name[];
extern char form_header_simple[];
extern char form_header_multipart[];
extern char form_header_simple_ext[];
extern char form_header_multipart_ext[];

void  client_puts(char const *, ...);
void  client_put_header(char const *, ...);
void  client_put_footer(void);
int   client_lookup_ip(char const *, char const *);
int   client_check_source_ip(int, char const *, char const *);
char *client_time_to_str(char *, unsigned long);
void  client_access_denied(void) __attribute__((noreturn));
void  client_not_configured(char const *) __attribute__((noreturn));
int   client_check_server_status(char const *, int);
int   client_print_server_status(int, char const *, char const *);

void  client_make_form_headers(void);

int   client_make_pipe(char const *);
char *client_packet_name(char *);
int   client_get_reply(char **, int *, char const *);
int   client_transaction(char *, char const *, char **, int*);

char *client_file_to_str(char const *, int);
int   client_file_to_stdout(char const *, int);
void  client_split(char const *, int, ...);

#endif /* __CLNTUTIL_H__ */
