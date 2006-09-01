/* -*- c -*- */
/* $Id$ */

#ifndef __SERVER_FRAMEWORK_H__
#define __SERVER_FRAMEWORK_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include <unistd.h>

enum
{
  STATE_READ_CREDS,
  STATE_READ_FDS,
  STATE_READ_LEN,
  STATE_READ_DATA,
  STATE_READ_READY,
  STATE_WRITE,
  STATE_WRITECLOSE,
  STATE_DISCONNECT,
};

struct client_state
{
  struct client_state *next;
  struct client_state *prev;

  int id;
  int fd;
  int state;
  
  int peer_pid;
  int peer_uid;
  int peer_gid;

  int client_fds[2];

  int expected_len;
  int read_len;
  unsigned char *read_buf;

  int write_len;
  int written;
  unsigned char *write_buf;
};

struct server_framework_state;
struct new_server_prot_packet;

struct server_framework_params
{
  int daemon_mode_flag;
  int force_socket_flag;
  unsigned char *program_name;
  unsigned char *socket_path;
  unsigned char *log_path;

  void *user_data;

  void (*startup_error)(const char *, ...);
  void (*handle_packet)(struct server_framework_state *,
                        struct client_state *,
                        size_t,
                        const struct new_server_prot_packet *,
                        void *);
  void (*cleanup_client)(struct server_framework_state *,
                         struct client_state *,
                         void *);
  void (*free_memory)(struct server_framework_state *, void *, void *);
};

struct server_framework_state *nsf_init(struct server_framework_params *params, void *data);
int  nsf_prepare(struct server_framework_state *state);
void nsf_cleanup(struct server_framework_state *state);

void nsf_main_loop(struct server_framework_state *state);

void nsf_err_bad_packet_length(struct server_framework_state *,
                               struct client_state *, size_t, size_t);
void nsf_err_invalid_command(struct server_framework_state *,
                             struct client_state *, int);

#endif /* __SERVER_FRAMEWORK_H__ */
