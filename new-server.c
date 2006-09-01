/* -*- mode: c -*- */
/* $Id$ */

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

#include "config.h"
#include "settings.h"
#include "ej_types.h"
#include "version.h"

#include "errlog.h"
#include "server_framework.h"
#include "new_server_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void startup_error(const char *, ...) __attribute__((noreturn,format(printf, 1, 2)));
static void handle_packet_func(struct server_framework_state *,
                               struct client_state *,
                               size_t,
                               const struct new_server_prot_packet *,
                               void *);

static struct server_framework_params params =
{
  .daemon_mode_flag = 0,
  .force_socket_flag = 0,
  .program_name = 0,
  .socket_path = "/tmp/new-server-socket",
  .log_path = "/tmp/new-server-log",
  .user_data = 0,
  .startup_error = startup_error,
  .handle_packet = handle_packet_func,
};

static struct server_framework_state *state = 0;

static void
startup_error(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", params.program_name, buf);
  exit(1);
}

typedef void handler_t(struct server_framework_state *state,
                       struct client_state *p,
                       size_t pkt_size,
                       const struct new_server_prot_packet *pkt,
                       void *user_data);

static handler_t *handlers[NEW_SRV_CMD_LAST] =
{
};

static void
handle_packet_func(struct server_framework_state *state,
                   struct client_state *p,
                   size_t pkt_size,
                   const struct new_server_prot_packet *pkt,
                   void *user_data)
{
  if (pkt->id <= 1 || pkt->id >= NEW_SRV_CMD_LAST || !handlers[pkt->id])
    return nsf_err_invalid_command(state, p, pkt->id);

}

int
main(int argc, char *argv[])
{
  int i;

  params.program_name = argv[0];
  for (i = 1; i < argc; ) {
    if (!strcmp(argv[i], "-D")) {
      params.daemon_mode_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-f")) {
      params.force_socket_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else
      break;
  }

  info("new-server %s, compiled %s", compile_version, compile_date);

  if (!(state = nsf_init(&params, 0))) return 1;
  if (nsf_prepare(state) < 0) return 1;
  nsf_main_loop(state);
  nsf_cleanup(state);

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
