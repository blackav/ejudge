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

#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void startup_error(const char *, ...) __attribute__((noreturn,format(printf, 1, 2)));
static void handle_packet_func(struct server_framework_state *,
                               struct client_state *,
                               size_t,
                               const struct new_server_prot_packet *);

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

static void
cmd_http_request(struct server_framework_state *state,
                 struct client_state *p,
                 size_t pkt_size,
                 const struct new_server_prot_packet *pkt_gen)
{
  enum
  {
    MAX_PARAM_NUM = 10000,
    MAX_PARAM_SIZE = 128 * 1024 * 1024,
  };

  const struct new_server_prot_http_request *pkt;
  size_t in_size;
  const ej_size_t *arg_sizes, *env_sizes, *param_name_sizes, *param_sizes;
  unsigned long bptr;
  const unsigned char ** args;
  const unsigned char ** envs;
  const unsigned char ** param_names;
  const unsigned char ** params;
  int i;
  char *out_txt = 0;
  size_t out_size = 0;
  FILE *out_f = 0;

  if (pkt_size < sizeof(*pkt))
    return nsf_err_packet_too_small(state, p, pkt_size, sizeof(*pkt));
  pkt = (const struct new_server_prot_http_request *) pkt_gen;

  if (pkt->arg_num < 0 || pkt->arg_num > MAX_PARAM_NUM)
    return nsf_err_protocol_error(state, p);
  if (pkt->env_num < 0 || pkt->env_num > MAX_PARAM_NUM)
    return nsf_err_protocol_error(state, p);
  if (pkt->param_num < 0 || pkt->param_num > MAX_PARAM_NUM)
    return nsf_err_protocol_error(state, p);

  in_size = sizeof(*pkt);
  in_size = (in_size + 15) & ~15;
  in_size += pkt->arg_num * sizeof(ej_size_t);
  in_size += pkt->env_num * sizeof(ej_size_t);
  in_size += pkt->param_num * 2 * sizeof(ej_size_t);
  if (pkt_size < in_size)
    return nsf_err_packet_too_small(state, p, pkt_size, in_size);

  XALLOCAZ(args, pkt->arg_num);
  XALLOCAZ(envs, pkt->env_num);
  XALLOCAZ(param_names, pkt->param_num);
  XALLOCAZ(params, pkt->param_num);

  bptr = (unsigned long) pkt;
  bptr += sizeof(pkt);
  bptr = (bptr + 15) * sizeof(ej_size_t);
  arg_sizes = (const ej_size_t *) bptr;
  bptr += pkt->arg_num * sizeof(ej_size_t);
  env_sizes = (const ej_size_t *) bptr;
  bptr += pkt->env_num * sizeof(ej_size_t);
  param_name_sizes = (const ej_size_t *) bptr;
  bptr += pkt->param_num * sizeof(ej_size_t);
  param_sizes = (const ej_size_t *) bptr;
  bptr += pkt->param_num * sizeof(ej_size_t);

  for (i = 0; i < pkt->arg_num; i++) {
    if (arg_sizes[i] > MAX_PARAM_SIZE) return nsf_err_protocol_error(state, p);
    in_size += arg_sizes[i] + 1;
  }
  for (i = 0; i < pkt->env_num; i++) {
    if (env_sizes[i] > MAX_PARAM_SIZE) return nsf_err_protocol_error(state, p);
    in_size += env_sizes[i] + 1;
  }
  for (i = 0; i < pkt->param_num; i++) {
    if (param_name_sizes[i] > MAX_PARAM_SIZE)
      return nsf_err_protocol_error(state, p);
    if (param_sizes[i] > MAX_PARAM_SIZE)
      return nsf_err_protocol_error(state, p);
    in_size += param_name_sizes[i] + 1;
    in_size += param_sizes[i] + 1;
  }
  in_size = (in_size + 15) & ~15;
  if (pkt_size != in_size)
    return nsf_err_bad_packet_length(state, p, pkt_size, in_size);

  for (i = 0; i < pkt->arg_num; i++) {
    args[i] = (const unsigned char*) bptr;
    bptr += arg_sizes[i] + 1;
    if (strlen(args[i]) != arg_sizes[i])
      return nsf_err_protocol_error(state, p);
  }
  for (i = 0; i < pkt->env_num; i++) {
    envs[i] = (const unsigned char*) bptr;
    bptr += env_sizes[i] + 1;
    if (strlen(envs[i]) != env_sizes[i])
      return nsf_err_protocol_error(state, p);
  }
  for (i = 0; i < pkt->param_num; i++) {
    param_names[i] = (const unsigned char*) bptr;
    bptr += param_name_sizes[i] + 1;
    if (strlen(param_names[i]) != param_name_sizes[i])
      return nsf_err_protocol_error(state, p);
    params[i] = (const unsigned char *) bptr;
    bptr += param_sizes[i] + 1;
  }

  // ok, generate HTML
  out_f = open_memstream(&out_txt, &out_size);
  fclose(out_f); out_f = 0;

  nsf_new_autoclose(state, p, out_txt, out_size);
  info("HTTP_REQUEST -> OK, %zu", out_size);
  nsf_send_reply(state, p, NEW_SRV_RPL_OK);
}

typedef void handler_t(struct server_framework_state *state,
                       struct client_state *p,
                       size_t pkt_size,
                       const struct new_server_prot_packet *pkt);

static handler_t *handlers[NEW_SRV_CMD_LAST] =
{
  [NEW_SRV_CMD_HTTP_REQUEST] cmd_http_request,
};

static void
handle_packet_func(struct server_framework_state *state,
                   struct client_state *p,
                   size_t pkt_size,
                   const struct new_server_prot_packet *pkt)
{
  if (pkt->id <= 1 || pkt->id >= NEW_SRV_CMD_LAST || !handlers[pkt->id])
    return nsf_err_invalid_command(state, p, pkt->id);

  handlers[pkt->id](state, p, pkt_size, pkt);
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
