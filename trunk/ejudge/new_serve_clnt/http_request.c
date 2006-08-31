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

#include "ej_types.h"
#include "new_serve_clnt/new_serve_clnt_priv.h"
#include "new_serve_proto.h"
#include "errlog.h"

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <unistd.h>

enum
{
  MAX_PARAM_NUM = 10000,
  MAX_PARAM_SIZE = 128 * 1024 * 1024,
};

int
new_serve_clnt_http_request(new_serve_conn_t conn,
                            int out_fd,
                            unsigned char *args[],
                            unsigned char *envs[],
                            int param_num,
                            unsigned char *param_names[],
                            size_t param_sizes_in[],
                            unsigned char *params[])
{
  int arg_num = 0, env_num = 0, i;
  ej_size_t *arg_sizes = 0, *env_sizes = 0, *param_sizes = 0;
  ej_size_t *param_name_sizes = 0;
  ej_size_t t;
  struct new_serve_prot_http_request *out = 0;
  size_t out_size;
  unsigned long bptr;// hope,that that's enough for pointer
  int pipe_fd[2] = { -1, -1 }, pass_fd[2];
  int errcode = -NEW_SRV_ERR_PARAM_OUT_OF_RANGE, r;
  void *void_in = 0;
  size_t in_size = 0;
  struct new_serve_prot_packet *in;
  char c;

  if (args) {
    for (; args[arg_num]; arg_num++);
  }
  if (arg_num < 0 || arg_num > MAX_PARAM_NUM) goto failed;
  if (envs) {
    for (; envs[env_num]; env_num++);
  }
  if (env_num < 0 || env_num > MAX_PARAM_NUM) goto failed;
  if (param_num < 0 || param_num > MAX_PARAM_NUM) goto failed;

  out_size = sizeof(*out);
  out_size = (out_size + 15) & ~15;
  out_size += arg_num * sizeof(ej_size_t);
  out_size += env_num * sizeof(ej_size_t);
  out_size += 2 * param_num * sizeof(ej_size_t);

  if (arg_num > 0) {
    XALLOCAZ(arg_sizes, arg_num);
    for (i = 0; i < arg_num; i++) {
      arg_sizes[i] = t = strlen(args[i]);
      if (t < 0 || t > MAX_PARAM_SIZE) goto failed;
      out_size += t + 1;
    }
  }

  if (env_num > 0) {
    XALLOCAZ(env_sizes, env_num);
    for (i = 0; i < env_num; i++) {
      env_sizes[i] = t = strlen(envs[i]);
      if (t < 0 || t > MAX_PARAM_SIZE) goto failed;
      out_size += t + 1;
    }
  }

  if (param_num > 0) {
    XALLOCAZ(param_name_sizes, param_num);
    XALLOCAZ(param_sizes, param_num);
    for (i = 0; i < param_num; i++) {
      param_name_sizes[i] = t = strlen(param_names[i]);
      if (t < 0 || t > MAX_PARAM_SIZE) goto failed;
      out_size += t + 1;
      param_sizes[i] = t = param_sizes_in[i];
      if (t < 0 || t > MAX_PARAM_SIZE) goto failed;
      out_size += t + 1;
    }
  }

  if (out_size < 0 || out_size > MAX_PARAM_SIZE)
    return -NEW_SRV_ERR_PARAM_OUT_OF_RANGE;

  out_size = (out_size + 15) & ~15;
  out = (struct new_serve_prot_http_request*) xcalloc(out_size, 1);
  out->b.magic = NEW_SERVE_PROT_PACKET_MAGIC;
  out->b.id = NEW_SRV_CMD_HTTP_REQUEST;
  out->arg_num = arg_num;
  out->env_num = env_num;
  out->param_num = param_num;

  bptr = (unsigned long) out;
  bptr += sizeof(*out);
  bptr = (bptr + 15) & ~15;
  if (arg_num > 0) {
    memcpy((void*) bptr, arg_sizes, arg_num * sizeof(arg_sizes[0]));
    bptr += arg_num * sizeof(arg_sizes[0]);
  }
  if (env_num > 0) {
    memcpy((void*) bptr, env_sizes, env_num * sizeof(env_sizes[0]));
    bptr += env_num * sizeof(env_sizes[0]);
  }
  if (param_num > 0) {
    memcpy((void*) bptr, param_name_sizes, param_num * sizeof(ej_size_t));
    memcpy((void*) bptr, param_sizes, param_num * sizeof(param_sizes[0]));
    bptr += param_num * sizeof(param_sizes[0]);
  }
  for (i = 0; i < arg_num; i++) {
    memcpy((void*) bptr, args[i], arg_sizes[i]);
    bptr += arg_sizes[i] + 1;
  }
  for (i = 0; i < env_num; i++) {
    memcpy((void*) bptr, envs[i], env_sizes[i]);
    bptr += env_sizes[i] + 1;
  }
  for (i = 0; i < param_num; i++) {
    memcpy((void*) bptr, param_names[i], param_name_sizes[i]);
    bptr += param_name_sizes[i] + 1;
    memcpy((void*) bptr, params[i], param_sizes[i]);
    bptr += param_sizes[i] + 1;
  }

  if (pipe(pipe_fd) < 0) {
    err("new_serve_clnt_http_request: pipe() failed: %s", os_ErrorMsg());
    errcode = -NEW_SRV_ERR_SYSTEM_ERROR;
    goto failed;
  }
  pass_fd[0] = out_fd;
  pass_fd[1] = pipe_fd[1];
  if ((errcode = new_serve_clnt_pass_fd(conn, 2, pass_fd)) < 0) goto failed;
  close(pipe_fd[1]); pipe_fd[1] = -1;
  if ((errcode = new_serve_clnt_send_packet(conn, out_size, out)) < 0)
    goto failed;
  if ((errcode = new_serve_clnt_recv_packet(conn, &in_size, &void_in)) < 0)
    goto failed;
  errcode = -NEW_SRV_ERR_PROTOCOL_ERROR;
  if (in_size != sizeof(*in)) {
    err("new_serve_clnt_http_request: packet size mismatch");
    goto failed;
  }
  in = (struct new_serve_prot_packet*) void_in;
  if (in->magic != NEW_SERVE_PROT_PACKET_MAGIC) {
    err("new_serve_clnt_http_request: packet magic mismatch");
    goto failed;
  }
  errcode = in->id;
  if (errcode < 0) goto failed;

  // wait for the server to complete page generation
  r = read(pipe_fd[0], &c, 1);
  if (r < 0) {
    err("new_serve_clnt_http_request: read() failed: %s", os_ErrorMsg());
    errcode = -NEW_SRV_ERR_READ_ERROR;
    goto failed;
  }
  if (r > 0) {
    err("new_serve_clnt_http_request: data in wait pipe");
    goto failed;
  }
  errcode = NEW_SRV_RPL_OK;

 failed:
  xfree(out);
  xfree(void_in);
  if (pipe_fd[0] >= 0) close(pipe_fd[0]);
  if (pipe_fd[1] >= 0) close(pipe_fd[1]);
  return errcode;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
