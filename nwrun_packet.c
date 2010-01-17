/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"
#include "version.h"

#include "nwrun_packet.h"
#include "errlog.h"

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <string.h>

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define NWRUN_IN_OFFSET(x)   XOFFSET(struct nwrun_in_packet, x)
#define NWRUN_IN_SIZE(x)     XFSIZE(struct nwrun_in_packet, x)
#define NWRUN_IN_PARAM(x, t) { #x, t, NWRUN_IN_OFFSET(x), NWRUN_IN_SIZE(x) }
static const struct config_parse_info nwrun_in_params[] =
{
  NWRUN_IN_PARAM(contest_id, "d"),
  NWRUN_IN_PARAM(prob_id, "d"),
  NWRUN_IN_PARAM(test_num, "d"),
  NWRUN_IN_PARAM(judge_id, "d"),
  NWRUN_IN_PARAM(use_contest_id_in_reply, "d"),
  NWRUN_IN_PARAM(enable_unix2dos, "d"),
  NWRUN_IN_PARAM(disable_stdin, "d"),
  NWRUN_IN_PARAM(ignore_stdout, "d"),
  NWRUN_IN_PARAM(ignore_stderr, "d"),
  NWRUN_IN_PARAM(redirect_stdin, "d"),
  NWRUN_IN_PARAM(redirect_stdout, "d"),
  NWRUN_IN_PARAM(redirect_stderr, "d"),
  NWRUN_IN_PARAM(time_limit_millis, "d"),
  NWRUN_IN_PARAM(real_time_limit_millis, "d"),
  NWRUN_IN_PARAM(max_stack_size, "d"),
  NWRUN_IN_PARAM(max_data_size, "d"),
  NWRUN_IN_PARAM(max_vm_size, "d"),
  NWRUN_IN_PARAM(max_output_file_size, "d"),
  NWRUN_IN_PARAM(max_error_file_size, "d"),
  NWRUN_IN_PARAM(enable_memory_limit_error, "d"),
  NWRUN_IN_PARAM(enable_security_violation_error, "d"),
  NWRUN_IN_PARAM(enable_secure_run, "d"),

  NWRUN_IN_PARAM(prob_short_name, "s"),
  NWRUN_IN_PARAM(program_name, "s"),
  NWRUN_IN_PARAM(test_file_name, "s"),
  NWRUN_IN_PARAM(input_file_name, "s"),
  NWRUN_IN_PARAM(output_file_name, "s"),
  NWRUN_IN_PARAM(result_file_name, "s"),
  NWRUN_IN_PARAM(error_file_name, "s"),
  NWRUN_IN_PARAM(log_file_name, "s"),

  { 0, 0, 0, 0 }
};
static const struct config_section_info nwrun_in_config[] =
{
  { "global", sizeof(struct nwrun_in_packet), nwrun_in_params, 0, 0, 0 },
  { NULL, 0, NULL }
};

struct generic_section_config *
nwrun_in_packet_parse(const unsigned char *path, struct nwrun_in_packet **pkt)
{
  FILE *f = 0;
  struct generic_section_config *config = 0, *p;
  struct nwrun_in_packet *packet = 0;

  if (!(f = fopen(path, "rb"))) {
    err("cannot open file %s: %s", path, os_ErrorMsg());
    goto cleanup;
  }
  if (!(config = parse_param(path, f, nwrun_in_config, 1, 0, 0, 0))) {
    goto cleanup;
  }
  fclose(f); f = 0;

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global")) {
      packet = (struct nwrun_in_packet *) p;
    }
  }

  if (!packet) {
    err("no global section in %s", path);
    goto cleanup;
  }
  *pkt = packet;
  return config;

 cleanup:
  param_free(config, nwrun_in_config);
  if (f) fclose(f);
  return 0;
}

struct generic_section_config *
nwrun_in_packet_free(struct generic_section_config *config)
{
  if (!config) return 0;

  param_free(config, nwrun_in_config);
  return 0;
}

#define NWRUN_OUT_OFFSET(x)   XOFFSET(struct nwrun_out_packet, x)
#define NWRUN_OUT_SIZE(x)     XFSIZE(struct nwrun_out_packet, x)
#define NWRUN_OUT_PARAM(x, t) { #x, t, NWRUN_OUT_OFFSET(x), NWRUN_OUT_SIZE(x) }
static const struct config_parse_info nwrun_out_params[] =
{
  NWRUN_OUT_PARAM(contest_id, "d"),
  NWRUN_OUT_PARAM(prob_id, "d"),
  NWRUN_OUT_PARAM(test_num, "d"),
  NWRUN_OUT_PARAM(judge_id, "d"),
  NWRUN_OUT_PARAM(status, "d"),
  NWRUN_OUT_PARAM(output_file_existed, "d"),
  NWRUN_OUT_PARAM(output_file_orig_size, "d"),
  NWRUN_OUT_PARAM(output_file_too_big, "d"),
  NWRUN_OUT_PARAM(error_file_existed, "d"),
  NWRUN_OUT_PARAM(error_file_orig_size, "d"),
  NWRUN_OUT_PARAM(error_file_truncated, "d"),
  NWRUN_OUT_PARAM(error_file_size, "d"),
  NWRUN_OUT_PARAM(cpu_time_millis, "d"),
  NWRUN_OUT_PARAM(real_time_millis, "d"),
  NWRUN_OUT_PARAM(is_signaled, "d"),
  NWRUN_OUT_PARAM(signal_num, "d"),
  NWRUN_OUT_PARAM(exit_code, "d"),
  NWRUN_OUT_PARAM(hostname, "d"),
  NWRUN_OUT_PARAM(comment, "d"),

  { 0, 0, 0, 0 }
};
static const struct config_section_info nwrun_out_config[] =
{
  { "global", sizeof(struct nwrun_out_packet), nwrun_out_params, 0, 0, 0 },
  { NULL, 0, NULL }
};

struct generic_section_config *
nwrun_out_packet_parse(const unsigned char *path, struct nwrun_out_packet **pkt)
{
  FILE *f = 0;
  struct generic_section_config *config = 0, *p;
  struct nwrun_out_packet *packet = 0;

  if (!(f = fopen(path, "rb"))) {
    err("cannot open file %s: %s", path, os_ErrorMsg());
    goto cleanup;
  }
  if (!(config = parse_param(path, f, nwrun_out_config, 1, 0, 0, 0))) {
    goto cleanup;
  }
  fclose(f); f = 0;

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global")) {
      packet = (struct nwrun_out_packet *) p;
    }
  }

  if (!packet) {
    err("no global section in %s", path);
    goto cleanup;
  }
  *pkt = packet;
  return config;

 cleanup:
  param_free(config, nwrun_out_config);
  if (f) fclose(f);
  return 0;
}

struct generic_section_config *
nwrun_out_packet_free(struct generic_section_config *config)
{
  if (!config) return 0;

  param_free(config, nwrun_out_config);
  return 0;
}

void
nwrun_out_packet_print(FILE *fout, const struct nwrun_out_packet *result)
{
  fprintf(fout, "# -*- coding: utf-8 -*-\n\n");

  fprintf(fout, "contest_id = %d\n", result->contest_id);
  fprintf(fout, "prob_id = %d\n", result->prob_id);
  fprintf(fout, "test_num = %d\n", result->test_num);
  fprintf(fout, "judge_id = %d\n", result->judge_id);
  fprintf(fout, "status = %d\n", result->status);

  fprintf(fout, "output_file_existed = %d\n", result->output_file_existed);
  fprintf(fout, "output_file_orig_size = %d\n", result->output_file_orig_size);
  fprintf(fout, "output_file_too_big = %d\n", result->output_file_too_big);

  fprintf(fout, "error_file_existed = %d\n", result->error_file_existed);
  fprintf(fout, "error_file_orig_size = %d\n", result->error_file_orig_size);
  fprintf(fout, "error_file_truncated = %d\n", result->error_file_truncated);
  fprintf(fout, "error_file_size = %d\n", result->error_file_size);

  fprintf(fout, "cpu_time_millis = %d\n", result->cpu_time_millis);
  fprintf(fout, "real_time_millis = %d\n", result->real_time_millis);

  fprintf(fout, "is_signaled = %d\n", result->is_signaled);
  fprintf(fout, "signal_num = %d\n", result->signal_num);
  fprintf(fout, "exit_code = %d\n", result->exit_code);

  // FIXME: this is wrong!
  if (result->comment[0]) {
    fprintf(fout, "comment = \"%s\"\n", result->comment);
  }
  if (result->hostname[0]) {
    fprintf(fout, "hostname = \"%s\"\n", result->hostname);
  }
}
