/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/nwrun_packet.h"
#include "ejudge/errlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <string.h>

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define NWRUN_IN_OFFSET(x)   XOFFSET(struct nwrun_in_packet, x)
#define NWRUN_IN_SIZE(x)     XFSIZE(struct nwrun_in_packet, x)
#define NWRUN_IN_PARAM(x, t) { #x, t, NWRUN_IN_OFFSET(x), NWRUN_IN_SIZE(x) }
static const struct config_parse_info nwrun_in_params[] =
{
  NWRUN_IN_PARAM(priority, "d"),
  NWRUN_IN_PARAM(contest_id, "d"),
  NWRUN_IN_PARAM(run_id, "d"),
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
  NWRUN_IN_PARAM(combined_stdin, "d"),
  NWRUN_IN_PARAM(combined_stdout, "d"),
  NWRUN_IN_PARAM(time_limit_millis, "d"),
  NWRUN_IN_PARAM(real_time_limit_millis, "d"),
  NWRUN_IN_PARAM(max_stack_size, "z"),
  NWRUN_IN_PARAM(max_data_size, "z"),
  NWRUN_IN_PARAM(max_vm_size, "z"),
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
  fclose(f); f = 0;
  if (!(config = parse_param(path, 0, nwrun_in_config, 1, 0, 0, 0))) {
    goto cleanup;
  }

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

void
nwrun_in_packet_print(FILE *fout, const struct nwrun_in_packet *p)
{
  if (!p) return;

  fprintf(fout, "# -*- coding: utf-8 -*-\n\n");

  fprintf(fout, "priority = %d\n", p->priority);
  fprintf(fout, "contest_id = %d\n", p->contest_id);
  fprintf(fout, "run_id = %d\n", p->run_id);
  fprintf(fout, "prob_id = %d\n", p->prob_id);
  fprintf(fout, "test_num = %d\n", p->test_num);
  fprintf(fout, "judge_id = %d\n", p->judge_id);
  fprintf(fout, "use_contest_id_in_reply = %d\n", p->use_contest_id_in_reply);
  fprintf(fout, "enable_unix2dos = %d\n", p->enable_unix2dos);
  fprintf(fout, "disable_stdin = %d\n", p->disable_stdin);
  fprintf(fout, "ignore_stdout = %d\n", p->ignore_stdout);
  fprintf(fout, "ignore_stderr = %d\n", p->ignore_stderr);
  fprintf(fout, "redirect_stdin = %d\n", p->redirect_stdin);
  fprintf(fout, "redirect_stdout = %d\n", p->redirect_stdout);
  fprintf(fout, "redirect_stderr = %d\n", p->redirect_stderr);
  fprintf(fout, "combined_stdin = %d\n", p->combined_stdin);
  fprintf(fout, "combined_stdout = %d\n", p->combined_stdout);
  fprintf(fout, "time_limit_millis = %d\n", p->time_limit_millis);
  fprintf(fout, "real_time_limit_millis = %d\n", p->real_time_limit_millis);
#ifdef __MINGW32__
  fprintf(fout, "max_stack_size = %I64d\n", (long long) p->max_stack_size);
  fprintf(fout, "max_data_size = %I64d\n", (long long) p->max_data_size);
  fprintf(fout, "max_vm_size = %I64d\n", (long long) p->max_vm_size);
  fprintf(fout, "max_output_file_size = %I64d\n", (long long) p->max_output_file_size);
  fprintf(fout, "max_error_file_size = %I64d\n", (long long) p->max_error_file_size);
#else
  fprintf(fout, "max_stack_size = %lld\n", (long long) p->max_stack_size);
  fprintf(fout, "max_data_size = %lld\n", (long long) p->max_data_size);
  fprintf(fout, "max_vm_size = %lld\n", (long long) p->max_vm_size);
  fprintf(fout, "max_output_file_size = %lld\n", (long long) p->max_output_file_size);
  fprintf(fout, "max_error_file_size = %lld\n", (long long) p->max_error_file_size);
#endif
  fprintf(fout, "enable_memory_limit_error = %d\n", p->enable_memory_limit_error);
  fprintf(fout, "enable_security_violation_error = %d\n", p->enable_security_violation_error);
  fprintf(fout, "enable_secure_run = %d\n", p->enable_secure_run);

  fprintf(fout, "prob_short_name = %s\n", p->prob_short_name);
  fprintf(fout, "program_name = %s\n", p->program_name);
  fprintf(fout, "test_file_name = %s\n", p->test_file_name);
  fprintf(fout, "input_file_name = %s\n", p->input_file_name);
  fprintf(fout, "output_file_name = %s\n", p->output_file_name);
  fprintf(fout, "result_file_name = %s\n", p->result_file_name);
  fprintf(fout, "error_file_name = %s\n", p->error_file_name);
  fprintf(fout, "log_file_name = %s\n", p->log_file_name);
}

#define NWRUN_OUT_OFFSET(x)   XOFFSET(struct nwrun_out_packet, x)
#define NWRUN_OUT_SIZE(x)     XFSIZE(struct nwrun_out_packet, x)
#define NWRUN_OUT_PARAM(x, t) { #x, t, NWRUN_OUT_OFFSET(x), NWRUN_OUT_SIZE(x) }
static const struct config_parse_info nwrun_out_params[] =
{
  NWRUN_OUT_PARAM(contest_id, "d"),
  NWRUN_OUT_PARAM(run_id, "d"),
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
  NWRUN_OUT_PARAM(real_time_available, "d"),
  NWRUN_OUT_PARAM(real_time_millis, "d"),
  NWRUN_OUT_PARAM(max_memory_used, "z"),
  NWRUN_OUT_PARAM(is_signaled, "d"),
  NWRUN_OUT_PARAM(signal_num, "d"),
  NWRUN_OUT_PARAM(exit_code, "d"),
  NWRUN_OUT_PARAM(hostname, "s"),
  NWRUN_OUT_PARAM(comment, "s"),
  NWRUN_OUT_PARAM(exit_comment, "s"),

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
  fclose(f); f = 0;
  if (!(config = parse_param(path, 0, nwrun_out_config, 1, 0, 0, 0))) {
    goto cleanup;
  }

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
  fprintf(fout, "run_id = %d\n", result->run_id);
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
  if (result->real_time_available > 0) {
    fprintf(fout, "real_time_available = %d\n", result->real_time_available);
    fprintf(fout, "real_time_millis = %d\n", result->real_time_millis);
  }

  if (result->max_memory_used > 0) {
    fprintf(fout, "max_memory_used = %lu\n", (unsigned long) result->max_memory_used);
  }

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
  if (result->exit_comment[0]) {
    fprintf(fout, "exit_comment = \"%s\"\n", result->exit_comment);
  }
}
