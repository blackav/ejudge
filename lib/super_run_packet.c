/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/super_run_packet.h"
#include "ejudge/meta_generic.h"
#include "ejudge/meta/super_run_packet_meta.h"
#include "ejudge/prepare.h"
#include "ejudge/errlog.h"
#include "ejudge/misctext.h"

#include "ejudge/xalloc.h"

#include <string.h>

void
super_run_in_global_packet_init(struct generic_section_config *gp)
{
  struct super_run_in_global_packet *p = (struct super_run_in_global_packet *) gp;
  if (!p) return;

  p->secure_run = -1;
  p->detect_violations = -1;
  p->enable_memory_limit_error = -1;
  p->suid_run = -1;
  p->enable_max_stack_size = -1;
  p->user_id = -1;
  p->is_virtual = -1;
  p->max_file_length = -1;
  p->max_line_length = -1;
  p->max_cmd_length = -1;
  p->enable_full_archive = -1;
  p->run_id = -1;
  p->accepting_mode = -1;
  p->separate_user_score = -1;
  p->mime_type = -1;
  p->notify_flag = -1;
  p->advanced_layout = -1;
  p->rejudge_flag = -1;
  p->disable_sound = -1;
  p->is_dos = -1;
  p->time_limit_retry_count = -1;
  p->testlib_mode = -1;

  p->scoring_system_val = -1;
  p->enable_ejudge_env = -1;
}

void
super_run_in_global_packet_set_default(struct generic_section_config *gp)
{
  struct super_run_in_global_packet *p = (struct super_run_in_global_packet *) gp;
  if (!p) return;

  if (p->secure_run < 0) p->secure_run = 0;
  if (p->detect_violations < 0) p->detect_violations = 0;
  if (p->enable_memory_limit_error < 0) p->enable_memory_limit_error = 0;
  if (p->suid_run < 0) p->suid_run = 0;
  if (p->enable_max_stack_size < 0) p->enable_max_stack_size = 0;
  if (p->user_id < 0) p->user_id = 0;
  if (p->is_virtual < 0) p->is_virtual = 0;
  if (p->max_file_length < 0) p->max_file_length = 0;
  if (p->max_line_length < 0) p->max_line_length = 0;
  if (p->max_cmd_length < 0) p->max_cmd_length = 0;
  if (p->enable_full_archive < 0) p->enable_full_archive = 0;
  if (p->run_id < 0) p->run_id = 0;
  if (p->accepting_mode < 0) p->accepting_mode = 0;
  if (p->separate_user_score < 0) p->separate_user_score = 0;
  if (p->mime_type < 0) p->mime_type = 0;
  if (p->notify_flag < 0) p->notify_flag = 0;
  if (p->advanced_layout < 0) p->advanced_layout = 0;
  if (p->rejudge_flag < 0) p->rejudge_flag = 0;
  if (p->disable_sound < 0) p->disable_sound = 0;

  if (p->scoring_system_val < 0) {
    p->scoring_system_val = prepare_parse_score_system(p->score_system);
    if (p->scoring_system_val < 0 || p->scoring_system_val >= SCORE_TOTAL) {
      err("invalid scoring system '%s'", p->score_system);
      p->scoring_system_val = SCORE_ACM;
    }
  }
}

struct super_run_in_global_packet *
super_run_in_global_packet_alloc(void)
{
  struct super_run_in_global_packet *p = NULL;
  XCALLOC(p, 1);
  super_run_in_global_packet_init((struct generic_section_config*) p);
  return p;
}

void
super_run_in_global_packet_free(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_super_run_in_global_packet_methods, gp);
    xfree(gp);
  }
}

void
super_run_in_problem_packet_init(struct generic_section_config *gp)
{
  struct super_run_in_problem_packet *p = (struct super_run_in_problem_packet *) gp;
  if (!p) return;

  p->check_presentation = -1;
  p->scoring_checker = -1;
  p->enable_checker_token = -1;
  p->interactive_valuer = -1;
  p->disable_pe = -1;
  p->disable_wtl = -1;
  p->wtl_is_cf = -1;
  p->use_stdin = -1;
  p->use_stdout = -1;
  p->combined_stdin = -1;
  p->combined_stdout = -1;
  p->ignore_exit_code = -1;
  p->ignore_term_signal = -1;
  p->binary_input = -1;
  p->binary_output = -1;
  p->real_time_limit_ms = -1;
  p->time_limit_ms = -1;
  p->use_ac_not_ok = -1;
  p->full_score = -1;
  p->full_user_score = -1;
  p->variable_full_score = -1;
  p->test_score = -1;
  p->use_corr = -1;
  p->use_info = -1;
  p->use_tgz = -1;
  p->tests_to_accept = -1;
  p->accept_partial = -1;
  p->min_tests_to_accept = -1;
  p->checker_real_time_limit_ms = -1;
  p->checker_time_limit_ms = -1;
  p->valuer_sets_marked = -1;
  p->interactor_time_limit_ms = -1;
  p->interactor_real_time_limit_ms = -1;
  p->disable_stderr = -1;
  p->max_open_file_count = -1;
  p->max_process_count = -1;
  p->enable_process_group = -1;
  p->enable_kill_all = -1;
  p->enable_extended_info = -1;
  p->stop_on_first_fail = -1;
  p->enable_control_socket = -1;
  p->test_count = -1;
  p->disable_vm_size_limit = -1;

  p->type_val = -1;
}

void
super_run_in_problem_packet_set_default(struct generic_section_config *gp)
{
  struct super_run_in_problem_packet *p = (struct super_run_in_problem_packet *) gp;
  if (!p) return;

  if (p->check_presentation < 0) p->check_presentation = 0;
  if (p->scoring_checker < 0) p->scoring_checker = 0;
  if (p->enable_checker_token < 0) p->enable_checker_token = 0;
  if (p->interactive_valuer < 0) p->interactive_valuer = 0;
  if (p->disable_pe < 0) p->disable_pe = 0;
  if (p->disable_wtl < 0) p->disable_wtl = 0;
  if (p->wtl_is_cf < 0) p->wtl_is_cf = 0;
  if (p->use_stdin < 0) p->use_stdin = 0;
  if (p->use_stdout < 0) p->use_stdout = 0;
  if (p->combined_stdin < 0) p->combined_stdin = 0;
  if (p->combined_stdout < 0) p->combined_stdout = 0;
  if (p->ignore_exit_code < 0) p->ignore_exit_code = 0;
  if (p->ignore_term_signal < 0) p->ignore_term_signal = 0;
  if (p->binary_input < 0) p->binary_input = 0;
  if (p->binary_output < 0) p->binary_output = 0;
  if (p->real_time_limit_ms < 0) p->real_time_limit_ms = 0;
  if (p->time_limit_ms < 0) p->time_limit_ms = 0;
  if (p->use_ac_not_ok < 0) p->use_ac_not_ok = 0;
  if (p->full_score < 0) p->full_score = 0;
  if (p->full_user_score < 0) p->full_user_score = 0;
  if (p->variable_full_score < 0) p->variable_full_score = 0;
  if (p->test_score < 0) p->test_score = 0;
  if (p->use_corr < 0) p->use_corr = 0;
  if (p->use_info < 0) p->use_info = 0;
  if (p->use_tgz < 0) p->use_tgz = 0;
  if (p->tests_to_accept < 0) p->tests_to_accept = 0;
  if (p->accept_partial < 0) p->accept_partial = 0;
  if (p->checker_real_time_limit_ms < 0) p->checker_real_time_limit_ms = 0;
  if (p->checker_time_limit_ms < 0) p->checker_time_limit_ms = 0;
  if (p->valuer_sets_marked < 0) p->valuer_sets_marked = 0;
  if (p->interactor_time_limit_ms < 0) p->interactor_time_limit_ms = 0;
  if (p->interactor_real_time_limit_ms < 0) p->interactor_real_time_limit_ms = 0;
  if (p->disable_stderr < 0) p->disable_stderr = 0;
  if (p->max_open_file_count < 0) p->max_open_file_count = 0;
  if (p->max_process_count < 0) p->max_process_count = 0;

  if (p->type_val < 0) {
    p->type_val = problem_parse_type(p->type);
    if (p->type_val < 0 || p->type_val >= PROB_TYPE_LAST) {
      err("invalid problem type '%s'", p->type);
      p->type_val = 0;
    }
  }
}

struct super_run_in_problem_packet *
super_run_in_problem_packet_alloc(void)
{
  struct super_run_in_problem_packet *p = NULL;
  XCALLOC(p, 1);
  strcpy(p->g.name, "problem");
  super_run_in_problem_packet_init((struct generic_section_config*) p);
  return p;
}

void
super_run_in_problem_packet_free(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_super_run_in_problem_packet_methods, gp);
    xfree(gp);
  }
}

void
super_run_in_tester_packet_init(struct generic_section_config *gp)
{
  struct super_run_in_tester_packet *p = (struct super_run_in_tester_packet *) gp;
  if (!p) return;

  p->is_dos = -1;
  p->no_redirect = -1;
  p->ignore_stderr = -1;
  p->no_core_dump = -1;
  p->enable_memory_limit_error = -1;
  p->clear_env = -1;
  p->enable_ejudge_env = -1;
}

void
super_run_in_tester_packet_set_default(struct generic_section_config *gp)
{
  struct super_run_in_tester_packet *p = (struct super_run_in_tester_packet *) gp;
  if (!p) return;

  if (p->is_dos < 0) p->is_dos = 0;
  if (p->no_redirect < 0) p->no_redirect = 0;
  if (p->ignore_stderr < 0) p->ignore_stderr = 0;
  if (p->no_core_dump < 0) p->no_core_dump = 0;
  if (p->enable_memory_limit_error < 0) p->enable_memory_limit_error = 0;
  if (p->clear_env < 0) p->clear_env = 0;
  if (p->enable_ejudge_env < 0) p->enable_ejudge_env = 0;
}

struct super_run_in_tester_packet *
super_run_in_tester_packet_alloc(void)
{
  struct super_run_in_tester_packet *p = NULL;
  XCALLOC(p, 1);
  strcpy(p->g.name, "tester");
  super_run_in_tester_packet_init((struct generic_section_config*) p);
  return p;
}

void
super_run_in_tester_packet_free(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_super_run_in_tester_packet_methods, gp);
    xfree(gp);
  }
}

struct super_run_in_packet *
super_run_in_packet_alloc(void)
{
  struct super_run_in_packet *p = NULL;
  XCALLOC(p, 1);
  p->global = (struct super_run_in_global_packet *) super_run_in_global_packet_alloc();
  p->problem = (struct super_run_in_problem_packet *) super_run_in_problem_packet_alloc();
  p->tester = (struct super_run_in_tester_packet *) super_run_in_tester_packet_alloc();
  return p;
}

void
super_run_in_packet_set_default(struct super_run_in_packet *p)
{
  if (!p) return;

  super_run_in_global_packet_set_default((struct generic_section_config*) p->global);
  super_run_in_problem_packet_set_default((struct generic_section_config*) p->problem);
  super_run_in_tester_packet_set_default((struct generic_section_config*) p->tester);
}

struct super_run_in_packet *
super_run_in_packet_free(struct super_run_in_packet *p)
{
  if (p) {
    super_run_in_global_packet_free((struct generic_section_config*) p->global);
    super_run_in_problem_packet_free((struct generic_section_config*) p->problem);
    super_run_in_tester_packet_free((struct generic_section_config*) p->tester);
    xfree(p);
  }
  return NULL;
}

void
super_run_in_packet_free_tester(struct super_run_in_packet *p)
{
  if (p) {
    super_run_in_tester_packet_free((struct generic_section_config*) p->tester);
    p->tester = NULL;
  }
}

struct config_section_info super_run_in_packet_info[] =
{
  { "global", sizeof(struct super_run_in_global_packet), NULL, NULL,
    super_run_in_global_packet_init, super_run_in_global_packet_free,
    &meta_super_run_in_global_packet_methods },

  { "problem", sizeof(struct super_run_in_problem_packet), NULL, NULL,
    super_run_in_problem_packet_init, super_run_in_problem_packet_free,
    &meta_super_run_in_problem_packet_methods },

  { "tester", sizeof(struct super_run_in_tester_packet), NULL, NULL,
    super_run_in_tester_packet_init, super_run_in_tester_packet_free,
    &meta_super_run_in_tester_packet_methods },

  { NULL, 0 },
};

void
super_run_in_packet_unparse_cfg(FILE *out_f, struct super_run_in_packet *p)
{
  if (p) {
    fprintf(out_f, "# -*- coding: utf-8 -*-\n\n");
    meta_unparse_cfg(out_f, &meta_super_run_in_global_packet_methods, p->global, NULL);
    fprintf(out_f, "\n[problem]\n\n");
    meta_unparse_cfg(out_f, &meta_super_run_in_problem_packet_methods, p->problem, NULL);
    fprintf(out_f, "\n[tester]\n\n");
    meta_unparse_cfg(out_f, &meta_super_run_in_tester_packet_methods, p->tester, NULL);
  }
}

struct super_run_in_packet *
super_run_in_packet_parse_cfg(const unsigned char *path, FILE *f)
{
  struct generic_section_config *cfg = parse_param(path, f, super_run_in_packet_info, 1, 0, 0, NULL);
  if (cfg == NULL) return NULL;
  struct super_run_in_packet *pkt = NULL;
  XCALLOC(pkt, 1);

  for (const struct generic_section_config *p = cfg; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global")) {
      pkt->global = (struct super_run_in_global_packet *) p;
    } else if (!strcmp(p->name, "problem")) {
      pkt->problem = (struct super_run_in_problem_packet *) p;
    } else if (!strcmp(p->name, "tester")) {
      pkt->tester = (struct super_run_in_tester_packet *) p;
    }
  }

  super_run_in_packet_set_default(pkt);

  return pkt;
}

struct super_run_in_packet *
super_run_in_packet_parse_cfg_str(const unsigned char *path, char *buf, size_t size)
{
  FILE *f = fmemopen(buf, size, "r");
  if (!f) return NULL;
  // FIXME: parse_param closes 'f'
  struct super_run_in_packet *pkg = super_run_in_packet_parse_cfg(path, f);
  //fclose(f); f = NULL;
  return pkg;
}

unsigned char *
super_run_in_packet_get_variable(
        const void *vp,
        const unsigned char *name)
{
  const struct super_run_in_packet *p = (const struct super_run_in_packet *) vp;
  if (!strncmp(name, "global.", 7)) {
    return meta_get_variable_str(&meta_super_run_in_global_packet_methods, p->global, name + 7);
  } else if (!strncmp(name, "problem.", 8)) {
    return meta_get_variable_str(&meta_super_run_in_problem_packet_methods, p->problem, name + 8);
  } else if (!strncmp(name, "tester.", 7)) {
    return meta_get_variable_str(&meta_super_run_in_tester_packet_methods, p->tester, name + 7);
  } else {
    return meta_get_variable_str(&meta_super_run_in_global_packet_methods, p->global, name + 7);
  }
}
