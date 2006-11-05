/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "printing.h"

#include "runlog.h"
#include "misctext.h"
#include "teamdb.h"
#include "prepare.h"
#include "archive_paths.h"
#include "fileutl.h"
#include "protocol.h"
#include "userlist.h"
#include "serve_state.h"
#include "xml_utils.h"

#include <reuse/exec.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

static int
print_banner_page(const serve_state_t state,
                  const unsigned char *banner_path, int run_id,
                  int user_id, int is_privileged)
{
  struct run_entry info;
  FILE *f = 0;
  time_t start_time;
  unsigned char *s;
  int i, variant;
  struct teamdb_export teaminfo;

  if (run_id < 0 || run_id >= run_get_total(state->runlog_state)) goto cleanup;
  run_get_entry(state->runlog_state, run_id, &info);
  if (info.status == RUN_VIRTUAL_START
      || info.status == RUN_VIRTUAL_STOP
      || info.status == RUN_EMPTY) {
    return -1;
  }
  if (teamdb_export_team(state->teamdb_state, info.user_id, &teaminfo) < 0)
    return -1;
  start_time = run_get_start_time(state->runlog_state);

  if (!(f = fopen(banner_path, "w"))) goto cleanup;
  fprintf(f, "\n\n\n\n\n\n\n\n\n\n");
  fprintf(f, "Run ID:           %d\n", info.run_id);
  fprintf(f, "Submission time:  %s\n",
          duration_str(1, info.time, start_time, 0, 0));
  fprintf(f, "Contest time:     %s\n",
          duration_str(0, info.time, start_time, 0, 0));
  if (is_privileged) {
    fprintf(f, "Originator IP:    %s\n", xml_unparse_ip(info.a.ip));
  }
  fprintf(f, "Size:             %u\n", info.size);
  if (is_privileged) {
    fprintf(f, "Hash code (SHA1): ");
    s = (unsigned char *) &info.sha1;
    for (i = 0; i < 20; i++) fprintf(f, "%02x", *s++);
    fprintf(f, "\n");
  }
  fprintf(f, "User ID:          %d\n", info.user_id);
  fprintf(f, "User login:       %s\n", teamdb_get_login(state->teamdb_state,
                                                        info.user_id));
  fprintf(f, "User name:        %s\n", teamdb_get_name(state->teamdb_state,
                                                       info.user_id));
  fprintf(f, "Problem:          %s\n", state->probs[info.prob_id]->short_name);
  if (state->probs[info.prob_id]->variant_num > 0) {
    variant = info.variant;
    if (!variant) {
      variant = find_variant(state, info.user_id, info.prob_id);
    }
    fprintf(f, "Variant:          %d\n", variant);
  }
  fprintf(f, "Language:         %s\n",
          (state->langs[info.lang_id])?((char*)state->langs[info.lang_id]->short_name):"");
  if (teaminfo.user && teaminfo.user->i.location) {
    fprintf(f, "Location:         %s\n", teaminfo.user->i.location);
  }
  fprintf(f, "Status:           %s\n", run_status_str(info.status, 0, 0));
  fclose(f);

  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

static int
do_print_run(const serve_state_t state, int run_id,
             int is_privileged, int user_id)
{
  const struct section_global_data *global = state->global;
  unsigned char *banner_path = 0;
  unsigned char *program_path = 0;
  unsigned char *ps_path = 0;
  unsigned char *log_path = 0;
  unsigned char *sfx = "";
  int arch_flags = 0, pages_num = -1, x, i;
  path_t run_arch;
  struct run_entry info;
  tpTask tsk = 0;
  unsigned char in_buf[1024];
  size_t in_buf_len;
  FILE *f = 0;
  int errcode = -SRV_ERR_SYSTEM_ERROR;
  struct teamdb_export teaminfo;
  const unsigned char *printer_name = 0, *user_name = 0, *location = 0;

  if (run_id < 0 || run_id >= run_get_total(state->runlog_state)) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }
  run_get_entry(state->runlog_state, run_id, &info);
  if (info.status == RUN_VIRTUAL_START
      || info.status == RUN_VIRTUAL_STOP
      || info.status == RUN_EMPTY) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }
  if (!is_privileged) {
    if (info.user_id != user_id) {
      errcode = -SRV_ERR_NO_PERMS;
      goto cleanup;
    }
    if (!global->enable_printing) {
      errcode = -SRV_ERR_NO_PERMS;
      goto cleanup;
    }
    if (info.pages > 0) {
      errcode = -SRV_ERR_ALREADY_PRINTED;
      goto cleanup;
    }
  }

  if (teamdb_export_team(state->teamdb_state, info.user_id, &teaminfo) < 0)
    return -1;
  if (!is_privileged) {
    if (teaminfo.user && teaminfo.user->i.printer_name)
      printer_name = teaminfo.user->i.printer_name;
  }

  if (global->disable_banner_page <= 0) {
    banner_path = (unsigned char*) alloca(strlen(global->print_work_dir) + 64);
    sprintf(banner_path, "%s/%06d.txt", global->print_work_dir, run_id);
    if (print_banner_page(state, banner_path, run_id, user_id,
                          is_privileged) < 0) {
      goto cleanup;
    }
  }

  if (global->disable_banner_page > 0) {
    if (state->langs[info.lang_id]) sfx = state->langs[info.lang_id]->src_sfx;
    user_name = teamdb_get_name_2(state->teamdb_state, info.user_id);
    if (!user_name) user_name = "";
    location = "";
    if (teaminfo.user && teaminfo.user->i.location)
      location = teaminfo.user->i.location;
    program_path = (unsigned char*) alloca(strlen(global->print_work_dir) + 64 + strlen(user_name) + strlen(location));
    sprintf(program_path, "%s/%06d_%s_%s%s", global->print_work_dir, run_id,
            user_name, location, sfx);
  } else {
    if (state->langs[info.lang_id]) sfx = state->langs[info.lang_id]->src_sfx;
    program_path = (unsigned char*) alloca(strlen(global->print_work_dir) + 64);
    sprintf(program_path, "%s/%06d%s", global->print_work_dir, run_id, sfx);
  }

  arch_flags = archive_make_read_path(state, run_arch, sizeof(run_arch),
                                      global->run_archive_dir,
                                      run_id, 0,0);
  if (arch_flags < 0) {
    goto cleanup;
  }
  if (generic_copy_file(arch_flags, 0, run_arch, "", 0, 0, program_path, 0) < 0) {
    goto cleanup;
  }

  ps_path = (unsigned char*) alloca(strlen(global->print_work_dir) + 64);
  sprintf(ps_path, "%s/%06d.ps", global->print_work_dir, run_id);

  log_path = (unsigned char*) alloca(strlen(global->print_work_dir) + 64);
  sprintf(log_path, "%s/%06d.out", global->print_work_dir, run_id);

  if (!(tsk = task_New())) goto cleanup;
  task_AddArg(tsk, global->a2ps_path);
  if (global->a2ps_args) {
    for (i = 0; global->a2ps_args[i]; i++)
      task_AddArg(tsk, global->a2ps_args[i]);
  } else {
    task_AddArg(tsk, "-1");
    task_AddArg(tsk, "-E");
    /*
    task_AddArg(tsk, "-X");
    task_AddArg(tsk, "koi8-r");
    */
  }
  task_AddArg(tsk, "-o");
  task_AddArg(tsk, ps_path);
  if (global->disable_banner_page <= 0) {
    task_AddArg(tsk, banner_path);
  }
  task_AddArg(tsk, program_path);
  task_SetPathAsArg0(tsk);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, O_WRONLY|O_CREAT|O_TRUNC, 0777);
  task_ClearEnv(tsk);
  if (task_Start(tsk) < 0) goto cleanup;
  task_Wait(tsk);
  task_Delete(tsk);
  tsk = 0;

  if (!(f = fopen(log_path, "r"))) goto cleanup;
  while (fgets(in_buf, sizeof(in_buf), f)) {
    in_buf_len = strlen(in_buf);
    if (in_buf_len > sizeof(in_buf) - 5) continue;
    if (!strncmp(in_buf, "[Total:", 7)) {
      if (sscanf(in_buf, "[Total: %d pages", &x) == 1 && x >= 1 && x < 100000) {
        pages_num = x;
        break;
      } 
    }
  }
  fclose(f);
  f = 0;
  if (pages_num <= 0) goto cleanup;

  if (!is_privileged) {
    if (pages_num + run_get_total_pages(state->runlog_state, info.user_id) > global->team_page_quota) {
      errcode = -SRV_ERR_PAGES_QUOTA;
      goto cleanup;
    }
    run_set_pages(state->runlog_state, run_id, pages_num);
  }

  if (!(tsk = task_New())) goto cleanup;
  task_AddArg(tsk, global->lpr_path);
  if (global->lpr_args) {
    for (i = 0; global->lpr_args[i]; i++)
      task_AddArg(tsk, global->lpr_args[i]);
  }
  if (printer_name) {
    task_AddArg(tsk, "-P");
    task_AddArg(tsk, printer_name);
  }
  task_AddArg(tsk, ps_path);
  task_SetPathAsArg0(tsk);
  if (task_Start(tsk) < 0) goto cleanup;
  task_Wait(tsk);
  task_Delete(tsk); tsk = 0;

  unlink(banner_path);
  unlink(program_path);
  unlink(ps_path);
  unlink(log_path);
  return pages_num;

 cleanup:
  if (tsk) task_Delete(tsk);
  if (banner_path) unlink(banner_path);
  if (program_path) unlink(program_path);
  if (ps_path) unlink(ps_path);
  if (log_path) unlink(log_path);
  return errcode;
}

int
priv_print_run(const serve_state_t state, int run_id, int user_id)
{
  return do_print_run(state, run_id, 1, user_id);
}

int
team_print_run(const serve_state_t state, int run_id, int user_id)
{
  return do_print_run(state, run_id, 0, user_id);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tpTask")
 * End:
 */
