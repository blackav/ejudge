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

#include "diff.h"

#include "runlog.h"
#include "protocol.h"
#include "prepare.h"
#include "archive_paths.h"
#include "fileutl.h"
#include "serve_state.h"

#include <reuse/exec.h>
#include <reuse/xalloc.h>

#include <unistd.h>
#include <fcntl.h>

int
compare_runs(const serve_state_t state, FILE *fout, int run_id1, int run_id2)
{
  struct run_entry info1, info2;
  int errcode = -SRV_ERR_SYSTEM_ERROR;
  unsigned char *tmpfile1 = 0, *tmpfile2 = 0, *tmpfile3 = 0;
  unsigned char par1[64], par2[64];
  int flags1, flags2;
  path_t arch_path1, arch_path2;
  tpTask tsk = 0;
  char *diff_txt = 0;
  size_t diff_len = 0;

  // refuse to do stupid things
  if (run_id1 == run_id2) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }

  // swap runs, if necessary
  if (run_id1 > run_id2) {
    int t = run_id1;
    run_id1 = run_id2;
    run_id2 = t;
  }

  // check the first run
  if (run_id1 < 0 || run_id1 >= run_get_total(state->runlog_state)) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }
  run_get_entry(state->runlog_state, run_id1, &info1);
  if (info1.status >= RUN_PSEUDO_FIRST && info1.status <= RUN_PSEUDO_LAST) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }
  if (info1.lang_id <= 0 || info1.lang_id > state->max_lang
      || !state->langs[info1.lang_id] || state->langs[info1.lang_id]->binary) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }

  // check the second run
  if (run_id2 < 0 || run_id2 >= run_get_total(state->runlog_state)) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }
  run_get_entry(state->runlog_state, run_id2, &info2);
  if (info2.status >= RUN_PSEUDO_FIRST && info2.status <= RUN_PSEUDO_LAST) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }
  if (info2.lang_id <= 0 || info2.lang_id > state->max_lang
      || !state->langs[info2.lang_id] || state->langs[info2.lang_id]->binary) {
    errcode = -SRV_ERR_BAD_RUN_ID;
    goto cleanup;
  }

  // compose temporary paths for the files
  snprintf(par1, sizeof(par1), "d1-%06d", run_id1);
  tmpfile1 = alloca(strlen(state->global->diff_work_dir) + 65);
  sprintf(tmpfile1, "%s/%s", state->global->diff_work_dir, par1);
  snprintf(par2, sizeof(par2), "d2-%06d", run_id2);
  tmpfile2 = alloca(strlen(state->global->diff_work_dir) + 65);
  sprintf(tmpfile2, "%s/%s", state->global->diff_work_dir, par2);
  tmpfile3 = alloca(strlen(state->global->diff_work_dir) + 65);
  sprintf(tmpfile3, "%s/diff", state->global->diff_work_dir);

  // copy files to temporary location
  if ((flags1=archive_make_read_path(state, arch_path1, sizeof(arch_path1),
                                     state->global->run_archive_dir, run_id1,
                                     0, 0))<0) {
    goto cleanup;
  }
  if (generic_copy_file(flags1, 0, arch_path1, "", 0, 0, tmpfile1, 0) < 0) {
    goto cleanup;
  }
  if ((flags2=archive_make_read_path(state, arch_path2, sizeof(arch_path2),
                                     state->global->run_archive_dir,run_id2,
                                     0, 0))<0) {
    goto cleanup;
  }
  if (generic_copy_file(flags2, 0, arch_path2, "", 0, 0, tmpfile2, 0) < 0) {
    goto cleanup;
  }

  fprintf(fout, "Content-type: text/plain\n\n");
  fflush(fout);

  if (!(tsk = task_New())) goto cleanup;
  task_AddArg(tsk, state->global->diff_path);
  task_AddArg(tsk, "-u");
  task_AddArg(tsk, par1);
  task_AddArg(tsk, par2);
  task_SetPathAsArg0(tsk);
  task_ClearEnv(tsk);
  task_SetWorkingDir(tsk, state->global->diff_work_dir);
  task_SetRedir(tsk, 1, TSR_FILE, tmpfile3, O_WRONLY|O_CREAT|O_TRUNC, 0777);
  if (task_Start(tsk) < 0) goto cleanup;
  task_Wait(tsk);
  task_Delete(tsk);
  tsk = 0;

  if (generic_read_file(&diff_txt, 0, &diff_len, 0, 0, tmpfile3, 0) < 0) {
    goto cleanup;
  }

  if (fwrite(diff_txt, 1, diff_len, fout) != diff_len) {
    goto cleanup;
  }

  unlink(tmpfile1);
  unlink(tmpfile2);
  unlink(tmpfile3);
  return 0;

 cleanup:
  if (tsk) task_Delete(tsk);
  if (tmpfile1) unlink(tmpfile1);
  if (tmpfile2) unlink(tmpfile2);
  if (tmpfile3) unlink(tmpfile3);
  if (diff_txt) xfree(diff_txt);
  return errcode;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tpTask")
 * End:
 */
