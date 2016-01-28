/* -*- c -*- */

/* Copyright (C) 2000-2016 Alexander Chernov <cher@ejudge.ru> */

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

/*
 * This program compiles incoming source files and puts the resulting
 * executables into the spool directory.
 *
 * Note: this program must compile and work on win32
 */

#include "ejudge/config.h"
#include "ejudge/prepare.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/parsecfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/interrupt.h"
#include "ejudge/runlog.h"
#include "ejudge/compile_packet.h"
#include "ejudge/curtime.h"
#include "ejudge/serve_state.h"
#include "ejudge/startstop.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/compat.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/ej_libzip.h"
#include "ejudge/testinfo.h"
#include "ejudge/misctext.h"

#include "ejudge/meta_generic.h"
#include "ejudge/meta/compile_packet_meta.h"
#include "ejudge/meta/prepare_meta.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAX_LOG_SIZE = 1024 * 1024, MAX_EXE_SIZE = 128 * 1024 * 1024 };

struct serve_state serve_state;
static int initialize_mode = 0;

static int daemon_mode;
static int restart_mode;

static int
check_style_only(
        const struct section_global_data *global,
        struct compile_request_packet *req,
        struct compile_reply_packet *rpl,
        const unsigned char *pkt_name,
        const unsigned char *run_name,
        const unsigned char *work_run_name,
        const unsigned char *report_dir,
        const unsigned char *status_dir)
{
  void *reply_bin = 0;
  size_t reply_bin_size = 0;
  unsigned char msgbuf[1024] = { 0 };
  path_t log_path;
  path_t txt_path;
  path_t work_src_path;
  path_t work_log_path;
  int r, i;
  const unsigned char *src_sfx = "";
  tpTask tsk = 0;

  // input file: ${global->compile_src_dir}/${pkt_name}${req->src_sfx}
  // output log file: ${report_dir}/${run_name}
  // file listing: ${report_dir}/${run_name} (if OK status)
  // working directory: ${global->compile_work_dir}

  snprintf(log_path, sizeof(log_path), "%s/%s", report_dir, run_name);
  snprintf(txt_path, sizeof(txt_path), "%s/%s.txt", report_dir, run_name);
  if (req->src_sfx) src_sfx = req->src_sfx;
  snprintf(work_src_path, sizeof(work_src_path), "%s/%s%s",
           global->compile_work_dir, work_run_name, src_sfx);
  snprintf(work_log_path, sizeof(work_log_path), "%s/%s.log",
           global->compile_work_dir, work_run_name);

  r = generic_copy_file(REMOVE, global->compile_src_dir, pkt_name, src_sfx,
                        0, global->compile_work_dir, work_run_name, src_sfx);
  if (!r) {
    snprintf(msgbuf, sizeof(msgbuf), "The source file %s/%s%s is missing.\n",
             global->compile_src_dir, pkt_name, src_sfx);
    goto internal_error;
  }
  if (r < 0) {
    snprintf(msgbuf, sizeof(msgbuf),
             "Read error on the source file %s/%s%s is missing.\n",
             global->compile_src_dir, pkt_name, src_sfx);
    goto internal_error;
  }

  //info("Starting: %s %s", req->style_checker, work_src_path);
  tsk = task_New();
  task_AddArg(tsk, req->style_checker);
  task_AddArg(tsk, work_src_path);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, global->compile_work_dir);
  task_EnableProcessGroup(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, work_log_path, TSK_REWRITE, 0777);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  if (req->sc_env_num > 0) {
    for (i = 0; i < req->sc_env_num; i++)
      task_PutEnv(tsk, req->sc_env_vars[i]);
  }
  task_EnableAllSignals(tsk);

  task_PrintArgs(tsk);

  if (task_Start(tsk) < 0) {
    err("Failed to start style checker process");
    snprintf(msgbuf, sizeof(msgbuf), "Failed to start style checker %s\n",
             req->style_checker);
    goto internal_error;
  }

  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    err("Style checker process is timed out");
    snprintf(msgbuf, sizeof(msgbuf), "Style checker %s process timeout\n",
             req->style_checker);
    goto internal_error;
  }
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    err("Style checker invalid task status");
    snprintf(msgbuf, sizeof(msgbuf),
             "Style checker %s invalid task status %d\n",
             req->style_checker, r);
    goto internal_error;
  }
  if (r == TSK_SIGNALED) {
    err("Style checker terminated by signal");
    snprintf(msgbuf, sizeof(msgbuf),
             "Style checker %s terminated by signal %d\n",
             req->style_checker, task_TermSignal(tsk));
    goto internal_error;
  }
  r = task_ExitCode(tsk);
  if (r != 0 && r != RUN_COMPILE_ERR && r != RUN_PRESENTATION_ERR
      && r != RUN_WRONG_ANSWER_ERR && r != RUN_STYLE_ERR) {
    err("Invalid style checker exit code");
    snprintf(msgbuf, sizeof(msgbuf),
             "Style checker %s exit code %d\n",
             req->style_checker, r);
    goto internal_error;
  }
  if (r) {
    // style checker error
    rpl->status = RUN_STYLE_ERR;
    get_current_time(&rpl->ts3, &rpl->ts3_us);
    generic_copy_file(0, 0, work_log_path, "", 0, 0, log_path, "");
    generic_copy_file(0, 0, work_log_path, "", 0, 0, txt_path, "");
  } else {
    // success
    rpl->status = RUN_OK;
    get_current_time(&rpl->ts3, &rpl->ts3_us);
    generic_copy_file(0, 0, work_log_path, "", 0, 0, txt_path, "");
  }

  if (compile_reply_packet_write(rpl, &reply_bin_size, &reply_bin) < 0)
    goto cleanup;
  // ignore error: we cannot do anything anyway
  generic_write_file(reply_bin, reply_bin_size, SAFE, status_dir, run_name, 0);

cleanup:
  task_Delete(tsk); tsk = 0;
  xfree(reply_bin); reply_bin = 0;
  req = compile_request_packet_free(req);
  clear_directory(global->compile_work_dir);
  return 0;

internal_error:
  rpl->status = RUN_CHECK_FAILED;
  get_current_time(&rpl->ts3, &rpl->ts3_us);
  if (compile_reply_packet_write(rpl, &reply_bin_size, &reply_bin) < 0)
    goto cleanup;
  if (generic_write_file(msgbuf, strlen(msgbuf), 0, 0, log_path, 0) < 0)
    goto cleanup;
  if (generic_write_file(reply_bin, reply_bin_size, SAFE, status_dir,
                         run_name, 0) < 0) {
    unlink(log_path);
  }
  goto cleanup;
}

struct testinfo_subst_handler_compile
{
  struct testinfo_subst_handler b;
  const struct compile_request_packet *request;
  const struct section_language_data *lang;
};

static unsigned char *
subst_get_variable(
        const void *vp,
        const unsigned char *name)
{
  const struct testinfo_subst_handler_compile *phc = (const struct testinfo_subst_handler_compile *) vp;
  if (!strncmp(name, "request.", 8)) {
    return meta_get_variable_str(&meta_compile_request_packet_methods, phc->request, name + 8);
  } else if (!strncmp(name, "lang.", 5)) {
    return meta_get_variable_str(&cntslang_methods, phc->lang, name + 5);
  } else {
    return xstrdup("");
  }
}

static unsigned char *
testinfo_subst_handler_substitute(struct testinfo_subst_handler *bp, const unsigned char *str)
{
  return text_substitute(bp, str, subst_get_variable);
}

#define VALID_SIZE(z) ((z) > 0 && (z) == (size_t) (z))

static int
invoke_style_checker(
        FILE *log_f,
        const struct serve_state *cs,
        const struct section_language_data *lang,
        const struct compile_request_packet *req,
        const unsigned char *input_file,
        const unsigned char *working_dir,
        const unsigned char *log_path,
        const testinfo_t *tinf)
{
  tpTask tsk = 0;
  int retval = RUN_CHECK_FAILED;

  tsk = task_New();
  task_AddArg(tsk, req->style_checker);
  task_AddArg(tsk, input_file);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, working_dir);
  task_EnableProcessGroup(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, 0777);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  if (req->sc_env_num > 0) {
    for (int i = 0; i < req->sc_env_num; i++)
      task_PutEnv(tsk, req->sc_env_vars[i]);
  }
  if (tinf && tinf->style_checker_env_u > 0) {
    for (int i = 0; i < tinf->style_checker_env_u; ++i)
      task_PutEnv(tsk, tinf->style_checker_env_v[i]);
  }
  if (lang && lang->compile_real_time_limit > 0) {
    task_SetMaxRealTime(tsk, lang->compile_real_time_limit);
  }
  task_EnableAllSignals(tsk);

  task_PrintArgs(tsk);
  if (task_Start(tsk) < 0) {
    err("Failed to start style checker process");
    fprintf(log_f, "\nFailed to start style checker %s\n", req->style_checker);
    goto cleanup;
  }
  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    err("Style checker process is timed out");
    fprintf(log_f, "\nStyle checker %s process is timed out\n", req->style_checker);
    goto cleanup;
  }

  int r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    err("Style checker invalid task status");
    fprintf(log_f, "\nStyle checker %s invalid task status %d\n", req->style_checker, r);
    goto cleanup;
  }
  if (r == TSK_SIGNALED) {
    err("Style checker terminated by signal");
    fprintf(log_f, "\nStyle checker %s terminated by signal %d\n", req->style_checker, task_TermSignal(tsk));
    goto cleanup;
  }
  r = task_ExitCode(tsk);
  if (r != 0 && r != RUN_COMPILE_ERR && r != RUN_PRESENTATION_ERR && r != RUN_WRONG_ANSWER_ERR && r != RUN_STYLE_ERR) {
    err("Invalid style checker exit code");
    fprintf(log_f, "\nStyle checker %s invalid exit code %d\n", req->style_checker, r);
    goto cleanup;
  }
  fprintf(log_f, "\n");
  if (!r) {
    retval = RUN_OK;
  } else {
    retval = RUN_STYLE_ERR;
    fprintf(log_f, "\nStyle checker detected errors\n");
  }

cleanup:
  task_Delete(tsk);
  return retval;
}

static int
invoke_compiler(
        FILE *log_f,
        const struct serve_state *cs,
        const struct section_language_data *lang,
        const struct compile_request_packet *req,
        const unsigned char *input_file,
        const unsigned char *output_file,
        const unsigned char *working_dir,
        const unsigned char *log_path,
        const testinfo_t *tinf)
{
  const struct section_global_data *global = serve_state.global;
  tpTask tsk = 0;

  tsk = task_New();
  task_AddArg(tsk, lang->cmd);
  task_AddArg(tsk, input_file);
  task_AddArg(tsk, output_file);
  task_SetPathAsArg0(tsk);
  task_EnableProcessGroup(tsk);
  if (VALID_SIZE(req->max_vm_size)) {
    task_SetVMSize(tsk, req->max_vm_size);
  } else if (VALID_SIZE(lang->max_vm_size)) {
    task_SetVMSize(tsk, lang->max_vm_size);
  } else if (VALID_SIZE(global->compile_max_vm_size)) {
    task_SetVMSize(tsk, global->compile_max_vm_size);
  }
  if (VALID_SIZE(req->max_stack_size)) {
    task_SetStackSize(tsk, req->max_stack_size);
  } else if (VALID_SIZE(lang->max_stack_size)) {
    task_SetStackSize(tsk, lang->max_stack_size);
  } else if (VALID_SIZE(global->compile_max_stack_size)) {
    task_SetStackSize(tsk, global->compile_max_stack_size);
  }
  if (VALID_SIZE(req->max_file_size)) {
    task_SetMaxFileSize(tsk, req->max_file_size);
  } else if (VALID_SIZE(lang->max_file_size)) {
    task_SetMaxFileSize(tsk, lang->max_file_size);
  } else if (VALID_SIZE(global->compile_max_file_size)) {
    task_SetMaxFileSize(tsk, global->compile_max_file_size);
  }

  if (req->env_num > 0) {
    for (int i = 0; i < req->env_num; i++)
      task_PutEnv(tsk, req->env_vars[i]);
  }
  if (tinf && tinf->compiler_env_u > 0) {
    for (int i = 0; i < tinf->compiler_env_u; ++i)
      task_PutEnv(tsk, tinf->compiler_env_v[i]);
  }
  task_SetWorkingDir(tsk, working_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, 0777);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  if (lang->compile_real_time_limit > 0) {
    task_SetMaxRealTime(tsk, lang->compile_real_time_limit);
  }
  task_EnableAllSignals(tsk);

  task_PrintArgs(tsk);

  if (task_Start(tsk) < 0) {
    err("failed to start compiler '%s'", lang->cmd);
    fprintf(log_f, "\nFailed to start compiler '%s'\n", lang->cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Wait(tsk);

  if (task_IsTimeout(tsk)) {
    err("Compilation process timed out");
    fprintf(log_f, "\nCompilation process timed out\n");
    task_Delete(tsk);
    return RUN_COMPILE_ERR;
  } else if (task_IsAbnormal(tsk)) {
    info("Compilation failed");
    task_Delete(tsk);
    return RUN_COMPILE_ERR;
  } else {
    info("Compilation sucessful");
    task_Delete(tsk);
    return RUN_OK;
  }
}

static void
handle_packet(
        FILE *log_f,
        const struct serve_state *cs,
        const unsigned char *pkt_name,
        const struct compile_request_packet *req,
        struct compile_reply_packet *rpl,
        const struct section_language_data *lang,
        const unsigned char *run_name,            // the incoming packet name
        const unsigned char *src_path,            // path to the source file in the spool directory
        const unsigned char *exe_path,            // path to the resulting exe file in the spool directory
        const unsigned char *working_dir,         // the working directory
        const unsigned char *log_work_path,       // the path to the log file (open in APPEND mode)
        unsigned char *exe_work_name,             // OUTPUT: the name of the executable
        int *p_override_exe,
        int *p_exe_copied)
{
  struct ZipData *zf = NULL;

  if (req->output_only) {
    if (rename(src_path, exe_path) >= 0) {
      rpl->status = RUN_OK;
      goto cleanup;
    }
    if (errno != EXDEV) {
      fprintf(log_f, "cannot move '%s' -> '%s': %s\n", src_path, exe_path, strerror(errno));
      rpl->status = RUN_CHECK_FAILED;
      goto cleanup;
    }
    if (generic_copy_file(REMOVE, NULL, src_path, "", 0, NULL, exe_path, "") < 0) {
      fprintf(log_f, "cannot copy '%s' -> '%s'\n", src_path, exe_path);
      rpl->status = RUN_CHECK_FAILED;
      goto cleanup;
    }

    *p_exe_copied = 1;
    rpl->status = RUN_OK;
    goto cleanup;
  }

  if (!lang) {
    fprintf(log_f, "invalid language %d\n", req->lang_id);
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  unsigned char src_work_name[PATH_MAX];
  snprintf(src_work_name, sizeof(src_work_name), "%06d%s", req->run_id, lang->src_sfx);
  unsigned char src_work_path[PATH_MAX];
  snprintf(src_work_path, sizeof(src_work_path), "%s/%s", working_dir, src_work_name);

  if (rename(src_path, src_work_path) >= 0) {
  } else if (errno != EXDEV) {
    fprintf(stderr, "cannot move '%s' -> '%s': %s\n", src_path, src_work_path, strerror(errno));
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  } else {
    if (generic_copy_file(REMOVE, NULL, src_path, "", 0, NULL, src_work_path, "") < 0) {
      fprintf(log_f, "cannot copy '%s' -> '%s'\n", src_path, exe_path);
      rpl->status = RUN_CHECK_FAILED;
      goto cleanup;
    }
  }

  if (!req->multi_header) {
    snprintf(exe_work_name, PATH_MAX, "%06d%s", req->run_id, lang->exe_sfx);
    unsigned char exe_work_path[PATH_MAX];
    snprintf(exe_work_path, sizeof(exe_work_path), "%s/%s", working_dir, exe_work_name);

    if (req->style_checker && req->style_checker[0]) {
      int r = invoke_style_checker(log_f, cs, lang, req, src_work_name, working_dir, log_work_path, NULL);
      if (r != RUN_OK) {
        rpl->status = r;
        goto cleanup;
      }
      if (req->style_check_only) {
        rpl->status = RUN_OK;
        *p_override_exe = 1;
        goto cleanup;
      }
    }

    int r = invoke_compiler(log_f, cs, lang, req, src_work_name, exe_work_name, working_dir, log_work_path, NULL);
    rpl->status = r;
    goto cleanup;
  }

  // multi-header mode
  snprintf(exe_work_name, PATH_MAX, "%06d%s", req->run_id, lang->exe_sfx);
  unsigned char exe_work_path[PATH_MAX];
  snprintf(exe_work_path, sizeof(exe_work_path), "%s/%s", working_dir, exe_work_name);
  zf = ej_libzip_open(log_f, exe_work_path, O_CREAT | O_TRUNC | O_WRONLY);
  if (!zf) {
    fprintf(log_f, "cannot create zip archive '%s'\n", exe_work_path);
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  if (!req->header_dir || !req->header_dir[0]) {
    fprintf(log_f, "'header_dir' parameter is not specified\n");
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  }
  struct stat stb;
  if (stat(req->header_dir, &stb) < 0) {
    fprintf(log_f, "header_dir directory '%s' does not exist\n", req->header_dir);
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  }
  if (!S_ISDIR(stb.st_mode)) {
    fprintf(log_f, "header_dir '%s' is not directory\n", req->header_dir);
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  int serial = 0;
  int status = RUN_OK;
  while (1) {
    unsigned char header_base[PATH_MAX];
    unsigned char footer_base[PATH_MAX];
    unsigned char compiler_env_base[PATH_MAX];

    ++serial;
    header_base[0] = 0;
    footer_base[0] = 0;
    compiler_env_base[0] = 0;
    if (req->header_pat && req->header_pat[0]) {
      snprintf(header_base, sizeof(header_base), req->header_pat, serial);
    }
    if (req->footer_pat && req->footer_pat[0]) {
      snprintf(footer_base, sizeof(footer_base), req->footer_pat, serial);
    }
    if (req->compiler_env_pat && req->compiler_env_pat[0]) {
      snprintf(compiler_env_base, sizeof(compiler_env_base), req->compiler_env_pat, serial);
    }

    unsigned char header_path[PATH_MAX];
    unsigned char footer_path[PATH_MAX];
    unsigned char compiler_env_path[PATH_MAX];
    header_path[0] = 0;
    footer_path[0] = 0;
    compiler_env_path[0] = 0;

    if (header_base[0]) {
      if (req->lang_header) {
        snprintf(header_path, sizeof(header_path), "%s/%s.%s%s", req->header_dir, header_base, lang->short_name, lang->src_sfx);
      } else {
        snprintf(header_path, sizeof(header_path), "%s/%s%s", req->header_dir, header_base, lang->src_sfx);
      }
    }
    if (footer_base[0]) {
      if (req->lang_header) {
        snprintf(footer_path, sizeof(footer_path), "%s/%s.%s%s", req->header_dir, footer_base, lang->short_name, lang->src_sfx);
      } else {
        snprintf(footer_path, sizeof(footer_path), "%s/%s%s", req->header_dir, footer_base, lang->src_sfx);
      }
    }
    if (compiler_env_base[0]) {
      if (req->lang_header) {
        snprintf(compiler_env_path, sizeof(compiler_env_path), "%s/%s.%s", req->header_dir, compiler_env_base, lang->short_name);
      } else {
        snprintf(compiler_env_path, sizeof(compiler_env_path), "%s/%s", req->header_dir, compiler_env_base);
      }
    }

    int header_exists = (header_path[0] && access(header_path, R_OK) >= 0);
    int footer_exists = (footer_path[0] && access(footer_path, R_OK) >= 0);
    int env_exists = (compiler_env_path[0] && access(compiler_env_path, R_OK) >= 0);
    if (!header_exists && !footer_exists && !env_exists) {
      if (serial == 1) {
        fprintf(log_f, "no test-specific header, footer, or compiler_env file found\n");
        status = RUN_CHECK_FAILED;
      }
      break;
    }

    testinfo_t test_info;
    memset(&test_info, 0, sizeof(test_info));
    testinfo_t *tinf = NULL;

    if (compiler_env_path[0]) {
      struct testinfo_subst_handler_compile hc;
      memset(&hc, 0, sizeof(hc));
      hc.b.substitute = testinfo_subst_handler_substitute;
      hc.request = req;
      hc.lang = lang;

      if (stat(compiler_env_path, &stb) < 0) {
        fprintf(log_f, "compiler env file '%s' does not exist: %s\n", compiler_env_path, strerror(errno));
        status = RUN_CHECK_FAILED;
        continue;
      } else if (!S_ISREG(stb.st_mode)) {
        fprintf(log_f, "compiler env file '%s' is not regular\n", compiler_env_path);
        status = RUN_CHECK_FAILED;
        continue;
      } else if (access(compiler_env_path, R_OK) < 0) {
        fprintf(log_f, "compiler env file '%s' is not readable: %s\n", compiler_env_path, strerror(errno));
        status = RUN_CHECK_FAILED;
        continue;
      } else if (testinfo_parse(compiler_env_path, &test_info, &hc.b) < 0) {
        fprintf(log_f, "invalid env file '%s'\n", compiler_env_path);
        status = RUN_CHECK_FAILED;
        continue;
      } else {
        tinf = &test_info;
      }
    }

    int file_check_failed = 0;
    char *header_s = NULL, *footer_s = NULL;
    size_t header_z = 0, footer_z = 0;
    if (header_path[0]) {
      if (stat(header_path, &stb) < 0) {
        fprintf(log_f, "header file '%s' does not exist: %s\n", header_path, strerror(errno));
        file_check_failed = 1;
      } else if (!S_ISREG(stb.st_mode)) {
        fprintf(log_f, "header file '%s' is not regular\n", header_path);
        file_check_failed = 1;
      } else if (access(header_path, R_OK) < 0) {
        fprintf(log_f, "header file '%s' is not readable: %s\n", header_path, strerror(errno));
        file_check_failed = 1;
      } else if (generic_read_file(&header_s, 0, &header_z, 0, NULL, header_path, "") < 0) {
        fprintf(log_f, "failed to read file '%s'\n", header_path);
        file_check_failed = 1;
      }
    }
    if (footer_path[0]) {
      if (stat(footer_path, &stb) < 0) {
        fprintf(log_f, "footer file '%s' does not exist: %s\n", footer_path, strerror(errno));
        file_check_failed = 1;
      } else if (!S_ISREG(stb.st_mode)) {
        fprintf(log_f, "footer file '%s' is not regular\n", footer_path);
        file_check_failed = 1;
      } else if (access(footer_path, R_OK) < 0) {
        fprintf(log_f, "footer file '%s' is not readable: %s\n", footer_path, strerror(errno));
        file_check_failed = 1;
      } else if (generic_read_file(&footer_s, 0, &footer_z, 0, NULL, footer_path, "") < 0) {
        fprintf(log_f, "failed to read file '%s'\n", footer_path);
        file_check_failed = 1;
      }
    }
    if (file_check_failed) {
      testinfo_free(tinf);
      xfree(header_s);
      xfree(footer_s);
      status = RUN_CHECK_FAILED;
      continue;
    }

    char *src_s = NULL;
    size_t src_z = 0;
    if (generic_read_file(&src_s, 0, &src_z, 0, NULL, src_work_path, "") < 0) {
      fprintf(log_f, "failed to read source file '%s'\n", src_work_path);
      testinfo_free(tinf);
      xfree(header_s);
      xfree(footer_s);
      status = RUN_CHECK_FAILED;
      continue;
    }

    size_t full_z = header_z + src_z + footer_z;
    char *full_s = xmalloc(full_z + 1);
    if (header_s && header_z > 0) {
      memcpy(full_s, header_s, header_z);
    }
    memcpy(full_s + header_z, src_s, src_z);
    if (footer_s && footer_z > 0) {
      memcpy(full_s + header_z + src_z, footer_s, footer_z);
    }
    full_s[full_z] = 0;
    xfree(header_s); header_s = NULL; header_z = 0;
    xfree(footer_s); footer_s = NULL; footer_z = 0;

    unsigned char test_src_name[PATH_MAX];
    snprintf(test_src_name, sizeof(test_src_name), "%06d_%03d%s", req->run_id, serial, lang->src_sfx);
    unsigned char test_src_path[PATH_MAX];
    snprintf(test_src_path, sizeof(test_src_path), "%s/%s", working_dir, test_src_name);
    if (generic_write_file(full_s, full_z, 0, NULL, test_src_path, NULL) < 0) {
      fprintf(log_f, "failed to write full source file '%s'\n", test_src_path);
      testinfo_free(tinf);
      xfree(full_s);
      status = RUN_CHECK_FAILED;
      continue;
    }
    xfree(full_s); full_s = NULL; full_z = 0;

    unsigned char test_exe_name[PATH_MAX];
    snprintf(test_exe_name, sizeof(test_exe_name), "%06d_%03d%s", req->run_id, serial, lang->exe_sfx);
    unsigned char test_exe_path[PATH_MAX];
    snprintf(test_exe_path, sizeof(test_exe_path), "%s/%s", working_dir, test_exe_name);

    int cur_status = RUN_OK;
    if (req->style_checker && req->style_checker[0]) {
      cur_status = invoke_style_checker(log_f, cs, lang, req, test_src_name, working_dir, log_work_path, tinf);
      // valid statuses: RUN_OK, RUN_STYLE_ERR, RUN_CHECK_FAILED
      if (cur_status == RUN_CHECK_FAILED) {
        status = RUN_CHECK_FAILED;
      } else if (cur_status == RUN_STYLE_ERR) {
        if (status == RUN_OK) {
          status = RUN_STYLE_ERR;
        }
      } else if (cur_status != RUN_OK) {
        fprintf(log_f, "invalid status %d returned from invoke_style_checker\n", cur_status);
        status = RUN_CHECK_FAILED;
      }
    }
    if (cur_status == RUN_OK) {
      cur_status = invoke_compiler(log_f, cs, lang, req, test_src_name, test_exe_name, working_dir, log_work_path, tinf);
      // valid statuses: RUN_OK, RUN_COMPILE_ERR, RUN_CHECK_FAILED
      if (cur_status == RUN_CHECK_FAILED) {
        status = RUN_CHECK_FAILED;
      } else if (cur_status == RUN_COMPILE_ERR) {
        if (status == RUN_OK || status == RUN_STYLE_ERR) { 
          status = RUN_COMPILE_ERR;
        }
      } else if (cur_status != RUN_OK) {
        fprintf(log_f, "invalid status %d returned from invoke_compiler\n", cur_status);
        status = RUN_CHECK_FAILED;
      } else {
        // OK
        if (lstat(test_exe_path, &stb) < 0) {
          fprintf(log_f, "output file '%s' does not exist: %s\n", test_exe_path, strerror(errno));
          status = RUN_CHECK_FAILED;
        } else if (!S_ISREG(stb.st_mode)) {
          fprintf(log_f, "output file '%s' is not regular\n", test_exe_path);
          status = RUN_CHECK_FAILED;
        } else if (access(test_exe_path, X_OK) < 0) {
          fprintf(log_f, "output file '%s' is not executable: %s\n", test_exe_path, strerror(errno));
          status = RUN_CHECK_FAILED;
        } else {
          if (zf->ops->add_file(zf, test_exe_name, test_exe_path) < 0) {
            fprintf(log_f, "cannot add file '%s' to zip archive\n", test_exe_path);
            status = RUN_CHECK_FAILED;
          }
        }
      }
    }
  }

  rpl->status = status;
  rpl->zip_mode = 1;

cleanup:
  if (zf) zf->ops->close(zf);
  return;
}

static int new_loop(void) __attribute__((unused));

static int
new_loop(void)
{
  int retval = 0;
  const struct section_global_data *global = serve_state.global;
  int override_exe = 0;
  int exe_copied = 0;

  interrupt_init();
  interrupt_disable();

  while (1) {
    // terminate if signaled
    if (interrupt_get_status() || interrupt_restart_requested()) break;

    unsigned char pkt_name[PATH_MAX];
    pkt_name[0] = 0;
    int r = scan_dir(global->compile_queue_dir, pkt_name, sizeof(pkt_name), 0);

    if (r < 0) {
      switch (-r) {
      case ENOMEM:
      case ENOENT:
      case ENFILE:
        err("trying to recover, sleep for 5 seconds");
        interrupt_enable();
        os_Sleep(5000);
        interrupt_disable();
        continue;
      default:
        err("unrecoverable error, exiting");
        return -1;
      }
    }

    if (!r) {
      interrupt_enable();
      os_Sleep(global->sleep_time);
      interrupt_disable();
      continue;
    }

    char *pkt_ptr = NULL;
    size_t pkt_len = 0;
    r = generic_read_file(&pkt_ptr, 0, &pkt_len, SAFE | REMOVE, global->compile_queue_dir, pkt_name, "");
    if (r == 0) continue;
    if (r < 0 || !pkt_ptr) {
      // it looks like there's no reasonable recovery strategy
      // so, just ignore the error
      continue;
    }

    struct compile_request_packet *req = NULL;
    r = compile_request_packet_read(pkt_len, pkt_ptr, &req);
    xfree(pkt_ptr); pkt_ptr = NULL;
    if (r < 0) {
      continue;
    }

    if (!req->contest_id) {
      // special packets
      r = req->lang_id;
      req = compile_request_packet_free(req);
      switch (r) {
      case 1:
        interrupt_flag_interrupt();
        break;
      case 2:
        interrupt_flag_sighup();
        break;
      }
      continue;
    }

    struct compile_reply_packet rpl;
    memset(&rpl, 0, sizeof(rpl));
    rpl.judge_id = req->judge_id;
    rpl.contest_id = req->contest_id;
    rpl.run_id = req->run_id;
    rpl.ts1 = req->ts1;
    rpl.ts1_us = req->ts1_us;
    rpl.use_uuid = req->use_uuid;
    rpl.uuid = req->uuid;
    get_current_time(&rpl.ts2, &rpl.ts2_us);
    rpl.run_block_len = req->run_block_len;
    rpl.run_block = req->run_block; /* !!! shares memory with req */

    unsigned char status_dir[PATH_MAX];
    snprintf(status_dir, sizeof(status_dir), "%s/%06d/status", global->compile_dir, rpl.contest_id);
    if (make_all_dir(status_dir, 0777) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      continue;
    }

    unsigned char run_name[PATH_MAX];
    if (req->use_uuid > 0) {
      snprintf(run_name, sizeof(run_name), "%s", ej_uuid_unparse(&req->uuid, NULL));
    } else {
      snprintf(run_name, sizeof(run_name), "%06d", rpl.run_id);
    }

    unsigned char report_dir[PATH_MAX];
    snprintf(report_dir, sizeof(report_dir), "%s/%06d/report", global->compile_dir, rpl.contest_id);
    if (make_dir(report_dir, 0777) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      continue;
    }

    unsigned char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/%s.txt", report_dir, run_name);
    unlink(log_path);

    unsigned char exe_work_name[PATH_MAX];
    exe_work_name[0] = 0;

    unsigned char log_work_name[PATH_MAX];
    snprintf(log_work_name, sizeof(log_work_name), "log_%06d.txt", req->run_id);
    unsigned char log_work_path[PATH_MAX];
    snprintf(log_work_path, sizeof(log_work_path), "%s/%s", global->compile_work_dir, log_work_name);
    unlink(log_work_path);
    FILE *log_f = fopen(log_work_path, "a");
    if (!log_f) {
      err("cannot open log file '%s': %s", log_work_path, strerror(errno));
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      continue;
    }

    const struct section_language_data *lang = NULL;
    if (req->lang_id) {
      if (req->lang_id <= 0 || req->lang_id > serve_state.max_lang || !(lang = serve_state.langs[req->lang_id])) {
        fprintf(log_f, "invalid language id %d passed from ej-contest\n", req->lang_id);
      }
    }

    unsigned char exe_path[PATH_MAX];
    const unsigned char *exe_sfx = "";
    if (lang && lang->exe_sfx) exe_sfx = lang->exe_sfx;
    snprintf(exe_path, sizeof(exe_path), "%s/%s%s", report_dir, run_name, exe_sfx);
    unlink(exe_path);

    unsigned char src_path[PATH_MAX];
    snprintf(src_path, sizeof(src_path), "%s/%s%s", global->compile_src_dir, pkt_name, req->src_sfx);

    override_exe = 0;
    exe_copied = 0;
    handle_packet(log_f, &serve_state, pkt_name, req, &rpl,
                  lang,
                  run_name,
                  src_path,
                  exe_path,
                  global->compile_work_dir,
                  log_work_path,
                  exe_work_name,
                  &override_exe,
                  &exe_copied);

    get_current_time(&rpl.ts3, &rpl.ts3_us);

    if (rpl.status == RUN_OK && !override_exe && !exe_copied) {
      if (!exe_work_name[0]) {
        err("the resulting executable name is empty");
        fprintf(log_f, "\ncompiler output file is empty\n");
        rpl.status = RUN_CHECK_FAILED;
      } else {
        unsigned char exe_work_path[PATH_MAX];
        snprintf(exe_work_path, sizeof(exe_work_path), "%s/%s", global->compile_work_dir, exe_work_name);
        struct stat stb;

        if (lstat(exe_work_path, &stb) < 0) {
          err("the resulting executable '%s' does not exist", exe_work_path);
          fprintf(log_f, "\ncompiler output file '%s' does not exist\n", exe_work_path);
          rpl.status = RUN_COMPILE_ERR;
        } else {
          if (!S_ISREG(stb.st_mode)) {
            err("the resulting executable '%s' is not a regular file", exe_work_path);
            fprintf(log_f, "\ncompiler output file '%s' is not a regular file\n", exe_work_path);
            rpl.status = RUN_CHECK_FAILED;
          } else if (stb.st_size > MAX_EXE_SIZE) {
            err("the resulting executable '%s' is too large (size = %lld)", exe_work_path, (long long) stb.st_size);
            fprintf(log_f, "\ncompiler output file '%s' is too large\n (size = %lld)", exe_work_path, (long long) stb.st_size);
            rpl.status = RUN_COMPILE_ERR;
          } else {
            if (rename(exe_work_path, exe_path) >= 0) {
              // good!
            } else if (errno != EXDEV) {
              int e = errno;
              err("rename %s -> %s failed: %s", exe_work_path, exe_path, strerror(e));
              fprintf(log_f, "\nrename %s -> %s failed: %s\n", exe_work_path, exe_path, strerror(e));
              rpl.status = RUN_CHECK_FAILED;
            } else {
              if (generic_copy_file(0, NULL, exe_work_path, "", 0, NULL, exe_path, "") < 0) {
                fprintf(log_f, "\ncopy %s -> %s failed\n", exe_work_path, exe_path);
                rpl.status = RUN_CHECK_FAILED;
              }
            }
          }
        }
      }
    }

    fclose(log_f); log_f = NULL;

    r = generic_copy_file(0, NULL, log_work_path, "", 0, NULL, log_path, "");
    if (r < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      clear_directory(global->compile_work_dir);
      unlink(exe_path);
      unlink(log_path);
      continue;
    }

    if (override_exe || (rpl.status == RUN_STYLE_ERR || rpl.status == RUN_COMPILE_ERR || rpl.status == RUN_CHECK_FAILED)) {
      generic_copy_file(0, NULL, log_work_path, "", 0, NULL, exe_path, "");
    }

    void *rpl_pkt = NULL;
    size_t rpl_size = 0;
    if (compile_reply_packet_write(&rpl, &rpl_size, &rpl_pkt) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      clear_directory(global->compile_work_dir);
      unlink(exe_path);
      unlink(log_path);
      continue;
    }
    if (generic_write_file(rpl_pkt, rpl_size, SAFE, status_dir, run_name, 0) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      xfree(rpl_pkt);
      clear_directory(global->compile_work_dir);
      unlink(exe_path);
      unlink(log_path);
      continue;
    }

    // all good
    rpl.run_block = NULL;
    compile_request_packet_free(req);
    xfree(rpl_pkt);
    clear_directory(global->compile_work_dir);
  }

  return retval;
}

static int do_loop(void) __attribute__((unused));

static int
do_loop(void)
{
  path_t src_name;
  path_t exe_name;

  path_t src_path;
  path_t exe_path;
  path_t log_path;

  path_t exe_out;
  path_t log_out;
  path_t txt_out;
  path_t report_dir, status_dir;

  path_t  pkt_name, run_name, work_run_name;
  char   *pkt_ptr;
  size_t  pkt_len;
  int    r, i;
  tpTask tsk = 0;
  unsigned char msgbuf[512];
  int ce_flag;
  struct compile_request_packet *req = 0;
  struct compile_reply_packet rpl;
  void *rpl_pkt = 0;
  size_t rpl_size = 0;
  const unsigned char *tail_message = 0;
#if HAVE_TRUNCATE - 0
  struct stat stb;
#endif /* HAVE_TRUNCATE */
  FILE *log_f = 0;
  struct section_language_data *lang = 0;
  const struct section_global_data *global = serve_state.global;

  // if (cr_serialize_init(&serve_state) < 0) return -1;
  interrupt_init();
  interrupt_disable();

  while (1) {
    // terminate if signaled
    if (interrupt_get_status() || interrupt_restart_requested()) break;

    r = scan_dir(global->compile_queue_dir, pkt_name, sizeof(pkt_name), 0);

    if (r < 0) {
      switch (-r) {
      case ENOMEM:
      case ENOENT:
      case ENFILE:
        err("trying to recover, sleep for 5 seconds");
        interrupt_enable();
        os_Sleep(5000);
        interrupt_disable();
        continue;
      default:
        err("unrecoverable error, exiting");
        return -1;
      }
    }

    if (!r) {
      interrupt_enable();
      os_Sleep(global->sleep_time);
      interrupt_disable();
      continue;
    }

    pkt_ptr = 0;
    pkt_len = 0;
    r = generic_read_file(&pkt_ptr, 0, &pkt_len, SAFE | REMOVE,
                          global->compile_queue_dir, pkt_name, "");
    if (r == 0) continue;
    if (r < 0 || !pkt_ptr) {
      // it looks like there's no reasonable recovery strategy
      // so, just ignore the error
      continue;
    }

    r = compile_request_packet_read(pkt_len, pkt_ptr, &req);
    xfree(pkt_ptr); pkt_ptr = 0;
    if (r < 0) {
      /*
       * the incoming packet is completely broken, so just drop it
       */
      goto cleanup_and_continue;
    }

    if (!req->contest_id) {
      // special packets
      r = req->lang_id;
      req = compile_request_packet_free(req);
      switch (r) {
      case 1:
        interrupt_flag_interrupt();
        break;
      case 2:
        interrupt_flag_sighup();
        break;
      }
      continue;
    }

    memset(&rpl, 0, sizeof(rpl));
    rpl.judge_id = req->judge_id;
    rpl.contest_id = req->contest_id;
    rpl.run_id = req->run_id;
    rpl.ts1 = req->ts1;
    rpl.ts1_us = req->ts1_us;
    rpl.use_uuid = req->use_uuid;
    rpl.uuid = req->uuid;
    get_current_time(&rpl.ts2, &rpl.ts2_us);
    rpl.run_block_len = req->run_block_len;
    rpl.run_block = req->run_block; /* !!! shares memory with req */
    msgbuf[0] = 0;

    /* prepare paths useful to report messages to the serve */
    snprintf(report_dir, sizeof(report_dir),
             "%s/%06d/report", global->compile_dir, rpl.contest_id);
    snprintf(status_dir, sizeof(status_dir),
             "%s/%06d/status", global->compile_dir, rpl.contest_id);
    if (req->use_uuid > 0) {
      snprintf(run_name, sizeof(run_name), "%s", ej_uuid_unparse(&req->uuid, NULL));
    } else {
      snprintf(run_name, sizeof(run_name), "%06d", rpl.run_id);
    }
    snprintf(work_run_name, sizeof(work_run_name), "%06d", rpl.run_id);
    pathmake(log_out, report_dir, "/", run_name, NULL);
    snprintf(txt_out, sizeof(txt_out), "%s/%s.txt", report_dir, run_name);

    make_all_dir(status_dir, 0777);
    make_dir(report_dir, 0777);

    if (!r) {
      /*
       * there is something wrong, but we have contest_id, judge_id
       * and run_id in place, so we can report an error back
       * to serve
       */
      snprintf(msgbuf, sizeof(msgbuf), "invalid compile packet\n");
      goto report_internal_error;
    }

    if (req->style_check_only && req->style_checker && req->style_checker[0]) {
      check_style_only(global, req, &rpl, pkt_name, run_name, work_run_name,
                       report_dir, status_dir);
      req = 0;
      continue;
    }

    if (req->lang_id <= 0 || req->lang_id > serve_state.max_lang
        || !(lang = serve_state.langs[req->lang_id])) {
      snprintf(msgbuf, sizeof(msgbuf), "invalid lang_id %d\n", req->lang_id);
      goto report_internal_error;
    }
    pathmake(src_name, work_run_name, lang->src_sfx, NULL);
    pathmake(exe_name, work_run_name, lang->exe_sfx, NULL);

    pathmake(src_path, global->compile_work_dir, "/", src_name, NULL);
    pathmake(exe_path, global->compile_work_dir, "/", exe_name, NULL);
    pathmake(log_path, global->compile_work_dir, "/", "log", NULL);
    /* the resulting executable file */
    snprintf(exe_out, sizeof(exe_out), "%s/%s%s", report_dir, run_name, lang->exe_sfx);

    /* move the source file into the working dir */
    r = generic_copy_file(REMOVE, global->compile_src_dir, pkt_name,
                          lang->src_sfx,
                          0, global->compile_work_dir, src_name, "");
    if (!r) {
      snprintf(msgbuf, sizeof(msgbuf), "the source file is missing\n");
      err("the source file is missing");
      goto report_internal_error;
    }
    if (r < 0) {
      snprintf(msgbuf, sizeof(msgbuf), "error reading the source file\n");
      err("cannot read the source file");
      goto report_internal_error;
    }

    tail_message = 0;
    ce_flag = 0;

    if (req->output_only) {
      // copy src_path -> exe_path
      generic_copy_file(0, NULL, src_path, NULL, 0, NULL, exe_path, NULL);
      ce_flag = 0;
      rpl.status = RUN_OK;
    } else {
      if (req->style_checker) {
        /* run style checker */
        //info("Starting: %s %s", req->style_checker, src_path);
        tsk = task_New();
        task_AddArg(tsk, req->style_checker);
        task_AddArg(tsk, src_path);
        task_SetPathAsArg0(tsk);
        task_SetWorkingDir(tsk, global->compile_work_dir);
        task_EnableProcessGroup(tsk);
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
        task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_REWRITE, 0777);
        task_SetRedir(tsk, 2, TSR_DUP, 1);
        if (req->sc_env_num > 0) {
          for (i = 0; i < req->sc_env_num; i++)
            task_PutEnv(tsk, req->sc_env_vars[i]);
        }
        if (lang->compile_real_time_limit > 0) {
          task_SetMaxRealTime(tsk, lang->compile_real_time_limit);
        }
        task_EnableAllSignals(tsk);

        task_PrintArgs(tsk);

        if (task_Start(tsk) < 0) {
          err("Failed to start style checker process");
          tail_message = "\n\nFailed to start style checker";
          ce_flag = 1;
          rpl.status = RUN_STYLE_ERR;
        } else {
          task_Wait(tsk);
          if (task_IsTimeout(tsk)) {
            err("Style checker process timed out");
            tail_message = "\n\nStyle checker process timed out";
            ce_flag = 1;
            rpl.status = RUN_STYLE_ERR;
          } else if (task_IsAbnormal(tsk)) {
            info("Style checker failed");
            ce_flag = 1;
            rpl.status = RUN_STYLE_ERR;
          } else {
            info("Style checker sucessful");
            ce_flag = 0;
            rpl.status = RUN_OK;
          }
        }
        task_Delete(tsk); tsk = 0;
      }

      if (!ce_flag) {
        //info("Starting: %s %s %s", lang->cmd, src_name, exe_name);
        tsk = task_New();
        task_AddArg(tsk, lang->cmd);
        task_AddArg(tsk, src_name);
        task_AddArg(tsk, exe_name);
        task_SetPathAsArg0(tsk);
        task_EnableProcessGroup(tsk);
        if (VALID_SIZE(req->max_vm_size)) {
          task_SetVMSize(tsk, req->max_vm_size);
        } else if (VALID_SIZE(lang->max_vm_size)) {
          task_SetVMSize(tsk, lang->max_vm_size);
        } else if (VALID_SIZE(global->compile_max_vm_size)) {
          task_SetVMSize(tsk, global->compile_max_vm_size);
        }
        if (VALID_SIZE(req->max_stack_size)) {
          task_SetStackSize(tsk, req->max_stack_size);
        } else if (VALID_SIZE(lang->max_stack_size)) {
          task_SetStackSize(tsk, lang->max_stack_size);
        } else if (VALID_SIZE(global->compile_max_stack_size)) {
          task_SetStackSize(tsk, global->compile_max_stack_size);
        }
        if (VALID_SIZE(req->max_file_size)) {
          task_SetMaxFileSize(tsk, req->max_file_size);
        } else if (VALID_SIZE(lang->max_file_size)) {
          task_SetMaxFileSize(tsk, lang->max_file_size);
        } else if (VALID_SIZE(global->compile_max_file_size)) {
          task_SetMaxFileSize(tsk, global->compile_max_file_size);
        }

        if (req->env_num > 0) {
          for (i = 0; i < req->env_num; i++)
            task_PutEnv(tsk, req->env_vars[i]);
        }
        task_SetWorkingDir(tsk, global->compile_work_dir);
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
        task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, 0777);
        task_SetRedir(tsk, 2, TSR_DUP, 1);
        if (lang->compile_real_time_limit > 0) {
          task_SetMaxRealTime(tsk, lang->compile_real_time_limit);
        }
        task_EnableAllSignals(tsk);
        
        /*
        if (cr_serialize_lock(&serve_state) < 0) {
          // FIXME: propose reasonable recovery?
          return -1;
        }
        */

        task_PrintArgs(tsk);
        task_Start(tsk);
        task_Wait(tsk);

        /*
        if (cr_serialize_unlock(&serve_state) < 0) {
          // FIXME: propose reasonable recovery?
          return -1;
        }
        */

        if (task_IsTimeout(tsk)) {
          err("Compilation process timed out");
          tail_message = "\n\nCompilation process timed out";
          ce_flag = 1;
          rpl.status = RUN_COMPILE_ERR;
        } else if (task_IsAbnormal(tsk)) {
          info("Compilation failed");
          ce_flag = 1;
          rpl.status = RUN_COMPILE_ERR;
        } else {
          info("Compilation sucessful");
          ce_flag = 0;
          rpl.status = RUN_OK;
        }
      }
    }

    get_current_time(&rpl.ts3, &rpl.ts3_us);
    if (compile_reply_packet_write(&rpl, &rpl_size, &rpl_pkt) < 0)
      goto cleanup_and_continue;

    while (1) {
      if (ce_flag) {
#if HAVE_TRUNCATE - 0
        // truncate log file at size 1MB
        if (stat(log_path, &stb) >= 0 && stb.st_size > MAX_LOG_SIZE) {
          truncate(log_path, MAX_LOG_SIZE);
          if ((log_f = fopen(log_path, "a"))) {
            fprintf(log_f, "\n\nCompilation log is truncated by ejudge!\n");
            fclose(log_f); log_f = 0;
          }
        }
#endif
        // append tail_message
        if (tail_message && (log_f = fopen(log_path, "a"))) {
          fprintf(log_f, "%s\n", tail_message);
          fclose(log_f); log_f = 0;
        }
        r = generic_copy_file(0, 0, log_path, "", 0, 0, log_out, "");
      } else {
        r = generic_copy_file(0, 0, exe_path, "", 0, 0, exe_out, "");
        generic_copy_file(0, 0, log_path, "", 0, 0, txt_out, "");
      }
      if (r >= 0 && generic_write_file(rpl_pkt, rpl_size, SAFE,
                                       status_dir, run_name, "") >= 0)
        break;

      info("waiting 5 seconds hoping for things to change");
      interrupt_enable();
      os_Sleep(5000);
      interrupt_disable();
    }
    goto cleanup_and_continue;

  report_internal_error:;
    rpl.status = RUN_CHECK_FAILED;
    get_current_time(&rpl.ts3, &rpl.ts3_us);
    if (compile_reply_packet_write(&rpl, &rpl_size, &rpl_pkt) < 0)
      goto cleanup_and_continue;
    if (generic_write_file(msgbuf, strlen(msgbuf), 0, 0, log_out, 0) < 0)
      goto cleanup_and_continue;
    if (generic_write_file(rpl_pkt, rpl_size, SAFE, status_dir, run_name, 0) < 0)
      unlink(log_out);
    goto cleanup_and_continue;

  cleanup_and_continue:;
    task_Delete(tsk); tsk = 0;
    clear_directory(global->compile_work_dir);
    xfree(rpl_pkt); rpl_pkt = 0;
    req = compile_request_packet_free(req);
  } /* while (1) */

  return 0;
}

static int
filter_languages(char *key)
{
  int i, total = 0;
  const struct section_language_data *lang = 0;

  for (i = 1; i <= serve_state.max_lang; i++) {
    if (!(lang = serve_state.langs[i])) continue;
    if (lang->disabled_by_config > 0) {
      serve_state.langs[i] = 0;
    } else if (strcmp(lang->key, key)) {
      serve_state.langs[i] = 0;
    }
  }

  for (i = 1; i <= serve_state.max_lang; i++) {
    total += serve_state.langs[i] != 0;
  }
  /*
  if (!total) {
    err("No languages after filter %s", key);
    return -1;
  }
  */
  return 0;
}

static int
check_config(void)
{
  int i;
  int total = 0;

  if (check_writable_spool(serve_state.global->compile_queue_dir, SPOOL_OUT) < 0)
    return -1;
  for (i = 1; i <= serve_state.max_lang; i++) {
    if (!serve_state.langs[i]) continue;

    /* script must exist and be executable */
    total++;
    if (check_executable(serve_state.langs[i]->cmd) < 0) return -1;
  }

  /*
  if (!total) {
    err("no languages");
    return -1;
  }
  */
  return 0;
}

int
main(int argc, char *argv[])
{
  int     i = 1, j = 0;
  char   *key = 0;
  path_t  cpp_opts = {0};
  int     code = 0;
  int     prepare_flags = 0;
  unsigned char *user = 0, *group = 0, *workdir = 0;

#if HAVE_SETSID - 0
  path_t  log_path;
#endif /* HAVE_SETSID */

  int pid = -1;
  char **argv_restart = 0;
  unsigned char *ejudge_xml_path = 0;
  unsigned char *compile_cfg_path = 0;
  path_t compile_cfg_buf = { 0 };
  path_t contests_home_dir = { 0 };
  path_t compile_home_dir = { 0 };

#if HAVE_OPEN_MEMSTREAM - 0
  FILE *lang_log_f = 0;
  char *lang_log_t = 0;
  size_t lang_log_z = 0;
#endif /* HAVE_OPEN_MEMSTREAM */

  path_t tmp_path;
  int tmp_len;

#if defined __WIN32__
  path_t tmp_dir = { 0 };
  path_t std_compile_home_dir = { 0 };
#endif

  enum { SUBST_SIZE = 16 };
  const unsigned char *subst_src[SUBST_SIZE];
  const unsigned char *subst_dst[SUBST_SIZE];
  const unsigned char **subst_src_ptr = 0;
  const unsigned char **subst_dst_ptr = 0;

  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 2);
  argv_restart[j++] = argv[0];

  //if (argc == 1) goto print_usage;
  code = 1;

  while (i < argc) {
    if (!strcmp(argv[i], "-i")) {
      initialize_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-k")) {
      if (++i >= argc) goto print_usage;
      argv_restart[j++] = argv[i];
      key = argv[i++];
    } else if (!strcmp(argv[i], "-D")) {
      daemon_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-R")) {
      restart_mode = 1;
      i++;
    } else if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      argv_restart[j++] = argv[i];
      pathcat(cpp_opts, argv[i++]);
    } else if (!strcmp(argv[i], "-u")) {
      if (++i >= argc) goto print_usage;
      user = argv[i++];
    } else if (!strcmp(argv[i], "-g")) {
      if (++i >= argc) goto print_usage;
      group = argv[i++];
    } else if (!strcmp(argv[i], "-C")) {
      if (++i >= argc) goto print_usage;
      workdir = argv[i++];
    } else if (!strcmp(argv[i], "-d")) {
      daemon_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-r")) {
      if (++i >= argc) goto print_usage;
      snprintf(contests_home_dir, sizeof(contests_home_dir), "%s", argv[i++]);
    } else if (!strcmp(argv[i], "-c")) {
      if (++i >= argc) goto print_usage;
      snprintf(compile_home_dir, sizeof(compile_home_dir), "%s", argv[i++]);
    } else if (!strcmp(argv[i], "-x")) {
      if (++i >= argc) goto print_usage;
      ejudge_xml_path = argv[i++];
      argv_restart[j++] = "-x";
      argv_restart[j++] = ejudge_xml_path;
    } else if (!strcmp(argv[i], "--help")) {
      code = 0;
      goto print_usage;
    } else break;
  }
  argv_restart[j++] = "-R";
  if (i < argc) {
    compile_cfg_path = argv[i];
    argv_restart[j++] = argv[i++];
  }
  if (i < argc) goto print_usage;
  argv_restart[j] = 0;
  start_set_args(argv_restart);

  if ((pid = start_find_process("ej-compile", 0)) > 0) {
    fprintf(stderr, "%s: is already running as pid %d\n", argv[0], pid);
    return 1;
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) {
    fprintf(stderr, "%s: ejudge.xml configuration file is not specified\n",
            argv[0]);
    return 1;
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (contests_home_dir[0]) {
    tmp_len = strlen(EJUDGE_CONTESTS_HOME_DIR);
    if (!strncmp(ejudge_xml_path, EJUDGE_CONTESTS_HOME_DIR, tmp_len)) {
      snprintf(tmp_path, sizeof(tmp_path), "%s%s",
               contests_home_dir, ejudge_xml_path + tmp_len);
      ejudge_xml_path = xstrdup(tmp_path);
    }
  }
#endif

#ifndef __WIN32__
  ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 1);
  if (!ejudge_config) {
    fprintf(stderr, "%s: ejudge.xml is invalid\n", argv[0]);
    return 1;
  }
#endif

#ifdef __WIN32__
  if (!compile_home_dir[0] && contests_home_dir[0]) {
    snprintf(compile_home_dir, sizeof(compile_home_dir),
             "%s/win32_compile", contests_home_dir);
  }

  if (!compile_cfg_path && compile_home_dir[0]) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/conf/compile.cfg", compile_home_dir);
    compile_cfg_path = xstrdup(compile_cfg_buf);
  }
  if (!compile_cfg_path && contests_home_dir[0]) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/win32_compile/conf/compile.cfg",
             contests_home_dir);
    compile_cfg_path = xstrdup(compile_cfg_buf);
  }

  if (!compile_cfg_path && ejudge_config && ejudge_config->compile_home_dir) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/conf/compile.cfg", ejudge_config->compile_home_dir);
    compile_cfg_path = compile_cfg_buf;
  }
  if (!compile_cfg_path && ejudge_config && ejudge_config->contests_home_dir) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/win32_compile/conf/compile.cfg",
             ejudge_config->contests_home_dir);
    compile_cfg_path = compile_cfg_buf;
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!compile_cfg_path) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/compile/conf/win32_compile.cfg", EJUDGE_CONTESTS_HOME_DIR);
    compile_cfg_path = compile_cfg_buf;
  }
#endif /* EJUDGE_CONTESTS_HOME_DIR */
  if (!compile_cfg_path) {
    fprintf(stderr, "%s: compile.cfg is not specified\n", argv[0]);
    return 1;
  }
#else
  if (!compile_cfg_path && ejudge_config && ejudge_config->compile_home_dir) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/conf/compile.cfg", ejudge_config->compile_home_dir);
    compile_cfg_path = compile_cfg_buf;
  }
  if (!compile_cfg_path && ejudge_config && ejudge_config->contests_home_dir) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/compile/conf/compile.cfg", ejudge_config->contests_home_dir);
    compile_cfg_path = compile_cfg_buf;
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!compile_cfg_path) {
    snprintf(compile_cfg_buf, sizeof(compile_cfg_buf),
             "%s/compile/conf/compile.cfg", EJUDGE_CONTESTS_HOME_DIR);
    compile_cfg_path = compile_cfg_buf;
  }
#endif /* EJUDGE_CONTESTS_HOME_DIR */
  if (!compile_cfg_path) {
    fprintf(stderr, "%s: compile.cfg is not specified\n", argv[0]);
    return 1;
  }
#endif /* __WIN32__ */

  if (start_prepare(user, group, workdir) < 0) return 1;

  memset(subst_src, 0, sizeof(subst_src));
  memset(subst_dst, 0, sizeof(subst_dst));

#ifdef __WIN32__
  int subst_idx = 0;
  if (compile_home_dir[0]) {
    if (ejudge_config) {
      subst_src[subst_idx] = ejudge_config->compile_home_dir;
      subst_dst[subst_idx] = compile_home_dir;
      subst_idx++;
    } else {
      snprintf(std_compile_home_dir, sizeof(std_compile_home_dir),
               "%s/compile", EJUDGE_CONTESTS_HOME_DIR);
      subst_src[subst_idx] = std_compile_home_dir;
      subst_dst[subst_idx] = compile_home_dir;

      subst_idx++;
    }
  }
  if (contests_home_dir[0]) {
    subst_src[subst_idx] = EJUDGE_CONTESTS_HOME_DIR;
    subst_dst[subst_idx] = contests_home_dir;
    subst_idx++;
  }
  if (compile_home_dir[0]) {
    subst_src[subst_idx] = "/COMPILE_HOME_DIR";
    subst_dst[subst_idx] = compile_home_dir;
    subst_idx++;
  }
  if (contests_home_dir[0]) {
    subst_src[subst_idx] = "/CONTESTS_HOME_DIR";
    subst_dst[subst_idx] = contests_home_dir;
    subst_idx++;
  }

  subst_src[subst_idx] = "/TMPDIR";
  subst_dst[subst_idx] = get_tmp_dir(tmp_dir, sizeof(tmp_dir));
  subst_idx++;

  fprintf(stderr, "Win32 substitutions:\n");
  for (int j = 0; subst_src[j]; ++j) {
    fprintf(stderr, "%s -> %s\n", subst_src[j], subst_dst[j]);
  }
  subst_src_ptr = subst_src;
  subst_dst_ptr = subst_dst;
#endif

  if (prepare(NULL, &serve_state, compile_cfg_path, prepare_flags, PREPARE_COMPILE,
              cpp_opts, 0, subst_src_ptr, subst_dst_ptr) < 0)
    return 1;
#if HAVE_OPEN_MEMSTREAM - 0
  if (!(lang_log_f = open_memstream(&lang_log_t, &lang_log_z))) return 1;
  if (lang_config_configure(lang_log_f, serve_state.global->lang_config_dir,
                            serve_state.max_lang, serve_state.langs) < 0) {
    fclose(lang_log_f); lang_log_f = 0;
    fprintf(stderr, "%s", lang_log_t);
    return 1;
  }
  close_memstream(lang_log_f); lang_log_f = 0;
#else
  if (lang_config_configure(stderr, serve_state.global->lang_config_dir,
                            serve_state.max_lang, serve_state.langs) < 0)
    return 1;
#endif /* HAVE_OPEN_MEMSTREAM */
  if (key && filter_languages(key) < 0) return 1;
  if (create_dirs(&serve_state, PREPARE_COMPILE) < 0) return 1;
  if (check_config() < 0) return 1;
  if (initialize_mode) return 0;

#if HAVE_SETSID - 0
  log_path[0] = 0;
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!log_path[0]) {
    snprintf(log_path, sizeof(log_path), "%s/var/ej-compile.log", EJUDGE_CONTESTS_HOME_DIR);
  }
#endif
  if (!log_path[0]) {
    snprintf(log_path, sizeof(log_path), "%s/ej-compile.log", serve_state.global->var_dir);
  }

  if (daemon_mode) {
    // daemonize itself
    if (start_open_log(log_path) < 0)
      return 1;

    if ((pid = fork()) < 0) return 1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return 1;

#if HAVE_OPEN_MEMSTREAM - 0 == 1
    fprintf(stderr, "%s", lang_log_t);
#endif /* HAVE_OPEN_MEMSTREAM */
  } else if (restart_mode) {
    if (start_open_log(log_path) < 0)
      return 1;
  }
#endif /* HAVE_SETSID */

#if HAVE_OPEN_MEMSTREAM - 0 == 1
  xfree(lang_log_t); lang_log_t = 0; lang_log_z = 0;
#endif /* HAVE_OPEN_MEMSTREAM */

  //if (do_loop() < 0) return 1;
  if (new_loop() < 0) return 1;

  if (interrupt_restart_requested()) start_restart();

  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] [config-file]\n", argv[0]);
  printf("  -k key - specify language key\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  printf("  -D     - start in daemon mode\n");
  printf("  -i     - initialize mode: create all dirs and exit\n");
  printf("  -k KEY - specify a language filter key\n");
  printf("  -u U   - start as user U (only as root)\n");
  printf("  -g G   - start as group G (only as root)\n");
  printf("  -C D   - change directory to D\n");
  printf("  -x X   - specify a path to ejudge.xml file\n");
  printf("  -r S   - substitute ${CONTESTS_HOME_DIR} for S in the config\n");
  printf("  -c C   - substitute ${COMPILE_HOME_DIR} for C in the config\n");
  return code;
}

