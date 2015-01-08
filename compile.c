/* -*- c -*- */

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

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

enum { MAX_LOG_SIZE = 1024 * 1024 };

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

    r = scan_dir(global->compile_queue_dir, pkt_name, sizeof(pkt_name));

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
        if (((ssize_t) req->max_vm_size) > 0) {
          task_SetVMSize(tsk, req->max_vm_size);
        } else if (((ssize_t) lang->max_vm_size) > 0) {
          task_SetVMSize(tsk, lang->max_vm_size);
        } else if (((ssize_t) global->compile_max_vm_size) > 0) {
          task_SetVMSize(tsk, global->compile_max_vm_size);
        }
        if (((ssize_t) req->max_stack_size) > 0) {
          task_SetStackSize(tsk, req->max_stack_size);
        } else if (((ssize_t) lang->max_stack_size) > 0) {
          task_SetStackSize(tsk, lang->max_stack_size);
        } else if (((ssize_t) global->compile_max_stack_size) > 0) {
          task_SetStackSize(tsk, global->compile_max_stack_size);
        }
        if (((ssize_t) req->max_file_size) > 0) {
          task_SetMaxFileSize(tsk, req->max_file_size);
        } else if (((ssize_t) lang->max_file_size) > 0) {
          task_SetMaxFileSize(tsk, lang->max_file_size);
        } else if (((ssize_t) global->compile_max_file_size) > 0) {
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
  ejudge_config = ejudge_cfg_parse(ejudge_xml_path);
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

  if (prepare(&serve_state, compile_cfg_path, prepare_flags, PREPARE_COMPILE,
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

  if (do_loop() < 0) return 1;

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

