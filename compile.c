/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2008 Alexander Chernov <cher@ejudge.ru> */

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
 */

#include "config.h"

#include "prepare.h"
#include "pathutl.h"
#include "errlog.h"
#include "parsecfg.h"
#include "fileutl.h"
#include "cr_serialize.h"
#include "interrupt.h"
#include "runlog.h"
#include "compile_packet.h"
#include "curtime.h"
#include "serve_state.h"
#include "startstop.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/exec.h>
#include <reuse/osdeps.h>

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
  path_t report_dir, status_dir;

  path_t  pkt_name, run_name;
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
  struct stat stb;
  FILE *log_f = 0;

  if (cr_serialize_init(&serve_state) < 0) return -1;
  interrupt_init();
  interrupt_disable();

  while (1) {
    // terminate if signaled
    if (interrupt_get_status() || interrupt_restart_requested()) break;

    r = scan_dir(serve_state.global->compile_queue_dir,
                 pkt_name, sizeof(pkt_name));

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
      os_Sleep(serve_state.global->sleep_time);
      interrupt_disable();
      continue;
    }

    pkt_ptr = 0;
    pkt_len = 0;
    r = generic_read_file(&pkt_ptr, 0, &pkt_len,
                          SAFE | REMOVE, serve_state.global->compile_queue_dir,
                          pkt_name, "");
    if (r == 0) continue;
    if (r < 0 || !pkt_ptr) {
      // it looks like there's no reasonable recovery strategy
      // so, just ignore the error
      continue;
    }

    r = compile_request_packet_read(&serve_state, pkt_len, pkt_ptr, &req);
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
        raise(SIGTERM);
        break;
      case 2:
        raise(SIGHUP);
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
    get_current_time(&rpl.ts2, &rpl.ts2_us);
    rpl.run_block_len = req->run_block_len;
    rpl.run_block = req->run_block; /* !!! shares memory with req */
    msgbuf[0] = 0;

    /* prepare paths useful to report messages to the serve */
    snprintf(report_dir, sizeof(report_dir),
             "%s/%06d/report", serve_state.global->compile_dir, rpl.contest_id);
    snprintf(status_dir, sizeof(status_dir),
             "%s/%06d/status", serve_state.global->compile_dir, rpl.contest_id);
    snprintf(run_name, sizeof(run_name), "%06d", rpl.run_id);
    pathmake(log_out, report_dir, "/", run_name, NULL);

    if (!r) {
      /*
       * there is something wrong, but we have contest_id, judge_id
       * and run_id in place, so we can report an error back
       * to serve
       */
      snprintf(msgbuf, sizeof(msgbuf), "invalid compile packet\n");
      goto report_internal_error;
    }
    
    pathmake(src_name, run_name, serve_state.langs[req->lang_id]->src_sfx, NULL);
    pathmake(exe_name, run_name, serve_state.langs[req->lang_id]->exe_sfx, NULL);

    pathmake(src_path, serve_state.global->compile_work_dir, "/", src_name, NULL);
    pathmake(exe_path, serve_state.global->compile_work_dir, "/", exe_name, NULL);
    pathmake(log_path, serve_state.global->compile_work_dir, "/", "log", NULL);
    /* the resulting executable file */
    pathmake(exe_out, report_dir, "/", exe_name, NULL);

    /* move the source file into the working dir */
    r = generic_copy_file(REMOVE, serve_state.global->compile_src_dir, pkt_name,
                          serve_state.langs[req->lang_id]->src_sfx,
                          0, serve_state.global->compile_work_dir, src_name, "");
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

    if (req->output_only) {
      // copy src_path -> exe_path
      generic_copy_file(0, NULL, src_path, NULL, 0, NULL, exe_path, NULL);
      ce_flag = 0;
      rpl.status = RUN_OK;
    } else {
      info("Starting: %s %s %s", serve_state.langs[req->lang_id]->cmd,
           src_name, exe_name);
      tsk = task_New();
      task_AddArg(tsk, serve_state.langs[req->lang_id]->cmd);
      task_AddArg(tsk, src_name);
      task_AddArg(tsk, exe_name);
      task_SetPathAsArg0(tsk);
      if (req->env_num > 0) {
        for (i = 0; i < req->env_num; i++)
          task_PutEnv(tsk, req->env_vars[i]);
      }
      task_SetWorkingDir(tsk, serve_state.global->compile_work_dir);
      task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_REWRITE, 0777);
      task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_WRITE);
      task_SetRedir(tsk, 2, TSR_DUP, 1);
      if (serve_state.langs[req->lang_id]->compile_real_time_limit > 0) {
        //task_SetMaxRealTime(tsk, serve_state.langs[req->lang_id]->compile_real_time_limit);
        task_SetMaxTime(tsk, serve_state.langs[req->lang_id]->compile_real_time_limit);
      }
#if HAVE_TASK_ENABLEALLSIGNALS - 0 == 1
      task_EnableAllSignals(tsk);
#endif
      if (cr_serialize_lock(&serve_state) < 0) {
        // FIXME: propose reasonable recovery?
        return -1;
      }
      task_Start(tsk);
      task_Wait(tsk);
      if (cr_serialize_unlock(&serve_state) < 0) {
        // FIXME: propose reasonable recovery?
        return -1;
      }

      /*
      if (task_IsTimeout(tsk)) {
        err("Compilation process timed out");
        snprintf(msgbuf, sizeof(msgbuf), "compilation process timed out\n");
        goto report_internal_error;
      }
      */

      if (task_IsTimeout(tsk)) {
        /* FIXME: this does not work in case of gcc/g++, since the
         * time is consumed by the children of gcc/g++ compiler driver...
         */
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

    get_current_time(&rpl.ts3, &rpl.ts3_us);
    if (compile_reply_packet_write(&rpl, &rpl_size, &rpl_pkt) < 0)
      goto cleanup_and_continue;

    while (1) {
      if (ce_flag) {
        // truncate log file at size 1MB
        if (stat(log_path, &stb) >= 0 && stb.st_size > MAX_LOG_SIZE) {
          truncate(log_path, MAX_LOG_SIZE);
          if ((log_f = fopen(log_path, "a"))) {
            fprintf(log_f, "\n\nCompilation log is truncated by ejudge!\n");
            fclose(log_f); log_f = 0;
          }
        }
        // append tail_message
        if (tail_message && (log_f = fopen(log_path, "a"))) {
          fprintf(log_f, "%s\n", tail_message);
          fclose(log_f); log_f = 0;
        }
        r = generic_copy_file(0, 0, log_path, "", 0, 0, log_out, "");
      } else {
        r = generic_copy_file(0, 0, exe_path, "", 0, 0, exe_out, "");
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
    clear_directory(serve_state.global->compile_work_dir);
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
  if (!total) {
    err("No languages after filter %s", key);
    return -1;
  }
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

  if (!total) {
    err("no languages");
    return -1;
  }
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
  path_t  log_path;
  int log_fd = -1, pid = -1;
  char **argv_restart = 0;
  FILE *lang_log_f = 0;
  char *lang_log_t = 0;
  size_t lang_log_z = 0;

  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 1);
  argv_restart[j++] = argv[0];

  if (argc == 1) goto print_usage;
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
    } else break;
  }
  if (i >= argc) goto print_usage;
  argv_restart[j++] = argv[i];
  argv_restart[j] = 0;
  start_set_args(argv_restart);

  if (start_prepare(user, group, workdir) < 0) return 1;

  if (prepare(&serve_state, argv[i], prepare_flags, PREPARE_COMPILE,
              cpp_opts, 0) < 0)
    return 1;
  if (!(lang_log_f = open_memstream(&lang_log_t, &lang_log_z))) return 1;
  if (lang_config_configure(lang_log_f, serve_state.global->lang_config_dir,
                            serve_state.max_lang, serve_state.langs) < 0) {
    fclose(lang_log_f); lang_log_f = 0;
    fprintf(stderr, "%s", lang_log_t);
    return 1;
  }
  fclose(lang_log_f); lang_log_f = 0;
  if (key && filter_languages(key) < 0) return 1;
  if (create_dirs(&serve_state, PREPARE_COMPILE) < 0) return 1;
  if (check_config() < 0) return 1;
  if (initialize_mode) return 0;

  if (daemon_mode) {
    // FIXME: make log file tunable?
    snprintf(log_path, sizeof(log_path), "%s/compile.log",
             serve_state.global->var_dir);

    // daemonize itself
    if ((log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600)) < 0) {
      err("cannot open log file `%s'", log_path);
      return 1;
    }
    close(0);
    if (open("/dev/null", O_RDONLY) < 0) return 1;
    close(1);
    if (open("/dev/null", O_WRONLY) < 0) return 1;
    close(2); dup(log_fd); close(log_fd);
    if ((pid = fork()) < 0) return 1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return 1;

    fprintf(stderr, "%s", lang_log_t);
  }

  xfree(lang_log_t); lang_log_t = 0; lang_log_z = 0;
  if (do_loop() < 0) return 1;

  if (interrupt_restart_requested()) start_restart();

  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -k key - specify language key\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  /*
    -i
    -k
    -D
    -u
    -g
    -C
   */
  return code;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tpTask")
 * End:
 */
