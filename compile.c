/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

/**
 * This program compiles incoming source files and puts the resulting
 * executables into the spool directory.
 */

#include "prepare.h"
#include "pathutl.h"
#include "parsecfg.h"
#include "fileutl.h"
#include "cr_serialize.h"

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
  char   statbuf[64];
  path_t report_dir, status_dir;

  path_t  pkt_name, run_name;
  char   *pkt_ptr, *ptr, *end_ptr;
  int     pkt_len;
  int     locale_id;
  int     contest_id;
  int     run_id;
  int     lang_id;
  int    r, n, i, v;
  tpTask tsk;
  sigset_t work_mask;
  unsigned char msgbuf[512];
  int ce_flag;
  char **compiler_env = 0;
  int env_count = 0, env_size = 0;

  sigemptyset(&work_mask);
  sigaddset(&work_mask, SIGINT);
  sigaddset(&work_mask, SIGTERM);
  sigaddset(&work_mask, SIGTSTP);

  if (cr_serialize_init() < 0) return -1;
  sigprocmask(SIG_BLOCK, &work_mask, 0);

  while (1) {
    r = scan_dir(global->compile_queue_dir, pkt_name);

    if (r < 0) {
      switch (-r) {
      case ENOMEM:
      case ENOENT:
      case ENFILE:
        err("trying to recover, sleep for 5 seconds");
        sigprocmask(SIG_UNBLOCK, &work_mask, 0);
        sleep(5);
        sigprocmask(SIG_BLOCK, &work_mask, 0);
        continue;
      default:
        err("unrecoverable error, exiting");
        return -1;
      }
    }

    if (!r) {
      sigprocmask(SIG_UNBLOCK, &work_mask, 0);
      os_Sleep(global->sleep_time);
      sigprocmask(SIG_BLOCK, &work_mask, 0);
      continue;
    }

    pkt_ptr = 0;
    pkt_len = 0;
    compiler_env = 0;
    env_count = 0;
    r = generic_read_file(&pkt_ptr, 0, &pkt_len,
                          SAFE | REMOVE, global->compile_queue_dir,
                          pkt_name, "");
    if (r == 0) continue;
    if (r < 0 || !pkt_ptr) {
      // it looks like there's no reasonable recovery strategy
      // so, just ignore the error
      continue;
    }

    chop(pkt_ptr);
    end_ptr = pkt_ptr + strlen(pkt_ptr);
    info("compile packet: <%s>", pkt_ptr);

    n = 0;
    if (sscanf(pkt_ptr, "%d %d %d %d %n", &contest_id, &run_id,
               &lang_id, &locale_id, &n) != 4) {
      // packet parse error, we cannot report such error back to
      // the contest's serve since the contest id is unknown
      // just ignore the error
      err("packet parse error");
    silent_packet_error:
      xfree(pkt_ptr);
      if (compiler_env) {
        for (i = 0; i < env_count; i++) xfree(compiler_env[i]);
        xfree(compiler_env);
      }
      continue;
    }

    if (contest_id <= 0 || contest_id > 9999) {
      // cannot report to the server, just ignore
      err("contest_id is invalid: %d", contest_id);
      goto silent_packet_error;
    }
    if (run_id < 0 || run_id > 999999) {
      err("run_id is invalid: %d", run_id);
      goto silent_packet_error;
    }

    ptr = pkt_ptr + n;
    n = 0;
    if (sscanf(ptr, "%d%n", &env_count, &n) == 1) {
      ptr += n;
      if (env_count < 0 || env_count > 9999) {
        err("env_count is invalid: %d", env_count);
        env_count = 0;
        goto silent_packet_error;
      }
      if (env_count > 0) {
        XCALLOC(compiler_env, env_count + 1);
        for (i = 0; i < env_count; i++) {
          n = 0;
          env_size = 0;
          if (sscanf(ptr, "%d%n", &env_size, &n) != 1) {
            err("cannot read compiler_env[%d] length", i);
            goto silent_packet_error;
          }
          ptr += n;
          if (env_size <= 0 || env_size > 999999) {
            err("invalid compiler_env[%d] length %d", i, env_size);
            goto silent_packet_error;
          }
          if (*ptr != ' ') {
            err("space expected after compiler_env[%d] length", i);
            goto silent_packet_error;
          }
          ptr++;
          if (end_ptr - ptr < env_size) {
            err("not enough space for compiler_env[%d]", i);
            goto silent_packet_error;
          }
          compiler_env[i] = (char*) xmalloc(env_size + 1);
          memcpy(compiler_env[i], ptr, env_size);
          compiler_env[i][env_size] = 0;
          ptr += env_size;
        }
      }
    }

    n = 0;
    if (sscanf(ptr, "%d%n", &v, &n) != 1 || ptr[n] || v) {
      err("invalid packet tail");
      goto silent_packet_error;
    }

    // don't need packet source any more
    xfree(pkt_ptr); pkt_ptr = 0;

    // at this point we may try to report messages to the contest server
    snprintf(report_dir, sizeof(report_dir),
             "%s/%04d/report", global->compile_dir, contest_id);
    snprintf(status_dir, sizeof(status_dir),
             "%s/%04d/status", global->compile_dir, contest_id);
    snprintf(run_name, sizeof(run_name), "%06d", run_id);
    pathmake(log_out, report_dir, "/", run_name, NULL);

    if (lang_id <= 0 || lang_id > max_lang || !langs[lang_id]) {
      snprintf(msgbuf, sizeof(msgbuf),
               "compile packet error: invalid language id %d\n", lang_id);
      err("invalid language id %d", lang_id);

    report_internal_error:
      if (generic_write_file(msgbuf, strlen(msgbuf), 0, 0, log_out, 0) < 0){
        // we tried, but it didn't work out :-(
        if (compiler_env) {
          for (i = 0; i < env_count; i++) xfree(compiler_env[i]);
          xfree(compiler_env);
        }
        continue;
      }
      snprintf(statbuf, sizeof(statbuf), "6\n");
      if (generic_write_file(statbuf, sizeof(statbuf), SAFE,
                             status_dir, run_name, 0) < 0) {
        // remove the report file
        unlink(log_out);
      }
      clear_directory(global->compile_work_dir);
      if (compiler_env) {
        for (i = 0; i < env_count; i++) xfree(compiler_env[i]);
        xfree(compiler_env);
      }
      continue;
    }

    if (locale_id < 0 || locale_id > 1024) {
      snprintf(msgbuf, sizeof(msgbuf),
               "compile packet error: invalid locale id %d\n", locale_id);
      err("invalid locale id %d", locale_id);
      goto report_internal_error;
    }

    pathmake(src_name, run_name, langs[lang_id]->src_sfx, NULL);
    pathmake(exe_name, run_name, langs[lang_id]->exe_sfx, NULL);

    pathmake(src_path, global->compile_work_dir, "/", src_name, NULL);
    pathmake(exe_path, global->compile_work_dir, "/", exe_name, NULL);
    pathmake(log_path, global->compile_work_dir, "/", "log", NULL);
    /* the resulting executable file */
    pathmake(exe_out, report_dir, "/", exe_name, NULL);

    /* move the source file into the working dir */
    r = generic_copy_file(REMOVE, global->compile_src_dir, pkt_name,
                          langs[lang_id]->src_sfx,
                          0, global->compile_work_dir, src_name, "");
    if (!r) {
      snprintf(msgbuf, sizeof(msgbuf),
               "the source file is missing\n");
      err("the source file is missing");
      goto report_internal_error;
    }
    if (r < 0) {
      // wait some time, then try again
      info("waiting 5 seconds hoping for things to change");
      sigprocmask(SIG_UNBLOCK, &work_mask, 0);
      sleep(5);
      sigprocmask(SIG_BLOCK, &work_mask, 0);
      if (compiler_env) {
        for (i = 0; i < env_count; i++) xfree(compiler_env[i]);
        xfree(compiler_env);
      }
      continue;
    }

    info("Starting: %s %s %s", langs[lang_id]->cmd, src_name, exe_name);
    tsk = task_New();
    task_AddArg(tsk, langs[lang_id]->cmd);
    task_AddArg(tsk, src_name);
    task_AddArg(tsk, exe_name);
    task_SetPathAsArg0(tsk);
    if (compiler_env) {
      for (i = 0; compiler_env[i]; i++)
        task_PutEnv(tsk, compiler_env[i]);
    }
    task_SetWorkingDir(tsk, global->compile_work_dir);
    task_SetRedir(tsk, 1, TSR_FILE, log_path,
                  O_WRONLY|O_CREAT|O_TRUNC, 0777);
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_WRONLY);
    task_SetRedir(tsk, 2, TSR_DUP, 1);
    if (langs[lang_id]->compile_real_time_limit > 0) {
      task_SetMaxRealTime(tsk, langs[lang_id]->compile_real_time_limit);
    }
    if (cr_serialize_lock() < 0) {
      // FIXME: propose reasonable recovery?
      return -1;
    }
    task_Start(tsk);
    task_Wait(tsk);
    if (cr_serialize_unlock() < 0) {
      // FIXME: propose reasonable recovery?
      return -1;
    }

    if (task_IsTimeout(tsk)) {
      task_Delete(tsk);
      err("Compilation process timed out");
      snprintf(msgbuf, sizeof(msgbuf),
               "compilation process timed out\n");
      goto report_internal_error;
    }

    if (task_IsAbnormal(tsk)) {
      info("Compilation failed");
      ce_flag = 1;
      sprintf(statbuf, "%d%s", 1, PATH_EOL);
    } else {
      info("Compilation sucessful");
      ce_flag = 0;
      sprintf(statbuf, "0%s", PATH_EOL);
    }

    while (1) {
      if (ce_flag) {
        r = generic_copy_file(0, 0, log_path, "", 0, 0, log_out, "");
      } else {
        r = generic_copy_file(0, 0, exe_path, "", 0, 0, exe_out, "");
      }
      if (r >= 0 && generic_write_file(statbuf, strlen(statbuf), SAFE,
                                       status_dir, run_name, "") >= 0)
        break;

      info("waiting 5 seconds hoping for things to change");
      sigprocmask(SIG_UNBLOCK, &work_mask, 0);
      sleep(5);
      sigprocmask(SIG_BLOCK, &work_mask, 0);
    }

    task_Delete(tsk);
    clear_directory(global->compile_work_dir);
    if (compiler_env) {
      for (i = 0; i < env_count; i++) xfree(compiler_env[i]);
      xfree(compiler_env);
    }
  }

  return 0;
}

int
filter_languages(char *key)
{
  int i, total = 0;

  for (i = 1; i <= max_lang; i++) {
    if (!langs[i]) continue;
    if (strcmp(langs[i]->key, key)) {
      langs[i] = 0;
    }
  }

  for (i = 1; i <= max_lang; i++) {
    total += langs[i] != 0;
  }
  if (!total) {
    err("No languages after filter %s", key);
    return -1;
  }
  return 0;
}

int
check_config(void)
{
  int i;
  int total = 0;

  if (check_writable_spool(global->compile_queue_dir, SPOOL_OUT) < 0)
    return -1;
  for (i = 1; i <= max_lang; i++) {
    if (!langs[i]) continue;

    /* script must exist and be executable */
    total++;
    if (check_executable(langs[i]->cmd) < 0) return -1;
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
  int     i = 1;
  char   *key = 0;
  path_t  cpp_opts = {0};
  int     code = 0;
  int     T_flag = 0;
  int     prepare_flags = 0;

  if (argc == 1) goto print_usage;
  code = 1;

  while (i < argc) {
    if (!strcmp(argv[i], "-T")) {
      T_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-k")) {
      if (++i >= argc) goto print_usage;
      key = argv[i++];
    } else if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      pathcat(cpp_opts, argv[i++]);
    } else if (!strcmp(argv[i], "-E")) {
      i++;
      prepare_flags |= PREPARE_USE_CPP;
    } else break;
  }
  if (i >= argc) goto print_usage;

  if (prepare(argv[i], prepare_flags, PREPARE_COMPILE, cpp_opts) < 0) return 1;
  if (T_flag) {
    print_configuration(stdout);
    return 0;
  }
  if (key && filter_languages(key) < 0) return 1;
  if (create_dirs(PREPARE_COMPILE) < 0) return 1;
  if (check_config() < 0) return 1;
  if (do_loop() < 0) return 1;

  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -T     - print configuration and exit\n");
  printf("  -k key - specify language key\n");
  printf("  -E     - enable C preprocessor\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return code;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tpTask")
 * End:
 */
