/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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
 *
 * NOTE: this is obsoleted!
 * THEORY OF OPERATION: for each language which has 'key' matching
 * to the command line parameter of the utility, src_dir is watched
 * for the new files. Each new file must have name NUM.SFX, where
 * NUM is the run number, SFX is the language suffix.
 * The program moves new source files out of spool directory,
 * and invokes a compile script on them.
 * If compilation failed, compiler error reports are put into
 * compile_report_dir. If compilation is successful, the executable binary
 * is put into compile_report_dir. The executable binary has the suffix
 * as specified in exe_sfx.
 * Then compilation status message is put into compile_status_dir.
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

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

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
  char    pkt_buf[128];
  char   *pkt_ptr;
  int     pkt_len;
  int     locale_id;
  int     contest_id;
  int     run_id;
  int     lang_id;

  int    r, n;
  tpTask tsk;

  if (cr_serialize_init() < 0) return -1;

  while (1) {
    r = scan_dir(global->compile_queue_dir, pkt_name);
    if (r < 0) return -1;
    if (!r) {
      os_Sleep(global->sleep_time);
      continue;
    }

    memset(pkt_buf, 0, sizeof(pkt_buf));
    pkt_ptr = pkt_buf;
    pkt_len = 0;
    r = generic_read_file(&pkt_ptr, sizeof(pkt_buf), &pkt_len,
                          SAFE | REMOVE, global->compile_queue_dir,
                          pkt_name, "");
    if (r == 0) continue;
    if (r < 0) return -1;

    chop(pkt_buf);
    info("compile packet: <%s>", pkt_buf);

    n = 0;
    if (sscanf(pkt_buf, "%d %d %d %d %n", &contest_id, &run_id,
               &lang_id, &locale_id, &n) != 4
        || pkt_buf[n]
        || contest_id <= 0
        || run_id < 0
        || lang_id <= 0 || lang_id > max_lang
        || !langs[lang_id]
        || locale_id < 0
        || locale_id > 1024) {
      err("bad packet");
      continue;
    }

    snprintf(report_dir, sizeof(report_dir),
             "%s/%04d/report", global->compile_dir, contest_id);
    snprintf(status_dir, sizeof(status_dir),
             "%s/%04d/status", global->compile_dir, contest_id);
    snprintf(run_name, sizeof(run_name), "%06d", run_id);
    pathmake(src_name, run_name, langs[lang_id]->src_sfx, NULL);
    pathmake(exe_name, run_name, langs[lang_id]->exe_sfx, NULL);

    pathmake(src_path, global->compile_work_dir, "/", src_name, NULL);
    pathmake(exe_path, global->compile_work_dir, "/", exe_name, NULL);
    pathmake(log_path, global->compile_work_dir, "/", "log", NULL);
    /* the resulting report file */
    pathmake(log_out, report_dir, "/", run_name, NULL);
    /* the resulting executable file */
    pathmake(exe_out, report_dir, "/", exe_name, NULL);

    /* move the source file into the working dir */
    r = generic_copy_file(REMOVE, global->compile_src_dir, pkt_name,
                          langs[lang_id]->src_sfx,
                          0, global->compile_work_dir, src_name, "");
    if (r <= 0) continue;

    info("Starting: %s %s %s", langs[lang_id]->cmd, src_name, exe_name);
    tsk = task_New();
    task_AddArg(tsk, langs[lang_id]->cmd);
    task_AddArg(tsk, src_name);
    task_AddArg(tsk, exe_name);
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, global->compile_work_dir);
    task_SetRedir(tsk, 1, TSR_FILE, log_path,
                  O_WRONLY|O_CREAT|O_TRUNC, 0777);
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_WRONLY);
    task_SetRedir(tsk, 2, TSR_DUP, 1);
    if (langs[lang_id]->compile_real_time_limit > 0) {
      task_SetMaxRealTime(tsk, langs[lang_id]->compile_real_time_limit);
    }
    if (cr_serialize_lock() < 0) return -1;
    task_Start(tsk);
    task_Wait(tsk);
    if (cr_serialize_unlock() < 0) return -1;

    if (task_IsTimeout(tsk)) {
      info("Compilation timeout");
      if (generic_copy_file(0, 0, log_path, "", 0, 0, log_out, "") < 0)
        return -1;
      sprintf(statbuf, "%d%s", 6, PATH_EOL);
      if (generic_write_file(statbuf, strlen(statbuf), SAFE,
                             status_dir,
                             run_name, "") < 0)
        return -1;
    } else if (task_IsAbnormal(tsk)) {
      // compilation error?
      info("Compilation failed");
      //copy logfile and create statfile
      if (generic_copy_file(0, 0, log_path, "", 0, 0, log_out, "") < 0)
        return -1;
      sprintf(statbuf, "%d%s", 1, PATH_EOL);
      if (generic_write_file(statbuf, strlen(statbuf), SAFE,
                             status_dir,
                             run_name, "") < 0)
        return -1;
    } else {
      // ok, we can move the executable to output dir
      info("Compilation sucessful");
      if (generic_copy_file(0, 0, exe_path, "",
                            0, 0, exe_out, "") < 0)
        return -1;
      sprintf(statbuf, "0%s", PATH_EOL);
      if (generic_write_file(statbuf, strlen(statbuf), SAFE,
                             status_dir,
                             run_name, "") < 0)
        return -1;
    }
    clear_directory(global->compile_work_dir);
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
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */


