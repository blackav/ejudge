/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * This program compiles incoming source files and puts the resulting
 * executables into the spool directory.
 *
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
  path_t base_name;
  path_t exe_name;

  path_t src_path;
  path_t exe_path;
  path_t log_path;

  path_t exe_out;
  path_t log_out;
  char   statbuf[64];

  int    r, i;
  tpTask tsk;

  while (1) {
    while (1) {
      for (i = 0; i <= max_lang; i++) {
        if (!langs[i]) continue;
        r = scan_dir(langs[i]->src_dir, src_name);
        if (r < 0) return -1;
        if (r > 0) break;
      }

      if (i <= max_lang) {
        os_rGetBasename(src_name, base_name, sizeof(base_name));
        pathmake(exe_name, base_name, langs[i]->exe_sfx, NULL);
        pathmake(src_path, langs[i]->work_dir, "/", src_name, NULL);
        pathmake(exe_path, langs[i]->work_dir, "/", exe_name, NULL);
        pathmake(log_path, langs[i]->work_dir, "/", "log", NULL);
        /* the resulting report file */
        pathmake(log_out,  langs[i]->compile_report_dir, "/", base_name, NULL);
        /* the resulting executable file */
        pathmake(exe_out,  langs[i]->compile_report_dir, "/", exe_name, NULL);

        /* move the source file into the working dir */
        r = generic_copy_file(SAFE|REMOVE, langs[i]->src_dir, src_name, "",
                              0, langs[i]->work_dir, src_name, "");
        if (r < 0) return -1;
        if (r == 0) break;

        info("Starting: %s %s %s", langs[i]->cmd, src_name, exe_name);
        tsk = task_New();
        task_AddArg(tsk, langs[i]->cmd);
        task_AddArg(tsk, src_name);
        task_AddArg(tsk, exe_name);
        task_SetPathAsArg0(tsk);
        task_SetWorkingDir(tsk, langs[i]->work_dir);
        task_SetRedir(tsk, 1, TSR_FILE, log_path,
                      O_WRONLY|O_CREAT|O_TRUNC, 0777);
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_WRONLY);
        task_SetRedir(tsk, 2, TSR_DUP, 1);
        task_Start(tsk);
        task_Wait(tsk);

        if (task_IsAbnormal(tsk)) {
          // compilation error?
          info("Compilation failed");
          //copy logfile and create statfile
          if (generic_copy_file(0, 0, log_path, "", 0, 0, log_out, "") < 0)
            return -1;
          sprintf(statbuf, "%d%s", 1, PATH_EOL);
          if (generic_write_file(statbuf, strlen(statbuf), SAFE,
                                 langs[i]->compile_status_dir,
                                 base_name, "") < 0)
            return -1;
        } else {
          // ok, we can move the executable to output dir
          info("Compilation sucessful");
          if (generic_copy_file(0, 0, exe_path, "",
                                0, 0, exe_out, "") < 0)
            return -1;
          sprintf(statbuf, "0%s", PATH_EOL);
          if (generic_write_file(statbuf, strlen(statbuf), SAFE,
                                 langs[i]->compile_status_dir,
                                 base_name, "") < 0)
            return -1;
        }
        clear_directory(langs[i]->work_dir);
        break;
      }

      os_Sleep(global->sleep_time);
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

  for (i = 1; i <= max_lang; i++) {
    if (!langs[i]) continue;

    /* script must exist and be executable */
    total++;
    if (check_executable(langs[i]->cmd) < 0) return -1;
    if (check_writable_spool(langs[i]->src_dir, SPOOL_OUT) < 0) return -1;
    if (check_writable_spool(langs[i]->compile_status_dir, SPOOL_IN) < 0)
      return -1;
    if (check_writable_dir(langs[i]->compile_report_dir) < 0) return -1;
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


