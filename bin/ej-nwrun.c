/* -*- c -*- */

/* Copyright (C) 2010-2017 Alexander Chernov <cher@ejudge.ru> */

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

#if __GNUC__ >= 7
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/parsecfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/runlog.h"
#include "ejudge/nwrun_packet.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define DEFAULT_MAX_OUTPUT_FILE_SIZE (64 * 1024 * 1024)
#define DEFAULT_MAX_ERROR_FILE_SIZE  (16 * 1024 * 1024)
#define DEFAULT_INPUT_FILE_NAME      "input.txt"
#define DEFAULT_OUTPUT_FILE_NAME     "output.txt"
#define DEFAULT_ERROR_FILE_NAME      "error.txt"

static const unsigned char *program_name;
static unsigned char *program_dir;
static unsigned char *config_file;

static void
die(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
die(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", program_name, buf);
  exit(1);
}

static void
get_program_dir(const unsigned char *program_path)
{
  unsigned char *workdir = 0;
  unsigned char fullpath[EJ_PATH_MAX];

  if (os_IsAbsolutePath(program_path)) {
    program_dir = os_DirName(program_path);
    os_normalize_path(program_dir);
    return;
  }

  workdir = os_GetWorkingDir();
  snprintf(fullpath, sizeof(fullpath), "%s/%s", workdir, program_path);
  xfree(workdir); workdir = 0;
  os_normalize_path(fullpath);
  program_dir = os_DirName(fullpath);
}

static void
get_config_file(void)
{
  unsigned char buf[EJ_PATH_MAX];

  if (config_file) return;

  snprintf(buf, sizeof(buf), "%s/nwrun.cfg", program_dir);
  config_file = xstrdup(buf);
}

static void
print_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

static void
print_help(void)
{
  exit(0);
}

struct config_global_data
{
  struct generic_section_config g;

  /** spool directory polling interval */
  int sleep_time;
  /** spool directory */
  unsigned char spool_dir[EJ_PATH_MAX];
  /** working directory */
  unsigned char work_dir[EJ_PATH_MAX];
  /** cache directory */
  unsigned char cache_dir[EJ_PATH_MAX];

  unsigned char queue_dir[EJ_PATH_MAX];
  unsigned char result_dir[EJ_PATH_MAX];
};

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define CONFIG_OFFSET(x)   XOFFSET(struct config_global_data, x)
#define CONFIG_SIZE(x)     XFSIZE(struct config_global_data, x)
#define CONFIG_PARAM(x, t) { #x, t, CONFIG_OFFSET(x), CONFIG_SIZE(x) }
static const struct config_parse_info config_global_params[] =
{
  CONFIG_PARAM(sleep_time, "d"),
  CONFIG_PARAM(spool_dir, "s"),
  CONFIG_PARAM(work_dir, "s"),
  CONFIG_PARAM(cache_dir, "s"),

  { 0, 0, 0, 0 }
};

static const struct config_section_info params[] =
{
  { "global", sizeof(struct config_global_data), config_global_params, 0, 0, 0 },
  { NULL, 0, NULL }
};

static struct generic_section_config *config;
static struct config_global_data *global;

static void
parse_config(void)
{
  FILE *f = 0;
  struct generic_section_config *p = 0;
  const unsigned char *subst_src[10];
  const unsigned char *subst_dst[10];
  int subst_idx = 0;
  unsigned char tmp_dir[EJ_PATH_MAX];

  memset(subst_src, 0, sizeof(subst_src));
  memset(subst_dst, 0, sizeof(subst_dst));

  if (!config_file) die("configuration file is not specified");
  f = fopen(config_file, "r");
  if (!f) die("cannot open configuration file %s", config_file);
  config = parse_param(config_file, 0, params, 1, 0, 0, 0);
  if (!config) {
    exit(1);
  }
  fclose(f); f = 0;

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global")) {
      global = (struct config_global_data *) p;
    }
  }

  if (!global) die("no global section in configuration file %s", config_file);

  if (global->sleep_time <= 0) global->sleep_time = 1000;
  if (!global->spool_dir[0]) {
    die("spool_dir is undefined in %s", config_file);
  }
  if (!global->work_dir[0]) {
    die("work_dir is undefined in %s", config_file);
  }

  subst_src[subst_idx] = "/TMPDIR";
  subst_dst[subst_idx] = get_tmp_dir(tmp_dir, sizeof(tmp_dir));
  subst_idx++;
  param_subst(global->work_dir, sizeof(global->work_dir), subst_src, subst_dst);

  snprintf(global->queue_dir, sizeof(global->queue_dir), "%s/queue", global->spool_dir);
  snprintf(global->result_dir, sizeof(global->result_dir), "%s/result", global->spool_dir);

  printf("%d\n", global->sleep_time);
  printf("%s\n", global->spool_dir);
  printf("%s\n", global->work_dir);
  printf("%s\n", global->cache_dir);
}

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static int
get_priority_code(int priority)
{
  priority += 16;
  if (priority < 0) priority = 0;
  if (priority > 31) priority = 31;
  return b32_digits[priority];
}

static void
create_dir(void)
{
  if (os_MakeDirPath(global->work_dir, 0777) < 0) {
    die("cannot create directory %s: %s", global->work_dir, os_ErrorMsg());
  }
  if (os_MakeDirPath(global->spool_dir, 0777) < 0) {
    die("cannot create directory %s: %s", global->work_dir, os_ErrorMsg());
  }

  if (make_all_dir(global->queue_dir, 0777) < 0) {
    exit(1);
  }
  if (make_all_dir(global->result_dir, 0777) < 0) {
    exit(1);
  }
}

static int
get_num_prefix(int num)
{
  if (num < 0) return '-';
  if (num < 10) return '0';
  if (num < 100) return '1';
  if (num < 1000) return '2';
  if (num < 10000) return '3';
  if (num < 100000) return '4';
  if (num < 1000000) return '5';
  return '6';
}

static int
concatenate_files(const unsigned char *dst_path, const unsigned char *src_path)
{
  int retcode = -1;
  FILE *fout = 0;
  FILE *fin = 0;
  int c;

  if (!(fout = fopen(dst_path, "ab"))) {
    err("failed to open %s for appending: %s", dst_path, os_ErrorMsg());
    goto failed;
  }
  if (!(fin = fopen(src_path, "rb"))) {
    err("failed to open %s for reading: %s", src_path, os_ErrorMsg());
    goto failed;
  }

  while ((c = getc(fin)) != EOF)
    putc(c, fout);

  if (ferror(fin)) {
    err("read error from %s", src_path);
    goto failed;
  }
  if (ferror(fout)) {
    err("write error to %s", dst_path);
    goto failed;
  }

  fclose(fin); fin = 0;
  fclose(fout); fout = 0;

  retcode = 0;

 failed:
  if (fin) fclose(fin);
  if (fout) fclose(fout);
  return retcode;
}

static int
run_program(
        const struct nwrun_in_packet *packet,
        const unsigned char *program_path,
        const unsigned char *input_path,
        const unsigned char *output_path,
        const unsigned char *error_path,
        struct nwrun_out_packet *result)
{
  tpTask tsk = 0;

  tsk = task_New();
  if (!tsk) {
    snprintf(result->comment, sizeof(result->comment),
             "cannot create a new task");
    return RUN_CHECK_FAILED;
  }

  task_AddArg(tsk, program_path);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, global->work_dir);
  if (packet->disable_stdin > 0) {
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  } else if (packet->redirect_stdin > 0 || packet->combined_stdin > 0) {
    task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ);
  }
  if (packet->ignore_stdout > 0) {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
  } else if (packet->redirect_stdout > 0 || packet->combined_stdout > 0) {
    task_SetRedir(tsk, 1, TSR_FILE, output_path, TSK_REWRITE, TSK_FULL_RW);
  }
  if (packet->ignore_stderr > 0) {
    task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
  } else if (packet->redirect_stderr > 0) {
    task_SetRedir(tsk, 2, TSR_FILE, error_path, TSK_REWRITE, TSK_FULL_RW);
  }

  if (packet->time_limit_millis > 0) {
    task_SetMaxTimeMillis(tsk, packet->time_limit_millis);
  }
  if (packet->real_time_limit_millis > 0) {
    task_SetMaxRealTime(tsk, (packet->real_time_limit_millis + 999) / 1000);
  }
  if (packet->max_stack_size > 0) {
    task_SetStackSize(tsk, packet->max_stack_size);
  }
  if (packet->max_data_size > 0) {
    task_SetDataSize(tsk, packet->max_data_size);
  }
  if (packet->max_vm_size > 0) {
    task_SetVMSize(tsk, packet->max_vm_size);
  }
  task_SetMaxProcessCount(tsk, 1);
  if (packet->enable_secure_run > 0) {
    task_EnableSecureExec(tsk);
  }
  if (packet->enable_secure_run > 0 && packet->enable_memory_limit_error > 0) {
    task_EnableMemoryLimitError(tsk);
  }
  if (packet->enable_secure_run > 0 && packet->enable_security_violation_error > 0) {
    task_EnableSecurityViolationError(tsk);
  }

  task_EnableAllSignals(tsk);

  if (task_Start(tsk) < 0) {
    snprintf(result->comment, sizeof(result->comment),
             "task start is failed");
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Wait(tsk);

  result->cpu_time_millis = task_GetRunningTime(tsk);
  result->real_time_available = 1;
  result->real_time_millis = task_GetRealTime(tsk);
  result->max_memory_used = task_GetMemoryUsed(tsk);

  result->comment[0] = 0;

  if (packet->enable_secure_run > 0
      && packet->enable_memory_limit_error > 0 && task_IsMemoryLimit(tsk)) {
    task_Delete(tsk);
    return RUN_MEM_LIMIT_ERR;
  }
  if (packet->enable_secure_run > 0
      && packet->enable_security_violation_error && task_IsSecurityViolation(tsk)) {
    task_Delete(tsk);
    return RUN_SECURITY_ERR;
  }
  if (task_IsTimeout(tsk)) {
    task_Delete(tsk);
    return RUN_TIME_LIMIT_ERR;
  }
  if (task_Status(tsk) == TSK_SIGNALED) {
    result->is_signaled = 1;
    result->signal_num = task_TermSignal(tsk);
    snprintf(result->exit_comment, sizeof(result->exit_comment),
             "%s", os_GetSignalString(result->signal_num));
    task_Delete(tsk);
    return RUN_RUN_TIME_ERR;
  }
  result->exit_code = task_ExitCode(tsk);
  task_Delete(tsk);
  return result->exit_code == 0 ? RUN_OK : RUN_RUN_TIME_ERR;
}

static void
handle_packet(
        const unsigned char *dir_path,
        const struct nwrun_in_packet *packet,
        const unsigned char *result_path,
        struct nwrun_out_packet *result)
{
  unsigned char dst_program_path[EJ_PATH_MAX];
  unsigned char src_program_path[EJ_PATH_MAX];
  unsigned char dst_input_path[EJ_PATH_MAX];
  unsigned char src_input_path[EJ_PATH_MAX];
  unsigned char run_output_path[EJ_PATH_MAX];
  unsigned char full_output_path[EJ_PATH_MAX];
  unsigned char run_error_path[EJ_PATH_MAX];
  //unsigned char log_file_path[EJ_PATH_MAX];
  unsigned char error_file_path[EJ_PATH_MAX];
  unsigned char result_file_path[EJ_PATH_MAX];

  ssize_t error_file_size;
  ssize_t output_file_size;

  FILE *f = 0;
  int cur_status = RUN_OK;

  /* copy the executable */
  snprintf(dst_program_path, sizeof(dst_program_path), "%s/%s",
           global->work_dir, packet->program_name);
  snprintf(src_program_path, sizeof(src_program_path), "%s/%s",
           dir_path, packet->program_name);
  if (fast_copy_file(src_program_path, dst_program_path) < 0) {
    snprintf(result->comment, sizeof(result->comment),
             "copy failed: %s -> %s", src_program_path, dst_program_path);
    goto cleanup;
  }

  /* copy the input file */
  snprintf(dst_input_path, sizeof(dst_input_path), "%s/%s",
           global->work_dir, packet->input_file_name);
  snprintf(src_input_path, sizeof(src_input_path), "%s/%s",
           dir_path, packet->test_file_name);
  if (packet->enable_unix2dos > 0) {
    if (generic_copy_file(CONVERT, "", src_input_path, "",
                          CONVERT, "", dst_input_path, "") < 0) {
      snprintf(result->comment, sizeof(result->comment),
               "unix2dos copy failed: %s -> %s", src_input_path, dst_input_path);
      goto cleanup;
    }
  } else {
    if (fast_copy_file(src_input_path, dst_input_path) < 0) {
      snprintf(result->comment, sizeof(result->comment),
               "copy failed: %s -> %s", src_input_path, dst_input_path);
      goto cleanup;
    }
  }

  if (packet->combined_stdin > 0) {
    snprintf(dst_input_path, sizeof(dst_input_path), "%s/%s.stdin",
             global->work_dir, packet->input_file_name);
    if (packet->enable_unix2dos > 0) {
      if (generic_copy_file(CONVERT, "", src_input_path, "",
                            CONVERT, "", dst_input_path, "") < 0) {
        snprintf(result->comment, sizeof(result->comment),
                 "unix2dos copy failed: %s -> %s", src_input_path,
                 dst_input_path);
        goto cleanup;
      }
    } else {
      if (fast_copy_file(src_input_path, dst_input_path) < 0) {
        snprintf(result->comment, sizeof(result->comment),
                 "copy failed: %s -> %s", src_input_path, dst_input_path);
        goto cleanup;
      }
    }
  }

  snprintf(run_output_path, sizeof(run_output_path), "%s/%s",
           global->work_dir, packet->output_file_name);
  if (packet->combined_stdout > 0) {
    snprintf(run_output_path, sizeof(run_output_path), "%s/%s.stdout",
             global->work_dir, packet->output_file_name);
  }

  snprintf(run_error_path, sizeof(run_error_path), "%s/%s",
           global->work_dir, packet->error_file_name);

  cur_status = run_program(packet, dst_program_path,
                           dst_input_path, run_output_path,
                           run_error_path, result);

  if (packet->combined_stdout > 0) {
    snprintf(full_output_path, sizeof(full_output_path), "%s/%s",
             global->work_dir, packet->output_file_name);
    concatenate_files(full_output_path, run_output_path);
    snprintf(run_output_path, sizeof(run_output_path), "%s", full_output_path);
  }

  info("Testing finished: CPU time = %d, real time = %d",
       result->cpu_time_millis, result->real_time_millis);

  /* copy the stderr output */
  result->error_file_existed = 0;
  if (packet->ignore_stderr <= 0) {
    error_file_size = generic_file_size("", run_error_path, "");
    if (error_file_size >= 0) {
      result->error_file_existed = 1;
      result->error_file_orig_size = error_file_size;
      if (error_file_size > packet->max_error_file_size) {
        result->error_file_truncated = 1;
        if (generic_truncate(run_error_path, packet->max_error_file_size) < 0) {
          snprintf(result->comment, sizeof(result->comment),
                   "truncate failed: %s", run_error_path);
          goto cleanup;
        }
        if (!(f = fopen(run_error_path, "a"))) {
          snprintf(result->comment, sizeof(result->comment),
                   "appending error file failed: %s", run_error_path);
          goto cleanup;
        }
        fprintf(f, "\n\nFile truncated!\n");
        fclose(f); f = 0;
        result->error_file_size = generic_file_size("", run_error_path, "");
      } else {
        result->error_file_truncated = 0;
        result->error_file_size = error_file_size;
      }

      if (packet->error_file_name[0]) {
        snprintf(error_file_path, sizeof(error_file_path), "%s/%s",
                 result_path, packet->error_file_name);
		info("Copy: %s -> %s", run_error_path, error_file_path);
        if (fast_copy_file(run_error_path, error_file_path) < 0) {
          snprintf(result->comment, sizeof(result->comment),
                   "copy failed: %s -> %s", run_error_path, error_file_path);
          goto cleanup;
        }
      }
    }
  }

  /* copy the program output */
  info("Copying program output");
  output_file_size = generic_file_size("", run_output_path, "");
  if (output_file_size < 0) {
    if (!result->comment[0]) {
      snprintf(result->comment, sizeof(result->comment),
               "no output file");
    }
    if (cur_status == RUN_OK) cur_status = RUN_PRESENTATION_ERR;
    result->status = cur_status;
    goto cleanup;
  }

  result->output_file_existed = 1;
  result->output_file_orig_size = output_file_size;
  if (output_file_size > packet->max_output_file_size) {
    result->output_file_too_big = 1;
    snprintf(result->comment, sizeof(result->comment),
             "output file is too big (%ld)", ((long) output_file_size));
    if (cur_status == RUN_OK) cur_status = RUN_PRESENTATION_ERR;
    result->status = cur_status;
    goto cleanup;
  }

  snprintf(result_file_path, sizeof(result_file_path), "%s/%s",
           result_path, packet->result_file_name);
  info("Copy: %s -> %s", run_output_path, result_file_path);
  if (fast_copy_file(run_output_path, result_file_path) < 0) {
    snprintf(result->comment, sizeof(result->comment),
             "copy failed: %s -> %s", run_output_path, result_file_path);
    result->status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  result->status = cur_status;

 cleanup:
  if (f) fclose(f);
  remove_directory_recursively(global->work_dir, 1);
}

static void
read_packet(const unsigned char *dir_path)
{
  unsigned char packet_conf_file[EJ_PATH_MAX];
  FILE *f = 0;
  struct generic_section_config *packet_config = 0;
  struct nwrun_in_packet *packet = 0;
  unsigned char result_name[EJ_PATH_MAX];
  unsigned char result_in_dir[EJ_PATH_MAX];
  unsigned char result_dir_dir[EJ_PATH_MAX];
  unsigned char contest_dir[EJ_PATH_MAX];
  struct nwrun_out_packet result;
  unsigned char result_packet_path[EJ_PATH_MAX];
  int clean_result_dir = 0;

  memset(&result, 0, sizeof(result));

  snprintf(packet_conf_file,sizeof(packet_conf_file),"%s/packet.cfg",dir_path);
  packet_config = nwrun_in_packet_parse(packet_conf_file, &packet);
  if (!packet_config) goto cleanup;

  nwrun_in_packet_print(stderr, (const struct nwrun_in_packet *) packet_config);

  /* setup packet defaults */
  if (packet->contest_id <= 0) {
    err("contest_id is not set");
    goto cleanup;
  }
  if (packet->prob_id <= 0) {
    err("prob_id is not set");
    goto cleanup;
  }
  if (packet->test_num <= 0) {
    err("test_num is not set");
    goto cleanup;
  }
  if (packet->judge_id <= 0) {
    err("judge_id is not set");
    goto cleanup;
  }
  if (!packet->program_name[0]) {
    err("program_name is not set");
    goto cleanup;
  }
  if (!packet->test_file_name[0]) {
    err("test_file_name is not set");
    goto cleanup;
  }
  if (!packet->input_file_name[0]) {
    snprintf(packet->input_file_name, sizeof(packet->input_file_name),
             "%s", DEFAULT_INPUT_FILE_NAME);
  }
  if (!packet->result_file_name[0]) {
    err("result_file_name is not set");
    goto cleanup;
  }
  if (!packet->output_file_name[0]) {
    snprintf(packet->output_file_name, sizeof(packet->output_file_name),
             "%s", DEFAULT_OUTPUT_FILE_NAME);
  }
  if (!packet->error_file_name[0]) {
    snprintf(packet->error_file_name, sizeof(packet->error_file_name),
             "%s", DEFAULT_ERROR_FILE_NAME);
  }

  if (packet->max_output_file_size <= 0) {
    packet->max_output_file_size = DEFAULT_MAX_OUTPUT_FILE_SIZE;
  }
  if (packet->max_error_file_size <= 0) {
    packet->max_error_file_size = DEFAULT_MAX_ERROR_FILE_SIZE;
  }
  if (packet->time_limit_millis <= 0) {
    err("time_limit_millis is invalid (%d)", packet->time_limit_millis);
    goto cleanup;
  }

  /* create the output directory */
  snprintf(result_name, sizeof(result_name), "%c%c%d%c%d%c%d%c%d%c%d",
           get_priority_code(packet->priority - 17),
           get_num_prefix(packet->contest_id), packet->contest_id,
           get_num_prefix(packet->run_id - 1), packet->run_id - 1,
           get_num_prefix(packet->prob_id), packet->prob_id,
           get_num_prefix(packet->test_num), packet->test_num,
           get_num_prefix(packet->judge_id), packet->judge_id);
  if (packet->use_contest_id_in_reply) {
    snprintf(contest_dir, sizeof(contest_dir), "%s/%06d", global->result_dir, packet->contest_id);
    if (make_all_dir(contest_dir, 0777) < 0) {
      goto cleanup;
    }
    snprintf(result_in_dir, sizeof(result_in_dir), "%s/in/%s_%s",
             contest_dir, os_NodeName(), result_name);
    snprintf(result_dir_dir, sizeof(result_dir_dir), "%s/dir/%s",
             contest_dir, result_name);
  } else {
    snprintf(result_in_dir, sizeof(result_in_dir), "%s/in/%s_%s",
             global->result_dir, os_NodeName(), result_name);
    snprintf(result_dir_dir, sizeof(result_dir_dir), "%s/dir/%s",
             global->result_dir, result_name);
  }

  if (make_dir(result_in_dir, 0777) < 0) {
    goto cleanup;
  }
  clean_result_dir = 1;

  // set default values
  snprintf(result.hostname, sizeof(result.hostname), "%s", os_NodeName());
  result.contest_id = packet->contest_id;
  result.run_id = packet->run_id;
  result.prob_id = packet->prob_id;
  result.test_num = packet->test_num;
  result.judge_id = packet->judge_id;
  result.status = RUN_CHECK_FAILED;
  snprintf(result.comment, sizeof(result.comment), "Default status was not changed");

  handle_packet(dir_path, packet, result_in_dir, &result);

  snprintf(result_packet_path, sizeof(result_packet_path), "%s/packet.cfg",
           result_in_dir);
  if (!(f = fopen(result_packet_path, "wb"))) {
    err("cannot open file %s: %s", result_packet_path, os_ErrorMsg());
    goto cleanup;
  }
  nwrun_out_packet_print(f, &result);
  fclose(f); f = 0;

  nwrun_out_packet_print(stderr, &result);

  if (rename(result_in_dir, result_dir_dir) < 0) {
    err("rename: %s -> %s failed: %s", result_in_dir, result_dir_dir, os_ErrorMsg());
    goto cleanup;
  }
  clean_result_dir = 0;

 cleanup:
  if (clean_result_dir) {
    remove_directory_recursively(result_in_dir, 0);
  }
  nwrun_in_packet_free(packet_config);
  if (f) fclose(f);
}

static void
do_loop(void)
{
  unsigned char new_entry_name[EJ_PATH_MAX];
  unsigned char out_entry_name[EJ_PATH_MAX];
  unsigned char new_path[EJ_PATH_MAX];
  unsigned char out_path[EJ_PATH_MAX];
  int r;
  int serial = 0;

  while (1) {
    r = scan_dir(global->queue_dir, new_entry_name, sizeof(new_entry_name), 0);
    if (r < 0) {
      die("scan_dir failed on %s", global->queue_dir);
      /* FIXME: recover and continue */
    }

    if (!r) {
      os_Sleep(global->sleep_time);
      continue;
    }

    snprintf(out_entry_name, sizeof(out_entry_name), "%s_%s", os_NodeName(), new_entry_name);
    snprintf(new_path, sizeof(new_path), "%s/dir/%s", global->queue_dir, new_entry_name);
    snprintf(out_path, sizeof(out_path), "%s/out/%s", global->queue_dir, out_entry_name);

    while (rename(new_path, out_path) < 0) {
      if (errno == ENOENT) {
        err("file %s is stolen?", new_path);
        out_path[0] = 0;
        os_Sleep(global->sleep_time);
        break;
      }

      if (errno == ENOTEMPTY || errno == EEXIST) {
        err("directory %s already exists", out_path);
        snprintf(out_entry_name, sizeof(out_entry_name), "%s_%d_%s",
                 os_NodeName(), ++serial, new_entry_name);
        snprintf(out_path, sizeof(out_path), "%s/out/%s", global->queue_dir,
                 out_entry_name);
        continue;
      }

      die("rename: %s -> %s failed: %s", new_path, out_path, strerror(errno));
    }

    if (out_path[0]) {
      read_packet(out_path);
      remove_directory_recursively(out_path, 0);
    }
  }
}

int
main(int argc, char *argv[])
{
  int i;

  if (argc <= 0 || !argv[0]) {
    fprintf(stderr, "invalid program name\n");
    return 1;
  }
  program_name = os_GetLastname(argv[0]);
  get_program_dir(argv[0]);

  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--version")) {
      print_version();
    } else if (!strcmp(argv[i], "--help")) {
      print_help();
    } else {
      die("invalid option: %s", argv[i]);
    }
  }

  get_config_file();
  parse_config();
  create_dir();
  do_loop();

  return 0;
}
