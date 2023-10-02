/* -*- c -*- */

/* Copyright (C) 2000-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/random.h"
#include "ejudge/ej_process.h"
#include "ejudge/agent_client.h"
#include "ejudge/version.h"

#include "ejudge/meta_generic.h"
#include "ejudge/meta/compile_packet_meta.h"
#include "ejudge/meta/prepare_meta.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
#include "flatbuf-gen/compile_heartbeat_builder.h"
#include "flatcc/flatcc_builder.h"
#pragma GCC diagnostic pop

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
#include <dirent.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/mman.h>

enum { MAX_LOG_SIZE = 1024 * 1024, MAX_EXE_SIZE = 128 * 1024 * 1024 };

enum { DEFAULT_WAIT_TIMEOUT_MS = 300000 }; // 5m
enum { HEARTBEAT_UPDATE_MS = 30000 }; // 30s

struct serve_state serve_state;
static int initialize_mode = 0;

static int daemon_mode;
static int restart_mode;
static int slave_mode;

static unsigned char *compile_server_id;
static __attribute__((unused)) unsigned char compile_server_spool_dir[PATH_MAX];
static unsigned char compile_server_queue_dir[PATH_MAX];
static unsigned char compile_server_queue_dir_dir[PATH_MAX];
static unsigned char compile_server_src_dir[PATH_MAX];
static unsigned char heartbeat_dir[PATH_MAX];
static unsigned char *agent_name;
static struct AgentClient *agent;
static unsigned char *instance_id;
static int verbose_mode;
static unsigned char *ip_address;
static long long last_heartbeat_update_ms;
static long long last_handled_request_ms;
static long long accumulated_ms;
static long long request_count;
static int heartbeat_mode = 1;
static unsigned char heartbeat_file_name[PATH_MAX];
static long long start_time_ms;
static unsigned char pending_stop_flag; // bool
static unsigned char pending_down_flag; // bool
static unsigned char pending_reboot_flag; // bool
static unsigned char *heartbeat_instance_id;
static unsigned char *local_cache = NULL;

struct testinfo_subst_handler_compile
{
  struct testinfo_subst_handler b;
  const struct compile_request_packet *request;
  const struct section_language_data *lang;
};

static int *lang_id_map = NULL;
static int lang_id_map_size = 0;

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
  if (tinf && tinf->style_checker_env.u > 0) {
    for (int i = 0; i < tinf->style_checker_env.u; ++i)
      task_PutEnv(tsk, tinf->style_checker_env.v[i]);
  }
  if (req->vcs_mode) {
    task_PutEnv(tsk, "EJUDGE_VCS_MODE=1");
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
    if (req->not_ok_is_cf > 0) {
      retval = RUN_CHECK_FAILED;
      fprintf(log_f, "\nStyle checker detected errors\n");
      fprintf(log_f, "Check failed on non-OK result mode enabled\n");
    } else {
      retval = RUN_STYLE_ERR;
      fprintf(log_f, "\nStyle checker detected errors\n");
    }
  }

cleanup:
  task_Delete(tsk);
  return retval;
}

// non-recursive
static int
copy_all_files(
        FILE *log_f,
        const unsigned char *src_dir,
        const unsigned char *dst_dir)
{
  unsigned char spath[PATH_MAX];
  unsigned char dpath[PATH_MAX];
  int retval = -1;
  int rfd = -1;
  int wfd = -1;
  unsigned char buf[65536];
  DIR *d = opendir(src_dir);
  if (!d) {
    err("copy_all_files: cannot open '%s': %s", src_dir, os_ErrorMsg());
    goto cleanup;
  }
  struct dirent *dd;
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) {
      continue;
    }

    if (snprintf(spath, sizeof(spath), "%s/%s", src_dir, dd->d_name) >= (int) sizeof(spath)) {
      err("copy_all_files: source path '%s/%s' too long", src_dir, dd->d_name);
      goto cleanup;
    }
    if (snprintf(dpath, sizeof(dpath), "%s/%s", dst_dir, dd->d_name) >= (int) sizeof(dpath)) {
      err("copy_all_files: destination path '%s/%s' too long", dst_dir, dd->d_name);
      goto cleanup;
    }

    // symlink is ok, its content is copied
    struct stat stb;
    if (stat(spath, &stb) < 0) {
      continue;
    }
    if (!S_ISREG(stb.st_mode)) {
      err("copy_all_files: file '%s' is not regular", spath);
      fprintf(log_f, "\nfile '%s' is not regular\n", spath);
      goto cleanup;
    }
    int mode = (stb.st_mode & 0777) | 0600;
    rfd = open(spath, O_RDONLY | O_NOCTTY | O_NONBLOCK);
    if (rfd < 0) {
      err("copy_all_files: failed to open '%s': %s", spath, os_ErrorMsg());
      goto cleanup;
    }
    if (fstat(rfd, &stb) < 0) {
      err("copy_all_files: fstat failed");
      goto cleanup;
    }
    if (!S_ISREG(stb.st_mode)) {
      err("copy_all_files: source file is not regular");
      goto cleanup;
    }
    wfd = open(dpath, O_WRONLY | O_CREAT | O_TRUNC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (wfd < 0) {
      err("copy_all_files: failed to open '%s': %s", dpath, os_ErrorMsg());
      goto cleanup;
    }
    if (fstat(wfd, &stb) < 0) {
      err("copy_all_files: fstat failed");
      goto cleanup;
    }
    if (!S_ISREG(stb.st_mode)) {
      err("copy_all_files: destination file is not regular");
      goto cleanup;
    }
    fchmod(wfd, mode);

    while (1) {
      int rsz = read(rfd, buf, sizeof(buf));
      if (rsz < 0) {
        err("copy_all_files: read error: %s", os_ErrorMsg());
        goto cleanup;
      }
      if (!rsz) break;
      unsigned char *wptr = buf;
      while (rsz > 0) {
        int wsz = write(wfd, wptr, rsz);
        if (wsz <= 0) {
          err("copy_all_files: write error: %s", os_ErrorMsg());
          goto cleanup;
        }
        rsz -= wsz;
        wptr += wsz;
      }
    }

    close(rfd); rfd = -1;
    close(wfd); wfd = -1;
  }

  closedir(d);
  d = NULL;
  retval = 0;

cleanup:;
  if (rfd >= 0) close(rfd);
  if (wfd >= 0) close(wfd);
  if (d) closedir(d);
  return retval;
}

static int
detect_prepended_size(
        const unsigned char *working_dir,
        const unsigned char *input_file,
        const unsigned char *output_file)
{
  enum { MAX_FILE_SIZE = 1024 * 1024 };
  enum { MAX_SIZE_DIFF = 1024 };
  unsigned char input_path[PATH_MAX];
  unsigned char output_path[PATH_MAX];
  int ifd = -1;
  int ofd = -1;
  struct stat istb, ostb;
  size_t isize = 0, osize = 0;
  unsigned char *ibuf = MAP_FAILED, *obuf = MAP_FAILED;
  int prepended_size = 0;

  if (snprintf(input_path, sizeof(input_path), "%s/%s", working_dir, input_file) >= (int)sizeof(input_path)) {
    goto done;
  }
  if (snprintf(output_path, sizeof(output_path), "%s/%s", working_dir, output_file) >= (int)sizeof(output_path)) {
    goto done;
  }

  ifd = open(input_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
  if (ifd < 0) {
    err("detect_prepended_size: open '%s' failed: %s", input_path, os_ErrorMsg());
    goto done;
  }
  if (fstat(ifd, &istb) < 0) {
    goto done;
  }
  if (!S_ISREG(istb.st_mode)) {
    err("detect_prepended_size: '%s' not a regular file", input_path);
    goto done;
  }
  if (istb.st_size > MAX_FILE_SIZE) {
    goto done;
  }
  if (istb.st_size <= 0) {
    goto done;
  }

  ofd = open(output_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
  if (ofd < 0) {
    err("detect_prepended_size: open '%s' failed: %s", output_path, os_ErrorMsg());
    goto done;
  }
  if (fstat(ofd, &ostb) < 0) {
    goto done;
  }
  if (!S_ISREG(ostb.st_mode)) {
    err("detect_prepended_size: '%s' not a regular file", output_path);
    goto done;
  }
  if (ostb.st_size <= 0) {
    goto done;
  }

  if (ostb.st_size > MAX_FILE_SIZE) {
    goto done;
  }
  if (ostb.st_size <= istb.st_size) {
    goto done;
  }
  if (istb.st_size + MAX_SIZE_DIFF < ostb.st_size) {
    goto done;
  }

  // both files are non-empty and less than 64KiB in size
  // and the output file is no larger than 1KiB
  isize = istb.st_size;
  ibuf = mmap(NULL, isize, PROT_READ, MAP_PRIVATE, ifd, 0);
  if (ibuf == MAP_FAILED) {
    err("detect_prepended_size: mmap '%s' failed: %s", input_path, os_ErrorMsg());
    goto done;
  }

  osize = ostb.st_size;
  obuf = mmap(NULL, osize, PROT_READ, MAP_PRIVATE, ofd, 0);
  if (obuf == MAP_FAILED) {
    err("detect_prepended_size: mmap '%s' failed: %s", output_path, os_ErrorMsg());
    goto done;
  }

  prepended_size = osize - isize;
  if (memcmp(ibuf, obuf + prepended_size, isize) != 0) {
    prepended_size = 0;
    goto done;
  }

  info("detect_prepended_size: prepended_size == %d", prepended_size);

done:
  if (ibuf != MAP_FAILED) munmap(ibuf, isize);
  if (obuf != MAP_FAILED) munmap(obuf, osize);
  if (ifd >= 0) close(ifd);
  if (ofd >= 0) close(ofd);
  return prepended_size;
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
        const testinfo_t *tinf,
        int *p_prepended_size)
{
  const struct section_global_data *global = serve_state.global;
  tpTask tsk = 0;

  if (req->extra_src_dir && req->extra_src_dir[0]) {
    int r = copy_all_files(log_f, req->extra_src_dir, working_dir);
    if (r < 0) {
      err("failed to copy extra_src_dir from %s to %s",
          req->extra_src_dir, working_dir);
      fprintf(log_f, "\nfailed to copy extra_src_dir %s to working_dir %s\n",
              req->extra_src_dir, working_dir);
      return RUN_CHECK_FAILED;
    }
  }

  tsk = task_New();
  if (req->vcs_mode) {
    unsigned char helper_path[PATH_MAX];
    snprintf(helper_path, sizeof(helper_path),
             "%s/ej-vcs-compile", EJUDGE_SERVER_BIN_PATH);
    task_AddArg(tsk, helper_path);
    task_AddArg(tsk, input_file);
    task_AddArg(tsk, output_file);
    task_AddArg(tsk, lang->short_name);
    if (req->vcs_compile_cmd && req->vcs_compile_cmd[0]) {
      task_AddArg(tsk, req->vcs_compile_cmd);
    }
  } else if (lang->enable_custom > 0 && req->compile_cmd && req->compile_cmd[0]) {
    unsigned char cmd_name[PATH_MAX];
    os_rGetLastname(req->compile_cmd, cmd_name, sizeof(cmd_name));
    if (generic_copy_file(0, NULL, req->compile_cmd, NULL, 0, working_dir, cmd_name, NULL) < 0) {
      err("failed to copy custom compiler '%s'", req->compile_cmd);
      fprintf(log_f, "\nFailed to copy custom compiler '%s'\n", req->compile_cmd);
      task_Delete(tsk);
      return RUN_CHECK_FAILED;
    }
    unsigned char cmd_path[PATH_MAX];
    if (snprintf(cmd_path, sizeof(cmd_path), "%s/%s", working_dir, cmd_name) >= (int) sizeof(cmd_path)) {
      abort();
    }
    make_executable(cmd_path);
    if (snprintf(cmd_path, sizeof(cmd_path), "./%s", cmd_name) >= (int) sizeof(cmd_path)) {
      abort();
    }
    task_AddArg(tsk, cmd_path);
    task_AddArg(tsk, input_file);
    task_AddArg(tsk, output_file);
  } else {
    task_AddArg(tsk, lang->cmd);
    task_AddArg(tsk, input_file);
    task_AddArg(tsk, output_file);
  }
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
  if (VALID_SIZE(req->max_rss_size)) {
    task_SetRSSSize(tsk, req->max_rss_size);
  } else if (VALID_SIZE(lang->max_rss_size)) {
    task_SetRSSSize(tsk, lang->max_rss_size);
  } else if (VALID_SIZE(global->compile_max_rss_size)) {
    task_SetRSSSize(tsk, global->compile_max_rss_size);
  }

  if (ejudge_config->enable_compile_container) {
    task_SetSuidHelperDir(tsk, EJUDGE_SERVER_BIN_PATH);
    task_EnableContainer(tsk);
    task_AppendContainerOptions(tsk, "mCs0mPmSmd");
    if (req->container_options && req->container_options[0]) {
      task_AppendContainerOptions(tsk, req->container_options);
    }
  }

  if (req->env_num > 0) {
    for (int i = 0; i < req->env_num; i++)
      task_PutEnv(tsk, req->env_vars[i]);
  }
  if (tinf && tinf->compiler_env.u > 0) {
    for (int i = 0; i < tinf->compiler_env.u; ++i)
      task_PutEnv(tsk, tinf->compiler_env.v[i]);
  }
  if (req->vcs_mode) {
    task_PutEnv(tsk, "EJUDGE_VCS_MODE=1");
  }
  task_SetWorkingDir(tsk, working_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  if (tinf && tinf->compiler_must_fail > 0) {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, 0777);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, 0777);
  }
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, 0777);
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
    task_Delete(tsk);
    if (req->not_ok_is_cf > 0) {
      fprintf(log_f, "\nCompilation process timed out\n");
      fprintf(log_f, "Check failed on non-OK result mode enabled\n");
      return RUN_CHECK_FAILED;
    } else {
      fprintf(log_f, "\nCompilation process timed out\n");
      return RUN_COMPILE_ERR;
    }
  } else if (task_IsAbnormal(tsk)) {
    info("Compilation failed");
    task_Delete(tsk);
    if (req->not_ok_is_cf > 0) {
      fprintf(log_f, "\nCompilation failed\n");
      fprintf(log_f, "Check failed on non-OK result mode enabled\n");
      return RUN_CHECK_FAILED;
    } else {
      return RUN_COMPILE_ERR;
    }
  } else {
    info("Compilation sucessful");
    task_Delete(tsk);
    if (req->preserve_numbers && p_prepended_size) {
      *p_prepended_size = detect_prepended_size(working_dir, input_file, output_file);
    }
    return RUN_OK;
  }
}

static void
save_heartbeat_file(const unsigned char *data, size_t size)
{
  unsigned char path[PATH_MAX];
  unsigned char dpath[PATH_MAX];
  __attribute__((unused)) int r;
  r = snprintf(path, sizeof(path), "%s/in/%s", heartbeat_dir, heartbeat_file_name);
  r = snprintf(dpath, sizeof(dpath), "%s/dir/%s", heartbeat_dir, heartbeat_file_name);
  int fd = -1;
  void *mem = MAP_FAILED;

  fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY, 0666);
  if (fd < 0) {
    err("open '%s' failed: %s", path, os_ErrorMsg());
    goto done;
  }
  if (ftruncate(fd, size) < 0) {
    err("ftruncate '%s', %lld failed: %s", path, (long long) size, os_ErrorMsg());
    goto done;
  }
  mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mem == MAP_FAILED) {
    err("mmap failed: %s", os_ErrorMsg());
    goto done;
  }
  close(fd); fd = -1;

  memcpy(mem, data, size);
  munmap(mem, size); mem = MAP_FAILED;

  if (rename(path, dpath) < 0) {
    err("rename '%s'->'%s' failed: %s", path, dpath, os_ErrorMsg());
    goto done;
  }
  path[0] = 0;

  r = snprintf(path, sizeof(path), "%s/dir/%s@S", heartbeat_dir, heartbeat_file_name);
  if (access(path, F_OK) >= 0) {
    pending_stop_flag = 1;
    r = unlink(path);
  }
  r = snprintf(path, sizeof(path), "%s/dir/%s@D", heartbeat_dir, heartbeat_file_name);
  if (access(path, F_OK) >= 0) {
    pending_down_flag = 1;
    r = unlink(path);
  }
  r = snprintf(path, sizeof(path), "%s/dir/%s@R", heartbeat_dir, heartbeat_file_name);
  if (access(path, F_OK) >= 0) {
    pending_reboot_flag = 1;
    r = unlink(path);
  }

done:;
  if (path[0]) unlink(path);
  if (fd >= 0) close(fd);
  if (mem != MAP_FAILED) munmap(mem, size);
}

#pragma GCC push_options
#pragma GCC optimize "no-inline"
static void
save_heartbeat(void)
{
  if (!heartbeat_mode) return;
  if (!heartbeat_dir[0]) return;

  struct timeval tv;
  gettimeofday(&tv, NULL);
  long long current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
  if (last_heartbeat_update_ms + HEARTBEAT_UPDATE_MS > current_time_ms) {
    return;
  }

  flatcc_builder_t builder;
  flatcc_builder_init(&builder);
  unsigned char *buffer = NULL;
  size_t size = 0;

  ej_compile_Heartbeat_start_as_root(&builder);

  ej_compile_Heartbeat_timestamp_ms_add(&builder, current_time_ms);
  ej_compile_Heartbeat_last_handled_request_ms_add(&builder, last_handled_request_ms);
  ej_compile_Heartbeat_start_time_ms_add(&builder, start_time_ms);
  ej_compile_Heartbeat_accumulated_ms_add(&builder, accumulated_ms);
  ej_compile_Heartbeat_request_count_add(&builder, request_count);
  if (heartbeat_instance_id && *heartbeat_instance_id) {
    ej_compile_Heartbeat_instance_id_create_str(&builder, heartbeat_instance_id);
  } else if (instance_id && *instance_id) {
    ej_compile_Heartbeat_instance_id_create_str(&builder, instance_id);
  }
  if (compile_server_id && *compile_server_id) {
    ej_compile_Heartbeat_queue_create_str(&builder, compile_server_id);
  }
  if (ip_address && *ip_address) {
    ej_compile_Heartbeat_ip_address_create_str(&builder, ip_address);
  }
  ej_compile_Heartbeat_pid_add(&builder, getpid());
  ej_compile_Heartbeat_end_as_root(&builder);

  buffer = flatcc_builder_get_direct_buffer(&builder, &size);

  if (agent) {
    __attribute__((unused)) long long last_saved_time_ms = 0;

    agent->ops->put_heartbeat(agent, heartbeat_file_name, buffer, size,
                              &last_saved_time_ms,
                              &pending_stop_flag, &pending_down_flag,
                              &pending_reboot_flag);
  } else {
    save_heartbeat_file(buffer, size);
  }

  flatcc_builder_clear(&builder);
  last_heartbeat_update_ms = current_time_ms;
}
#pragma GCC pop_options

static void
delete_heartbeat(void)
{
  if (!heartbeat_mode) return;
  if (!heartbeat_dir[0]) return;

  if (agent) {
    agent->ops->delete_heartbeat(agent, heartbeat_file_name);
  } else {
    unsigned char path[PATH_MAX];
    __attribute__((unused)) int r;
    r = snprintf(path, sizeof(path), "%s/dir/%s", heartbeat_dir, heartbeat_file_name);
    r = unlink(path);
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
        const unsigned char *contest_server_id,
        const unsigned char *run_name,            // the incoming packet name
        const unsigned char *src_path,            // path to the source file in the spool directory
        const unsigned char *src_buf,
        size_t src_len,
        const unsigned char *exe_sfx,
        const unsigned char *exe_path,            // path to the resulting exe file in the spool directory
        const unsigned char *working_dir,         // the working directory
        const unsigned char *log_work_path,       // the path to the log file (open in APPEND mode)
        unsigned char *exe_work_name,             // OUTPUT: the name of the executable
        int *p_override_exe,
        int *p_exe_copied)
{
  struct ZipData *zf = NULL;
  int prepended_size = 0;

  if (req->output_only) {
    if (req->style_checker && req->style_checker[0]) {
      unsigned char src_work_name[PATH_MAX];
      snprintf(src_work_name, sizeof(src_work_name), "%llx", random_u64());
      unsigned char src_work_path[PATH_MAX];
      snprintf(src_work_path, sizeof(src_work_path), "%s/%s", working_dir, src_work_name);

      if (src_buf) {
        if (generic_write_file(src_buf, src_len, 0, NULL, src_work_path, "") < 0) {
          fprintf(log_f, "cannot write to '%s'\n", src_work_path);
          rpl->status = RUN_CHECK_FAILED;
          goto cleanup;
        }
      } else {
        if (generic_copy_file(0, NULL, src_path, "", 0, NULL, src_work_path, "") < 0) {
          fprintf(log_f, "cannot copy '%s' -> '%s'\n", src_path, src_work_path);
          rpl->status = RUN_CHECK_FAILED;
          goto cleanup;
        }
      }

      int r = invoke_style_checker(log_f, cs, lang, req, src_work_name, working_dir, log_work_path, NULL);
      if (r != RUN_OK) {
        rpl->status = r;
        goto cleanup;
      }
    }

    if (src_buf) {
      if (agent) {
        if (agent->ops->put_output(agent,
                                   contest_server_id,
                                   rpl->contest_id,
                                   run_name,
                                   exe_sfx,
                                   src_buf, src_len) < 0) {
          fprintf(log_f, "put_output failed\n");
          rpl->status = RUN_CHECK_FAILED;
          goto cleanup;
        }
      } else {
        if (generic_write_file(src_buf, src_len, 0, NULL, exe_path, "") < 0) {
          fprintf(log_f, "cannot write to '%s': %s\n", exe_path, strerror(errno));
          rpl->status = RUN_CHECK_FAILED;
          goto cleanup;
        }
      }
      *p_exe_copied = 1;
      rpl->status = RUN_OK;
      goto cleanup;
    }
    if (agent) {
      if (agent->ops->put_output_2(agent,
                                   contest_server_id,
                                   rpl->contest_id,
                                   run_name,
                                   exe_sfx,
                                   src_path) < 0) {
        fprintf(log_f, "put_output_2 failed\n");
        rpl->status = RUN_CHECK_FAILED;
        goto cleanup;
      }
      *p_exe_copied = 1;
      rpl->status = RUN_OK;
      goto cleanup;
    }
    if (rename(src_path, exe_path) >= 0) {
      *p_exe_copied = 1;
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
  snprintf(src_work_name, sizeof(src_work_name), "%llx%s", random_u64(), lang->src_sfx);
  unsigned char src_work_path[PATH_MAX];
  snprintf(src_work_path, sizeof(src_work_path), "%s/%s", working_dir, src_work_name);

  if (src_buf) {
    if (generic_write_file(src_buf, src_len, 0, NULL, src_work_path, "") < 0) {
      fprintf(log_f, "cannot write to '%s': %s\n", src_work_path, strerror(errno));
      rpl->status = RUN_CHECK_FAILED;
      goto cleanup;
    }
  } else if (rename(src_path, src_work_path) >= 0) {
  } else if (errno != EXDEV) {
    fprintf(stderr, "cannot move '%s' -> '%s': %s\n", src_path, src_work_path, strerror(errno));
    rpl->status = RUN_CHECK_FAILED;
    goto cleanup;
  } else {
    if (generic_copy_file(REMOVE, NULL, src_path, "", 0, NULL, src_work_path, "") < 0) {
      fprintf(log_f, "cannot copy '%s' -> '%s'\n", src_path, src_work_path);
      rpl->status = RUN_CHECK_FAILED;
      goto cleanup;
    }
  }

  if (!req->multi_header) {
    snprintf(exe_work_name, PATH_MAX, "%llx%s", random_u64(), lang->exe_sfx);
    unsigned char exe_work_path[PATH_MAX];
    snprintf(exe_work_path, sizeof(exe_work_path), "%s/%s", working_dir, exe_work_name);

    /*
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
    */

    if (req->style_check_only <= 0) {
      int r = invoke_compiler(log_f, cs, lang, req, src_work_name, exe_work_name, working_dir, log_work_path, NULL, &prepended_size);
      rpl->status = r;
      if (r != RUN_OK) goto cleanup;
      rpl->prepended_size = prepended_size;
    }

    if (req->vcs_mode <= 0 && req->style_checker && req->style_checker[0]) {
      int r = invoke_style_checker(log_f, cs, lang, req, src_work_name, working_dir, log_work_path, NULL);
      rpl->status = r;
      if (r == RUN_OK && req->style_check_only > 0) *p_override_exe = 1;
    }

    goto cleanup;
  }

  // multi-header mode
  snprintf(exe_work_name, PATH_MAX, "%llx%s", random_u64(), lang->exe_sfx);
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

  int style_already_checked = 0;
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
    unsigned char lang_name_part[PATH_MAX];
    header_path[0] = 0;
    footer_path[0] = 0;
    compiler_env_path[0] = 0;
    lang_name_part[0] = 0;

    if (req->lang_header) {
      if (req->lang_short_name && req->lang_short_name[0]) {
        snprintf(lang_name_part, sizeof(lang_name_part), ".%s", req->lang_short_name);
      } else if (lang->multi_header_suffix && lang->multi_header_suffix[0]) {
        snprintf(lang_name_part, sizeof(lang_name_part), ".%s", lang->multi_header_suffix);
      } else {
        snprintf(lang_name_part, sizeof(lang_name_part), ".%s", lang->short_name);
      }
    }

    if (header_base[0]) {
      snprintf(header_path, sizeof(header_path), "%s/%s%s%s", req->header_dir, header_base, lang_name_part, lang->src_sfx);
    }
    if (footer_base[0]) {
      snprintf(footer_path, sizeof(footer_path), "%s/%s%s%s", req->header_dir, footer_base, lang_name_part, lang->src_sfx);
    }
    if (compiler_env_base[0]) {
      snprintf(compiler_env_path, sizeof(compiler_env_path), "%s/%s%s", req->header_dir, compiler_env_base, lang_name_part);
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

    unsigned char test_src_name[PATH_MAX];
    snprintf(test_src_name, sizeof(test_src_name), "%llx%s", random_u64(), lang->src_sfx);
    unsigned char test_src_path[PATH_MAX];
    snprintf(test_src_path, sizeof(test_src_path), "%s/%s", working_dir, test_src_name);
    if (generic_write_file(full_s, full_z, 0, NULL, test_src_path, NULL) < 0) {
      fprintf(log_f, "failed to write full source file '%s'\n", test_src_path);
      testinfo_free(tinf);
      xfree(full_s);
      status = RUN_CHECK_FAILED;
      xfree(header_s); header_s = NULL; header_z = 0;
      xfree(footer_s); footer_s = NULL; footer_z = 0;
      continue;
    }
    xfree(full_s); full_s = NULL; full_z = 0;

    unsigned char test_exe_name[PATH_MAX];
    // FIXME: random exe name?
    snprintf(test_exe_name, sizeof(test_exe_name), "%06d_%03d%s", req->run_id, serial, lang->exe_sfx);
    unsigned char test_exe_path[PATH_MAX];
    snprintf(test_exe_path, sizeof(test_exe_path), "%s/%s", working_dir, test_exe_name);

    int cur_status = RUN_OK;
    /*
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
    */
    if (cur_status == RUN_OK) {
      fprintf(log_f, "=== compilation for test %d ===\n", serial);
      fflush(log_f);
      cur_status = invoke_compiler(log_f, cs, lang, req, test_src_name, test_exe_name, working_dir, log_work_path, tinf, &prepended_size);
      // valid statuses: RUN_OK, RUN_COMPILE_ERR, RUN_CHECK_FAILED
      if (cur_status == RUN_CHECK_FAILED) {
        status = RUN_CHECK_FAILED;
      } else if (cur_status == RUN_COMPILE_ERR) {
        if (tinf && (tinf->compiler_must_fail > 0 || tinf->allow_compile_error > 0) && tinf->source_stub) {
          unsigned char source_stub_path[PATH_MAX];
          snprintf(source_stub_path, sizeof(source_stub_path), "%s/%s%s%s", req->header_dir, tinf->source_stub, lang_name_part, lang->src_sfx);
          if (stat(source_stub_path, &stb) < 0) {
            fprintf(log_f, "source stub file '%s' does not exist: %s\n", source_stub_path, strerror(errno));
            status = RUN_CHECK_FAILED;
          } else if (!S_ISREG(stb.st_mode)) {
            fprintf(log_f, "source stub file '%s' is not regular\n", source_stub_path);
            status = RUN_CHECK_FAILED;
          } else if (access(source_stub_path, R_OK) < 0) {
            fprintf(log_f, "source stub file '%s' is not readable: %s\n", source_stub_path, strerror(errno));
            status = RUN_CHECK_FAILED;
          } else {
            char *source_stub_s = NULL;
            size_t source_stub_z = 0;
            if (generic_read_file(&source_stub_s, 0, &source_stub_z, 0, NULL, source_stub_path, "") < 0) {
              fprintf(log_f, "failed to read file '%s'\n", source_stub_path);
              status = RUN_CHECK_FAILED;
            } else {
              // ignore header and footer for now
              if (1) {
                full_z = source_stub_z;
                full_s = xmalloc(full_z + 1);
                memcpy(full_s, source_stub_s, source_stub_z);
                full_s[full_z] = 0;
              } else {
                full_z = header_z + source_stub_z + footer_z;
                full_s = xmalloc(full_z + 1);
                if (header_s && header_z > 0) {
                  memcpy(full_s, header_s, header_z);
                }
                memcpy(full_s + header_z, source_stub_s, source_stub_z);
                if (footer_s && footer_z > 0) {
                  memcpy(full_s + header_z + source_stub_z, footer_s, footer_z);
                }
                full_s[full_z] = 0;
              }

              xfree(source_stub_s); source_stub_s = NULL; source_stub_z = 0;

              if (generic_write_file(full_s, full_z, 0, NULL, test_src_path, NULL) < 0) {
                fprintf(log_f, "failed to write full source file '%s'\n", test_src_path);
                status = RUN_CHECK_FAILED;
              } else {
                cur_status = invoke_compiler(log_f, cs, lang, req, test_src_name, test_exe_name, working_dir, log_work_path, tinf, &prepended_size);

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
              xfree(full_s); full_s = NULL; full_z = 0;
            }
          }
        } else {
          if (status == RUN_OK || status == RUN_STYLE_ERR) {
            status = RUN_COMPILE_ERR;
          }
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
        } else if (tinf && tinf->compiler_must_fail > 0) {
          if (status == RUN_OK || status == RUN_STYLE_ERR) {
            status = RUN_COMPILE_ERR;
          }
          fprintf(log_f, "compiler must fail on test %d, but compilation was successful\n", serial);
          if (tinf->comment) {
            fprintf(log_f, "possible reason:\n");
            fprintf(log_f, "%s\n", tinf->comment);
          }
        } else {
          if (zf->ops->add_file(zf, test_exe_name, test_exe_path) < 0) {
            fprintf(log_f, "cannot add file '%s' to zip archive\n", test_exe_path);
            status = RUN_CHECK_FAILED;
          }
        }
      }
    }

    if (status == RUN_OK && !style_already_checked && req->vcs_mode <= 0 && req->style_checker && req->style_checker[0]) {
      fprintf(log_f, "=== style checking ===\n");
      fflush(log_f);

      style_already_checked = 1;
      cur_status = invoke_style_checker(log_f, cs, lang, req, test_src_name, working_dir, log_work_path, tinf);
      // valid statuses: RUN_OK, RUN_STYLE_ERR, RUN_CHECK_FAILED
      if (cur_status == RUN_CHECK_FAILED) {
        status = RUN_CHECK_FAILED;
      } else if (cur_status == RUN_STYLE_ERR) {
        status = RUN_STYLE_ERR;
      } else if (cur_status != RUN_OK) {
        fprintf(log_f, "invalid status %d returned from invoke_style_checker\n", cur_status);
        status = RUN_CHECK_FAILED;
      }
    }

    xfree(header_s); header_s = NULL; header_z = 0;
    xfree(footer_s); footer_s = NULL; footer_z = 0;
  }

  rpl->status = status;
  rpl->zip_mode = 1;
  rpl->prepended_size = prepended_size;

cleanup:
  if (zf) zf->ops->close(zf);
  return;
}

static const unsigned char stub_program[] =
"#! /bin/sh\n"
"echo 'This is a stub program!'\n"
"exit 1\n";

static int
do_write_string(
        const unsigned char *path,
        int perms,
        const unsigned char *str)
{
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, perms);
  if (fd < 0) {
    err("%s: failed to open '%s': %s", __FUNCTION__, path, os_ErrorMsg());
    return -1;
  }
  ssize_t len = strlen(str);
  const unsigned char *p = str;
  while (len > 0) {
    ssize_t w = write(fd, p, len);
    if (w < 0) {
      err("%s: write error: %s", __FUNCTION__, os_ErrorMsg());
      close(fd);
      unlink(path);
      return -1;
    }
    if (!w) abort();
    p += w;
    len -= w;
  }
  if (close(fd) < 0) {
    err("%s: close failed: %s", __FUNCTION__, os_ErrorMsg());
    unlink(path);
    return -1;
  }
  return 0;
}

static int
do_copy_regular_file(
        const unsigned char *dst_path,
        const unsigned char *src_path)
{
  int src_fd = -1;
  int retval = -1;
  size_t src_size = 0;
  unsigned char *src_ptr = MAP_FAILED;
  int dst_fd = -1;
  int need_unlink = 0;
  unsigned char *dst_ptr = MAP_FAILED;

  src_fd = open(src_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
  if (src_fd < 0) {
    err("%s: open '%s' failed: %s", __FUNCTION__, src_path, os_ErrorMsg());
    goto done;
  }
  struct stat stb;
  if (fstat(src_fd, &stb) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: '%s' is not regular", __FUNCTION__, src_path);
    goto done;
  }
  if (stb.st_size < 0 || stb.st_size > 128 * 1024 * 1024) {
    err("%s: '%s' is too big", __FUNCTION__, src_path);
    goto done;
  }
  src_size = stb.st_size;

  dst_fd = open(dst_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, stb.st_mode & 0777);
  if (dst_fd < 0) {
    err("%s: open '%s' failed: %s", __FUNCTION__, dst_path, os_ErrorMsg());
    goto done;
  }
  need_unlink = 1;
  if (fstat(dst_fd, &stb) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: '%s' is not regular", __FUNCTION__, dst_path);
    goto done;
  }

  if (src_size > 0) {
    src_ptr = mmap(NULL, src_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    if (src_ptr == MAP_FAILED) {
      err("%s: mmap of '%s' failed: %s", __FUNCTION__, src_path, os_ErrorMsg());
      goto done;
    }

    if (posix_fallocate(dst_fd, 0, src_size) < 0) {
      err("%s: fallocate failed: %s", __FUNCTION__, os_ErrorMsg());
      goto done;
    }
    dst_ptr = mmap(NULL, src_size, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, 0);
    if (dst_ptr == MAP_FAILED) {
      err("%s: mmap of '%s' failed: %s", __FUNCTION__, dst_path, os_ErrorMsg());
      goto done;
    }
    memcpy(dst_ptr, src_ptr, src_size);
  }

  retval = 0;
  need_unlink = 0;

done:;
  if (dst_ptr != MAP_FAILED) munmap(dst_ptr, src_size);
  if (src_ptr != MAP_FAILED) munmap(src_ptr, src_size);
  if (need_unlink) unlink(dst_path);
  if (dst_fd >= 0) close(dst_fd);
  if (src_fd >= 0) close(src_fd);
  return retval;
}

static int
copy_to_local_cache(
        const struct compile_request_packet *req,
        const unsigned char *exe_work_path,
        const unsigned char *exe_sfx)
{
  unsigned char uuid_buf[64];
  unsigned char cached_path[PATH_MAX];
  int r;

  r = snprintf(cached_path, sizeof(cached_path), "%s/%s%s",
               local_cache,
               ej_uuid_unparse_r(uuid_buf, sizeof(uuid_buf),
                                 &req->judge_uuid, ""),
               exe_sfx);
  if (r >= (int)sizeof(cached_path)) {
    err("%s: cached_path is too long", __FUNCTION__);
    return -1;
  }

  struct stat stb;
  if (stat(exe_work_path, &stb) < 0) {
    err("%s: stat failed for '%s': %s", __FUNCTION__, exe_work_path, os_ErrorMsg());
    return -1;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: '%s' not regular", __FUNCTION__, exe_work_path);
    return -1;
  }

  if (rename(exe_work_path, cached_path) >= 0) {
    if (do_write_string(exe_work_path, 777, stub_program) < 0) {
      err("%s: writing of stub file failed", __FUNCTION__);
      unlink(cached_path);
      return -1;
    }
    return 0;
  }
  if (errno != EXDEV) {
    err("%s: rename failed: %s", __FUNCTION__, os_ErrorMsg());
    return -1;
  }
  if (do_copy_regular_file(cached_path, exe_work_path) < 0) {
    return -1;
  }
  if (do_write_string(exe_work_path, 777, stub_program) < 0) {
    err("%s: writing of stub file failed", __FUNCTION__);
    unlink(cached_path);
    return -1;
  }
  return 0;
}

static int
new_loop(int parallel_mode, const unsigned char *global_log_path)
{
  int retval = 0;
  const struct section_global_data *global = serve_state.global;
  int override_exe = 0;
  int exe_copied = 0;
  path_t full_working_dir = { 0 };
  struct Future *future = NULL;
  int ifd = -1;
  int ifd_wd = -1;
  sigset_t emptymask;
  int efd = -1;

  random_init();
  sigemptyset(&emptymask);

  if (parallel_mode) {
    unsigned long long u64 = random_u64();
    snprintf(full_working_dir, sizeof(full_working_dir), "%s/%016llx", global->compile_work_dir, u64);
    if (make_dir(full_working_dir, 0) < 0) {
      err("cannot create '%s': %s", full_working_dir, os_ErrorMsg());
      return -1;
    }
  } else {
    snprintf(full_working_dir, sizeof(full_working_dir), "%s", global->compile_work_dir);
  }

  if (agent_name && *agent_name) {
    if (!strncmp(agent_name, "ssh:", 4)) {
      agent = agent_client_ssh_create();
      if (agent->ops->init(agent, instance_id,
                           agent_name + 4, compile_server_id,
                           PREPARE_COMPILE, verbose_mode, ip_address) < 0) {
        err("failed to initalize agent");
        return -1;
      }
      if (agent->ops->connect(agent) < 0) {
        err("failed to connect to client");
        return -1;
      }
    } else {
      err("invalid agent");
      return -1;
    }
  } else {
    ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) {
      err("inotify_init1 failed: %s", os_ErrorMsg());
      return -1;
    }
  }

#if defined EJUDGE_COMPILE_SPOOL_DIR
  // nothing to do
#else
  if (snprintf(compile_server_queue_dir, sizeof(compile_server_queue_dir), "%s", global->compile_queue_dir) >= sizeof(compile_server_queue_dir)) {
    err("path '%s' is too long", global->compile_queue_dir);
    return -1;
  }
  if (snprintf(compile_server_src_dir, sizeof(compile_server_src_dir), "%s", global->compile_src_dir) >= sizeof(compile_server_src_dir)) {
    err("path '%s' is too long", global->compile_src_dir);
    return -1;
  }
#endif

  snprintf(compile_server_queue_dir_dir, sizeof(compile_server_queue_dir_dir),
           "%s/dir", compile_server_queue_dir);

  if (ifd >= 0) {
    ifd_wd = inotify_add_watch(ifd, compile_server_queue_dir_dir, IN_CREATE | IN_MOVED_TO);
    if (ifd_wd < 0) {
      err("inotify_add_watch failed: %s", os_ErrorMsg());
      return -1;
    }

    efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) {
      err("epoll_create1 failed: %s", os_ErrorMsg());
      return -1;
    }

    struct epoll_event ev =
    {
      .events = EPOLLIN,
      .data.fd = ifd,
    };
    if (epoll_ctl(efd, EPOLL_CTL_ADD, ifd, &ev) < 0) {
      err("epoll_ctl failed: %s", os_ErrorMsg());
      return -1;
    }
  }

  interrupt_init();
  interrupt_setup_usr1();
  interrupt_setup_usr2();
  interrupt_disable();

  while (1) {
    interrupt_enable();
    interrupt_disable();

    // terminate if signaled
    if (interrupt_get_status() || interrupt_restart_requested()) break;
    if (interrupt_was_usr1()) {
      if ((daemon_mode || slave_mode) && global_log_path && *global_log_path) {
        start_open_log(global_log_path);
        dup2(STDERR_FILENO, STDOUT_FILENO);
      }
      interrupt_reset_usr1();
      continue;
    }

    save_heartbeat();
    if (pending_stop_flag || pending_down_flag || pending_reboot_flag) {
      break;
    }

    unsigned char pkt_name[PATH_MAX];
    pkt_name[0] = 0;
    int r = 0;
    char *pkt_ptr = NULL;
    size_t pkt_len = 0;

    if (agent) {
      if (interrupt_was_usr2()) {
        interrupt_reset_usr2();
        if (future) {
          r = agent->ops->async_wait_complete(agent, &future,
                                              pkt_name, sizeof(pkt_name),
                                              &pkt_ptr,
                                              &pkt_len);
          if (r < 0) {
            err("async_wait_complete failed");
            break;
          }
          if (!pkt_name[0]) {
            continue;
          }
        }
      } else if (!future) {
        r = agent->ops->async_wait_init(agent, SIGUSR2, 0,
                                        1,
                                        pkt_name, sizeof(pkt_name), &future,
                                        DEFAULT_WAIT_TIMEOUT_MS,
                                        &pkt_ptr,
                                        &pkt_len);
        //r = agent->ops->poll_queue(agent, pkt_name, sizeof(pkt_name));
        if (r < 0) {
          err("async_wait_init failed");
          break;
        }
        if (!pkt_name[0]) {
          continue;
        }
      }
    } else {
      r = scan_dir(compile_server_queue_dir, pkt_name, sizeof(pkt_name), 0);
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
    }

    if (!r) {
      if (agent) {
        interrupt_enable();
        os_Sleep(5000);
        interrupt_disable();
      } else {
        struct epoll_event events[1];
        int r = epoll_pwait(efd, events, 1, HEARTBEAT_UPDATE_MS, &emptymask);
        if (r == 1) {
          if (events[0].data.fd != ifd) abort();
          // just read all the data in the ifd without any processing
          unsigned char ibuf[4096];
          while (1) {
            int r = read(ifd, ibuf, sizeof(ibuf));
            if (r <= 0) break;
          }
        }
      }
      continue;
    }

    if (agent) {
      if (!pkt_ptr) {
        r = agent->ops->get_packet(agent, pkt_name, &pkt_ptr, &pkt_len);
      } else {
        r = 1;
      }
    } else {
      r = generic_read_file(&pkt_ptr, 0, &pkt_len, SAFE | REMOVE, compile_server_queue_dir, pkt_name, "");
    }
    if (r == 0){
      continue;
    }
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

    if (lang_id_map
        && req->lang_id > 0 && req->lang_id < lang_id_map_size
        && lang_id_map[req->lang_id] > 0) {
      info("language %d mapped to %d", req->lang_id, lang_id_map[req->lang_id]);
      req->lang_id = lang_id_map[req->lang_id];
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
    rpl.judge_uuid = req->judge_uuid;
    rpl.contest_id = req->contest_id;
    rpl.run_id = req->run_id;
    rpl.submit_id = req->submit_id;
    rpl.ts1 = req->ts1;
    rpl.ts1_us = req->ts1_us;
    rpl.use_uuid = req->use_uuid;
    rpl.uuid = req->uuid;
    get_current_time(&rpl.ts2, &rpl.ts2_us);
    rpl.run_block_len = req->run_block_len;
    rpl.run_block = req->run_block; /* !!! shares memory with req */

    last_handled_request_ms = rpl.ts2 * 1000LL + rpl.ts2_us / 1000;

    unsigned char contest_server_reply_dir[PATH_MAX];
    contest_server_reply_dir[0] = 0;
    const unsigned char *contest_server_id = NULL;
    unsigned char contest_reply_dir[PATH_MAX];

#if defined EJUDGE_COMPILE_SPOOL_DIR
    {
      if (req->contest_server_id && *req->contest_server_id) {
        contest_server_id = req->contest_server_id;
      }
      if (!contest_server_id) {
        contest_server_id = compile_server_id;
      }
      if (!contest_server_id || !*contest_server_id) {
        contest_server_id = "localhost";
      }
      if (snprintf(contest_server_reply_dir, sizeof(contest_server_reply_dir), "%s/%s", EJUDGE_COMPILE_SPOOL_DIR, contest_server_id) >= sizeof(contest_server_reply_dir)) {
        rpl.run_block = NULL;
        compile_request_packet_free(req);
        continue;
      }
      if (make_dir(contest_server_reply_dir, 0777) < 0) {
        rpl.run_block = NULL;
        compile_request_packet_free(req);
        continue;
      }
    }
    strcpy(contest_reply_dir, contest_server_reply_dir);
#else
    if (snprintf(contest_server_reply_dir, sizeof(contest_server_reply_dir), "%s", global->compile_dir) >= sizeof(contest_server_reply_dir)) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      continue;
    }

    snprintf(contest_reply_dir, sizeof(contest_reply_dir), "%s/%06d", contest_server_reply_dir, rpl.contest_id);
    if (make_dir(contest_reply_dir, 0777) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      continue;
    }
#endif

    unsigned char status_dir[PATH_MAX];
    snprintf(status_dir, sizeof(status_dir), "%s/status", contest_reply_dir);
    if (make_all_dir(status_dir, 0777) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      continue;
    }

    unsigned char run_name[PATH_MAX];
    if (req->use_uuid > 0) {
      if (ej_uuid_is_nonempty(req->judge_uuid)) {
        snprintf(run_name, sizeof(run_name), "%s", ej_uuid_unparse(&req->judge_uuid, NULL));
      } else {
        snprintf(run_name, sizeof(run_name), "%s", ej_uuid_unparse(&req->uuid, NULL));
      }
    } else {
      snprintf(run_name, sizeof(run_name), "%06d", rpl.run_id);
    }

    unsigned char report_dir[PATH_MAX];
    snprintf(report_dir, sizeof(report_dir), "%s/report", contest_reply_dir);
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
    snprintf(log_work_path, sizeof(log_work_path), "%s/%s", full_working_dir, log_work_name);
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
    if (lang /*&& lang->exe_sfx*/) exe_sfx = lang->exe_sfx;
    snprintf(exe_path, sizeof(exe_path), "%s/%s%s", report_dir, run_name, exe_sfx);
    unlink(exe_path);

    unsigned char src_path[PATH_MAX];
    const unsigned char *src_sfx = "";
    if (req->src_sfx) src_sfx = req->src_sfx;
    snprintf(src_path, sizeof(src_path), "%s/%s%s", compile_server_src_dir, pkt_name, src_sfx);

    char *src_buf = NULL;
    size_t src_len = 0;
    if (agent) {
      r = agent->ops->get_data(agent, pkt_name, src_sfx, &src_buf, &src_len);
      if (r < 0) {
        err("agent get_data failed");
        fclose(log_f); log_f = NULL;
        rpl.run_block = NULL;
        compile_request_packet_free(req);
        continue;
      }
      if (!r || !src_buf) {
        fclose(log_f); log_f = NULL;
        rpl.run_block = NULL;
        compile_request_packet_free(req);
        continue;
      }
    }

    override_exe = 0;
    exe_copied = 0;
    handle_packet(log_f, &serve_state, pkt_name, req, &rpl,
                  lang,
                  contest_server_id,
                  run_name,
                  src_path,
                  src_buf,
                  src_len,
                  exe_sfx,
                  exe_path,
                  full_working_dir,
                  log_work_path,
                  exe_work_name,
                  &override_exe,
                  &exe_copied);

    free(src_buf); src_buf = NULL; src_len = 0;

    get_current_time(&rpl.ts3, &rpl.ts3_us);
    long long current_time_ms = rpl.ts3 * 1000LL + rpl.ts3_us / 1000;
    accumulated_ms += (current_time_ms - last_handled_request_ms);
    ++request_count;

    if (rpl.status == RUN_OK && !override_exe && !exe_copied) {
      if (!exe_work_name[0]) {
        err("the resulting executable name is empty");
        fprintf(log_f, "\ncompiler output file is empty\n");
        rpl.status = RUN_CHECK_FAILED;
      } else {
        unsigned char exe_work_path[PATH_MAX];
        snprintf(exe_work_path, sizeof(exe_work_path), "%s/%s", full_working_dir, exe_work_name);
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
            if (agent) {
              if (req->enable_remote_cache > 0 && local_cache && *local_cache
                  && ej_uuid_is_nonempty(req->judge_uuid)) {
                if (copy_to_local_cache(req, exe_work_path, exe_sfx) >= 0) {
                  rpl.cached_on_remote = 1;
                }
              }
              if (agent->ops->put_output_2(agent,
                                           contest_server_id,
                                           rpl.contest_id,
                                           run_name,
                                           exe_sfx,
                                           exe_work_path) < 0) {
                err("put_output failed");
                fprintf(log_f, "\nput_output failed\n");
                rpl.status = RUN_CHECK_FAILED;
              }
            } else if (rename(exe_work_path, exe_path) >= 0) {
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

    if (agent) {
      r = agent->ops->put_output_2(agent,
                                   contest_server_id,
                                   rpl.contest_id,
                                   run_name,
                                   ".txt",
                                   log_work_path);
    } else {
      r = generic_copy_file(0, NULL, log_work_path, "", 0, NULL, log_path, "");
    }
    if (r < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      clear_directory(full_working_dir);
      unlink(exe_path);
      unlink(log_path);
      continue;
    }

    if (override_exe || (rpl.status == RUN_STYLE_ERR || rpl.status == RUN_COMPILE_ERR || rpl.status == RUN_CHECK_FAILED)) {
      if (agent) {
        agent->ops->put_output_2(agent, contest_server_id, rpl.contest_id, run_name, exe_sfx, log_work_path);
      } else {
        generic_copy_file(0, NULL, log_work_path, "", 0, NULL, exe_path, "");
      }
    }

    void *rpl_pkt = NULL;
    size_t rpl_size = 0;
    if (compile_reply_packet_write(&rpl, &rpl_size, &rpl_pkt) < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      clear_directory(full_working_dir);
      unlink(exe_path);
      unlink(log_path);
      continue;
    }
    if (agent) {
      r = agent->ops->put_reply(agent, contest_server_id, rpl.contest_id, run_name, rpl_pkt, rpl_size);
    } else {
      r = generic_write_file(rpl_pkt, rpl_size, SAFE, status_dir, run_name, 0);
    }
    if (r < 0) {
      rpl.run_block = NULL;
      compile_request_packet_free(req);
      xfree(rpl_pkt);
      clear_directory(full_working_dir);
      unlink(exe_path);
      unlink(log_path);
      continue;
    }

    // all good
    rpl.run_block = NULL;
    compile_request_packet_free(req);
    xfree(rpl_pkt);
    clear_directory(full_working_dir);
  }

  delete_heartbeat();

  if (agent) {
    agent->ops->close(agent);
  }

  return retval;
}

static void
make_heartbeat_file_name(void)
{
  const unsigned char *basename = NULL;
  if (compile_server_id && *compile_server_id) {
    basename = compile_server_id;
  } else if (ip_address && *ip_address) {
    basename = ip_address;
  } else {
    basename = os_NodeName();
  }

  __attribute__((unused)) int r;
  r = snprintf(heartbeat_file_name, sizeof(heartbeat_file_name), "%s.%d", basename, getpid());
}

static int
filter_languages(char *key)
{
  // key is not NULL
  int i, total = 0;
  const struct section_language_data *lang = 0;

  for (i = 1; i <= serve_state.max_lang; i++) {
    if (!(lang = serve_state.langs[i])) continue;
    if (lang->disabled_by_config > 0) {
      serve_state.langs[i] = 0;
    } else if (!lang->key) {
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

#if !defined EJUDGE_COMPILE_SPOOL_DIR
  if (check_writable_spool(serve_state.global->compile_queue_dir, SPOOL_OUT) < 0)
    return -1;
#endif
  for (i = 1; i <= serve_state.max_lang; i++) {
    if (!serve_state.langs[i]) continue;

    /* script must exist and be executable */
    total++;
    if (!serve_state.langs[i]->cmd) return -1;
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

static int
parse_lang_id_map(const char *prog, const char *file)
{
  FILE *f = NULL;

  if (!(f = fopen(file, "r"))) {
    fprintf(stderr, "%s: cannot open '%s': %s\n", prog, file, strerror(errno));
    goto fail;
  }
  char buf[1024];
  while (fgets(buf, sizeof(buf), f)) {
    int l = strlen(buf);
    while (l > 0 && isspace((unsigned char) buf[l - 1])) --l;
    buf[l] = 0;
    if (!l) continue;
    int n, from_id, to_id;
    if (sscanf(buf, "%d%d%n", &from_id, &to_id, &n) != 2 || buf[n]) {
      fprintf(stderr, "%s: failed to parse map line\n", prog);
      goto fail;
    }
    if (from_id <= 0 || to_id <= 0 || from_id > 100000 || to_id > 100000) {
      fprintf(stderr, "%s: failed to parse map line\n", prog);
      goto fail;
    }
    if (from_id >= lang_id_map_size) {
      int new_lang_id_map_size = lang_id_map_size * 2;
      if (!lang_id_map_size) {
        new_lang_id_map_size = 16;
      }
      while (from_id >= new_lang_id_map_size) {
        new_lang_id_map_size *= 2;
      }
      int *new_lang_id_map = NULL;
      XCALLOC(new_lang_id_map, new_lang_id_map_size);
      if (lang_id_map_size > 0) {
        memcpy(new_lang_id_map, lang_id_map, lang_id_map_size * new_lang_id_map[0]);
      }
      xfree(lang_id_map);
      lang_id_map = new_lang_id_map;
      lang_id_map_size = new_lang_id_map_size;
    }
    if (lang_id_map[from_id]) {
      fprintf(stderr, "%s: duplicate entry in lang_id map\n", prog);
      goto fail;
    }
    lang_id_map[from_id] = to_id;
  }

  fclose(f);
  return 0;

fail:;
  if (f) fclose(f);
  return -1;
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
  int     parallel_mode = 0;
  int     ejudge_xml_fd = -1;
  int     stderr_fd = -1;
  int     disable_stack_trace = 0;
  unsigned char *halt_command = NULL;
  unsigned char *reboot_command = NULL;
  unsigned char *lang_id_map = NULL;

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

  {
    const unsigned char *s = getenv("EJ_COMPILE_SERVER_ID");
    if (s && *s) {
      compile_server_id = xstrdup(s);
    }
  }

  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 2);
  argv_restart[j++] = argv[0];

  struct timeval stv;
  gettimeofday(&stv, NULL);
  start_time_ms = stv.tv_sec * 1000LL + stv.tv_usec / 1000;

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
    } else if (!strcmp(argv[i], "-S")) {
      slave_mode = 1;
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
    } else if (!strcmp(argv[i], "-I")) {
      if (++i >= argc) goto print_usage;
      xfree(compile_server_id); compile_server_id = NULL;
      compile_server_id = xstrdup(argv[i++]);
      argv_restart[j++] = "-I";
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "-l")) {
      if (++i >= argc) goto print_usage;
      argv_restart[j++] = argv[i - 1];
      argv_restart[j++] = argv[i];
      char *eptr = NULL;
      errno = 0;
      long lval = strtol(argv[i++], &eptr, 10);
      if (errno || *eptr || eptr == argv[i - 1] || (int) lval != lval || lval < 0) goto print_usage;
      struct stat stb;
      if (fstat(lval, &stb) < 0 || !S_ISREG(stb.st_mode)) goto print_usage;
      ejudge_xml_fd = lval;
    } else if (!strcmp(argv[i], "-e")) {
      if (++i >= argc) goto print_usage;
      char *eptr = NULL;
      errno = 0;
      long lval = strtol(argv[i++], &eptr, 10);
      if (errno || *eptr || eptr == argv[i - 1] || (int) lval != lval || lval < 0) goto print_usage;
      struct stat stb;
      if (fstat(lval, &stb) < 0) goto print_usage;
      stderr_fd = lval;
    } else if (!strcmp(argv[i], "--agent")) {
      if (++i >= argc) goto print_usage;
      xfree(agent_name);
      agent_name = xstrdup(argv[i++]);
      argv_restart[j++] = "--agent";
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "--instance-id")) {
      if (++i >= argc) goto print_usage;
      xfree(instance_id);
      instance_id = xstrdup(argv[i++]);
      argv_restart[j++] = "--instance-id";
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "-hi")) {
      if (++i >= argc) goto print_usage;
      xfree(heartbeat_instance_id);
      heartbeat_instance_id = xstrdup(argv[i++]);
      argv_restart[j++] = argv[i];
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "--ip")) {
      if (++i >= argc) goto print_usage;
      xfree(ip_address);
      ip_address = xstrdup(argv[i++]);
      argv_restart[j++] = "--ip";
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "-hc")) {
      if (++i >= argc) goto print_usage;
      xfree(halt_command);
      halt_command = xstrdup(argv[i++]);
      argv_restart[j++] = argv[i];
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "-rc")) {
      if (++i >= argc) goto print_usage;
      xfree(reboot_command);
      reboot_command = xstrdup(argv[i++]);
      argv_restart[j++] = argv[i];
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "--lang-id-map")) {
      if (++i >= argc) goto print_usage;
      xfree(lang_id_map);
      lang_id_map = xstrdup(argv[i++]);
      argv_restart[j++] = argv[i];
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "--local-cache")) {
      if (++i >= argc) goto print_usage;
      xfree(local_cache);
      local_cache = xstrdup(argv[i++]);
      argv_restart[j++] = argv[i];
      argv_restart[j++] = argv[i - 1];
    } else if (!strcmp(argv[i], "-p")) {
      parallel_mode = 1;
      ++i;
      argv_restart[j++] = "-p";
    } else if (!strcmp(argv[i], "-v")) {
      verbose_mode = 1;
      ++i;
      argv_restart[j++] = "-v";
    } else if (!strcmp(argv[i], "-nst")) {
      disable_stack_trace = 1;
      ++i;
      argv_restart[j++] = argv[i];
    } else if (!strcmp(argv[i], "-hb")) {
      heartbeat_mode = 1;
      ++i;
      argv_restart[j++] = argv[i];
    } else if (!strcmp(argv[i], "-nhb")) {
      heartbeat_mode = 0;
      ++i;
      argv_restart[j++] = argv[i];
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
  if (disable_stack_trace <= 0) {
    start_enable_stacktrace(NULL);
  }

  if (!compile_server_id || !*compile_server_id) {
    xfree(compile_server_id); compile_server_id = NULL;
    compile_server_id = xstrdup(os_NodeName());
  }
  if (!compile_server_id || !*compile_server_id) {
    xfree(compile_server_id); compile_server_id = NULL;
    compile_server_id = xstrdup("localhost");
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
  if (ejudge_xml_fd > 0) {
    FILE *exf = fdopen(dup(ejudge_xml_fd), "r");
    if (!exf) {
      fprintf(stderr, "%s: FD is invalid\n", argv[0]);
      return 1;
    }
    ejudge_config = ejudge_cfg_parse_file(ejudge_xml_path, exf, 1);
  } else {
    ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 1);
  }
  if (!ejudge_config) {
    fprintf(stderr, "%s: ejudge.xml is invalid\n", argv[0]);
    return 1;
  }

  if (lang_id_map && *lang_id_map) {
    if (parse_lang_id_map(argv[0], lang_id_map) < 0) {
      return 1;
    }
  }

  unsigned char **host_names = NULL;
  if (!(host_names = ejudge_get_host_names())) {
    fprintf(stderr, "%s: cannot obtain the list of host names\n", argv[0]);
    return 1;
  }
  if (!host_names[0]) {
    fprintf(stderr, "%s: cannot determine the name of the host\n", argv[0]);
    return 1;
  }

  int parallelism = ejudge_cfg_get_host_option_int(ejudge_config, host_names, "compile_parallelism", 1, 0);
  if (parallelism <= 0 || parallelism > 128) {
    fprintf(stderr, "%s: invalid value of compile_parallelism host option\n", argv[0]);
    return 1;
  }
  if (parallelism > 1) parallel_mode = 1;
  for (int hi = 0; host_names[hi]; ++hi) {
    free(host_names[hi]);
  }
  free(host_names); host_names = NULL;

  int *pids = NULL;
  int pid_count;
  if ((pid_count = start_find_all_processes("ej-compile", NULL, &pids)) < 0) {
    fprintf(stderr, "%s: cannot get the list of processes\n", argv[0]);
    return 1;
  }
  if (pid_count >= parallelism) {
    fprintf(stderr, "%d", pids[0]);
    for (int i = 1; i < pid_count; ++i) {
      fprintf(stderr, " %d", pids[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "%s: %d processes are already running\n", argv[0], pid_count);
    return 1;
  }
  xfree(pids); pids = NULL;
#endif

  int tmp_fd = -1;
  if (stderr_fd >= 0) {
    tmp_fd = dup(STDERR_FILENO);
    dup2(stderr_fd, STDERR_FILENO);
  }
  info("%s %s, compiled %s", "ej-compile", compile_version, compile_date);
  if (stderr_fd >= 0) {
    dup2(tmp_fd, STDERR_FILENO); close(tmp_fd); tmp_fd = -1;
    close(stderr_fd); stderr_fd = -1;
  }

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

#if defined EJUDGE_COMPILE_SPOOL_DIR
  {
    struct stat stb;

    if (stat(EJUDGE_COMPILE_SPOOL_DIR, &stb) < 0) {
      fprintf(stderr, "%s: compile spool directory '%s' does not exist\n", argv[0], EJUDGE_COMPILE_SPOOL_DIR);
      return 1;
    }
    if (!S_ISDIR(stb.st_mode)) {
      fprintf(stderr, "%s: compile spool '%s' is not directory\n", argv[0], EJUDGE_COMPILE_SPOOL_DIR);
      return 1;
    }
    if (access(EJUDGE_COMPILE_SPOOL_DIR, X_OK | W_OK | R_OK) < 0) {
      fprintf(stderr, "%s: compile spool '%s' has insufficient permissions\n", argv[0], EJUDGE_COMPILE_SPOOL_DIR);
      return 1;
    }
  }
#endif

  make_heartbeat_file_name();

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

  if (prepare(ejudge_config, NULL, &serve_state, compile_cfg_path, prepare_flags, PREPARE_COMPILE,
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

#if defined EJUDGE_COMPILE_SPOOL_DIR
  {
    if (snprintf(compile_server_spool_dir, sizeof(compile_server_spool_dir), "%s/%s", EJUDGE_COMPILE_SPOOL_DIR, compile_server_id) >= sizeof(compile_server_spool_dir)) {
      fprintf(stderr, "%s: path '%s/%s' is too long\n", argv[0], EJUDGE_COMPILE_SPOOL_DIR, compile_server_id);
      return 1;
    }
    if (make_dir(compile_server_spool_dir, 0) < 0) return 1;

    if (snprintf(compile_server_queue_dir, sizeof(compile_server_queue_dir), "%s/queue", compile_server_spool_dir) >= sizeof(compile_server_queue_dir)) {
      fprintf(stderr, "%s: path '%s/queue' is too long\n", argv[0], compile_server_spool_dir);
      return 1;
    }
    if (make_all_dir(compile_server_queue_dir, 0777) < 0) return 1;

    if (snprintf(compile_server_src_dir, sizeof(compile_server_src_dir), "%s/src", compile_server_spool_dir) >= sizeof(compile_server_src_dir)) {
      fprintf(stderr, "%s: path '%s/src' is too long\n", argv[0], compile_server_spool_dir);
      return 1;
    }
    if (make_dir(compile_server_src_dir, 0777) < 0) return 1;

    snprintf(heartbeat_dir, sizeof(heartbeat_dir), "%s/heartbeat", compile_server_spool_dir);
    if (make_all_dir(heartbeat_dir, 0777) < 0) return 1;
  }
#endif

  if (create_dirs(NULL, &serve_state, PREPARE_COMPILE) < 0) return 1;
  if (check_config() < 0) return 1;
  if (local_cache && *local_cache) {
    if (make_dir(local_cache, 0770) < 0) return 1;
  }

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

  if (new_loop(parallel_mode, log_path) < 0) return 1;

  if (pending_down_flag) {
    info("DOWN request from the server");
    if (halt_command) {
      start_shutdown(halt_command);
    }
  }
  if (pending_reboot_flag) {
    info("REBOOT request from the server");
    if (reboot_command) {
      start_shutdown(reboot_command);
    }
  }
  if (pending_stop_flag) {
    info("STOP request from the server");
  }

  if (interrupt_restart_requested()) start_restart();

  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] [config-file]\n", argv[0]);
  printf("  -k key - specify language key\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  printf("  -D     - start in daemon mode\n");
  printf("  -i     - initialize mode: create all dirs and exit\n");
  printf("  -p     - parallel mode: support multiple instances\n");
  printf("  -k KEY - specify a language filter key\n");
  printf("  -u U   - start as user U (only as root)\n");
  printf("  -g G   - start as group G (only as root)\n");
  printf("  -C D   - change directory to D\n");
  printf("  -x X   - specify a path to ejudge.xml file\n");
  printf("  -I ID  - specify compile server id\n");
  printf("  -r S   - substitute ${CONTESTS_HOME_DIR} for S in the config\n");
  printf("  -c C   - substitute ${COMPILE_HOME_DIR} for C in the config\n");
  printf("  -a A   - use agent A to access to compile queue\n");
  printf("  -s I   - set instance Id to I\n");
  return code;
}
