/* Copyright (C) 1999-2017 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1999-07-20 11:05:09 cher> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/**
 * FILE:    ejudge/win32/exec.c
 * PURPOSE: process abstraction layer, Win32 implementation
 */

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>

#include <malloc.h>

/* Some missing prototypes */
BOOL WINAPI AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess);
WINAPI BOOL SetInformationJobObject(HANDLE hJob,
                                    JOBOBJECTINFOCLASS info_class,
                                    PVOID job_info,
                                    DWORD job_info_len);

WINAPI BOOL QueryInformationJobObject(HANDLE hJob,
                                      JOBOBJECTINFOCLASS info_class,
                                      PVOID job_info,
                                      DWORD job_info_len,
                                      PDWORD job_info_ret_len);
BOOL WINAPI TerminateJobObject(HANDLE hJob,UINT uExitCode);

/* only ANSI version */
WINAPI HANDLE CreateJobObjectA(LPSECURITY_ATTRIBUTES, LPCTSTR);

#define NOT_IMPLEMENTED() SWERR(("Not implemented"))

typedef struct envvar_s
{
  unsigned char *name;
  unsigned char *value;
} envvar_t;
typedef struct envvar_table_s
{
  size_t a, u;
  envvar_t *vars;
} envvar_table_t;

typedef struct tRedir
{
  int fd;                       /* file descriptor (0 - 2) */
  int tag;                      /* operation */
  union
  {
    int fd2;                    /* file descr. (0 - 2) or handle */
    struct
    {
      char *path;               /* path ("/dev/null" included) */
      int   oflag;              /* flags for open(2) */
      int   mode;               /* mode for open(2) (ignored) */
    } s;
    struct
    {
      int    idx;               /* inherited index (0 - read, 1 - write) */
      HANDLE pipe[2];
    } p;
  } u;
} tRedir;
struct redir_arr_s
{
  int     a, u;
  tRedir *v;
};

struct task_args_s
{
  int    a, u;
  char **v;
};

/*
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;

typedef struct _STARTUPINFO {
    DWORD   cb;
    LPTSTR  lpReserved;
    LPTSTR  lpDesktop;
    LPTSTR  lpTitle;
    DWORD   dwX;
    DWORD   dwY;
    DWORD   dwXSize;
    DWORD   dwYSize;
    DWORD   dwXCountChars;
    DWORD   dwYCountChars;
    DWORD   dwFillAttribute;
    DWORD   dwFlags;
    WORD    wShowWindow;
    WORD    cbReserved2;
    LPBYTE  lpReserved2;
    HANDLE  hStdInput;
    HANDLE  hStdOutput;
    HANDLE  hStdError;
} STARTUPINFO, *LPSTARTUPINFO;
*/

struct tTask
{
  int                 (*main)(int, char **);
  char                 *path;
  int                   state;
  unsigned int          code;
  int                   is_exited; /* is process exited normally */
  int                   exit_code; /* process exit code */
  char                 *cmdline;
  char                 *working_dir;
  PROCESS_INFORMATION   pi;     /* as returned by CreateProcess */
  STARTUPINFO           si;     /* for CreateProcess */
  struct task_args_s    args;
  strarray_t            env;    /* environment variables */
  char                 *envblock;
  int                   clear_env;
  struct redir_arr_s    redirs;
  HANDLE               *std_streams[3];
  HANDLE                prc;    /* this process handle */

  // process limits
  int                   max_time;        /* CPU time limit (in seconds) */
  int                   max_time_millis; /* CPU time limit (in milliseconds) */
  int                   max_real_time; /* real time limit (in seconds) */
  unsigned long         max_data_size; /* data segment size (in bytes) */
  unsigned long         max_stack_size;
  unsigned long         max_vm_size;
  int                   max_proc_count;

  HANDLE                job;
  unsigned int          start_time;

  // accounting information
  int                   was_real_timeout;
  long                  used_time; /* in milliseconds */
  long                  real_time;
  int                   used_proc_count;
  unsigned int          used_real_time;
  unsigned long         used_vm_size;
};

struct task_arr_t
{
  int     a, u;
  tTask **v;
};
static struct task_arr_t tasks;

static int               verbose_flag;

#define PROC_SIGNALED(x)   (((x) & 0xC0000000) == 0xC0000000)
#define PROC_SIGNALCODE(x) (((x) & 0x0000FFFF))
#define PROC_EXITED(x)     (((x) & 0xC0000000) != 0xC0000000)
#define PROC_EXITCODE(x)   (((x) & 0x0000FFFF))

/* environment block manipulation functions */
static envvar_table_t *envvar_make_table(int clear_env_flag);
static unsigned char *envvar_make_block(envvar_table_t *t);
static envvar_table_t *envvar_free(envvar_table_t *t);
static void envvar_put(envvar_table_t *t, const char *str);

int
task_SetFlag(char *opt, int flag)
{
  switch (flag)
    {
    case 200:
      verbose_flag = 1;
      break;
    case 201:
      verbose_flag = 0;
      break;
    default:
      SWERR(("task_SetFlags: unsupported flag = %d", flag));
    }
  return 0;
}

tTask *
task_New(void)
{
  tTask *r;

  XCALLOC(r, 1);
  r->state = TSK_STOPPED;

  XEXPAND2(tasks);
  tasks.v[tasks.u++] = r;

  // for our convinience
  r->std_streams[0] = &r->si.hStdInput;
  r->std_streams[1] = &r->si.hStdOutput;
  r->std_streams[2] = &r->si.hStdError;

  r->prc = GetCurrentProcess();
  r->job = INVALID_HANDLE_VALUE;
  r->si.hStdInput = INVALID_HANDLE_VALUE;
  r->si.hStdOutput = INVALID_HANDLE_VALUE;
  r->si.hStdError = INVALID_HANDLE_VALUE;
  r->pi.hProcess = INVALID_HANDLE_VALUE;
  r->pi.hThread = INVALID_HANDLE_VALUE;

  return r;
}

void
task_Delete(tTask *tsk)
{
  int i;

  ASSERT(tsk);

  for (i = 0; i < tasks.u; i++) {
    if (tsk == tasks.v[i]) break;
  }
  if (i >= tasks.u) {
    write_log(LOG_REUSE, LOG_ERROR, "bad task descriptor");
    return;
  }

  /* close all handles */
  for (i = 0; i < tsk->redirs.u; i++) {
    tRedir *p = &tsk->redirs.v[i];
    switch (p->tag) {
    case TSR_FILE:
      xfree(p->u.s.path);
      break;
    case TSR_PIPE:
      if (p->u.p.pipe[0] != INVALID_HANDLE_VALUE) CloseHandle(p->u.p.pipe[0]);
      if (p->u.p.pipe[1] != INVALID_HANDLE_VALUE) CloseHandle(p->u.p.pipe[1]);
      p->u.p.pipe[0] = INVALID_HANDLE_VALUE;
      p->u.p.pipe[1] = INVALID_HANDLE_VALUE;
      break;
    }
  }

  for (i = 0; i < 3; i++) {
    if (*tsk->std_streams[i]) CloseHandle(*tsk->std_streams[i]);
    *tsk->std_streams[i] = INVALID_HANDLE_VALUE;
  }
  if (tsk->prc != INVALID_HANDLE_VALUE) CloseHandle(tsk->prc);
  tsk->prc = INVALID_HANDLE_VALUE;
  if (tsk->job != INVALID_HANDLE_VALUE) CloseHandle(tsk->job);
  tsk->job = INVALID_HANDLE_VALUE;
  if (tsk->pi.hProcess != INVALID_HANDLE_VALUE) CloseHandle(tsk->pi.hProcess);
  tsk->pi.hProcess = INVALID_HANDLE_VALUE;
  if (tsk->pi.hThread != INVALID_HANDLE_VALUE) CloseHandle(tsk->pi.hThread);
  tsk->pi.hThread = INVALID_HANDLE_VALUE;

  xfree(tsk->path);
  xfree(tsk->cmdline);
  for (i = 0; i < tsk->args.u; i++) {
    xfree(tsk->args.v[i]);
  }
  xfree(tsk->args.v);

  for (i = 0; i < tsk->env.u; i++)
    xfree(tsk->env.v[i]);
  xfree(tsk->env.v);
  xfree(tsk->envblock);

  xfree(tsk->redirs.v);
  xfree(tsk);
}

/* FIXME: how to implement? return HANDLE? */
int
task_GetPipe(tTask *tsk, int fd)
{
  int     i;
  tRedir *p;

  ASSERT(tsk);

  for (i = 0; i < tsk->redirs.u; i++) {
    p = &tsk->redirs.v[i];
    if (p->fd == fd && p->tag == TSR_PIPE) {
      write_log(LOG_REUSE, LOG_DEBUG, "task_GetPipe: handle %u",
                (unsigned int) p->u.p.pipe[1 - p->u.p.idx]);
      return (int) p->u.p.pipe[1 - p->u.p.idx];
    }
  }

  return -1;
}

static void
do_add_arg(tTask *tsk, char const *arg)
{
  XEXPAND2(tsk->args);
  tsk->args.v[tsk->args.u++] = xstrdup(arg);
}

  int
task_AddArg(tTask *tsk, char const *arg)
{
  ASSERT(tsk);
  if (!arg) arg = "";
  if (tsk->state != TSK_STOPPED) return -1;

  do_add_arg(tsk, arg);
  return 0;
}

int
task_nAddArgs(tTask *tsk, int n, ...)
{
  va_list args;

  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return -1;

  va_start(args, n);
  for (; n > 0; n--) {
    do_add_arg(tsk, va_arg(args, char *));
  }
  va_end(args);
  return 0;
}

int
task_zAddArgs(tTask *tsk, ...)
{
  va_list  args;
  char    *s;

  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return -1;

  va_start(args, tsk);
  while ((s = va_arg(args, char *)))
    do_add_arg(tsk, s);
  va_end(args);
  return 0;
}

int
task_pnAddArgs(tTask *tsk, int n, char **p)
{
  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return -1;
  if (!p) return 0;

  for (; n > 0; n--) {
    do_add_arg(tsk, *p++);
  }
  return 0;
}

int
task_pzAddArgs(tTask *tsk, char **p)
{
  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return -1;
  if (!p) return 0;

  while (*p) {
    do_add_arg(tsk, *p++);
  }
  return 0;
}

int
task_SetPath(tTask *tsk, char const *arg)
{
  ASSERT(tsk);
  ASSERT(arg);
  if (tsk->state != TSK_STOPPED) return -1;

  xfree(tsk->path);
  tsk->path = xstrdup(arg);
  return 0;
}

char *
task_SetPathAsArg0(tTask *tsk)
{
  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return NULL;
  if (tsk->args.u <= 0) return NULL;

  xfree(tsk->path);
  tsk->path = xstrdup(tsk->args.v[0]);
  return tsk->path;
}

int
task_SetWorkingDir(tTask *tsk, char const *path)
{
  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return 0;

  xfree(tsk->working_dir);
  tsk->working_dir = xstrdup(path);
  return 0;
}

int
task_PutEnv(tTask *tsk, char const *var)
{
  int n, i;
  char *p;

  ASSERT(tsk);
  ASSERT(var);

  if (tsk->state != TSK_STOPPED) return 0;
  if ((p = strchr(var, '='))) {
    n = p - var + 1;
    for (i = 0; i < tsk->env.u; ++i) {
      if (!strncmp(var, tsk->env.v[i], n)) {
        xfree(tsk->env.v[i]);
        tsk->env.v[i] = xstrdup(var);
        return 0;
      }
    }
    xexpand(&tsk->env);
    tsk->env.v[tsk->env.u++] = xstrdup(var);
  } else {
    n = strlen(var);
    for (i = 0; i<tsk->env.u; ++i) {
      if (!strncmp(var, tsk->env.v[i], n)) {
        if (tsk->env.v[i][n] == '=') {
          xfree(tsk->env.v[i]);
          tsk->env.v[i] = tsk->env.v[--tsk->env.u];
          return 0;
        }
      }
    }
  }
  return 0;
}

int
task_SetEnv(tTask *tsk, const char *name, const char *value)
{
  ASSERT(tsk);
  ASSERT(name);

  if (!value) {
    return task_PutEnv(tsk, name);
  } else {
    int nlen = strlen(name);
    int vlen = strlen(value);
    if (nlen + vlen < 65536) {
      unsigned char *b = (unsigned char*) alloca((nlen + vlen + 2) * sizeof(*b));
      memcpy(b, name, nlen);
      b[nlen] = '=';
      memcpy(b + nlen + 1, value, vlen);
      b[nlen + vlen + 1] = 0;
      return task_PutEnv(tsk, b);
    } else {
      unsigned char *b = (unsigned char*) xmalloc((nlen + vlen + 2) * sizeof(*b));
      memcpy(b, name, nlen);
      b[nlen] = '=';
      memcpy(b + nlen + 1, value, vlen);
      b[nlen + vlen + 1] = 0;
      int r = task_PutEnv(tsk, b);
      xfree(b);
      return r;
    }
  }
}

int
task_FormatEnv(tTask *tsk, const char *name, const char *format, ...)
{
  unsigned char buf[16384];
  unsigned char buf2[16384];
  va_list args;

  ASSERT(tsk);
  ASSERT(name);

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  snprintf(buf2, sizeof(buf2), "%s=%s", name, buf);
  return task_PutEnv(tsk, buf2);
}

int
task_ClearEnv(tTask *tsk)
{
  ASSERT(tsk);
  tsk->clear_env = 1;
  return 0;
}

int
task_SetMaxTime(tTask *tsk, int secs)
{
  ASSERT(tsk);
  ASSERT(secs >= 0);
  ASSERT(tsk->state == TSK_STOPPED);

  tsk->max_time = secs;
  return 0;
}

int
task_SetMaxTimeMillis(tTask *tsk, int msecs)
{
  ASSERT(tsk);
  ASSERT(msecs >= 0);
  ASSERT(tsk->state == TSK_STOPPED);

  tsk->max_time_millis = msecs;
  return 0;
}

int
task_SetMaxRealTime(tTask *tsk, int secs)
{
  ASSERT(tsk);
  ASSERT(secs >= 0);
  ASSERT(tsk->state == TSK_STOPPED);

  tsk->max_real_time = secs;
  return 0;
}

int
task_SetMaxRealTimeMillis(tTask *tsk, int msecs)
{
  ASSERT(tsk);
  ASSERT(msecs >= 0);
  ASSERT(tsk->state == TSK_STOPPED);

  tsk->max_real_time = (msecs + 999) / 1000;
  return 0;
}

int
task_SetMaxProcCount(tTask *tsk, int cnt)
{
  ASSERT(tsk);
  ASSERT(cnt >= 0);
  ASSERT(tsk->state == TSK_STOPPED);

  tsk->max_proc_count = cnt;
  return 0;
}

  int
task_SetRedir(tTask *tsk, int fd, int mode, ...)
{
  va_list  args;
  int      i;
  tRedir  *p;

  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return -1;

  XEXPAND2(tsk->redirs);
  i = tsk->redirs.u++;
  p = &tsk->redirs.v[i];

  p->fd  = fd;
  p->tag = mode;

  va_start(args, mode);
  switch (mode) {
  case TSR_DUP:
    p->u.fd2 = va_arg(args, int);
    break;
  case TSR_FILE:
    p->u.s.path  = xstrdup(va_arg(args, char *));
    p->u.s.oflag = va_arg(args, int);
    p->u.s.mode  = va_arg(args, int);
    break;
  case TSR_CLOSE:
    break;
  case TSR_PIPE:
    p->u.p.idx     = !!va_arg(args, int);
    p->u.p.pipe[0] = INVALID_HANDLE_VALUE;
    p->u.p.pipe[1] = INVALID_HANDLE_VALUE;
    break;
  default:
    SWERR(("task_SetRedir: mode == %d", mode));
  }
  va_end(args);

  return 0;
}

int
task_SetEntryFunction(tTask *tsk, int (*func)(int, char **))
{
  ASSERT(tsk);

  tsk->main = func;
  return 0;
}

int
task_EnableAllSignals(tTask *tsk)
{
  return 0;
}

int
task_IgnoreSIGPIPE(tTask *tsk)
{
  return 0;
}

int
task_DisableCoreDump(tTask *tsk)
{
  ASSERT(tsk);
  return 0;
}

int
task_EnableMemoryLimitError(tTask *tsk)
{
  return 0;
}

int
task_SetSuidHelperDir(tTask *tsk, const char *path)
{
  return 0;
}

int
task_EnableSecureExec(tTask *tsk)
{
  return 0;
}

int
task_EnableSuidExec(tTask *tsk)
{
  return 0;
}

int
task_EnableSecurityViolationError(tTask *tsk)
{
  return 0;
}

int
task_SetQuietFlag(tTask *tsk)
{
  return 0;
}

char *
task_GetErrorMessage(tTask *tsk)
{
  return "UNSUPPORTED";
}

int
task_SetDataSize(tTask *tsk, size_t size)
{
  ASSERT(tsk);
  ASSERT(tsk->state == TSK_STOPPED);
  // 0 means no limit
  tsk->max_data_size = size;
  return 0;
}

int
task_SetStackSize(tTask *tsk, size_t size)
{
  ASSERT(tsk);
  ASSERT(tsk->state == TSK_STOPPED);
  tsk->max_stack_size = size;
  return 0;
}

int
task_SetVMSize(tTask *tsk, size_t size)
{
  ASSERT(tsk);
  ASSERT(tsk->state == TSK_STOPPED);
  tsk->max_vm_size = size;
  return 0;
}

int
task_SetKillSignal(tTask *tsk, char const *signame)
{
  ASSERT(tsk);
  return 0;
}

int
task_EnableProcessGroup(tTask *tsk)
{
  return 0;
}

int
task_SetMaxCoreSize(tTask *tsk, ssize_t max_core_size)
{
  return 0;
}

int
task_SetMaxFileSize(tTask *tsk, ssize_t max_file_size)
{
  return 0;
}

int
task_SetMaxLockedMemorySize(tTask *tsk, ssize_t max_locked_memory_size)
{
  return 0;
}

int
task_SetMaxMessageQueueSize(tTask *tsk, ssize_t max_msg_queue_size)
{
  return 0;
}

int
task_SetMaxNiceValue(tTask *tsk, int max_nice_value)
{
  return 0;
}

int
task_SetMaxOpenFileCount(tTask *tsk, int max_open_file_count)
{
  return 0;
}

int
task_SetMaxProcessCount(tTask *tsk, int max_process_count)
{
  return 0;
}

int
task_SetMaxPrioValue(tTask *tsk, int max_prio_value)
{
  return 0;
}

int
task_SetMaxPendingCount(tTask *tsk, int max_pending_count)
{
  return 0;
}

int
task_SetUmask(tTask *tsk, int umask)
{
  return 0;
}

static char *
print_as_shell_redir(int oflags)
{
  if ((oflags & O_RDWR))
    return "<>";
  if ((oflags & O_APPEND))
    return ">>";
  if ((oflags & O_WRONLY))
    return ">";
  if ((oflags & O_RDONLY))
    return "<";
  return "?";
}

int
task_PrintArgs(tTask *tsk)
{
  int i;

  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return -1;

  if (!tsk->path && tsk->args.u > 0) {
    tsk->path = xstrdup(tsk->args.v[0]);
  }

  if (verbose_flag) {
    if (tsk->main) {
      fprintf(stderr, "task_Start: 0x%08x(%d):",
              (unsigned int) tsk->main, tsk->args.u);
    } else {
      fprintf(stderr, "task_Start: execv(%d):", tsk->args.u);
    }

    for (i = 0; i < tsk->args.u; i++) {
      fprintf(stderr, " %s", tsk->args.v[i]?tsk->args.v[i]:"<NULL>");
    }

    for (i = 0; i < tsk->redirs.u; i++) {
      tRedir *p = &tsk->redirs.v[i];
      fprintf(stderr, " %u", p->fd);
      switch (p->tag) {
      case TSR_FILE:
        fprintf(stderr, "%s%s",
                print_as_shell_redir(p->u.s.oflag),
                p->u.s.path);
        break;
      case TSR_CLOSE:
        fprintf(stderr, "-");
        break;
      case TSR_DUP:
        fprintf(stderr, ">&%u", p->u.fd2);
        break;
      case TSR_PIPE:
        fprintf(stderr, "%c|", (p->u.p.idx)?'>':'<');
        break;
      default:
        SWERR(("task_PrintArgs: unsupported redirection: %d", p->tag));
      }
    }

    fprintf(stderr, "\n");
  }

  return 0;
}

static int std_handle_names[3] =
{
  STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
};

static HANDLE
normalize_handle(int h)
{
  switch (h) {
  case 0:  return GetStdHandle(STD_INPUT_HANDLE);
  case 1:  return GetStdHandle(STD_OUTPUT_HANDLE);
  case 2:  return GetStdHandle(STD_ERROR_HANDLE);
  default: return (HANDLE) h;
  }
}

static int
close_std_handle(tTask *tsk, int ind)
{
  HANDLE *p;

  ASSERT(tsk);
  ASSERT(ind >= 0 || ind <= 2);
  p = tsk->std_streams[ind];

  if (*p != NULL && *p != INVALID_HANDLE_VALUE) {
    if (!CloseHandle(*p)) {
      write_log(LOG_REUSE, LOG_ERROR,
                "CloseHandle([%d]) failed: %d", ind, GetLastError());
      tsk->state = TSK_ERROR;
      *p = NULL;
      return -1;
    }
  }
  *p = NULL;
  return 0;
}

static int
dup_std_handle(tTask *tsk, int ind, HANDLE src)
{
  HANDLE *p;

  ASSERT(ind >= 0 || ind <= 2);
  p = tsk->std_streams[ind];
  if (src == NULL || src == INVALID_HANDLE_VALUE) {
    src = GetStdHandle(std_handle_names[ind]);
  }

  if (*p == src) return 0;
  if (close_std_handle(tsk, ind) < 0) return -1;

  if (!DuplicateHandle(tsk->prc, src,
                       tsk->prc, p,
                       0, TRUE, DUPLICATE_SAME_ACCESS)) {
    write_log(LOG_REUSE, LOG_ERR,
              "DuplicateHandle failed: %d", GetLastError());
    tsk->state = TSK_ERROR;
    return -1;
  }
  return 0;
}

int
task_Start(tTask *tsk)
{
  int     cmdlen = 0;
  int     i;
  HANDLE  hnd = INVALID_HANDLE_VALUE;
  char   *src, *dst;
  envvar_table_t *envtable = 0;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui_limit;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION ex_limit;

  write_log(LOG_REUSE, LOG_DEBUG, "task_Start: entered");

  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) {
    write_log(LOG_REUSE, LOG_ERROR, "task_Start: bad state");
    return -1;
  }

  if (verbose_flag) task_PrintArgs(tsk);

  if (tsk->main) {
    int code;

    /* just call the specified function */
    tsk->state = TSK_RUNNING;
    code = tsk->main(tsk->args.u, tsk->args.v);
    tsk->state = TSK_EXITED;
    tsk->is_exited = 1;
    tsk->exit_code = code;
    return 0;
  }

  /* build solid commandline */
  /* need to reserve room for escape " -> \", \ -> \\ */
  for (i = 0; i < tsk->args.u; i++) {
    cmdlen += strlen(tsk->args.v[i]) * 2 + 3;
  }

  XCALLOC(tsk->cmdline, cmdlen);
  dst = tsk->cmdline;
  for (i = 0; i < tsk->args.u; i++) {
    if (i) *dst++ = ' ';
    *dst++ = '\"';
    src = tsk->args.v[i];
    while (*src) {
      if (*src == '\\' || *src == '\"') *dst++ = '\\';
      *dst++ = *src++;
    }
    *dst++ = '\"';
  }
  *dst = 0;

  /* build environment block */
  /* unfortunately we need the getenv and putenv function
   * that manipulate our own environment variable set
   */

  if (tsk->env.u > 0) {
    envtable = envvar_make_table(tsk->clear_env);
    for (i = 0; i < tsk->env.u; i++)
      envvar_put(envtable, tsk->env.v[i]);
    tsk->envblock = envvar_make_block(envtable);
    envvar_free(envtable);
    envtable = 0;
  } else if (!tsk->clear_env) {
    // pass the environment unchanged
    tsk->envblock = 0;
  } else {
    // clear the environment
    tsk->envblock = xstrdup("");
  }

  /* do default redirections: duplicate standard handles */
  tsk->si.cb         = sizeof(tsk->si);
  tsk->si.dwFlags    = STARTF_USESTDHANDLES;
  if (dup_std_handle(tsk, 0, NULL) < 0) return -1;
  if (dup_std_handle(tsk, 1, NULL) < 0) return -1;
  if (dup_std_handle(tsk, 2, NULL) < 0) return -1;

  /* process user redirections */
  for (i = 0; i < tsk->redirs.u; i++) {
    tRedir *p = &tsk->redirs.v[i];
    ASSERT(p->fd >= 0 && p->fd <= 2);

    switch (p->tag) {
    case TSR_DUP:
      // FIXME: we should manipulate with the new handle names
      switch (p->u.fd2) {
      case 0: hnd = tsk->si.hStdInput; break;
      case 1: hnd = tsk->si.hStdOutput; break;
      case 2: hnd = tsk->si.hStdError; break;
      default:
        SWERR(("not supported"));
        break;
      }
      if (dup_std_handle(tsk,p->fd,hnd) < 0) return -1;
      break;
    case TSR_CLOSE:
      if (close_std_handle(tsk, p->fd) < 0) return -1;
      break;
    case TSR_FILE:
      {
        int                 rw_mode     = 0;
        int                 open_mode   = 0;
        int                 sh_mode     = 0;
        HANDLE              new_hnd;
        SECURITY_ATTRIBUTES attr;

        /* translate some special names */
        if (!strcmp(p->u.s.path, "/dev/null")) {
          xfree(p->u.s.path);
          p->u.s.path = xstrdup("NUL");
        } else if (!strcmp(p->u.s.path, "/dev/stdin")) {
          if (dup_std_handle(tsk, p->fd, normalize_handle(0)) < 0) return -1;
          break;
        } else if (!strcmp(p->u.s.path, "/dev/stdout")) {
          if (dup_std_handle(tsk, p->fd, normalize_handle(1)) < 0) return -1;
          break;
        } else if (!strcmp(p->u.s.path, "/dev/stderr")) {
          if (dup_std_handle(tsk, p->fd, normalize_handle(2)) < 0) return -1;
          break;
        }

        switch (p->u.s.oflag) {
        case TSK_REWRITE:
          rw_mode   = GENERIC_WRITE;
          open_mode = CREATE_ALWAYS;
          sh_mode   = FILE_SHARE_READ | FILE_SHARE_WRITE;
          break;
        case TSK_WRITE:
          rw_mode   = GENERIC_WRITE;
          open_mode = OPEN_EXISTING;
          sh_mode   = FILE_SHARE_READ | FILE_SHARE_WRITE;
          break;
        case TSK_READ:
          rw_mode   = GENERIC_READ;
          open_mode = OPEN_EXISTING;
          sh_mode   = FILE_SHARE_READ | FILE_SHARE_WRITE;
          break;
		case TSK_APPEND:
		  rw_mode = GENERIC_WRITE;
		  open_mode = CREATE_ALWAYS;
          sh_mode   = FILE_SHARE_READ | FILE_SHARE_WRITE;
		  break;
        default:
          SWERR(("unsupported open mode: %d", p->u.s.oflag));
        }

        if (close_std_handle(tsk, p->fd) < 0) return -1;

        attr.nLength              = sizeof(attr);
        attr.lpSecurityDescriptor = NULL;
        attr.bInheritHandle       = TRUE;
        new_hnd = CreateFile(p->u.s.path, rw_mode, sh_mode,
                             &attr, open_mode, 0, NULL);
        if (new_hnd == INVALID_HANDLE_VALUE) {
          write_log(LOG_REUSE, LOG_ERROR,
                    "CreateFile(\"%s\", ...) failed: %d",
                    p->u.s.path, GetLastError());
          tsk->state = TSK_ERROR;
          return -1;
        }
        *tsk->std_streams[p->fd] = new_hnd;
      }
      break;
    case TSR_PIPE:
      {
        SECURITY_ATTRIBUTES attr;

        attr.nLength              = sizeof(attr);
        attr.lpSecurityDescriptor = NULL;
        attr.bInheritHandle       = TRUE;

        close_std_handle(tsk, p->fd);
        if (!(CreatePipe(&p->u.p.pipe[0], &p->u.p.pipe[1], &attr, 0))) {
          write_log(LOG_REUSE, LOG_ERROR, "CreatePipe failed: %d",
                    GetLastError());
          tsk->state = TSK_ERROR;
          return -1;
        }

        /* make non-inheritable the other end of pipe */
        SetHandleInformation(p->u.p.pipe[1 - p->u.p.idx],
                             HANDLE_FLAG_INHERIT, 0);
        *tsk->std_streams[p->fd] = p->u.p.pipe[p->u.p.idx];
      }
      break;
    default:
      SWERR(("task_Start: unsupported redirection: %d", p->tag));
    }
  }

  // if no limits are set, just run the process
  if (!tsk->max_proc_count
      && !tsk->max_vm_size && !tsk->max_stack_size && !tsk->max_data_size
      && !tsk->max_time && !tsk->max_time_millis) {
    if (!CreateProcess(NULL, tsk->cmdline, NULL, NULL,
                       TRUE, CREATE_NEW_PROCESS_GROUP,
                       tsk->envblock, tsk->working_dir,
                       &tsk->si, &tsk->pi)) {
      write_log(LOG_REUSE, LOG_ERROR, "CreateProcess failed: %d",
                GetLastError());
      tsk->state = TSK_ERROR;
      tsk->code = GetLastError();
      return -1;
    }

    /* close the opposite side of pipes */
    for (i = 0; i < tsk->redirs.u; i++) {
      tRedir *p = &tsk->redirs.v[i];
      if (p->tag == TSR_PIPE) {
        HANDLE hh = p->u.p.pipe[p->u.p.idx];
        if (hh != NULL && hh != INVALID_HANDLE_VALUE) {
          CloseHandle(hh);
          p->u.p.pipe[p->u.p.idx] = INVALID_HANDLE_VALUE;
        }
      }
    }

    /* close standard descriptors */
    if (tsk->si.hStdInput != INVALID_HANDLE_VALUE) {
      CloseHandle(tsk->si.hStdInput);
      tsk->si.hStdInput = INVALID_HANDLE_VALUE;
    }
    if (tsk->si.hStdOutput != INVALID_HANDLE_VALUE) {
      CloseHandle(tsk->si.hStdOutput);
      tsk->si.hStdOutput = INVALID_HANDLE_VALUE;
    }
    if (tsk->si.hStdError != INVALID_HANDLE_VALUE) {
      CloseHandle(tsk->si.hStdError);
      tsk->si.hStdError = INVALID_HANDLE_VALUE;
    }

    write_log(LOG_REUSE, LOG_INFO, "new process started: %u",
              (unsigned int) tsk->pi.hProcess);
    tsk->state = TSK_RUNNING;
    return 0;
  }

  // impose a number of restrictions on the process to start
  if ((tsk->job = CreateJobObjectA(NULL, NULL)) == INVALID_HANDLE_VALUE) {
    tsk->state = TSK_ERROR;
    tsk->code = GetLastError();
    write_log(LOG_REUSE, LOG_ERROR, "CreateJobObject failed: %d", tsk->code);
    return -1;
  }

  memset(&ui_limit, 0, sizeof(ui_limit));
  ui_limit.UIRestrictionsClass = JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_HANDLES;
  if (!SetInformationJobObject(tsk->job, JobObjectBasicUIRestrictions,
                               &ui_limit, sizeof(ui_limit))) {
    tsk->state = TSK_ERROR;
    tsk->code = GetLastError();
    write_log(LOG_REUSE, LOG_ERROR, "SetInformationJobObject failed: %d", tsk->code);
    return -1;
  }

  memset(&ex_limit, 0, sizeof(ex_limit));
  ex_limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | */ JOB_OBJECT_LIMIT_PRIORITY_CLASS;
  ex_limit.BasicLimitInformation.PriorityClass = NORMAL_PRIORITY_CLASS;

  if (tsk->max_time_millis) {
    ex_limit.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = (long long) tsk->max_time_millis * 10000;
    ex_limit.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = (long long) tsk->max_time_millis * 10000;
    ex_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_PROCESS_TIME;
  } else if (tsk->max_time) {
    ex_limit.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = (long long) tsk->max_time * 10000000;
    ex_limit.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = (long long) tsk->max_time * 10000000;
    ex_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_PROCESS_TIME;
  }

  if (tsk->max_vm_size) {
    ex_limit.JobMemoryLimit = tsk->max_vm_size;
    ex_limit.ProcessMemoryLimit = tsk->max_vm_size;
    ex_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  }

  if (tsk->max_proc_count) {
    ex_limit.BasicLimitInformation.ActiveProcessLimit = tsk->max_proc_count;
    ex_limit.BasicLimitInformation.LimitFlags|=JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  }

  if (!SetInformationJobObject(tsk->job, JobObjectExtendedLimitInformation,
                               &ex_limit, sizeof(ex_limit))) {
    tsk->state = TSK_ERROR;
    tsk->code = GetLastError();
    write_log(LOG_REUSE, LOG_ERROR, "SetInformationJobObject failed: %d", tsk->code);
    return -1;
  }

  if (!CreateProcess(NULL, tsk->cmdline, NULL, NULL,
                     TRUE, CREATE_SUSPENDED,
                     tsk->envblock, tsk->working_dir,
                     &tsk->si, &tsk->pi)) {
    tsk->state = TSK_ERROR;
    tsk->code = GetLastError();
    write_log(LOG_REUSE, LOG_ERROR, "CreateProcess failed: %d", tsk->code);
    return -1;
  }

  if (!AssignProcessToJobObject(tsk->job, tsk->pi.hProcess)) {
    TerminateProcess(tsk->pi.hProcess, 255);
    CloseHandle(tsk->pi.hProcess); tsk->pi.hProcess = INVALID_HANDLE_VALUE;
    CloseHandle(tsk->pi.hThread); tsk->pi.hThread = INVALID_HANDLE_VALUE;
    tsk->state = TSK_ERROR;
    tsk->code = GetLastError();
    write_log(LOG_REUSE, LOG_ERROR, "AssignProcessToJobObject failed: %d", tsk->code);
    return -1;
  }
  tsk->start_time = GetTickCount();
  if (!ResumeThread(tsk->pi.hThread)) {
    TerminateProcess(tsk->pi.hProcess, 255);
    CloseHandle(tsk->pi.hProcess); tsk->pi.hProcess = INVALID_HANDLE_VALUE;
    CloseHandle(tsk->pi.hThread); tsk->pi.hThread = INVALID_HANDLE_VALUE;
    tsk->state = TSK_ERROR;
    tsk->code = GetLastError();
    write_log(LOG_REUSE, LOG_ERROR, "AssignProcessToJobObject failed: %d", tsk->code);
    return -1;
  }

  /* close the opposite side of pipes */
  for (i = 0; i < tsk->redirs.u; i++) {
    tRedir *p = &tsk->redirs.v[i];
    if (p->tag == TSR_PIPE) {
      HANDLE hh = p->u.p.pipe[p->u.p.idx];
      if (hh != NULL && hh != INVALID_HANDLE_VALUE) {
        CloseHandle(hh);
        p->u.p.pipe[p->u.p.idx] = INVALID_HANDLE_VALUE;
      }
    }
  }

  /* close standard descriptors */
  if (tsk->si.hStdInput != INVALID_HANDLE_VALUE) {
    CloseHandle(tsk->si.hStdInput);
    tsk->si.hStdInput = INVALID_HANDLE_VALUE;
  }
  if (tsk->si.hStdOutput != INVALID_HANDLE_VALUE) {
    CloseHandle(tsk->si.hStdOutput);
    tsk->si.hStdOutput = INVALID_HANDLE_VALUE;
  }
  if (tsk->si.hStdError != INVALID_HANDLE_VALUE) {
    CloseHandle(tsk->si.hStdError);
    tsk->si.hStdError = INVALID_HANDLE_VALUE;
  }

  tsk->state = TSK_RUNNING;
  write_log(LOG_REUSE, LOG_INFO, "new process started: %u",
            (unsigned int) tsk->pi.hProcess);
  return 0;
}

void task_update_info(tTask *tsk);

tTask *
task_Wait(tTask *tsk)
{
  unsigned int cur_time;
  int r;

  ASSERT(tsk);

  if (tsk->state == TSK_ERROR || tsk->state == TSK_STOPPED) return NULL;
  if (tsk->state == TSK_SIGNALED || tsk->state == TSK_EXITED) return tsk;

  ASSERT(tsk->state == TSK_RUNNING);

  if (tsk->max_real_time) {
    cur_time = GetTickCount();
    const int wait_add = 40;
    int wait_time = tsk->max_real_time * 1000 - (cur_time - tsk->start_time) + wait_add;
    while (wait_time > 0) {
      int wait_delta = 100;
      if (wait_time < wait_delta)
	wait_delta = wait_time;
      r = WaitForSingleObject(tsk->pi.hProcess, wait_delta);
      if (r == WAIT_FAILED) {
	tsk->state = TSK_ERROR;
	tsk->code = GetLastError();
	write_log(LOG_REUSE, LOG_ERROR, "WaitForSingleObject failed: %d",
		  GetLastError());
	return NULL;
      }
      task_update_info(tsk);
      if (task_IsTimeout(tsk)) {
	break;
      }
      if (r != WAIT_TIMEOUT) {
	break;
      }
      wait_time -= wait_delta;
    }
    
    if (r == WAIT_TIMEOUT) {
      write_log(LOG_REUSE, LOG_ERROR, "RealTime timeout: %d",
                GetTickCount() - tsk->start_time);
      if (tsk->job != INVALID_HANDLE_VALUE) {
        // FIXME: set a reasonable error code
	if (!TerminateJobObject(tsk->job, 255)) {
          // FIXME: handle error
        }
      } else {
        // FIXME: set a reasonable error code
        if (!TerminateProcess(tsk->pi.hProcess, 255)) {
          // FIXME: handle error
        }
      }
      if (WaitForSingleObject(tsk->pi.hProcess, INFINITE) == WAIT_FAILED) {
        // FIXME: handle error
      }
      tsk->was_real_timeout = 1;
    }
  } else {
    if (WaitForSingleObject(tsk->pi.hProcess, INFINITE) == WAIT_FAILED) {
      tsk->state = TSK_ERROR;
      tsk->code = GetLastError();
      write_log(LOG_REUSE, LOG_ERROR, "WaitForSingleObject failed: %d",
                GetLastError());
      return NULL;
    }
  }
  
  GetExitCodeProcess(tsk->pi.hProcess, (DWORD*) &tsk->code);
  if (PROC_SIGNALED(tsk->code)) {
    tsk->state = TSK_SIGNALED;
  } else {
    tsk->state = TSK_EXITED;
  }
  
  task_update_info(tsk);
  return tsk;
}

void
task_update_info(tTask *tsk)
{
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION basic_acct;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext_limit;
  
  unsigned int finish_time = GetTickCount();
  
  if (tsk->job != INVALID_HANDLE_VALUE) {
    if (!QueryInformationJobObject(tsk->job,
                                   JobObjectBasicAccountingInformation,
                                   &basic_acct, sizeof(basic_acct), NULL)) {
      // accounting information is not available
      write_log(LOG_REUSE, LOG_ERROR, "QueryInformationJobObject failed: %d",
                GetLastError());
      return;
    }
    if (!QueryInformationJobObject(tsk->job, JobObjectExtendedLimitInformation,
                                   &ext_limit, sizeof(ext_limit), NULL)) {
      // accounting information is not available
      write_log(LOG_REUSE, LOG_ERROR, "QueryInformationJobObject failed: %d",
                GetLastError());
      return;
    }

    tsk->used_time = (basic_acct.TotalKernelTime.QuadPart + basic_acct.TotalUserTime.QuadPart) / 10000;
    tsk->real_time = finish_time - tsk->start_time;
    tsk->used_proc_count = basic_acct.ActiveProcesses;
    tsk->used_real_time = finish_time - tsk->start_time;
    tsk->used_vm_size = ext_limit.PeakJobMemoryUsed;
  }
}

tTask *
task_NewWait(tTask *tsk)
{
  return task_Wait(tsk);
}

int
task_Status(tTask *tsk)
{
  ASSERT(tsk);
  return tsk->state;
}

int
task_TermSignal(tTask *tsk)
{
  ASSERT(tsk);
  if (tsk->state != TSK_SIGNALED) return -1;
  return PROC_SIGNALCODE(tsk->code);
}

int
task_ExitCode(tTask *tsk)
{
  ASSERT(tsk);
  if (tsk->state != TSK_EXITED)
    return -1;
  if (tsk->is_exited)
    return tsk->exit_code;
  return PROC_EXITCODE(tsk->code);
}

int
task_IsTimeout(tTask *tsk)
{
  ASSERT(tsk);
  if (tsk->was_real_timeout) return 1;
  if (tsk->max_time_millis > 0 && tsk->used_time >= tsk->max_time_millis) return 1;
  if (tsk->max_time > 0 && tsk->used_time >= tsk->max_time * 1000) return 1;
  return 0;
}

int
task_IsRealTimeout(tTask *tsk)
{
  return 0;
}

int
task_IsMemoryLimit(tTask *tsk)
{
  return 0;
}

int
task_IsSecurityViolation(tTask *tsk)
{
  return 0;
}

long
task_GetRunningTime(tTask *tsk)
{
  ASSERT(tsk);
  return tsk->used_time;
}

long
task_GetRealTime(tTask *tsk)
{
  ASSERT(tsk);
  return tsk->real_time;
}

long
task_GetMemoryUsed(tTask *tsk)
{
  ASSERT(tsk);
  return tsk->used_vm_size;
}

int
task_GetProcessStats(tTask *tsk, struct ej_process_stats *pstats)
{
  memset(pstats, 0, sizeof(*pstats));
  return -1;
}

int
task_IsAbnormal(tTask *tsk)
{
  ASSERT(tsk);
  if (tsk->state == TSK_SIGNALED)
    return 1;
  if (tsk->state == TSK_EXITED && tsk->is_exited && tsk->exit_code > 0)
    return 1;
  if (tsk->state == TSK_EXITED && tsk->code > 0)
    return 1;
  return 0;
}

void
task_Log(tTask *tsk, int fac, int sev)
{
  ASSERT(tsk);

  if (tsk->state != TSK_SIGNALED && tsk->state != TSK_EXITED)
    return;

  if (tsk->state == TSK_SIGNALED) {
      write_log(fac, sev,
                "process %u is terminated with signal %d (%s)",
                (unsigned int) tsk->pi.hProcess,
                PROC_SIGNALCODE(tsk->code),
                os_GetSignalString(PROC_SIGNALCODE(tsk->code)));
  } else {
      int   r = tsk->code;
      if (tsk->is_exited) r = tsk->exit_code;
      write_log(fac, sev,
                "process %u is exited with code %d",
                (unsigned int) tsk->pi.hProcess, PROC_EXITCODE(r));
    }
}

int
task_ErrorCode(tTask *tsk, int *p_exit_code, int *p_error)
{
  return 0;
}

int
task_Kill(tTask *tsk)
{
  return 0;
}

int
task_TryProcessGroup(tTask *tsk)
{
  return 0;
}

int
task_KillProcessGroup(tTask *tsk)
{
  return 0;
}

static envvar_table_t *
envvar_make_table(int clear_env_flag)
{
  unsigned char *sblk = "";
  unsigned char *p = sblk, *q, *name, *value;
  envvar_table_t *tbl;
  size_t esz;

  if (!clear_env_flag) sblk = GetEnvironmentStrings();

  XCALLOC(tbl, 1);
  tbl->a = 16;
  XCALLOC(tbl->vars, tbl->a);

  while (*p) {
    esz = strlen(p);
    if (!(q = strchr(p, '='))) {
      name = xstrdup(p);
      value = xstrdup("");
    } else {
      name = xmemdup(p, q - p);
      value = xstrdup(p + 1);
    }
    if (tbl->u == tbl->a) {
      tbl->a *= 2;
      XREALLOC(tbl->vars, tbl->a);
    }
    tbl->vars[tbl->u].name = name;
    tbl->vars[tbl->u].value = value;
    tbl->u++;
    p += esz + 1;
  }

  if (!clear_env_flag) FreeEnvironmentStrings(sblk);

  return tbl;
}

static unsigned char *
envvar_make_block(envvar_table_t *t)
{
  size_t outsize = 0, sz;
  int i;
  unsigned char *blk, *p;

  if (!t) return xstrdup("");

  for (i = 0; i < t->u; i++) {
    outsize += strlen(t->vars[i].name) + strlen(t->vars[i].value) + 2;
  }

  XCALLOC(blk, outsize + 1);
  p = blk;

  for (i = 0; i < t->u; i++) {
    sz = strlen(t->vars[i].name);
    strcpy(p, t->vars[i].name);
    p += sz;
    *p++ = '=';
    sz = strlen(t->vars[i].value);
    strcpy(p, t->vars[i].value);
    p += sz + 1;
  }

  return blk;
}

static envvar_table_t *
envvar_free(envvar_table_t *t)
{
  int i;

  if (!t) return 0;
  for (i = 0; i < t->u; i++) {
    xfree(t->vars[i].name);
    xfree(t->vars[i].value);
  }
  xfree(t->vars);
  xfree(t);
  return 0;
}

static void
envvar_put(envvar_table_t *t, const char *str)
{
  const char *eqp;
  unsigned char *name, *value;
  int i;

  if (!str) return;
  if (!(eqp = strchr(str, '='))) {
    // remove the given variable
    name = (unsigned char*) str;
    for (i = 0; i < t->u; i++)
      if (!strcmp(name, t->vars[i].name))
        break;
    if (i == t->u) return;
    xfree(t->vars[i].name);
    xfree(t->vars[i].value);
    for (i++; i < t->u; i++) {
      t->vars[i - 1].name = t->vars[i].name;
      t->vars[i - 1].value = t->vars[i].value;
    }
    t->u--;
  } else {
    // put the value
    name = (unsigned char*) alloca(eqp - str + 1);
    memcpy(name, str, eqp - str);
    name[eqp - str] = 0;
    value = (unsigned char*) eqp + 1;
    for (i = 0; i < t->u; i++)
      if (!strcmp(name, t->vars[i].name))
        break;
    if (i < t->u) {
      // replace the existing value
      xfree(t->vars[i].value);
      t->vars[i].value = xstrdup(value);
    } else {
      // append a new value
      if (t->u == t->a) {
        t->a *= 2;
        XREALLOC(t->vars, t->a);
      }
      t->vars[t->u].name = name;
      t->vars[t->u].value = value;
      t->u++;
    }
  }
}
