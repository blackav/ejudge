/* Copyright (C) 1998-2016 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1998-01-21 14:33:28 cher> */

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
 * FILE:    unix/exec.c
 * PURPOSE: process abstraction layer
 */

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#ifdef __linux__
#include <sys/ptrace.h>
#include <sys/utsname.h>
#endif

#ifndef __GNUC__
#define __FUNCTION__ "???"
#endif /* __GNUC__ */

/* file descriptor redirections */
typedef struct tRedir
{
  int       fd;                 /* file descriptor */
  int       tag;                /* file descriptor operation */
  union
  {
    int       fd2;              /* second fd for dup operation */
    struct
    {
      char     *path;           /* file path */
      int       oflag;          /* flags for open(2) call */
      int       mode;           /* mode for open(2) call */
    }         s;                /* file redirection structure */
    struct
    {
      int       idx;            /* inherited pipe */
      int       pfd[2];         /* as returned by pipe(2) */
    }         p;
  }         u;
} tRedir;

/* task description structure */
struct tTask
{
  int  (*main)(int, char **);   /* task start function */
  char  *suid_helper_dir;       /* directory with suid helpers */
  char  *path;                  /* task invocation path */
  int    state;                 /* current task state */
  int    code;                  /* process termination code */
  int    is_exited;             /* is process exited normally */
  int    exit_code;             /* process exit code */
  int    pid;                   /* process pid */
  char  *working_dir;           /* the working directory */
  int    max_time;              /* maximal allowed time */
  int    max_time_millis;       /* maximal allowed time in milliseconds */
  int    max_real_time;         /* maximal allowed realtime */
  int    was_timeout;           /* was the timeout happened? */
  int    was_real_timeout;      /* was the real time limit exceeded? */
  int    was_memory_limit;      /* was the memory limit happened? */
  int    was_security_violation;/* was the security violation happened? */
  int    termsig;               /* termination signal */
  int    max_stack_size;        /* max size of stack */
  int    max_data_size;         /* max size of data */
  int    max_vm_size;           /* max size of virtual memory */
  int    disable_core;          /* disable core dumps? */
  int    enable_memory_limit_error; /* enable memory limit error detection? */
  int    enable_secure_exec;    /* drop capabilities before exec'ing */
  int    enable_suid_exec;      /* change user_id through suid helper binaries */
  int    enable_security_violation_error;/*enable security violation detection*/
  int    clear_env;             /* clear the environment? */
  int    quiet_flag;            /* be quiet */
  int    enable_all_signals;    /* unmask all signals after fork */
  int    ignore_sigpipe;        /* ignore SIGPIPE after fork */
  int    enable_process_group;  /* create a new process group */
  ssize_t max_core_size;        /* maximum size of core files */
  ssize_t max_file_size;        /* maximum size of created files */
  ssize_t max_locked_mem_size;  /* maximum size of locked memory */
  ssize_t max_msg_queue_size;   /* maximum size of POSIX message queues */
  int    max_nice_value;        /* max priority */
  int    max_open_file_count;   /* max number of open files per process */
  int    max_process_count;     /* max number of created processes/threads */
  int    max_prio_value;        /* max real-time priority */
  int    max_pending_count;     /* max number of pending signals */
  int    umask;                 /* process umask */
  struct rusage usage;          /* process resource utilization */
  struct timeval start_time;    /* start real-time */
  struct timeval stop_time;     /* stop real-time */
  struct
  {
    char **v;                   /* pointer to data */
    int    u;                   /* used entries */
    int    a;                   /* allocated entries */
  }      args;                  /* arguments to pass to subprocess */
  struct
  {
    tRedir *v;                  /* pointer to data */
    int     u;                  /* used entries */
    int     a;                  /* allocated entries */
  } redirs;                     /* redirections */
  strarray_t env;               /* environment variables */

  char *last_error_msg;         /* last error text */
  unsigned long used_vm_size;   /* maximum used VM size (if available) */
  int cleanup_invoked;          /* not to invoke cleanup handler several times */
};

#define PIDARR_SIZE 32
static pid_t volatile pidarr[PIDARR_SIZE]; /* pids of terminated processes */
static int   volatile statarr[PIDARR_SIZE]; /* return code of term. process */
static struct rusage usagearr[PIDARR_SIZE];
static int   volatile pidused;  /* used entries in pidarr, statarr */

static tTask **task_v;          /* task descriptors */
static int     task_u;          /* used entries in task_v */
static int     task_a;          /* allocated entries */
static int     task_active;     /* number of active tasks */

static int     verbose_flag;    /* 1 - report info of started processes */

static int linux_ms_time_limit = -1;
static int linux_secure_exec_supported = -1;

#ifdef __linux__
static int linux_fix_time_flag = -1;
static int linux_ptrace_code = -1;
static int linux_rlimit_code = -1;
static void linux_set_fix_flag(void);
static int linux_secure_exec_new_interface = 0;
static void linux_set_secure_exec_supported_flag(void);
#endif

static int do_kill(tTask *tsk, int pid, int signal);

/**
 * NAME:    sigchld_handler
 * PURPOSE: handler for SIGCHLD signal (child termination)
 * ARGS:    sig - signal number
 */
volatile static int sigchld_flag = 0;
  static void
sigchld_handler(int sig)
{
  sigchld_flag = 1;
  (void) &sigchld_handler;
}

static void task_fini_module(void);
static int initialized = 0;
static void
task_init_module(void)
{
  sigset_t bm;

  if (initialized) return;
  initialized = 1;

  sigemptyset(&bm);
  sigaddset(&bm, SIGCHLD);
  sigprocmask(SIG_BLOCK, &bm, 0);
  signal(SIGCHLD, sigchld_handler);
  atexit(task_fini_module);
}
static void
task_fini_module(void)
{
  if (!initialized) return;
  initialized = 0;
  xfree(task_v);
}

/**
 * NAME:    find_prc_in_list
 * PURPOSE: find task with specified pid and modify its status
 *          according to the status provided
 * ARGS:    pid    - process pid
 *          stat   - process termination status
 *          pusage - process resource utilization
 */
  static void
find_prc_in_list(pid_t pid, int stat, struct rusage *pusage)
{
  int i;
  unsigned long long elapsed = 0LL;

  for (i = 0; i < task_u; i++)
    if (task_v[i] && task_v[i]->pid == pid)
      break;

  if (i >= task_u) return;

  if (task_v[i]->enable_memory_limit_error && (stat & 0x10000)) {
    task_v[i]->was_memory_limit = 1;
  }
  if (task_v[i]->enable_security_violation_error && (stat & 0x20000)) {
    task_v[i]->was_security_violation = 1;
  }
  if ((stat & 0x40000)) {
    task_v[i]->was_timeout = 1;
  }
  stat &= 0xffff;
  gettimeofday(&task_v[i]->stop_time, 0);

  task_active--;

  // workaround for broken usage ru_stime field
  if (pusage->ru_stime.tv_sec > 100000) {
    fprintf(stderr, "BOGUS ru_stime VALUE, fixing it to be 0\n");
    fprintf(stderr, "ru_stime.tv_sec: %ld\n", pusage->ru_stime.tv_sec);
    fprintf(stderr, "ru_stime.tv_usec: %ld\n", pusage->ru_stime.tv_usec);
    pusage->ru_stime.tv_sec = 0;
    pusage->ru_stime.tv_usec = 0;
  }

  elapsed += pusage->ru_utime.tv_sec * 1000;
  elapsed += pusage->ru_stime.tv_sec * 1000;
  elapsed += pusage->ru_utime.tv_usec / 1000;
  elapsed += pusage->ru_stime.tv_usec / 1000;
  if (task_v[i]->max_time_millis > 0 && elapsed >= task_v[i]->max_time_millis) {
    task_v[i]->was_timeout = 1;
  } else if (task_v[i]->max_time > 0 && elapsed >= task_v[i]->max_time * 1000) {
    task_v[i]->was_timeout = 1;
  }

  if (WIFSIGNALED(stat)) {
    if (linux_ms_time_limit > 0 && WTERMSIG(stat) == SIGKILL
	&& !task_v[i]->was_timeout && task_v[i]->max_time_millis > 0) {
      if (elapsed >= task_v[i]->max_time_millis)
        task_v[i]->was_timeout = 1;
    } else if (linux_ms_time_limit <= 0 && !task_v[i]->was_timeout
               && task_v[i]->max_time_millis > 0) {
      if (elapsed >= task_v[i]->max_time_millis) {
        task_v[i]->was_timeout = 1;
        // FIXME: ugly hack: update the process time accounting structure
        pusage->ru_utime.tv_sec = task_v[i]->max_time_millis / 1000;
        pusage->ru_stime.tv_sec = 0;
        pusage->ru_utime.tv_usec = (task_v[i]->max_time_millis % 1000) * 1000;
        pusage->ru_stime.tv_usec = 0;
      }
    } else {
      if (WTERMSIG(stat) == SIGKILL && !task_v[i]->was_timeout
          && task_v[i]->max_time > 0
          && elapsed >= task_v[i]->max_time * 1000) {
        task_v[i]->was_timeout = 1;
      }
    }
    task_v[i]->state = TSK_SIGNALED;
  } else {
    if (linux_ms_time_limit <= 0 && !task_v[i]->was_timeout
        && task_v[i]->max_time_millis > 0) {
      if (elapsed >= task_v[i]->max_time_millis) {
        task_v[i]->was_timeout = 1;
        // FIXME: ugly hack: update the process time accounting structure
        pusage->ru_utime.tv_sec = task_v[i]->max_time_millis / 1000;
        pusage->ru_stime.tv_sec = 0;
        pusage->ru_utime.tv_usec = (task_v[i]->max_time_millis % 1000) * 1000;
        pusage->ru_stime.tv_usec = 0;
      }
    }
    task_v[i]->state = TSK_EXITED;
  }
  task_v[i]->code = stat;
  task_v[i]->usage = *pusage;
}

/**
 * NAME:    bury_dead_prc
 * PURPOSE: modify task status for all terminated processes
 */
  static void
bury_dead_prc(void)
{
  pid_t pid;
  int   f = 1;
  int   stat;
  struct rusage usage;
  sigset_t bs, os;

  sigemptyset(&bs);
  sigaddset(&bs, SIGCHLD);
  sigprocmask(SIG_UNBLOCK, &bs, &os);
  if (!sigismember(&os, SIGCHLD)) {
    fprintf(stderr, "EXEC: BURY_DEAD_PRC: SIGCHLD WAS NOT BLOCKED\n");
  }

  while (f)
    {
      f = 0;

      // FIXME: does it ever work???
      while (pidused > 0)
        {
          f = 1;
          pid  = pidarr[pidused];
          stat = statarr[pidused];
          usage = usagearr[pidused];
          pidused--;

          find_prc_in_list(pid, stat, &usage);
        }

      memset(&usage, 0, sizeof(usage));
      pid = wait4(-1, &stat, WNOHANG, &usage);
      if (pid > 0)
        {
          f = 1;

          find_prc_in_list(pid, stat, &usage);
        }
    }

  sigprocmask(SIG_BLOCK, &bs, 0);
  sigchld_flag = 0;
}

/**
 * NAME:    task_SetFlag
 * PURPOSE: set module options
 * ARGS:    opt  - option name
 *          flag - option id
 * RETURN:  0
 * NOTE:    this function is called back from getopt module
 */
  int
task_SetFlag(char *opt, int flag)
{
  task_init_module();
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

/**
 * NAME:    task_New
 * PURPOSE: create new task structure
 * RETURN:  pointer to newly created task structure
 */
  tTask *
task_New(void)
{
  tTask *r;
  int i;

  task_init_module();
  bury_dead_prc();

  r = xcalloc(1, sizeof(tTask));
  r->state = TSK_STOPPED;
  r->termsig = SIGTERM;

  r->max_core_size = -1;
  r->max_file_size = -1;
  r->max_locked_mem_size = -1;
  r->max_msg_queue_size = -1;
  r->max_nice_value = -1;
  r->max_open_file_count = -1;
  r->max_process_count = -1;
  r->max_prio_value = -1;
  r->max_pending_count = -1;
  r->umask = -1;

  /* find an empty slot */
  for (i = 0; i < task_u; i++)
    if (!task_v[i]) break;
  if (i >= task_u) {
    if (task_u >= task_a) {
      task_a += 16;
      task_v = xrealloc(task_v, sizeof(task_v[0]) * task_a);
    }
    task_v[task_u++] = r;
  } else {
    task_v[i] = r;
  }

  return r;
}

/**
 * NAME:    task_Delete
 * PURPOSE: delete task structure
 * ARGS:    tsk - task to delete
 * NOTE:    if task is active when deleted, task is not terminated
 *          but detached and not watched for exit
 */
  void
task_Delete(tTask *tsk)
{
  int i;

  task_init_module();
  bury_dead_prc();

  if (!tsk) return;

  for (i = 0; i < task_u; i++)
    if (task_v[i] == tsk)
      {
        if (tsk->state == TSK_RUNNING)
          task_active--;
        task_v[i] = NULL;
      }

  for (i = 0; i < tsk->args.u; i++)
    xfree(tsk->args.v[i]);
  for (i = 0; i < tsk->redirs.u; i++) {
    if (tsk->redirs.v[i].tag == TSR_FILE) {
      xfree(tsk->redirs.v[i].u.s.path);
    } else if (tsk->redirs.v[i].tag == TSR_PIPE) {
      int *pp = tsk->redirs.v[i].u.p.pfd;
      if (pp[0] >= 0) close(pp[0]);
      if (pp[1] >= 0) close(pp[0]);
    }
  }
  for (i = 0; i < tsk->env.u; i++)
    xfree(tsk->env.v[i]);
  xfree(tsk->path);
  xfree(tsk->env.v);
  xfree(tsk->args.v);
  xfree(tsk->redirs.v);
  xfree(tsk->working_dir);
  xfree(tsk->last_error_msg);
  xfree(tsk->suid_helper_dir);
  xfree(tsk);
}

/**
 * NAME:    task_GetPipe
 * PURPOSE: get the actual fd of pipe redirections
 * ARGS:    tsk - task structure
 *          fd  - piped file descriptor
 * RETURNS: >= 0 - fd of the pipe
 *           < 0 - error
 */
  int
task_GetPipe(tTask *tsk, int fd)
{
  int i;

  ASSERT(tsk);
  task_init_module();

  for (i = 0; i < tsk->redirs.u; i++) {
    if (tsk->redirs.v[i].fd == fd && tsk->redirs.v[i].tag == TSR_PIPE) {
      /*
        tRedir rdr = tsk->redirs.v + i;
        int    idx = rdr->u.p.idx;
        if (idx < 0) idx = 0;
        if (idx > 1) idx = 1;
        idx = 1 - idx;
        return rdr->u.p.pfd[idx];
       */
      return tsk->redirs.v[i].u.p.pfd[(tsk->redirs.v[i].u.p.idx <= 0)?1:0];
    }
  }
  return -1;
}

/**
 * NAME:    do_add_arg
 * PURPOSE: add argument to the task start arguments
 * ARGS:    tsk - task to add argument to
 *          arg - argument to add
 */
  static void
do_add_arg(tTask *tsk, char const *arg)
{
  if (tsk->args.u + 1 >= tsk->args.a)
    {
      tsk->args.a += 16;
      tsk->args.v = (char**) xrealloc(tsk->args.v,
                                      sizeof(char*) * tsk->args.a);
    }
  tsk->args.v[(tsk->args.u)++] = xstrdup(arg);
  tsk->args.v[tsk->args.u] = NULL;
}

/**
 * NAME:    task_AddArg
 * PURPOSE: add argument to task start arguments
 * ARGS:    tsk - task
 *          arg - argument
 */
  int
task_AddArg(tTask *tsk, char const *arg)
{
  task_init_module();
  ASSERT(tsk);
  if (!arg) arg = "";

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    {
      return -1;
    }

  do_add_arg(tsk, arg);
  return 0;
}

/**
 * NAME:    task_nAddArgs
 * PURPOSE: add arguments to the tast invokation arguments
 * ARGS:    tsk - task
 *          n   - number of arguments
 *          ... - arguments (char* pointers)
 * RETURN:  0 - ok, -1 - error
 */
  int
task_nAddArgs(tTask *tsk, int n, ...)
{
  va_list args;

  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    {
      return -1;
    }

  va_start(args, n);
  for (; n > 0; n--)
    do_add_arg(tsk, va_arg(args, char *));
  va_end(args);

  return 0;
}

/**
 * NAME:    task_zAddArgs
 * PURPOSE: add task invokation arguments
 * ARGS:    tsk - task
 *          ... - extra arguments (terminated with NULL argument)
 * RETURN:  0 - ok, -1 - error
 */
  int
task_zAddArgs(tTask *tsk, ...)
{
  va_list  args;
  char    *s;

  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    {
      return -1;
    }

  va_start(args, tsk);
  while ((s = va_arg(args, char *)))
    do_add_arg(tsk, s);
  va_end(args);

  return 0;
}

/**
 * NAME:    task_pnAddArgs
 * PURPOSE: add arguments to task invokation parameters
 * ARGS:    tsk - task
 *          n   - number of arguments
 *          p   - array of arguments
 * RETURN:  0 - ok, -1 - error
 */
  int
task_pnAddArgs(tTask *tsk, int n, char **p)
{
  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    {
      return -1;
    }

  if (!p) return 0;
  for (; n > 0; n--)
    do_add_arg(tsk, *p++);

  return 0;
}

/**
 * NAME:    task_pzAddArgs
 * PURPOSE: add arguments to task invokation arguments
 * ARGS:    tsk - task
 *          p   - array of arguments (terminated with NULL)
 * RETURN:  0 - ok, -1 - error
 */
  int
task_pzAddArgs(tTask *tsk, char **p)
{
  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    {
      return -1;
    }

  if (!p) return 0;
  while (*p)
    do_add_arg(tsk, *p++);

  return 0;
}

/**
 * NAME:    task_SetPath
 * PURPOSE: set invokation path
 * ARGS:    tsk - task
 *          arg - invocation path
 * RETURN:  0 - ok, -1 - error
 */
  int
task_SetPath(tTask *tsk, char const *arg)
{
  task_init_module();
  ASSERT(tsk);
  ASSERT(arg);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    return -1;

  xfree(tsk->path);
  tsk->path = xstrdup(arg);
  return 0;
}

/**
 * NAME:    task_SetPathAsArg0
 * PURPOSE: use argv[0] as invokation path
 * ARGS:    tsk - task
 * RETURN:  invocation path, or NULL if error
 * NOTE:    the function is deprecated, argv[0] is used by default
 *          if explicit invocation path is not set
 */
  char *
task_SetPathAsArg0(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    return NULL;

  if (tsk->args.u <= 0)
    return NULL;
  xfree(tsk->path);
  tsk->path = xstrdup(tsk->args.v[0]);
  return tsk->path;
}

/**
 * NAME:    task_SetWorkingDir
 * PURPOSE: set the working directory for the task
 * ARGS:    tsk  - task
 *          path - the working directory
 * RETURN:  0 - successful completion
 */
  int
task_SetWorkingDir(tTask *tsk, char const *path)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return 0;

  xfree(tsk->working_dir);
  tsk->working_dir = xstrdup(path);
  return 0;
}

/**
 * NAME:    task_PutEnv
 * PURPOSE: adds one environment variable, which will be set when
 *          the process is started. Environment variable is specified
 *          in form "NAME=VALUE". If only "NAME" is specified, that
 *          variable is removed from the environment.
 * ARGS:    tsk - task
 *          s   - environment variable specification
 */
int
task_PutEnv(tTask *tsk, char const *s)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_STOPPED) return 0;

  xexpand(&tsk->env);
  tsk->env.v[tsk->env.u++] = xstrdup(s);
  return 0;
}

int
task_SetEnv(tTask *tsk, const char *name, const char *value)
{
  task_init_module();
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

  task_init_module();
  ASSERT(tsk);
  ASSERT(name);

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  snprintf(buf2, sizeof(buf2), "%s=%s", name, buf);
  return task_PutEnv(tsk, buf2);
}


/**
 * NAME:    task_ClearEnv
 * PURPOSE: set the 'clear environment' flag
 * ARGS:    tsk - task
 * RETURN:  0 - successful completion
 */
int
task_ClearEnv(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->clear_env = 1;
  return 0;
}

/**
 * NAME:    task_SetMaxTime
 * PURPOSE: set the maximum time for the process
 * ARGS:    tsk  - task
 *          time - the maximum time in seconds
 * RETURN:  0 - successful completion
 */
int
task_SetMaxTime(tTask *tsk, int time)
{
  task_init_module();
  ASSERT(tsk);
  bury_dead_prc();
  if (tsk->state != TSK_STOPPED) return 0;

#ifdef __linux__
  if (linux_fix_time_flag < 0) linux_set_fix_flag();
  ASSERT(linux_ms_time_limit >= 0);
  ASSERT(linux_fix_time_flag >= 0);
#endif /* __linux__ */

  tsk->max_time = time;
  tsk->max_time_millis = 0;
  return 0;
}

int
task_SetMaxTimeMillis(tTask *tsk, int time)
{
  task_init_module();
  ASSERT(tsk);
  bury_dead_prc();
  if (tsk->state != TSK_STOPPED) return 0;

#ifdef __linux__
  if (linux_fix_time_flag < 0) linux_set_fix_flag();
  ASSERT(linux_ms_time_limit >= 0);
  ASSERT(linux_fix_time_flag >= 0);
#endif /* __linux__ */

  tsk->max_time = 0;
  tsk->max_time_millis = time;
  return 0;
}

/**
 * NAME:    task_SetMaxRealTime
 * PURPOSE: set the maximum real (astronomic) time for the process
 * ARGS:    tsk  - task
 *          time - the maximum time in seconds
 * RETURN:  0 - successful completion
 */
int
task_SetMaxRealTime(tTask *tsk, int time)
{
  task_init_module();
  ASSERT(tsk);
  bury_dead_prc();
  if (tsk->state != TSK_STOPPED) return 0;

  tsk->max_real_time = time;
  return 0;
}

int
task_SetMaxRealTimeMillis(tTask *tsk, int time_ms)
{
  task_init_module();
  ASSERT(tsk);
  bury_dead_prc();
  if (tsk->state != TSK_STOPPED) return 0;

  tsk->max_real_time = (time_ms + 999) / 1000;
  return 0;
}

/**
 * NAME:    task_SetRedir
 * PURPOSE: set file descriptiors redirections
 * ARGS:    tsk  - task
 *          fd   - file descriptor
 *          mode - redirection mode
 *          ...  - redirection mode specific arguments
 * RETURN:  0 - ok, -1 - error
 * NOTE:    redirection mode specific arguments are as follows:
 *            for TSR_CLOSE:
 *              no specific arguments
 *            for TSR_FILE
 *              char *path  - file path
 *              int   oflag - open flags
 *              int   mode  - open file mode
 *            for TSR_DUP
 *              int fd2     - second file descriptor
 *            for TSR_PIPE
 *              int   idx   - inherited index of the pipe
 *                            (0 - read, 1 - write)
 */
  int
task_SetRedir(tTask *tsk, int fd, int mode, ...)
{
  int     i;
  va_list args;
  int     m, p;

  task_init_module();
  bury_dead_prc();

  ASSERT(tsk);
  ASSERT(fd >= 0);

  if (tsk->state != TSK_STOPPED)
    return -1;

  if (tsk->redirs.u >= tsk->redirs.a)
    {
      tsk->redirs.a += 16;
      tsk->redirs.v = xrealloc(tsk->redirs.v,
                               tsk->redirs.a * sizeof(tsk->redirs.v[0]));
    }
  i = tsk->redirs.u++;

  tsk->redirs.v[i].fd = fd;
  tsk->redirs.v[i].tag = mode;

  va_start(args, mode);
  switch (mode)
    {
    case TSR_DUP:
      tsk->redirs.v[i].u.fd2 = va_arg(args, int);
      break;
    case TSR_FILE:
      tsk->redirs.v[i].u.s.path = xstrdup(va_arg(args, char*));
      m = va_arg(args, int);
      p = va_arg(args, int);
      switch (m) {
      case TSK_READ:     m = O_RDONLY; p = 0; break;
      case TSK_WRITE:    m = O_WRONLY; p = 0; break;
      case TSK_REWRITE:  m = O_CREAT | O_WRONLY | O_TRUNC; break;
      case TSK_APPEND:   m = O_CREAT | O_WRONLY | O_APPEND; break;
      }
      switch (p) {
      case TSK_FULL_RW:  p = 0666; break;
      }
      tsk->redirs.v[i].u.s.oflag = m;
      tsk->redirs.v[i].u.s.mode = p;
      break;
    case TSR_CLOSE:
      break;
    case TSR_PIPE:
      tsk->redirs.v[i].u.p.idx = !!va_arg(args, int);
      tsk->redirs.v[i].u.p.pfd[0] = -1;
      tsk->redirs.v[i].u.p.pfd[1] = -1;
      break;
    default:
      SWERR(("task_SetRedir: mode == %d", mode));
    }
  va_end(args);

  return 0;
}

/**
 * NAME:    task_SetEntryFunction
 * PURPOSE: sets a pointer to an entry function to be called
 *          instead of fork/exec
 * ARGS:    tsk  - the task
 *          func - the entry function
 * RETURN:  0 - successful completion
 */
  int
task_SetEntryFunction(tTask *tsk, int (*func)(int, char **))
{
  task_init_module();
  ASSERT(tsk);
  tsk->main = func;
  return 0;
}

int
task_EnableMemoryLimitError(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);

#ifdef __linux__
  if (linux_fix_time_flag < 0) linux_set_fix_flag();
  ASSERT(linux_ms_time_limit >= 0);
  ASSERT(linux_fix_time_flag >= 0);

  if (linux_ptrace_code <= 0) return -1;

  tsk->enable_memory_limit_error = 1;
  return 0;
#else
  return -1;
#endif /* __linux__ */
}

int
task_EnableSecurityViolationError(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);

#ifdef __linux__
  if (linux_fix_time_flag < 0) linux_set_fix_flag();
  ASSERT(linux_ms_time_limit >= 0);
  ASSERT(linux_fix_time_flag >= 0);

  if (linux_ptrace_code <= 0) return -1;

  tsk->enable_security_violation_error = 1;
  return 0;
#else
  return -1;
#endif /* __linux__ */
}

int
task_EnableSecureExec(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);

#ifdef __linux__
  linux_set_secure_exec_supported_flag();
  if (linux_secure_exec_supported != 1) return -1;
  tsk->enable_secure_exec = 1;
  return 0;
#else
  return -1;
#endif /* __linux__ */
}

int
task_SetSuidHelperDir(tTask *tsk, const char *path)
{
  task_init_module();
  ASSERT(tsk);
  xfree(tsk->suid_helper_dir);
  tsk->suid_helper_dir = xstrdup(path);
  return 0;
}

int
task_EnableSuidExec(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->enable_suid_exec = 1;
  return 0;
}

int
task_EnableAllSignals(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->enable_all_signals = 1;
  return 0;
}

int
task_IgnoreSIGPIPE(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->ignore_sigpipe = 1;
  return 0;
}

int
task_EnableProcessGroup(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->enable_process_group = 1;
  return 0;
}

int
task_SetMaxCoreSize(tTask *tsk, ssize_t max_core_size)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_core_size = max_core_size;
  return 0;
}

int
task_SetMaxFileSize(tTask *tsk, ssize_t max_file_size)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_file_size = max_file_size;
  return 0;
}

int
task_SetMaxLockedMemorySize(tTask *tsk, ssize_t max_locked_mem_size)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_locked_mem_size = max_locked_mem_size;
  return 0;
}

int
task_SetMaxMessageQueueSize(tTask *tsk, ssize_t max_msg_queue_size)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_msg_queue_size = max_msg_queue_size;
  return 0;
}

int
task_SetMaxNiceValue(tTask *tsk, int max_nice_value)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_nice_value = max_nice_value;
  return 0;
}

int
task_SetMaxOpenFileCount(tTask *tsk, int max_open_file_count)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_open_file_count = max_open_file_count;
  return 0;
}

int
task_SetMaxProcessCount(tTask *tsk, int max_process_count)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_process_count = max_process_count;
  return 0;
}

int
task_SetMaxPrioValue(tTask *tsk, int max_prio_value)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_prio_value = max_prio_value;
  return 0;
}

int
task_SetMaxPendingCount(tTask *tsk, int max_pending_count)
{
  task_init_module();
  ASSERT(tsk);
  tsk->max_pending_count = max_pending_count;
  return 0;
}

int
task_SetUmask(tTask *tsk, int umask)
{
  task_init_module();
  ASSERT(tsk);
  tsk->umask = umask;
  return 0;
}

int
task_DisableCoreDump(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->disable_core = 1;
  return 0;
}

int
task_SetQuietFlag(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  tsk->quiet_flag = 1;
  return 0;
}

char *
task_GetErrorMessage(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (!tsk->last_error_msg) return "no error";
  return tsk->last_error_msg;
}

int
task_SetDataSize(tTask *tsk, int size)
{
  task_init_module();
  ASSERT(tsk);
  if (size < 0) return -1;
  tsk->max_data_size = size;
  return 0;
}

int
task_SetStackSize(tTask *tsk, int size)
{
  task_init_module();
  ASSERT(tsk);
  if (size < 0) return -1;
  tsk->max_stack_size = size;
  return 0;
}

int
task_SetVMSize(tTask *tsk, int size)
{
  task_init_module();
  ASSERT(tsk);
  if (size < 0) return -1;
  tsk->max_vm_size = size;
  return 0;
}

int
task_SetKillSignal(tTask *tsk, char const *signame)
{
  task_init_module();
  ASSERT(tsk);

  if (!signame) {
    tsk->termsig = SIGTERM;
    return 0;
  }
  if (!strcasecmp(signame, "kill")) {
    tsk->termsig = SIGKILL;
  } else if (!strcasecmp(signame, "term")) {
    tsk->termsig = SIGTERM;
  } else if (!strcasecmp(signame, "int")) {
    tsk->termsig = SIGINT;
  } else {
    char buf[512];

    snprintf(buf, sizeof(buf), "invalid signal specification: '%s'", signame);
    if (tsk->quiet_flag) {
      xfree(tsk->last_error_msg);
      tsk->last_error_msg = xstrdup(buf);
    } else {
      write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , buf);
    }
    return -1;
  }
  return 0;
}

/**
 * NAME:    print_as_shell_redir
 * PURPOSE: pretty print task file descriptor redirection
 * ARGS:    oflags - open flags specified for redirection
 * RETURN:  string - redirection in external form
 */
  static char *
print_as_shell_redir(int oflags)
{
  if ((oflags & O_ACCMODE) == O_RDWR)
    return "<>";
  if ((oflags & O_ACCMODE) == O_RDONLY)
    return "<";
  if ((oflags & O_ACCMODE) == O_WRONLY) {
    if ((oflags & O_APPEND))
      return ">>";
    return ">";
  }
  return "?";
}

/**
 * NAME:    task_PrintArgs
 * PURPOSE: print arguments of the task, including redirections
 * ARGS:    tsk - task
 * RETURN:  0 - ok, -1 - error
 */
  int
task_PrintArgs(tTask *tsk)
{
  int i;

  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state != TSK_STOPPED)
    return -1;

  if (!tsk->path && tsk->args.u > 0)
    tsk->path = xstrdup(tsk->args.v[0]);

  if (1 /*verbose_flag*/)
    {
      if (tsk->main) {
        fprintf(stderr, "task_Start: 0x%08lx(%d):",
                (unsigned long) tsk->main, tsk->args.u);
      } else {
        fprintf(stderr, "task_Start: execv(%d):", tsk->args.u);
      }
      for (i = 0; i < tsk->args.u; i++)
        fprintf(stderr, " %s", tsk->args.v[i]?tsk->args.v[i]:"<NULL>");

      for (i = 0; i < tsk->redirs.u; i++)
        {
          fprintf(stderr, " %d", tsk->redirs.v[i].fd);
          switch (tsk->redirs.v[i].tag)
            {
            case TSR_FILE:
              fprintf(stderr, "%s%s",
                      print_as_shell_redir(tsk->redirs.v[i].u.s.oflag),
                      tsk->redirs.v[i].u.s.path);
              break;
            case TSR_CLOSE:
              fprintf(stderr, "-");
              break;
            case TSR_DUP:
              fprintf(stderr, ">&%d", tsk->redirs.v[i].u.fd2);
              break;
            case TSR_PIPE:
              fprintf(stderr, "%c|", (tsk->redirs.v[i].u.p.idx)?'>':'<');
              break;
            default:
              SWERR(("task_Start: invalid redirection %d",
                     tsk->redirs.v[i].tag));
            }
        }

      fprintf(stderr, "\n");
    }
  return 0;
}

void
task_fPrintArgs(tTask *tsk, FILE *fout)
{
  int i;

  if (tsk->args.u > 0) {
    fprintf(fout, " %s", tsk->args.v[0]?tsk->args.v[0]:"<NULL>");
  }
  for (i = 1; i < tsk->args.u; i++)
    fprintf(fout, " %s", tsk->args.v[i]?tsk->args.v[i]:"<NULL>");

  for (i = 0; i < tsk->redirs.u; i++) {
    fprintf(fout, " %d", tsk->redirs.v[i].fd);
    switch (tsk->redirs.v[i].tag) {
    case TSR_FILE:
      fprintf(fout, "%s%s", print_as_shell_redir(tsk->redirs.v[i].u.s.oflag),
              tsk->redirs.v[i].u.s.path);
      break;
    case TSR_CLOSE:
      fprintf(fout, "-");
      break;
    case TSR_DUP:
      fprintf(fout, ">&%d", tsk->redirs.v[i].u.fd2);
      break;
    case TSR_PIPE:
      fprintf(fout, "%c|", (tsk->redirs.v[i].u.p.idx)?'>':'<');
      break;
    default:
      SWERR(("task_Start: invalid redirection %d", tsk->redirs.v[i].tag));
    }
  }
  fprintf(fout, "\n");
}

#define TASK_ERR_PIPE_FAILED       100
#define TASK_ERR_COMM_PIPE_FAILED  101
#define TASK_ERR_COMM_DUP_FAILED   102
#define TASK_ERR_COMM_FCNTL_FAILED 103
#define TASK_ERR_FORK_FAILED       104
#define TASK_ERR_REDIR_OPEN_FAILED 105
#define TASK_ERR_REDIR_DUP_FAILED  106
#define TASK_ERR_REDIR_INVALID     107
#define TASK_ERR_CHDIR_FAILED      108
#define TASK_ERR_EXECV_FAILED      109
#define TASK_ERR_RLIMIT_FAILED     110
#define TASK_ERR_PUTENV_FAILED     111
#define TASK_ERR_LIMIT_CPU_FAILED  112

static char *
format_exitcode(tTask *tsk, char *buf, int size, int code, int err)
{
  char *s;

  switch (code) {
  case TASK_ERR_PIPE_FAILED:        s = "pipe() failed";   break;
  case TASK_ERR_COMM_PIPE_FAILED:   s = "pipe() failed";   break;
  case TASK_ERR_COMM_DUP_FAILED:    s = "dup2() failed";   break;
  case TASK_ERR_COMM_FCNTL_FAILED:  s = "fcntl() failed";  break;
  case TASK_ERR_FORK_FAILED:        s = "fork() failed";   break;
  case TASK_ERR_REDIR_OPEN_FAILED:  s = "open() failed";   break;
  case TASK_ERR_REDIR_DUP_FAILED:   s = "dup2() failed";   break;
  case TASK_ERR_REDIR_INVALID:      s = "bad redirection"; break;
  case TASK_ERR_CHDIR_FAILED:       s = "chdir() failed";  break;
  case TASK_ERR_EXECV_FAILED:       s = "execv() failed";  break;
  case TASK_ERR_RLIMIT_FAILED:      s = "rlimit() failed"; break;
  case TASK_ERR_PUTENV_FAILED:      s = "putenv() failed"; break;
  case TASK_ERR_LIMIT_CPU_FAILED:   s = "rlimit() failed"; break;
  default:                          s = "unknown";         break;
  }
  if (tsk->quiet_flag) {
    snprintf(buf, size, "%s: %s", s, os_GetErrorString(err));
  } else {
    snprintf(buf,size,"%d, %s: %d, %s",code,s,err,os_GetErrorString(err));
    buf[size - 1] = 0;
  }
  return buf;
}

#define MAKECODE(c,e) (((c & 0xFF) << 16) | (e & 0xFFFF))

static void
set_limit(int fd, int resource, rlim_t value)
{
  struct rlimit lim;
  int code;

  memset(&lim, 0, sizeof(lim));
  lim.rlim_cur = value;
  lim.rlim_max = value;
  if (setrlimit(resource, &lim) < 0) {
    code = MAKECODE(TASK_ERR_RLIMIT_FAILED, errno);
    write(fd, &code, sizeof(code));
    _exit(TASK_ERR_RLIMIT_FAILED);
  }
}

static void
invoke_execv_helper(tTask *tsk, const char *path, char **args)
{
  char helper_path[PATH_MAX];
  int count;
  for (count = 0; args[count]; ++count) {}
  snprintf(helper_path, sizeof(helper_path), "%s/%s", tsk->suid_helper_dir, "ej-suid-exec");
  char **new_args = alloca((count + 3) * sizeof(new_args[0]));
  new_args[0] = helper_path;
  new_args[1] = "-d";
  for (count = 0; args[count]; ++count) {
    new_args[count + 2] = args[count];
  }
  new_args[count + 2] = NULL;
  errno = 0;
  execv(helper_path, new_args);
}

/**
 * NAME:    task_Start
 * PURPOSE: start a task
 * ARGS:    tsk - task
 * RETURN:  0 - ok, -1 - error
 */
  int
task_Start(tTask *tsk)
{
  pid_t   pid;
  int     i;
  int     comm_fd = -1;
  tRedir *rdr;
  char    errbuf[512];
  sigset_t ss;
  struct rlimit lim;

  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();
  if (signal(SIGCHLD, sigchld_handler) != sigchld_handler) {
    fprintf(stderr, "EXEC: TASK_START: SIGCHLD WAS RESET\n");
  }

  if (tsk->state != TSK_STOPPED)
    return -1;

  if (!tsk->path && tsk->args.u > 0)
    tsk->path = xstrdup(tsk->args.v[0]);

  //if (verbose_flag) task_PrintArgs(tsk);

  if (tsk->main) {
    int code;

    /* just call the specified function */
    tsk->state = TSK_RUNNING;
    tsk->pid = getpid();
    task_active++;
    code = tsk->main(tsk->args.u, tsk->args.v);
    tsk->state = TSK_EXITED;
    task_active--;
    tsk->is_exited = 1;
    tsk->exit_code = code;
    return 0;
  }

  /* create pipes */
  for (i = 0, rdr = tsk->redirs.v; i < tsk->redirs.u; i++, rdr++) {
    if (rdr->tag != TSR_PIPE) continue;
    if (pipe(rdr->u.p.pfd) < 0) {
      tsk->state = TSK_ERROR;
      tsk->pid = 1;
      tsk->code = errno;
      tsk->exit_code = TASK_ERR_PIPE_FAILED;
      snprintf(errbuf, sizeof(errbuf), "pipe() failed: %s", os_ErrorString());
      if (tsk->quiet_flag) {
        xfree(tsk->last_error_msg);
        tsk->last_error_msg = xstrdup(errbuf);
      } else {
        write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , errbuf);
      }
      return -1;
    }
  }

  /* get the number of communication fd and create status pipe */
  {
    int           pp[2];

    getrlimit(RLIMIT_NOFILE, &lim);
    comm_fd = lim.rlim_cur - 3;
    if (pipe(pp) < 0) {
      tsk->state = TSK_ERROR;
      tsk->pid = 1;
      tsk->code = errno;
      tsk->exit_code = TASK_ERR_COMM_PIPE_FAILED;
      snprintf(errbuf, sizeof(errbuf), "pipe() failed: %s", os_ErrorMsg());
      if (tsk->quiet_flag) {
        xfree(tsk->last_error_msg);
        tsk->last_error_msg = xstrdup(errbuf);
      } else {
        write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , errbuf);
      }
      return -1;
    }
    if (dup2(pp[0], comm_fd) < 0 || dup2(pp[1], comm_fd + 1) < 0) {
      tsk->state = TSK_ERROR;
      tsk->pid = 1;
      tsk->code = errno;
      tsk->exit_code = TASK_ERR_COMM_DUP_FAILED;
      snprintf(errbuf, sizeof(errbuf), "dup2() failed: %s", os_ErrorMsg());
      if (tsk->quiet_flag) {
        xfree(tsk->last_error_msg);
        tsk->last_error_msg = xstrdup(errbuf);
      } else {
        write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , errbuf);
      }
      close(pp[0]); close(pp[1]); close(comm_fd);
      return -1;      
    }
    close(pp[0]);
    close(pp[1]);

    /* set close-on-exec flag for write descriptor */
    if (fcntl(comm_fd + 1, F_SETFD, FD_CLOEXEC) < 0) {
      tsk->state = TSK_ERROR;
      tsk->pid = 1;
      tsk->code = errno;
      tsk->exit_code = TASK_ERR_COMM_FCNTL_FAILED;
      snprintf(errbuf, sizeof(errbuf), "fcntl() failed: %s", os_ErrorMsg());
      if (tsk->quiet_flag) {
        xfree(tsk->last_error_msg);
        tsk->last_error_msg = xstrdup(errbuf);
      } else {
        write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , errbuf);
      }
      close(comm_fd);
      close(comm_fd + 1);
      return -1;      
    }
  }

  // save the start real time
  gettimeofday(&tsk->start_time, 0);

  errno = 0;
  pid = fork();
  if (pid < 0)
    {
      tsk->state = TSK_ERROR;
      tsk->pid = 1;
      tsk->code = errno;
      tsk->exit_code = TASK_ERR_FORK_FAILED;
      snprintf(errbuf, sizeof(errbuf), "fork() failed: %s", os_ErrorMsg());
      if (tsk->quiet_flag) {
        xfree(tsk->last_error_msg);
        tsk->last_error_msg = xstrdup(errbuf);
      } else {
        write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , errbuf);
      }
      close(comm_fd); close(comm_fd + 1);
      return -1;
    }

  if (pid > 0)
    {
      int rb, rv;

      tsk->state = TSK_RUNNING;
      tsk->pid = pid;
      task_active++;

      if (tsk->enable_process_group > 0) {
        setpgid(tsk->pid, tsk->pid);
      }

      /* close the writing end of communication pipe */
      close(comm_fd + 1);

      /* close client's end of the pipe */
      for (i = 0, rdr = tsk->redirs.v; i < tsk->redirs.u; i++, rdr++) {
        if (rdr->tag != TSR_PIPE) continue;
        close(rdr->u.p.pfd[rdr->u.p.idx]);
        rdr->u.p.pfd[rdr->u.p.idx] = -1;
      }

      rb = read(comm_fd, &rv, sizeof(rv));
      if (rb < 0) {
        snprintf(errbuf, sizeof(errbuf), "read from pipe failed: %s",
                 os_ErrorMsg());
        if (tsk->quiet_flag) {
          xfree(tsk->last_error_msg);
          tsk->last_error_msg = xstrdup(errbuf);
        } else {
          write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__ , errbuf);
        }
        /* FIXME: should we mark process as not started? */
        close(comm_fd);
        return 0;
      }
      if (!rb) {
        /* everything seems ok */
        close(comm_fd);
        return 0;
      }
      if (rb != sizeof(rv)) {
        snprintf(errbuf, sizeof(errbuf), "child protocol error");
        if (tsk->quiet_flag) {
          xfree(tsk->last_error_msg);
          tsk->last_error_msg = xstrdup(errbuf);
        } else {
          write_log(LOG_REUSE, LOG_ERROR, "%s: %s", __FUNCTION__, errbuf);
        }
        /* FIXME: should we mark process as not started? */
        close(comm_fd);
        return 0;
      }

      {
        char buf[1024];

        tsk->state = TSK_ERROR;
        tsk->pid = 1;
        tsk->code = rv & 0xFFFF;
        tsk->exit_code = (rv >> 16) & 0xFF;
        format_exitcode(tsk, buf, sizeof(buf), tsk->exit_code, tsk->code);
        if (tsk->quiet_flag) {
          xfree(tsk->last_error_msg);
          tsk->last_error_msg = xstrdup(buf);
        } else {
          write_log(LOG_REUSE, LOG_ERROR, "%s: process not started: %s",
                    __FUNCTION__ , buf);
        }
        close(comm_fd);
        return -1;
      }
    }

  /* now we're at child */
  {
    int i;
    int tfd;
    int code;

    if (tsk->enable_process_group > 0) {
      setpgid(0, 0);
    }

#ifdef __linux__
    if (tsk->enable_memory_limit_error && linux_ptrace_code > 0) {
      code = ptrace(linux_ptrace_code, 0, 0, 0);
      //fprintf(stderr, "reuse: ptrace returned %d\n", code);
    }
#endif

    /* close the reading end of communication pipe */
    close(comm_fd);

    /* perform redirections */
    for (i = 0, rdr = tsk->redirs.v; i < tsk->redirs.u; i++, rdr++)
      {
        switch (tsk->redirs.v[i].tag)
          {
          case TSR_FILE:
            errno = 0;
            if ((tfd = open(tsk->redirs.v[i].u.s.path,
                            tsk->redirs.v[i].u.s.oflag,
                            tsk->redirs.v[i].u.s.mode)) < 0)
              {
                /*
                write_log(LOG_REUSE, LOG_CRIT,
                          "task_Start: failed to open(%s, %d, %4.4o): %s",
                          tsk->redirs.v[i].u.s.path,
                          tsk->redirs.v[i].u.s.oflag,
                          tsk->redirs.v[i].u.s.mode,
                          os_GetErrorString(errno));
                */
                code = MAKECODE(TASK_ERR_REDIR_OPEN_FAILED, errno);
                write(comm_fd + 1, &code, sizeof(code));
                _exit(TASK_ERR_REDIR_OPEN_FAILED);
              }
            errno = 0;
            if (dup2(tfd, tsk->redirs.v[i].fd) < 0)
              {
                /*
                write_log(LOG_REUSE, LOG_CRIT,
                          "task_Start: failed to dup2(%d, %d): %s",
                          tfd, tsk->redirs.v[i].fd,
                          os_GetErrorString(errno));
                */
                code = MAKECODE(TASK_ERR_REDIR_DUP_FAILED, errno);
                write(comm_fd + 1, &code, sizeof(code));
                _exit(TASK_ERR_REDIR_DUP_FAILED);
              }
            close(tfd);
            break;
            
          case TSR_DUP:
            errno = 0;
            if (dup2(tsk->redirs.v[i].u.fd2, tsk->redirs.v[i].fd) < 0)
              {
                /*
                write_log(LOG_REUSE, LOG_CRIT,
                          "task_Start: failed to dup2(%d, %d): %s",
                          tsk->redirs.v[i].u.fd2,
                          tsk->redirs.v[i].fd,
                          os_GetErrorString(errno));
                */
                code = MAKECODE(TASK_ERR_REDIR_DUP_FAILED, errno);
                write(comm_fd + 1, &code, sizeof(code));
                _exit(TASK_ERR_REDIR_DUP_FAILED);
              }
            break;
          case TSR_CLOSE:
            errno = 0;
            close(tsk->redirs.v[i].fd);
            /*
            if (close(tsk->redirs.v[i].fd) < 0)
              {
                write_log(LOG_REUSE, LOG_ERR,
                          "task_Start: failed to close(%d): %s",
                          tsk->redirs.v[i].fd,
                          os_GetErrorString(errno));
              }
            */
            break;
          case TSR_PIPE:
            errno = 0;
            if (rdr->u.p.pfd[rdr->u.p.idx] != rdr->fd) {
              if (dup2(rdr->u.p.pfd[rdr->u.p.idx], rdr->fd) < 0) {
                /*
                write_log(LOG_REUSE, LOG_CRIT,
                          "task_Start: failed to dup2(%d, %d): %s",
                          rdr->u.p.pfd[rdr->u.p.idx], rdr->fd,
                          os_ErrorString());
                */
                code = MAKECODE(TASK_ERR_REDIR_DUP_FAILED, errno);
                write(comm_fd + 1, &code, sizeof(code));
                _exit(TASK_ERR_REDIR_DUP_FAILED);
              }
              close(rdr->u.p.pfd[rdr->u.p.idx]);
            }
            close(rdr->u.p.pfd[1 - rdr->u.p.idx]);
            break;
          default:
            /*
            write_log(LOG_REUSE, LOG_CRIT, 
                      "task_Start: child: invalid redirection %d",
                      tsk->redirs.v[i].tag);
            */
            code = MAKECODE(TASK_ERR_REDIR_INVALID, 0);
            write(comm_fd + 1, &code, sizeof(code));
            _exit(TASK_ERR_REDIR_INVALID);
          }
      }

    /* clear the environment, if asked */
    if (tsk->clear_env) {
      clearenv();
    }

    /* set the environment */
    for (i = 0; i < tsk->env.u; i++) {
      if (putenv(tsk->env.v[i]) < 0) {
        code = MAKECODE(TASK_ERR_PUTENV_FAILED, errno);
        write(comm_fd + 1, &code, sizeof(code));
        _exit(TASK_ERR_PUTENV_FAILED);
      }
    }
    

    /* change the working directory */
    if (tsk->working_dir) {
      if (chdir(tsk->working_dir) < 0) {
        code = MAKECODE(TASK_ERR_CHDIR_FAILED, errno);
        write(comm_fd + 1, &code, sizeof(code));
        _exit(TASK_ERR_CHDIR_FAILED);
      }
    }

    if (tsk->max_stack_size > 0) {
      set_limit(comm_fd + 1, RLIMIT_STACK, tsk->max_stack_size);
    }
    if (tsk->max_data_size > 0) {
      set_limit(comm_fd + 1, RLIMIT_DATA, tsk->max_data_size);
    }
    if (tsk->max_vm_size > 0) {
      set_limit(comm_fd + 1, RLIMIT_AS, tsk->max_vm_size);
    }
    if (tsk->max_core_size >= 0) {
      set_limit(comm_fd + 1, RLIMIT_CORE, tsk->max_core_size);
    } else if (tsk->disable_core) {
      set_limit(comm_fd + 1, RLIMIT_CORE, 0);
    }
    if (tsk->max_file_size >= 0) {
      set_limit(comm_fd + 1, RLIMIT_FSIZE, tsk->max_file_size);
    }
    if (tsk->max_locked_mem_size >= 0) {
      set_limit(comm_fd + 1, RLIMIT_MEMLOCK, tsk->max_locked_mem_size);
    }
    if (tsk->max_msg_queue_size >= 0) {
      set_limit(comm_fd + 1, RLIMIT_MSGQUEUE, tsk->max_msg_queue_size);
    }
    if (tsk->max_nice_value >= 0) {
      set_limit(comm_fd + 1, RLIMIT_NICE, tsk->max_nice_value);
    }
    if (tsk->max_open_file_count >= 0) {
      set_limit(comm_fd + 1, RLIMIT_NOFILE, tsk->max_open_file_count);
    }
    if (tsk->max_process_count >= 0) {
      set_limit(comm_fd + 1, RLIMIT_NPROC, tsk->max_process_count);
    }
    if (tsk->max_prio_value >= 0) {
      set_limit(comm_fd + 1, RLIMIT_RTPRIO, tsk->max_prio_value);
    }
    if (tsk->max_pending_count >= 0) {
      set_limit(comm_fd + 1, RLIMIT_SIGPENDING, tsk->max_pending_count);
    }
    if (tsk->umask >= 0) {
      umask(tsk->umask & 0777);
    }

    /* set millisecond time limit */
#ifdef __linux__
    if (linux_ms_time_limit > 0 && tsk->max_time_millis > 0) {
      // the kernel supports millisecond-precise time-limits
      memset(&lim, 0, sizeof(lim));
      lim.rlim_cur = tsk->max_time_millis + 1000;
      lim.rlim_max = tsk->max_time_millis + 1000;
      if (setrlimit(linux_rlimit_code, &lim) < 0) {
        code = MAKECODE(TASK_ERR_LIMIT_CPU_FAILED, errno);
        write(comm_fd + 1, &code, sizeof(code));
        _exit(TASK_ERR_LIMIT_CPU_FAILED);
      }
      /* enable kernel-based time-limit detection */
      ptrace(0x4282, 0, 0, 0);
    } else if (tsk->max_time_millis > 0) {
      // the kernel does not support millisecond-precise time-limits
      tsk->max_time = (tsk->max_time_millis + 999) / 1000;
    }
#else
    if (tsk->max_time_millis > 0) {
      // the kernel does not support millisecond-precise time-limits
      tsk->max_time = (tsk->max_time_millis + 999) / 1000;
    }
#endif

    if (tsk->max_time > 0) {
      memset(&lim, 0, sizeof(lim));

#ifdef __linux__
      ASSERT(linux_fix_time_flag >= 0);
      if (linux_fix_time_flag > 0) {
        lim.rlim_cur = tsk->max_time;
        lim.rlim_max = tsk->max_time;
      } else {
        lim.rlim_cur = tsk->max_time + 1;
        lim.rlim_max = tsk->max_time + 1;
      }
#else
      lim.rlim_cur = tsk->max_time + 1;
      lim.rlim_max = tsk->max_time + 1;
#endif

      if (setrlimit(RLIMIT_CPU, &lim) < 0) {
        code = MAKECODE(TASK_ERR_LIMIT_CPU_FAILED, errno);
        write(comm_fd + 1, &code, sizeof(code));
        _exit(TASK_ERR_LIMIT_CPU_FAILED);
      }

#ifdef __linux__
      /* enable kernel-based time-limit detection */
      ptrace(0x4282, 0, 0, 0);
#endif
    }

#ifdef __linux__
    if (tsk->enable_secure_exec && linux_secure_exec_supported > 0) {
      if (linux_secure_exec_new_interface) {
        ptrace(0x4281, 0, 0, 0);
      } else {
      }
    }
#endif

    /* do exec */
    //fprintf(stderr, "starting: %s\n", tsk->path);
    if (tsk->enable_all_signals) {
      sigemptyset(&ss);
      sigprocmask(SIG_SETMASK, &ss, 0);
    }

    if (tsk->ignore_sigpipe) {
      signal(SIGPIPE, SIG_IGN);
    }

    if (tsk->enable_suid_exec) {
      invoke_execv_helper(tsk, tsk->path, tsk->args.v);
    } else {
      errno = 0;
      execv(tsk->path, tsk->args.v);
    }
    /*
    write_log(LOG_REUSE, LOG_CRIT,
              "task_Start: execv failed: %s",
              os_GetErrorString(errno));
    */
    code = MAKECODE(TASK_ERR_EXECV_FAILED, errno);
    write(comm_fd + 1, &code, sizeof(code));
    _exit(TASK_ERR_EXECV_FAILED);
  }
}

/**
 * NAME:    task_Wait
 * PURPOSE: wait for a specified task
 * ARGS:    tsk - task
 * RETURN:  the task pointer itself, or NULL if error
 */
  tTask *
task_Wait(tTask *tsk)
{
  return task_NewWait(tsk);
}

static void
invoke_cleanup_helper(tTask *tsk)
{
  char helper_path[PATH_MAX];
  char *args[3];

  if (tsk->state != TSK_SIGNALED && tsk->state != TSK_EXITED) return;

  snprintf(helper_path, sizeof(helper_path), "%s/%s", tsk->suid_helper_dir, "ej-suid-chown");
  args[0] = helper_path;
  if (tsk->working_dir) {
    args[1] = tsk->working_dir;
  } else {
    args[1] = ".";
  }
  args[2] = NULL;

  sigset_t cur, temp, empty;
  sigfillset(&temp);
  sigemptyset(&empty);
  sigprocmask(SIG_SETMASK, &temp, &cur);
  int helper_pid = fork();
  if (helper_pid < 0) {
    sigprocmask(SIG_SETMASK, &cur, NULL);
    return;
  }
  if (!helper_pid) {
    sigprocmask(SIG_SETMASK, &empty, NULL);
    execv(helper_path, args);
    _exit(1);
  }
  waitpid(helper_pid, NULL, 0);
  sigprocmask(SIG_SETMASK, &cur, NULL);
}

struct process_info
{
  char state;
  int ppid;
  int pgrp;
  int session;
  int tty_nr;
  int tpgid;
  unsigned flags;
  unsigned long minflt;
  unsigned long cminflt;
  unsigned long majflt;
  unsigned long cmajflt;
  unsigned long utime;
  unsigned long stime;
  unsigned long cutime;
  unsigned long cstime;
  long priority;
  long nice;
  long num_threads;
  long itrealvalue;
  long long starttime;
  unsigned long vsize;
  long rss;
  unsigned long rsslim;
  unsigned long startcode;
  unsigned long endcode;
  unsigned long startstack;
  unsigned long kstkesp;
  unsigned long kstkeip;
  unsigned long signal;
  unsigned long blocked;
  unsigned long sigignore;
  unsigned long sigcatch;
  unsigned long wchan;
  unsigned long nswap;
  unsigned long cnswap;
  int exit_signal;
  int processor;
  long clock_ticks;
};

static int
parse_proc_pid_stat(int pid, struct process_info *info)
{
  unsigned char path[PATH_MAX];
  FILE *f = NULL;
  unsigned char buf[8192];
  int blen;

  memset(info, 0, sizeof(*info));
  snprintf(path, sizeof(path), "/proc/%d/stat", pid);
  f = fopen(path, "r");
  if (!f) goto fail;
  if (!fgets(buf, sizeof(buf), f)) goto fail;
  blen = strlen(buf);
  if (blen + 1 == sizeof(buf)) goto fail;
  fclose(f); f = NULL;

  unsigned char *p = strrchr(buf, ')');
  if (!p) goto fail;
  ++p;

  int r = sscanf(p, " %c%d%d%d%d%d%u%lu%lu%lu%lu%lu%lu%lu%lu%ld%ld%ld%ld%llu%lu%ld%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%d%d",
                 &info->state,
                 &info->ppid,
                 &info->pgrp,
                 &info->session,
                 &info->tty_nr,
                 &info->tpgid,
                 &info->flags,
                 &info->minflt,
                 &info->cminflt,
                 &info->majflt,
                 &info->cmajflt,
                 &info->utime,
                 &info->stime,
                 &info->cutime,
                 &info->cstime,
                 &info->priority,
                 &info->nice,
                 &info->num_threads,
                 &info->itrealvalue,
                 &info->starttime,
                 &info->vsize,
                 &info->rss,
                 &info->rsslim,
                 &info->startcode,
                 &info->endcode,
                 &info->startstack,
                 &info->kstkesp,
                 &info->kstkeip,
                 &info->signal,
                 &info->blocked,
                 &info->sigignore,
                 &info->sigcatch,
                 &info->wchan,
                 &info->nswap,
                 &info->cnswap,
                 &info->exit_signal,
                 &info->processor);
  if (r != 37) goto fail;

  if ((info->clock_ticks = sysconf(_SC_CLK_TCK)) <= 0) goto fail;

  return 0;

fail:
  if (f) fclose(f);
  return -1;
}

tTask *
task_NewWait(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);

  bury_dead_prc();

  if (tsk->state == TSK_ERROR || tsk->state == TSK_STOPPED)
    return NULL;
  if (tsk->state == TSK_SIGNALED || tsk->state == TSK_EXITED) {
    if (tsk->enable_suid_exec && !tsk->cleanup_invoked) {
      invoke_cleanup_helper(tsk);
    }
    return tsk;
  }
  ASSERT(tsk->state == TSK_RUNNING);

  sigset_t bs;
  sigemptyset(&bs);
  sigaddset(&bs, SIGCHLD);

  struct timeval cur_time, rt_timeout;
  gettimeofday(&cur_time, NULL);
  rt_timeout.tv_sec = 0;
  rt_timeout.tv_usec = 0;
  if (tsk->max_real_time > 0) {
    rt_timeout = cur_time;
    rt_timeout.tv_sec += tsk->max_real_time;
  }

  long long max_time_ms = 0;
  if (tsk->max_time_millis > 0) {
    max_time_ms = tsk->max_time_millis;
  } else if (tsk->max_time > 0) {
    max_time_ms = tsk->max_time * 1000;
  }

  int pid, stat = 0;
  struct rusage usage;
  unsigned long used_vm_size = 0;

  while (1) {
    memset(&usage, 0, sizeof(usage));
    pid = wait4(tsk->pid, &stat, WNOHANG, &usage);
    if (pid < 0) {
      write_log(LOG_REUSE, LOG_ERROR, "task_NewWait: wait4 failed: %s\n", os_ErrorMsg());
      // FIXME: recover?
      return tsk;
    }
    if (pid > 0 && pid != tsk->pid) {
      find_prc_in_list(pid, stat, &usage);
      continue;
    }
    if (pid > 0) {
      find_prc_in_list(pid, stat, &usage);
      tsk->used_vm_size = used_vm_size;
      if (tsk->enable_suid_exec && !tsk->cleanup_invoked) {
        invoke_cleanup_helper(tsk);
      }
      return tsk;
    }

    if (tsk->max_real_time > 0) {
      gettimeofday(&cur_time, NULL);
      if (cur_time.tv_sec > rt_timeout.tv_sec
          || (cur_time.tv_sec == rt_timeout.tv_sec && cur_time.tv_usec >= rt_timeout.tv_usec)) {
        if (tsk->enable_process_group > 0) {
          do_kill(tsk, -tsk->pid, tsk->termsig);
        } else {
          do_kill(tsk, tsk->pid, tsk->termsig);
        }
        tsk->was_timeout = 1;
        tsk->was_real_timeout = 1;
        tsk->used_vm_size = used_vm_size;
        break;
      }
    }

    struct process_info info;
    long long cur_utime = 0;
    if (parse_proc_pid_stat(tsk->pid, &info) >= 0) {
      if (info.vsize > 0 && info.vsize > used_vm_size) {
        used_vm_size = info.vsize;
        //fprintf(stderr, "VMSize: %lu\n", used_vm_size);
      }
      if (max_time_ms > 0) {
        cur_utime = info.utime + info.stime;
        cur_utime = (cur_utime * 1000) / info.clock_ticks;
        //fprintf(stderr, "CPUTime: %lld\n", cur_utime);
        if (cur_utime >= max_time_ms) {
          if (tsk->enable_process_group > 0) {
            do_kill(tsk, -tsk->pid, tsk->termsig);
          } else {
            do_kill(tsk, tsk->pid, tsk->termsig);
          }
          tsk->was_timeout = 1;
          tsk->used_vm_size = used_vm_size;
          break;
        }
      }
    } else {
      fprintf(stderr, "Failed to parse /proc/PID/stat\n");
      cur_utime = 1000; // not to poll too often
    }

    // wait 0.1 s
    struct timespec wt;
    wt.tv_sec = 0;
    if (cur_utime >= 500) {
      // if running time >= 0.5 s poll each 0.1 s
      wt.tv_nsec = 100000000;
    } else if (cur_utime >= 10) {
      // if running time >= 0.01 s poll each 0.01 s
      //wt.tv_nsec = 10000000;
      wt.tv_nsec = 100000000;
    } else {
      // poll each 0.002 s
      //wt.tv_nsec = 2000000;
      wt.tv_nsec = 100000000;
    }
    sigtimedwait(&bs, 0, &wt);
  }

  while (1) {
    memset(&usage, 0, sizeof(usage));
    pid = wait4(tsk->pid, &stat, 0, &usage);
    if (pid < 0) {
      write_log(LOG_REUSE, LOG_ERROR, "task_NewWait: wait4 failed: %s\n", os_ErrorMsg());
      // FIXME: recover?
      return tsk;
    }
    if (pid > 0 && pid != tsk->pid) {
      find_prc_in_list(pid, stat, &usage);
      continue;
    }
    if (pid > 0) {
      find_prc_in_list(pid, stat, &usage);
      if (tsk->enable_suid_exec && !tsk->cleanup_invoked) {
        invoke_cleanup_helper(tsk);
      }
      return tsk;
    }
  }

  abort();
  return tsk;
}

/**
 * NAME:    task_Status
 * PURPOSE: return task status
 * ARGS:    tsk - task
 * RETURN:  task status
 */
  int
task_Status(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  return tsk->state;
}

/**
 * NAME:    task_TermSignal
 * PURPOSE: return termination signal
 * ARGS:    tsk - task
 * RETURN:  termination signal, or -1 if task is not terminated by signal
 */
  int
task_TermSignal(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_SIGNALED)
    return -1;
  return WTERMSIG(tsk->code);
}

/**
 * NAME:    task_ExitCode
 * PURPOSE: get exit code of the task
 * ARGS:    tsk - task
 * RETURN:  exit code of the task, or -1 is task is not exited
 */
  int
task_ExitCode(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_EXITED)
    return -1;
  if (tsk->is_exited)
    return tsk->exit_code;
  return WEXITSTATUS(tsk->code);
}

/**
 * NAME:    task_IsAbnormal
 * PURPOSE: check for abnormal task termination
 * ARGS:    tsk - task
 * RETURN:  0 - task exited with code 0,
 *          1 - task either terminated with signal, or exited with code > 0
 */
  int
task_IsAbnormal(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state == TSK_SIGNALED)
    return 1;
  if (tsk->state == TSK_EXITED && tsk->is_exited && tsk->exit_code > 0)
    return 1;
  if (tsk->state == TSK_EXITED && WEXITSTATUS(tsk->code) > 0)
    return 1;
  return 0;
}

/**
 * NAME:    task_IsTimeout
 * PURPOSE: check if the task was terminated due to timeout
 * ARGS:    tsk - task
 * RETURN:  -1 - task is not finished
 *          0  - task is finished, no timeout
 *          1  - timeout
 */
int
task_IsTimeout(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_EXITED && tsk->state != TSK_SIGNALED) return -1;
  return tsk->was_timeout || tsk->was_real_timeout;
}

int
task_IsRealTimeout(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_EXITED && tsk->state != TSK_SIGNALED) return -1;
  return tsk->was_real_timeout;
}

long
task_GetMemoryUsed(tTask *tsk)
{
  ASSERT(tsk);
  return tsk->used_vm_size;
}

int
task_IsMemoryLimit(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_EXITED && tsk->state != TSK_SIGNALED) return -1;
  return tsk->was_memory_limit;
}

int
task_IsSecurityViolation(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_EXITED && tsk->state != TSK_SIGNALED) return -1;
  return tsk->was_security_violation;
}

/**
 * NAME:    task_GetRunningTime
 * PURPOSE: returns the running time of finished task in milliseconds
 * ARGS:    tsk - task
 * RETURN:  -1 - task is not finished
 *          else, elapsed time in milliseconds returned
 */
long
task_GetRunningTime(tTask *tsk)
{
  long millis = 0;

  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_SIGNALED && tsk->state != TSK_EXITED) return -1;

  millis += (tsk->usage.ru_utime.tv_usec + tsk->usage.ru_stime.tv_usec + 500) / 1000;
  millis += tsk->usage.ru_utime.tv_sec * 1000;
  millis += tsk->usage.ru_stime.tv_sec * 1000;
  if (millis > 100000 || millis < 0) {
    fprintf(stderr, "SUSPICIOUS RUNNING TIME: %ld\n", millis);
    fprintf(stderr, "ru_utime.tv_sec: %ld\n", tsk->usage.ru_utime.tv_sec);
    fprintf(stderr, "ru_utime.tv_usec: %ld\n", tsk->usage.ru_utime.tv_usec);
    fprintf(stderr, "ru_stime.tv_sec: %ld\n", tsk->usage.ru_stime.tv_sec);
    fprintf(stderr, "ru_stime.tv_usec: %ld\n", tsk->usage.ru_stime.tv_usec);
  }
  return millis;
}

long
task_GetRealTime(tTask *tsk)
{
  long long millis;

  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_SIGNALED && tsk->state != TSK_EXITED) return -1;

  millis = tsk->stop_time.tv_sec * 1000LL + (tsk->stop_time.tv_usec + 500)/ 1000;
  millis -= tsk->start_time.tv_sec * 1000LL + tsk->start_time.tv_usec / 1000;
  return (long) millis;
}

/**
 * NAME:    task_Log
 * PURPOSE: log task termination event
 * ARGS:    tsk - task
 *          fac - logging facility
 *          sev - logging severity
 */
  void
task_Log(tTask *tsk, int fac, int sev)
{
  task_init_module();
  ASSERT(tsk);

  if (tsk->state != TSK_SIGNALED && tsk->state != TSK_EXITED)
    return;
  if (tsk->state == TSK_SIGNALED)
    {
      write_log(fac, sev,
                "process %d is terminated with signal %d (%s)",
                tsk->pid,
                WTERMSIG(tsk->code),
                os_GetSignalString(WTERMSIG(tsk->code)));
    }
  else
    {
      char *s = "";
      int   r = WEXITSTATUS(tsk->code);
      if (tsk->is_exited)
        r = tsk->exit_code;
      switch (r)
        {
        case 100:
          s = " :invalid redirection"; break;
        case 101:
          s = " :dup2 failed?"; break;
        case 102:
          s = " :open failed?"; break;
        case 103:
          s = " :dup2 failed?"; break;
        case 104:
          s = " :exec failed?"; break;
        default:
          break;
        }
      write_log(fac, sev,
                "process %d is exited with code %d%s",
                tsk->pid, r, s);
    }
}

/**
 * NAME:    task_Kill
 * PURPOSE: terminate the task
 * ARGS:    tsk         - task
 * RETURN:  -1, if task is not in TSK_RUNNING state, or
 *          error occured.
 *          0, if task is terminated
 */
int
task_Kill(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->pid > 0) {
    do_kill(tsk, tsk->pid, tsk->termsig);
  }
  return 0;
}

int
task_TryProcessGroup(tTask *tsk)
{
  task_init_module();
  return do_kill(tsk, -tsk->pid, 0);
}

int
task_KillProcessGroup(tTask *tsk)
{
  task_init_module();
  if (tsk->pid > 0) {
    do_kill(tsk, -tsk->pid, SIGKILL);
  }
  return 0;
}

/**
 * NAME:    task_GetPid
 * PURPOSE: get the pid of the process
 * ARGS:    tsk         - task
 * RETURN:  pid of the specified process
 */
int
task_GetPid(tTask *tsk)
{
  task_init_module();
  ASSERT(tsk);
  return tsk->pid;
}

/**
 * NAME:    task_ErrorCode
 * PURPOSE: get error code and error number
 * ARGS:    tsk         - task
 *          p_exit_code - pointer to store error code value
 *                        NULL, if not interested
 *          p_error     - pointer to store error number
 *                        NULL, if not interested
 * RETURN:  -1, if task is not in TSK_ERROR state
 *          error code (the same as stored in p_exit_code)
 */
int
task_ErrorCode(tTask *tsk, int *p_exit_code, int *p_error)
{
  task_init_module();
  ASSERT(tsk);
  if (tsk->state != TSK_ERROR) return -1;
  if (p_exit_code) *p_exit_code = tsk->exit_code;
  if (p_error)     *p_error     = tsk->code;
  return tsk->exit_code;
}

#ifdef __linux__
static void
linux_set_fix_flag(void)
{
  /* we need to check the actual ulimit behaviour by
   * running a simple program with time limit set to 0 sec and
   * measuring the actual running time
   */
  int pid, status, retcode, mjver = 0, mnver = 0, patch = 0;
  struct rusage usage;
  struct utsname buf;
  struct rlimit lim;

  if (linux_fix_time_flag >= 0) return;
  if (linux_ms_time_limit >= 0) return;

  if (uname(&buf) < 0 || strcasecmp(buf.sysname, "linux")
      || sscanf(buf.release, "%d.%d.%d", &mjver, &mnver, &patch) != 3) {
    linux_fix_time_flag = 0;
    linux_ms_time_limit = 0;
    return;
  }
  
  if (mjver >= 3 || (mjver == 2 && mnver >= 6))
    linux_fix_time_flag = 0;

  if (mjver == 2 && mnver == 4) {
    linux_ptrace_code = 0x20;
    linux_rlimit_code = 11;
  } else if (mjver == 2 && mnver == 6 && patch >= 25) {
    linux_ptrace_code = 0x4280;
    linux_rlimit_code = 19;
  } else if (mjver == 2 && mnver == 6) {
    linux_ptrace_code = 0x4280;
    linux_rlimit_code = 15;
  } else {
    linux_ptrace_code = 0x4280;
    linux_rlimit_code = 0;
  }

  // check for millisecond time limit
  if (linux_rlimit_code > 0) {
    if ((pid = fork()) < 0) return;
    if (!pid) {
      memset(&lim, 0, sizeof(lim));
      lim.rlim_cur = 1000;
      lim.rlim_max = 1000;
      if (setrlimit(linux_rlimit_code, &lim) < 0) _exit(1);
      _exit(0);
    }

    memset(&usage, 0, sizeof(usage));
    if (wait4(pid, &status, 0, &usage) != pid) return;
    linux_ms_time_limit = 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
      linux_ms_time_limit = 1;
  } else {
    linux_ms_time_limit = 0;
  }

  if (linux_fix_time_flag < 0) {
    if ((pid = fork()) < 0) return;
    if (!pid) {
      memset(&lim, 0, sizeof(lim));
      lim.rlim_cur = 0;
      lim.rlim_max = 0;
      if (setrlimit(RLIMIT_CPU, &lim) < 0) _exit(1);

      // FIXME: is it good to run busy loop for 1 second?
      while (1);
      _exit(1);
    }

    memset(&usage, 0, sizeof(usage));
    retcode = wait4(pid, &status, 0, &usage);
    // FIXME: we should not leave a process running...
    if (retcode != pid) return;

    // if user time is > 0.5 sec consider that we should adjust limit time
    if (usage.ru_utime.tv_sec >= 1 || usage.ru_utime.tv_usec >= 500000) {
      linux_fix_time_flag = 1;
    } else {
      linux_fix_time_flag = 0;
    }
  }
}

static void
linux_set_secure_exec_supported_flag(void)
{
  int pid, status, res;

  if (linux_secure_exec_supported >= 0) return;
  linux_secure_exec_supported = 0;

  // try new (ptrace-based) secure exec interface
  if ((pid = fork()) < 0) return;

  if (!pid) {
    if (ptrace(0x4281, 0, 0, 0) < 0) _exit(1);
    //if (dup(0) >= 0) _exit(1);
    _exit(0);
  }

  // parent
  while (1) {
    res = waitpid(pid, &status, 0);
    if ((res < 0 && errno != EINTR) || res == pid) break;
  }
  if (res == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    linux_secure_exec_supported = 1;
    linux_secure_exec_new_interface = 1;
    return;
  }
}
#endif

static void
invoke_kill_helper(tTask *tsk, int pid, int signal)
  __attribute__((noreturn));
static void
invoke_kill_helper(tTask *tsk, int pid, int signal)
{
  char helper_path[PATH_MAX];
  char pid_buf[64];
  char signal_buf[64];
  char *helper_args[] = { helper_path, pid_buf, signal_buf, NULL };
  sigset_t empty;

  sigemptyset(&empty);
  sigprocmask(SIG_SETMASK, &empty, NULL);
  snprintf(helper_path, sizeof(helper_path), "%s/%s", tsk->suid_helper_dir, "ej-suid-kill");
  snprintf(pid_buf, sizeof(pid_buf), "%d", pid);
  snprintf(signal_buf, sizeof(signal_buf), "%d", signal);
  execv(helper_path, helper_args);
  _exit(1);
}

static int
do_kill(tTask *tsk, int pid, int signal)
{
  if (!tsk->enable_suid_exec) return kill(pid, signal);

  // hold off everything while killing
  sigset_t cur, temp;
  sigfillset(&temp);
  sigprocmask(SIG_SETMASK, &temp, &cur);
  int helper_pid = fork();
  if (helper_pid < 0) {
    sigprocmask(SIG_SETMASK, &cur, NULL);
    return -1;
  }
  if (!helper_pid) {
    invoke_kill_helper(tsk, pid, signal);
    // noreturn
  }
  int status = 0;
  waitpid(helper_pid, &status, 0);
  sigprocmask(SIG_SETMASK, &cur, NULL);
  return (WIFEXITED(status) && !WEXITSTATUS(status))?0:-1;
}
