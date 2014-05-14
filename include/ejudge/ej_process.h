/* -*- c -*- */
/* $Id$ */

#ifndef __EJ_PROCESS_H__
#define __EJ_PROCESS_H__

/* Copyright (C) 2005-2012 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>

enum
{
  BACKGROUND_PROCESS_RUNNING,
  BACKGROUND_PROCESS_FINISHED,
  BACKGROUND_PROCESS_GARBAGE,
};

struct background_process_buffer
{
  unsigned char *buf;
  int allocated, size;
};

struct background_process
{
  struct background_process *prev, *next;

  unsigned char *name; //!< process name for identification

  unsigned char *stdin_b; //!< bytes to send to the process' stdin
  int stdin_z; //!< size of the process' stdin
  int stdin_u; //!< already send bytes

  int time_limit_ms; //!< time limit in milliseconds
  int kill_grace_ms; //!< timeout between SIGTERM and SIGKILL
  long long start_time_ms; //!< the process start time
  long long term_time_ms; //!< time of SIGTERM
  long long kill_time_ms; //!< time of SIGKILL
  long long stop_time_ms; //!< time of wait finishing

  int merge_out_flag; //!< merge stdout and stderr?
  int stdin_f; //!< the process stdin
  int stdout_f; //!< the process stdout
  int stderr_f; //!< the process stderr

  struct background_process_buffer out;
  struct background_process_buffer err;

  int state;
  int pid;
  int is_exited;
  int exit_code;
  int is_signaled;
  int term_signal;

  long long utime_ms;
  long long stime_ms;
  long maxrss;

  void *user;
  void (*continuation)(struct background_process *);
};

unsigned char *read_process_output(const unsigned char *cmd,
                                   const unsigned char *workdir,
                                   int max_ok_code,
                                   int redirect_stderr);

int
ejudge_invoke_process(
        char **args,
        char **envs,
        const unsigned char *workdir,
        const unsigned char *stdin_file,
        const unsigned char *stdin_text,
        int merge_out_flag,
        unsigned char **stdout_text,
        unsigned char **stderr_text);

struct background_process *
ejudge_start_process(
        FILE *log_f,
        const unsigned char *name,
        char **args,
        char **envs,
        const unsigned char *workdir,
        const unsigned char *stdin_text,
        int merge_out_flag,
        int time_limit_ms,
        void (*continuation)(struct background_process*),
        void *user);

struct background_process_head
{
  struct background_process *first;
  struct background_process *last;
};

void
background_process_cleanup(struct background_process_head *list);
int
background_process_set_fds(struct background_process_head *list, int max_fd, void *vprset, void *vpwset);
void
background_process_check_finished(struct background_process_head *list);
void
background_process_readwrite(struct background_process_head *list, void *vprset, void *vpwset);
void
background_process_register(struct background_process_head *list, struct background_process *prc);
struct background_process *
background_process_find(struct background_process_head *list, const unsigned char *name);
int
background_process_handle_termination(
        struct background_process_head *list,
        int pid,
        int status,
        const void *vusage);
void
background_process_call_continuations(struct background_process_head *list);
void
background_process_close_fds(struct background_process_head *list);

void
background_process_append_pollfd(struct background_process_head *list, void *vp);

unsigned char **
ejudge_get_host_names(void);

int
ejudge_start_daemon_process(
        char **args,
        const unsigned char *workdir);

int
ejudge_timed_write(
        const unsigned char *log,
        int fd,
        const void *data,
        ssize_t size,
        int timeout_ms);

ssize_t
ejudge_timed_fdgets(
        const unsigned char *log,
        int fd,
        unsigned char *buf,
        ssize_t size,
        int timeout_ms);

#endif /* __EJ_PROCESS_H__ */
