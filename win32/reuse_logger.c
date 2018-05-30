/* Copyright (C) 1999-2016 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1999-07-20 23:50:19 cher> */

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

#define __REUSE__ 1

#include "ejudge/logger.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <time.h>

/*  CreateFile GetSystemTime CloseHandle ReadFile WriteFile */

static HANDLE  log_fd  = INVALID_HANDLE_VALUE;
static HANDLE  log2_fd = INVALID_HANDLE_VALUE;
static char   *log_path = NULL;

static logmodule_t default_module =
{ 0, "", LOG_INFO };
static logmodule_t logger_module =
{ LOG_LOGGER, "logger", LOG_NOTICE };
static logmodule_t sw_module =
{ LOG_SW, "sw", LOG_INFO };
static logmodule_t utils_module =
{ LOG_REUSE, "reuse", LOG_NOTICE };
static logmodule_t *logmodules[LOG_MAX_MODULE_NUM];

#define MAX_LOG_LEVEL 50

#define LOG_MIN_PRIO LOG_JUNK
#define LOG_MAX_PRIO LOG_EMERG
static char *priority_names[]=
{
  "junk", "debug", "info", "notice", "warning",
  "error", "critical", "alert", "emerg"
};

static int initialized = 0;
static void
minimal_init(void)
{
  HANDLE prc, err, log = INVALID_HANDLE_VALUE;

  if (initialized) return;
  initialized = 1;

  logmodules[0] = &default_module;
  logmodules[LOG_LOGGER] = &logger_module;
  logmodules[LOG_SW] = &sw_module;
  logmodules[LOG_REUSE] = &utils_module;

  if (log_fd == INVALID_HANDLE_VALUE) {
    prc = GetCurrentProcess();
    err = GetStdHandle(STD_ERROR_HANDLE);
    if (err == INVALID_HANDLE_VALUE) return;
    if (!DuplicateHandle(prc,err,prc,&log,0,FALSE, DUPLICATE_SAME_ACCESS)) {
      return;
    }
    log_fd = log;
  }
}

void
logger_init_ex(logmodule_t *mi, char *path, int stderr_flag)
{
  int i;

  minimal_init();

  if (mi) {
    for (i = 0; mi[i].name; i++) {
      ASSERT(mi[i].num > 3 && mi[i].num < LOG_MAX_MODULE_NUM);
      logmodules[mi[i].num] = &mi[i];
    } /* for (i) */
  } /* if (mi) */

  if (path) {
    HANDLE t = CreateFile(path,
			  GENERIC_WRITE,
			  FILE_SHARE_READ,
			  NULL,
			  OPEN_ALWAYS,
			  FILE_FLAG_WRITE_THROUGH,
			  NULL);
    if (t == INVALID_HANDLE_VALUE) {
      fprintf(stderr, "Cannot open log file '%s'\n", path);
    } else {
      log_path = path;
      log_fd   = t;
      if (stderr_flag) {
        log2_fd = GetStdHandle(STD_ERROR_HANDLE);
        if (log2_fd == INVALID_HANDLE_VALUE) {
          swabort();
        }
      }
    }
  }
}

void
logger_init(logmodule_t *mi, char *path)
{
  logger_init_ex(mi, path, 0);
}

int
vwrite_log(int facility, int level, char const *format, va_list args)
{
  char      bprio[32];
  char      bfac[32];
  char      btime[64];

  int        r;
  int        msglen = 1023;
  char       msg[1024];
  DWORD      bw;

  minimal_init();

  if (!format) return 0;
  if (log_fd == INVALID_HANDLE_VALUE) return 0;

  /* check for valid module */
  if (facility < 0 || facility >= LOG_MAX_MODULE_NUM) facility = 0;
  if (!logmodules[facility]) facility = 0;

  /* check that the facility is blocked */
  if (logmodules[facility]->blocked) return 0;

  /* check against minimal log level for the facility */
  if (level < logmodules[facility]->level) return 0;

#if 0
  {
    SYSTEMTIME st;

    GetSystemTime(&st);
    snprintf(btime, 64, "%02d:%02d:%02d %02d/%02d/%d:",
             st.wHour, st.wMinute, st.wSecond,
             st.wDay, st.wMonth, st.wYear);
    btime[63] = 0;
  }
#else
  {
    time_t     xtt;
    struct tm *xtm;
    char      *xat;
    int        len;

    time(&xtt);
    xtm = localtime(&xtt);
    xat = asctime(xtm);
    strcpy(btime, xat);
    len = strlen(btime);
    while (btime[len - 1] == '\n' || btime[len - 1] == '\r') {
      btime[--len] = 0;
    }
    strcat(btime, ":");
  }
#endif

  if (level < LOG_MIN_PRIO || level > LOG_MAX_PRIO) {
    sprintf(bprio, "%d:", level);
  } else {
    snprintf(bprio, 32, "%s:", priority_names[level]);
  }

  bfac[0] = 0;
  if (facility && logmodules[facility]->name) {
    snprintf(bfac, 32, "%s:", logmodules[facility]->name);
    bfac[31] = 0;
  } else if (!logmodules[facility]->name) {
    sprintf(bfac, "%d:", facility);
  }

  r = snprintf(msg, 1024, "%s%s%s", btime, bfac, bprio);
  vsnprintf(msg + r, 1024 - r, format, args);
  msg[msglen] = 0;
  r = strlen(msg) + 2;
  if (r >= 1024) {
    r = 1023;
  }
  strcpy(msg + r - 2, "\r\n\0");
  r = strlen(msg);

  if (log_fd == INVALID_HANDLE_VALUE) {
    log_fd = GetStdHandle(STD_ERROR_HANDLE);
    if (log_fd == INVALID_HANDLE_VALUE) {
      swabort();
    }
  }

  if (!WriteFile(log_fd, msg, r, &bw, NULL)) {
    fprintf(stderr, "log file write error\n");
    CloseHandle(log_fd);
    log_fd = INVALID_HANDLE_VALUE;
    return -1;
  }
  FlushFileBuffers(log_fd);
  if (log2_fd != INVALID_HANDLE_VALUE) {
    WriteFile(log2_fd, msg, r, &bw, NULL);
  }

  return bw;
}

int
write_log(int facility, int level, char const *format, ...)
{
  va_list    args;
  int        r;

  va_start(args, format);
  r = vwrite_log(facility, level, format, args);
  va_end(args);
  return r;
}

void
logger_close(void)
{
  if (log_fd != INVALID_HANDLE_VALUE) {
    CloseHandle(log_fd);
    log_fd = INVALID_HANDLE_VALUE;
    log_path = 0;
  }
}

int
logger_get_fd(void)
{
  minimal_init();

  /* this is not true... */
  return (int) log_fd;
}

static jmp_buf  default_handler;

static char     *swerr_file;
static int       swerr_line;
static jmp_buf   swerr_handler;

#ifdef __GNUC__
static void _swerr(char *, int, jmp_buf *, char *, va_list) __attribute__ ((noreturn));
#else
static void _swerr(char *, int, jmp_buf *, char *, va_list);
#endif

static void
_swwarn(char *file, int line, char *format, va_list args)
{
  char buf[1024];
  int  n;

  n = snprintf(buf, 1024, "Internal: %s: %d: ", file, line);
  vsnprintf(buf + n, 1024 - n, format, args);
  buf[1023] = 0;

  write_log(LOG_SW, LOG_ALERT, "%s", buf);
}

static void
_swerr(char *file, int line, jmp_buf *jb, char *format, va_list args)
{
  char buf[1024];
  int  n;

  n = snprintf(buf, 1024, "Internal: %s: %d: ", file, line);
  vsnprintf(buf + n, 1024 - n, format, args);
  buf[1023] = 0;

  write_log(LOG_SW, LOG_EMERG, "%s", buf);
  swabort();
}

void
swerr(char *file, int line, char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swerr(file, line, &default_handler, format, args);
#ifndef __GNUC__
  va_end(args);
#endif
}

void
swerr1(char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swerr(swerr_file, swerr_line, &default_handler, format, args);
#ifndef __GNUC__
  va_end(args);
#endif
}

void
swerr2(char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swerr(swerr_file, swerr_line, &swerr_handler, format, args);
#ifndef __GNUC__
  va_end(args);
#endif
}

void
swerr_SetPos(char *file, int line)
{
  swerr_file = file;
  swerr_line = line;
}

void
swerr_SetPosBuf(char *file, int line, void *buf)
{
  swerr_file    = file;
  swerr_line    = line;

  memcpy(&swerr_handler, buf, sizeof (swerr_handler));
}

void
swabort(void)
{
  //RaiseException(0xC0000100, EXCEPTION_NONCONTINUABLE, 0, NULL);
  fflush(NULL);
  ExitProcess(0xC0000100);
}

void
swwarn(char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swwarn(swerr_file, swerr_line, format, args);
  va_end(args);
}
