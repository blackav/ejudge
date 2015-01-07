/* Copyright (C) 1997-2015 Alexander Chernov <cher@ejudge.ru> */

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
 * FILE:    utils/logger.c
 * PURPOSE: logging facilities, fatal error handling
 */

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <setjmp.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static int   log_fd    = 2;     /* logging file descriptor */
static int   log2_fd   = -1;    /* secondary log descriptor */
static char *log_path  = NULL;  /* full path to the log file */

static int   global_log_level = 0;

static logmodule_t default_module =
{ 0, "", LOG_INFO };
static logmodule_t logger_module =
{ LOG_LOGGER, "logger", LOG_ERR };
static logmodule_t sw_module =
{ LOG_SW, 0, LOG_ERR };
static logmodule_t utils_module =
{ LOG_REUSE, "reuse", LOG_INFO };
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
static void minimal_init(void)
{
  initialized = 1;

  if (log_fd < 0) log_fd = 2;
  log_path = NULL;

  memset(logmodules, 0, sizeof(logmodules));

  logmodules[0] = &default_module;
  logmodules[LOG_LOGGER] = &logger_module;
  logmodules[LOG_SW] = &sw_module;
  logmodules[LOG_REUSE] = &utils_module;
}

/**
 * NAME:    logger_init
 * PURPOSE: initialize the logger module
 */
void
logger_init_ex(logmodule_t *mi, char *path, int flag)
{
  int i;

  if (!initialized) minimal_init();

  if (mi) {
    for (i = 0; mi[i].name; i++) {
      ASSERT(mi[i].num > 3 && mi[i].num < LOG_MAX_MODULE_NUM);
      logmodules[mi[i].num] = &mi[i];
    } /* for (i) */
  } /* if (mi) */

  if (path) {
    if ((i = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644)) < 0) {
      fprintf(stderr, "Cannot open log file '%s'\n", path);
    } else {
      log_path = path;
      log_fd   = i;
      if (flag) {
        log2_fd = 2;
      }
    }
  }
}

void
logger_init(logmodule_t *mi, char *path)
{
  logger_init_ex(mi, path, 0);
}

void
logger_set_level(int fac, int level)
{
  if (fac < 0 || fac >= LOG_MAX_MODULE_NUM) fac = -1;
  if (level < 0) level = 0;
  if (level > LOG_EMERG) level = LOG_EMERG;

  if (fac == -1) {
    global_log_level = level;
  }
}

/**
 * NAME:    vwrite_log
 * PURPOSE: write log message
 * ARGS:    facility - logging facility
 *          level    - severity level
 *          format   - user provided message
 *          args     - extra format specific arguments
 * RETURN:  number of bytes written to the log file
 */
int
vwrite_log(int facility, int level, char const *format, va_list args)
{
  int        r;
  time_t     tt;
  struct tm *ptm;
  char       atm[32];
  char      *prio, bprio[32];
  char      *pfac, bfac[32];
  int        msglen = 1023;
  char       msg[1024];

  assert (format != NULL);
  if (!initialized) minimal_init();

  /* check whether log file is open */
  if (log_fd <= 0) return 0;

  /* check for valid module */
  if (facility < 0 || facility >= LOG_MAX_MODULE_NUM) facility = 0;
  if (!logmodules[facility]) facility = 0;

  /* check that the facility is blocked */
  if (logmodules[facility]->blocked) return 0;

  /* check against minimal log level for the facility */
  if (level < global_log_level) return 0;
  if (level < logmodules[facility]->level) return 0;

  time(&tt);
  ptm = gmtime(&tt);
  snprintf(atm, sizeof(atm), "%d-%02d-%02dT%02d:%02d:%02dZ",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);

  if (level < LOG_MIN_PRIO || level > LOG_MAX_PRIO) {
    sprintf(bprio, "%d", level);
    prio = bprio;
  } else {
    prio = priority_names[level];
  }

  if (!logmodules[facility]->name) {
    sprintf(bfac, "%d", facility);
    pfac = bfac;
  } else {
    pfac = logmodules[facility]->name;
  }

  if (facility == 0) {
    r = sprintf(msg, "%s:%s:", atm, prio);
  } else {
    r = sprintf(msg, "%s:%s:%s:", atm, pfac, prio);
  }

  
  vsnprintf(msg + r, msglen - r, format, args);
  msg[msglen] = 0;
  r = strlen(msg);
  msg[r++] = '\n';
  
  if (r >= 1024) {
    fprintf(stderr, "fatal buffer overrun in logger module\n");
    abort();
  }

  /*
  if (write(log_fd, msg, r) < 0) {
    fprintf(stderr, "log file write error: %s\n", strerror(errno));
    fprintf(stderr, "closing log file\n");
    close(log_fd);
    log_fd = -1;
    return -1;
  }
  */
  // ignore errors that may happen on logger fd
  write(log_fd, msg, r);
  if (log2_fd >= 0) write(log2_fd, msg, r);

  return r;
}

/**
 * NAME:    write_log
 * PURPOSE: write log message
 * ARGS:    facility - logging facility
 *          level    - severity level
 *          format   - user provided message
 *          ...      - extra format specific arguments
 * RETURN:  number of bytes written to the log file
 */
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

/**
 * NAME:    logger_close
 * PURPOSE: close log file
 */
void
logger_close(void)
{
  if (!initialized) minimal_init();
}

/**
 * NAME:    logger_get_fd
 * PURPOSE: get logging file descriptor
 * RETURN:  logging file descriptor
 */
int
logger_get_fd(void)
{
  if (!initialized) minimal_init();

  return log_fd;
}

/* ==================== Fatal errors handling ======================= */

/* hope the message won't be that long */
#define FATALBUFLEN 1024
static char fatalbuf[FATALBUFLEN]; /* buffer for the fatal error message */

static jmp_buf  default_handler; /* fatal error recovery point */

static char    *swerr_file;     /* source file name */
static int      swerr_line;     /* source file line */
static jmp_buf  swerr_handler;  /* fatal error recovery point */

#ifdef __GNUC__
static void _swerr(char *file, int line, jmp_buf *jb, char *format, va_list args) __attribute__ ((noreturn));
#else
static void _swerr();
#endif

/**
 * NAME:    _swwarn
 * PURPOSE: report non-fatal software error (warning)
 * ARGS:    file   - source file name
 *          line   - source file line
 *          format - message text
 *          args   - extra format specific arguments
 */
static void
_swwarn(char *file, int line, char *format, va_list args)
{
  int   n;
  char *s = fatalbuf;

  n = sprintf(s, "Internal: %s: %d: ", file, line);
  n = vsprintf(s += n, format, args);
  sprintf(s += n, "\n");

  write_log(LOG_SW, LOG_ALERT, "%s", fatalbuf);
}

/**
 * NAME:    _swerr
 * PURPOSE: report fatal software error
 * ARGS:    file   - source file name
 *          line   - source line number
 *          jb     - fatal error recovery point
 *          format - message text
 *          args   - extra format specific arguments
 * RETURN:  
 */
static void
_swerr(char *file, int line, jmp_buf *jb, char *format, va_list args)
{
  int   n;
  char *s = fatalbuf;

  n = sprintf(s, "Internal: %s: %d: ", file, line);
  n = vsprintf(s += n, format, args);
  sprintf(s += n, "\n");

  write_log(LOG_SW, LOG_EMERG, "%s", fatalbuf);

  /* one day we'll do longjmp */
  abort();
}

/**
 * NAME:    swerr
 * PURPOSE: report software fatal error
 * ARGS:    file   - source file name
 *          line   - source line number
 *          format - error message
 *          ...    - extra format specific arguments
 */
void
swerr(char *file, int line, char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swerr(file, line, &default_handler, format, args);
}

/**
 * NAME:    swerr1
 * PURPOSE: report software fatal error
 * ARGS:    format - error message
 *          ...    - extra message specific arguments
 * NOTE:    error recovery is performing using the default error recovery point
 */
void
swerr1(char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swerr(swerr_file, swerr_line, &default_handler, format, args);
}

/**
 * NAME:    swerr2
 * PURPOSE: report software fatal error
 * ARGS:    format - error message
 *          ...    - extra message specific arguments
 * NOTE:    error recovery is performing using the user error recovery point
 */
void
swerr2(char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swerr(swerr_file, swerr_line, &swerr_handler, format, args);
}

/**
 * NAME:    swerr_SetPos
 * PURPOSE: set source position to report fatal error later with swerr1
 * ARGS:    file - source file name
 *          line - source line number
 */
void
swerr_SetPos(char *file, int line)
{
  swerr_file = file;
  swerr_line = line;
}

/**
 * NAME:    swerr_SetPos
 * PURPOSE: set source position and recovery point
 *          to report fatal error later with swerr2
 * ARGS:    file - source file name
 *          line - source line number
 *          buf  - pointer to jmp_buf - error recovery point
 */
void
swerr_SetPosBuf(char *file, int line, void *buf)
{
  swerr_file    = file;
  swerr_line    = line;

  /* This does not work : swerr_handler = *((jmp_buf) buf); */
  memcpy(&swerr_handler, buf, sizeof (swerr_handler));
}

/**
 * NAME:    swabort
 * PURPOSE: software abort
 * NOTE:    this should normally perform fatal error recovery
 */
void
swabort(void)
{
  abort();
}

/**
 * NAME:    swwarn
 * PURPOSE: write software warning (non fatal error)
 * ARGS:    format - message
 *          ...    - extra message specific arguments
 * NOTE:    source position should be set separately by swerr_SetPos
 */
void
swwarn(char *format, ...)
{
  va_list args;

  va_start(args, format);
  _swwarn(swerr_file, swerr_line, format, args);
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
