/* $Id$ */

#ifndef __REUSE_LOGGER_H__
#define __REUSE_LOGGER_H__

/* Copyright (C) 1997-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdarg.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define LOG_MAX_MODULE_NUM   1024
typedef struct logmodule_t
{
  int   num;                    /* module id */
  char *name;                   /* module name */
  int   level;                  /* default logging level */
  int   blocked;                /* is this facility blocked */
} logmodule_t;

/* Logging priority (a la syslog) */
#define LOG_JUNK     0
#define LOG_DEBUG    1
#define LOG_INFO     2
#define LOG_NOTICE   3
#define LOG_WARNING  4
#define LOG_WARN     4
#define LOG_ERR      5
#define LOG_ERROR    5
#define LOG_CRIT     6
#define LOG_ALERT    7
#define LOG_EMERG    8

/* logger facility itself */
#define LOG_LOGGER   1
#define LOG_SW       2
#define LOG_REUSE    3

void logger_init(logmodule_t *, char *);
void logger_init_ex(logmodule_t *, char *, int);

void logger_open(void);
void logger_close(void);

void logger_set_level(int fac, int level);

int  write_log(int facility, int level, char const *format, ...);
int  vwrite_log(int facility, int level,char const*format,va_list args);
int  logger_get_fd(void);

/* These do return */
#define SWWARN(t)       do { swerr_SetPos(__FILE__, __LINE__); swwarn t; } while(0)

/* These do not return */
#define SWERR(t)        do { swerr_SetPos(__FILE__, __LINE__); swerr1 t; } while(0)
#define SWABORT()       swabort()

#define SWERRJ(b,t)     do { swerr_SetPos(__FILE__, __LINE__, &(b)); swerr2 t; } while(0)
#define SWABORTJ(b)     abort()

void swerr_SetPos(char *file, int lineno);
void swerr_SetPosBuf(char *file, int lineno, void* jmpbuf);

#ifdef __GNUC__
void swerr(char *file, int lineno, char *txt, ...) __attribute__ ((noreturn));
void swerr1(char *txt, ...) __attribute__ ((noreturn));
void swerr2(char *txt, ...) __attribute__ ((noreturn));
void swabort(void) __attribute__ ((noreturn));
#else
void swerr(char *file, int lineno, char *txt, ...);
void swwarn(char *txt, ...);
void swerr1(char *txt, ...);
void swerr2(char *txt, ...);
void swabort(void);
#endif

void swwarn(char *txt, ...);

#if !defined RELEASE
#define ASSERT(e) do { if (!(e)) swerr(__FILE__, __LINE__, "assertion failed: %s", #e); } while(0)
#else
#define ASSERT(e)
#endif /* RELEASE */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_LOGGER_H__ */
