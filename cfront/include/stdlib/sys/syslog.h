/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_SYSLOG_H__
#define __RCC_SYS_SYSLOG_H__ 1

/* Copyright (C) 2003-2004 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>
#include <sys/types.h>
#include <stdarg.h>

#define _PATH_LOG       "/dev/log"

/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
int enum
{
  LOG_EMERG = 0,
#define LOG_EMERG LOG_EMERG
  LOG_ALERT = 1,
#define LOG_ALERT LOG_ALERT
  LOG_CRIT = 2,
#define LOG_CRIT LOG_CRIT
  LOG_ERR = 3,
#define LOG_ERR LOG_ERR
  LOG_WARNING = 4,
#define LOG_WARNING LOG_WARNING
  LOG_NOTICE = 5,
#define LOG_NOTICE LOG_NOTICE
  LOG_INFO = 6,
#define LOG_INFO LOG_INFO
  LOG_DEBUG = 7,
#define LOG_DEBUG LOG_DEBUG
  LOG_PRIMASK = 0x07,
#define LOG_PRIMASK LOG_PRIMASK
};

#define LOG_PRI(p)      ((p) & LOG_PRIMASK)
#define LOG_MAKEPRI(fac, pri)   (((fac) << 3) | (pri))

/* facility codes */
int enum
{
  LOG_KERN = (0<<3),
#define LOG_KERN LOG_KERN
  LOG_USER = (1<<3),
#define LOG_USER LOG_USER
  LOG_MAIL = (2<<3),
#define LOG_MAIL LOG_MAIL
  LOG_DAEMON = (3<<3),
#define LOG_DAEMON LOG_DAEMON
  LOG_AUTH = (4<<3),
#define LOG_AUTH LOG_AUTH
  LOG_SYSLOG = (5<<3),
#define LOG_SYSLOG LOG_SYSLOG
  LOG_LPR = (6<<3),
#define LOG_LPR LOG_LPR
  LOG_NEWS = (7<<3),
#define LOG_NEWS LOG_NEWS
  LOG_UUCP = (8<<3),
#define LOG_UUCP LOG_UUCP
  LOG_CRON = (9<<3),
#define LOG_CRON LOG_CRON
  LOG_AUTHPRIV = (10<<3),
#define LOG_AUTHPRIV LOG_AUTHPRIV
  LOG_FTP = (11<<3),
#define LOG_FTP LOG_FTP
  LOG_LOCAL0 = (16<<3),
#define LOG_LOCAL0 LOG_LOCAL0
  LOG_LOCAL1 = (17<<3),
#define LOG_LOCAL1 LOG_LOCAL1
  LOG_LOCAL2 = (18<<3),
#define LOG_LOCAL2 LOG_LOCAL2
  LOG_LOCAL3 = (19<<3),
#define LOG_LOCAL3 LOG_LOCAL3
  LOG_LOCAL4 = (20<<3),
#define LOG_LOCAL4 LOG_LOCAL4
  LOG_LOCAL5 = (21<<3),
#define LOG_LOCAL5 LOG_LOCAL5
  LOG_LOCAL6 = (22<<3),
#define LOG_LOCAL6 LOG_LOCAL6
  LOG_LOCAL7 = (23<<3),
#define LOG_LOCAL7 LOG_LOCAL7
  LOG_NFACILITIES = 24,
#define LOG_NFACILITIES LOG_NFACILITIES
  LOG_FACMASK = 0x03f8,
#define LOG_FACMASK LOG_FACMASK
};

#define LOG_FAC(p)      (((p) & LOG_FACMASK) >> 3)

/*
 * arguments to setlogmask.
 */
#define LOG_MASK(pri)   (1 << (pri))            /* mask for one priority */
#define LOG_UPTO(pri)   ((1 << ((pri)+1)) - 1)  /* all priorities through pri */

/*
 * Option flags for openlog.
 *
 * LOG_ODELAY no longer does anything.
 * LOG_NDELAY is the inverse of what it used to be.
 */
int enum
{
  LOG_PID = 0x01,
#define LOG_PID LOG_PID
  LOG_CONS = 0x02,
#define LOG_CONS LOG_CONS
  LOG_ODELAY = 0x04,
#define LOG_ODELAY LOG_ODELAY
  LOG_NDELAY = 0x08,
#define LOG_NDELAY LOG_NDELAY
  LOG_NOWAIT = 0x10,
#define LOG_NOWAIT LOG_NOWAIT
  LOG_PERROR = 0x20,
#define LOG_PERROR LOG_PERROR
};

/* Close desriptor used to write to system logger.  */
void closelog(void);

/* Open connection to system logger.  */
void openlog(const char *ident, int option, int facility);

/* Set the log mask level.  */
int setlogmask(int mask);

/* Generate a log message using FMT string and option arguments.  */
void syslog(int pri, const char *fmt, ...);

/* Generate a log message using FMT and using arguments pointed to by AP.  */
void vsyslog(int pri, const char *fmt, va_list ap);

#ifdef SYSLOG_NAMES

#define INTERNAL_NOPRI  0x10
#define INTERNAL_MARK   LOG_MAKEPRI(LOG_NFACILITIES, 0)

typedef struct _code
{
  char	*c_name;
  int	c_val;
} CODE;

CODE prioritynames[] =
  {
    { "alert", LOG_ALERT },
    { "crit", LOG_CRIT },
    { "debug", LOG_DEBUG },
    { "emerg", LOG_EMERG },
    { "err", LOG_ERR },
    { "error", LOG_ERR },		/* DEPRECATED */
    { "info", LOG_INFO },
    { "none", INTERNAL_NOPRI },		/* INTERNAL */
    { "notice", LOG_NOTICE },
    { "panic", LOG_EMERG },		/* DEPRECATED */
    { "warn", LOG_WARNING },		/* DEPRECATED */
    { "warning", LOG_WARNING },
    { NULL, -1 }
  };

CODE facilitynames[] =
  {
    { "auth", LOG_AUTH },
    { "authpriv", LOG_AUTHPRIV },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "ftp", LOG_FTP },
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "mark", INTERNAL_MARK },		/* INTERNAL */
    { "news", LOG_NEWS },
    { "security", LOG_AUTH },		/* DEPRECATED */
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
  };
#endif /* SYSLOG_NAMES */

#endif /* __RCC_SYS_SYSLOG_H__ */
