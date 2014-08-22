/*$Id$*/

/* Copyright (C) 1997-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: Fri Jul 11 20:19:57 1997 by cher (Alexander Chernov) */

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
 * FILE:    utils/errors.c
 * PURPOSE: error reporting routine
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/logger.h"
#include "ejudge/getopt.h"
#include "ejudge/errors.h"
#include "ejudge/positions.h"
#include "ejudge/xalloc.h"

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static int standard_write_handler();
/* error write handler */
static err_tfWriteHandler  write_handler = standard_write_handler;
/* extra user provided data to be passed to the callback */
static void               *write_handler_data = NULL;

/* table of errors by numbers */
#define ERROR_MAP_SIZE 1024
static tErrorTable const * error_map[ERROR_MAP_SIZE];

/* error counters by severity */
static int error_cntr[ERC_FATAL + 1];

/**
 * NAME:    err_Initialize
 * PURPOSE: initialize the module
 */
  void
err_Initialize(void)
{  
}

/**
 * NAME:    err_Register
 * PURPOSE: register errors
 * ARGS:    table - table of errors to be registered
 * RETURN:  number of error reports registered
 */
  int
err_Register(const tErrorTable * const table)
{
  int i;
  int cnt = 0;

  for (i = 0; table[i].Number != 0; i++)
    {
      ASSERT(table[i].Number > 0);
      ASSERT(table[i].Number < ERROR_MAP_SIZE);

      if (!error_map[table[i].Number])
        {
          error_map[table[i].Number] = table + i;
          cnt++;
        }
    }
  return cnt;
}

static char const * const sev_string[]=
{ "", "Info", "Notice", "Warning", "Error", "Severe", "Critical", "Fatal" };

#define POS_BUF_SIZE 1024

/**
 * NAME:    err_DoWrite
 * PURPOSE: format and write error message
 * ARGS:    severity - error severity
 *          code     - error code
 *          pos      - pointer to the position structure
 *          format   - error message
 *          args     - extra message specific args
 * RETURN:  value returned by the error write handler (number of bytes written)
 */
  static int
err_DoWrite(int severity,
            int code,
            tPosition *pos,
            char *format,
            va_list args)
{
  const char *sev_str = NULL;
  char        pos_buf[POS_BUF_SIZE];
  const char *pos_str = NULL;
  char  sev_buf[32];

  if (severity >= ERC_INFO && severity <= ERC_CRIT)
    {
      error_cntr[severity]++;
      sev_str = sev_string[severity];
    }
  else if (severity != 0)
    {
      sev_str = sev_buf;
      sprintf(sev_buf, "Bad_Severity(%d)", severity);
    }

  if (pos)
    {
      pos_str = pos_buf;
      possnPrintf(pos_buf, POS_BUF_SIZE, "%f:%l:%c", *pos);
    }

  if (!format)
    {
      format = "<NULL>";
    }

  return write_handler(write_handler_data,
                       severity,
                       code,
                       pos,
                       sev_str,
                       pos_str,
                       format,
                       args);
}

/**
 * NAME:    err_vpWrite
 * PURPOSE: write error message
 * ARGS:    code - error code
 *          pos  - error position
 *          args - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_vpWrite(int code, tPosition *pos, va_list args)
{
  char  err_buf[32];
  char *err_str = NULL;
  int   err_sev;

  if (code <= 0 || code >= ERROR_MAP_SIZE || !error_map[code])
    {
      err_str = err_buf;
      sprintf(err_buf, "Bad_Error(%d)", code);
      err_sev = 0;
    }
  else
    {
      err_str = error_map[code]->Format;
      err_sev = error_map[code]->Class;
    }

  return err_DoWrite(err_sev, code, pos, err_str, args);
}

/**
 * NAME:    err_pWrite
 * PURPOSE: write error message
 * ARGS:    code - error code
 *          pos  - error position
 *          ...  - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_pWrite(int code, tPosition *pos, ...)
{
  va_list args;
  int     r;
  
  va_start(args, pos);
  r = err_vpWrite(code, pos, args);
  va_end(args);
  return r;
}

/**
 * NAME:    err_vWrite
 * PURPOSE: write error message
 * ARGS:    code - error code
 *          args - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_vWrite(int code, va_list args)
{
  return err_vpWrite(code, NULL, args);
}

/**
 * NAME:    err_Write
 * PURPOSE: write error message
 * ARGS:    code - error code
 *          ...  - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_Write(int code, ...)
{
  va_list args;
  int     r;
  
  va_start(args, code);
  r = err_vpWrite(code, NULL, args);
  va_end(args);  
  return r;
}

/**
 * NAME:    err_vpsWrite
 * PURPOSE: write error message
 * ARGS:    sev    - error severity
 *          pos    - error position
 *          format - error message
 *          args   - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_vpsWrite(int sev, tPosition *pos, char *format, va_list args)
{
  return err_DoWrite(sev, 0, pos, format, args);
}

/**
 * NAME:    err_psWrite
 * PURPOSE: write error message
 * ARGS:    sev    - error severity
 *          pos    - error position
 *          format - error message
 *          ...    - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_psWrite(int sev, tPosition *pos, char *format, ...)
{
  va_list args;
  int     r;

  va_start(args, format);
  r = err_DoWrite(sev, 0, pos, format, args);
  va_end(args);
  return r;
}

/**
 * NAME:    err_vsWrite
 * PURPOSE: write error message
 * ARGS:    sev    - error severity
 *          format - error message
 *          args   - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_vsWrite(int sev, char *format, va_list args)
{
  return err_DoWrite(sev, 0, 0, format, args);
}

/**
 * NAME:    err_sWrite
 * PURPOSE: write error message
 * ARGS:    sev    - error severity
 *          format - error message
 *          ...    - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  int
err_sWrite(int sev, char *format, ...)
{
  va_list args;
  int     r;

  va_start(args, format);
  r = err_DoWrite(sev, 0, 0, format, args);
  va_end(args);
  return r;
}

/**
 * NAME:    err_InstallWriteHandler
 * PURPOSE: install error write handler
 * ARGS:    func - new error write handler
 *          data - user specified data to be passed back to the handler
 * RETURN:  previous error write handler
 */
  err_tfWriteHandler
err_InstallWriteHandler(err_tfWriteHandler func, void *data)
{
  err_tfWriteHandler old = write_handler;

  write_handler = func?func:standard_write_handler;
  write_handler_data = data;

  return old;
}

/**
 * NAME:    standard_write_handler
 * PURPOSE: standard error write handler
 * ARGS:    data         - user provided data
 *          severity     - error severity
 *          code         - error code
 *          pos          - error position
 *          severity_str - severity converted to string
 *          pos_str      - position converted to string
 *          format       - error message itself
 *          args         - extra message-specific arguments
 * RETURN:  number of bytes written
 */
  static int
standard_write_handler(void *data, /* not used */
                       int severity, /* not used */
                       int code, /* not used */
                       tPosition *pos, /* not used */
                       char *severity_str,
                       char *pos_str,
                       char *format,
                       va_list args)
{
  int r;

  if (pos_str)
    {
      if (severity_str)
        {
          fprintf(stderr, "%s:%s:", pos_str, severity_str);
          r = vfprintf(stderr, format, args);
        }
      else
        {
          fprintf(stderr, "%s:", pos_str);
          r = vfprintf(stderr, format, args);
        }
    }
  else
    {
      if (severity_str)
        {
          fprintf(stderr, "%s:", severity_str);
          r = vfprintf(stderr, format, args);
        }
      else
        {
          r = vfprintf(stderr, format, args);
        }
    }
  fputs("\n", stderr);
  return r;
}

#define SAVE_MAGIC_VALUE 0x92E37A55U
/**
 * NAME:    err_SaveCounters
 * PURPOSE: save the error counters
 */
void *
err_SaveCounters(void)
{
  int *ps = xmalloc(sizeof(error_cntr) + sizeof(int));
  memmove(ps + 1, error_cntr, sizeof(error_cntr));
  ps[0] = SAVE_MAGIC_VALUE;
  return ps;
}

/**
 * NAME:    err_RestoreCounters
 * PURPOSE: restore the error counters
 */
void
err_RestoreCounters(void *vps)
{
  int *ps = (int*) vps;
  ASSERT(ps[0] == SAVE_MAGIC_VALUE);
  memmove(error_cntr, ps + 1, sizeof(error_cntr));
  memset(ps, 0, sizeof(error_cntr) + sizeof(int));
  xfree(ps);
}

/**
 * NAME:    err_ClearCntr
 * PURPOSE: clear error counters
 */
  void
err_ClearCntr(void)
{
  memset(error_cntr, 0, sizeof(error_cntr));
}

/**
 * NAME:    err_GetCntr
 * PURPOSE: get error counter for a specific error class
 * ARGS:    kind - error class
 * RETURN:  error counter (number of error messages of specific class)
 */
  int
err_GetCntr(int kind)
{
  return error_cntr[kind];
}

/**
 * NAME:    err_GetSumCntr
 * PURPOSE: get total number of error messages with severity
 *          higher or equal to provided
 * ARGS:    kind - error class (minimal severity to start counting)
 * RETURN:  total number of error messages
 */
  int
err_GetSumCntr(int kind)
{
  int s = 0;
  int i;

  ASSERT(kind >= ERC_NONE && kind <= ERC_FATAL);
  for (i = kind; i <= ERC_FATAL; i++)
    {
      s += error_cntr[i];
    }

  return s;
}
