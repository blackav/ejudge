/* $Id$ */

#ifndef __REUSE_ERRORS_H__
#define __REUSE_ERRORS_H__

/* Copyright (C) 1997-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: Fri Jul 11 20:17:26 1997 by cher (Alexander Chernov) */

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

/* Error classes */
enum
{
  ERC_NONE = 0,                 /* not used */
  ERC_INFO = 1,
  ERC_NOTICE,
  ERC_WARNING,
  ERC_ERROR,
  ERC_SEVERE,
  ERC_CRIT,
  ERC_FATAL
};

/* this structure is reuse-compatible (for now) */
typedef struct tErrorTable
{
  int   Number;
  int   Class;
  char *Format;
} tErrorTable, *ptErrorTable;

struct tPosition;

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

void err_Initialize(void);
int  err_Register(const tErrorTable * const);

int  err_Write(int, ...);
int  err_vWrite(/*int code, va_list args*/);
int  err_sWrite(int, char *, ...);
int  err_vsWrite(/*int severity, char *format, va_list args*/);
int  err_psWrite(int, struct tPosition *, char *, ...);
int  err_vpsWrite(/*int sev, tPosition *pos, char *f, va_list args*/);
int  err_pWrite(int, struct tPosition *, ...);
int  err_vpWrite(/*int code, tPosition *pos, va_list args*/);

typedef int (*err_tfWriteHandler)(/*
                                   *void              *data,
                                   *int               sev,
                                   *int               code,
                                   *struct tPosition *pos,
                                   *char             *sev_str,
                                   *char             *pos_str,
                                   *char             *format,
                                   *va_list           args
                                   */);

err_tfWriteHandler err_InstallWriteHandler(err_tfWriteHandler, void*);

void err_ClearCntr(void);
int  err_GetCntr(int);
int  err_GetSumCntr(int);

void *err_SaveCounters(void);
void  err_RestoreCounters(void *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_ERRORS_H__ */
