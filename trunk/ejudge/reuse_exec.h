/* $Id$ */

#ifndef __REUSE_EXEC_H__
#define __REUSE_EXEC_H__

/* Copyright (C) 1998-2011 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1998-01-21 14:26:50 cher> */

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

#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/* Task states */
enum
{ 
  TSK_ERROR,                    /* error occured */
  TSK_STOPPED,                  /* task is not started */
  TSK_RUNNING,                  /* task is runnning */
  TSK_EXITED,                   /* task has exited */
  TSK_SIGNALED                  /* task was terminated by a signal */
};

/* file descriptor operations */
enum
{
  TSR_CLOSE,                    /* close file descriptor */
  TSR_FILE,                     /* redirect to/from file */
  TSR_DUP,                      /* duplicate file descriptor */
  TSR_PIPE                      /* pipe the file descriptor */
};

/* file open flags */
enum
{
  TSK_REWRITE = 0x10000,
  TSK_WRITE   = 0x20000,
  TSK_READ    = 0x30000,
  TSK_APPEND  = 0x40000
};

/* file open modes */
enum
{
  TSK_FULL_RW = 0666
};

/* task descriptor structure, not exported */
struct tTask;
typedef struct tTask tTask, *tpTask;

int      task_SetFlag(char *, int);

tpTask   task_New(void);
int      task_AddArg(tpTask, char const *arg);
int      task_nAddArgs(tpTask, int n, ...);
int      task_zAddArgs(tpTask, ... /* NULL */);
int      task_pnAddArgs(tpTask, int n, char **p);
int      task_pzAddArgs(tpTask, char **p);
int      task_SetPath(tpTask, char const *arg);
int      task_SetRedir(tpTask, int fd, int mode, ...);
void     task_Delete(tpTask);
char    *task_SetPathAsArg0(tpTask);
int      task_SetEntryFunction(tpTask, int (*)(int, char **));
int      task_SetWorkingDir(tpTask, char const *);
int      task_SetMaxTime(tpTask, int);
int      task_SetMaxTimeMillis(tpTask, int);
int      task_SetMaxRealTime(tpTask, int);
int      task_SetMaxProcCount(tTask *tsk, int cnt);

int      task_PutEnv(tpTask, char const *);
int      task_ClearEnv(tpTask);

int      task_SetKillSignal(tpTask, char const *);
int      task_SetStackSize(tpTask, int);
int      task_SetDataSize(tpTask, int);
int      task_SetVMSize(tpTask, int);
int      task_DisableCoreDump(tpTask);
int      task_EnableMemoryLimitError(tpTask);
int      task_EnableSecureExec(tpTask);
int      task_EnableAllSignals(tpTask);
int      task_EnableSecurityViolationError(tpTask);
int      task_EnableProcessGroup(tpTask);

int      task_PrintArgs(tpTask);
void     task_fPrintArgs(tpTask, FILE *);
int      task_SetQuietFlag(tpTask);
char*    task_GetErrorMessage(tpTask);

int      task_Start(tpTask);
tpTask   task_Wait(tpTask);
int      task_Kill(tpTask);
int      task_Status(tpTask);
int      task_TermSignal(tpTask);
int      task_ExitCode(tpTask);
int      task_ErrorCode(tpTask, int *, int *);
long     task_GetRunningTime(tpTask);
long     task_GetRealTime(tpTask);
void     task_Log(tpTask, int fac, int sev);
int      task_IsAbnormal(tpTask);
int      task_IsTimeout(tpTask);
int      task_IsMemoryLimit(tpTask);
int      task_IsSecurityViolation(tpTask);
int      task_GetPipe(tpTask, int);
int      task_GetPid(tpTask);

#define task_GetMemoryUsed task_GetMemoryUsed
long     task_GetMemoryUsed(tpTask);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_EXEC_H__ */
