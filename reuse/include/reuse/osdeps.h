/* $Id$ */

#ifndef __REUSE_OSDEPS_H__
#define __REUSE_OSDEPS_H__

/* Copyright (C) 1997-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1997-11-18 16:14:11 cher> */

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
 * FILE:    utils/osdeps.h
 * PURPOSE: miscellanious os-dependent functions
 */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

char *os_GetErrorString(int);
const char *os_GetSignalString(int);
char *os_ErrorString(void);
char *os_ErrorMsg(void);

char *os_FindInPath(char const *);

char *os_GetSuffix(char const *);
int   os_rGetSuffix(char const *, char *, int);
char *os_SubstSuffix(char const *, char const *);

char *os_GetBasename(char const *);
int   os_rGetBasename(char const *, char *, int);
char *os_GetLastname(char const *);
int   os_rGetLastname(char const *, char *, int);

int   os_MakeDirPath(char const *, int);
int   os_MakeDirPath2(const unsigned char *path, const unsigned char *mode_str, const unsigned char *group_str);
int   os_MakeDir(char const *, int);

char *os_DirName(char const *);
int   os_rDirName(char const *, char *, int);
char *os_NodeName(void);
char *os_tempnam(char const *, char const *);

enum { OSPK_REG = 0, OSPK_DIR = 1, OSPK_OTHER = 2 };
int   os_IsFile(char const *path);

int os_SetLock(char const *, int, int);

enum { REUSE_X_OK = 1, REUSE_W_OK = 2, REUSE_R_OK = 4, REUSE_F_OK = 8 };
int os_CheckAccess(char const *path, int perms);
void *os_AttachFILE(int, char const *);

void os_Sleep(int);

char *os_GetWorkingDir(void);
int   os_rGetWorkingDir(char *, unsigned int, int);
int   os_IsAbsolutePath(char const *);
void  os_normalize_path(char *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_OSDEPS_H__ */
