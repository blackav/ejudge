/* $Id$ */

#ifndef __REUSE_GETOPT_H__
#define __REUSE_GETOPT_H__

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

#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/* option parse status */
#define OPT_END   -1            /* no more options available */
#define OPT_ERROR -2            /* error parsing options */

#define OPT_HIDDEN   0x1
#define OPT_USERMASK 0xFFFF0000

/* option descriptor */
typedef struct optrec_t
{
  int         opt_id;       /* option id (returned by opt_get) */
  int         opt_opts;     /* some bitfield flags */
  char       *opt_name;     /* option name */
  char       *opt_flags;    /* option flags */
  void       *opt_data;     /* data address to update */
  char       *opt_info;     /* user visible info about this option */
  void       *opt_extra;    /* extra information */
  char       *opt_arginfo;  /* user visible argument information  */
} optrec_t;

/* option file descriptor to be opened automatically by getopt
 * and returned to the caller.
 * note, that this structure is not used, though
 */
typedef struct optfile_t
{
  char      *name;              /* file name */
  FILE      *file;              /* opened file descriptor */
  char      *(*filter)(char *name); /* filename filter (input parameter) */
} optfile_t;

/* option resources structure */
typedef struct optresource_t
{
  int        id;                /* option identifier */
  void      *ptr;               /* option resource pointer */
} optresource_t;

/* option bitflags flags structure */
typedef struct optmask_t
{
  unsigned long flags;          /* values of flags */
  unsigned long mask;           /* mask of altered flags  */
} optmask_t;

void  opt_banner(void);
void  opt_setargs(optrec_t *, char *, char **,
                         char *, char *, int, char **, int);
int   opt_get(void);
int   opt_close(void);
char *opt_getname(void);
char *opt_getid(void);

void  opt_install_handler(int (*)(int, char *, ...));
void  opt_restore_handler(void);
void  opt_resetargs(optrec_t *, int, char **, int);

int   opt_setoptions(optrec_t *);
void  opt_clearoptions(void);

void  opt_setflags(int);
int   opt_setquiet();
int   opt_getquiet();

/* These functions handles start-up errors
 * they never exit
 */
#ifdef __GNUC__
void err_Startup(char *format, ...) __attribute__((noreturn));
void err_vStartup(/* char *format, va_list args */) __attribute__ ((noreturn));
#else
void err_Startup(char *format, ...);
void err_vStartup(/* char *format, va_list args */);
#endif

#define opt_default ((char *) 2L)

/* various flags (bitmask) */
#define OPTF_NOATSIGN    1      /* do not honor '@' in options */
#define OPTF_NOEXIT      2      /* do not exit() when error */
#define OPTF_NOWARN      4      /* do not warn about unknown opts */
#define OPTF_ALL         7      /* bitmask of all flags */

/* various error codes passed to the custom error handler */
#define OPTE_OK          0
#define OPTE_RESPECIFIED 1      /* option can be specified only once */
#define OPTE_ARG         2      /* argument expected for option */
#define OPTE_SHORT       3      /* integer argument expected */
#define OPTE_FILENAME    4      /* filename required */
#define OPTE_CANNOTOPEN  5      /* cannot open file */
#define OPTE_OPTION      6      /* invalid option */
#define OPTE_IGNOPTION   7      /* option is unknown and ignored */
#define OPTE_NESTINDIR   8      /* netsted interect files */
#define OPTE_INDIR       9      /* indirect file name expected */
#define OPTE_OPENINDIR   10     /* cannot open indirect file */
#define OPTE_TOOMANY     11     /* too many options */
#define OPTE_NOADDR      12     /* no support for option linked */
#define OPTE_TOONEST     13     /* too many indirection levels */
#define OPTE_ONCE        14     /* option may be specified only once */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_GETOPT_H__ */
