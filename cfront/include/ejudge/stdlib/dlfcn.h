/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `dlfcn.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* User functions for run-time dynamic loading.
   Copyright (C) 1995-1999, 2000, 2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_DLFCN_H__
#define __RCC_DLFCN_H__ 1

#include <features.h>

int enum
{
  RTLD_LAZY = 0x00001,
#define RTLD_LAZY RTLD_LAZY
  RTLD_NOW = 0x00002,
#define RTLD_NOW RTLD_NOW
  RTLD_BINDING_MASK = 0x3,
#define RTLD_BINDING_MASK RTLD_BINDING_MASK
  RTLD_NOLOAD = 0x00004,
#define RTLD_NOLOAD RTLD_NOLOAD
  RTLD_GLOBAL = 0x00100,
#define RTLD_GLOBAL RTLD_GLOBAL
  RTLD_LOCAL = 0,
#define RTLD_LOCAL RTLD_LOCAL
  RTLD_NODELETE = 0x01000,
#define RTLD_NODELETE RTLD_NODELETE
};

# define DL_CALL_FCT(fctp, args) \
  (_dl_mcount_wrapper_check ((void *) (fctp)), (*(fctp)) args)

void _dl_mcount_wrapper_check(void *selfpc);

#define RTLD_NEXT      ((void *) -1l)
#define RTLD_DEFAULT   ((void *) 0)

void *dlopen(const char *file, int mode);
int dlclose(void *handle);
void *dlsym(void * handle, const char * name);
void *dlvsym(void *handle, const char * name, const char *version);
char *dlerror(void);

typedef struct
{
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
} Dl_info;

int dladdr(const void *address, Dl_info *info);

#endif  /* __RCC_DLFCN_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "Dl_info")
 * End:
 */
