/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_UTSNAME_H__
#define __RCC_SYS_UTSNAME_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

int enum
  {
    _UTSNAME_LENGTH = 65,
    _UTSNAME_DOMAIN_LENGTH = _UTSNAME_LENGTH,
    _UTSNAME_NODENAME_LENGTH = _UTSNAME_LENGTH
  };

struct utsname
{
  char sysname[_UTSNAME_LENGTH];
  char nodename[_UTSNAME_NODENAME_LENGTH];
  char release[_UTSNAME_LENGTH];
  char version[_UTSNAME_LENGTH];
  char machine[_UTSNAME_LENGTH];
  char domainname[_UTSNAME_DOMAIN_LENGTH];
};

int uname(struct utsname *);

#endif /* __RCC_SYS_UTSNAME_H__ */
