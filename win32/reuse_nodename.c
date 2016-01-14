/* -*- mode:c -*- */

/* Copyright (C) 2002-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/osdeps.h"

#include <windows.h>

/**
 * NAME:    os_NodeName
 * PURPOSE: get the host name
 * RETURN:  hostname - string in the static location
 */
static char nodename_buf[MAX_COMPUTERNAME_LENGTH + 16];
char *
os_NodeName(void)
{
  DWORD len = MAX_COMPUTERNAME_LENGTH + 10;

  GetComputerName(nodename_buf, &len);
  nodename_buf[MAX_COMPUTERNAME_LENGTH + 10] = 0;
  return nodename_buf;
}
