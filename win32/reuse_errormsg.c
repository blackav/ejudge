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
#include <stdio.h>

static char errmsg_buf[512];

/**
 * NAME:    os_ErrorMsg
 * PURPOSE: get error string of the current error (errno variable)
 * RETURN:  error string for the current error
 */
char *
os_ErrorMsg(void)
{
  char buf[512];
  int  e = GetLastError();

  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, e,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buf, sizeof(buf), NULL);
  snprintf(errmsg_buf, sizeof(errmsg_buf), "%d, %s", e, buf);
  errmsg_buf[sizeof(errmsg_buf) - 1] = 0;
  return errmsg_buf;
}
