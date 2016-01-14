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

#include <stdio.h>
#include <string.h>
#include <errno.h>

static char errbuf[256];

/**
 * NAME:    os_ErrorMsg
 * PURPOSE: get error string of the current error (errno variable)
 * RETURN:  error string for the current error
 */
char *
os_ErrorMsg(void)
{
  char *s = 0;

  s = strerror(errno);
  sprintf(errbuf, "%d, %s", errno, s?s:"unknown error");
  return errbuf;
}
