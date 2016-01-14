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

static const char * const signal_strings[] =
{
  [0x5] = "Access violation",
  [0x6] = "In page error",
  [0x8] = "Invalid handle",
  [0x17] = "No memory",
  [0x1D] = "Illegal instruction",
  [0x25] = "Noncontinuable exception",
  [0x26] = "Invalid disposition",
  [0x8C] = "Array bounds exceeded",
  [0x8D] = "Denormal operand",
  [0x8E] = "Divide by zero",
  [0x8F] = "Inexact result",
  [0x90] = "Float invalid operation",
  [0x91] = "Float overflow",
  [0x92] = "Float stack check",
  [0x93] = "Float underflow",
  [0x94] = "Integer divide by zero",
  [0x95] = "Integer overflow",
  [0x96] = "Privileged instruction",
  [0xFD] = "Stack overflow",
  [0x100] = "Software abort",
  [0x13A] = "Control C Exit",
  [0x142] =  "DLL init failed",
  [0x26B] = "DLL init failed logoff",
};

/**
 * NAME:    os_GetSignalString
 * PURPOSE: get the signal name
 * ARGS:    s - signal number
 * RETURN:  string with the signal name
 */
const char *
os_GetSignalString(int s)
{
  static char buf[128];

  if (s > 0 && s < sizeof(signal_strings)/sizeof(signal_strings[0])
      && signal_strings[s]) {
    snprintf(buf, sizeof(buf), "Exception 0x%X - %s",
                (0xc0000000 | s), signal_strings[s]);
    return buf;
  }
  snprintf(buf, sizeof(buf), "Exception 0x%X", (0xc0000000 | s));
  return buf;
}
