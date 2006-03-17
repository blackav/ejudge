/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "cr_serialize.h"
#include "prepare.h"
#include "prepare_vars.h"

#include <windows.h>

static HANDLE hMutex = 0;

int
cr_serialize_init(void)
{
  char name[128];

  if (!global->cr_serialization_key) return 0;
  if (hMutex) return 0;

  snprintf(name, sizeof(name), "ejudge_%d", global->cr_serialization_key);
  hMutex = CreateMutex(NULL, FALSE, name);
  if (!hMutex) return -1;
  return 0;
}

int
cr_serialize_lock(void)
{
  if (!global->cr_serialization_key) return 0;
  if (WaitForSingleObject(hMutex, INFINITE) == WAIT_FAILED) return -1;
  return 0;
}

int
cr_serialize_unlock(void)
{
  if (!global->cr_serialization_key) return 0;
  if (!ReleaseMutex(hMutex)) return -1;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "HANDLE")
 * End:
 */
