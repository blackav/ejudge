/* -*- mode: c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/cr_serialize.h"
#include "ejudge/prepare.h"

#include <windows.h>

static HANDLE hMutex = 0;

int
cr_serialize_init(const serve_state_t state)
{
  char name[128];

  if (!state->global->cr_serialization_key) return 0;
  if (hMutex) return 0;

  snprintf(name, sizeof(name), "ejudge_%d", state->global->cr_serialization_key);
  hMutex = CreateMutex(NULL, FALSE, name);
  if (!hMutex) return -1;
  return 0;
}

int
cr_serialize_lock(const serve_state_t state)
{
  if (!state->global->cr_serialization_key) return 0;
  if (WaitForSingleObject(hMutex, INFINITE) == WAIT_FAILED) return -1;
  return 0;
}

int
cr_serialize_unlock(const serve_state_t state)
{
  if (!state->global->cr_serialization_key) return 0;
  if (!ReleaseMutex(hMutex)) return -1;
  return 0;
}
