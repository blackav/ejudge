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

#include "interrupt.h"

#include <windows.h>

static volatile int was_interrupt = 0;

static BOOL WINAPI
interrupt_handler(DWORD dwCtrlType)
{
  was_interrupt = 1;
  return TRUE;
}

void
interrupt_init(void)
{
}

void
interrupt_enable(void)
{
  SetConsoleCtrlHandler(interrupt_handler, FALSE);
}

void
interrupt_disable(void)
{
  SetConsoleCtrlHandler(interrupt_handler, TRUE);
}

int
interrupt_get_status(void)
{
  return was_interrupt;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "BOOL" "WINAPI")
 * End:
 */
