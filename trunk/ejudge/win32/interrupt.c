/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/interrupt.h"

#include <windows.h>

static volatile int was_interrupt = 0;
static volatile int was_sighup = 0;

static BOOL WINAPI
interrupt_handler(DWORD dwCtrlType)
{
  was_interrupt = 1;
  return TRUE;
}

void
interrupt_flag_interrupt(void)
{
  was_interrupt = 1;
}

void
interrupt_flag_sighup(void)
{
  was_sighup = 1;
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

int
interrupt_restart_requested(void)
{
  return was_sighup;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
