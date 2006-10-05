/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include <signal.h>

static volatile int was_interrupt = 0;
static volatile int was_sighup = 0;
static sigset_t orig_mask;
static sigset_t work_mask;

static void
interrupt_handler(int signo)
{
  was_interrupt = 1;
}

static void
sighup_handler(int signo)
{
  was_sighup = 1;
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

void
interrupt_init(void)
{
  sigemptyset(&work_mask);
  sigaddset(&work_mask, SIGINT);
  sigaddset(&work_mask, SIGTERM);
  sigaddset(&work_mask, SIGTSTP);
  sigaddset(&work_mask, SIGHUP);

  sigprocmask(SIG_SETMASK, 0, &orig_mask);

  signal(SIGINT, interrupt_handler);
  signal(SIGTERM, interrupt_handler);
  signal(SIGTSTP, interrupt_handler);
  signal(SIGHUP, sighup_handler);
}

void
interrupt_enable(void)
{
  sigprocmask(SIG_UNBLOCK, &work_mask, 0);
}

void
interrupt_disable(void)
{
  sigprocmask(SIG_BLOCK, &work_mask, 0);
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
