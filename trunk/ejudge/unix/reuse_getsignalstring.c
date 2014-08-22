/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

/* names of signals */
#define SIGNUM 31
static const char *signames[SIGNUM] = 
{
  "(unknown signal)",
  "SIGHUP",     "SIGINT",    "SIGQUIT",   "SIGILL",
  "SIGTRAP",    "SIGABRT",   "SIGBUS",    "SIGFPE",
  "SIGKILL",    "SIGUSR1",   "SIGSEGV",   "SIGUSR2",
  "SIGPIPE",    "SIGALRM",   "SIGTERM",   "SIGCHLD",
  "SIGCONT",    "SIGSTOP",   "SIGTSTP",   "SIGTTIN",
  "SIGTTOU",    "SIGURG",    "SIGXCPU",   "SIGXFSZ",
  "SIGVTALRM",  "SIGPROF",   "SIGWINCH",  "SIGIO",
  "SIGPWR"
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
  if (s <= 0 || s >= SIGNUM)
    return signames[0];
  return signames[s];
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
