/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SIGNAL_H__
#define __RCC_SIGNAL_H__

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>
#include <sys/types.h>
#include <bits/sigset.h>

typedef void (*__sighandler_t)(int);

#define SIG_ERR ((__sighandler_t) -1)
#define SIG_DFL ((__sighandler_t) 0)
#define SIG_IGN ((__sighandler_t) 1)

int enum
  {
    SIGHUP = 1,
#define SIGHUP SIGHUP
    SIGINT = 2,
#define SIGINT SIGINT
    SIGQUIT = 3,
#define SIGQUIT SIGQUIT
    SIGILL = 4,
#define SIGILL SIGILL
    SIGTRAP = 5,
#define SIGTRAP SIGTRAP
    SIGABRT = 6,
#define SIGABRT SIGABRT
    SIGIOT = 6,
#define SIGIOT SIGIOT
    SIGBUS = 7,
#define SIGBUS SIGBUS
    SIGFPE = 8,
#define SIGFPE SIGFPE
    SIGKILL = 9,
#define SIGKILL SIGKILL
    SIGUSR1 = 10,
#define SIGUSR1 SIGUSR1
    SIGSEGV = 11,
#define SIGSEGV SIGSEGV
    SIGUSR2 = 12,
#define SIGUSR2 SIGUSR2
    SIGPIPE = 13,
#define SIGPIPE SIGPIPE
    SIGALRM = 14,
#define SIGALRM SIGALRM
    SIGTERM = 15,
#define SIGTERM SIGTERM
    SIGSTKFLT = 16,
#define SIGSTKFLT SIGSTKFLT
    SIGCLD = 17,
#define SIGCLD SIGCLD
    SIGCHLD = 17,
#define SIGCHLD SIGCHLD
    SIGCONT = 18,
#define SIGCONT SIGCONT
    SIGSTOP = 19,
#define SIGSTOP SIGSTOP
    SIGTSTP = 20,
#define SIGTSTP SIGTSTP
    SIGTTIN = 21,
#define SIGTTIN SIGTTIN
    SIGTTOU = 22,
#define SIGTTOU SIGTTOU
    SIGURG = 23,
#define SIGURG SIGURG
    SIGXCPU = 24,
#define SIGXCPU SIGXCPU
    SIGXFSZ = 25,
#define SIGXFSZ SIGXFSZ
    SIGVTALRM = 26,
#define SIGVTALRM SIGVTALRM
    SIGPROF = 27,
#define SIGPROF SIGPROF
    SIGWINCH = 28,
#define SIGWINCH SIGWINCH
    SIGPOLL = 29,
#define SIGPOLL SIGPOLL
    SIGIO = 29,
#define SIGIO SIGIO
    SIGPWR = 30,
#define SIGPWR SIGPWR
    SIGSYS = 31,
#define SIGSYS SIGSYS
    SIGUNUSED = 31,
    _NSIG = 64,
#define _NSIG _NSIG
    SIGRTMIN = 32,
#define SIGRTMIN SIGRTMIN
    SIGRTMAX = 63
#define SIGRTMAX SIGRTMAX
  };

/* BSD stuff */
int sigblock(int mask);
int sigsetmask(int mask);
int siggetmask(void);
#define NSIG _NSIG

__sighandler_t signal(int, __sighandler_t);

int kill(pid_t, int);
int killpg(pid_t pgrp, int sig);
int raise(int sig);

typedef union sigval
{
  int sival_int;
  void *sival_ptr;
} sigval_t;

typedef struct siginfo
{
  int si_signo;
  int si_errno;
  int si_code;
  union
  {
    struct
    {
      pid_t si_pid;
      uid_t si_uid;
    } _kill;

    struct
    {
      unsigned int _timer1;
      unsigned int _timer2;
    } _timer;

    struct
    {
      pid_t si_pid;
      uid_t si_uid;
      sigval_t si_sigval;
    } _rt;

    struct
    {
      pid_t si_pid;
      uid_t si_uid;
      int si_status;
      clock_t si_utime;
      clock_t si_stime;
    } _sigchld;

    struct
    {
      void *si_addr;
    } _sigfault;

    struct
    {
      int si_band;
      int si_fd;
    } _sigpoll;
  } _sifields;
} siginfo_t;

#define si_pid     _sifields._kill.si_pid
#define si_uid     _sifields._kill.si_uid
#define si_timer1  _sifields._timer._timer1
#define si_timer2  _sifields._timer._timer2
#define si_status  _sifields._sigchld.si_status
#define si_utime   _sifields._sigchld.si_utime
#define si_stime   _sifields._sigchld.si_stime
#define si_value   _sifields._rt.si_sigval
#define si_int     _sifields._rt.si_sigval.sival_int
#define si_ptr     _sifields._rt.si_sigval.sival_ptr
#define si_addr    _sifields._sigfault.si_addr
#define si_band    _sifields._sigpoll.si_band
#define si_fd      _sifields._sigpoll.si_fd

struct sigaction
{
  __sighandler_t sa_handler;
  void (*sa_sigaction)(int, siginfo_t *, void *);
  sigset_t sa_mask;
  int sa_flags;
  void (*sa_restorer)(void);
};

int enum
{
  SA_NOCLDSTOP = 1,
#define SA_NOCLDSTOP SA_NOCLDSTOP
  SA_NOCLDWAIT = 2,
#define SA_NOCLDWAIT SA_NOCLDWAIT
  SA_SIGINFO = 4,
#define SA_SIGINFO SA_SIGINFO
  SA_ONSTACK = 0x08000000,
#define SA_ONSTACK SA_ONSTACK
  SA_RESTART = 0x10000000,
#define SA_RESTART SA_RESTART
  SA_NODEFER = 0x40000000,
#define SA_NODEFER SA_NODEFER
  SA_RESETHAND = 0x80000000,
#define SA_RESETHAND SA_RESETHAND
  SA_INTERRUPT = 0x20000000,
#define SA_INTERRUPT SA_INTERRUPT
  SA_NOMASK = SA_NODEFER,
#define SA_NOMASK SA_NOMASK
  SA_ONESHOT = SA_RESETHAND,
#define SA_ONESHOT SA_ONESHOT
  SA_STACK = SA_ONSTACK
#define SA_STACK SA_STACK
};

int enum
{
  SIG_BLOCK = 0,
#define SIG_BLOCK SIG_BLOCK
  SIG_UNBLOCK = 1,
#define SIG_UNBLOCK SIG_UNBLOCK
  SIG_SETMASK = 2
#define SIG_SETMASK SIG_SETMASK
};

int sigemptyset(sigset_t *);
int sigfillset(sigset_t *);
int sigaddset(sigset_t *, int);
int sigdelset(sigset_t *, int);
int sigismember(const sigset_t *, int);

int sigisemptyset(const sigset_t *);
int sigandset(sigset_t *, const sigset_t *, const sigset_t *);
int sigorset(sigset_t *, const sigset_t *, const sigset_t *);

int sigprocmask(int, const sigset_t *, sigset_t *);
int sigsuspend(const sigset_t *);
int __sigaction(int, const struct sigaction *, struct sigaction *);
int sigaction(int, const struct sigaction *, struct sigaction *);
int sigpending(sigset_t *);

struct timespec;
int sigwait(const sigset_t *, int *);
int sigwaitinfo(const sigset_t *, siginfo_t *);
int sigtimedwait(const sigset_t *, siginfo_t *, const struct timespec *);

int sigqueue(pid_t, int, const union sigval);

int enum
{
  SI_ASYNCNL = -6,
#define SI_ASYNCNL SI_ASYNCNL
  SI_SIGIO,
#define SI_SIGIO SI_SIGIO
  SI_ASYNCIO,
#define SI_ASYNCIO SI_ASYNCIO
  SI_MESGQ,
#define SI_MESGQ SI_MESGQ
  SI_TIMER,
#define SI_TIMER SI_TIMER
  SI_QUEUE,
#define SI_QUEUE SI_QUEUE
  SI_USER,
#define SI_USER SI_USER
  SI_KERNEL = 0x80
#define SI_KERNEL SI_KERNEL
};

int enum
{
  ILL_ILLOPC = 1,
#define ILL_ILLOPC ILL_ILLOPC
  ILL_ILLOPN,
#define ILL_ILLOPN ILL_ILLOPN
  ILL_ILLADR,
#define ILL_ILLADR ILL_ILLADR
  ILL_ILLTRP,
#define ILL_ILLTRP ILL_ILLTRP
  ILL_PRVOPC,
#define ILL_PRVOPC ILL_PRVOPC
  ILL_PRVREG,
#define ILL_PRVREG ILL_PRVREG
  ILL_COPROC,
#define ILL_COPROC ILL_COPROC
  ILL_BADSTK
#define ILL_BADSTK ILL_BADSTK
};

int enum
{
  FPE_INTDIV = 1,
#define FPE_INTDIV FPE_INTDIV
  FPE_INTOVF,
#define FPE_INTOVF FPE_INTOVF
  FPE_FLTDIV,
#define FPE_FLTDIV FPE_FLTDIV
  FPE_FLTOVF,
#define FPE_FLTOVF FPE_FLTOVF
  FPE_FLTUND,
#define FPE_FLTUND FPE_FLTUND
  FPE_FLTRES,
#define FPE_FLTRES FPE_FLTRES
  FPE_FLTINV,
#define FPE_FLTINV FPE_FLTINV
  FPE_FLTSUB
#define FPE_FLTSUB FPE_FLTSUB
};

int enum
{
  SEGV_MAPERR = 1,
#define SEGV_MAPERR SEGV_MAPERR
  SEGV_ACCERR
#define SEGV_ACCERR SEGV_ACCERR
};

int enum
{
  BUS_ADRALN = 1,
#define BUS_ADRALN BUS_ADRALN
  BUS_ADRERR,
#define BUS_ADRERR BUS_ADRERR
  BUS_OBJERR
#define BUS_OBJERR BUS_OBJERR
};

int enum
{
  TRAP_BRKPT = 1,
#define TRAP_BRKPT TRAP_BRKPT
  TRAP_TRACE
#define TRAP_TRACE TRAP_TRACE
};

int enum
{
  CLD_EXITED = 1,
#define CLD_EXITED CLD_EXITED
 CLD_KILLED,
#define CLD_KILLED CLD_KILLED
  CLD_DUMPED,
#define CLD_DUMPED CLD_DUMPED
  CLD_TRAPPED,
#define CLD_TRAPPED CLD_TRAPPED
  CLD_STOPPED,
#define CLD_STOPPED CLD_STOPPED
  CLD_CONTINUED
#define CLD_CONTINUED CLD_CONTINUED
};

int enum
{
  POLL_IN = 1,
#define POLL_IN POLL_IN
  POLL_OUT,
#define POLL_OUT POLL_OUT
  POLL_MSG,
#define POLL_MSG POLL_MSG
  POLL_ERR,
#define POLL_ERR POLL_ERR
  POLL_PRI,
#define POLL_PRI POLL_PRI
  POLL_HUP
#define POLL_HUP POLL_HUP
};

#define __SIGEV_MAX_SIZE 64
#define __SIGEV_PAD_SIZE ((__SIGEV_MAX_SIZE / sizeof (int)) - 3)

typedef struct sigevent
{
  sigval_t sigev_value;
  int sigev_signo;
  int sigev_notify;

  union
  {
    int _pad[__SIGEV_PAD_SIZE];
    struct
    {
      void (*_function) (sigval_t);
      void *_attribute;
    } _sigev_thread;
  } _sigev_un;
} sigevent_t;

#define sigev_notify_function   _sigev_un._sigev_thread._function
#define sigev_notify_attributes _sigev_un._sigev_thread._attribute

int enum
{
  SIGEV_SIGNAL = 0,
# define SIGEV_SIGNAL SIGEV_SIGNAL
  SIGEV_NONE,
# define SIGEV_NONE SIGEV_NONE
  SIGEV_THREAD
# define SIGEV_THREAD SIGEV_THREAD
};

__sighandler_t sigset(int sig, __sighandler_t disp);
extern const char *const sys_siglist[_NSIG];
#define _sys_siglist sys_siglist

#endif /* __RCC_SIGNAL_H__ */
