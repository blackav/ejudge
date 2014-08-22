/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/ttydefaults.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*-
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ttydefaults.h       8.4 (Berkeley) 1/21/94
 */

/* Copyright (C) 2004 Alexander Chernov */

#ifndef __RCC_SYS_TTYDEFAULTS_H__
#define __RCC_SYS_TTYDEFAULTS_H__

#include <features.h>

/*
 * Defaults on "first" open.
 */
#define TTYDEF_IFLAG    (BRKINT | ISTRIP | ICRNL | IMAXBEL | IXON | IXANY)
#define TTYDEF_OFLAG    (OPOST | ONLCR | XTABS)
#define TTYDEF_LFLAG    (ECHO | ICANON | ISIG | IEXTEN | ECHOE|ECHOKE|ECHOCTL)
#define TTYDEF_CFLAG    (CREAD | CS7 | PARENB | HUPCL)
#define TTYDEF_SPEED    (B9600)

/*
 * Control Character Defaults
 */
#define CTRL(x) (x&037)

int enum
{
  CEOF = CTRL('d'),
#define CEOF CEOF
  CEOL = 0,
#define CEOL CEOL
  CERASE = 0177,
#define CERASE CERASE
  CINTR = CTRL('c'),
#define CINTR CINTR
  CSTATUS = 0,
#define CSTATUS CSTATUS
  CKILL = CTRL('u'),
#define CKILL CKILL
  CMIN = 1,
#define CMIN CMIN
  CQUIT = 034,
#define CQUIT CQUIT
  CSUSP = CTRL('z'),
#define CSUSP CSUSP
  CTIME = 0,
#define CTIME CTIME
  CDSUSP = CTRL('y'),
#define CDSUSP CDSUSP
  CSTART = CTRL('q'),
#define CSTART CSTART
  CSTOP = CTRL('s'),
#define CSTOP CSTOP
  CLNEXT = CTRL('v'),
#define CLNEXT CLNEXT
  CDISCARD = CTRL('o'),
#define CDISCARD CDISCARD
  CWERASE = CTRL('w'),
#define CWERASE CWERASE
  CREPRINT = CTRL('r'),
#define CREPRINT CREPRINT
  CEOT = CEOF,
#define CEOT CEOT
  CBRK = CEOL,
#define CBRK CBRK
  CRPRNT = CREPRINT,
#define CRPRNT CRPRNT
  CFLUSH = CDISCARD
#define CFLUSH CFLUSH
};

#endif /* __RCC_SYS_TTYDEFAULTS_H__ */
