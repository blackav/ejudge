# -*- Makefile -*-
# $Id$

# Copyright (C) 2000 Alexander Chernov <cher@ispras.ru> */

#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.

#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

ifeq ($(shell uname),Linux)
CFLAGS=-Wall -O2
LDFLAGS=-s
ARCH=unix
EXESFX=
else
CFLAGS=-mno-cygwin -O2 -Wall
LDFLAGS=-mno-cygwin -s
ARCH=win32
EXESFX=.exe
endif

CC=gcc
LD=gcc

TARGETS = maxs${EXESFX} summ${EXESFX} check_a${EXESFX} check_b${EXESFX}

all : ${TARGETS}
clean:
	-rm -f ${TARGETS}

maxs${EXESFX} : maxs.c
summ${EXESFX} : summ.c

check_a.exe: summ.exe
	cp $< $@
check_b.exe: maxs.exe
	cp $< $@

check_a: summ
	ln -f $< $@
check_b: maxs
	ln -f $< $@
