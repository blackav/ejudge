# -*- Makefile -*-
# $Id$

# Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

CC = gcc
CDEBUGFLAGS=-g -Wall

CCOMPFLAGS=-D_GNU_SOURCE
LDCOMPFLAGS=

LDLIBS=${EXTRALIBS} -lm
CFLAGS=-I. ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CEXTRAFLAGS}
LDFLAGS=${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
AR=ar

CFILES=\
 corr_close.c\
 corr_eof.c\
 fatal.c\
 fatal_cf.c\
 fatal_pe.c\
 fatal_wa.c\
 in_close.c\
 in_eof.c\
 init.c\
 normalize_file.c\
 ok.c\
 read_buf.c\
 read_corr_int.c\
 read_double.c\
 read_file_by_line.c\
 read_file.c\
 read_in_double.c\
 read_in_int.c\
 read_team_double.c\
 read_team_int.c\
 read_team_long_double.c\
 team_close.c\
 team_eof.c\
 vars.c\
 xcalloc.c\
 xmalloc.c\
 xrealloc.c\
 xstrdup.c

OFILES=$(CFILES:.c=.o) testinfo.o

all : libchecker.a
clean :
	-rm -f *.o *.a *~ *.bak

libchecker.a : ${OFILES}
	${AR} rcv $@ $^

corr_close.o: corr_close.c checker_internal.h
corr_eof.o: corr_eof.c checker_internal.h
fatal.o: fatal.c checker_internal.h
fatal_cf.o: fatal_cf.c checker_internal.h
fatal_pe.o: fatal_pe.c checker_internal.h
fatal_wa.o: fatal_wa.c checker_internal.h
in_close.o: in_close.c checker_internal.h
in_eof.o: in_eof.c checker_internal.h
init.o: init.c checker_internal.h
normalize_file.o: normalize_file.c checker_internal.h
ok.o: ok.c checker_internal.h
read_buf.o: read_buf.c checker_internal.h
read_corr_int.o: read_corr_int.c checker_internal.h
read_double.o: read_double.c checker_internal.h
read_file_by_line.o: read_file_by_line.c checker_internal.h
read_file.o: read_file.c checker_internal.h
read_in_double.o: read_in_double.c checker_internal.h
read_in_int.o: read_in_int.c checker_internal.h
read_team_double.o: read_team_double.c checker_internal.h
read_team_int.o: read_team_int.c checker_internal.h
read_team_long_double.o: read_team_long_double.c checker_internal.h
team_close.o: team_close.c checker_internal.h
team_eof.o: team_eof.c checker_internal.h
vars.o: vars.c checker_internal.h
xcalloc.o: xcalloc.c checker_internal.h
xmalloc.o: xmalloc.c checker_internal.h
xrealloc.o: xrealloc.c checker_internal.h
xstrdup.o: xstrdup.c checker_internal.h

testinfo.o: ../testinfo.c testinfo.h
	${CC} ${CFLAGS} -c -o $@ $<
