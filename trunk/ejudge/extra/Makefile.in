# -*- Makefile -*-
# $Id$

# Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

CC=gcc
LD=gcc
CFLAGS=${CDEBUGFLAGS} ${CCOMPFLAGS} ${CINTLFLAG} ${CEXTRAFLAGS}
LDFLAGS=${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}

TARGETS=bpcemu2 dosrun3 bppemu bccemu
ifeq ($(shell uname -r), 2.2.23-cher1) 
TARGETS += capexec libdropcaps.so
endif

all: ${TARGETS}
clean:
	-rm -f ${TARGETS} *.o

bpcemu2: bpcemu2.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
bpcemu2.o: bpcemu2.c

capexec: capexec.o
	${LD} ${LDFLAGS} $^ -o $@ -lcap ${LDLIBS}
capexec.o: capexec.c

libdropcaps.so : libdropcaps.o
	${LD} -shared ${LDFLAGS} $^ -o $@ -lcap ${LDLIBS}
libdropcaps.o : libdropcaps.c

dosrun3: dosrun3.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
dosrun3.o: dosrun3.c
