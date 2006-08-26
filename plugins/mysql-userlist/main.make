# -*- Makefile -*-
# $Id$

# Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

ULDB_MYSQL_CFILES = uldb_mysql.c

CFILES = $(ULDB_MYSQL_CFILES)
HFILES =

CC = gcc
LD = gcc

CFLAGS = -I. -I../.. $(MYSQL_INCL_OPT) $(REUSE_INCL_OPT) $(EXPAT_INCL_OPT) $(CDEBUGFLAGS) $(CCOMPFLAGS) $(CEXTRAFLAGS) $(WPTRSIGN)
LDFLAGS = $(MYSQL_LIB_OPT) $(REUSE_LIB_OPT) $(EXPAT_LIB_OPT) $(CDEBUGFLAGS) $(LDCOMPFLAGS) $(LDEXTRAFLAGS)
LDLIBS = $(EXTRALIBS) $(MYSQL_LIBS) -lreuse -lexpat -lm

all : plugin_uldb_mysql.so

install :

clean :
	-rm -f *.so *.o deps.make

distclean : clean
	-rm -f Makefile

deps.make : $(CFILES) $(HFILES)
	../../cdeps -v ULDB_MYSQL_OFILES -I ../.. -g -c '$$(CC) $$(CFLAGS) -DPIC -fPIC' $(ULDB_MYSQL_CFILES) > deps.make

include deps.make

plugin_uldb_mysql.so : $(ULDB_MYSQL_OFILES)
	$(LD) -shared $(LDFLAGS) $^ -o $@ $(LDLIBS)

