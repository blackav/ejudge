# -*- Makefile -*-

# Copyright (C) 2024 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

PLUGINDIR = $(libexecdir)/ejudge/plugins

AUTH_OIDC_CFILES = auth_oidc.c

CFILES = $(AUTH_OIDC_CFILES)
HFILES =

CC = gcc
LD = gcc

CFLAGS = -I. -I../.. -I../../include $(MYSQL_INCL_OPT) $(EXPAT_INCL_OPT) $(CDEBUGFLAGS) $(CCOMPFLAGS) $(CEXTRAFLAGS) $(WPTRSIGN)
LDFLAGS = $(MYSQL_LIB_OPT) $(EXPAT_LIB_OPT) $(CDEBUGFLAGS) $(LDCOMPFLAGS) $(LDEXTRAFLAGS)
LDLIBS = $(EXTRALIBS) $(MYSQL_LIBS) -lcurl -lexpat -lm

PLUGINS = auth_oidc.so

all : $(PLUGINS)

install : $(PLUGINS)
	install -d "${DESTDIR}${PLUGINDIR}"
	install -m 0755 $(PLUGINS) "${DESTDIR}${PLUGINDIR}"

clean :
	-rm -f *.so *.o deps.make

distclean : clean
	-rm -f Makefile

deps.make : $(CFILES) $(HFILES)
	../../cdeps -v AUTH_OIDC_OFILES -I ../.. -I ../../include -g -c '$$(CC) $$(CFLAGS) -DPIC -fPIC' $(AUTH_OIDC_CFILES) > deps.make

include deps.make

auth_oidc.so : $(AUTH_OIDC_OFILES)
	$(LD) -shared $(LDFLAGS) $^ -o $@ $(LDLIBS)
