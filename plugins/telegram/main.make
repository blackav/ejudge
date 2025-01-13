# -*- Makefile -*-

# Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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

CC = gcc
LD = gcc

CFLAGS = -I../../include $(MYSQL_INCL_OPT) $(MONGOC_CFLAGS) $(CDEBUGFLAGS) $(CCOMPFLAGS) $(CEXTRAFLAGS) $(WPTRSIGN)
LDFLAGS = $(MYSQL_LIB_OPT) $(EXPAT_LIB_OPT) $(CDEBUGFLAGS) $(LDCOMPFLAGS) $(LDEXTRAFLAGS)
LDLIBS = $(EXTRALIBS) $(MYSQL_LIBS) $(MONGOC_LIBS) -lcurl -lexpat -lm

CFILES = telegram.c telegram_data.c telegram_pbs.c telegram_token.c mongo_conn.c telegram_chat.c telegram_user.c telegram_chat_state.c telegram_subscription.c mysql_conn.c

PLUGINS = sn_telegram.so

all : $(PLUGINS)

install : $(PLUGINS)
	install -d "${DESTDIR}${PLUGINDIR}"
	install -m 0755 $(PLUGINS) "${DESTDIR}${PLUGINDIR}"

clean :
	-rm -f *.so *.o deps.make

distclean : clean
	-rm -f Makefile

deps.make : $(CFILES) $(HFILES)
	../../cdeps -v TELEGRAM_OFILES -I ../../include -g -c '$$(CC) $$(CFLAGS) -DPIC -fPIC' $(CFILES) > deps.make

include deps.make

sn_telegram.so : $(TELEGRAM_OFILES)
	$(LD) -shared $(LDFLAGS) $^ -o $@ $(LDLIBS)
