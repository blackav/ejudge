# -*- Makefile -*-
# $Id$

# Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

ifdef RELEASE
CDEBUGFLAGS=-O2 -Wall -DNDEBUG -DRELEASE ${WERROR}
else
CDEBUGFLAGS=-g -Wall ${WERROR}
endif
CEXTRAFLAGS=
LDEXTRAFLAGS=
EXTRALIBS=
CCOMPFLAGS=-D_GNU_SOURCE -std=gnu99 -I../.. -I../../reuse/include -g -DPIC -fPIC
LDCOMPFLAGS= -g -shared
EXESFX=

LDLIBS=${EXTRALIBS} -lz $(LIBINTL) $(LIBICONV) $(LIBLIBICONV) -lm
CFLAGS=${CDEBUGFLAGS} ${CCOMPFLAGS} ${CEXTRAFLAGS} ${WPTRSIGN}
LDFLAGS=${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
EXPAT_LIB=-lexpat

TARGETDIR = ${libexecdir}/ejudge/csp/contests
SOFILES = \
 priv_clar_page.so\
 priv_download_runs_confirmation_page.so\
 priv_edit_run_page.so\
 priv_login_page.so\
 priv_main_page.so\
 priv_view_users_page.so\
 priv_view_priv_users_page.so

CFILES = $(SOFILES:.so=.c) I_priv_view_priv_users_page.c

all : $(CFILES) $(SOFILES)

install : all
	install -d "${DESTDIR}${TARGETDIR}"
	for i in ${SOFILES}; do install -m 0755 $$i "${DESTDIR}${TARGETDIR}"; done

clean : 
	-rm -f *.o *.so

priv_view_priv_users_page.so : priv_view_priv_users_page.c I_priv_view_priv_users_page.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@

po : contests.po
contests.po : $(CFILES)
	${XGETTEXT} -d ejudge --no-location --foreign-user  -k_ -k__ -s -o $@ *.c

priv_login_page.c : priv_login_page.csp priv_includes.csp priv_header.csp priv_footer.csp
priv_main_page.c : priv_main_page.csp priv_includes.csp priv_header.csp priv_footer.csp
priv_view_users_page.c : priv_view_users_page.csp priv_includes.csp priv_header.csp priv_footer.csp
priv_view_priv_users_page.c : priv_view_priv_users_page.csp priv_includes.csp priv_header.csp priv_footer.csp
priv_download_runs_confirmation_page.c : priv_download_runs_confirmation_page.csp priv_includes.csp priv_header.csp priv_footer.csp
priv_edit_run_page.c: priv_edit_run_page.csp priv_includes.csp priv_header.csp priv_footer.csp

%.c : %.csp
	../../ej-page-gen $< > $@

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.so : %.o
	$(CC) $(LDFLAGS) $< -o $@

