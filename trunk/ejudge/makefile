# -*- Makefile -*-
# $Id$

# Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# === Configuration options ===

# The following is a path to CGI data directory, which is
# used by CGI scripts. The path may either be
# relative or absolute. If the path is relative (ie does not start
# with /), the start point is the directory, from which CGI scripts
# are started. The path "../cgi-data" is the default.
CGI_DATA_PATH_FLAG = -DCGI_DATA_PATH=\"../cgi-data\"

# Change this to point to the actual reuse library installation
REUSE_DIR=/home/cher/reuse

# Install destination
INST_BIN_PATH=/home/cher/working-ejudge
INST_LOCALE_PATH=/home/cher/working-ejudge/locale

ifeq ($(shell uname), Linux)
REUSE_CONF=ix86-linux
CDEBUGFLAGS=-g -Wall
CINTLFLAG=-DCONF_HAS_LIBINTL
CEXTRAFLAGS=
LDEXTRAFLAGS=
EXTRALIBS=
else
REUSE_CONF=ix86-win32-mingw
CDEBUGFLAGS=-O2 -s -Wall
CINTLFLAG=
CEXTRAFLAGS=
LDEXTRAFLAGS=
EXTRALIBS=
endif

REUSE_INCLDIR=${REUSE_DIR}/include
REUSE_CONFINCLDIR=${REUSE_INCLDIR}/${REUSE_CONF}
REUSE_LIBDIR=${REUSE_DIR}/lib/${REUSE_CONF}
REUSE_LIB=-lreuse

# === End of configuration options ===

include files.make

ifeq (${REUSE_CONF}, ix86-linux)
CCOMPFLAGS=-D_GNU_SOURCE
LDCOMPFLAGS=
EXESFX=
ARCH=unix
else
ifeq (${REUSE_CONF}, ix86-win32-mingw)
CCOMPFLAGS=-mno-cygwin
LDCOMPFLAGS=-mno-cygwin
EXESFX=.exe
ARCH=win32
else
$(error "unsupported configuration")
endif
endif

LDLIBS=${EXTRALIBS} -lreuse -lz
CFLAGS=-I. -I${REUSE_INCLDIR} -I${REUSE_CONFINCLDIR} ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CINTLFLAG} ${CGI_DATA_PATH_FLAG} ${CEXTRAFLAGS}
LDFLAGS=-L${REUSE_LIBDIR} ${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
EXPAT=-lexpat

C_CFILES=compile.c version.c
C_OBJECTS=$(C_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libcharsets.a

SERVE_CFILES=serve.c version.c
SERVE_OBJECTS=$(SERVE_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libcharsets.a

RUN_CFILES=run.c version.c
RUN_OBJECTS=$(RUN_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libcharsets.a

M_CFILES=master.c version.c 
M_OBJECTS=$(M_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libserve_clnt.a libcharsets.a

T_CFILES = team.c version.c
T_OBJECTS = $(T_CFILES:.c=.o) libcommon.a libserve_clnt.a libuserlist_clnt.a libcharsets.a

REG_CFILES = register.c version.c
REG_OBJECTS = ${REG_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libcharsets.a

UL_CFILES = userlist-server.c version.c
UL_OBJECTS = ${UL_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libcharsets.a

US_CFILES = users.c version.c
US_OBJECTS = ${US_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libcharsets.a

ED_CFILES = edit-userlist.c version.c
ED_OBJECTS = ${ED_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libcharsets.a

SS_CFILES = super-serve.c version.c
SS_OBJECTS = ${SS_CFILES:.c=.o} libcommon.a libcharsets.a

CU_CFILES = clean-users.c version.c
CU_OBJECTS = ${CU_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libcharsets.a

TARGETS=compile$(EXESFX) serve$(EXESFX) run$(EXESFX) master$(EXESFX) team$(EXESFX) register${EXESFX} userlist-server${EXESFX} users${EXESFX} edit-userlist${EXESFX} super-serve clean-users

local_all: $(TARGETS)
all: local_all subdirs_all

subdirs_all:
	$(MAKE) -C extra all
	$(MAKE) -C checkers all

extra_progs:
	$(MAKE) -C extra all
checker_lib:
	$(MAKE) -C checkers all

install: ${TARGETS} po mo
	install -d ${INST_BIN_PATH}
	for i in ${TARGETS}; do install -m 0755 $$i ${INST_BIN_PATH}; done
	cd ${INST_BIN_PATH}; rm -f judge; ln master judge
	install -d ${INST_LOCALE_PATH}/ru_RU.KOI8-R/LC_MESSAGES
	install -m 0644 locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo ${INST_LOCALE_PATH}/ru_RU.KOI8-R/LC_MESSAGES

compile$(EXESFX) : $(C_OBJECTS)
	$(LD) $(LDFLAGS) $(C_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

run${EXESFX} : $(RUN_OBJECTS)
	$(LD) $(LDFLAGS) $(RUN_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

serve : $(SERVE_OBJECTS)
	$(LD) $(LDFLAGS) $(SERVE_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

master : $(M_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT}

team: $(T_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT}

register: ${REG_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

userlist-server: ${UL_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

super-serve: ${SS_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

clean-users: ${CU_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

users: ${US_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

edit-userlist: $(ED_OBJECTS)
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT} -lmenu -lpanel -lncurses

clean:
	-rm -f *.o *~ *.a $(TARGETS) revinfo version.c $(ARCH)/*.o ejudge.po mkChangeLog serve_clnt/*.o charsets/*.o userlist_clnt/*.o cdeps deps.make filter_expr.[ch] filter_scan.c
	-rm -rf locale
	$(MAKE) -C extra clean
	$(MAKE) -C checkers clean

version.c: revinfo $(HFILES) $(CFILES) $(OTHERFILES)
	./revinfo -C -d db/versions -r db/revisions $(HFILES) $(CFILES) $(OTHERFILES)
version.o: version.c

revinfo: revinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
revinfo.o: revinfo.c

mkChangeLog: mkChangeLog.o
	${LD} ${LDFLAGS} $^ -o $@
mkChangeLog.o: mkChangeLog.c

cdeps: cdeps.o
	${LD} ${LDFLAGS} $^ -o $@
cdeps.o: cdeps.c

log: mkChangeLog
	cvs log -l | ./mkChangeLog AUTHORS ChangeLog ChangeLog
	for i in win32 unix serve_clnt userlist_clnt charsets checkers; do cd $$i; cvs log -l | ../mkChangeLog ../AUTHORS ChangeLog ChangeLog; cd ..; done

rev:
	./revinfo -d db/versions -r db/revisions $(HFILES) $(CFILES)

new_version: revinfo force
	./revinfo -C -n -d db/versions -r db/revisions $(HFILES) $(CFILES)
force:

# localization stuff
po: ejudge.ru_RU.KOI8-R.po
ejudge.ru_RU.KOI8-R.po: $(CFILES) ejudge.po
	chmod +w $@
	msgmerge -U $@ ejudge.po

ejudge.po: $(CFILES)
	xgettext -d ejudge --foreign-user  -k_ -s -o $@ *.c

ru_all:
	-mkdir -p locale/ru_RU.KOI8-R/LC_MESSAGES

mo: locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo
locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo : ejudge.ru_RU.KOI8-R.po ru_all
	msgfmt -o $@ -c $<

libcommon.a : $(COMMON_CFILES:.c=.o) filter_scan.o filter_expr.o $(ARCH)/fileutl.o
	ar rcv $@ $^

libserve_clnt.a: $(SERVE_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

libcharsets.a: charsets/nls.o charsets/nls_cp1251.o charsets/nls_cp866.o charsets/nls_iso8859-5.o charsets/nls_koi8-r.o charsets/nls_utf8.o charsets/utf8_to_enc.o charsets/utf8_to_enc_unchecked.o charsets/utf8_to_enc_heap.o charsets/utf8_to_koi8.o charsets/utf8_to_koi8_heap.o charsets/utf8_to_koi8_unchecked.o charsets/koi8_to_enc.o charsets/koi8_to_enc_unchecked.o charsets/koi8_to_enc_heap.o 
	ar rcv $@ $^

libuserlist_clnt.a: $(USERLIST_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

deps.make: cdeps ${CFILES} ${HFILES} filter_expr.c filter_expr.h filter_scan.c 
	./cdeps ${CFILES} filter_expr.c filter_scan.c > deps.make

filter_expr.c filter_expr.h : filter_expr.y
	bison -l -o filter_expr.c -d -p filter_expr_ $<

filter_scan.c : filter_scan.lex
	flex -p -s -L -8 -B -o$@ -Pfilter_expr_ $<

filter_test : filter_test.o filter_expr.o filter_scan.o filter_tree.o filter_eval.o prepare.o pathutl.o $(ARCH)/fileutl.o sformat.o runlog.o teamdb.o parsecfg.o contests.o opcaps.o userlist.o userlist_proto.o protocol.o expat_iface.o userlist_xml.o libuserlist_clnt.a libcharsets.a
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} -lexpat

include deps.make
