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

LDLIBS=${EXTRALIBS} -lreuse
CFLAGS=-I. -I${REUSE_INCLDIR} -I${REUSE_CONFINCLDIR} ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CINTLFLAG} ${CGI_DATA_PATH_FLAG} ${CEXTRAFLAGS}
LDFLAGS=-L${REUSE_LIBDIR} ${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
EXPAT=-lexpat

C_CFILES=compile.c version.c prepare.c pathutl.c parsecfg.c sformat.c contests.c opcaps.c expat_iface.c userlist_proto.c cr_serialize.c $(ARCH)/fileutl.c
C_OBJECTS=$(C_CFILES:.c=.o) libuserlist_clnt.a libcharsets.a

SERVE_CFILES=serve.c version.c html.c master_html.c prepare.c runlog.c clarlog.c teamdb.c parsecfg.c pathutl.c misctext.c base64.c sformat.c contests.c opcaps.c expat_iface.c userlist_proto.c protocol.c userlist_xml.c sha.c filter_tree.c filter_expr.c filter_scan.c filter_eval.c $(ARCH)/fileutl.c  
SERVE_OBJECTS=$(SERVE_CFILES:.c=.o) libuserlist_clnt.a libcharsets.a

SUBMIT_CFILES=submit.c version.c prepare.c teamdb.c parsecfg.c pathutl.c sformat.c base64.c contests.c expat_iface.c userlist_proto.c $(ARCH)/fileutl.c  
SUBMIT_OBJECTS=$(SUBMIT_CFILES:.c=.o)

CLAR_CFILES=clar.c version.c prepare.c teamdb.c parsecfg.c pathutl.c sformat.c $(ARCH)/fileutl.c base64.c misctext.c contests.c expat_iface.c userlist_proto.c
CLAR_OBJECTS=$(CLAR_CFILES:.c=.o)

RUN_CFILES=run.c version.c prepare.c parsecfg.c pathutl.c sformat.c contests.c opcaps.c expat_iface.c userlist_proto.c cr_serialize.c $(ARCH)/fileutl.c
RUN_OBJECTS=$(RUN_CFILES:.c=.o) libuserlist_clnt.a libcharsets.a

M_CFILES=master.c contests.c opcaps.c expat_iface.c version.c parsecfg.c clntutil.c cgi.c pathutl.c misctext.c base64.c protocol.c userlist_proto.c $(ARCH)/fileutl.c  
M_OBJECTS=$(M_CFILES:.c=.o) libuserlist_clnt.a libserve_clnt.a libcharsets.a

P_CFILES=mkpasswd.c version.c teamdb.c base64.c pathutl.c userlist_proto.c
P_OBJECTS=$(P_CFILES:.c=.o)

T_CFILES = team.c version.c cgi.c teamdb.c base64.c clntutil.c parsecfg.c misctext.c pathutl.c contests.c opcaps.c expat_iface.c userlist_proto.c protocol.c $(ARCH)/fileutl.c  
T_OBJECTS = $(T_CFILES:.c=.o) libserve_clnt.a libuserlist_clnt.a libcharsets.a

REG_CFILES = register.c contests.c opcaps.c userlist_xml.c protocol.c userlist_proto.c version.c expat_iface.c cgi.c base64.c clntutil.c pathutl.c misctext.c $(ARCH)/fileutl.c
REG_OBJECTS = ${REG_CFILES:.c=.o} libuserlist_clnt.a libcharsets.a

MT_CFILES = make-teamdb.c localdb.c idmap.c
MT_OBJECTS = ${MT_CFILES:.c=.o}

MTI_CFILES = make-teamdb-inet.c inetdb.c
MTI_OBJECTS = ${MTI_CFILES:.c=.o}

SP_CFILES = send-passwords.c inetdb.c teamdb.c pathutl.c base64.c ${ARCH}/fileutl.c userlist_proto.c
SP_OBJECTS = ${SP_CFILES:.c=.o}

UL_CFILES = userlist-server.c contests.c userlist_cfg.c pathutl.c userlist_xml.c userlist.c expat_iface.c base64.c sha.c version.c protocol.c opcaps.c
UL_OBJECTS = ${UL_CFILES:.c=.o} libuserlist_clnt.a libcharsets.a

US_CFILES = users.c userlist_proto.c contests.c opcaps.c clntutil.c misctext.c base64.c cgi.c expat_iface.o pathutl.c ${ARCH}/fileutl.c version.c
US_OBJECTS = ${US_CFILES:.c=.o} libuserlist_clnt.a libcharsets.a

ED_CFILES = edit-userlist.c userlist_proto.c contests.c opcaps.c userlist_xml.c userlist_cfg.c userlist.c expat_iface.c pathutl.c protocol.c
ED_OBJECTS = ${ED_CFILES:.c=.o} libuserlist_clnt.a libcharsets.a

SS_CFILES = super-serve.c contests.c userlist_cfg.c opcaps.c expat_iface.c pathutl.c version.c
SS_OBJECTS = ${SS_CFILES:.c=.o} libcharsets.a

CU_CFILES = clean-users.c contests.c userlist_cfg.c userlist_xml.c runlog.c clarlog.c protocol.c opcaps.c expat_iface.c pathutl.c ${ARCH}/fileutl.c version.c
CU_OBJECTS = ${CU_CFILES:.c=.o} libcharsets.a

TARGETS=compile$(EXESFX) serve$(EXESFX) run$(EXESFX) master$(EXESFX) team$(EXESFX) register${EXESFX} userlist-server${EXESFX} users${EXESFX} edit-userlist${EXESFX} filter_test super-serve clean-users

local_all: $(TARGETS)
all: local_all subdirs_all

subdirs_all:
	$(MAKE) -C extra all

install: ${TARGETS} po mo
	install -d ${INST_BIN_PATH}
	for i in ${TARGETS}; do install -m 0755 $$i ${INST_BIN_PATH}; done
	install -d ${INST_LOCALE_PATH}/ru_RU.KOI8-R/LC_MESSAGES
	install -m 0644 locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo ${INST_LOCALE_PATH}/ru_RU.KOI8-R/LC_MESSAGES

compile$(EXESFX) : $(C_OBJECTS)
	$(LD) $(LDFLAGS) $(C_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

run${EXESFX} : $(RUN_OBJECTS)
	$(LD) $(LDFLAGS) $(RUN_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

serve.exe:
serve : $(SERVE_OBJECTS)
	$(LD) $(LDFLAGS) $(SERVE_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

submit.exe:
submit : $(SUBMIT_OBJECTS)
	$(LD) $(LDFLAGS) $(SUBMIT_OBJECTS) -o $@ $(LDLIBS) ${EXPAT}

clar.exe:
clar : $(CLAR_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT}

master.exe:
master : $(M_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT}

mkpasswd.exe:
mkpasswd : $(P_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS)

team.exe:
team: $(T_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT}

register.exe:
register: ${REG_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

make-teamdb.exe:
make-teamdb: ${MT_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}

make-teamdb-inet.exe:
make-teamdb-inet: ${MTI_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}

send-passwords.exe:
send-passwords: ${SP_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}

userlist-server.exe:
userlist-server: ${UL_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

super-serve: ${SS_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

clean-users: ${CU_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

users.exe:
users: ${US_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT}

edit-userlist.exe:
edit-userlist: $(ED_OBJECTS)
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT} -lmenu -lpanel -lncurses

clean:
	-rm -f *.o *~ *.a $(TARGETS) revinfo version.c $(ARCH)/*.o ejudge.po mkChangeLog serve_clnt/*.o charsets/*.o userlist_clnt/*.o cdeps deps.make filter_expr.[ch] filter_scan.c
	-rm -rf locale
	$(MAKE) -C extra clean

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
	for i in win32 unix serve_clnt userlist_clnt charsets; do cd $$i; cvs log -l | ../mkChangeLog ../AUTHORS ChangeLog ChangeLog; cd ..; done

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
