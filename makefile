# -*- Makefile -*-
# $Id$

# Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

# === Configuration options ===

# The following is a path to CGI data directory, which is
# used by CGI scripts `team' and `master'. The path may either be
# relative or absolute. If the path is relative (ie does not start
# with /), the start point is the directory, from which CGI scripts
# are started. The path "../cgi-data" is the default.

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

CGI_DATA_PATH_FLAG = -DCGI_DATA_PATH=\"../cgi-data\"
REUSE_INCLDIR=/home/cher/c-sema/include
REUSE_CONFINCLDIR=${REUSE_INCLDIR}/${REUSE_CONF}
REUSE_LIBDIR=/home/cher/c-sema/lib/${REUSE_CONF}
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

C_CFILES=compile.c version.c prepare.c pathutl.c parsecfg.c sformat.c $(ARCH)/fileutl.c   
C_OBJECTS=$(C_CFILES:.c=.o)

SERVE_CFILES=serve.c version.c html.c prepare.c runlog.c clarlog.c teamdb.c parsecfg.c pathutl.c misctext.c base64.c sformat.c $(ARCH)/fileutl.c  
SERVE_OBJECTS=$(SERVE_CFILES:.c=.o)

SUBMIT_CFILES=submit.c version.c prepare.c teamdb.c parsecfg.c pathutl.c sformat.c base64.c $(ARCH)/fileutl.c  
SUBMIT_OBJECTS=$(SUBMIT_CFILES:.c=.o)

CLAR_CFILES=clar.c version.c prepare.c teamdb.c parsecfg.c pathutl.c sformat.c $(ARCH)/fileutl.c base64.c misctext.c  
CLAR_OBJECTS=$(CLAR_CFILES:.c=.o)

RUN_CFILES=run.c version.c prepare.c parsecfg.c pathutl.c sformat.c $(ARCH)/fileutl.c  
RUN_OBJECTS=$(RUN_CFILES:.c=.o)

M_CFILES=master.c version.c parsecfg.c clntutil.c cgi.c pathutl.c misctext.c base64.c $(ARCH)/fileutl.c  
M_OBJECTS=$(M_CFILES:.c=.o)

P_CFILES=mkpasswd.c version.c teamdb.c base64.c pathutl.c  
P_OBJECTS=$(P_CFILES:.c=.o)

T_CFILES = team.c version.c cgi.c teamdb.c base64.c clntutil.c parsecfg.c misctext.c pathutl.c $(ARCH)/fileutl.c  
T_OBJECTS = $(T_CFILES:.c=.o)

REG_CFILES = register.c version.c cgi.c base64.c clntutil.c parsecfg.c misctext.c pathutl.c ${ARCH}/fileutl.c
REG_OBJECTS = ${REG_CFILES:.c=.o}

MT_CFILES = make-teamdb.c localdb.c idmap.c
MT_OBJECTS = ${MT_CFILES:.c=.o}

MTI_CFILES = make-teamdb-inet.c inetdb.c
MTI_OBJECTS = ${MTI_CFILES:.c=.o}

SP_CFILES = send-passwords.c inetdb.c teamdb.c pathutl.c base64.c ${ARCH}/fileutl.c
SP_OBJECTS = ${SP_CFILES:.c=.o}

UL_CFILES = userlist-server.c userlist_cfg.c utf8_utils.c nls.c nls_cp1251.c nls_koi8-r.c nls_utf8.c nls_iso8859-5.c nls_cp866.c pathutl.c userlist_xml.c userlist.c userlist_clnt.c expat_iface.c
UL_OBJECTS = ${UL_CFILES:.c=.o}

TARGETS=compile$(EXESFX) serve$(EXESFX) submit$(EXESFX) run$(EXESFX) master$(EXESFX) clar$(EXESFX) mkpasswd$(EXESFX) team$(EXESFX) register${EXESFX} make-teamdb${EXESFX} make-teamdb-inet${EXESFX} send-passwords${EXESFX} userlist-server${EXESFX}

all: $(TARGETS)

compile$(EXESFX) : $(C_OBJECTS)
	$(LD) $(LDFLAGS) $(C_OBJECTS) -o $@ $(LDLIBS)

run${EXESFX} : $(RUN_OBJECTS)
	$(LD) $(LDFLAGS) $(RUN_OBJECTS) -o $@ $(LDLIBS)

serve.exe:
serve : $(SERVE_OBJECTS)
	$(LD) $(LDFLAGS) $(SERVE_OBJECTS) -o $@ $(LDLIBS)

submit.exe:
submit$ : $(SUBMIT_OBJECTS)
	$(LD) $(LDFLAGS) $(SUBMIT_OBJECTS) -o $@ $(LDLIBS)

clar.exe:
clar : $(CLAR_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS)

master.exe:
master : $(M_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS)

mkpasswd.exe:
mkpasswd : $(P_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS)

team.exe:
team: $(T_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS)

register.exe:
register: ${REG_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}

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

clean:
	-rm -f *.o *~ $(TARGETS) revinfo version.c $(ARCH)/*.o ejudge.po mkChangeLog

deps:
	$(CC) $(CFLAGS) -MM $(CFILES)

# experimental
version.c: revinfo $(HFILES) $(CFILES)
	./revinfo -C -d db/versions -r db/revisions $(HFILES) $(CFILES)
version.o: version.c

revinfo: revinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
revinfo.o: revinfo.c

mkChangeLog: mkChangeLog.o
	${LD} ${LDFLAGS} $^ -o $@
mkChangeLog.o: mkChangeLog.c

log: mkChangeLog
	cvs log -l | ./mkChangeLog AUTHORS ChangeLog ChangeLog
	for i in win32 unix; do cd $$i; cvs log -l | ../mkChangeLog ../AUTHORS ChangeLog ChangeLog; cd ..; done

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

# automatically generated dependencies
base64.o: base64.c base64.h pathutl.h
cgi.o: cgi.c cgi.h
clar.o: clar.c clarlog.h prepare.h pathutl.h parsecfg.h teamdb.h \
 misctext.h fileutl.h base64.h
clarlog.o: clarlog.c clarlog.h teamdb.h unix/unix_fileutl.h pathutl.h
clntutil.o: clntutil.c clntutil.h pathutl.h \
 fileutl.h unix/unix_fileutl.h misctext.h
compile.o: compile.c prepare.h pathutl.h parsecfg.h fileutl.h
html.o: html.c html.h misctext.h pathutl.h fileutl.h runlog.h \
 clarlog.h teamdb.h prepare.h parsecfg.h base64.h
master.o: master.c cgi.h fileutl.h pathutl.h \
 clarlog.h base64.h parsecfg.h clntutil.h
misctext.o: misctext.c misctext.h base64.h
mkpasswd.o: mkpasswd.c teamdb.h
parsecfg.o: parsecfg.c parsecfg.h pathutl.h
pathutl.o: pathutl.c pathutl.h
prepare.o: prepare.c prepare.h pathutl.h parsecfg.h fileutl.h \
 sformat.h teamdb.h
run.o: run.c prepare.h pathutl.h parsecfg.h runlog.h fileutl.h
runlog.o: runlog.c runlog.h pathutl.h unix/unix_fileutl.h
serve.o: serve.c runlog.h parsecfg.h teamdb.h prepare.h pathutl.h \
 html.h clarlog.h misctext.h base64.h fileutl.h
submit.o: submit.c pathutl.h prepare.h parsecfg.h teamdb.h fileutl.h
team.o: team.c cgi.h teamdb.h parsecfg.h pathutl.h \
 fileutl.h clntutil.h clarlog.h base64.h
teamdb.o: teamdb.c teamdb.h pathutl.h base64.h
idmap.o: idmap.c idmap.h
localdb.o: localdb.c localdb.h
inetdb.o: inetdb.c inetdb.h
register.o: register.c cgi.h fileutl.h pathutl.h \
 base64.h parsecfg.h clntutil.h
send-passwords.o: send-passwords.c inetdb.h teamdb.h fileutl.h
make-teamdb.o: make-teamdb.c idmap.h localdb.h
make-teamdb-inet.o: make-teamdb-inet.c inetdb.h
sformat.o: sformat.c prepare.h pathutl.h parsecfg.h teamdb.h

unix/fileutl.o: unix/fileutl.c fileutl.h unix/unix_fileutl.h pathutl.h
win32/fileutl.o: win32/fileutl.c fileutl.h pathutl.h
