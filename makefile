# -*- Makefile -*-
# $Id$

# Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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

CFILES=base64.c cgi.c clar.c clarlog.c clntutil.c compile.c html.c\
  master.c misctext.c mkpasswd.c parsecfg.c pathutl.c prepare.c\
  run.c runlog.c serve.c submit.c team.c teamdb.c xalloc.c\
  register.c\
  unix/exec.c unix/fileutl.c unix/logger.c unix/osdeps.c\
  win32/exec.c win32/fileutl.c win32/logger.c win32/osdeps.c

HFILES=base64.h cgi.h clarlog.h clntutil.h exec.h fileutl.h html.h logger.h\
  misctext.h osdeps.h parsecfg.h pathutl.h prepare.h runlog.h\
  teamdb.h xalloc.h version.h\
  unix/unix_fileutl.h

ifeq ($(shell uname),Linux)
CFLAGS=-Wall -I. -DCONF_HAS_SNPRINTF -DCONF_HAS_STRERROR -g -D_GNU_SOURCE -DCONF_HAS_LIBINTL 
LDFLAGS=-g
LDLIBS=
ARCH=unix
EXESFX=
else
CFLAGS=-mno-cygwin -O3 -Wall -I. -DCONF_HAS__SNPRINTF
LDFLAGS=-mno-cygwin
ARCH=win32
EXESFX=.exe
LDLIBS=
endif

CC=gcc
LD=gcc

C_CFILES=compile.c version.c prepare.c pathutl.c parsecfg.c xalloc.c $(ARCH)/fileutl.c $(ARCH)/osdeps.c $(ARCH)/exec.c $(ARCH)/logger.c 
C_OBJECTS=$(C_CFILES:.c=.o)

SERVE_CFILES=serve.c version.c html.c prepare.c runlog.c clarlog.c teamdb.c parsecfg.c pathutl.c misctext.c base64.c $(ARCH)/fileutl.c xalloc.c $(ARCH)/logger.c $(ARCH)/osdeps.c
SERVE_OBJECTS=$(SERVE_CFILES:.c=.o)

SUBMIT_CFILES=submit.c version.c prepare.c teamdb.c parsecfg.c pathutl.c base64.c $(ARCH)/fileutl.c xalloc.c $(ARCH)/logger.c $(ARCH)/osdeps.c
SUBMIT_OBJECTS=$(SUBMIT_CFILES:.c=.o)

CLAR_CFILES=clar.c version.c prepare.c teamdb.c parsecfg.c pathutl.c $(ARCH)/fileutl.c xalloc.c base64.c misctext.c $(ARCH)/logger.c $(ARCH)/osdeps.c
CLAR_OBJECTS=$(CLAR_CFILES:.c=.o)

RUN_CFILES=run.c version.c prepare.c parsecfg.c pathutl.c $(ARCH)/fileutl.c xalloc.c $(ARCH)/logger.c $(ARCH)/osdeps.c $(ARCH)/exec.c
RUN_OBJECTS=$(RUN_CFILES:.c=.o)

M_CFILES=master.c version.c parsecfg.c clntutil.c cgi.c pathutl.c misctext.c xalloc.c base64.c $(ARCH)/fileutl.c $(ARCH)/osdeps.c $(ARCH)/logger.c 
M_OBJECTS=$(M_CFILES:.c=.o)

P_CFILES=mkpasswd.c version.c teamdb.c base64.c pathutl.c xalloc.c $(ARCH)/logger.c $(ARCH)/osdeps.c
P_OBJECTS=$(P_CFILES:.c=.o)

T_CFILES = team.c version.c cgi.c teamdb.c base64.c clntutil.c parsecfg.c misctext.c pathutl.c xalloc.c $(ARCH)/fileutl.c $(ARCH)/logger.c $(ARCH)/osdeps.c
T_OBJECTS = $(T_CFILES:.c=.o)

REG_CFILES = register.c
REG_OBJECTS = ${REG_CFILES:.c=.o}

TARGETS=compile$(EXESFX) serve$(EXESFX) submit$(EXESFX) run$(EXESFX) master$(EXESFX) clar$(EXESFX) mkpasswd$(EXESFX) team$(EXESFX) register${EXESFX}

all: $(TARGETS)

compile$(EXESFX) : $(C_OBJECTS)
	$(LD) $(LDFLAGS) $(C_OBJECTS) -o $@ $(LDLIBS)

serve.exe:
serve : $(SERVE_OBJECTS)
	$(LD) $(LDFLAGS) $(SERVE_OBJECTS) -o $@ $(LDLIBS)

submit.exe:
submit$ : $(SUBMIT_OBJECTS)
	$(LD) $(LDFLAGS) $(SUBMIT_OBJECTS) -o $@ $(LDLIBS)

clar.exe:
clar : $(CLAR_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS)

run$(EXESFX) : $(RUN_OBJECTS)
	$(LD) $(LDFLAGS) $(RUN_OBJECTS) -o $@ $(LDLIBS)

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

clean:
	-rm *.o $(TARGETS) revinfo version.c $(ARCH)/*.o

deps:
	$(CC) $(CFLAGS) -MM $(CFILES)

# experimental
version.c: revinfo $(HFILES) $(CFILES)
	./revinfo -C -d db/versions -r db/revisions $(HFILES) $(CFILES)
version.o: version.c

revinfo: revinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
revinfo.o: revinfo.c

rev:
	./revinfo -d db/versions -r db/revisions $(HFILES) $(CFILES)

new_version: revinfo force
	./revinfo -C -n -d db/versions -r db/revisions $(HFILES) $(CFILES)
force:

# localization stuff
po: ejudge.po
ejudge.po: $(CFILES)
	xgettext -d ejudge --foreign-user `[ -f ejudge.po ] && echo -j` -k_ -s *.c

# automatically generated dependencies
base64.o: base64.c base64.h pathutl.h logger.h
cgi.o: cgi.c cgi.h xalloc.h
clar.o: clar.c clarlog.h prepare.h pathutl.h parsecfg.h teamdb.h \
 misctext.h logger.h fileutl.h base64.h
clarlog.o: clarlog.c clarlog.h teamdb.h unix/unix_fileutl.h pathutl.h \
 logger.h xalloc.h osdeps.h
clntutil.o: clntutil.c clntutil.h logger.h pathutl.h xalloc.h \
 fileutl.h unix/unix_fileutl.h misctext.h
compile.o: compile.c prepare.h pathutl.h parsecfg.h xalloc.h logger.h \
 fileutl.h exec.h osdeps.h
html.o: html.c html.h misctext.h pathutl.h fileutl.h runlog.h \
 clarlog.h logger.h teamdb.h prepare.h parsecfg.h base64.h xalloc.h \
 osdeps.h
master.o: master.c cgi.h fileutl.h pathutl.h xalloc.h logger.h \
 clarlog.h base64.h osdeps.h parsecfg.h clntutil.h
misctext.o: misctext.c misctext.h base64.h logger.h
mkpasswd.o: mkpasswd.c teamdb.h
parsecfg.o: parsecfg.c parsecfg.h xalloc.h pathutl.h
pathutl.o: pathutl.c pathutl.h osdeps.h logger.h
prepare.o: prepare.c prepare.h pathutl.h parsecfg.h fileutl.h xalloc.h \
 logger.h osdeps.h
run.o: run.c prepare.h pathutl.h parsecfg.h runlog.h fileutl.h \
 osdeps.h logger.h exec.h xalloc.h
runlog.o: runlog.c runlog.h xalloc.h logger.h pathutl.h \
 unix/unix_fileutl.h
serve.o: serve.c runlog.h parsecfg.h teamdb.h prepare.h pathutl.h \
 html.h clarlog.h misctext.h base64.h fileutl.h xalloc.h logger.h \
 osdeps.h
submit.o: submit.c pathutl.h prepare.h parsecfg.h teamdb.h fileutl.h \
 logger.h
team.o: team.c cgi.h teamdb.h parsecfg.h pathutl.h osdeps.h logger.h \
 xalloc.h fileutl.h clntutil.h clarlog.h base64.h
teamdb.o: teamdb.c teamdb.h pathutl.h osdeps.h logger.h xalloc.h \
 base64.h
xalloc.o: xalloc.c xalloc.h


register.o: register.c

unix/exec.o: unix/exec.c exec.h xalloc.h logger.h osdeps.h
unix/fileutl.o: unix/fileutl.c fileutl.h unix/unix_fileutl.h logger.h \
 pathutl.h osdeps.h xalloc.h
unix/logger.o: unix/logger.c logger.h xalloc.h osdeps.h
unix/osdeps.o: unix/osdeps.c osdeps.h xalloc.h logger.h

win32/exec.o: win32/exec.c exec.h logger.h xalloc.h osdeps.h
win32/fileutl.o: win32/fileutl.c fileutl.h logger.h pathutl.h osdeps.h \
 xalloc.h
win32/logger.o: win32/logger.c logger.h osdeps.h
win32/osdeps.o: win32/osdeps.c osdeps.h logger.h xalloc.h
