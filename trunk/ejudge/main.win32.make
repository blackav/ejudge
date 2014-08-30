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

ifeq (${ARCH}, win32)
CDEBUGFLAGS=-g -Wall -Werror
CEXTRAFLAGS=
LDEXTRAFLAGS=
EXTRALIBS=
CCOMPFLAGS=-std=gnu99 -Iinclude $(WPTRSIGN)
LDCOMPFLAGS=-std=gnu99
EXESFX=.exe
else
$(error "unsupported configuration")
endif

LDLIBS=${EXTRALIBS} -lz -lm -liconv -lintl
CFLAGS=-I. ${EXPAT_INCL_OPT} ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CEXTRAFLAGS}
LDFLAGS=${EXPAT_LIB_OPT} ${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
EXPAT_LIB=-lexpat

C_CFILES=compile.c version.c
C_OBJECTS=$(C_CFILES:.c=.o) libcommon.a libplatform.a

RUN_CFILES=run.c version.c
RUN_OBJECTS=$(RUN_CFILES:.c=.o) libcommon.a libplatform.a

NWRUN_CFILES=nwrun.c version.c
NWRUN_OBJECTS=$(NWRUN_CFILES:.c=.o) libcommon.a libplatform.a

BINTARGETS = ej-compile.exe ej-nwrun.exe
CGITARGETS = 
TARGETS = ${BINTARGETS} ${CGITARGETS}

all: local_all
local_all: $(TARGETS)

release:
	rm -fr CVS db serve_clnt unix userlist_clnt win32 checkers/CVS checkers/.cvsignore checkers/Makefile checkers/ChangeLog checkers/*.c checkers/*.o checkers/testinfo.h extra/CVS extra/.cvsignore extra/Makefile extra/*.c extra/*.o scripts/CVS .build .cvsignore ChangeLog OLDNEWS TODO *.c *.h *.o *.a *.make *.po makefile *.lex *.y

subdirs_all:
	$(MAKE) -C extra DESTDIR="${DESTDIR}" all
	$(MAKE) -C checkers DESTDIR="${DESTDIR}" all
	$(MAKE) -C scripts DESTDIR="${DESTDIR}" all

extra_progs:
	$(MAKE) -C extra DESTDIR="${DESTDIR}" all
checker_lib:
	$(MAKE) -C checkers DESTDIR="${DESTDIR}" all

local_install: ${TARGETS} ejudge-config po mo
	install -d "${DESTDIR}${bindir}"
	for i in ${BINTARGETS}; do install -m 0755 $$i "${DESTDIR}${bindir}"; done
	install -m 0755 ejudge-config "${DESTDIR}${bindir}"
	install -d "${DESTDIR}${cgibindir}"
	for i in ${CGITARGETS}; do install -m 0755 $$i "${DESTDIR}${cgibindir}"; done
	cd "${DESTDIR}${cgibindir}"; rm -f judge${CGI_PROG_SUFFIX}; ln master${CGI_PROG_SUFFIX} judge${CGI_PROG_SUFFIX}
	if [ x"${ENABLE_NLS}" = x1 ]; then install -d "${DESTDIR}${datadir}/locale/ru_RU.KOI8-R/LC_MESSAGES"; fi
	if [ x"${ENABLE_NLS}" = x1 ]; then install -m 0644 locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo "${DESTDIR}${datadir}/locale/ru_RU.KOI8-R/LC_MESSAGES"; fi

install: local_install
	$(MAKE) -C extra DESTDIR="${DESTDIR}" install
	$(MAKE) -C checkers DESTDIR="${DESTDIR}" install
	$(MAKE) -C scripts DESTDIR="${DESTDIR}" install

ej-compile$(EXESFX) : $(C_OBJECTS)
	$(LD) $(LDFLAGS) $(C_OBJECTS) libcommon.a -o $@ $(LDLIBS) ${EXPAT_LIB}

ej-run${EXESFX} : $(RUN_OBJECTS)
	$(LD) $(LDFLAGS) $(RUN_OBJECTS) libcommon.a -o $@ $(LDLIBS) ${EXPAT_LIB}

ej-nwrun${EXESFX} : $(NWRUN_OBJECTS)
	$(LD) $(LDFLAGS) $(NWRUN_OBJECTS) libcommon.a -o $@ $(LDLIBS) ${EXPAT_LIB}

serve : $(SERVE_OBJECTS)
	$(LD) $(LDFLAGS) $(SERVE_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB}

serve-cmd : ${SM_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

master${CGI_PROG_SUFFIX} : $(M_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT_LIB}

team${CGI_PROG_SUFFIX}: $(T_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT_LIB}

serve-control${CGI_PROG_SUFFIX}: ${SC_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

register${CGI_PROG_SUFFIX}: ${REG_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

userlist-server: ${UL_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

super-serve: ${SS_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

clean-users: ${CU_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

collect-emails: ${CE_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

slice-userlist: ${SU_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

users${CGI_PROG_SUFFIX}: ${US_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

edit-userlist: $(ED_OBJECTS)
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB} -lmenu -lpanel -lncurses

ejudge-setup: ${ST_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB} -lmenu -lpanel -lncurses

local_clean:
	-rm -f *.exe *.o *~ *.a $(TARGETS) revinfo newrevinfo version.c $(ARCH)/*.o ejudge.po mkChangeLog serve_clnt/*.o userlist_clnt/*.o xml_utils/*.o super_clnt/*.o cdeps deps.make filter_expr.[ch] filter_scan.c master master${CGI_PROG_SUFFIX} team team${CGI_PROG_SUFFIX} register register${CGI_PROG_SUFFIX} users users${CGI_PROG_SUFFIX} ejudge-config serve-control serve-control${CGI_PROG_SUFFIX} serve-cmd
	-rm -rf locale
clean: local_clean
	$(MAKE) -C extra clean
	$(MAKE) -C checkers clean

local_distclean :
	rm -rf autom4te.cache config.log config.status Makefile config.h ejudge-config.v TAGS Makefile.in
distclean : clean local_distclean
	$(MAKE) -C extra distclean
	$(MAKE) -C checkers distclean
	$(MAKE) -C scripts distclean

pristine : distclean
	rm -f configure

version.c: newrevinfo $(HFILES) $(CFILES) $(OTHERFILES)
	./newrevinfo
	#REVINFO_NO_COMMIT=1 ./revinfo -S -C -p -d db/versions -r db/revisions $(HFILES) $(CFILES) $(OTHERFILES)
version.o: version.c

newrevinfo : newrevinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
newrevinfo.o : newrevinfo.c

revinfo: prjutils2/revinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
prjutils2/revinfo.o: prjutils2/revinfo.c

mkChangeLog: mkChangeLog.o
	${LD} ${LDFLAGS} $^ -o $@
mkChangeLog.o: mkChangeLog.c

cdeps.exe: prjutils2/cdeps.o
	${LD} ${LDFLAGS} $^ -o $@
prjutils2/cdeps.o: prjutils2/cdeps.c

log: mkChangeLog
	cvs log -l | ./mkChangeLog AUTHORS ChangeLog ChangeLog
	for i in win32 unix serve_clnt userlist_clnt checkers; do cd $$i; cvs log -l | ../mkChangeLog ../AUTHORS ChangeLog ChangeLog; cd ..; done

rev:
	./revinfo -d db/versions -r db/revisions $(HFILES) $(CFILES)

new_version: revinfo.exe force
	./revinfo -C -n -d db/versions -r db/revisions $(HFILES) $(CFILES)
force:

# localization stuff
po: ejudge.ru_RU.KOI8-R.po
ejudge.ru_RU.KOI8-R.po: $(CFILES) ejudge.po
	chmod +w $@
	${MSGMERGE} -U $@ ejudge.po

ejudge.po: $(CFILES)
	${XGETTEXT} -d ejudge --foreign-user  -k_ -s -o $@ *.c

ru_all:
	-mkdir -p locale/ru_RU.KOI8-R/LC_MESSAGES

ejudge-config : ejudge-config.v version.c
	vvv=`grep compile_version version.c | sed 's/^[^"]*["]\([^"]*\)["].*$$/\1/'` && sed "s/@BUILD_VERSION@/$$vvv/" < ejudge-config.v > ejudge-config && chmod +x ejudge-config

ifdef ENABLE_NLS
mo : locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo
else
mo :
endif

locale/ru_RU.KOI8-R/LC_MESSAGES/ejudge.mo : ejudge.ru_RU.KOI8-R.po ru_all
	${MSGFMT} -o $@ -c $<

libcommon.a : $(WIN32_COMMON_CFILES:.c=.o) filter_scan.o filter_expr.o contests_meta.o prepare_meta.o
	ar rcv $@ $^

libplatform.a : $(WIN32_PLATFORM_CFILES:.c=.o)
	ar rcv $@ $^


libserve_clnt.a: $(SERVE_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

libsuper_clnt.a : $(SUPER_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

libuserlist_clnt.a: $(USERLIST_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

deps.make: cdeps.exe ${CFILES} ${HFILES} filter_expr.c filter_expr.h filter_scan.c 
	./cdeps -I include -I . ${CFILES} filter_expr.c filter_scan.c > deps.make

tags : ${CFILES} ${HFILES} filter_expr.c filter_expr.h filter_scan.c 
	ctags -e $^

filter_expr.c filter_expr.h : filter_expr.y
	bison -l -o filter_expr.c -d -p filter_expr_ $<
	cp -p filter_expr.h ./include/ejudge/filter_expr.h

filter_scan.c : filter_scan.lex
	flex -p -s -L -8 -B -o$@ -Pfilter_expr_ $<

include deps.make
