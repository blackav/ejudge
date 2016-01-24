# -*- Makefile -*-

# Copyright (C) 2014-2016 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

include files.make

ifeq (${ARCH}, unix)
ifdef RELEASE
CDEBUGFLAGS=-O2 -Wall -DNDEBUG -DRELEASE ${WERROR}
else
CDEBUGFLAGS=-g -Wall ${WERROR}
endif
ifdef STATIC
CDEBUGFLAGS += -static
endif
CEXTRAFLAGS=
LDEXTRAFLAGS=
EXTRALIBS=
CCOMPFLAGS=-D_GNU_SOURCE -std=gnu99 -Iinclude -g
LDCOMPFLAGS= -g
EXESFX=
else
$(error "unsupported configuration")
endif

LDLIBS=${EXTRALIBS} -lz $(LIBINTL) $(LIBICONV) $(LIBLIBICONV) -lm
CFLAGS=-I. ${EXPAT_INCL_OPT} ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CEXTRAFLAGS} ${WPTRSIGN}
LDFLAGS=${EXPAT_LIB_OPT} ${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
EXPAT_LIB=-lexpat

C_CFILES=compile.c version.c
C_OBJECTS=$(C_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

CC_CFILES=compile-control.c version.c
CC_OBJECTS=$(CC_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

SERVE_CFILES=serve.c version.c
SERVE_OBJECTS=$(SERVE_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

RUN_CFILES=run.c version.c
RUN_OBJECTS=$(RUN_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

NWRUN_CFILES=nwrun.c version.c
NWRUN_OBJECTS=$(NWRUN_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a libplatform.a

NCHECK_CFILES=ej-ncheck.c version.c
NCHECK_OBJECTS=$(NCHECK_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

T3M_CFILES=ej-batch.c version.c
T3M_OBJECTS=$(T3M_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

SC_CFILES = serve-control.c version.c
SC_OBJECTS = $(SC_CFILES:.c=.o) libuserlist_clnt.a libsuper_clnt.a libcommon.a libplatform.a libcommon.a

UL_CFILES = userlist-server.c version.c
UL_OBJECTS = ${UL_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a libplatform.a

ULC_CFILES = userlist-server-control.c version.c
ULC_OBJECTS = ${ULC_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

JS_CFILES = job-server.c version.c
JS_OBJECTS = ${JS_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

JSC_CFILES = job-server-control.c version.c
JSC_OBJECTS = ${JSC_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

JP_CFILES = job-server-cmd.c version.c
JP_OBJECTS = ${JP_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

US_CFILES = users.c version.c
US_OBJECTS = ${US_CFILES:.c=.o} libuserlist_clnt.a libcommon.a libplatform.a libcommon.a

ED_CFILES = edit-userlist.c version.c
ED_OBJECTS = ${ED_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

SS_CFILES = super-serve.c version.c
SS_OBJECTS = ${SS_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

SR_CFILES = ej-super-run.c version.c
SR_OBJECTS = ${SR_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

SSC_CFILES = super-serve-control.c version.c
SSC_OBJECTS = ${SSC_CFILES:.c=.o} libcommon.a libsuper_clnt.a libplatform.a libcommon.a

SRC_CFILES = ej-super-run-control.c version.c
SRC_OBJECTS = ${SRC_CFILES:.c=.o} libcommon.a libsuper_clnt.a libplatform.a libcommon.a

CU_CFILES = convert-clars.c version.c
CU_OBJECTS = ${CU_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

CR_CFILES = convert-runs.c version.c
CR_OBJECTS = ${CR_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

FIX_DB_CFILES = fix-db.c version.c
FIX_DB_OBJECTS = ${FIX_DB_CFILES:.c=.o} libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

SU_CFILES = slice-userlist.c version.c
SU_OBJECTS = ${SU_CFILES:.c=.o} libcommon.a libuserlist_clnt.a

CE_CFILES = collect-emails.c version.c
CE_OBJECTS = ${CE_CFILES:.c=.o} libcommon.a libuserlist_clnt.a

ST_CFILES = ejudge-setup.c version.c
ST_OBJECTS = ${ST_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

ECC_CFILES = ejudge-configure-compilers.c version.c
ECC_OBJECTS = ${ECC_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

EC_CFILES = ejudge-control.c version.c
EC_OBJECTS = ${EC_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

EX_CFILES = execute.c version.c
EX_OBJECTS = ${EX_CFILES:.c=.o} libcommon.a libplatform.a libcommon.a

NC_CFILES=new-client.c version.c
NC_OBJECTS=$(NC_CFILES:.c=.o) libnew_server_clnt.a libcommon.a libplatform.a libcommon.a

NS_CFILES=new-server.c version.c
NS_OBJECTS=$(NS_CFILES:.c=.o) libcommon.a libuserlist_clnt.a libplatform.a libcommon.a

NSM_CFILES = new-server-cmd.c version.c
NSM_OBJECTS = $(NSM_CFILES:.c=.o) libcommon.a libnew_server_clnt.a libuserlist_clnt.a libplatform.a libcommon.a

NSC_CFILES=new-server-control.c version.c
NSC_OBJECTS=$(NSC_CFILES:.c=.o) libcommon.a libnew_server_clnt.a libplatform.a libcommon.a

NRM_CFILES=ej-normalize.c version.c
NRM_OBJECTS=$(NRM_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

P_CFILES = ej-polygon.c version.c
P_OBJECTS = $(P_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

IC_CFILES = ej-import-contest.c version.c
IC_OBJECTS = $(IC_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

G_CFILES = ej-page-gen.c 
G_OBJECTS = $(G_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

PB_CFILES = ej-parblock.c
PB_OBJECTS = $(PB_CFILES:.c=.o) libcommon.a libplatform.a libcommon.a

INSTALLSCRIPT = ejudge-install.sh
BINTARGETS = ejudge-jobs-cmd ejudge-edit-users ejudge-setup ejudge-configure-compilers ejudge-control ejudge-execute ejudge-contests-cmd
SERVERBINTARGETS = ej-compile ej-compile-control ej-run ej-nwrun ej-ncheck ej-batch ej-serve ej-users ej-users-control ej-jobs ej-jobs-control ej-super-server ej-super-server-control ej-contests ej-contests-control uudecode ej-convert-clars ej-convert-runs ej-fix-db ej-super-run ej-super-run-control ej-normalize ej-polygon ej-import-contest ej-page-gen ej-parblock
CGITARGETS = users${CGI_PROG_SUFFIX} serve-control${CGI_PROG_SUFFIX} new-client${CGI_PROG_SUFFIX}
TARGETS = ${SERVERBINTARGETS} ${BINTARGETS} ${CGITARGETS} newrevinfo
STYLEFILES = style/logo.gif style/priv.css style/unpriv.css style/unpriv3.css style/ejudge3.css style/priv.js style/priv_prob_dlg.js style/unpriv.js style/filter_expr.html style/sprintf.js style/ejudge3_ss.css style/ejudge_mobile.css style/jquery.min.js style/jquery.timepicker.css style/jquery.timepicker.min.js style/prism.js style/prism.css

all: prereq_all local_all subdirs_all mo
local_all: $(TARGETS) ejudge-config

release:
	rm -fr CVS db unix userlist_clnt win32 checkers/CVS checkers/.cvsignore checkers/Makefile checkers/ChangeLog checkers/*.c checkers/*.o checkers/testinfo.h extra/CVS extra/.cvsignore extra/Makefile extra/*.c extra/*.o scripts/CVS .build .cvsignore ChangeLog OLDNEWS TODO *.c *.h *.o *.a *.make *.po makefile *.lex *.y

prereq_all: version.o
	$(MAKE) -C libdwarf DESTDIR="${DESTDIR}" all
	$(MAKE) -C reuse DESTDIR="${DESTDIR}" all
	$(MAKE) -C cfront DESTDIR="${DESTDIR}" all

subdirs_all:
	$(MAKE) -C extra DESTDIR="${DESTDIR}" all
	$(MAKE) -C checkers DESTDIR="${DESTDIR}" all
	$(MAKE) -C scripts DESTDIR="${DESTDIR}" all
	$(MAKE) -C plugins/mysql-common DESTDIR="${DESTDIR}" all
	$(MAKE) -C plugins/mysql-userlist DESTDIR="${DESTDIR}" all
	$(MAKE) -C plugins/mysql-clardb DESTDIR="${DESTDIR}" all
	$(MAKE) -C plugins/mysql-rundb DESTDIR="${DESTDIR}" all
	$(MAKE) -C plugins/mongo-common DESTDIR="${DESTDIR}" all
	$(MAKE) -C plugins/mongo-xuser DESTDIR="${DESTDIR}" all
	$(MAKE) -C csp/contests DESTDIR="${DESTDIR}" all
	$(MAKE) -C csp/super-server DESTDIR="${DESTDIR}" all

extra_progs:
	$(MAKE) -C extra DESTDIR="${DESTDIR}" all
checker_lib:
	$(MAKE) -C checkers DESTDIR="${DESTDIR}" all

install_ej_users: ej-users
	install -m 0755 ej-users "${DESTDIR}${serverbindir}"
install_ej_contests: ej-contests
	install -m 0755 ej-contests "${DESTDIR}${serverbindir}"
install_ej_super_server: ej-super-server
	install -m 0755 ej-super-server "${DESTDIR}${serverbindir}"
install_ej_super_run: ej-super-run
	install -m 0755 ej-super-run "${DESTDIR}${serverbindir}"

local_install: ${TARGETS} ejudge-config po mo
	install -d "${DESTDIR}${bindir}"
	for i in ${BINTARGETS}; do install -m 0755 $$i "${DESTDIR}${bindir}"; done
	install -d "${DESTDIR}${serverbindir}"
	for i in ${SERVERBINTARGETS}; do install -m 0755 $$i "${DESTDIR}${serverbindir}"; done
	install -m 0755 ejudge-config "${DESTDIR}${bindir}"
	install -d "${DESTDIR}${cgibindir}"
	for i in ${CGITARGETS}; do install -m 0755 $$i "${DESTDIR}${cgibindir}"; done
	cd "${DESTDIR}${cgibindir}"; rm -f new-master${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} new-master${CGI_PROG_SUFFIX}
	cd "${DESTDIR}${cgibindir}"; rm -f new-judge${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} new-judge${CGI_PROG_SUFFIX}
	cd "${DESTDIR}${cgibindir}"; rm -f new-register${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} new-register${CGI_PROG_SUFFIX}
	cd "${DESTDIR}${cgibindir}"; rm -f register${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} register${CGI_PROG_SUFFIX}
	cd "${DESTDIR}${cgibindir}"; rm -f team${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} team${CGI_PROG_SUFFIX}
	cd "${DESTDIR}${cgibindir}"; rm -f judge${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} judge${CGI_PROG_SUFFIX}
	cd "${DESTDIR}${cgibindir}"; rm -f master${CGI_PROG_SUFFIX}; ln new-client${CGI_PROG_SUFFIX} master${CGI_PROG_SUFFIX}
	if [ x"${ENABLE_NLS}" = x1 ]; then for locale in "ru_RU.${CHARSET}" "uk_UA.${CHARSET}" "kk_KZ.${CHARSET}"; do install -d "${DESTDIR}${datadir}/locale/$${locale}/LC_MESSAGES"; install -m 0644 "locale/$${locale}/LC_MESSAGES/ejudge.mo" "${DESTDIR}${datadir}/locale/$${locale}/LC_MESSAGES"; done; fi
	install -d "${DESTDIR}${datadir}/ejudge"
	install -d "${DESTDIR}${datadir}/ejudge/style"
	for i in ${STYLEFILES}; do install -m 0644 $$i "${DESTDIR}${datadir}/ejudge/style"; done
	for i in style/*.jpg; do install -m 0644 $$i "${DESTDIR}${datadir}/ejudge/style"; done
	for i in style/*.png; do install -m 0644 $$i "${DESTDIR}${datadir}/ejudge/style"; done
	tar x -C "${DESTDIR}${datadir}/ejudge/style" -f style/jquery-ui.tbz
	tar x -C "${DESTDIR}${datadir}/ejudge/style" -f style/jqgrid.tbz
	install -d "${DESTDIR}${datadir}/ejudge/style/icons"
	for i in style/icons/*.png; do install -m 0644 $$i "${DESTDIR}${datadir}/ejudge/style/icons"; done
	install -m 0755 style/ejudge-upgrade-web "${DESTDIR}${bindir}"
	cp -rpd include "${DESTDIR}${prefix}"
	install -d "${DESTDIR}${prefix}/lib/ejudge/make"
	install -m 0644 csp_header.make "${DESTDIR}${prefix}/lib/ejudge/make"

install: local_install
	$(MAKE) -C libdwarf DESTDIR="${DESTDIR}" install
	$(MAKE) -C reuse DESTDIR="${DESTDIR}" install
	$(MAKE) -C cfront DESTDIR="${DESTDIR}" install
	$(MAKE) -C scripts DESTDIR="${DESTDIR}" install
	$(MAKE) -C checkers DESTDIR="${DESTDIR}" install
	$(MAKE) -C extra DESTDIR="${DESTDIR}" install
	$(MAKE) -C plugins/mysql-common DESTDIR="${DESTDIR}" install
	$(MAKE) -C plugins/mysql-userlist DESTDIR="${DESTDIR}" install
	$(MAKE) -C plugins/mysql-clardb DESTDIR="${DESTDIR}" install
	$(MAKE) -C plugins/mysql-rundb DESTDIR="${DESTDIR}" install
	$(MAKE) -C plugins/mongo-common DESTDIR="${DESTDIR}" install
	$(MAKE) -C plugins/mongo-xuser DESTDIR="${DESTDIR}" install
	$(MAKE) -C csp/contests DESTDIR="${DESTDIR}" install
	$(MAKE) -C csp/super-server DESTDIR="${DESTDIR}" install
	#if [ ! -f "${INSTALLSCRIPT}" ]; then ./ejudge-setup -b; fi
	if [ -f "${INSTALLSCRIPT}" ]; then install -m 0755 "${INSTALLSCRIPT}" "${DESTDIR}${bindir}"; fi

ej-compile$(EXESFX) : $(C_OBJECTS)
	$(LD) $(LDFLAGS) $(C_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB} ${LIBZIP} ${LIBUUID}

ej-compile-control : $(CC_OBJECTS)
	$(LD) $(LDFLAGS) $(CC_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB}

ej-run${EXESFX} : $(RUN_OBJECTS)
	$(LD) $(LDFLAGS) $(RUN_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB} ${LIBZIP} ${LIBUUID}

ej-nwrun${EXESFX} : $(NWRUN_OBJECTS)
	$(LD) $(LDFLAGS) $(NWRUN_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB} ${LIBZIP}

ej-ncheck${EXESFX} : $(NCHECK_OBJECTS)
	$(LD) $(LDFLAGS) $(NCHECK_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB}

ej-batch : $(T3M_OBJECTS)
	$(LD) $(LDFLAGS) $(T3M_OBJECTS) -o $@ $(LDLIBS) -ldl ${EXPAT_LIB} ${LIBZIP} ${LIBUUID}

ej-serve : $(SERVE_OBJECTS)
	$(LD) $(LDFLAGS) $(SERVE_OBJECTS) -o $@ $(LDLIBS) -ldl ${EXPAT_LIB} ${LIBUUID}

serve-control${CGI_PROG_SUFFIX}: ${SC_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

ej-users: ${UL_OBJECTS}
	${LD} ${LDFLAGS} $^  libcommon.a libplatform.a -rdynamic -o $@ ${LDLIBS} -ldl ${EXPAT_LIB}

ej-users-control: ${ULC_OBJECTS}
	${LD} ${LDFLAGS} $^  libcommon.a -rdynamic -o $@ ${LDLIBS} ${EXPAT_LIB}

ej-jobs: ${JS_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a libplatform.a -o $@ ${LDLIBS} ${EXPAT_LIB}

ej-jobs-control: ${JSC_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a libplatform.a -o $@ ${LDLIBS} ${EXPAT_LIB}

ejudge-jobs-cmd: ${JP_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a libplatform.a -o $@ ${LDLIBS} ${EXPAT_LIB}

ej-super-server: ${SS_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl ${LIBUUID}

ej-super-server-control: ${SSC_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB}

ej-super-run: ${SR_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl ${LIBZIP} ${LIBUUID}

ej-super-run-control: ${SRC_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl

ej-normalize: ${NRM_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl

ej-polygon: ${P_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} ${LIBCURL} ${LIBZIP} -ldl

ej-import-contest: ${IC_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} ${LIBCURL} ${LIBZIP} -ldl

ej-page-gen: ${G_OBJECTS} libuserlist_clnt.a libnew_server_clnt.a
	${LD} ${LDFLAGS} -Wl,--whole-archive $^ -o $@ ${LDLIBS} libdwarf/libdwarf/libdwarf.a -lelf ${EXPAT_LIB} ${LIBZIP} -ldl -lpanel${NCURSES_SUFFIX} -lmenu${NCURSES_SUFFIX} -lncurses${NCURSES_SUFFIX} ${LIBUUID} -Wl,--no-whole-archive $(MONGO_LIBS)
ej-page-gen.debug : ej-page-gen
	objcopy --only-keep-debug $< $@

ej-convert-clars: ${CU_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic $^ libcommon.a libplatform.a -o $@ ${LDLIBS} ${EXPAT_LIB} ${LIBUUID} -ldl

ej-convert-runs: ${CR_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl ${LIBUUID}

ej-fix-db: ${FIX_DB_OBJECTS}
	${LD} ${LDFLAGS} -rdynamic ${FIX_DB_OBJECTS} -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl ${LIBUUID}

ej-parblock: ${PB_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB} -ldl ${LIBUUID}

ej-suid-exec : ej-suid-exec.c
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@

ej-suid-chown : ej-suid-chown.c
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@

ej-suid-kill : ej-suid-kill.c
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@

ej-suid-ipcrm : ej-suid-ipcrm.c
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@

collect-emails: ${CE_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

slice-userlist: ${SU_OBJECTS}
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB}

users${CGI_PROG_SUFFIX}: ${US_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB}

ejudge-edit-users: $(ED_OBJECTS)
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS} ${EXPAT_LIB} -lmenu${NCURSES_SUFFIX} -lpanel${NCURSES_SUFFIX} -lncurses${NCURSES_SUFFIX}

ejudge-setup: ${ST_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -lmenu${NCURSES_SUFFIX} -lpanel${NCURSES_SUFFIX} -lncurses${NCURSES_SUFFIX}

ejudge-configure-compilers: ${ECC_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB} -lmenu${NCURSES_SUFFIX} -lpanel${NCURSES_SUFFIX} -lncurses${NCURSES_SUFFIX}

ejudge-control: ${EC_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a -o $@ ${LDLIBS} ${EXPAT_LIB}

ejudge-execute : ${EX_OBJECTS}
	${LD} ${LDFLAGS} $^ libcommon.a libplatform.a -o $@ ${LDLIBS} ${EXPAT_LIB}

new-client${CGI_PROG_SUFFIX} : $(NC_OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT_LIB}

ej-contests : $(NS_OBJECTS)
	$(LD) $(LDFLAGS) -rdynamic $(NS_OBJECTS) -o $@ $(LDLIBS) -ldl ${EXPAT_LIB} ${LIBZIP} ${LIBUUID} $(MONGO_LIBS)

ejudge-contests-cmd : $(NSM_OBJECTS)
	$(LD) $(LDFLAGS) $(NSM_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB}

ej-contests-control : $(NSC_OBJECTS)
	$(LD) $(LDFLAGS) $(NSC_OBJECTS) -o $@ $(LDLIBS) ${EXPAT_LIB}

make-js-actions : make-js-actions.o
	$(LD) $(LDFLAGS) make-js-actions.o -o $@ $(LDLIBS)

struct-sizes : struct-sizes.o
	$(LD) $(LDFLAGS) $^ -o $@ $(LDLIBS) ${EXPAT_LIB}

ejudge-install.sh : ejudge-setup
	./ejudge-setup -b -i scripts/lang_ids.cfg

local_clean:
	-rm -f *.o *~ *.a $(TARGETS) revinfo newrevinfo version.c $(ARCH)/*.o ejudge.po mkChangeLog2 userlist_clnt/*.o xml_utils/*.o super_clnt/*.o cdeps deps.make filter_expr.[ch] filter_scan.c users users${CGI_PROG_SUFFIX} ejudge-config serve-control serve-control${CGI_PROG_SUFFIX} prjutils2/*.o make-js-actions new_server_clnt/*.o mktable struct-sizes *.debug
	-rm -rf locale
clean: subdir_clean local_clean

subdir_clean:
	$(MAKE) -C extra clean
	$(MAKE) -C checkers clean
	$(MAKE) -C plugins/mysql-common DESTDIR="${DESTDIR}" clean
	$(MAKE) -C plugins/mysql-userlist DESTDIR="${DESTDIR}" clean
	$(MAKE) -C plugins/mysql-clardb DESTDIR="${DESTDIR}" clean
	$(MAKE) -C plugins/mysql-rundb DESTDIR="${DESTDIR}" clean
	$(MAKE) -C plugins/mongo-common DESTDIR="${DESTDIR}" clean
	$(MAKE) -C plugins/mongo-xuser DESTDIR="${DESTDIR}" clean
	$(MAKE) -C csp/contests DESTDIR="${DESTDIR}" clean
	$(MAKE) -C csp/super-server DESTDIR="${DESTDIR}" clean
	$(MAKE) -C cfront clean
	$(MAKE) -C reuse clean
	#$(MAKE) -C libdwarf clean


local_distclean :
	rm -rf autom4te.cache config.log config.status Makefile config.h ejudge-config.v TAGS Makefile.in
distclean : subdir_distclean local_clean local_distclean

subdir_distclean :
	$(MAKE) -C extra distclean
	$(MAKE) -C extra/captest distclean
	$(MAKE) -C checkers distclean
	$(MAKE) -C scripts distclean
	$(MAKE) -C plugins/mysql-common DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C plugins/mysql-userlist DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C plugins/mysql-clardb DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C plugins/mysql-rundb DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C plugins/mongo-common DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C plugins/mongo-xuser DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C csp/contests DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C csp/super-server DESTDIR="${DESTDIR}" distclean
	$(MAKE) -C cfront distclean
	$(MAKE) -C reuse distclean
	-$(MAKE) -C libdwarf distclean

pristine : distclean
	rm -f configure

version.c: newrevinfo $(HFILES) $(CFILES) $(OTHERFILES)
	./newrevinfo
#	#@REVINFO_NO_COMMIT=1 ./revinfo -S -C -p -d db/versions -r db/revisions $(HFILES) $(CFILES) $(OTHERFILES)
version.o: version.c

#new_revision: revinfo $(HFILES) $(CFILES) $(OTHERFILES)
#	@./revinfo -S -C -d db/versions -r db/revisions $(HFILES) $(CFILES) $(OTHERFILES)
#
#new_version: revinfo force
#	@./revinfo -S -C -n -d db/versions -r db/revisions $(HFILES) $(CFILES) $(OTHERFILES)

force:

revinfo: prjutils2/revinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
prjutils2/revinfo.o: prjutils2/revinfo.c

newrevinfo : newrevinfo.o
	$(LD) $(LDFLAGS) $^ -o $@
newrevinfo.o : newrevinfo.c

mkChangeLog2: prjutils2/mkChangeLog2.o prjutils2/changelog.o prjutils2/expat_iface.o prjutils2/svn_xmllog.o prjutils2/usermap.o prjutils2/xalloc.o
	${LD} ${LDFLAGS} $^ -o $@ -lexpat -lm
prjutils2/mkChangeLog2.o: prjutils2/mkChangeLog2.c
prjutils2/changelog.o: prjutils2/changelog.c
prjutils2/expat_iface.o: prjutils2/expat_iface.c
prjutils2/svn_xmllog.o: prjutils2/svn_xmllog.c
prjutils2/usermap.o: prjutils2/usermap.c
prjutils2/xalloc.o: prjutils2/xalloc.c

uudecode.o : uudecode.c
uudecode : uudecode.o
	${LD} ${LDFLAGS} $^ -o $@

cdeps: prjutils2/cdeps.o
	${LD} ${LDFLAGS} $^ -o $@
prjutils2/cdeps.o: prjutils2/cdeps.c

log: mkChangeLog2
	L=`./mkChangeLog2 --input=ChangeLog --latest-revision`; echo "Latest revision: $$L"; svn log -v --xml -r "$$L:HEAD" | ./mkChangeLog2 --user-map=AUTHORS --input=ChangeLog --output=ChangeLog --prefix=/trunk/ejudge/ --strip-prefix=/trunk/ejudge/ --ignore-subdirs
	for i in win32 unix userlist_clnt checkers extra scripts super_clnt xml_utils new_server_clnt; do cd $$i; L=`../mkChangeLog2 --input=ChangeLog --latest-revision`; echo "Latest revision: $$L"; svn log -v --xml -r "$$L:HEAD" | ../mkChangeLog2 --user-map=../AUTHORS --input=ChangeLog --output=ChangeLog --prefix=/trunk/ejudge/$$i/ --strip-prefix=/trunk/ejudge/$$i/; cd ..; done
	for i in plugins/mysql-common plugins/mysql-userlist plugins/mysql-clardb plugins/mysql-rundb; do cd $$i; L=`../../mkChangeLog2 --input=ChangeLog --latest-revision`; echo "Latest revision: $$L"; svn log -v --xml -r "$$L:HEAD" | ../../mkChangeLog2 --user-map=../../AUTHORS --input=ChangeLog --output=ChangeLog --prefix=/trunk/ejudge/$$i/ --strip-prefix=/trunk/ejudge/$$i/; cd ../..; done

# localization stuff
ifdef ENABLE_NLS
po : ejudge.ru_RU.UTF-8.po ejudge.ru_RU.${CHARSET}.po ejudge.uk_UA.${CHARSET}.po ejudge.kk_KZ.${CHARSET}.po
else
po :
endif

ifneq (${CHARSET}, UTF-8)
ejudge.ru_RU.${CHARSET}.po : ejudge.ru_RU.UTF-8.po
	sed "s/UTF-8/${CHARSET}/g" < ejudge.ru_RU.UTF-8.po | ${ICONV} -f UTF-8 -t ${CHARSET} > ejudge.ru_RU.${CHARSET}.po
endif

ejudge.ru_RU.UTF-8.po: $(CFILES) ejudge.po
	${MSGMERGE} -U $@ ejudge.po

ejudge.uk_UA.UTF-8.po: $(CFILES) ejudge.po
	${MSGMERGE} -U $@ ejudge.po

ejudge.kk_KZ.UTF-8.po: $(CFILES) ejudge.po
	${MSGMERGE} -U $@ ejudge.po

ejudge.po: $(CFILES) subdirs_all
	${XGETTEXT} -d ejudge --no-location --foreign-user  -k_ -k__ -s -o $@ *.c csp/contests/*.c csp/super-server/*.c

ru_all:
	-mkdir -p locale/ru_RU.${CHARSET}/LC_MESSAGES
uk_all:
	-mkdir -p locale/uk_UA.${CHARSET}/LC_MESSAGES
kk_all:
	-mkdir -p locale/kk_KZ.${CHARSET}/LC_MESSAGES

ejudge-config : ejudge-config.v version.c
	vvv=`grep compile_version version.c | sed 's/^[^"]*["]\([^"]*\)["].*$$/\1/'` && sed "s/@BUILD_VERSION@/$$vvv/" < ejudge-config.v > ejudge-config && chmod +x ejudge-config

ifdef ENABLE_NLS
mo : locale/ru_RU.${CHARSET}/LC_MESSAGES/ejudge.mo locale/uk_UA.${CHARSET}/LC_MESSAGES/ejudge.mo locale/kk_KZ.${CHARSET}/LC_MESSAGES/ejudge.mo
else
mo :
endif

locale/ru_RU.${CHARSET}/LC_MESSAGES/ejudge.mo : ejudge.ru_RU.${CHARSET}.po ru_all
	${MSGFMT} -o $@ -c $<
locale/uk_UA.${CHARSET}/LC_MESSAGES/ejudge.mo : ejudge.uk_UA.${CHARSET}.po uk_all
	${MSGFMT} -o $@ -c $<
locale/kk_KZ.${CHARSET}/LC_MESSAGES/ejudge.mo : ejudge.kk_KZ.${CHARSET}.po kk_all
	${MSGFMT} -o $@ -c $<

include meta.make

libcommon.a : $(COMMON_CFILES:.c=.o) filter_scan.o filter_expr.o $(META_O_FILES)
	ar rcv $@ $^

libplatform.a : $(PLATFORM_CFILES:.c=.o)
	ar rcv $@ $^

libsuper_clnt.a : $(SUPER_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

libuserlist_clnt.a: $(USERLIST_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

libnew_server_clnt.a: $(NEW_SERVER_CLNT_CFILES:.c=.o)
	ar rcv $@ $^

deps.make: cdeps ${CFILES} ${HFILES} filter_expr.c filter_expr.h filter_scan.c $(META_C_FILES) $(META_H_FILES)
	@./cdeps -I include ${CFILES} filter_expr.c filter_scan.c > deps.make

tags : ${CFILES} ${HFILES} filter_expr.c filter_expr.h filter_scan.c 
	@ctags -e $^

filter_expr.c filter_expr.h ./include/ejudge/filter_expr.h : filter_expr.y
	bison -l -o filter_expr.c -d -p filter_expr_ $<
	cp -p filter_expr.h ./include/ejudge/filter_expr.h

filter_scan.c : filter_scan.lex
	flex -p -s -L -8 -B -o$@ -Pfilter_expr_ $<

style/actions.js : make-js-actions
	./make-js-actions > style/actions.js

contest-1/contest-1.c : contest-1/contest-1.tar.gz
	contest-1/make-c.sh contest-1.tar.gz contest-1/contest-1.tar.gz contest-1/contest-1.c
contest-1/contest-1.tar.gz :
	tar cvz --exclude-vcs -C contest-1 -f contest-1/contest-1.tar.gz problems

reuse/objs/libreuse.a :
	$(MAKE) -C reuse all

cfront/ej-cfront : reuse/objs/libreuse.a
	$(MAKE) -C cfront all

include/libdwarf-internal/dwarf.h include/libdwarf-internal/libdwarf.h libdwarf/libdwarf/libdwarf.a:
	$(MAKE) -C libdwarf all

bson_utils.o : bson_utils.c
	$(CC) $(CFLAGS) $(MONGO_CFLAGS) -c $< -o $@

include deps.make
