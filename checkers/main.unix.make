# -*- Makefile -*-

# Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

ifdef NEED32
ifdef NEED64
NEED_COMPAT=1
endif
endif

ifdef RELEASE
CDEBUGFLAGS=-O2 -Wall -DNDEBUG -DRELEASE ${WERROR}
LDDEBUGFLAGS=-s
else
CDEBUGFLAGS=-g -Wall ${WERROR}
LDDEBUGFLAGS=-g
endif

ifdef STATIC
LDDEBUGFLAGS += -static
endif

ifndef NO_RPATH
RPATHOPT=-Wl,-rpath,${libdir}
endif

CCOMPFLAGS=-D_GNU_SOURCE -DEJUDGE_CHECKER
LDCOMPFLAGS=

LDLIBS=${EXTRALIBS} -lm
CFLAGS=-I. ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CEXTRAFLAGS} ${WPTRSIGN}
LDFLAGS=${LDDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
AR=ar

include files.make

OFILES=$(CFILES:.c=.o) testinfo.o
PICOFILES = $(CFILES:%.c=pic/%.o) pic/testinfo.o
PIC32OFILES = $(CFILES:%.c=pic32/%.o) pic32/testinfo.o
O32FILES=$(CFILES:%.c=m32/%.o) m32/testinfo.o
CHKXFILES = $(CHKCFILES:.c=)
STYLEXFILES = $(STYLECFILES:.c=)

ifndef STATIC
TARGETS = pic libchecker.a libchecker.so ${CHKXFILES} ${STYLEXFILES}
ifdef NEED_COMPAT
TARGETS += pic32 pic32/libchecker.so m32 m32/libchecker.a
endif
else
TARGETS = libchecker.a ${CHKXFILES} ${STYLEXFILES}
ifdef NEED_COMPAT
TARGETS += m32 m32/libchecker.a
endif
endif
TARGETLIBS = libchecker.a

all : ${TARGETS} mo

clean :
	-rm -fr *.o *.a *.so *~ *.bak testinfo.h testinfo.c pic pic32 m32 ${CHKXFILES} ${STYLEXFILES}
pic :
	mkdir pic

pic32 :
	mkdir pic32

m32 :
	mkdir m32

distclean : clean
	rm -f Makefile Makefile.in

install : all
	mkdir -p "${DESTDIR}${includedir}/ejudge"
	for i in checker.h checker_internal.h checkutils.h testinfo.h; do install -m 644 $$i "${DESTDIR}${includedir}/ejudge"; done
	mkdir -p "${DESTDIR}${libdir}"
	if [ x"${lib32dir}" != x ]; then mkdir -p "${DESTDIR}${lib32dir}"; fi
	install -m 644 libchecker.a "${DESTDIR}${libdir}"
	if [ x"${STATIC}" = x ]; then install -m 755 libchecker.so "${DESTDIR}${libdir}"; else rm -f "${DESTDIR}${libdir}/libchecker.so"; fi
	if [ -f "m32/libchecker.a" -a x"${lib32dir}" != x ]; then install -m 644 "m32/libchecker.a" "${DESTDIR}/${lib32dir}"; fi
	if [ -f "pic32/libchecker.so" -a x"${lib32dir}" != x ]; then install -m 755 "pic32/libchecker.so" "${DESTDIR}/${lib32dir}"; fi
	mkdir -p "${DESTDIR}${datadir}/ejudge/testlib"
	mkdir -p "${DESTDIR}${datadir}/ejudge/testlib/fpc"
	mkdir -p "${DESTDIR}${datadir}/ejudge/testlib/delphi"
	for i in symbols.pas testlib.pas; do install -m 644 fpc/$$i "${DESTDIR}${datadir}/ejudge/testlib/fpc"; done
	install -m 644 delphi/testlib.pas "${DESTDIR}${datadir}/ejudge/testlib/delphi"
	mkdir -p "${DESTDIR}${libexecdir}/ejudge/checkers"
	for i in ${CHKXFILES} ${STYLEXFILES}; do install -m 755 $$i "${DESTDIR}${libexecdir}/ejudge/checkers"; done
	-cd "${DESTDIR}${datadir}/ejudge/testlib/fpc"; FPC=`"${DESTDIR}${libexecdir}/ejudge"/fpc-version -p`; [ x"$$FPC" != x ] && "$$FPC" testlib.pas
	-cd "${DESTDIR}${datadir}/ejudge/testlib/delphi"; DCC=`"${DESTDIR}${libexecdir}/ejudge"/dcc-version -p`; [ x"$$DCC" != x ] && "$$DCC" testlib.pas
	if [ x"${ENABLE_NLS}" = x1 ]; then for locale in "ru_RU.UTF-8" "uk_UA.UTF-8" "kk_KZ.UTF-8"; do install -d "${DESTDIR}${datadir}/locale/$${locale}/LC_MESSAGES"; install -m 0644 "locale/$${locale}/LC_MESSAGES/ejudgecheckers.mo" "${DESTDIR}${datadir}/locale/$${locale}/LC_MESSAGES"; done; fi

libchecker.a : ${OFILES}
	${AR} rcv $@ $^
libchecker.so : ${PICOFILES}
	${CC} -shared $^ -o $@ -lm
m32/libchecker.a : ${O32FILES}
	${AR} rcv $@ $^
pic32/libchecker.so : ${PIC32OFILES}
	${CC} -m32 -shared $^ -o $@ -lm

corr_close.o: corr_close.c checker_internal.h
pic/corr_close.o: corr_close.c checker_internal.h
corr_eof.o: corr_eof.c checker_internal.h
pic/corr_eof.o: corr_eof.c checker_internal.h
eq_double.o : eq_double.c checker_internal.h
	${CC} ${CFLAGS} -std=gnu99 -c $< -o $@
eq_double_abs.o : eq_double_abs.c checker_internal.h
	${CC} ${CFLAGS} -std=gnu99 -c $< -o $@
pic/eq_double.o : eq_double.c checker_internal.h
	${CC} ${CFLAGS} -fPIC -DPIC -std=gnu99 -c $< -o $@
pic/eq_double_abs.o : eq_double_abs.c checker_internal.h
	${CC} ${CFLAGS} -fPIC -DPIC -std=gnu99 -c $< -o $@
eq_float.o : eq_float.c checker_internal.h
	${CC} ${CFLAGS} -std=gnu99 -c $< -o $@
eq_float_abs.o : eq_float_abs.c checker_internal.h
	${CC} ${CFLAGS} -std=gnu99 -c $< -o $@
pic/eq_float.o : eq_float.c checker_internal.h
	${CC} ${CFLAGS} -fPIC -DPIC -std=gnu99 -c $< -o $@
pic/eq_float_abs.o : eq_float_abs.c checker_internal.h
	${CC} ${CFLAGS} -fPIC -DPIC -std=gnu99 -c $< -o $@
eq_long_double.o : eq_long_double.c checker_internal.h
	${CC} ${CFLAGS} -std=gnu99 -c $< -o $@
eq_long_double_abs.o : eq_long_double_abs.c checker_internal.h
	${CC} ${CFLAGS} -std=gnu99 -c $< -o $@
pic/eq_long_double.o : eq_long_double.c checker_internal.h
	${CC} ${CFLAGS} -fPIC -DPIC -std=gnu99 -c $< -o $@
pic/eq_long_double_abs.o : eq_long_double_abs.c checker_internal.h
	${CC} ${CFLAGS} -fPIC -DPIC -std=gnu99 -c $< -o $@
fatal.o: fatal.c checker_internal.h
pic/fatal.o: fatal.c checker_internal.h
fatal_cf.o: fatal_cf.c checker_internal.h
pic/fatal_cf.o: fatal_cf.c checker_internal.h
fatal_pe.o: fatal_pe.c checker_internal.h
pic/fatal_pe.o: fatal_pe.c checker_internal.h
fatal_wa.o: fatal_wa.c checker_internal.h
pic/fatal_wa.o: fatal_wa.c checker_internal.h
in_close.o: in_close.c checker_internal.h
pic/in_close.o: in_close.c checker_internal.h
in_eof.o: in_eof.c checker_internal.h
pic/in_eof.o: in_eof.c checker_internal.h
init.o: init.c checker_internal.h testinfo.h
pic/init.o: init.c checker_internal.h testinfo.h
normalize_file.o: normalize_file.c checker_internal.h
pic/normalize_file.o: normalize_file.c checker_internal.h
normalize_spaces_in_file.o: normalize_file.c checker_internal.h
pic/normalize_spaces_in_file.o: normalize_file.c checker_internal.h
ok.o: ok.c checker_internal.h
pic/ok.o: ok.c checker_internal.h
read_buf.o: read_buf.c checker_internal.h
pic/read_buf.o: read_buf.c checker_internal.h
read_corr_int.o: read_corr_int.c checker_internal.h
pic/read_corr_int.o: read_corr_int.c checker_internal.h
read_double.o: read_double.c checker_internal.h
pic/read_double.o: read_double.c checker_internal.h
read_file_by_line.o: read_file_by_line.c checker_internal.h
pic/read_file_by_line.o: read_file_by_line.c checker_internal.h
read_file.o: read_file.c checker_internal.h
pic/read_file.o: read_file.c checker_internal.h
read_in_double.o: read_in_double.c checker_internal.h
pic/read_in_double.o: read_in_double.c checker_internal.h
read_in_int.o: read_in_int.c checker_internal.h
pic/read_in_int.o: read_in_int.c checker_internal.h
read_team_double.o: read_team_double.c checker_internal.h
pic/read_team_double.o: read_team_double.c checker_internal.h
read_team_int.o: read_team_int.c checker_internal.h
pic/read_team_int.o: read_team_int.c checker_internal.h
read_team_long_double.o: read_team_long_double.c checker_internal.h
pic/read_team_long_double.o: read_team_long_double.c checker_internal.h
team_close.o: team_close.c checker_internal.h
pic/team_close.o: team_close.c checker_internal.h
team_eof.o: team_eof.c checker_internal.h
pic/team_eof.o: team_eof.c checker_internal.h
vars.o: vars.c checker_internal.h
pic/vars.o: vars.c checker_internal.h
xcalloc.o: xcalloc.c checker_internal.h
pic/xcalloc.o: xcalloc.c checker_internal.h
xmalloc.o: xmalloc.c checker_internal.h
pic/xmalloc.o: xmalloc.c checker_internal.h
xrealloc.o: xrealloc.c checker_internal.h
pic/xrealloc.o: xrealloc.c checker_internal.h
xstrdup.o: xstrdup.c checker_internal.h
pic/xstrdup.o: xstrdup.c checker_internal.h
testinfo.o: testinfo.c testinfo.h
pic/testinfo.o: testinfo.c testinfo.h

testinfo.h: ../include/ejudge/testinfo.h
	ln -sf ../include/ejudge/testinfo.h .
testinfo.c: ../testinfo.c
	ln -sf ../testinfo.c

ifdef STATIC
cmp_% : cmp_%.c checker.h checker_internal.h libchecker.a
	${CC} ${CFLAGS} ${LDFLAGS} -L. $< -o $@ -lchecker -lm
else
cmp_% : cmp_%.c checker.h checker_internal.h libchecker.so
	${CC} ${CFLAGS} ${LDFLAGS} ${RPATHOPT} -L. $< -o $@ -lchecker -lm
endif

style_% : style_%.c
	${CC} ${CFLAGS} ${LDFLAGS} -L.. $< -o $@ -lcommon -lplatform -lcommon -lplatform -lz -lm

pic/%.o : %.c
	${CC} ${CFLAGS} -fPIC -DPIC -c $< -o $@

pic32/%.o : %.c
	${CC} ${CFLAGS} -m32 -fPIC -DPIC -c $< -o $@

m32/%.o : %.c
	${CC} ${CFLAGS} -m32 -c $< -o $@

ifdef ENABLE_NLS
mo : locale/ru_RU.UTF-8/LC_MESSAGES/ejudgecheckers.mo locale/uk_UA.UTF-8/LC_MESSAGES/ejudgecheckers.mo locale/kk_KZ.UTF-8/LC_MESSAGES/ejudgecheckers.mo
else
mo :
endif

ejudgecheckers.ru_RU.UTF-8.po: $(CFILES) $(CHKCFILES) $(STYLECFILES) ejudgecheckers.po
	${MSGMERGE} -U $@ ejudgecheckers.po
ejudgecheckers.uk_UA.UTF-8.po: $(CFILES) $(CHKCFILES) $(STYLECFILES) ejudgecheckers.po
	${MSGMERGE} -U $@ ejudgecheckers.po
ejudgecheckers.kk_KZ.UTF-8.po: $(CFILES) $(CHKCFILES) $(STYLECFILES) ejudgecheckers.po
	${MSGMERGE} -U $@ ejudgecheckers.po

ejudgecheckers.po: $(CFILES) $(CHKCFILES) $(STYLECFILES)
	${XGETTEXT} -d ejudgecheckers --no-location --foreign-user  -k_ -k__ -s -o $@ *.c

locale/ru_RU.UTF-8/LC_MESSAGES/ejudgecheckers.mo : ejudgecheckers.ru_RU.UTF-8.po locale/ru_RU.UTF-8/LC_MESSAGES 
	${MSGFMT} -o $@ -c $<
locale/uk_UA.UTF-8/LC_MESSAGES/ejudgecheckers.mo : ejudgecheckers.uk_UA.UTF-8.po locale/uk_UA.UTF-8/LC_MESSAGES 
	${MSGFMT} -o $@ -c $<
locale/kk_KZ.UTF-8/LC_MESSAGES/ejudgecheckers.mo : ejudgecheckers.kk_KZ.UTF-8.po locale/kk_KZ.UTF-8/LC_MESSAGES 
	${MSGFMT} -o $@ -c $<

locale/ru_RU.UTF-8/LC_MESSAGES :
	mkdir -p $@
locale/uk_UA.UTF-8/LC_MESSAGES :
	mkdir -p $@
locale/kk_KZ.UTF-8/LC_MESSAGES :
	mkdir -p $@
