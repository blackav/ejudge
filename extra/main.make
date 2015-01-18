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

CC=gcc
LD=gcc
CFLAGS=${LIBCAP_INCL_OPT} ${CDEBUGFLAGS} ${CCOMPFLAGS} ${CINTLFLAG} ${CEXTRAFLAGS} ${WPTRSIGN} -DHAVE_CONFIG_H
LDFLAGS=${LIBCAP_LIB_OPT} ${LDDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}

TARGETS=bpcemu2 dosrun3 bppemu bccemu qbemu ej-javac ej-make-archive
TARGETALLWAYS=${TARGETS}
ifndef NO_KERNEL
TARGETS += capexec
ifndef STATIC
TARGETS += libdropcaps.so
ifdef NEED32
TARGETS += libdropcaps32.so
endif
ifdef NEED64
TARGETS += libdropcaps64.so
endif
endif
endif

all: ${TARGETS}
clean:
	-rm -f ${TARGETS} *.o
distclean: clean
	rm -f Makefile
install:
	mkdir -p "${DESTDIR}${libexecdir}/ejudge/lang"
	for i in ${TARGETALLWAYS}; do install -m 755 $$i "${DESTDIR}${libexecdir}/ejudge/lang"; done
	if [ x"${NO_KERNEL}" = x ]; then install -m 755 capexec "${DESTDIR}${libexecdir}/ejudge/lang"; fi
	if [ x"${NO_KERNEL}" = x -a x"${STATIC}" = x ]; then install -m 755 libdropcaps.so "${DESTDIR}${libexecdir}/ejudge/lang"; fi
	if [ x"${NO_KERNEL}" = x -a x"${STATIC}" = x -a x"${NEED32}" != x ]; then install -m 755 libdropcaps32.so "${DESTDIR}${libexecdir}/ejudge/lang"; fi
	if [ x"${NO_KERNEL}" = x -a x"${STATIC}" = x -a x"${NEED64}" != x ]; then install -m 755 libdropcaps64.so "${DESTDIR}${libexecdir}/ejudge/lang"; fi

bpcemu2: bpcemu2.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
bpcemu2.o: bpcemu2.c

bppemu: bppemu.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
bppemu.o: bppemu.c

bccemu: bccemu.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
bccemu.o: bccemu.c

qbemu: qbemu.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
qbemu.o: qbemu.c

capexec: capexec.o
	${LD} ${LDFLAGS} $^ -o $@ ${LIBCAP_LINK} ${LDLIBS}
capexec.o: capexec.c

libdropcaps.so : libdropcaps.o
	${LD} -shared ${LDFLAGS} $^ -o $@ ${LIBCAP_LINK} ${LDLIBS}
libdropcaps.o : libdropcaps.c
	${CC} ${CFLAGS} -DPIC -fPIC -c libdropcaps.c -o libdropcaps.o

libdropcaps32.so : libdropcaps32.o
	${LD} -shared ${LDFLAGS} $^ -m32 -o $@ ${LIBCAP_LINK} ${LDLIBS}
libdropcaps32.o : libdropcaps.c
	${CC} ${CFLAGS} -DPIC -fPIC -m32 -c libdropcaps.c -o libdropcaps32.o

libdropcaps64.so : libdropcaps64.o
	${LD} -shared ${LDFLAGS} $^ -m64 -o $@ ${LIBCAP_LINK} ${LDLIBS}
libdropcaps64.o : libdropcaps.c
	${CC} ${CFLAGS} -DPIC -fPIC -m64 -c libdropcaps.c -o libdropcaps64.o

dosrun3: dosrun3.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
dosrun3.o: dosrun3.c

ej-javac : ej-javac.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
ej-javac.o : ej-javac.c

ej-make-archive : ej-make-archive.o
	${LD} ${LDFLAGS} $^ -o $@ ${LDLIBS}
ej-make-archive.o : ej-make-archive.c
