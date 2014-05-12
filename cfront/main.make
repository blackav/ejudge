# -*- mode: Makefile -*-
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

ifeq ($(ARCH), unix)
CFLAGS = -Wall -g ${WERROR}
CFLAGSINT = -D_GNU_SOURCE -I. -I.. -I../include -std=gnu99 ${NO_POINTER_SIGN}
LDFLAGS = -Wall -g
LDFLAGSINT = -L../reuse/objs -std=gnu99
LDLIBSINT = -lreuse -lm
LDLIBS =
else
CFLAGS = -O2 -Wall
CFLAGSINT = -D_GNU_SOURCE -I. -I.. -I../include -mno-cygwin -std=gnu99
LDFLAGS = -s
LDFLAGSINT = -L../reuse/objs -mno-cygwin -std=gnu99
LDLIBSINT = -lreuse
LDLIBS =
endif

LN = ln -sf

ALLCFLAGS = ${CFLAGS} ${CFLAGSINT}
ALLLDFLAGS = ${LDFLAGS} ${LDFLAGSINT}
ALLLDLIBS = ${LDLIBS} ${LDLIBSINT}

CFRONTCFILES = \
 attribute_names.c\
 builtin_idents.c\
 c_errors.c\
 cfrontenv.c\
 meta.c\
 meta_gen.c\
 parser.c\
 pos.c\
 scanner.c\
 sema.c\
 sema_an.c\
 sema_data.c\
 sema_maps.c\
 tree.c\
 tree_dump.c\
 tree_fold.c\
 typedef.c

CFRONTHFILES = \
 attribute_names.h\
 builtin_idents.h\
 c_errors.h\
 cfrontenv.h\
 lconfig.h\
 meta.h\
 meta_gen.h\
 parser.h\
 pos.h\
 scanner.h\
 sema.h\
 sema_an.h\
 sema_data.h\
 sema_func.h\
 sema_maps.h\
 tree.h\
 tree_fold.h\
 typedef.h

TOOLCFILES = cpp.c rcc.c ccmain.c

BINARIES = ej-cpp${EXESFX} ej-cfront${EXESFX} ej-ccmain${EXESFX}

all : ${BINARIES}

install: ${BINARIES}
	install -d "${DESTDIR}${serverbindir}/../cfront"
	for i in ${BINARIES}; do install -m 0755 $$i "${DESTDIR}${serverbindir}/../cfront"; done
	tar cf - include | tar xf - -C "${DESTDIR}${prefix}"

install-bin: ${BINARIES}
	for i in ${BINARIES}; do install -m 0755 $$i "${DESTDIR}${serverbindir}/../cfront"; done

clean :
	-rm -f ${BINARIES} cdeps *.o *.a reuse/*.o unix/*.o

ej-cpp${EXESFX} : cpp.o libcfront.a
	${LD} ${ALLLDFLAGS} $^ -o $@ ${ALLLDLIBS}

ej-cfront${EXESFX} : rcc.o libcfront.a
	${LD} ${ALLLDFLAGS} $^ -o $@ ${ALLLDLIBS}

ej-ccmain${EXESFX} : ccmain.o libcfront.a
	${LD} ${ALLLDFLAGS} $^ -o $@ ${ALLLDLIBS}

libcfront.a : $(CFRONTCFILES:.c=.o)
	ar rcv $@ $^

%.o : %.c
	${CC} ${ALLCFLAGS} -c -o $@ $<

reuse/%.c : ../reuse/%.c
	$(LN) ../$< $@
unix/%.c : ../unix/%.c
	$(LN) ../$< $@

deps.make: cdeps ${CFRONTCFILES} ${TOOLCFILES} ${CFRONTHFILES} 
	@./cdeps -I .. -I . -I ../include ${CFRONTCFILES} ${TOOLCFILES} > deps.make

cdeps.o : cdeps.c

cdeps : cdeps.o
	${LD} ${ALLLDFLAGS} $^ -o $@

parser.c parser.h parser.output : parser.y
	${BISON} ${BISONFLAGS} -o parser.c parser.y

scanner.c : scanner.lex
	${FLEX} ${FLEXFLAGS} -oscanner.c scanner.lex

cdeps.c : ../prjutils2/cdeps.c
	$(LN) $< $@

include deps.make
