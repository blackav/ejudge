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
CFLAGS = -Wall -g $(WERROR)
CFLAGSINT = -D_GNU_SOURCE -Iinclude -I.. -std=gnu99 $(NO_POINTER_SIGN)
LDFLAGS = -Wall -g
LDFLAGSINT = -std=gnu99
LDLIBSINT = -lm
LDLIBS =
else
CFLAGS = -O2 -Wall
CFLAGSINT = -D_GNU_SOURCE -Iinclude -I.. -mno-cygwin -std=gnu99 $(NO_POINTER_SIGN)
LDFLAGS = -s
LDFLAGSINT = -mno-cygwin -std=gnu99
LDLIBSINT = 
LDLIBS =
endif

ALLCFLAGS = ${CFLAGS} ${CFLAGSINT}
ALLLDFLAGS = ${LDFLAGS} ${LDFLAGSINT}
ALLLDLIBS = ${LDLIBS} ${LDLIBSINT}

LN = ln -sf

REUSECFILES =\
 c_value.c\
 c_value_ops.c\
 errors.c\
 flexstring.c\
 fp_props_f.c\
 fp_props_ld.c\
 fsclear.c\
 fsdestroy.c\
 fsdup.c\
 fsinschar.c\
 getopt.c\
 hash.c\
 mempage.c\
 number_io_tab1.c\
 number_io_tab2.c\
 os_readdd.c\
 os_readdf.c\
 os_readdld.c\
 posinitmodule.c\
 positions.c\
 possnprintf.c\
 poswrite.c\
 readhd.c\
 readhf.c\
 readhld.c\
 ssinit.c\
 ssinitmodule.c\
 ssstring.c\
 strncatx.c\
 strnput0.c\
 strtold.c\
 writehd.c\
 writehf.c\
 writehld.c\
 writell.c\
 writeull.c\
 xalloc.c\
 xcalloc.c\
 xexpand.c\
 xexpand2.c\
 xexpand3.c\
 xexpand4.c\
 xfree.c\
 xmalloc.c\
 xmemdup.c\
 xrealloc.c\
 xstrarrayfree.c\
 xstrdup.c\
 xstrmerge0.c\
 xstrmerge1.c\
 xstrmerge2.c\
 xstrmerge3.c\
 $(ARCH)/checkaccess.c\
 $(ARCH)/dirname.c\
 $(ARCH)/errormsg.c\
 $(ARCH)/errorstring.c\
 $(ARCH)/exec.c\
 $(ARCH)/getbasename.c\
 $(ARCH)/geterrorstring.c\
 $(ARCH)/getsignalstring.c\
 $(ARCH)/logger.c\
 $(ARCH)/rgetlastname.c\
 $(ARCH)/rgetsuffix.c\
 $(ARCH)/substsuffix.c\
 $(ARCH)/tempnam.c\
 $(ARCH)/tempfile.c\
 $(ARCH)/xfile.c

REUSEHFILES =\
 include/reuse/c_value.h\
 include/reuse/c_value_ops.h\
 include/reuse/errors.h\
 include/reuse/exec.h\
 include/reuse/flexstring.h\
 include/reuse/fp_props.h\
 include/reuse/getopt.h\
 include/reuse/hash.h\
 include/reuse/hash_priv.h\
 include/reuse/integral.h\
 include/reuse/logger.h\
 include/reuse/mempage.h\
 include/reuse/number_io.h\
 include/reuse/osdeps.h\
 include/reuse/positions.h\
 include/reuse/positionsp.h\
 include/reuse/stringset.h\
 include/reuse/str_utils.h\
 include/reuse/tempfile.h\
 include/reuse/xalloc.h\
 include/reuse/xfile.h

all : objs objs/$(ARCH) objs/libreuse.a

clean :
	-rm -fr objs/* cdeps *.o

deps.make: objs objs/cdeps ${REUSECFILES} ${REUSEHFILES} 
	./objs/cdeps -I .. -I include -v REUSEOFILES -D -d objs/ ${REUSECFILES} > deps.make

include deps.make

objs :
	-mkdir -p objs
objs/unix : objs
	-mkdir -p objs/unix
objs/win32 : objs
	-mkdir -p objs/win32

objs/libreuse.a : ${REUSEOFILES}
	ar rcv $@ ${REUSEOFILES}

%.o : %.c
	${CC} ${ALLCFLAGS} -c -o $@ $<

objs/%.o : %.c
	${CC} ${ALLCFLAGS} -c -o $@ $<
%.o : %.c
	${CC} ${ALLCFLAGS} -c -o $@ $<

objs/cdeps.o : cdeps.c

objs/cdeps : objs/cdeps.o
	${LD} ${ALLLDFLAGS} $^ -o $@

cdeps.c : ../prjutils2/cdeps.c
	$(LN) $< $@

# temporary hacks
hash.c : reuse_hash.c
	$(LN) $< $@
mempage.c : reuse_mempage.c
	$(LN) $< $@
xalloc.c : reuse_xalloc.c
	$(LN) $< $@
xcalloc.c : reuse_xcalloc.c
	$(LN) $< $@
xexpand.c : reuse_xexpand.c
	$(LN) $< $@
xexpand2.c : reuse_xexpand2.c
	$(LN) $< $@
xexpand3.c : reuse_xexpand3.c
	$(LN) $< $@
xexpand4.c : reuse_xexpand4.c
	$(LN) $< $@
xfree.c : reuse_xfree.c
	$(LN) $< $@
xmalloc.c : reuse_xmalloc.c
	$(LN) $< $@
xmemdup.c : reuse_xmemdup.c
	$(LN) $< $@
xrealloc.c : reuse_xrealloc.c
	$(LN) $< $@
xstrarrayfree.c : reuse_xstrarrayfree.c
	$(LN) $< $@
xstrdup.c : reuse_xstrdup.c
	$(LN) $< $@
xstrmerge0.c : reuse_xstrmerge0.c
	$(LN) $< $@
xstrmerge1.c : reuse_xstrmerge1.c
	$(LN) $< $@
xstrmerge2.c : reuse_xstrmerge2.c
	$(LN) $< $@
xstrmerge3.c : reuse_xstrmerge3.c
	$(LN) $< $@

unix/checkaccess.c : ../unix/reuse_checkaccess.c
	$(LN) ../$< $@
unix/dirname.c : ../unix/reuse_dirname.c
	$(LN) ../$< $@
unix/errormsg.c : ../unix/reuse_errormsg.c
	$(LN) ../$< $@
unix/errorstring.c : ../unix/reuse_errorstring.c
	$(LN) ../$< $@
unix/exec.c : ../unix/reuse_exec.c
	$(LN) ../$< $@
unix/getbasename.c : ../unix/reuse_getbasename.c
	$(LN) ../$< $@
unix/geterrorstring.c : ../unix/reuse_geterrorstring.c
	$(LN) ../$< $@
unix/getsignalstring.c : ../unix/reuse_getsignalstring.c
	$(LN) ../$< $@
unix/logger.c : ../unix/reuse_logger.c
	$(LN) ../$< $@
unix/rgetlastname.c : ../unix/reuse_rgetlastname.c
	$(LN) ../$< $@
unix/rgetsuffix.c : ../unix/reuse_rgetsuffix.c
	$(LN) ../$< $@
unix/substsuffix.c : ../unix/reuse_substsuffix.c
	$(LN) ../$< $@
unix/tempnam.c : ../unix/reuse_tempnam.c
	$(LN) ../$< $@

