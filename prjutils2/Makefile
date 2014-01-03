# $Id$

CC = gcc
LD = gcc

CFLAGS = -Wall -g
LDLIBS = -lexpat

all : mkChangeLog2 revinfo cdeps

clean :
	rm -f  *.o mkChangeLog2 revinfo cdeps

log : mkChangeLog2
	svn log --xml -v | ./mkChangeLog2 --user-map=AUTHORS --input=ChangeLog --output=ChangeLog --prefix=/trunk/prjutils/ --strip-prefix=/trunk/prjutils/

mkChangeLog2 : mkChangeLog2.o xalloc.o expat_iface.o changelog.o svn_xmllog.o usermap.o
revinfo : revinfo.o
cdeps : cdeps.o

# dependencies
changelog.o: changelog.c changelog.h xalloc.h
expat_iface.o: expat_iface.c expat_iface.h xalloc.h
mkChangeLog2.o: mkChangeLog2.c svn_xmllog.h expat_iface.h usermap.h \
  xalloc.h changelog.h
svn_xmllog.o: svn_xmllog.c svn_xmllog.h expat_iface.h xalloc.h
usermap.o: usermap.c usermap.h xalloc.h
xalloc.o: xalloc.c xalloc.h

revinfo.o : revinfo.c

cdeps.o : cdeps.c
