# -*- Makefile -*-
# $Id$

# Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

CC = gcc
LD = gcc
LDLIBS = -lcap
CFLAGS = -Wall -g

CFILES = t1.c t2.c t2_helper.c t2_helper_2.c t3.c t4.c t5.c t5_helper.c t6.c
XFILES = $(CFILES:.c=)

all : $(XFILES)
clean:
	-rm -f $(XFILES)


t2_helper : t2_helper.c
	$(CC) $(CFLAGS) -static -s t2_helper.c -o t2_helper

t2_helper_2 : t2_helper_2.c
	$(CC) $(CFLAGS) -static -s t2_helper_2.c -o t2_helper_2

t5_helper : t5_helper.c
	$(CC) $(CFLAGS) t5_helper.c -o t5_helper

tests:
	./t1
	./t2
	./t3
	./t4
	./t5
	./t6
	@echo "All tests passed successfully"
