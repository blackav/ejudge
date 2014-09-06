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

ifdef RELEASE
CDEBUGFLAGS=-O2 -Wall -DNDEBUG -DRELEASE ${WERROR}
else
CDEBUGFLAGS=-g -Wall ${WERROR}
endif
CEXTRAFLAGS=
LDEXTRAFLAGS=
EXTRALIBS=
CCOMPFLAGS=-D_GNU_SOURCE -std=gnu99 -I../.. -I../../include -g -DPIC -fPIC
LDCOMPFLAGS= -g -shared
EXESFX=

LDLIBS=${EXTRALIBS} -lz $(LIBINTL) $(LIBICONV) $(LIBLIBICONV) -lm
CFLAGS=${CDEBUGFLAGS} ${CCOMPFLAGS} ${CEXTRAFLAGS} ${WPTRSIGN}
LDFLAGS=${CDEBUGFLAGS} ${LDCOMPFLAGS} ${LDEXTRAFLAGS}
CC=gcc
LD=gcc
EXPAT_LIB=-lexpat

TARGETDIR = ${libexecdir}/ejudge/csp/contests
CFILES = \
 csp_check_tests_page.c\
 csp_cnts_clear_file_action.c\
 csp_cnts_commit_page.c\
 csp_cnts_edit_access_page.c\
 csp_cnts_edit_cur_contest_page.c\
 csp_cnts_edit_cur_global_page.c\
 csp_cnts_edit_cur_language_page.c\
 csp_cnts_edit_cur_problem_page.c\
 csp_cnts_edit_cur_variant_page.c\
 csp_cnts_edit_file_page.c\
 csp_cnts_edit_member_fields_page.c\
 csp_cnts_edit_permissions_page.c\
 csp_cnts_edit_user_fields_page.c\
 csp_cnts_new_serve_cfg_page.c\
 csp_cnts_reload_file_action.c\
 csp_cnts_save_file_action.c\
 csp_cnts_start_edit_action.c\
 csp_cnts_start_edit_problem_action.c\
 csp_contest_already_edited_page.c\
 csp_contest_locked_page.c\
 csp_contest_page.c\
 csp_contest_xml_page.c\
 csp_create_contest_page.c\
 csp_create_contest_2_action.c\
 csp_login_page.c\
 csp_main_page.c\
 csp_problem_packages_page.c\
 csp_error_unknown_page.c

SOFILES = $(CFILES:.c=.so)

all : $(CFILES) $(SOFILES)

install : all
	install -d "${DESTDIR}${prefix}/share/ejudge/csp/super-server"
	for i in *.csp; do install -m 0644 $$i "${DESTDIR}${prefix}/share/ejudge/csp/super-server"; done
	for i in I_*.c; do install -m 0644 $$i "${DESTDIR}${prefix}/share/ejudge/csp/super-server"; done

clean : 
	-rm -f *.o *.so *.ds csp_*.c

po : super-server.po
super-server.po : $(CFILES)
	${XGETTEXT} -d ejudge --no-location --foreign-user  -k_ -k__ -s -o $@ *.c

csp_main_page.so : csp_main_page.c I_main_page.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@
csp_check_tests_page.so : csp_check_tests_page.c I_check_tests_page.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@

csp_check_tests_page.c : check_tests_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_clear_file_action.c : cnts_clear_file_action.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_commit_page.c : cnts_commit_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_edit_access_page.c : cnts_edit_access_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_edit_cur_contest_page.c : cnts_edit_cur_contest_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_cur_global_page.c : cnts_edit_cur_global_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_cur_language_page.c : cnts_edit_cur_language_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_cur_problem_page.c : cnts_edit_cur_problem_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_one_problem.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_cur_variant_page.c : cnts_edit_cur_variant_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_file_page.c : cnts_edit_file_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_edit_member_fields_page.c : cnts_edit_member_fields_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_edit_permissions_page.c : cnts_edit_permissions_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_edit_user_fields_page.c : cnts_edit_user_fields_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_new_serve_cfg_page.c : cnts_new_serve_cfg_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp
csp_cnts_save_file_action.c : cnts_save_file_action.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_reload_file_action.c : cnts_reload_file_action.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_start_edit_action.c : cnts_start_edit_action.csp includes.csp stdvars.csp header.csp footer.csp
csp_cnts_start_edit_problem_action.c : cnts_start_edit_problem_action.csp includes.csp stdvars.csp header.csp footer.csp
csp_contest_already_edited_page.c : contest_already_edited_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_contest_locked_page.c : contest_locked_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_contest_page.c : contest_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_contest_xml_page.c : contest_xml_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_create_contest_page.c : create_contest_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_create_contest_2_action.c : create_contest_2_action.csp includes.csp stdvars.csp header.csp footer.csp
csp_login_page.c : main_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_main_page.c : main_page.csp includes.csp stdvars.csp header.csp footer.csp
csp_problem_packages_page.c : problem_packages_page.csp includes.csp stdvars.csp header.csp footer.csp

csp_error_unknown_page.c : error_unknown_page.csp includes.csp stdvars.csp header.csp footer.csp

csp_%.c : %.csp
	../../ej-page-gen -x none -o $@ -d $*.ds $<

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.so : %.o
	$(CC) $(LDFLAGS) $< -o $@

