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
SOFILES = \
 csp_priv_assign_cyphers_page.so\
 csp_priv_audit_log_page.so\
 csp_priv_clar_page.so\
 csp_priv_download_runs_confirmation_page.so\
 csp_priv_edit_clar_page.so\
 csp_priv_edit_run_page.so\
 csp_priv_exam_info_page.so\
 csp_priv_ip_users_page.so\
 csp_priv_login_page.so\
 csp_priv_main_page.so\
 csp_priv_new_run_page.so\
 csp_priv_online_users_page.so\
 csp_priv_passwords_page.so\
 csp_priv_priorities_page.so\
 csp_priv_priv_users_page.so\
 csp_priv_report_page.so\
 csp_priv_settings_page.so\
 csp_priv_source_page.so\
 csp_priv_standings_page.so\
 csp_priv_submit_page.so\
 csp_priv_testing_queue_page.so\
 csp_priv_upsolving_page.so\
 csp_priv_user_ips_page.so\
 csp_priv_user_info_page.so\
 csp_priv_users_page.so\
 csp_priv_error_unknown.so\
 csp_reg_contests_page.so\
 csp_reg_create_page.so\
 csp_reg_edit_page.so\
 csp_reg_login_page.so\
 csp_reg_main_page.so\
 csp_reg_error_unknown.so\
 csp_unpriv_clar_page.so\
 csp_unpriv_contests_page.so\
 csp_unpriv_login_page.so\
 csp_unpriv_main_page.so\
 csp_unpriv_recover_1_page.so\
 csp_unpriv_recover_2_page.so\
 csp_unpriv_recover_3_page.so\
 csp_unpriv_report_page.so\
 csp_unpriv_standings_page.so\
 csp_unpriv_error_unknown.so

CFILES = $(SOFILES:.so=.c) I_priv_ip_users_page.c  I_priv_priv_users_page.c  I_priv_user_ips_page.c

all : $(CFILES) $(SOFILES)

install : all
	#install -d "${DESTDIR}${TARGETDIR}"
	#for i in ${SOFILES}; do install -m 0755 $$i "${DESTDIR}${TARGETDIR}"; done
	install -d "${DESTDIR}${prefix}/share/ejudge/csp/contests"
	for i in *.csp I_*.c; do install -m 0644 $$i "${DESTDIR}${prefix}/share/ejudge/csp/contests"; done

clean : 
	-rm -f *.o *.so *.ds csp_*.c

csp_priv_priv_users_page.so : csp_priv_priv_users_page.c I_priv_priv_users_page.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@
csp_priv_user_ips_page.so : csp_priv_user_ips_page.c I_priv_user_ips_page.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@
csp_priv_ip_users_page.so : csp_priv_ip_users_page.c I_priv_ip_users_page.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@

po : contests.po
contests.po : $(CFILES)
	${XGETTEXT} -d ejudge --no-location --foreign-user  -k_ -k__ -s -o $@ *.c

csp_priv_assign_cyphers_page.c : priv_assign_cyphers_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_audit_log_page.c : priv_audit_log_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_clar_page.c : priv_clar_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_download_runs_confirmation_page.c : priv_download_runs_confirmation_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_edit_run_page.c: priv_edit_run_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_edit_clar_page.c: priv_edit_clar_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_exam_info_page.c: priv_exam_info_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_ip_users_page.c : priv_ip_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_login_page.c : priv_login_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_main_page.c : priv_main_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_new_run_page.c : priv_new_run_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_online_users_page.c : priv_online_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_passwords_page.c : priv_passwords_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_priorities_page.c : priv_priorities_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_priv_users_page.c : priv_priv_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_report_page.c : priv_report_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_settings_page.c : priv_settings_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_source_page.c : priv_source_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_standings_page.c : priv_standings_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_submit_page.c : priv_submit_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_testing_queue_page.c : priv_testing_queue_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_upsolving_page.c : priv_upsolving_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_user_ips_page.c : priv_user_ips_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_user_info_page.c : priv_user_info_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_users_page.c : priv_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp

csp_priv_error_unknown.c : priv_error_unknown.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp

UNPRIV_DEPS = unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_simple_header.csp unpriv_menu.csp unpriv_status.csp unpriv_separator.csp unpriv_footer.csp

csp_unpriv_clar_page.c : unpriv_clar_page.csp $(UNPRIV_DEPS)
csp_unpriv_contests_page.c : unpriv_contests_page.csp $(UNPRIV_DEPS)
csp_unpriv_login_page.c : unpriv_login_page.csp $(UNPRIV_DEPS)
csp_unpriv_main_page.c : unpriv_main_page.csp unpriv_main_clars.csp unpriv_main_clar_submit.csp unpriv_main_info.csp unpriv_main_runs.csp unpriv_main_run_submit.csp unpriv_main_settings.csp unpriv_main_startstop.csp unpriv_main_statements.csp unpriv_main_summary.csp $(UNPRIV_DEPS)
csp_unpriv_recover_1_page.c : unpriv_recover_1_page.csp $(UNPRIV_DEPS)
csp_unpriv_recover_2_page.c : unpriv_recover_2_page.csp $(UNPRIV_DEPS)
csp_unpriv_recover_3_page.c : unpriv_recover_3_page.csp $(UNPRIV_DEPS)
csp_unpriv_report_page.c : unpriv_report_page.csp $(UNPRIV_DEPS)
csp_unpriv_standings_page.c : unpriv_standings_page.csp $(UNPRIV_DEPS)

csp_unpriv_error_unknown.c : unpriv_error_unknown.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp

csp_reg_contests_page.c : reg_contests_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_create_page.c : reg_create_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_edit_page.c : reg_edit_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_login_page.c : reg_login_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_main_page.c : reg_main_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_main_settings.csp reg_footer.csp

csp_reg_csp_error_unknown.c : reg_error_unknown.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp

csp_%.c : %.csp
	../../ej-page-gen -x none -o $@ -d $*.ds $<

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.so : %.o
	$(CC) $(LDFLAGS) $< -o $@

