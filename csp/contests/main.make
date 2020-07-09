# -*- Makefile -*-

# Copyright (C) 2014-2020 Alexander Chernov <cher@ejudge.ru> */

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
CCOMPFLAGS=-D_GNU_SOURCE -std=gnu11 -I../.. -I../../include -g -DPIC -fPIC
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
 csp_int_standings.so\
 csp_int_public_log.so\
 csp_priv_add_review_comment_action.so\
 csp_priv_api_keys_page.so\
 csp_priv_assign_cyphers_page.so\
 csp_priv_audit_log_page.so\
 csp_priv_clar_page.so\
 csp_priv_crop_avatar_page.so\
 csp_priv_create_api_key.so\
 csp_priv_delete_api_key.so\
 csp_priv_download_runs_confirmation_page.so\
 csp_priv_edit_clar_page.so\
 csp_priv_edit_run_page.so\
 csp_priv_exam_info_page.so\
 csp_priv_ip_users_page.so\
 csp_priv_language_stats_page.so\
 csp_priv_problem_stats_page.so\
 csp_priv_login_page.so\
 csp_priv_main_page.so\
 csp_priv_new_run_page.so\
 csp_priv_online_users_page.so\
 csp_priv_passwords_page.so\
 csp_priv_priorities_page.so\
 csp_priv_priv_users_page.so\
 csp_priv_reload_statement_action.so\
 csp_priv_report_page.so\
 csp_priv_save_cropped_avatar_ajax.so\
 csp_priv_settings_page.so\
 csp_priv_source_page.so\
 csp_priv_standings_page.so\
 csp_priv_submit_page.so\
 csp_priv_testing_queue_page.so\
 csp_priv_tokenize_displayed_1_page.so\
 csp_priv_upsolving_page.so\
 csp_priv_user_ips_page.so\
 csp_priv_user_info_page.so\
 csp_priv_users_page.so\
 csp_priv_users_new_page.so\
 csp_priv_users_new_ajax.so\
 csp_priv_error_internal.so\
 csp_priv_error_inv_param.so\
 csp_priv_error_no_perm.so\
 csp_priv_error_oper_failed.so\
 csp_priv_error_unknown.so\
 csp_priv_error_userlist_server_down.so\
 csp_reg_contests_page.so\
 csp_reg_create_page.so\
 csp_reg_crop_avatar_page.so\
 csp_reg_edit_page.so\
 csp_reg_login_page.so\
 csp_reg_main_page.so\
 csp_reg_save_cropped_avatar_ajax.so\
 csp_reg_error_internal.so\
 csp_reg_error_inv_param.so\
 csp_reg_error_inv_session.so\
 csp_reg_error_no_perm.so\
 csp_reg_error_simple_registered.so\
 csp_reg_error_unknown.so\
 csp_reg_error_userlist_server_down.so\
 csp_unpriv_api_keys_page.so\
 csp_unpriv_clar_page.so\
 csp_unpriv_contests_page.so\
 csp_unpriv_create_api_key.so\
 csp_unpriv_delete_api_key.so\
 csp_unpriv_login_page.so\
 csp_unpriv_main_page.so\
 csp_unpriv_recover_1_page.so\
 csp_unpriv_recover_2_page.so\
 csp_unpriv_recover_3_page.so\
 csp_unpriv_report_page.so\
 csp_unpriv_source_page.so\
 csp_unpriv_standings_page.so\
 csp_unpriv_error_cnts_unavailable.so\
 csp_unpriv_error_disqualified.so\
 csp_unpriv_error_internal.so\
 csp_unpriv_error_inv_param.so\
 csp_unpriv_error_no_perm.so\
 csp_unpriv_error_oper_failed.so\
 csp_unpriv_error_registration_incomplete.so\
 csp_unpriv_error_service_not_available.so\
 csp_unpriv_error_unknown.so\
 csp_unpriv_error_userlist_server_down.so

CFILES = $(SOFILES:.so=.c) I_priv_ip_users_page.c  I_priv_priv_users_page.c  I_priv_user_ips_page.c I_priv_users_new_ajax.c I_int_standings.c

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
csp_priv_users_new_ajax.so : csp_priv_users_new_ajax.c I_priv_users_new_ajax.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@

csp_int_standings.so : csp_int_standings.c I_int_standings.c
	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@
#csp_int_public_log.so : csp_int_public_log.c I_int_public_log.c
#	$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) $^ -o $@

po : contests.po
contests.po : $(CFILES)
	${XGETTEXT} -d ejudge --no-location --foreign-user  -k_ -k__ -s -o $@ *.c

csp_priv_add_review_comment_action.c : priv_add_review_comment_action.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_api_keys_page.c : priv_api_keys_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_assign_cyphers_page.c : priv_assign_cyphers_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_audit_log_page.c : priv_audit_log_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_clar_page.c : priv_clar_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_create_api_key.c : priv_create_api_key.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_delete_api_key.c : priv_delete_api_key.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_download_runs_confirmation_page.c : priv_download_runs_confirmation_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_edit_run_page.c: priv_edit_run_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_edit_clar_page.c: priv_edit_clar_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_exam_info_page.c: priv_exam_info_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_ip_users_page.c : priv_ip_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_language_stats_page.c : priv_language_stats_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_problem_stats_page.c : priv_problem_stats_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_login_page.c : priv_login_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_main_page.c : priv_main_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_new_run_page.c : priv_new_run_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_online_users_page.c : priv_online_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_passwords_page.c : priv_passwords_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_priorities_page.c : priv_priorities_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_priv_users_page.c : priv_priv_users_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_reload_statement_action.c : priv_reload_statement_action.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
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
csp_priv_users_new_page.c : priv_users_new_page.csp priv_includes.csp priv_stdvars.csp priv_header_jq.csp priv_footer.csp
csp_priv_users_new_ajax.c : priv_users_new_ajax.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_tokenize_displayed_1_page.c : priv_tokenize_displayed_1_page.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_crop_avatar_page.c : priv_crop_avatar_page.csp priv_includes.csp priv_stdvars.csp priv_header_croppie.csp priv_footer.csp
csp_priv_save_cropped_avatar_ajax.c : priv_save_cropped_avatar_ajax.csp priv_includes.csp priv_stdvars.csp

csp_priv_error_internal.c : priv_error_internal.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_error_inv_param.c : priv_error_inv_param.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_error_no_perm.c : priv_error_no_perm.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_error_oper_failed.c : priv_error_oper_failed.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_error_unknown.c : priv_error_unknown.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp
csp_priv_error_userlist_server_down.c : priv_error_userlist_server_down.csp priv_includes.csp priv_stdvars.csp priv_header.csp priv_footer.csp

UNPRIV_DEPS = unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_simple_header.csp unpriv_menu.csp unpriv_status.csp unpriv_separator.csp unpriv_footer.csp

csp_unpriv_api_keys_page.c : unpriv_api_keys_page.csp $(UNPRIV_DEPS)
csp_unpriv_clar_page.c : unpriv_clar_page.csp $(UNPRIV_DEPS)
csp_unpriv_contests_page.c : unpriv_contests_page.csp $(UNPRIV_DEPS)
csp_unpriv_create_api_key.c : unpriv_create_api_key.csp $(UNPRIV_DEPS)
csp_unpriv_delete_api_key.c : unpriv_delete_api_key.csp $(UNPRIV_DEPS)
csp_unpriv_login_page.c : unpriv_login_page.csp $(UNPRIV_DEPS)
csp_unpriv_main_page.c : unpriv_main_page.csp unpriv_main_clars.csp unpriv_main_clar_submit.csp unpriv_main_info.csp unpriv_main_runs.csp unpriv_main_run_submit.csp unpriv_main_settings.csp unpriv_main_startstop.csp unpriv_main_statements.csp unpriv_main_summary.csp $(UNPRIV_DEPS)
csp_unpriv_recover_1_page.c : unpriv_recover_1_page.csp $(UNPRIV_DEPS)
csp_unpriv_recover_2_page.c : unpriv_recover_2_page.csp $(UNPRIV_DEPS)
csp_unpriv_recover_3_page.c : unpriv_recover_3_page.csp $(UNPRIV_DEPS)
csp_unpriv_report_page.c : unpriv_report_page.csp $(UNPRIV_DEPS)
csp_unpriv_source_page.c : unpriv_source_page.csp $(UNPRIV_DEPS)
csp_unpriv_standings_page.c : unpriv_standings_page.csp $(UNPRIV_DEPS)

csp_unpriv_error_cnts_unavailable.c : unpriv_error_cnts_unavailable.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_disqualified.c : unpriv_error_disqualified.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_internal.c : unpriv_error_internal.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_inv_param.c : unpriv_error_inv_param.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_no_perm.c : unpriv_error_no_perm.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_oper_failed.c : unpriv_error_oper_failed.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_registration_incomplete.c : unpriv_error_registration_incomplete.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_service_not_available.c : unpriv_error_service_not_available.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_unknown.c : unpriv_error_unknown.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp
csp_unpriv_error_userlist_server_down.c : unpriv_error_userlist_server_down.csp unpriv_includes.csp unpriv_stdvars.csp unpriv_header.csp unpriv_menu.csp unpriv_footer.csp

csp_reg_contests_page.c : reg_contests_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_create_page.c : reg_create_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_crop_avatar_page.c : reg_crop_avatar_page.csp reg_includes.csp reg_stdvars.csp reg_header_croppie.csp reg_separator.csp reg_footer.csp
csp_reg_edit_page.c : reg_edit_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_login_page.c : reg_login_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_footer.csp
csp_reg_main_page.c : reg_main_page.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_separator.csp reg_main_settings.csp reg_footer.csp
csp_reg_save_cropped_avatar_ajax.c : reg_save_cropped_avatar_ajax.csp reg_includes.csp reg_stdvars.csp

csp_int_standings.c : int_standings.csp int_standings_cell.csp
csp_int_public_log.c : int_public_log.csp

csp_reg_csp_error_internal.c : reg_error_internal.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp
csp_reg_csp_error_inv_param.c : reg_error_inv_param.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp
csp_reg_csp_error_inv_session.c : reg_error_inv_session.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp
csp_reg_csp_error_no_perm.c : reg_error_no_perm.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp
csp_reg_csp_error_simple_registered.c : reg_error_simple_registered.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp
csp_reg_csp_error_unknown.c : reg_error_unknown.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp
csp_reg_csp_error_userlist_server_down.c : reg_error_userlist_server_down.csp reg_includes.csp reg_stdvars.csp reg_header.csp reg_footer.csp

csp_%.c : %.csp
	../../ej-page-gen -x none -o $@ -d $*.ds $<

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.so : %.o
	$(CC) $(LDFLAGS) $< -o $@

