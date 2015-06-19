# -*- Makefile -*-

# Copyright (C) 2014-2015 Alexander Chernov <cher@ejudge.ru> */

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
 csp_cnts_edit_cur_languages_page.c\
 csp_cnts_edit_cur_problems_page.c\
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
 csp_user_browse_page.c\
 csp_user_browse_data.c\
 csp_get_contest_list.c\
 csp_cnts_save_basic_form.c\
 csp_cnts_save_flags_form.c\
 csp_cnts_save_registration_form.c\
 csp_cnts_save_timing_form.c\
 csp_cnts_save_urls_form.c\
 csp_cnts_save_headers_form.c\
 csp_cnts_save_attrs_form.c\
 csp_cnts_save_notifications_form.c\
 csp_cnts_save_advanced_form.c\
 csp_glob_save_main_form.c\
 csp_glob_save_capabilities_form.c\
 csp_glob_save_files_form.c\
 csp_glob_save_quotas_form.c\
 csp_glob_save_urls_form.c\
 csp_glob_save_attrs_form.c\
 csp_glob_save_advanced_form.c\
 csp_glob_save_limits_form.c\
 csp_lang_save_main_form.c\
 csp_prob_save_id_form.c\
 csp_prob_save_files_form.c\
 csp_prob_save_validation_form.c\
 csp_prob_save_view_form.c\
 csp_prob_save_submission_form.c\
 csp_prob_save_compiling_form.c\
 csp_prob_save_running_form.c\
 csp_prob_save_limits_form.c\
 csp_prob_save_checking_form.c\
 csp_prob_save_scoring_form.c\
 csp_prob_save_feedback_form.c\
 csp_prob_save_standing_form.c\
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
csp_cnts_edit_cur_languages_page.c : cnts_edit_cur_languages_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_cur_problems_page.c : cnts_edit_cur_problems_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp
csp_cnts_edit_cur_problem_page.c : cnts_edit_cur_problem_page.csp includes.csp stdvars.csp header.csp footer.csp cnts_edit_cur_top_menu.csp cnts_edit_cur_bottom_menu.csp cnts_edit_cur_problem_submission.csp cnts_edit_cur_problem_compiling.csp cnts_edit_cur_problem_running.csp cnts_edit_cur_problem_limits.csp cnts_edit_cur_problem_checking.csp cnts_edit_cur_problem_scoring.csp cnts_edit_cur_problem_feedback.csp cnts_edit_cur_problem_standing.csp cnts_edit_cur_problem_macros.csp
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
csp_user_browse_page.c : user_browse_page.csp includes.csp stdvars.csp header_jqgrid.csp footer.csp
csp_user_browse_data.c : user_browse_data.csp includes.csp stdvars.csp
csp_get_contest_list.c : get_contest_list.csp includes.csp stdvars.csp
csp_cnts_save_basic_form.c : cnts_save_basic_form.csp includes.csp stdvars.csp
csp_cnts_save_flags_form.c : cnts_save_flags_form.csp includes.csp stdvars.csp
csp_cnts_save_registration_form.c : cnts_save_registration_form.csp includes.csp stdvars.csp
csp_cnts_save_timing_form.c : cnts_save_timing_form.csp includes.csp stdvars.csp
csp_cnts_save_urls_form.c : cnts_save_urls_form.csp includes.csp stdvars.csp
csp_cnts_save_headers_form.c : cnts_save_headers_form.csp includes.csp stdvars.csp
csp_cnts_save_attrs_form.c : cnts_save_attrs_form.csp includes.csp stdvars.csp
csp_cnts_save_notifications_form.c : cnts_save_notifications_form.csp includes.csp stdvars.csp
csp_cnts_save_advanced_form.c : cnts_save_advanced_form.csp includes.csp stdvars.csp
csp_glob_save_main_form.c : glob_save_main_form.csp includes.csp stdvars.csp
csp_glob_save_capabilities_form.c : glob_save_capabilities_form.csp includes.csp stdvars.csp
csp_glob_save_files_form.c : glob_save_files_form.csp includes.csp stdvars.csp
csp_glob_save_quotas_form.c : glob_save_quotas_form.csp includes.csp stdvars.csp
csp_glob_save_urls_form.c : glob_save_urls_form.csp includes.csp stdvars.csp
csp_glob_save_attrs_form.c : glob_save_attrs_form.csp includes.csp stdvars.csp
csp_glob_save_advanced_form.c : glob_save_advanced_form.csp includes.csp stdvars.csp
csp_glob_save_limits_form.c : glob_save_limits_form.csp includes.csp stdvars.csp
csp_lang_save_main_form.c : lang_save_main_form.csp includes.csp stdvars.csp
csp_prob_save_id_form.c : prob_save_id_form.csp includes.csp stdvars.csp
csp_prob_save_files_form.c : prob_save_files_form.csp includes.csp stdvars.csp
csp_prob_save_validation_form.c : prob_save_validation_form.csp includes.csp stdvars.csp
csp_prob_save_view_form.c : prob_save_view_form.csp includes.csp stdvars.csp
csp_prob_save_submission_form.c : prob_save_submission_form.csp includes.csp stdvars.csp
csp_prob_save_compiling_form.c : prob_save_compiling_form.csp includes.csp stdvars.csp
csp_prob_save_running_form.c : prob_save_running_form.csp includes.csp stdvars.csp
csp_prob_save_limits_form.c : prob_save_limits_form.csp includes.csp stdvars.csp
csp_prob_save_checking_form.c : prob_save_checking_form.csp includes.csp stdvars.csp
csp_prob_save_scoring_form.c : prob_save_scoring_form.csp includes.csp stdvars.csp
csp_prob_save_feedback_form.c : prob_save_feedback_form.csp includes.csp stdvars.csp
csp_prob_save_standing_form.c : prob_save_standing_form.csp includes.csp stdvars.csp

csp_error_unknown_page.c : error_unknown_page.csp includes.csp stdvars.csp header.csp footer.csp

csp_%.c : %.csp
	../../ej-page-gen -x none -o $@ -d $*.ds $<

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.so : %.o
	$(CC) $(LDFLAGS) $< -o $@

