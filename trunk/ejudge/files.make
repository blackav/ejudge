# -*- Makefile -*-
# $Id$

# Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

USERLIST_CLNT_CFILES=\
 userlist_clnt/add_field.c\
 userlist_clnt/admin_process.c\
 userlist_clnt/change_registration.c\
 userlist_clnt/clear_team_passwords.c\
 userlist_clnt/close.c\
 userlist_clnt/delete_field.c\
 userlist_clnt/do_pass_fd.c\
 userlist_clnt/dump_database.c\
 userlist_clnt/edit_field.c\
 userlist_clnt/generate_team_passwd.c\
 userlist_clnt/get_contests.c\
 userlist_clnt/get_info.c\
 userlist_clnt/get_uid_by_pid.c\
 userlist_clnt/list_all_users.c\
 userlist_clnt/list_users.c\
 userlist_clnt/login.c\
 userlist_clnt/logout.c\
 userlist_clnt/lookup_cookie.c\
 userlist_clnt/map_contest.c\
 userlist_clnt/open.c\
 userlist_clnt/pass_fd.c\
 userlist_clnt/priv_cookie.c\
 userlist_clnt/priv_login.c\
 userlist_clnt/recv_packet.c\
 userlist_clnt/register_contest.c\
 userlist_clnt/register_new.c\
 userlist_clnt/remove_member.c\
 userlist_clnt/send_packet.c\
 userlist_clnt/set_info.c\
 userlist_clnt/set_passwd.c\
 userlist_clnt/team_cookie.c\
 userlist_clnt/team_login.c\
 userlist_clnt/team_set_passwd.c

SERVE_CLNT_CFILES=\
 serve_clnt/do_pass_fd.c\
 serve_clnt/edit_run.c\
 serve_clnt/get_archive.c\
 serve_clnt/import_xml_runs.c\
 serve_clnt/master_page.c\
 serve_clnt/message.c\
 serve_clnt/open.c\
 serve_clnt/pass_fd.c\
 serve_clnt/recv_packet.c\
 serve_clnt/send_packet.c\
 serve_clnt/show_item.c\
 serve_clnt/simple_cmd.c\
 serve_clnt/standings.c\
 serve_clnt/submit_clar.c\
 serve_clnt/submit_run.c\
 serve_clnt/team_page.c\
 serve_clnt/view.c

COMMON_CFILES=\
 base64.c\
 cgi.c\
 clarlog.c\
 clntutil.c\
 contests.c\
 copyright.c\
 cr_serialize.c\
 expat_iface.c\
 filter_eval.c\
 filter_tree.c\
 html.c\
 l10n.c\
 master_html.c\
 misctext.c\
 opcaps.c\
 parsecfg.c\
 pathutl.c\
 prepare.c\
 protocol.c\
 runlog.c\
 runlog_import.c\
 runlog_xml.c\
 sformat.c\
 sha.c\
 teamdb.c\
 testinfo.c\
 userlist.c\
 userlist_cfg.c\
 userlist_proto.c\
 userlist_xml.c

CFILES=\
 clar.c\
 clean-users.c\
 compile.c\
 edit-userlist.c\
 filter_test.c\
 idmap.c\
 inetdb.c\
 localdb.c\
 make-teamdb-inet.c\
 make-teamdb.c\
 master.c\
 mkpasswd.c\
 register.c\
 run.c\
 send-passwords.c\
 serve.c\
 submit.c\
 super-serve.c\
 team.c\
 testinfo.c\
 userlist-server.c\
 users.c\
 unix/fileutl.c\
 win32/fileutl.c\
 charsets/koi8_to_enc.c\
 charsets/koi8_to_enc_heap.c\
 charsets/koi8_to_enc_unchecked.c\
 charsets/nls.c\
 charsets/nls_cp1251.c\
 charsets/nls_cp866.c\
 charsets/nls_iso8859-5.c\
 charsets/nls_koi8-r.c\
 charsets/nls_utf8.c\
 charsets/utf8_to_enc.c\
 charsets/utf8_to_enc_heap.c\
 charsets/utf8_to_enc_unchecked.c\
 charsets/utf8_to_koi8.c\
 charsets/utf8_to_koi8_heap.c\
 charsets/utf8_to_koi8_unchecked.c\
 ${COMMON_CFILES}\
 ${SERVE_CLNT_CFILES}\
 ${USERLIST_CLNT_CFILES}

HFILES=\
 base64.h\
 cgi.h\
 clarlog.h\
 client_actions.h\
 clntutil.h\
 contests.h\
 copyright.h\
 cr_serialize.h\
 expat_iface.h\
 fileutl.h\
 filter_eval.h\
 filter_tree.h\
 html.h\
 idmap.h\
 inetdb.h\
 l10n.h\
 localdb.h\
 misctext.h\
 nls.h\
 opcaps.h\
 parsecfg.h\
 pathutl.h\
 prepare.h\
 protocol.h\
 runlog.h\
 serve_clnt.h\
 sformat.h\
 sha.h\
 teamdb.h\
 testinfo.h\
 userlist.h\
 userlist_cfg.h\
 userlist_clnt.h\
 version.h\
 unix/unix_fileutl.h\
 userlist_clnt/private.h

OTHERFILES=\
 filter_expr.y\
 filter_scan.lex
