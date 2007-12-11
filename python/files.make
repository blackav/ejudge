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

USERLIST_CLNT_MODULES = \
 ../userlist_clnt/admin_process.c\
 ../userlist_clnt/change_registration.c\
 ../userlist_clnt/close.c\
 ../userlist_clnt/cnts_passwd_op.c\
 ../userlist_clnt/control.c\
 ../userlist_clnt/copy_user_info.c\
 ../userlist_clnt/create_member.c\
 ../userlist_clnt/create_user.c\
 ../userlist_clnt/delete_cookie.c\
 ../userlist_clnt/delete_field.c\
 ../userlist_clnt/delete_info.c\
 ../userlist_clnt/do_pass_fd.c\
 ../userlist_clnt/edit_field.c\
 ../userlist_clnt/get_cookie.c\
 ../userlist_clnt/get_database.c\
 ../userlist_clnt/get_fd.c\
 ../userlist_clnt/get_info.c\
 ../userlist_clnt/import_csv_users.c\
 ../userlist_clnt/list_all_users.c\
 ../userlist_clnt/login.c\
 ../userlist_clnt/logout.c\
 ../userlist_clnt/lookup_cookie.c\
 ../userlist_clnt/lookup_user.c\
 ../userlist_clnt/lookup_user_id.c\
 ../userlist_clnt/move_member.c\
 ../userlist_clnt/open.c\
 ../userlist_clnt/pass_fd.c\
 ../userlist_clnt/priv_cookie.c\
 ../userlist_clnt/priv_login.c\
 ../userlist_clnt/read_and_notify.c\
 ../userlist_clnt/recv_packet.c\
 ../userlist_clnt/register_contest.c\
 ../userlist_clnt/register_new_2.c\
 ../userlist_clnt/send_packet.c\
 ../userlist_clnt/set_cookie.c\
 ../userlist_clnt/set_passwd.c\
 ../userlist_clnt/team_cookie.c\
 ../userlist_proto.c\
 ../xml_utils/parse_ip.c

