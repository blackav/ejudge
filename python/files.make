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
 ../userlist_clnt/open.c\
 ../userlist_clnt/close.c\
 ../userlist_clnt/send_packet.c\
 ../userlist_clnt/recv_packet.c\
 ../userlist_clnt/get_fd.c\
 ../userlist_clnt/pass_fd.c\
 ../userlist_clnt/do_pass_fd.c\
 ../userlist_clnt/read_and_notify.c\
 ../userlist_clnt/admin_process.c\
 ../userlist_clnt/login.c\
 ../userlist_clnt/register_new_2.c\
 ../userlist_clnt/create_user.c\
 ../userlist_clnt/edit_field.c\
 ../userlist_clnt/change_registration.c\
 ../userlist_clnt/register_contest.c\
 ../userlist_proto.c\
 ../xml_utils/parse_ip.c

