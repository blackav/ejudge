# -*- Makefile -*-
# $Id$

# Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

CFILES=\
 base64.c\
 cgi.c\
 clar.c\
 clarlog.c\
 clntutil.c\
 compile.c\
 html.c\
 idmap.c\
 inetdb.c\
 localdb.c\
 make-teamdb-inet.c\
 make-teamdb.c\
 master.c\
 misctext.c\
 mkpasswd.c\
 nls.c\
 nls_cp1251.c\
 nls_cp866.c\
 nls_iso8859-5.c\
 nls_koi8-r.c\
 nls_utf8.c\
 parsecfg.c\
 pathutl.c\
 prepare.c\
 register.c\
 run.c\
 runlog.c\
 send-passwords.c\
 serve.c\
 sformat.c\
 sha.c\
 submit.c\
 team.c\
 teamdb.c\
 userlist.c\
 userlist-server.c\
 userlist_cfg.c\
 userlist_clnt.c\
 userlist_xml.c\
 utf8_utils.c\
 unix/fileutl.c\
 win32/fileutl.c

HFILES=\
 base64.h\
 cgi.h\
 clarlog.h\
 clntutil.h\
 fileutl.h\
 html.h\
 idmap.h\
 inetdb.h\
 localdb.h\
 misctext.h\
 nls.h\
 parsecfg.h\
 pathutl.h\
 prepare.h\
 protocol.h\
 runlog.h\
 sformat.h\
 sha.h\
 teamdb.h\
 userlist.h\
 userlist_cfg.h\
 userlist_clnt.h\
 utf8_utils.h\
 version.h\
 unix/unix_fileutl.h
