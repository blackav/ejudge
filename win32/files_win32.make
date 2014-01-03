# -*- Makefile -*-
# $Id$

# Copyright (C) 2009-2014 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

WIN32_COMMON_CFILES=\
 base64.c\
 charsets.c\
 clarlog.c\
 contests.c\
 compile_packet_1.c\
 compile_packet_3.c\
 compile_packet_5.c\
 digest_3.c\
 digest_4.c\
 ejudge_cfg.c\
 ej_uuid.c\
 errlog.c\
 expat_iface.c\
 filehash.c\
 filter_expr.c\
 filter_tree.c\
 l10n.c\
 lang_config.c\
 meta_generic.c\
 mime_type.c\
 misctext.c\
 nwrun_packet.c\
 opcaps.c\
 parsecfg.c\
 pathutl.c\
 prepare.c\
 prepare_serve.c\
 problem_common.c\
 problem_xml.c\
 protocol.c\
 random.c\
 run_common.c\
 run_inverse.c\
 runlog.c\
 runlog_static.c\
 run_packet_5.c\
 serve_state.c\
 sformat.c\
 sha.c\
 shellcfg_parse.c\
 team_extra.c\
 testinfo.c\
 testing_report_xml.c\
 tsc.c\
 userlist.c\
 userlist_proto.c\
 userlist_xml.c\
 varsubst.c\
 version.c\
 watched_file.c\
 xml_utils/attr_bool.c\
 xml_utils/attr_bool_byte.c\
 xml_utils/attr_date.c\
 xml_utils/attr_int.c\
 xml_utils/attr_ulong.c\
 xml_utils/elem_ip_mask.c\
 xml_utils/empty_text.c\
 xml_utils/err_attrs.c\
 xml_utils/err_attr_invalid.c\
 xml_utils/err_attr_not_allowed.c\
 xml_utils/err_attr_undefined.c\
 xml_utils/err_attr_undefined_s.c\
 xml_utils/err_elem_empty.c\
 xml_utils/err_elem_invalid.c\
 xml_utils/err_elem_not_allowed.c\
 xml_utils/err_elem_redefined.c\
 xml_utils/err_elem_undefined.c\
 xml_utils/err_elem_undefined_s.c\
 xml_utils/err_get_attr_name.c\
 xml_utils/err_get_elem_name.c\
 xml_utils/err_nested_elems.c\
 xml_utils/err_top_level.c\
 xml_utils/err_top_level_s.c\
 xml_utils/err_variables.c\
 xml_utils/full_cookie.c\
 xml_utils/leaf_elem.c\
 xml_utils/parse_bool.c\
 xml_utils/parse_date.c\
 xml_utils/parse_int.c\
 xml_utils/parse_ip.c\
 xml_utils/parse_ip_mask.c\
 xml_utils/unparse_bool.c\
 xml_utils/unparse_date.c\
 xml_utils/unparse_ip.c\
 xml_utils/unparse_ip_mask.c\
 xml_utils/unparse_run_status.c\
 xml_utils/unparse_text.c\
 xml_utils/xml_err.c\
 xml_utils/xml_err_a.c\
 reuse/reuse_xalloc.c\
 reuse/reuse_xcalloc.c\
 reuse/reuse_xexpand.c\
 reuse/reuse_xexpand2.c\
 reuse/reuse_xfree.c\
 reuse/reuse_xmalloc.c\
 reuse/reuse_xmemdup.c\
 reuse/reuse_xrealloc.c\
 reuse/reuse_xstrarrayfree.c\
 reuse/reuse_xstrdup.c

WIN32_PLATFORM_CFILES =\
 pathutl.c\
 $(ARCH)/cpu.c\
 $(ARCH)/cr_serialize.c\
 $(ARCH)/curtime.c\
 $(ARCH)/ej_process.c\
 $(ARCH)/fileutl.c\
 $(ARCH)/fmemopen.c\
 $(ARCH)/full_archive.c\
 $(ARCH)/interrupt.c\
 $(ARCH)/open_memstream.c\
 $(ARCH)/reuse_checkaccess.c\
 $(ARCH)/reuse_dirname.c\
 $(ARCH)/reuse_getlastname.c\
 $(ARCH)/reuse_getsignalstring.c\
 $(ARCH)/reuse_getworkingdir.c\
 $(ARCH)/reuse_errormsg.c\
 $(ARCH)/reuse_exec.c\
 $(ARCH)/reuse_getsignalstring.c\
 $(ARCH)/reuse_isabsolutepath.c\
 $(ARCH)/reuse_isfile.c\
 $(ARCH)/reuse_logger.c\
 $(ARCH)/reuse_makedirpath.c\
 $(ARCH)/reuse_nodename.c\
 $(ARCH)/reuse_normalize_path.c\
 $(ARCH)/reuse_rgetworkingdir.c\
 $(ARCH)/reuse_sleep.c\
 $(ARCH)/sock_op_enable_creds.c\
 $(ARCH)/sock_op_get_creds.c\
 $(ARCH)/sock_op_get_fds.c\
 $(ARCH)/sock_op_put_creds.c\
 $(ARCH)/sock_op_put_fds.c\
 $(ARCH)/startstop.c\
 $(ARCH)/timestamp.c
