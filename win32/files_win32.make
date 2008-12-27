# $Id$

WIN32_COMMON_CFILES=\
 compile_packet_1.c\
 compile_packet_3.c\
 compile_packet_5.c\
 ejudge_cfg.c\
 errlog.c\
 lang_config.c\
 meta_generic.c\
 parsecfg.c\
 pathutl.c\
 prepare.c\
 problem_common.c\
 problem_xml.c\
 sformat.c\
 shellcfg_parse.c\
 userlist.c\
 userlist_xml.c\
 varsubst.c\
 xml_utils/unparse_bool.c\
 xml_utils/unparse_date.c

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
 $(ARCH)/sock_op_enable_creds.c\
 $(ARCH)/sock_op_get_creds.c\
 $(ARCH)/sock_op_get_fds.c\
 $(ARCH)/sock_op_put_creds.c\
 $(ARCH)/sock_op_put_fds.c\
 $(ARCH)/startstop.c\
 $(ARCH)/timestamp.c
