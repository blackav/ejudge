# -*- Makefile -*-
# $Id$

# Copyright (C) 2011-2014 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

META_C_FILES = contests_meta.c super-serve_meta.c prepare_meta.c super_html_6_meta.c super_run_packet_meta.c problem_config_meta.c polygon_packet_meta.c ej_import_packet_meta.c new_server_match.c
META_H_FILES = $(META_C_FILES:.c=.h)
META_O_FILES = $(META_C_FILES:.c=.o)

CSP_C_FILES = csp/contests/priv_main_page.c
CSP_O_FILES = $(CSP_C_FILES:.c=.o)

META_CC = ./cfront/ej-cfront
META_CC_FLAGS = -B cfront/ -I cfront/include/stdlib -I include -I .

contests_meta.c contests_meta.h : $(META_CC) contests.h
	$(META_CC) $(META_CC_FLAGS) contests.h -o contests.out --force-h --meta --meta-struct contest_desc --meta-enum-prefix CNTS --meta-func-prefix contest_desc 

super-serve_meta.c super-serve_meta.h : $(META_CC) super-serve.h
	$(META_CC) $(META_CC_FLAGS) super-serve.h -o super-serve.out --force-h --meta --meta-struct sid_state --meta-enum-prefix SSSS --meta-func-prefix ss_sid_state

prepare_meta.c prepare_meta.h : $(META_CC) prepare.h
	$(META_CC) $(META_CC_FLAGS) prepare.h -o prepare.out --force-h --meta --meta-struct section_global_data --meta-struct section_problem_data --meta-struct section_language_data --meta-struct section_tester_data --meta-enum-prefix CNTSGLOB --meta-enum-prefix CNTSPROB --meta-enum-prefix CNTSLANG --meta-enum-prefix CNTSTESTER --meta-func-prefix cntsglob --meta-func-prefix cntsprob --meta-func-prefix cntslang --meta-func-prefix cntstester

super_html_6_meta.c super_html_6_meta.h : $(META_CC) super_html_6.h
	$(META_CC) $(META_CC_FLAGS) super_html_6.h -o super_html_6.out --force-h --meta --meta-struct ss_op_param_USER_CREATE_ONE_ACTION --meta-struct ss_op_param_USER_CREATE_MANY_ACTION --meta-struct ss_op_param_USER_CREATE_FROM_CSV_ACTION --meta-struct ss_op_param_USER_CREATE_REG_ACTION --meta-struct ss_op_param_USER_EDIT_REG_ACTION

super_run_packet_meta.c super_run_packet_meta.h : $(META_CC) super_run_packet.h
	$(META_CC) $(META_CC_FLAGS) super_run_packet.h -o super_run_packet.out --force-h --meta --meta-struct super_run_in_global_packet --meta-struct super_run_in_problem_packet --meta-struct super_run_in_tester_packet

problem_config_meta.c problem_config_meta.h : $(META_CC) problem_config.h
	$(META_CC) $(META_CC_FLAGS) problem_config.h -o problem_config.out --force-h --meta --meta-struct problem_config_section

polygon_packet_meta.c polygon_packet_meta.h : $(META_CC) polygon_packet.h
	$(META_CC) $(META_CC_FLAGS) polygon_packet.h -o polygon_packet.out --force-h --meta --meta-struct polygon_packet

ej_import_packet_meta.c ej_import_packet_meta.h : $(META_CC) ej_import_packet.h
	$(META_CC) $(META_CC_FLAGS) ej_import_packet.h -o ej_import_packet.out --force-h --meta --meta-struct ej_import_packet

new_server_match.c : genmatcher new_server_at.c
	./genmatcher > new_server_match.c

genmatcher : genmatcher.c new-server.h new_server_at.c
	$(CC) $(CFLAGS) $< -o $@

csp/contests/priv_main_page.c : ej-page-gen csp/contests/priv_main_page.csp
	./ej-page-gen csp/contests/priv_main_page.csp > csp/contests/priv_main_page.c

csp/contests/%.o : csp/contests/%.c
	$(CC) $(CFLAGS) -fPIC -DPIC -c $<
