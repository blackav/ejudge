# -*- Makefile -*-
# $Id$

# Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

CFILES=\
 in_close.c\
 team_close.c\
 corr_close.c\
 eq_double.c\
 eq_float.c\
 eq_long_double.c\
 eq_sexpr.c\
 in_eof.c\
 team_eof.c\
 corr_eof.c\
 in_eoln.c\
 team_eoln.c\
 corr_eoln.c\
 normalize_file.c\
 normalize_spaces_in_file.c\
 normalize_line.c\
 skip_eoln.c\
 read_buf.c\
 read_file_by_line.c\
 read_file_by_line_f.c\
 read_file.c\
 read_file_f.c\
 read_line.c\
 read_int.c\
 read_unsigned_int.c\
 read_long_long.c\
 read_unsigned_long_long.c\
 read_double.c\
 read_long_double.c\
 read_in_int.c\
 read_in_unsigned_int.c\
 read_in_long_long.c\
 read_in_unsigned_long_long.c\
 read_in_double.c\
 read_in_long_double.c\
 read_team_int.c\
 read_team_unsigned_int.c\
 read_team_long_long.c\
 read_team_unsigned_long_long.c\
 read_team_double.c\
 read_team_long_double.c\
 read_corr_int.c\
 read_corr_unsigned_int.c\
 read_corr_long_long.c\
 read_corr_unsigned_long_long.c\
 read_corr_double.c\
 read_corr_long_double.c\
 read_sexpr.c\
 ok.c\
 fatal.c\
 fatal_cf.c\
 fatal_pe.c\
 fatal_read.c\
 fatal_wa.c\
 init.c\
 vars.c\
 xcalloc.c\
 xmalloc.c\
 xrealloc.c\
 xstrdup.c

CHKCFILES =\
 cmp_bytes.c\
 cmp_double.c\
 cmp_double_seq.c\
 cmp_int.c\
 cmp_int_seq.c\
 cmp_unsigned_int.c\
 cmp_unsigned_int_seq.c\
 cmp_long_double.c\
 cmp_long_double_seq.c\
 cmp_long_long.c\
 cmp_long_long_seq.c\
 cmp_unsigned_long_long.c\
 cmp_unsigned_long_long_seq.c\
 cmp_huge_int.c\
 cmp_file.c\
 cmp_file_nospace.c\
 cmp_sexpr.c\
 cmp_yesno.c
