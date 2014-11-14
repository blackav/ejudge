/*
    Copyright (C) 2006 Silicon Graphics, Inc.  All Rights Reserved.
    Portions Copyright (C) 2009-2011 David Anderson. All Rights Reserved.

    This program is free software; you can redistribute it and/or modify it
    under the terms of version 2 of the GNU General Public License as
    published by the Free Software Foundation.

    This program is distributed in the hope that it would be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Further, this software is distributed without any warranty that it is
    free of the rightful claim of any third person regarding infringement
    or the like.  Any license provided herein, whether implied or
    otherwise, applies only to this software file.  Patent licenses, if
    any, provided herein do not apply to combinations of this program with
    other software, or any other product whatsoever.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street - Fifth Floor, Boston MA 02110-1301, USA.

    Contact information:  Silicon Graphics, Inc., 1500 Crittenden Lane,
    Mountain View, CA 94043, or:

    http://www.sgi.com

    For further information regarding this notice, see:

    http://oss.sgi.com/projects/GenInfo/NoticeExplan


*/


extern int dwarf_names_print_on_error;

void deal_with_name_offset_err(Dwarf_Debug dbg,
    char *err_loc,
    char *name,
    Dwarf_Unsigned die_off,
    int nres,
    Dwarf_Error err);

Dwarf_Unsigned get_info_max_offset(Dwarf_Debug dbg);

void print_pubname_style_entry(Dwarf_Debug dbg,
    char *line_title,
    char *name,
    Dwarf_Unsigned die_off,
    Dwarf_Unsigned cu_off,
    Dwarf_Unsigned global_cu_off,
    Dwarf_Unsigned maxoff);
