/*

  Copyright (C) 2000 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2008-2011  David Anderson. All Rights Reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2.1 of the GNU Lesser General Public License
  as published by the Free Software Foundation.

  This program is distributed in the hope that it would be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

  Further, this software is distributed without any warranty that it is
  free of the rightful claim of any third person regarding infringement
  or the like.  Any license provided herein, whether implied or
  otherwise, applies only to this software file.  Patent licenses, if
  any, provided herein do not apply to combinations of this program with
  other software, or any other product whatsoever.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write the Free Software
  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston MA 02110-1301,
  USA.

  Contact information:  Silicon Graphics, Inc., 1500 Crittenden Lane,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan

*/




/*
    This struct holds information about a abbreviation.
    It is put in the hash table for abbreviations for
    a compile-unit.
*/
struct Dwarf_Abbrev_List_s {
    Dwarf_Unsigned ab_code;
    Dwarf_Half ab_tag;
    Dwarf_Half ab_has_child;

    /*  Points to start of attribute and form pairs in the .debug_abbrev
        section for the abbrev. */
    Dwarf_Byte_Ptr ab_abbrev_ptr;

    struct Dwarf_Abbrev_List_s *ab_next;
};
