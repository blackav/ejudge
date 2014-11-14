/*
   Copyright (C) 2000,2005 Silicon Graphics, Inc.  All Rights Reserved.
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

/* #define DWARF_SIMPLE_MALLOC 1  */

char * _dwarf_get_alloc(Dwarf_Debug, Dwarf_Small, Dwarf_Unsigned);
Dwarf_Debug _dwarf_get_debug(void);
int _dwarf_free_all_of_one_debug(Dwarf_Debug);
struct Dwarf_Error_s * _dwarf_special_no_dbg_error_malloc(void);


/*  ALLOC_AREA_INDEX_TABLE_MAX is the size of the
    struct ial_s index_into_allocated array in dwarf_alloc.c
*/
#define ALLOC_AREA_INDEX_TABLE_MAX 57
