/*

  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2009-2011 David Anderson. All Rights Reserved.

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
/* The address of the Free Software Foundation is
   Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
   Boston, MA 02110-1301, USA.
   SGI has moved from the above address.
*/




#include "config.h"
#include "dwarf_incl.h"
#include <stdio.h>
#include "dwarf_abbrev.h"

int
dwarf_get_abbrev(Dwarf_Debug dbg,
    Dwarf_Unsigned offset,
    Dwarf_Abbrev * returned_abbrev,
    Dwarf_Unsigned * length,
    Dwarf_Unsigned * abbr_count, Dwarf_Error * error)
{
    Dwarf_Small *abbrev_ptr = 0;
    Dwarf_Small *abbrev_section_end = 0;
    Dwarf_Half attr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Abbrev ret_abbrev = 0;
    Dwarf_Unsigned labbr_count = 0;
    Dwarf_Unsigned utmp = 0;


    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    if (dbg->de_debug_abbrev.dss_data == 0) {
        /*  Loads abbrev section (and .debug_info as we do those
            together). */
        int res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
    }

    if (offset >= dbg->de_debug_abbrev.dss_size) {
        return (DW_DLV_NO_ENTRY);
    }


    ret_abbrev = (Dwarf_Abbrev) _dwarf_get_alloc(dbg, DW_DLA_ABBREV, 1);
    if (ret_abbrev == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }
    ret_abbrev->ab_dbg = dbg;
    if (returned_abbrev == 0 || abbr_count == 0) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        _dwarf_error(dbg, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }


    *abbr_count = 0;
    if (length != NULL)
        *length = 1;

    abbrev_ptr = dbg->de_debug_abbrev.dss_data + offset;
    abbrev_section_end =
        dbg->de_debug_abbrev.dss_data + dbg->de_debug_abbrev.dss_size;

    DECODE_LEB128_UWORD(abbrev_ptr, utmp);
    ret_abbrev->ab_code = (Dwarf_Word) utmp;
    if (ret_abbrev->ab_code == 0) {
        *returned_abbrev = ret_abbrev;
        *abbr_count = 0;
        if (length) {
            *length = 1;
        }
        return (DW_DLV_OK);
    }

    DECODE_LEB128_UWORD(abbrev_ptr, utmp);
    ret_abbrev->ab_tag = utmp;
    ret_abbrev->ab_has_child = *(abbrev_ptr++);
    ret_abbrev->ab_abbrev_ptr = abbrev_ptr;

    do {
        Dwarf_Unsigned utmp2;

        DECODE_LEB128_UWORD(abbrev_ptr, utmp2);
        attr = (Dwarf_Half) utmp2;
        DECODE_LEB128_UWORD(abbrev_ptr, utmp2);
        attr_form = (Dwarf_Half) utmp2;

        if (attr != 0)
            (labbr_count)++;

    } while (abbrev_ptr < abbrev_section_end &&
        (attr != 0 || attr_form != 0));

    if (abbrev_ptr > abbrev_section_end) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        _dwarf_error(dbg, error, DW_DLE_ABBREV_DECODE_ERROR);
        return (DW_DLV_ERROR);
    }

    if (length != NULL)
        *length = abbrev_ptr - dbg->de_debug_abbrev.dss_data - offset;

    *returned_abbrev = ret_abbrev;
    *abbr_count = labbr_count;
    return (DW_DLV_OK);
}

int
dwarf_get_abbrev_code(Dwarf_Abbrev abbrev,
    Dwarf_Unsigned * returned_code,
    Dwarf_Error * error)
{
    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }

    *returned_code = abbrev->ab_code;
    return (DW_DLV_OK);
}

/*  DWARF defines DW_TAG_hi_user as 0xffff so no tag should be
    over 16 bits.  */
int
dwarf_get_abbrev_tag(Dwarf_Abbrev abbrev,
    Dwarf_Half * returned_tag, Dwarf_Error * error)
{
    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }

    *returned_tag = abbrev->ab_tag;
    return (DW_DLV_OK);
}


int
dwarf_get_abbrev_children_flag(Dwarf_Abbrev abbrev,
    Dwarf_Signed * returned_flag,
    Dwarf_Error * error)
{
    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }

    *returned_flag = abbrev->ab_has_child;
    return (DW_DLV_OK);
}


int
dwarf_get_abbrev_entry(Dwarf_Abbrev abbrev,
    Dwarf_Signed indx,
    Dwarf_Half * returned_attr_num,
    Dwarf_Signed * form,
    Dwarf_Off * offset, Dwarf_Error * error)
{
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Byte_Ptr abbrev_end = 0;
    Dwarf_Byte_Ptr mark_abbrev_ptr = 0;
    Dwarf_Half attr = 0;
    Dwarf_Half attr_form = 0;

    if (indx < 0)
        return (DW_DLV_NO_ENTRY);

    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }

    if (abbrev->ab_code == 0) {
        return (DW_DLV_NO_ENTRY);
    }

    if (abbrev->ab_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    abbrev_ptr = abbrev->ab_abbrev_ptr;
    abbrev_end =
        abbrev->ab_dbg->de_debug_abbrev.dss_data +
        abbrev->ab_dbg->de_debug_abbrev.dss_size;

    for (attr = 1, attr_form = 1;
        indx >= 0 && abbrev_ptr < abbrev_end && (attr != 0 ||
            attr_form != 0);
        indx--) {
        Dwarf_Unsigned utmp4;

        mark_abbrev_ptr = abbrev_ptr;
        DECODE_LEB128_UWORD(abbrev_ptr, utmp4);
        attr = (Dwarf_Half) utmp4;
        DECODE_LEB128_UWORD(abbrev_ptr, utmp4);
        attr_form = (Dwarf_Half) utmp4;
    }

    if (abbrev_ptr >= abbrev_end) {
        _dwarf_error(abbrev->ab_dbg, error, DW_DLE_ABBREV_DECODE_ERROR);
        return (DW_DLV_ERROR);
    }

    if (indx >= 0) {
        return (DW_DLV_NO_ENTRY);
    }

    if (form != NULL)
        *form = attr_form;
    if (offset != NULL)
        *offset = mark_abbrev_ptr - abbrev->ab_dbg->de_debug_abbrev.dss_data;

    *returned_attr_num = (attr);
    return DW_DLV_OK;
}

/*  This function is not entirely safe to call.
    The problem is that the DWARF[234] specification does not insist
    that bytes in .debug_abbrev that are not referenced by .debug_info
    or .debug_types need to be initialized to anything specific.
    Any garbage bytes may cause trouble.  Not all compilers/linkers
    leave unreferenced garbage bytes in .debug_abbrev, so this may
    work for most objects. */
int
dwarf_get_abbrev_count(Dwarf_Debug dbg)
{
    Dwarf_Abbrev ab;
    Dwarf_Unsigned offset = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Unsigned attr_count = 0;
    Dwarf_Unsigned abbrev_count = 0;
    int abres = DW_DLV_OK;
    Dwarf_Error err;

    while ((abres = dwarf_get_abbrev(dbg, offset, &ab,
        &length, &attr_count,
        &err)) == DW_DLV_OK) {

        ++abbrev_count;
        offset += length;
        dwarf_dealloc(dbg, ab, DW_DLA_ABBREV);
    }
    return abbrev_count;
}

