/*

  Copyright (C) 2000,2002,2004,2005 Silicon Graphics, Inc.  All Rights Reserved.
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



#include "config.h"
#include "dwarf_incl.h"
#include <stdio.h>
#include "dwarf_vars.h"
#include "dwarf_global.h"

int
dwarf_get_vars(Dwarf_Debug dbg,
    Dwarf_Var ** vars,
    Dwarf_Signed * ret_var_count, Dwarf_Error * error)
{
    int res = _dwarf_load_section(dbg, &dbg->de_debug_varnames,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (!dbg->de_debug_abbrev.dss_size) {
        return (DW_DLV_NO_ENTRY);
    }

    return _dwarf_internal_get_pubnames_like_data(dbg,
        dbg->de_debug_varnames.dss_data,
        dbg->de_debug_varnames.dss_size,
        (Dwarf_Global **) vars, /* Type punning for sections
            with identical format. */
        ret_var_count,
        error,
        DW_DLA_VAR_CONTEXT,
        DW_DLA_VAR,
        DW_DLE_DEBUG_VARNAMES_LENGTH_BAD,
        DW_DLE_DEBUG_VARNAMES_VERSION_ERROR);
}

/* Deallocating fully requires deallocating the list
   and all entries.  But some internal data is
   not exposed, so we need a function with internal knowledge.
*/

void
dwarf_vars_dealloc(Dwarf_Debug dbg, Dwarf_Var * dwgl,
    Dwarf_Signed count)
{
    _dwarf_internal_globals_dealloc(dbg, (Dwarf_Global *) dwgl,
        count,
        DW_DLA_VAR_CONTEXT,
        DW_DLA_VAR, DW_DLA_LIST);
    return;
}


int
dwarf_varname(Dwarf_Var var_in, char **ret_varname, Dwarf_Error * error)
{
    Dwarf_Global var = (Dwarf_Global) var_in;

    if (var == NULL) {
        _dwarf_error(NULL, error, DW_DLE_VAR_NULL);
        return (DW_DLV_ERROR);
    }

    *ret_varname = (char *) (var->gl_name);
    return DW_DLV_OK;
}


int
dwarf_var_die_offset(Dwarf_Var var_in,
    Dwarf_Off * returned_offset, Dwarf_Error * error)
{
    Dwarf_Global var = (Dwarf_Global) var_in;

    return dwarf_global_die_offset(var, returned_offset, error);

}


int
dwarf_var_cu_offset(Dwarf_Var var_in,
    Dwarf_Off * returned_offset, Dwarf_Error * error)
{
    Dwarf_Global var = (Dwarf_Global) var_in;

    return dwarf_global_cu_offset(var, returned_offset, error);
}


int
dwarf_var_name_offsets(Dwarf_Var var_in,
    char **returned_name,
    Dwarf_Off * die_offset,
    Dwarf_Off * cu_offset, Dwarf_Error * error)
{
    Dwarf_Global var = (Dwarf_Global) var_in;

    return
        dwarf_global_name_offsets(var,
            returned_name, die_offset, cu_offset,
            error);
}
