/*
  Copyright (C) 2000-2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2009-2011 SN Systems Ltd. All rights reserved.
  Portions Copyright 2008-2011 David Anderson. All rights reserved.

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



$Header: /plroot/cmplrs.src/v7.4.5m/.RCS/PL/dwarfdump/RCS/print_sections.c,v 1.69 2006/04/17 00:09:56 davea Exp $ */
/*  The address of the Free Software Foundation is
    Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
    Boston, MA 02110-1301, USA.
    SGI has moved from the Crittenden Lane address.
*/

#include "globals.h"
#include "naming.h"
#include "dwconf.h"
#include "esb.h"

#include "print_sections.h"
#include "print_frames.h"


/* Get all the data in .debug_static_funcs
   On error, this allows some dwarf memory leaks.
*/
extern void
print_static_funcs(Dwarf_Debug dbg)
{
    Dwarf_Func *funcbuf = NULL;
    Dwarf_Signed count = 0;
    Dwarf_Signed i = 0;
    Dwarf_Off die_off = 0;
    Dwarf_Off cu_off = 0;
    int gfres = 0;

    current_section_id = DEBUG_STATIC_FUNC;

    if (!do_print_dwarf) {
        return;
    }

    printf("\n.debug_static_func\n");
    gfres = dwarf_get_funcs(dbg, &funcbuf, &count, &err);
    if (gfres == DW_DLV_ERROR) {
        print_error(dbg, "dwarf_get_funcs", gfres, err);
    } else if (gfres == DW_DLV_NO_ENTRY) {
        /* no static funcs */
    } else {
        Dwarf_Unsigned maxoff = get_info_max_offset(dbg);

        for (i = 0; i < count; i++) {
            int fnres = 0;
            int cures3 = 0;
            Dwarf_Unsigned global_cu_off = 0;
            char *name = 0;

            fnres = dwarf_func_name_offsets(funcbuf[i], &name, &die_off,
                &cu_off, &err);
            deal_with_name_offset_err(dbg, "dwarf_func_name_offsets",
                name, die_off, fnres, err);
            cures3 = dwarf_func_cu_offset(funcbuf[i],
                &global_cu_off, &err);
            if (cures3 != DW_DLV_OK) {
                print_error(dbg, "dwarf_global_cu_offset", cures3, err);
            }

            if (check_pubname_attr) {
                Dwarf_Bool has_attr;
                int ares;
                int dres;
                Dwarf_Die die;

                /* get die at die_off */
                dres = dwarf_offdie(dbg, die_off, &die, &err);
                if (dres != DW_DLV_OK) {
                    print_error(dbg, "dwarf_offdie", dres, err);
                }


                ares =
                    dwarf_hasattr(die, DW_AT_external, &has_attr, &err);
                if (ares == DW_DLV_ERROR) {
                    print_error(dbg, "hassattr on DW_AT_external", ares,
                        err);
                }
                if (checking_this_compiler()) {
                    DWARF_CHECK_COUNT(pubname_attr_result,1);
                    if (ares == DW_DLV_OK && has_attr) {
                        /* Should the value of flag be examined? */
                    } else {
                        DWARF_CHECK_ERROR2(pubname_attr_result,name,
                            "pubname (in static funcs section) does not have DW_AT_external");
                    }
                }
                dwarf_dealloc(dbg, die, DW_DLA_DIE);
            }

            if (do_print_dwarf || record_dwarf_error) {
                print_pubname_style_entry(dbg,
                    "static-func", name, die_off,
                    cu_off, global_cu_off, maxoff);
                record_dwarf_error = FALSE;  /* Clear error condition */
            }
        }
        dwarf_funcs_dealloc(dbg, funcbuf, count);
    }
}   /* print_static_funcs() */
