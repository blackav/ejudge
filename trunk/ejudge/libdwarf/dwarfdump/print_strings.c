/*
  Copyright (C) 2000-2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2009-2012 SN Systems Ltd. All rights reserved.
  Portions Copyright 2008-2012 David Anderson. All rights reserved.

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

/* print data in .debug_string */
extern void
print_strings(Dwarf_Debug dbg)
{
    Dwarf_Signed length = 0;
    string name;
    Dwarf_Off offset = 0;
    int sres = 0;

    current_section_id = DEBUG_STR;
    printf("\n.debug_string\n");
    while ((sres = dwarf_get_str(dbg, offset, &name, &length, &err))
        == DW_DLV_OK) {
        if (display_offsets) {
            printf("name at offset 0x%" DW_PR_XZEROS DW_PR_DUx
                ", length %4" DW_PR_DSd " is '%s'\n",
                (Dwarf_Unsigned)offset, length, name);
        } else {
            printf("name: length %4" DW_PR_DSd " is '%s'\n",
                length, name);
        }
        offset += length + 1;
    }
    /*  An inability to find the section is not necessarily
        a real error, so do not report error unless we've
        seen a real record. */
    if (sres == DW_DLV_ERROR && offset != 0) {
        print_error(dbg, "dwarf_get_str failure", sres, err);
    }
}
