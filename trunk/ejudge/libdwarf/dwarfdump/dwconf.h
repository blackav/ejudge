/*
    Copyright (C) 2006 Silicon Graphics, Inc.  All Rights Reserved.
    Portions Copyright 2011 David Anderson. All Rights Reserved.

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


    $Header: /plroot/cmplrs.src/v7.4.5m/.RCS/PL/dwarfdump/RCS/dwconf.h,v 1.2 2006/04/18 04:29:39 davea Exp $ */


/* declarations helping configure the frame reader.  */
struct dwconf_s {
    char *cf_config_file_path;
    char *cf_abi_name;

    /*  2 for old, 3 for frame interface 3. 2 means use the old
        mips-abi-oriented frame interface. 3 means use the new
        DWARF3-capable and configureable-abi interface.

        Now, anyone who revises dwarf.h and libdwarf.h to match their
        abi-of-interest will still be able to use cf_interface_number 2
        as before.  But most folks don't update those header files and
        instead of making *them* configurable we make dwarfdump (and
        libdwarf) configurable sufficiently to print frame information
        sensibly. */
    int cf_interface_number;

    /* The number of table rules , aka columns. For MIPS/IRIX is 66. */
    unsigned long cf_table_entry_count;

    /*  Array of cf_table_entry_count reg names. Names not filled in
        from dwarfdump.conf have NULL (0) pointer value.
        cf_named_regs_table_size must match size of cf_regs array.
        Set cf_regs_malloced  1  if table was malloced. Set 0
        if static.
        */
    char **cf_regs;
    unsigned long cf_named_regs_table_size;
    unsigned    cf_regs_malloced;

    /*  The 'default initial value' when intializing a table. for MIPS
        is DW_FRAME_SAME_VAL(1035). For other ISA/ABIs may be
        DW_FRAME_UNDEFINED_VAL(1034). */
    unsigned cf_initial_rule_value;
    int cf_same_val;
    int cf_undefined_val;

    /*  The number of the cfa 'register'. For cf_interface_number 2 of
        MIPS this is 0. For other architectures (and anytime using
        cf_interface_number 3) this should be outside the table, a
        special value such as 1436, not a table column at all).  */
    int cf_cfa_reg;

    /*  If non-zero it is the number of bytes in an address
        for the frame data.  Normally it will be zero because
        there are usually other sources for the correct address size.
        However, with DWARF2 frame data there is no explicit address
        size in the frame data and the object file might not have
        other .debug_ sections to work with.
        If zero, no address size was supplied, and that is normal and
        the already-set (or defaulted) address size is to be used.
        Only an exceptional frame configure will specify address
        size here.  This won't work at all if the object needing
        this setting has different address size in different CUs. */
    unsigned cf_address_size;
};


/* Returns DW_DLV_OK if works. DW_DLV_ERROR if cannot do what is asked. */
int find_conf_file_and_read_config(const char *named_file,
    const char *named_abi, char **defaults,
    struct dwconf_s *conf_out);
void init_conf_file_data(struct dwconf_s *config_file_data);
void init_mips_conf_file_data(struct dwconf_s *config_file_data);

void print_reg_from_config_data(Dwarf_Signed reg,
    struct dwconf_s *config_data);


void init_generic_config_1200_regs(struct dwconf_s *conf);
