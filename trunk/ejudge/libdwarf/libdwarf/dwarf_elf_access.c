/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 Arxan Technologies, Inc. All Rights Reserved.
  Portions Copyright 2009-2012 David Anderson. All rights reserved.
  Portions Copyright 2009-2010 Novell Inc. All rights reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

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
#include "dwarf_elf_access.h"

/* Include Relocation definitions in the case of Windows */
#ifdef WIN32
#include "dwarf_reloc_arm.h"
#include "dwarf_reloc_mips.h"
#include "dwarf_reloc_ppc.h"
#include "dwarf_reloc_ppc64.h"
#include "dwarf_reloc_x86_64.h"
#endif /* WIN32 */

#ifdef HAVE_ELF_H
#include <elf.h>
#endif
#ifdef HAVE_LIBELF_H
#include <libelf.h>
#else
#ifdef HAVE_LIBELF_LIBELF_H
#include <libelf/libelf.h>
#endif
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#define FALSE 0
#define TRUE  1

#ifndef EM_MIPS
/* This is the standard elf value EM_MIPS. */
#define EM_MIPS 8
#endif

#ifndef EM_K10M
#define EM_K10M 181  /* Intel K10M */
#endif
#ifndef EM_L10M
#define EM_L10M 180  /* Intel L10M */
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183  /* Arm 64 */
#endif
#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 0x101
#endif
#ifndef R_AARCH64_ABS32
#define R_AARCH64_ABS32 0x102
#endif



#ifdef HAVE_ELF64_GETEHDR
extern Elf64_Ehdr *elf64_getehdr(Elf *);
#endif
#ifdef HAVE_ELF64_GETSHDR
extern Elf64_Shdr *elf64_getshdr(Elf_Scn *);
#endif
#ifdef WORDS_BIGENDIAN
#define WRITE_UNALIGNED(dbg,dest,source, srclength,len_out) \
    {                                             \
        dbg->de_copy_word(dest,                   \
            ((char *)source) +srclength-len_out,  \
            len_out) ;                            \
    }


#else /* LITTLE ENDIAN */

#define WRITE_UNALIGNED(dbg,dest,source, srclength,len_out) \
    {                               \
        dbg->de_copy_word( (dest) , \
            ((char *)source) ,      \
            len_out) ;              \
    }
#endif



typedef struct {
    dwarf_elf_handle elf;
    int              is_64bit;
    Dwarf_Small      length_size;
    Dwarf_Small      pointer_size;
    Dwarf_Unsigned   section_count;
    Dwarf_Endianness endianness;
    Dwarf_Small      machine;
    int              libdwarf_owns_elf;
    Elf32_Ehdr *ehdr32;

#ifdef HAVE_ELF64_GETEHDR
    Elf64_Ehdr *ehdr64;
#endif
    /*  Elf symtab and its strtab.  Initialized at first
        call to do relocations, the actual data is in the Dwarf_Debug
        struct, not allocated locally here. */
    struct Dwarf_Section_s *symtab;
    struct Dwarf_Section_s *strtab;

} dwarf_elf_object_access_internals_t;

struct Dwarf_Elf_Rela {
    Dwarf_ufixed64 r_offset;
    /*Dwarf_ufixed64 r_info; */
    Dwarf_ufixed64 r_type;
    Dwarf_ufixed64 r_symidx;
    Dwarf_ufixed64 r_addend;
};


static int dwarf_elf_object_access_load_section(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Small** section_data,
    int* error);

/* dwarf_elf_object_access_internals_init() */
static int
dwarf_elf_object_access_internals_init(void* obj_in,
    dwarf_elf_handle elf,
    int* error)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    char *ehdr_ident = 0;
    Dwarf_Half machine = 0;
    obj->elf = elf;

    if ((ehdr_ident = elf_getident(elf, NULL)) == NULL) {
        *error = DW_DLE_ELF_GETIDENT_ERROR;
        return DW_DLV_ERROR;
    }

    obj->is_64bit = (ehdr_ident[EI_CLASS] == ELFCLASS64);


    if (ehdr_ident[EI_DATA] == ELFDATA2LSB){
        obj->endianness = DW_OBJECT_LSB;
    } else if (ehdr_ident[EI_DATA] == ELFDATA2MSB){
        obj->endianness = DW_OBJECT_MSB;
    }

    if (obj->is_64bit) {
#ifdef HAVE_ELF64_GETEHDR
        obj->ehdr64 = elf64_getehdr(elf);
        if (obj->ehdr64 == NULL) {
            *error = DW_DLE_ELF_GETEHDR_ERROR;
            return DW_DLV_ERROR;
        }
        obj->section_count = obj->ehdr64->e_shnum;
        machine = obj->ehdr64->e_machine;
        obj->machine = machine;
#else
        *error = DW_DLE_NO_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif
    } else {
        obj->ehdr32 = elf32_getehdr(elf);
        if (obj->ehdr32 == NULL) {
            *error = DW_DLE_ELF_GETEHDR_ERROR;
            return DW_DLV_ERROR;
        }
        obj->section_count = obj->ehdr32->e_shnum;
        machine = obj->ehdr32->e_machine;
        obj->machine = machine;
    }

    /*  The following length_size is Not Too Significant. Only used
        one calculation, and an approximate one at that. */
    obj->length_size = obj->is_64bit ? 8 : 4;
    obj->pointer_size = obj->is_64bit ? 8 : 4;

    if (obj->is_64bit && machine != EM_MIPS) {
        /*  MIPS/IRIX makes pointer size and length size 8 for -64.
            Other platforms make length 4 always. */
        /*  4 here supports 32bit-offset dwarf2, as emitted by cygnus
            tools, and the dwarfv2.1 64bit extension setting.
            This is not the same as the size-of-an-offset, which
            is 4 in 32bit dwarf and 8 in 64bit dwarf.  */
        obj->length_size = 4;
    }
    return DW_DLV_OK;
}

/* dwarf_elf_object_access_get_byte_order */
static
Dwarf_Endianness
dwarf_elf_object_access_get_byte_order(void* obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->endianness;
}

/* dwarf_elf_object_access_get_section_count() */
static
Dwarf_Unsigned
dwarf_elf_object_access_get_section_count(void * obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->section_count;
}


/*  dwarf_elf_object_access_get_section()

    If writing a function vaguely like this for a non-elf object,
    be sure that when section-index is passed in as zero that
    you set the fields in *ret_scn to reflect an empty section
    with an empty string as the section name.  Adjust your
    section indexes of your non-elf-reading-code
    for all the necessary functions in Dwarf_Obj_Access_Methods_s
    accordingly.
*/
static
int
dwarf_elf_object_access_get_section_info(
    void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Obj_Access_Section* ret_scn,
    int* error)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;

    Elf32_Shdr *shdr32 = 0;

#ifdef HAVE_ELF64_GETSHDR
    Elf64_Shdr *shdr64 = 0;
#endif
    Elf_Scn *scn = 0;


    scn = elf_getscn(obj->elf, section_index);
    if (scn == NULL) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }
    if (obj->is_64bit) {
#ifdef HAVE_ELF64_GETSHDR
        shdr64 = elf64_getshdr(scn);
        if (shdr64 == NULL) {
            *error = DW_DLE_ELF_GETSHDR_ERROR;
            return DW_DLV_ERROR;
        }

        /*  Get also section 'sh_type' and sh_info' fields, so the caller
            can use it for additional tasks that require that info. */
        ret_scn->type = shdr64->sh_type;
        ret_scn->size = shdr64->sh_size;
        ret_scn->addr = shdr64->sh_addr;
        ret_scn->link = shdr64->sh_link;
        ret_scn->info = shdr64->sh_info;
        ret_scn->entrysize = shdr64->sh_entsize;
        ret_scn->name = elf_strptr(obj->elf, obj->ehdr64->e_shstrndx,
            shdr64->sh_name);
        if (ret_scn->name == NULL) {
            *error = DW_DLE_ELF_STRPTR_ERROR;
            return DW_DLV_ERROR;
        }
        return DW_DLV_OK;
#else
        *error = DW_DLE_MISSING_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif /* HAVE_ELF64_GETSHDR */
    }
    if ((shdr32 = elf32_getshdr(scn)) == NULL) {
        *error = DW_DLE_ELF_GETSHDR_ERROR;
        return DW_DLV_ERROR;
    }

    /*  Get also the section type, so the caller can use it for
        additional tasks that require to know the section type. */
    ret_scn->type = shdr32->sh_type;
    ret_scn->size = shdr32->sh_size;
    ret_scn->addr = shdr32->sh_addr;
    ret_scn->link = shdr32->sh_link;
    ret_scn->info = shdr32->sh_info;
    ret_scn->entrysize = shdr32->sh_entsize;
    ret_scn->name = elf_strptr(obj->elf, obj->ehdr32->e_shstrndx,
        shdr32->sh_name);
    if (ret_scn->name == NULL) {
        *error = DW_DLE_ELF_STRPTR_ERROR;
        return DW_DLV_ERROR;
    }
    return DW_DLV_OK;
}

/* dwarf_elf_object_access_get_length_size */
static
Dwarf_Small
dwarf_elf_object_access_get_length_size(void* obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->length_size;
}

/* dwarf_elf_object_access_get_pointer_size */
static
Dwarf_Small
dwarf_elf_object_access_get_pointer_size(void* obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->pointer_size;
}

#define MATCH_REL_SEC(i_,s_,r_)  \
if (i_ == s_.dss_index) { \
    *r_ = &s_;            \
    return DW_DLV_OK;    \
}

static int
find_section_to_relocate(Dwarf_Debug dbg,Dwarf_Half section_index,
   struct Dwarf_Section_s **relocatablesec, int *error)
{
    MATCH_REL_SEC(section_index,dbg->de_debug_info,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_abbrev,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_line,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_loc,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_aranges,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_macinfo,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_pubnames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_ranges,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_frame,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_frame_eh_gnu,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_pubtypes,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_funcnames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_typenames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_varnames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_weaknames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_types,relocatablesec);
    /* dbg-> de_debug_tu_index,reloctablesec); */
    /* dbg-> de_debug_cu_index,reloctablesec); */
    /* dbg-> de_debug_gdbindex,reloctablesec); */
    /* dbg-> de_debug_str,syms); */
    /* de_elf_symtab,syms); */
    /* de_elf_strtab,syms); */
    *error = DW_DLE_RELOC_SECTION_MISMATCH;
    return DW_DLV_ERROR;

}
#undef MATCH_REL_SEC

static void
get_rela_elf32(Dwarf_Small *data, unsigned int i,
  int endianness,
  int machine,
  struct Dwarf_Elf_Rela *relap)
{
    Elf32_Rela *relp = (Elf32_Rela*)(data + (i * sizeof(Elf32_Rela)));
    relap->r_offset = relp->r_offset;
    /*
    relap->r_info = relp->r_info;
   */
    relap->r_type = ELF32_R_TYPE(relp->r_info);
    relap->r_symidx = ELF32_R_SYM(relp->r_info);
    relap->r_addend = relp->r_addend;
}

static void
get_rela_elf64(Dwarf_Small *data, unsigned int i,
  int endianness,
  int machine,
  struct Dwarf_Elf_Rela *relap)
{
#ifdef HAVE_ELF64_RELA
    Elf64_Rela * relp = (Elf64_Rela*)(data + (i * sizeof(Elf64_Rela)));
    relap->r_offset = relp->r_offset;
    /*
    relap->r_info = relp->r_info;
    */
#define ELF64MIPS_REL_SYM(i) ((i) & 0xffffffff)
#define ELF64MIPS_REL_TYPE(i) ((i >> 56) &0xff)
    if (machine == EM_MIPS && endianness == DW_OBJECT_LSB ){
        /*  This is really wierd. Treat this very specially.
            The Elf64 LE MIPS object used for
            testing (that has rela) wants the
            values as  sym  ssym type3 type2 type, treating
            each value as independent value. But libelf xlate
            treats it as something else so we fudge here.
            It is unclear
            how to precisely characterize where these relocations
            were used.
            SGI MIPS on IRIX never used .rela relocations.
            The BE 64bit elf MIPS test object with rela uses traditional
            elf relocation layouts, not this special case.  */
        /*  We ignore the special TYPE2 and TYPE3, they should be
            value R_MIPS_NONE in rela. */
        relap->r_type = ELF64MIPS_REL_TYPE(relp->r_info);
        relap->r_symidx = ELF64MIPS_REL_SYM(relp->r_info);
#undef MIPS64SYM
#undef MIPS64TYPE
    } else
    {
        relap->r_type = ELF64_R_TYPE(relp->r_info);
        relap->r_symidx = ELF64_R_SYM(relp->r_info);
    }
    relap->r_addend = relp->r_addend;
#endif
}

static void
get_relocations_array(Dwarf_Bool is_64bit,
    int endianness,
    int machine,
    Dwarf_Small *data,
    unsigned int num_relocations,
    struct Dwarf_Elf_Rela *relap)
{
    unsigned int i = 0;
    void (*get_relocations)(Dwarf_Small *data, unsigned int i,
        int endianness,
        int machine,
        struct Dwarf_Elf_Rela *relap);

    /* Handle 32/64 bit issue */
    if (is_64bit) {
        get_relocations = get_rela_elf64;
    } else {
        get_relocations = get_rela_elf32;
    }

    for (i=0; i < num_relocations; i++) {
        get_relocations(data, i,endianness,machine,
            &(relap[i]));
    }

}

static int
get_relocation_entries(Dwarf_Bool is_64bit,
    int endianness,
    int machine,
    Dwarf_Small *relocation_section,
    Dwarf_Unsigned relocation_section_size,
    Dwarf_Unsigned relocation_section_entrysize,
    struct Dwarf_Elf_Rela **relas,
    unsigned int *nrelas,
    int *error)
{
    unsigned int relocation_size = 0;

    if (is_64bit) {
#ifdef HAVE_ELF64_RELA
        relocation_size = sizeof(Elf64_Rela);
#else
        *error = DW_DLE_MISSING_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif
    } else {
        relocation_size = sizeof(Elf32_Rela);
    }
    if (relocation_size != relocation_section_entrysize) {
        /*  Means our struct definition does not match the
            real object. */
        *error = DW_DLE_RELOC_SECTION_LENGTH_ODD;
        return DW_DLV_ERROR;
    }

    if (relocation_section == NULL) {
        *error = DW_DLE_RELOC_SECTION_PTR_NULL;
        return(DW_DLV_ERROR);
    }

    if ((relocation_section_size != 0)) {
        size_t bytescount = 0;
        if (relocation_section_size%relocation_size) {
            *error = DW_DLE_RELOC_SECTION_LENGTH_ODD;
            return DW_DLV_ERROR;
        }
        *nrelas = relocation_section_size/relocation_size;
        bytescount = (*nrelas) * sizeof(struct Dwarf_Elf_Rela);
        *relas = malloc(bytescount);
        if (!*relas) {
            *error = DW_DLE_MAF;
            return(DW_DLV_ERROR);
        }
        memset(*relas,0,bytescount);
        get_relocations_array(is_64bit,endianness,machine,
            relocation_section,
            *nrelas, *relas);
    }
    return(DW_DLV_OK);
}

/*  We have a EM_QUALCOMM_DSP6 relocatable object
    test case in dwarf regression tests, atefail/ig_server.
    Values for QUALCOMM were derived from this executable.

    The r = 0 in the function will get optimized away
    when not needed.

*/

#define EM_QUALCOMM_DSP6 0xa4
#define QUALCOMM_REL32   6

static Dwarf_Bool
is_32bit_abs_reloc(unsigned int type, Dwarf_Half machine)
{
    Dwarf_Bool r = 0;
    switch (machine) {
#if defined(EM_MIPS) && defined (R_MIPS_32)
    case EM_MIPS:
        r =  (0
#if defined (R_MIPS_32)
            | (type == R_MIPS_32)
#endif
#if defined (R_MIPS_TLS_DTPREL32)
            | (type == R_MIPS_TLS_DTPREL32)
#endif /* DTPREL32 */
            );
        break;
#endif /* MIPS case */
#if defined(EM_SPARC32PLUS)  && defined (R_SPARC_UA32)
    case EM_SPARC32PLUS:
        r =  (type == R_SPARC_UA32);
        break;
#endif
#if defined(EM_SPARCV9)  && defined (R_SPARC_UA32)
    case EM_SPARCV9:
        r =  (type == R_SPARC_UA32);
        break;
#endif
#if defined(EM_SPARC) && defined (R_SPARC_UA32)
    case EM_SPARC:
        r =  (0
#if defined(R_SPARC_UA32)
            | (type == R_SPARC_UA32)
#endif
#if (R_SPARC_TLS_DTPOFF32)
            | (type == R_SPARC_TLS_DTPOFF32)
#endif
            );
        break;
#endif /* EM_SPARC */
#if defined(EM_386) && defined (R_386_32)
    case EM_386:
        r = (0
#if defined (R_386_32)
            |  (type == R_386_32)
#endif
#if defined (R_386_TLS_LDO_32)
            | (type == R_386_TLS_LDO_32)
#endif
#if defined (R_386_TLS_DTPOFF32)
            | (type == R_386_TLS_DTPOFF32)
#endif
            );
        break;
#endif /* EM_386 */

#if defined (EM_SH) && defined (R_SH_DIR32)
    case EM_SH:
        r = (0
#if defined (R_SH_DIR32)
            | (type == R_SH_DIR32)
#endif
#if defined (R_SH_DTPOFF32)
            | (type == R_SH_TLS_DTPOFF32)
#endif
            );
        break;
#endif /* SH */

#if defined(EM_IA_64) && defined (R_IA64_SECREL32LSB)
    case EM_IA_64:
        r = (0
#if defined (R_IA64_SECREL32LSB)
            | (type == R_IA64_SECREL32LSB)
#endif
#if defined (R_IA64_DIR32LSB)
            | (type == R_IA64_DIR32LSB)
#endif
#if defined (R_IA64_DTPREL32LSB)
            | (type == R_IA64_DTPREL32LSB)
#endif
            );
        break;
#endif /* EM_IA_64 */

#if defined(EM_ARM) && defined (R_ARM_ABS32)
    case EM_ARM:
    case EM_AARCH64:
        r = (0
#if defined (R_ARM_ABS32)
            | ( type == R_ARM_ABS32)
#endif
#if defined (R_AARCH64_ABS32)
            | ( type == R_AARCH64_ABS32)
#endif
#if defined (R_ARM_TLS_LDO32)
            | ( type == R_ARM_TLS_LDO32)
#endif
            );
        break;
#endif /* EM_ARM */

/*  On FreeBSD R_PPC64_ADDR32 not defined
    so we use the R_PPC_ names which
    have the proper value.
    Our headers have:
    R_PPC64_ADDR64   38
    R_PPC_ADDR32     1 so we use this one
    R_PPC64_ADDR32   R_PPC_ADDR32

    R_PPC64_DTPREL32 110  which may be wrong/unavailable
    R_PPC64_DTPREL64 78
    R_PPC_DTPREL32   78
    */
#if defined(EM_PPC64) && defined (R_PPC_ADDR32)
    case EM_PPC64:
        r = (0
#if defined(R_PPC_ADDR32)
            | (type == R_PPC_ADDR32)
#endif
#if defined(R_PPC64_DTPREL32)
            | (type == R_PPC64_DTPREL32)
#endif
            );
        break;
#endif /* EM_PPC64 */


#if defined(EM_PPC) && defined (R_PPC_ADDR32)
    case EM_PPC:
        r = (0
#if defined (R_PPC_ADDR32)
            | (type == R_PPC_ADDR32)
#endif
#if defined (R_PPC_DTPREL32)
            | (type == R_PPC_DTPREL32)
#endif
            );
        break;
#endif /* EM_PPC */

#if defined(EM_S390) && defined (R_390_32)
    case EM_S390:
        r = (0
#if defined (R_390_32)
            | (type == R_390_32)
#endif
#if defined (R_390_TLS_LDO32)
            | (type == R_390_TLS_LDO32)
#endif
            );
        break;
#endif /* EM_S390 */

#if defined(EM_X86_64) && defined (R_X86_64_32)
#if defined(EM_K10M)
    case EM_K10M:
#endif
#if defined(EM_L10M)
    case EM_L10M:
#endif
    case EM_X86_64:
        r = (0
#if defined (R_X86_64_32)
            | (type == R_X86_64_32)
#endif
#if defined (R_X86_64_DTPOFF32)
            | (type ==  R_X86_64_DTPOFF32)
#endif
            );
        break;
#endif /* EM_X86_64 */

    case  EM_QUALCOMM_DSP6:
        r = (type == QUALCOMM_REL32);
        break;
    }
    return r;
}

static Dwarf_Bool
is_64bit_abs_reloc(unsigned int type, Dwarf_Half machine)
{
    Dwarf_Bool r = 0;
    switch (machine) {
#if defined(EM_MIPS) && defined (R_MIPS_64)
    case EM_MIPS:
        r = (0
#if defined (R_MIPS_64)
            | (type == R_MIPS_64)
#endif
#if defined(R_MIPS_TLS_DTPREL64)
            | (type == R_MIPS_TLS_DTPREL64)
#endif
            );
        break;
#endif /* EM_MIPS */
#if defined(EM_SPARC32PLUS) && defined (R_SPARC_UA64)
    case EM_SPARC32PLUS:
        r =  (type == R_SPARC_UA64);
        break;
#endif
#if defined(EM_SPARCV9) && defined (R_SPARC_UA64)
    case EM_SPARCV9:
        r = (0
#if defined (R_SPARC_UA64)
            | (type == R_SPARC_UA64)
#endif
#if defined (R_SPARC_TLS_DTPOFF64)
            | (type == R_SPARC_TLS_DTPOFF64)
#endif
            );
        break;
#endif
#if defined(EM_SPARC) && defined (R_SPARC_UA64)
    case EM_SPARC:
        r = (0
#if defined(R_SPARC_UA64)
            | (type == R_SPARC_UA64)
#endif
#if defined (R_SPARC_TLS_DTPOFF64)
            | (type == R_SPARC_TLS_DTPOFF64)
#endif
            );
        break;
#endif /* EM_SPARC */

#if defined(EM_IA_64) && defined (R_IA64_SECREL64LSB)
    case EM_IA_64:
        r = (0
#if defined (R_IA64_SECREL64LSB)
            | (type == R_IA64_SECREL64LSB)
#endif
#if defined (R_IA64_DIR64LSB)
            | (type == R_IA64_DIR64LSB)
#endif
#if defined (R_IA64_DTPREL64LSB)
            | (type == R_IA64_DTPREL64LSB)
#endif
            );
        break;
#endif /* EM_IA_64 */

#if defined(EM_PPC64) && defined (R_PPC64_ADDR64)
    case EM_PPC64:
        r = (0
#if defined(R_PPC64_ADDR64)
            | (type == R_PPC64_ADDR64)
#endif
#if defined(R_PPC64_DTPREL64)
            | (type == R_PPC64_DTPREL64)
#endif
            );
        break;
#endif /* EM_PPC64 */

#if defined(EM_S390) && defined (R_390_64)
    case EM_S390:
        r = (0
#if defined(R_390_64)
            | (type == R_390_64)
#endif
#if defined(R_390_TLS_LDO64)
            | (type == R_390_TLS_LDO64)
#endif
            );
        break;
#endif /* EM_390 */

#if defined(EM_X86_64) && defined (R_X86_64_64)
#if defined(EM_K10M)
    case EM_K10M:
#endif
#if defined(EM_L10M)
    case EM_L10M:
#endif
    case EM_X86_64:
        r = (0
#if defined (R_X86_64_64)
            | (type == R_X86_64_64)
#endif
#if defined (R_X86_64_DTPOFF32)
            | (type == R_X86_64_DTPOFF64)
#endif
            );
        break;
#endif /* EM_X86_64 */
#if defined(EM_AARCH64) && defined (R_AARCH64_ABS64)
    case EM_AARCH64:
        r = (0
#if defined (R_AARCH64_ABS64)
            | ( type == R_AARCH64_ABS64)
#endif
            );
        break;
#endif /* EM_AARCH64 */

    }
    return r;
}


/*  Returns DW_DLV_OK if it works, else DW_DLV_ERROR.
    The caller may decide to ignore the errors or report them. */
static int
update_entry(Dwarf_Debug dbg,
    Dwarf_Bool is_64bit, Dwarf_Endianness endianess,
    Dwarf_Half machine, struct Dwarf_Elf_Rela *rela,
    Dwarf_Small *target_section,
    Dwarf_Small *symtab_section_data,
    Dwarf_Unsigned symtab_section_size,
    Dwarf_Unsigned symtab_section_entrysize,
    int *error)
{
    unsigned int type = 0;
    unsigned int sym_idx = 0;
#ifdef HAVE_ELF64_SYM
    Elf64_Sym sym_buf;
    Elf64_Sym *sym = 0;
#else
    Elf32_Sym sym_buf;
    Elf32_Sym *sym = 0;
#endif
    Elf32_Sym *sym32 = 0;
    Dwarf_ufixed64 offset = 0;
    Dwarf_sfixed64 addend = 0;
    Dwarf_Unsigned reloc_size = 0;
    Dwarf_Unsigned symtab_entry_count = 0;

    if (symtab_section_entrysize == 0) {
        *error = DW_DLE_SYMTAB_SECTION_ENTRYSIZE_ZERO;
        return DW_DLV_ERROR;
    }
    symtab_entry_count = symtab_section_size/symtab_section_entrysize;

    /* Dwarf_Elf_Rela dereferencing */
    offset = rela->r_offset;
    addend = rela->r_addend;
    type = rela->r_type;
    sym_idx = rela->r_symidx;
    if (sym_idx >= symtab_entry_count) {
        *error = DW_DLE_RELOC_SECTION_SYMBOL_INDEX_BAD;
        return DW_DLV_ERROR;
    }



    if (is_64bit) {
#ifdef HAVE_ELF64_SYM
        sym = &((Elf64_Sym*)symtab_section_data)[sym_idx];
#endif
    } else {
        sym32 = &((Elf32_Sym*)symtab_section_data)[sym_idx];

        /*  Convert Elf32_Sym struct to Elf64_Sym struct. We point at
            an Elf64_Sym local variable (sym_buf) to allow us to use the
            same pointer (sym) for both 32-bit and 64-bit instances.  */
        sym = &sym_buf;
        sym->st_name = sym32->st_name;
        sym->st_info = sym32->st_info;
        sym->st_other = sym32->st_other;
        sym->st_shndx = sym32->st_shndx;
        sym->st_value = sym32->st_value;
        sym->st_size = sym32->st_size;
    }

    /* Determine relocation size */
    if (is_32bit_abs_reloc(type, machine)) {
        reloc_size = 4;
    } else if (is_64bit_abs_reloc(type, machine)) {
        reloc_size = 8;
    } else {
        *error = DW_DLE_RELOC_SECTION_RELOC_TARGET_SIZE_UNKNOWN;
        return DW_DLV_ERROR;
    }


    {
        /*  Assuming we do not need to do a READ_UNALIGNED here
            at target_section + offset and add its value to
            outval.  Some ABIs say no read (for example MIPS),
            but if some do then which ones? */
        Dwarf_Unsigned outval = sym->st_value + addend;
        WRITE_UNALIGNED(dbg,target_section + offset,
            &outval,sizeof(outval),reloc_size);
    }
    return DW_DLV_OK;
}



/*  Somewhat arbitrarily, we attempt to apply all the relocations we can
    and still notify the caller of at least one error if we found
    any errors.  */
static int
apply_rela_entries(Dwarf_Debug dbg,
    Dwarf_Bool is_64bit,
    Dwarf_Endianness endianess,
    Dwarf_Half machine,
    Dwarf_Small *target_section,
    Dwarf_Small *symtab_section,
    Dwarf_Unsigned symtab_section_size,
    Dwarf_Unsigned symtab_section_entrysize,
    struct Dwarf_Elf_Rela *relas, unsigned int nrelas,
    int *error)
{
    int return_res = DW_DLV_OK;
    if ((target_section != NULL)  && (relas != NULL)) {
        unsigned int i;
        if (symtab_section_entrysize == 0) {
            *error = DW_DLE_SYMTAB_SECTION_ENTRYSIZE_ZERO;
            return DW_DLV_ERROR;
        }
        if (symtab_section_size%symtab_section_entrysize) {
            *error = DW_DLE_SYMTAB_SECTION_LENGTH_ODD;
            return DW_DLV_ERROR;
        }
        for (i = 0; i < nrelas; i++) {
            int res = update_entry(dbg, is_64bit,
                endianess,
                machine,
                &(relas)[i],
                target_section,
                symtab_section,
                symtab_section_size,
                symtab_section_entrysize,
                error);
            if (res != DW_DLV_OK) {
                return_res = res;
            }
        }
    }
    return return_res;
}


static int
loop_through_relocations(
   Dwarf_Debug dbg,
   dwarf_elf_object_access_internals_t* obj,
   struct Dwarf_Section_s *relocatablesec,
   int *error)
{
    Dwarf_Small *target_section = 0;
    Dwarf_Small *symtab_section = obj->symtab->dss_data;
    Dwarf_Unsigned symtab_section_entrysize = obj->symtab->dss_entrysize;
    Dwarf_Unsigned symtab_section_size = obj->symtab->dss_size;
    Dwarf_Small *relocation_section  = relocatablesec->dss_reloc_data;
    Dwarf_Unsigned relocation_section_size =
        relocatablesec->dss_reloc_size;
    Dwarf_Unsigned relocation_section_entrysize = relocatablesec->dss_reloc_entrysize;

    int ret = DW_DLV_ERROR;
    struct Dwarf_Elf_Rela *relas = 0;
    unsigned int nrelas = 0;
    Dwarf_Small *mspace = 0;

    ret = get_relocation_entries(obj->is_64bit,
        obj->endianness,
        obj->machine,
        relocation_section,
        relocation_section_size,
        relocation_section_entrysize,
        &relas, &nrelas, error);
    if (ret != DW_DLV_OK) {
        free(relas);
        return ret;
    }

    /*  Some systems read Elf in read-only memory via mmap or the like.
        So the only safe thing is to copy the current data into
        malloc space and refer to the malloc space instead of the
        space returned by the elf library */
    mspace = malloc(relocatablesec->dss_size);
    if (!mspace) {
        *error = DW_DLE_RELOC_SECTION_MALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    memcpy(mspace,relocatablesec->dss_data,relocatablesec->dss_size);
    relocatablesec->dss_data = mspace;
    target_section = relocatablesec->dss_data;
    relocatablesec->dss_data_was_malloc = 1;

    ret = apply_rela_entries(
        dbg,
        obj->is_64bit,
        obj->endianness, obj->machine,
        target_section,
        symtab_section,
        symtab_section_size,
        symtab_section_entrysize,
        relas, nrelas, error);
    free(relas);
    return ret;
}

/*  Find the section data in dbg and find all the relevant
    sections.  Then do relocations.
*/
static int
dwarf_elf_object_relocate_a_section(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Debug dbg,
    int* error)
{
    int res = DW_DLV_ERROR;
    dwarf_elf_object_access_internals_t*obj = 0;
    struct Dwarf_Section_s * relocatablesec = 0;
    if (section_index == 0) {
        return DW_DLV_NO_ENTRY;
    }
    obj = (dwarf_elf_object_access_internals_t*)obj_in;

    /* The section to relocate must already be loaded into memory. */
    res = find_section_to_relocate(dbg, section_index,&relocatablesec,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /*  Sun and possibly others do not always set sh_link in .debug_* sections.
        So we cannot do full  consistency checks. */
    if (relocatablesec->dss_reloc_index == 0 ) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_SECTION_MISSING_INDEX;
        return DW_DLV_ERROR;
    }
    /* Now load the relocations themselves. */
    res =  dwarf_elf_object_access_load_section(obj_in,
        relocatablesec->dss_reloc_index,
        &relocatablesec->dss_reloc_data, error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /* Now get the symtab. */
    if (!obj->symtab) {
        obj->symtab = &dbg->de_elf_symtab;
        obj->strtab = &dbg->de_elf_strtab;
    }
    if (obj->symtab->dss_index != relocatablesec->dss_reloc_link) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_MISMATCH_RELOC_INDEX;
        return DW_DLV_ERROR;
    }
    if (obj->strtab->dss_index != obj->symtab->dss_link) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_MISMATCH_STRTAB_INDEX;
        return DW_DLV_ERROR;
    }
    if (!obj->symtab->dss_data) {
        /* Now load the symtab */
        res =  dwarf_elf_object_access_load_section(obj_in,
            obj->symtab->dss_index,
            &obj->symtab->dss_data, error);
        if (res != DW_DLV_OK) {
            return res;
        }
    }
    if (!obj->strtab->dss_data) {
        /* Now load the strtab */
        res = dwarf_elf_object_access_load_section(obj_in,
            obj->strtab->dss_index,
            &obj->strtab->dss_data,error);
        if (res != DW_DLV_OK){
            return res;
        }
    }

    /* We have all the data we need in memory. */
    res = loop_through_relocations(dbg,obj,relocatablesec,error);

    return res;
}

/* dwarf_elf_object_access_load_section */
static int
dwarf_elf_object_access_load_section(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Small** section_data,
    int* error)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    if (section_index == 0) {
        return DW_DLV_NO_ENTRY;
    }

    {
        Elf_Scn *scn = 0;
        Elf_Data *data = 0;

        scn = elf_getscn(obj->elf, section_index);
        if (scn == NULL) {
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }

        /*  When using libelf as a producer, section data may be stored
            in multiple buffers. In libdwarf however, we only use libelf
            as a consumer (there is a dwarf producer API, but it doesn't
            use libelf). Because of this, this single call to elf_getdata
            will retrieve the entire section in a single contiguous
            buffer. */
        data = elf_getdata(scn, NULL);
        if (data == NULL) {
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }
        *section_data = data->d_buf;
    }
    return DW_DLV_OK;
}


/* dwarf_elf_access method table. */
static const struct Dwarf_Obj_Access_Methods_s dwarf_elf_object_access_methods =
{
    dwarf_elf_object_access_get_section_info,
    dwarf_elf_object_access_get_byte_order,
    dwarf_elf_object_access_get_length_size,
    dwarf_elf_object_access_get_pointer_size,
    dwarf_elf_object_access_get_section_count,
    dwarf_elf_object_access_load_section,
    dwarf_elf_object_relocate_a_section
};


/* Interface for the ELF object file implementation.  */
int
dwarf_elf_object_access_init(dwarf_elf_handle elf,
    int libdwarf_owns_elf,
    Dwarf_Obj_Access_Interface** ret_obj,
    int *err)
{
    int res = 0;
    dwarf_elf_object_access_internals_t *internals = 0;
    Dwarf_Obj_Access_Interface *intfc = 0;

    internals = malloc(sizeof(dwarf_elf_object_access_internals_t));
    if (!internals) {
        /* Impossible case, we hope. Give up. */
        return DW_DLV_ERROR;
    }
    memset(internals,0,sizeof(*internals));
    res = dwarf_elf_object_access_internals_init(internals, elf, err);
    if (res != DW_DLV_OK){
        free(internals);
        return DW_DLV_ERROR;
    }
    internals->libdwarf_owns_elf = libdwarf_owns_elf;

    intfc = malloc(sizeof(Dwarf_Obj_Access_Interface));
    if (!intfc) {
        /* Impossible case, we hope. Give up. */
        free(internals);
        return DW_DLV_ERROR;
    }
    /* Initialize the interface struct */
    intfc->object = internals;
    intfc->methods = &dwarf_elf_object_access_methods;

    *ret_obj = intfc;
    return DW_DLV_OK;
}



/* Clean up the Dwarf_Obj_Access_Interface returned by elf_access_init.  */
void
dwarf_elf_object_access_finish(Dwarf_Obj_Access_Interface* obj)
{
    if (!obj) {
        return;
    }
    if (obj->object) {
        dwarf_elf_object_access_internals_t *internals =
            (dwarf_elf_object_access_internals_t *)obj->object;
        if (internals->libdwarf_owns_elf){
            elf_end(internals->elf);
        }
    }
    free(obj->object);
    free(obj);
}

/*  This function returns the Elf * pointer
    associated with a Dwarf_Debug.

    This function only makes sense if ELF is implied.  */
int
dwarf_get_elf(Dwarf_Debug dbg, dwarf_elf_handle * elf,
    Dwarf_Error * error)
{
    struct Dwarf_Obj_Access_Interface_s * obj = 0;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    obj = dbg->de_obj_file;
    if (obj) {
        dwarf_elf_object_access_internals_t *internals =
            (dwarf_elf_object_access_internals_t*)obj->object;
        if (internals->elf == NULL) {
            _dwarf_error(dbg, error, DW_DLE_FNO);
            return (DW_DLV_ERROR);
        }
        *elf = internals->elf;
        return DW_DLV_OK;

    }
    _dwarf_error(dbg, error, DW_DLE_FNO);
    return DW_DLV_ERROR;
}


