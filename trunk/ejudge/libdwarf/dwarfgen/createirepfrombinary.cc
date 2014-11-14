/*
  Copyright (C) 2010-2013 David Anderson.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of the example nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY David Anderson ''AS IS'' AND ANY
  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL David Anderson BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

// createirepfrombinary.cc

// Reads an object and inserts its dwarf data into
// an object intended to hold all the dwarf data.

#include "config.h"
#include <unistd.h>
#include <stdlib.h> // for exit
#include <iostream>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <string.h> // For memset etc
#include <sys/stat.h> //open
#include <fcntl.h> //open
#include "gelf.h"
#include "strtabdata.h"
#include "dwarf.h"
#include "libdwarf.h"
#include "irepresentation.h"
#include "createirepfrombinary.h"
#include "general.h" // For IToHex()

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::vector;
using std::list;
using std::map;

static void readFrameDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep);
static void readMacroDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep);
static void readCUDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep);
static void readGlobals(Dwarf_Debug dbg, IRepresentation & irep);

class DbgInAutoCloser {
public:
    DbgInAutoCloser(Dwarf_Debug dbg,int fd): dbg_(dbg),fd_(fd) {};
    ~DbgInAutoCloser() {
        Dwarf_Error err = 0;
        dwarf_finish(dbg_,&err);
        close(fd_);
    };
private:
    Dwarf_Debug dbg_;
    int fd_;
};


void
createIrepFromBinary(const std::string &infile,
   IRepresentation & irep)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Error err;
    int fd = open(infile.c_str(),O_RDONLY, 0);
    if(fd < 0 ) {
        cerr << "Unable to open " << infile <<
            " for reading." << endl;
        exit(1);
    }
    // All reader error handling is via the err argument.
    int res = dwarf_init(fd,DW_DLC_READ,
        0,
        0,
        &dbg,
        &err);
    if(res != DW_DLV_OK) {
        close(fd);
        cerr << "Error init-ing " << infile <<
            " for reading." << endl;
        exit(1);
    }

    DbgInAutoCloser closer(dbg,fd);

    readFrameDataFromBinary(dbg,irep);
    readCUDataFromBinary(dbg,irep);
    readMacroDataFromBinary(dbg,irep);
    readGlobals(dbg,irep);
    return;
}

static void
readFrameDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep)
{
    Dwarf_Error err = 0;
    Dwarf_Cie * cie_data = 0;
    Dwarf_Signed  cie_count = 0;
    Dwarf_Fde * fde_data = 0;
    Dwarf_Signed  fde_count = 0;
    int res = dwarf_get_fde_list(dbg,
        &cie_data,
        &cie_count,
        &fde_data,
        &fde_count,
        &err);
    if(res == DW_DLV_NO_ENTRY) {
        // No frame data.
        return;
    }
    if(res == DW_DLV_ERROR) {
        cerr << "Error reading frame data " << endl;
        exit(1);
    }

    for(Dwarf_Signed i =0; i < cie_count; ++i) {
        Dwarf_Unsigned bytes_in_cie = 0;
        Dwarf_Small    version = 0;
        char *         augmentation = 0;
        Dwarf_Unsigned code_alignment_factor = 0;
        Dwarf_Signed   data_alignment_factor = 0;
        Dwarf_Half     return_address_register_rule = 0;
        Dwarf_Ptr      initial_instructions = 0;
        Dwarf_Unsigned initial_instructions_length = 0;
        res = dwarf_get_cie_info(cie_data[i], &bytes_in_cie,
            &version,&augmentation, &code_alignment_factor,
            &data_alignment_factor,&return_address_register_rule,
            &initial_instructions,&initial_instructions_length,
            &err);
        if(res != DW_DLV_OK) {
            cerr << "Error reading frame data cie index " << i << endl;
            exit(1);
        }
        // Index in cie_data must match index in ciedata_, here
        // correct by construction.
        IRCie cie(bytes_in_cie,version,augmentation,code_alignment_factor,
            data_alignment_factor,return_address_register_rule,
            initial_instructions,initial_instructions_length);
        irep.framedata().insert_cie(cie);
    }
    for(Dwarf_Signed i =0; i < fde_count; ++i) {
        Dwarf_Addr low_pc = 0;
        Dwarf_Unsigned    func_length = 0;
        Dwarf_Ptr         fde_bytes = 0;
        Dwarf_Unsigned    fde_byte_length = 0;
        Dwarf_Off   cie_offset = 0;
        Dwarf_Signed     cie_index = 0;
        Dwarf_Off      fde_offset = 0;
        res = dwarf_get_fde_range(fde_data[i], &low_pc,
            &func_length,&fde_bytes, &fde_byte_length,
            &cie_offset,&cie_index,
            &fde_offset,
            &err);
        if(res != DW_DLV_OK) {
            cerr << "Error reading frame data fde index " << i << endl;
            exit(1);
        }
        IRFde fde(low_pc,func_length,fde_bytes,fde_byte_length,
            cie_offset, cie_index,fde_offset);
        Dwarf_Ptr instr_in = 0;
        Dwarf_Unsigned instr_len = 0;
        res = dwarf_get_fde_instr_bytes(fde_data[i],
            &instr_in, &instr_len, &err);
        if(res != DW_DLV_OK) {
            cerr << "Error reading frame data fde instructions " << i << endl;
            exit(1);
        }
        fde.get_fde_instrs_into_ir(instr_in,instr_len);
        irep.framedata().insert_fde(fde);
    }
    dwarf_fde_cie_list_dealloc(dbg,cie_data,cie_count,
        fde_data,fde_count);
}


static void
readCUMacroDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep,
    Dwarf_Unsigned macrodataoffset,IRCUdata &cu)
{
    // Arbitrary, but way too high to be real!
    // Probably should be lower.
    Dwarf_Unsigned maxcount = 1000000000;
    Dwarf_Error error;
    Dwarf_Signed mcount=0;
    Dwarf_Macro_Details *md = 0;
    int res = dwarf_get_macro_details(dbg,macrodataoffset,
        maxcount, &mcount, &md, &error);
    if(res == DW_DLV_OK) {
        IRMacro &macrodata = irep.macrodata();
        vector<IRMacroRecord> mvec = macrodata.getMacroVec();
        mvec.reserve(mcount);
        Dwarf_Unsigned dieoffset = cu.baseDie().getGlobalOffset();
        Dwarf_Macro_Details *mdp = md;
        for(int i = 0; i < mcount; ++i, mdp++ ) {
            IRMacroRecord ir(dieoffset,mdp->dmd_offset,
                mdp->dmd_type, mdp->dmd_lineno,
                mdp->dmd_fileindex, mdp->dmd_macro?mdp->dmd_macro:"");
            mvec.push_back(ir);
        }
    }
    dwarf_dealloc(dbg, md, DW_DLA_STRING);
}

void
get_basic_attr_data_one_attr(Dwarf_Debug dbg,
    Dwarf_Attribute attr,IRCUdata &cudata,IRAttr & irattr)
{
    Dwarf_Error error;
    Dwarf_Half attrnum = 0;
    Dwarf_Half finalform = 0;
    Dwarf_Half initialform = 0;
    int res = dwarf_whatattr(attr,&attrnum,&error);
    if(res != DW_DLV_OK) {
        cerr << "Unable to get attr number " << endl;
        exit(1);
    }
    res = dwarf_whatform(attr,&finalform,&error);
    if(res != DW_DLV_OK) {
        cerr << "Unable to get attr form " << endl;
        exit(1);
    }

    res = dwarf_whatform_direct(attr,&initialform,&error);
    if(res != DW_DLV_OK) {
        cerr << "Unable to get attr direct form " << endl;
        exit(1);
    }
    irattr.setBaseData(attrnum,finalform,initialform);
    enum Dwarf_Form_Class cl = dwarf_get_form_class(
        cudata.getVersionStamp(), attrnum,
        cudata.getOffsetSize(), finalform);
    irattr.setFormClass(cl);
    if (cl == DW_FORM_CLASS_UNKNOWN) {
        cerr << "Unable to figure out form class. ver " <<
            cudata.getVersionStamp() <<
            " attrnum " << attrnum <<
            " offsetsize " << cudata.getOffsetSize() <<
            " formnum " <<  finalform << endl;
        return;
    }
    irattr.setFormData(formFactory(dbg,attr,cudata,irattr));
}
void
get_basic_die_data(Dwarf_Debug dbg,
    Dwarf_Die indie,IRDie &irdie)
{
    Dwarf_Half tagval = 0;
    Dwarf_Error error = 0;
    int res = dwarf_tag(indie,&tagval,&error);
    if(res != DW_DLV_OK) {
        cerr << "Unable to get die tag "<< endl;
        exit(1);
    }
    Dwarf_Off goff = 0;
    res = dwarf_dieoffset(indie,&goff,&error);
    if(res != DW_DLV_OK) {
        cerr << "Unable to get die offset "<< endl;
        exit(1);
    }
    Dwarf_Off localoff = 0;
    res = dwarf_die_CU_offset(indie,&localoff,&error);
    if(res != DW_DLV_OK) {
        cerr << "Unable to get cu die offset "<< endl;
        exit(1);
    }
    irdie.setBaseData(tagval,goff,localoff);
}


static void
get_attrs_of_die(Dwarf_Die in_die,IRDie &irdie,
    IRCUdata &cudata,
    IRepresentation &irep,
    Dwarf_Debug dbg)
{
    Dwarf_Error error = 0;
    Dwarf_Attribute *atlist = 0;
    Dwarf_Signed atcnt = 0;
    std::list<IRAttr> &attrlist = irdie.getAttributes();
    int res = dwarf_attrlist(in_die, &atlist,&atcnt,&error);
    if(res == DW_DLV_NO_ENTRY) {
        return;
    }
    if(res == DW_DLV_ERROR) {
        cerr << "dwarf_attrlist failed " << endl;
        exit(1);
    }
    for (Dwarf_Signed i = 0; i < atcnt; ++i) {
        Dwarf_Attribute attr = atlist[i];
        // Use an empty attr to get a placeholder on
        // the attr list for this IRDie.
        IRAttr irattr;
        attrlist.push_back(irattr);
        // We want a pointer to the final attr to be
        // recorded for references, not a local temp IRAttr.
        IRAttr & lastirattr = attrlist.back();
        get_basic_attr_data_one_attr(dbg,attr,cudata,lastirattr);

    }
    dwarf_dealloc(dbg,atlist, DW_DLA_LIST);
}

// Invariant: IRDie and IRCUdata are in the irep tree,
// not local record references to local scopes.
static void
get_children_of_die(Dwarf_Die in_die,IRDie&irdie,
    IRCUdata &ircudata,
    IRepresentation &irep,
    Dwarf_Debug dbg)
{
    Dwarf_Die curchilddie = 0;
    Dwarf_Error error = 0;
    int res = dwarf_child(in_die,&curchilddie,&error);
    if(res == DW_DLV_NO_ENTRY) {
        return;
    }
    if(res == DW_DLV_ERROR) {
        cerr << "dwarf_child failed " << endl;
        exit(1);
    }
    //std::list<IRDie> & childlist =  irdie.getChildren();
    int childcount = 0;
    for(;;) {
        IRDie child;
        get_basic_die_data(dbg,curchilddie,child);
        irdie.addChild(child);
        IRDie &lastchild = irdie.lastChild();
        get_attrs_of_die(curchilddie,lastchild,ircudata,irep,dbg);

        ircudata.insertLocalDieOffset(lastchild.getCURelativeOffset(),
            &lastchild);

        get_children_of_die(curchilddie,lastchild,ircudata,irep,dbg);
        ++childcount;

        Dwarf_Die tchild = 0;
        res = dwarf_siblingof(dbg,curchilddie,&tchild,&error);
        if(res == DW_DLV_NO_ENTRY) {
            break;
        }
        if(res == DW_DLV_ERROR) {
            cerr << "dwarf_siblingof failed " << endl;
            exit(1);
        }
        dwarf_dealloc(dbg,curchilddie,DW_DLA_DIE);
        curchilddie = tchild;
    }
    dwarf_dealloc(dbg,curchilddie,DW_DLA_DIE);
}

static void
get_linedata_of_cu_die(Dwarf_Die in_die,IRDie&irdie,
    IRCUdata &ircudata,
    IRepresentation &irep,
    Dwarf_Debug dbg)
{
    Dwarf_Error error = 0;
    char **srcfiles = 0;
    Dwarf_Signed srccount = 0;
    IRCULineData&culinesdata =  ircudata.getCULines();
    int res = dwarf_srcfiles(in_die,&srcfiles, &srccount,&error);
    if(res == DW_DLV_ERROR) {
        cerr << "dwarf_srcfiles failed " << endl;
        exit(1);
    } else if (res == DW_DLV_NO_ENTRY) {
        // No data.
        return;
    }

    std::vector<IRCUSrcfile> &srcs = culinesdata.get_cu_srcfiles();
    for (Dwarf_Signed i = 0; i < srccount; ++i) {
        IRCUSrcfile S(srcfiles[i]);
        srcs.push_back(S);
        /* use srcfiles[i] */
        dwarf_dealloc(dbg, srcfiles[i], DW_DLA_STRING);
    }
    dwarf_dealloc(dbg, srcfiles, DW_DLA_LIST);

    Dwarf_Line * linebuf = 0;
    Dwarf_Signed linecnt = 0;
    int res2 = dwarf_srclines(in_die,&linebuf,&linecnt, &error);
    if(res == DW_DLV_ERROR) {
        cerr << "dwarf_srclines failed " << endl;
        exit(1);
    } else if (res == DW_DLV_NO_ENTRY) {
        // No data.
        cerr << "dwarf_srclines failed NO_ENTRY, crazy "
            "since srcfiles worked" << endl;
        exit(1);
    }

    std::vector<IRCULine> &lines = culinesdata.get_cu_lines();
    for(Dwarf_Signed j = 0; j < linecnt ; ++j ) {
        Dwarf_Line li = linebuf[j];
        int lres;

        Dwarf_Addr address = 0;
        lres = dwarf_lineaddr(li,&address,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_lineaddr failed. " << endl;
            exit(1);
        }
        Dwarf_Bool is_addr_set = 0;
        lres = dwarf_line_is_addr_set(li,&is_addr_set,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_line_is_addr_set failed. " << endl;
            exit(1);
        }
        Dwarf_Unsigned fileno = 0;
        lres = dwarf_line_srcfileno(li,&fileno,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_srcfileno failed. " << endl;
            exit(1);
        }
        Dwarf_Unsigned lineno = 0;
        lres = dwarf_lineno(li,&lineno,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_lineno failed. " << endl;
            exit(1);
        }
        Dwarf_Unsigned lineoff = 0;
        lres = dwarf_lineoff_b(li,&lineoff,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_lineoff failed. " << endl;
            exit(1);
        }
        char *linesrctmp = 0;
        lres = dwarf_linesrc(li,&linesrctmp,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_linesrc failed. " << endl;
            exit(1);
        }
        // libdwarf is trying to generate a full path,
        // the string here is that generated data, not
        // simply the 'file' path represented by the
        // file number (fileno).
        std::string linesrc(linesrctmp);


        Dwarf_Bool is_stmt = 0;
        lres = dwarf_linebeginstatement(li,&is_stmt,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_linebeginstatement failed. " << endl;
            exit(1);
        }

        Dwarf_Bool basic_block = 0;
        lres = dwarf_lineblock(li,&basic_block,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_lineblock failed. " << endl;
            exit(1);
        }

        Dwarf_Bool end_sequence = 0;
        lres = dwarf_lineendsequence(li,&end_sequence,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_lineendsequence failed. " << endl;
            exit(1);
        }

        Dwarf_Bool prologue_end = 0;
        Dwarf_Bool epilogue_begin = 0;
        Dwarf_Unsigned isa = 0;
        Dwarf_Unsigned discriminator = 0;
        lres = dwarf_prologue_end_etc(li,&prologue_end,
            &epilogue_begin,&isa,&discriminator,&error);
        if (lres != DW_DLV_OK) {
            cerr << "dwarf_prologue_end_etc failed. " << endl;
            exit(1);
        }

        IRCULine L(address,
            is_addr_set,
            fileno,
            lineno,
            lineoff,
            linesrc,
            is_stmt,
            basic_block,
            end_sequence,
            prologue_end,epilogue_begin,
            isa,discriminator);
        lines.push_back(L);
    }
    dwarf_srclines_dealloc(dbg, linebuf, linecnt);
}

static bool
getToplevelOffsetAttr(Dwarf_Die cu_die,Dwarf_Half attrnumber,
    Dwarf_Unsigned &offset_out)
{
    Dwarf_Error error = 0;
    Dwarf_Off offset = 0;
    Dwarf_Attribute attr = 0;
    int res = dwarf_attr(cu_die,attrnumber,&attr, &error);
    bool foundit = false;
    Dwarf_Off sectoff = 0;
    if(res == DW_DLV_OK) {
        Dwarf_Signed sval = 0;
        Dwarf_Unsigned uval = 0;
        res = dwarf_global_formref(attr,&offset,&error);
        if(res == DW_DLV_OK) {
            foundit = true;
            offset_out = offset;
        }
    }
    return foundit;
}

// We record the .debug_info info for each CU found
// To start with we restrict attention to very few DIEs and
// attributes,  but intend to get all eventually.
static void
readCUDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep)
{
    Dwarf_Error error;
    int cu_number = 0;
    std::list<IRCUdata> &culist = irep.infodata().getCUData();

    for(;;++cu_number) {
        Dwarf_Unsigned cu_header_length = 0;
        Dwarf_Half version_stamp = 0;
        Dwarf_Unsigned abbrev_offset = 0;
        Dwarf_Half address_size = 0;
        Dwarf_Unsigned next_cu_header = 0;
        Dwarf_Half offset_size = 0;
        Dwarf_Half extension_size = 0;
        Dwarf_Die no_die = 0;
        Dwarf_Die cu_die = 0;
        int res = DW_DLV_ERROR;
        res = dwarf_next_cu_header_b(dbg,&cu_header_length,
            &version_stamp, &abbrev_offset, &address_size,
            &offset_size, &extension_size,
            &next_cu_header, &error);
        if(res == DW_DLV_ERROR) {
            cerr <<"Error in dwarf_next_cu_header"<< endl;
            exit(1);
        }
        if(res == DW_DLV_NO_ENTRY) {
            /* Done. */
            return;
        }
        IRCUdata cudata(cu_header_length,version_stamp,
            abbrev_offset,address_size, offset_size,
            extension_size,next_cu_header);

        //  The CU will have a single sibling (well, it is
        //  not exactly a sibling, but close enough), a cu_die.
        res = dwarf_siblingof(dbg,no_die,&cu_die,&error);
        if(res == DW_DLV_ERROR) {
            cerr <<"Error in dwarf_siblingof on CU die "<< endl;
            exit(1);
        }
        if(res == DW_DLV_NO_ENTRY) {
            /* Impossible case. */
            cerr <<"no Entry! in dwarf_siblingof on CU die "<< endl;
            exit(1);
        }
        Dwarf_Off macrooffset = 0;
        bool foundmsect = getToplevelOffsetAttr(cu_die,DW_AT_macro_info,
            macrooffset);
        Dwarf_Off linesoffset = 0;
        bool foundlines = getToplevelOffsetAttr(cu_die,DW_AT_stmt_list,
            linesoffset);
        Dwarf_Off dieoff = 0;
        res = dwarf_dieoffset(cu_die,&dieoff,&error);
        if(res != DW_DLV_OK) {
            cerr << "Unable to get cu die offset for macro infomation "<< endl;
            exit(1);
        }
        if(foundmsect) {
            cudata.setMacroData(macrooffset,dieoff);
        }
        if(foundlines) {
            cudata.setLineData(linesoffset,dieoff);
        }
        culist.push_back(cudata);
        IRCUdata & treecu = irep.infodata().lastCU();
        IRDie &cuirdie = treecu.baseDie();
        get_basic_die_data(dbg,cu_die,cuirdie);
        treecu.insertLocalDieOffset(cuirdie.getCURelativeOffset(),
            &cuirdie);
        get_attrs_of_die(cu_die,cuirdie,treecu,irep,dbg);
        get_children_of_die(cu_die,cuirdie,treecu,irep,dbg);
        get_linedata_of_cu_die(cu_die,cuirdie,treecu,irep,dbg);

        // Now we have all local DIEs in the CU so we
        // can identify all targets of local CLASS_REFERENCE
        // and insert the IRDie * into the IRFormReference
        treecu.updateReferenceAttrDieTargets();

        dwarf_dealloc(dbg,cu_die,DW_DLA_DIE);
    }
    // If we want pointers from child to parent now is the time
    // we can construct them.
}

// We read thru the CU headers and the CU die to find
// the macro info for each CU (if any).
// We record the CU macro info for each CU found (using
// the value of the DW_AT_macro_info attribute, if any).
static void
readMacroDataFromBinary(Dwarf_Debug dbg, IRepresentation & irep)
{

    list<IRCUdata>  &cudata = irep.infodata().getCUData();
    list<IRCUdata>::iterator it = cudata.begin();
    int ct = 0;
    for( ; it != cudata.end(); ++it,++ct) {
        Dwarf_Unsigned macrooffset = 0;
        Dwarf_Unsigned cudieoffset = 0;
        bool foundmsect = it->hasMacroData(&macrooffset,&cudieoffset);
        if(foundmsect) {
            readCUMacroDataFromBinary(dbg, irep, macrooffset,*it);
        }
    }
}

// Offsets refer to .debug_info, nothing else.
static void
readGlobals(Dwarf_Debug dbg, IRepresentation & irep)
{
    Dwarf_Error   error;
    Dwarf_Global *globs = 0;
    Dwarf_Type   *types = 0;
    Dwarf_Signed  cnt = 0;
    Dwarf_Signed  i = 0;
    int res = 0;
    IRPubsData  &pubdata = irep.pubnamedata();

    res = dwarf_get_globals(dbg, &globs,&cnt, &error);
    if(res == DW_DLV_OK) {
        std::list<IRPub> &pubnames = pubdata.getPubnames();
        for (Dwarf_Signed i = 0; i < cnt; ++i) {
            Dwarf_Global g = globs[i];
            char *name = 0;
            // dieoff and cuoff may be in .debug_info
            // or .debug_types
            Dwarf_Off dieoff = 0;
            Dwarf_Off cuoff = 0;
            res = dwarf_global_name_offsets(g,&name,
                &dieoff,&cuoff,&error);
            if( res == DW_DLV_OK) {
                IRPub p(name,dieoff,cuoff);
                dwarf_dealloc(dbg,name,DW_DLA_STRING);
                pubnames.push_back(p);
            }
        }
        dwarf_globals_dealloc(dbg, globs, cnt);
    } else if (res == DW_DLV_ERROR) {
        cerr << "dwarf_get_globals failed" << endl;
        exit(1);
    }
    res = dwarf_get_pubtypes(dbg, &types,&cnt, &error);
    if(res == DW_DLV_OK) {
        std::list<IRPub> &pubtypes = pubdata.getPubtypes();
        for (Dwarf_Signed i = 0; i < cnt; ++i) {
            Dwarf_Type g = types[i];
            char *name = 0;
            // dieoff and cuoff may be in .debug_info
            // or .debug_types
            Dwarf_Off dieoff = 0;
            Dwarf_Off cuoff = 0;
            res = dwarf_pubtype_name_offsets(g,&name,
                &dieoff,&cuoff,&error);
            if( res == DW_DLV_OK) {
                IRPub p(name,dieoff,cuoff);
                dwarf_dealloc(dbg,name,DW_DLA_STRING);
                pubtypes.push_back(p);
            }
        }
        dwarf_types_dealloc(dbg, types, cnt);
    } else if (res == DW_DLV_ERROR) {
        cerr << "dwarf_get_globals failed" << endl;
        exit(1);
    }




}

