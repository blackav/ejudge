/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2009-2010 SN Systems Ltd. All Rights Reserved.
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

$Header: /plroot/cmplrs.src/v7.4.5m/.RCS/PL/dwarfdump/RCS/tag_common.h,v 1.8 2008/01/23 09:47:59 davea Exp $ */

#ifndef tag_common_INCLUDED
#define tag_common_INCLUDED



/* The following is the magic token used to
   distinguish real tags/attrs from group-delimiters.
   Blank lines have been eliminated by an awk script.
*/
#define MAGIC_TOKEN_VALUE 0xffffffff

/* TAG_TREE.LIST Expected input format

0xffffffff
value of a tag
value of a standard tag that may be a child of that tag
...
0xffffffff
value of a tag
value of a standard tag that may be a child of that tag
...
0xffffffff
...

No blank lines or commentary allowed, no symbols, just numbers.

*/

/* TAG_ATTR.LIST Expected input format

0xffffffff
value of a tag
value of a standard attribute that follows that tag
...
0xffffffff
value of a tag
value of a standard attribute that follows that tag
...
0xffffffff
...

No blank lines or commentary allowed, no symbols, just numbers.

*/

/* We don't need really long lines: the input file is simple. */
#define MAX_LINE_SIZE 1000

/*  1 more than the highest number in the DW_TAG defines,
    this is for standard TAGs. Number of rows. */
#define STD_TAG_TABLE_ROWS 0x44
/* Enough entries to have a bit for each standard legal tag. */
#define STD_TAG_TABLE_COLUMNS 7

/* TAG tree common extension maximums. */
#define EXT_TAG_TABLE_ROWS  7
#define EXT_TAG_TABLE_COLS  7

/* The following 2 used in tag_tree.c only. */
#define TAG_TABLE_ROW_MAXIMUM STD_TAG_TABLE_ROWS
#define TAG_TABLE_COLUMN_MAXIMUM  EXT_TAG_TABLE_COLS



/*  Number of attributes columns per tag. The array is bit fields,
    BITS_PER_WORD fields per word. Dense and quick to inspect */
#define COUNT_ATTRIBUTE_STD 7

#define STD_ATTR_TABLE_ROWS STD_TAG_TABLE_ROWS
#define  STD_ATTR_TABLE_COLUMNS  7
/* tag/attr tree common extension maximums. */
#define EXT_ATTR_TABLE_ROWS 7
#define EXT_ATTR_TABLE_COLS 7

/* The following 2 used in tag_attr.c only. */
#define ATTR_TABLE_ROW_MAXIMUM STD_ATTR_TABLE_ROWS
#define ATTR_TABLE_COLUMN_MAXIMUM  EXT_ATTR_TABLE_COLS

/* Bits per 'int' to mark legal attrs. */
#define BITS_PER_WORD 32

#define IS_EOF 1
#define NOT_EOF 0

extern void bad_line_input(const std::string &msg);
extern void trim_newline(std::string &line, int max);
extern bool is_blank_line(const std::string &pLine);
extern int read_value(unsigned int *outval,FILE *f);

#endif /* tag_common_INCLUDED */
