/*
  Copyright (C) 2009-2012 David Anderson.  All Rights Reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

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

*/
/* The address of the Free Software Foundation is
   Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
   Boston, MA 02110-1301, USA.  */



/*
This tries to find the string 'contained' in the
string 'container'.  it returns true if found, else false.
The comparisons are independent  of case.

Regrettably there is no generally accepted version that
does this job, though GNU Linux has  strcasestr() which
does what we need.   Our code here do not behave like
strstr or strcasestr in the case of
an empty 'contained' argument: we return FALSE (this
case is not interesting for dwarfdump).

There is a public domain stristr().    But given that dwarfdump is GPL,
it would seem (IANAL) that we cannot mix public domain code
into the release.

The software here is independently written and indeed trivial.

The POSIX function tolower() is only properly defined on unsigned char, hence
the ugly casts.

strstrnocase.c

*/
#include <ctype.h>
#include <stdio.h>
#include <globals.h>

boolean
is_strstrnocase(const char * container, const char * contained)
{
    const unsigned char *ct = (const unsigned char *)container;
    for (; *ct; ++ct )
    {
        const unsigned char * cntnd = (const unsigned char *)contained;
        boolean innerwrong = TRUE;
        for (; *cntnd; ++cntnd,++ct)
        {
            char lct = tolower(*ct);
            char tlc = tolower(*cntnd);
            if (lct != tlc) {
                innerwrong=TRUE;
                break; /* Go to outer loop */
            }
            innerwrong=FALSE;
        }
        if (!innerwrong) {
            return TRUE;
        }
    }
    return FALSE;
}

#ifdef TEST
static void
test(const  char *t1, const char *t2,int resexp)
{
    boolean  res = is_strstrnocase(t1,t2);
    if (res == resexp) {
        return;
    }
    printf("Error,mismatch %s and %s.  Expected %d got %d\n",
        t1,t2,resexp,res);
}

int main()
{
    test("aaaaa","a",1);
    test("aaaaa","b",0);
    test("abaaba","ba",1);
    test("abaaxa","x",1);
    test("abaabA","Ba",1);
    test("a","ab",0);
    test("b","c",0);
    test("b","",0);
    test("","c",0);
    test("","",0);
    test("aaaaa","aaaaaaaa",0);
}
#endif
