/* $Id$ */

#ifndef __REUSE_POSITIONS_H__
#define __REUSE_POSITIONS_H__

/* Copyright (C) 1995-2014 Alexander Chernov <cher@ejudge.ru> */
/* Ich, Doktor Josef Grosch, Informatiker, Juli 1992 */
/* Alexander Chernov, October 1995 */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/*
 * This file (Positions.h) is derived from file Positions.h which is
 * a part of Reuse library from Karlsruhe Compiler Toolbox (Cocktail).
 * I provide additional functionality related with posibility of
 * keeping track of several input files. All original copying
 * information is preserved.
 */

#include "ejudge/integral.h"
#include "ejudge/r_stringset.h"

#include <stdio.h>

/* typedef tssEntry tFName; */
typedef unsigned short tFName;
/*
 * type of an entry in a table of file names is defined as alias
 * of generic entry type in string table (see StringSet.h)
 */

typedef struct tPosition
{
  unsigned int   Line;
  unsigned short Column;
  tFName         FName;
} tPosition;

/*
 * FName is an internal representation of file name (actually it is
 * a string identifier in a table of file names).
 */

/*
 * This stuff is preserved for compatbility with original
 * Cocktail version of Positions.h
 */

/* A default position. */
#if !defined __REUSE__
#if defined __BORLANDC__
static tPosition NoPosition;
#else
tPosition NoPosition;
#endif /* __BORLANDC__ */
#endif /* __REUSE__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define Compare(pos1,pos2)   posCmp(&(pos1),&(pos2))
/* int  Compare(tPosition Position1, tPosition Position2); */
/* Returns -1 if Position1 < Position2.         */
/* Returns  0 if Position1 = Position2.         */
/* Returns  1 if Position1 > Position2.         */

  void WritePosition(FILE * File, tPosition Position);
/* The 'Position' is printed on the 'File'.     */

#define posLine(pos)     ((pos).Line)

/* wrappers for functions */
#define posPut(pos,f)    _posPut(&(pos),f)
/* void posPut(tPosition pos,FILE *f); */
/* Writes tPosition structure to binary file */
  void _posPut(tPosition *pos,FILE *f);

#define posGet(pos,f)    _posGet(&(pos),f)
/* void posGet(tPosition pos,FILE *f); */
/* Reads tPosition structure from binary file. The function properly
 * manipulates with string identifiers of graphical position and file
 * name. Internal tables must be read prior to reading of any of
 * tPosition structures. See posGetTable.
 */
  void _posGet(tPosition *pos,FILE *f);

#define posRead(pos,f)   _posRead(&(pos),f)
/* void posRead(tPosition pos,FILE *f); */
/* Reads tPosition structure from text file */
  void _posRead(tPosition *pos,FILE *f);

#define posWrite(pos,f)  _posWrite(&(pos),f)
/* void posWrite(tPosition pos,FILE *f); */
/* Writes tPosition structure to text file */
  void _posWrite(tPosition *pos,FILE *f);

#define posNext(pos,c)   _posNext(&(pos),c)
/* void posNext(tPosition pos,char c); */
/* Increases position according to character `c':
 * '\n' and '\t' characters are supported
 */
  void _posNext(tPosition *pos,char c);

#define posNextChar(pos) ((pos).Column++)
/* void posNextChar(tPosition pos); */
/* Increase position for ordinary printable character */

#define posNNextChars(pos,n) ((pos).Column += (n))
/* void posNNextChars(tPosition pos, int n); */
/* Increase position for n ordinary printable characters */

#define posNL(pos)       ((pos).Column = 0, (pos).Line++)
/* void posNL(tPosition pos); */
/* Increase position for '\n' character */

#define posTab(pos)      ((pos).Column = (((pos).Column + 8) & ~7))
/* void posTab(tPosition pos); */
/* Increase position for '\t' character.
 * Tabulation is assumed to be 8 characters long.
 */

  void posInitModule(void);
/* initializes internal tables. This function must be called prior
 * to any use of other functions of this module.
 */

  void posCloseModule(void);
/*
 * Deallocate memory allocated for internal data structures.
 * You CANNOT USE functions of the module except `posInitModule'
 * and `posStatistics' after you closed the module!
 */

  void posStatistics(FILE*);
/*
 * Prints some statistics into the given file
 */

  tPosition posMake(ruint_t Line, ruint_t Pos, char *FName);
/* Words as a constructor for tPosition structure */

#define posSetFName(p, f)         _posSetFName(&(p), f)
/* void posSetFName(tPosition pos, char *Fname); */
  void _posSetFName(tPosition *pos, char *FName);
/* Fills up FName field */

#define posIsNoPosition(p)        ((p).FName == 0)
/* Bool posIsMoPosition(tPosition pos); */
/* checks whether pos == NoPosition */

  int posCmp(const tPosition *pos1,const tPosition *pos2);
/*
 * returns -1, if *pos1 < *pos2,
 *          0, if *pos1 == *pos2,
 *          1, if *pos1 > *pos2
 * This function is particularly for use with such routines as qsort or
 * bsearch and other that use user provided comparison function.
 * This function must be casted to type void (*)(const void *,const void *)
 * in order to avoid compiler warnings.
 */

  int  possnPrintf(char *buf, int n, char const *format, tPosition pos);
  void posPrintf(FILE *f,char *strFormat,tPosition Pos);
/*
 * Prints source position in external representation.
 * The format line is similar to the format line
 * of function `printf' with certail specific:
 * -- format specifier begins with character '%' and ends with one of
 *    characters: 'l', 'c', 'f', 'g'. All characters beetween these
 *    characters constitute format specifier. Two subsequent '%' signs
 *    means one '%'.
 *    Format specifier has the form:
 *    '%' [ '-' | '+' | '#' ] [ <width> [ '.' <precision> ] ] <letter>
 *    where letter is one of: 'l', 'c', 'f', 'g' that mean:
 *        'l' - print line number         - transformed to 'u'
 *        'c' - print column number       - transformed to 'u'
 *        'f' - print file name           - transformed to 's'
 *        'g' - print graphical reference - transformed to 's'
 *    <width> and <precision> has the same sence as in printf
 */

/* Iterators for FName table */
#define posWriteFName(pos,f) fprintf((f),"%u",(pos).FName) 
#define posFirstFName()      ((tFName) 0)
#define posNextFName(f)      ((f)++)
  char *posGetFNameStr(tFName);
  int  posIsValidFName(tFName);

/*
 * Internal tables management functions.
 * DO NOT CALL THEM DIRECTLY
 */

  void posPutTable(FILE *f);
  void posGetTable(FILE *f);
  void posWriteTable(FILE *f);
  void posReadTable(FILE *f);

/* Cocktail specific stuff */

typedef int tPositionTable;
/*
 * It is stub type to represent internal tables in AST tree.
 * actual type does not matter here. Only name of this stub type
 * is significant for AST type specific macros for reading and
 * writing.
 * You should define field of this type in a ROOT node type of AST tree
 * as FIRST field (before any subnodes).
 */

#define gettPositionTable(x)    posGetTable(yyf);
#define puttPositionTable(x)    posPutTable(yyf);
#define readtPositionTable(x)   posReadTable(yyf);
#define writetPositionTable(x)  posWriteTable(yyf);
/* These macros read and write internal position tables */

/* Cocktail type specific macro for tPosition */
#define begintPosition(pos)     pos = NoPosition;
#define closetPosition(pos)
#define puttPosition(pos)       _posPut(&(pos),yyf);
#define gettPosition(pos)       _posGet(&(pos),yyf);
#define writetPosition(pos)     _posWrite(&(pos),yyf);
#define readtPosition(pos)      _posRead(&(pos),yyf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_POSITIONS_H__ */
