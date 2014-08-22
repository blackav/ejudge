/* $Id$ */

/* Copyright (C) 1995-2014 Alexander Chernov <cher@ejudge.ru> */

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

#ifndef __REUSE_STRINGSET_H__
#define __REUSE_STRINGSET_H__

#include "ejudge/integral.h"

#include <stdio.h>

typedef unsigned int tssEntry;

/* This file defines interface to String Set module. Routines from this
 * module can store and manipulate with strings stored in table. It is
 * possible to have more than one string table in a time. Each string
 * table is denoted with string table descriptor. Such descriptor must
 * be passed to any routine which manipulates with string table. Number
 * of strings which can be stored in the table is unlimited. Memory will
 * be automatically reallocated when the table exceeds its capasity.
 * There are no means to remove string from the table.
 */

typedef struct tssDesc
{
  tssEntry *Transl;
  ruint_t     TranslSize;
  char **Table;
  ruint_t Allocd;
  ruint_t Used;
} tssDesc;

#if defined __cplusplus
extern "C" {
#endif /* __cplusplus */

/* module initialization/closure functions */

  void ssInitModule(void);
/* Initializes module. */

  void ssCloseModule(void);
/* Closes module. Deallocates memory used for internal data.
 * You cannot use functions of the module after you closed it.
 */

  void ssStatistics(FILE *f);
/* Prints some statistics about module */

#define ssInit(ssd)          _ssInit(&(ssd))
/* void ssInit(tssDesc ssd); */
/* Initializes string table `ssd' . This string table must not be
   initialized before. This function correspond to a C++ constructor
   of a class. */
  void _ssInit   (tssDesc *pssd);

#define ssDestroy(ssd)       _ssDestroy(&(ssd))
/* void ssDestroy(tssDesc ssd); */
/* Destroys string table `ssd'. Releases all dynamically allocated memory.
 * The table must be initialized. If it's not, behavour is undefined.
 * Destroyed string table must not be used further. A user have to
 * initialize it again prior to its use.
 */
  void _ssDestroy(tssDesc *pssd);

#define ssClear(ssd)         _ssClear(&(ssd))
/* void ssClear(tssDesc ssd); */
/* Clears string table, but do not destroys it. All strings which contained
 * in the table are released. A user can use emptied string table further
 * to add new strings etc.
 */
  void _ssClear  (tssDesc *pssd);

#define ssAdd(ssd,str)       _ssAdd(&(ssd),str)
/* void tssEntry ssAdd(tssDesc ssd,char *str); */
/* Adds string `str' to string table `ssd' and returns its identifier in
 * this table. This identifier may be used for accessing this string.
 * If string table already contains the same string, new table cell will
 * not be allocated and the function will return identifier of already
 * contained string. So several different by the sence strings may share
 * the same store cell if those string are equal.
 */
  tssEntry _ssAdd(tssDesc *pssd,char *str);

#define ssCheck(ssd,str)     _ssCheck(&(ssd),str)
/* int ssCheck(tssDesc ssd,char *str); */
/* Checks whether string `str' already stored in the string table
 * `ssd'. Returns `1' (TRUE) if so, and `0' if this string is not
 * contained in the table.
 */
  int  _ssCheck  (tssDesc *pssd,char *str);

#define ssString(ssd,sse)    _ssString(&(ssd),sse)
/* char *ssString(tssDesc ssd,tssEntry sse); */
/* Returns pointer to string with identifier `sse' in the string
 * table `ssd'. The function returns pointer to internal store of this
 * string, so you must access the string READ ONLY!!!
 * If there is no string with such identified dynamic error is raised
 * (currently `abort' function is called).
 */
  char *_ssString(tssDesc *pssd,tssEntry sse);

#define ssDup(ssd,sse)       _ssDup(&(ssd),sse)
/* char *ssDup(tssDesc ssd,tssEntry sse); */
/* Returns copy of the string with identifier `sse' in the string
 * table `ssd'. Memory for copy is allocated in the heap (strdup
 * function is used. You can freely modify this copy.
 */
  char *_ssDup   (tssDesc *pssd,tssEntry sse);

#define ssSize(ssd)          ((ssd).Used)
/* void ssSize(tssDesc ssd); */
/* returns size of string set */

#define ssPut(ssd,sse,pf)    _ssPut(&(ssd),sse,pf)
/* void ssPut(tssDesc ssd,tssEntry sse,FILE *pf); */
/* Writes identifier of a string to a binary file. String identified is
 * written as a number, not as string itself, so the whole string table
 * must be also written.
 */
  void _ssPut    (tssDesc *pssd,tssEntry sse,FILE *pf);

#define ssWrite(ssd,sse,pf)  _ssWrite(&(ssd),sse,pf)
/* void ssWrite(tssDesc ssd,tssEntry sse,FILE *pf); */
/* Writes string identified to a text file. */
  void _ssWrite  (tssDesc *pssd,tssEntry sse,FILE *pf);

#define ssGet(ssd,sse,pf)    _ssGet(&(ssd),&(sse),pf)
/* void ssGet(tssDesc ssd,tssEntry sse,FILE *pf); */
/* Reads string identified from binary file. During reading string
 * identifier will be translated to actual string identifier of the
 * string which was denoted by this string identifier during writing.
 * In order to translate it correctly, the whole string table must be
 * read PRIOR to reading of all string identifiers related to this
 * string table.
 */
  void _ssGet    (tssDesc *pssd,tssEntry *sse,FILE *pf);

#define ssRead(ssd,sse,pf)   _ssRead(&(ssd),&(sse),pf)
/* void ssRead(tssDesc ssd,tssEntry sse,FILE *pf); */
/* Reads string identifier from text file. During reading this identifier
 * will be recoded. See description of ssGet for further information
 */
  void _ssRead   (tssDesc *pssd,tssEntry *sse,FILE *pf);

#define ssdPut(ssd,pf)       _ssdPut(&(ssd),pf)
/* void ssdPut(tssDesc ssd,FILE *pf); */
/* Writes string table `ssd' as a whole to binary file. */
  void _ssdPut   (tssDesc *ppsd,FILE *f);

#define ssdGet(ssd,pf)       _ssdGet(&(ssd),pf)
/* void ssdPut(tssDesc ssd,FILE *pf); */
/* Reads string table `ssd' from a binary file. String table `ssd' must
 * be initialized prior to reading. String table from a file will be
 * APPENDED to existing string table `ssd', this makes necessary recoding
 * of string identifiers during their reading. This recoding is performed
 * in correspoing functions (see above). String table must be read PRIOR
 * to reading identifiers of string contained in it.
 */
  void _ssdGet   (tssDesc *ppsd,FILE *f);

#define ssdWrite(ssd,pf)     _ssdWrite(&(ssd),pf)
/* void ssdPut(tssDesc ssd,FILE *pf); */
/* Writes string table `ssd' as a whole to text file. */
  void _ssdWrite (tssDesc *ppsd,FILE *f);

#define ssdRead(ssd,pf)      _ssdRead(&(ssd),pf)
/* void ssdPut(tssDesc ssd,FILE *pf); */
/* Reads string table `ssd' from a text file. See `ssdPut' function
 * for further description.
 */
  void _ssdRead  (tssDesc *ppsd,FILE *f);

/* Macros for cocktail */

#define begintssEntry(sse)           sse = 0;
#define closetssEntry(sse)
#define readtssEntry(sse)            abort();
#define writetssEntry(sse)           abort();
#define gettssEntry(sse)             abort();
#define puttssEntry(sse)             abort();
#define copytssEntry(sseDest,sseSrc) sseDest = sseSrc;

/* type tssEntry cannot be used as Field of AST tree. The user should
 * define concrete type simply 'typedef tssEntry MyType' and then redefine
 * type specific Cocktail macros in order to specify concrete string table to
 * manipulate with. I. e. user should define a new type (as synonym of type
 * tssDesc for each string table to be used in AST tree).
*/

#define begintssDesc(ssd)            abort();
#define closetssDesc(ssd)            abort();
#define readtssDesc(ssd)             abort();
#define writetssDesc(ssd)            abort();
#define gettssDesc(ssd)              abort();
#define puttssDesc(ssd)              abort();
#define copytssDesc(ssd)             abort();

/* There are no allowed operations in AST tree with tssDesc, so data of
 * this type cannot be stored in it. There is the following technics to
 * automatize reading and writing of such tables:
 * Each string table must be defined outside of AST tree in static memory
 * area (let this string table is called GRefTable).
 * User should define a new type as stub in AST tree, e. g.
 * typedef int tGRefTable. Type of it does not matter, only name of the
 * type is used to redefine AST type specific macroses (in our example:
 * WritetGrefTable, ReadtGRefTable, PuttGRefTable, GettGRefTable) to 
 * manipulate with concrete String Table, e. g.
 * #define GettGRefTable(x) ssdGet(GRefTable,yyf);
 * (see file Position.h for example of such technique).
 */

#if defined __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_STRINGSET_H__ */
