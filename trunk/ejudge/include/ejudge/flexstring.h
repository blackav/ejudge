/* $Id$ */

#ifndef __REUSE_FLEXSTRING_H__
#define __REUSE_FLEXSTRING_H__

/* Copyright (C) 1995-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <95/11/01 17:31:50 cher> */

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

/* DESCRIPTION:
 * tFString is a flexible string type.
 * Strings are terminated with '\0' character and can have
 * unlimited length. The module provides type-specific interface for
 * C code generated from AST specifications.
 * 
 * The following operations are defined on type tFString
 * (they are actually defined as macros, so don't confuse that tFString
 * is passed by value even it is modified in the function).
 * 
 */

#include "ejudge/integral.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct tFString
{
  char *String;
  ruint_t Allocd;
  ruint_t Used;
} tFString;

#if defined __cplusplus
extern "C" {
#endif /* __cplusplus */

#define fsNULL             { NULL, 0, 0 }
/* 
 * fsNULL is a STATIC INITIALIZER. 
 * You can use it for initialization of your static data like this
 * static tFString fs_foo = fsNULL;
 */

#define fsInit(a)          { (a).String = NULL; (a).Allocd = (a).Used = 0; }
/*
 * void fsInit(tFString fs);
 *   initializes structure. Work like C++ constructor.
 *   You must initialize all variables of type tFString prior
 *   to their use. Static or global variables are initialized
 *   automatically by C compiler, or you may use explicit
 *   initializator `fsNULL'. Automatic variables you MUST
 *   initialize by explicit call to fsInit. If you pass already
 *   initialized value to the routine it will not fail, but this
 *   will cause a heap memory leak. But call fsInit after another
 *   fsInit or after fsDestroy is safe.
 */    

#define fsInitEmpty(a)     _fsInitEmpty(&(a))
  void _fsInitEmpty(tFString *pfs);
/*
 * void fsInitEmpty(tFString fs);
 *   Initializes the flexible string with empty string. The difference
 *   between this function and the previous function is that the
 *   fsInit function initialized the string with NULL pointer when this
 *   one initializes the string with empty string "". Note, that this NULL
 *   pointer will be transparently changed to a valid memory location
 *   when the value of the string is changed to a non-empty. Note, however,
 *   that this does not affect fsString function and under certain condition
 *   fsString might return NULL pointer.
 */

#define fsDestroy(a)       _fsDestroy(&(a))
  void _fsDestroy(tFString *pfs);
/* 
 * void fsDestroy(tFString fs);
 *    Frees memory allocated for the given flexible string and
 *    resets its value to the value of empty string.
 *    The objects still keeps valid value, i. e you may call
 *    all flexible string routines with this value.
 *    You may call even fsInit or fsDestroy again and it will not
 *    an error.
 */

#define fsClear(a)         _fsClear(&(a))
  void _fsClear(tFString *pfs);
/*
 * void fsClear(tFString fs);
 *    clears string contained in its argument but do not release
 *    dynamic memory.
 */    

#define fsAlloc(a,s) _fsAlloc(&(a),s)
  void _fsAlloc(tFString *pfs,size_t size);
/*
 * void fsAlloc(tFString fs,size_t size);   
 *    allocates enough memory for storing a string of length size
 *    (size must count '\0' string terminator), but do not change contents
 *    of the string `fs'. If string `fs' already has enough size, no
 *    action is performed.
 */ 

#define fsSetChar(a,b)  _fsSetChar(&(a),b)
  void _fsSetChar(tFString *pfs, int);

#define fsSetStr(a,b)   _fsSetStr(&(a),b)
  void _fsSetStr(tFString *pfs, char *);

#define fsSetMem(a,b,c) _fsSetMem(&(a),b,c)
  void _fsSetMem(tFString *pfs, char *, int);

#define fsAdd(a,b) _fsInsChar(&(a),b,(a).Used)
/*
 * vois fsAdd(tFString fs,char c);
 *    adds a character passed in argument 'c' to the end of string
 *    and expands string memory if necessary.
 */
    
#define fsAppend(a,b) _fsInsStr(&(a),b,(a).Used)
/*
 * void fsAppend(tFString fs,char *str);
 *    adds a null-terminated string passed in 'str' to the end 
 *    of the flexible string 'fs'.
 */

#define fsAddMem(fs,s,l) _fsInsMem(&(fs),s,l,(fs).Used)
/*
 * void fsAddMem(tFString fs, char *mem, int len);
 *    adds a memory block to the end of the flexible string
 *    ``fs''
 */

#define fsConcat(d,s) _fsInsFS(&(d),&(s),(d).Used)
/*
 * void fsConcat(tFString fsDest,tFString fsSrc);      
 *    concatenates two flexible strings 'fsDest' and 'fsSrc' and
 *    puts the result to `fsDest'.
 */
    
#define fsInsChar(fs,c,p)  _fsInsChar(&(fs),c,p)
  void _fsInsChar(tFString *,char,int);
/*
 * void fsInsChar(tFString fsDest,int ch,int pos);
 *    inserts a character `ch' at position `pos' of string `fsDest'
 *    0 -- first position, fsLength(fsDest)-1 -- last position,
 *    fsLength(fsDest) -- has the same effect as fsAdd
 *    If pos lies out of valid range, range check error is reported
 *    and program aborts.
 */
    
#define fsInsStr(fs,s,p)   _fsInsStr(&(fs),s,p)
  void _fsInsStr(tFString *,char *,int);
/*
 * void fsInsStr(tFString fsDest,char *str,int pos);
 *    inserts a string `str' at position `pos'
 */
    
#define fsInsMem(fs,s,l,p) _fsInsMem(&(fs),s,l,p)
  void _fsInsMem(tFString*,char*,int l,int p);
/*
 * void fsInsMem(tFString fs, char *s, int l, int p);
 *    inserts a memory block `s' of length `l' at position `pos'
 */

#define fsInsFS(fs1,fs2,p) _fsInsFS(&(fs1),&(fs2),p)
  void _fsInsFS(tFString *,tFString *,int);
/*
 * void fsInsFS(tFString fsDest,tFString fsSrc,int pos);
 *    inserts a flexible string `fsSrc' at position `pos'
 */ 

#define fsCut(fs,i,l) _fsCut(&(fs),i,l)
  void _fsCut(tFString *, int, int);
/*
 * void fsCut(tFString fs, int start, int len);
 *    cuts off substring starting from start with length len
 *    EXPERIMENTAL FEATURE:
 *      if start is < 0, it's counter from the tail of the string
 *         (-1 is the last char in the string)
 *      if len is < 0, start is supposed to be the LAST character
 */


#define fsLength(a)        ((a).Used)
/*
 * int fsLength(tFString fs);
 *    returns the length of flexible string 'fs'.
 *    '\0' terminator of the string is not counted.
 */
    
#define fsString(a)        ((a).String)
/*
 * char* fsString(tFString fs);
 *    returns C string contained in flexible string.
 *    The function returns a pointer to the internal buffer where
 *    the string is stored. Used may modify this string and such
 *    modifications will take effect on further value of the
 *    string. Be careful not to write characters after the end
 *    of string since it is not guaranteed that there is allocated
 *    for the string memory that lies right after the terminator of
 *    the string.
 */
    
#define fsDup(a)           _fsDup(&(a))
  char *_fsDup(tFString *pfs);
/*
 * char* fsDup(tFString fs);   
 *    returns a duplicate of C string contained in string 'fs'.
 *    Memory for the copy is allocated in the heap, so user should
 *    take care to free allocated memory when the string will not
 *    further used.
 */

#define fsDup2(str,func)   _fsDup2(&(str), func)
  char *_fsDup2(tFString *, void *(*malloc_func)(size_t));
/*
 * char *fsDup2(tFString fs, void *(*malloc_func)(size_t));
 *    returns a duplicate of C string contained in string 'fs'.
 *    The function uses user-provided function `malloc_func'
 *    to allocated memory for storing a string.
 */

#define fsAssign(d,s) _fsAssign(&(d),&(s))
  void _fsAssign(tFString *,tFString *);
/*
 * void fsAssign(tFString fsDest,tFString fsSrc);      
 *    assigns value of flexible sting 'fsSrc' to 'fsDest'.
 *    (in C++ it corresponds to overloaded assignment operator).
 *    Memory, possibly used by string `d' is correctly freed.
 */
    
#define fsCopy(d,s) _fsCopy(&(d),&(s))
  void _fsCopy(tFString *,tFString *);
/*
 * void fsCopy(tFString fsDest,tFString fsSrc);
 *    copies value of string 'fsSrc' to string 'fsDest'. String
 *    fsDest must not be initialized. (in C++ this function
 *    corresponds to copy constructor).
 */
    
#define fsPut(s,f)         _fsPut(&(s),f)
  void _fsPut(tFString *pfs,FILE *f);
/*
 * void fsPut(tFString fs,FILE *f);
 *    writes contents of flexible string 'fs' to binary file 'f'.
 */    

#define fsGet(s,f) _fsGet(&(s),f)
  void _fsGet(tFString *pfs,FILE *f);
/*
 * void fsGet(tFString fs,FILE *f);
 *    reads flexible string from binary file 'f'. Read value is put
 *    to 'fs'.
 */    

#define fsWrite(s,f)       _fsWrite(&(s),f)
/*
 * void fsWrite(tFString fs,FILE *f);
 *    writes flexible string 'fs' to text file 'f'.
 */
  void _fsWrite(tFString *pfs,FILE *f);
    
#define fsRead(s,f) _fsRead(&(s),f)
  void _fsRead(tFString *pfs,FILE *f);
/*
 * void fsRead(tFString fs,FILE *f);   
 *    reads flexible string 'fs' from the text file 'f'.
 */    

#define fsInt(s,pi)        _fsInt(&(s),pi)
/*
 * Bool fsInt(tFString fs,int *pi);
 *    converts string `fs' to integer value. Returns True if conversion was
 *    successful and False if conversion failed.
 */
  int  _fsInt(tFString *pfs,int *pi);
    
#define fsDouble(s,pd)     _fsDouble(&(s),pd)
/*
 * Bool fsDouble(tFString fs,double *pd);
 *    converts string `fs' to double value.
 */
  int  _fsDouble(tFString *pfs,double *pd);

#define fsCmpCaseStr(fs,s) _fsCmpCaseStr(&(fs),s)
/*
 * int fsCmpCaseStr(tFString fs, char *str);
 *    case-insensetive comparison of flex-string fs and string str.
 *    String `str' must have all letters in UPPER case. This function is
 *    particularly convenient for comparing read value in `fs' with table
 *    entry, passed in `str'.
 *    Returns 0,  if strings are equal;
 *            -1, if fs < s;
 *            1,  if fs > s.
 */
  int  _fsCmpCaseStr(tFString *pfs, char *str);

#define fsUpperCase(fs) _fsUpperCase(&(fs))
/*
 * void fsUpperCase(tFString fs);
 *    convert flexible string ``fs'' to upper case
 */
  void _fsUpperCase(tFString *pfs);

#define fsLowerCase(fs) _fsLowerCase(&(fs))
/*
 * void fsLowerCase(tFString fs);
 *    convert flexible string ``fs'' to lower case
 */
  void _fsLowerCase(tFString *pfs);

  void fsInitModule(void);
/*
 *    Initializes internal data. User must call this routine before
 *    using functions of this module.
 */

  void fsStatistics(FILE *f);
/*
 *    Reports statistics about memory consumption of the module.
 */

  void fsCloseModule(void);
/*
 *    Releases memory used for internal buffers
 */    

/* Macros for Cocktail.
 * This macros will be used by AST generated routines if you use
 * type tFString as attribute in AST tree. Refer documentation
 * for AST to full information about use of these macros.
 */

#define begintFString(s)      fsInit(s);
#define closetFString(s)      fsDestroy(s);
#define readtFString(s)       fsRead(s,yyf);
#define writetFString(s)      fsWrite(s,yyf);
#define puttFString(s)        fsPut(s,yyf);
#define gettFString(s)        fsGet(s,yyf);
#define copytFString(dst,src) fsCopy(dst,src);

/* The following functions are used by Put and Write
 * routines of other modules (e. g. StringSet).
 * This routines are for internal use, so don't call them
 * directly.
 */

  void fsPutStr(char *str,FILE *f);
  void fsWriteStr(char *str,FILE *f);

  char *fsReadStr(FILE *f);
  char *fsGetStr(FILE *f);

/* This is static buffer used by numerous Reuse routines.
 * This buffer is used especially as temporary buffer for
 * strings during their reading from file.
 */
#if defined __REUSE__
extern tFString reuse_fsTempBuf;
#endif /* __REUSE__ */

/* Cocktail type specific macros for `tString' */
#define readtString(a)         a = fsReadStr(yyf);
#define writetString(a)        fsWriteStr(a,yyf);

#define gettString(a)          s = fsGetStr(yyf);
#define puttString(a)          fsPutStr(a,yyf);

#define copytString(a,b)       a = (b == NULL)? b : strdup(b);
#define equaltString(a,b)      ((a == NULL && b == NULL)?1:\
(a == NULL || b == NULL) ? 0 : strcmp(a,b) == 0)

#define closetString(a)        if(a != NULL) free(a); a = NULL;
#define begintString(a)        a = NULL;
     
/* Cocktail type specific macros for `char'.
 * Only Read and Write macros are redefined here since other
 * macros for `char' are good enought.
 * `writechar' macro writes a character to a text file in more
 * readable form that native AST `writechar' does.
 */
#define readchar(a)            fscanf(yyf," \'%c\'",&(a));
#define writechar(a)           fprintf(yyf,"\'%c\'",(a));
     
#if defined __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_FLEXSTRING_H__ */
