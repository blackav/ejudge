/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_STDIO_H__
#define __RCC_STDIO_H__

/* Copyright (C) 1999-2005 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>

#ifndef FILENAME_MAX
int enum {
#defconst FILENAME_MAX 4096
};
#endif /* FILENAME_MAX is defined */

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#ifndef RCC_SSIZE_T_DEFINED
#define RCC_SSIZE_T_DEFINED 1
typedef long ssize_t;
#endif /* RCC_SSIZE_T_DEFINED */

#ifndef __RCC_OFF_T_DEFINED__
#define __RCC_OFF_T_DEFINED__
typedef long off_t;
#endif

#ifndef RCC_VA_LIST_DEFINED
#define RCC_VA_LIST_DEFINED
typedef __builtin_va_list va_list;
#endif /* RCC_VA_LIST_DEFINED */

#ifndef __RCC_LOFF_T_DEFINED__
#define __RCC_LOFF_T_DEFINED__
typedef long long loff_t;
typedef loff_t off64_t;
#endif /* __RCC_LOFF_T_DEFINED__ */

#ifndef SEEK_SET
int enum
{
#defconst SEEK_SET 0
#defconst SEEK_CUR 1
#defconst SEEK_END 2
};
#endif /* SEEK_SET */

#ifndef RCC_WCHAR_T_DEFINED
#define RCC_WCHAR_T_DEFINED 1
/* FIXME: wchar_t should be somehow built-in */
typedef long int wchar_t;
#endif /* RCC_WCHAR_T_DEFINED */

#ifndef RCC_FILE_DEFINED
#define RCC_FILE_DEFINED 1
typedef struct
{
  int dummy;
} FILE;
#endif /* RCC_FILE_DEFINED */

int enum
{
  _IOFBF = 0,
#define _IOFBF _IOFBF
  _IOLBF = 1,
#define _IOLBF _IOLBF
  _IONBF = 2,
#define _IONBF _IONBF
};

FILE *fopen(char const *, char const *);
FILE *fopen64(char const *, const char *);
FILE *fdopen(int, char const *);
FILE *freopen(char const *, char const *, FILE *);
FILE *freopen64(const char *, const char *, FILE *);
int fclose(FILE *);
int fcloseall(void);

FILE *popen(const char *, const char *);
int pclose(FILE *);

int printf(char const *, ...);
int fprintf(FILE *, char const *, ...);
int sprintf(char *, char const *, ...);
int snprintf(char *, size_t, char const *, ...);
int asprintf(char **, const char *, ...);
int dprintf(int, const char *, ...);
int vprintf(char const *, va_list);
int vfprintf(FILE *, char const *, va_list);
int vsprintf(char *, char const *, va_list);
int vsnprintf(char *, size_t, char const *, va_list);
int vasprintf(char **, const char *, va_list);
int vdprintf(int, char *, ...);

int scanf(char const *, ...);
int fscanf(FILE *, char const *, ...);
int sscanf(char const *, char const *, ...);

int getchar(void);
int getc(FILE *);
int fgetc(FILE *);
int putchar(int);
int putc(int, FILE *);
int fputc(int, FILE *);
int ungetc(int, FILE *);

char *fgets(char *, size_t, FILE *);
char *gets(char *);
int   puts(char const *);
int   fputs(char const *, FILE *);

int fflush(FILE *);

size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);

void clearerr(FILE *);
int feof(FILE *);
int ferror(FILE *);
int fileno(FILE *);

void setbuf(FILE *, char *);
void setbuffer(FILE *, char *, size_t);
void setlinebuf(FILE *);
int setvbuf(FILE *, char *, int, size_t);

extern FILE *stdin;
#define stdin stdin
extern FILE *stdout;
#define stdout stdout
extern FILE *stderr;
#define stderr stderr

int enum
{
#defconst EOF -1
};

#if !defined NULL
#define NULL 0
#endif

#ifndef EXIT_SUCCESS
int enum
{
#defconst EXIT_SUCCESS 0
#defconst EXIT_FAILURE 1
};
#endif /* EXIT_SUCCESS */

int enum
{
#defconst _IO_BUFSIZ 8192
#defconst BUFSIZ _IO_BUFSIZ
};

FILE *open_memstream(char **bufloc, size_t *sizeloc);
FILE *fmemopen(void *, size_t, const char *);

void exit(int);
int rename(const char *, const char *);
int remove(const char *);
void perror(const char *);

ssize_t __getdelim(char **lineptr, size_t *n, int delimiter, FILE *stream);
#ifdef __USE_GNU
ssize_t getdelim(char **lineptr, size_t *n, int delimiter, FILE *stream);
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
#endif /* __USE_GNU */

FILE *tmpfile(void);
FILE *tmpfile64(void);
char *tmpnam(char *s);
char *tmpnam_r(char *s);
char *tempnam(const char *dir, const char *pfx);

int fflush_unlocked(FILE *);

int getc_unlocked(FILE *);
int getchar_unlocked(void);
int fgetc_unlocked(FILE *);

int fputc_unlocked(int c, FILE *stream);
int putc_unlocked(int c, FILE *stream);
int putchar_unlocked(int c);

char *fgets_unlocked(char *s, int n, FILE *stream);
int fputs_unlocked(const char *s, FILE *stream);

size_t fread_unlocked(void *ptr, size_t size, size_t n, FILE *stream);
size_t fwrite_unlocked(const void *ptr, size_t size, size_t n, FILE *stream);

int fseek(FILE *stream, long int off, int whence);
long int ftell(FILE *stream);
void rewind(FILE *stream);

int fseeko(FILE *stream, off_t off, int whence);
off_t ftello(FILE *stream);
int fseeko64(FILE *stream, off64_t off, int whence);
off64_t ftello64(FILE *stream);

typedef struct { int dummy; } fpos_t;
typedef struct { int dummy; } fpos64_t;

int fgetpos(FILE *stream, fpos_t *pos);
int fsetpos(FILE *stream, const fpos_t *pos);
int fgetpos64(FILE *stream, fpos64_t *pos);
int fsetpos64(FILE *stream, const fpos64_t *pos);

void clearerr_unlocked(FILE *stream);
int feof_unlocked(FILE *stream);
int ferror_unlocked(FILE *stream);
int fileno_unlocked(FILE *stream);

FILE *popen(const char *command, const char *modes);
int pclose(FILE *stream);

char *ctermid(char *s);
char *cuserid(char *s);

void flockfile(FILE *stream);
int ftrylockfile(FILE *stream);
void funlockfile(FILE *stream);

#define P_tmpdir  "/tmp"

#endif /* __RCC_STDIO_H__ */

