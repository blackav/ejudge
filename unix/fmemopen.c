/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ejudge/config.h"

#include <stdio.h>

#if HAVE_FMEMOPEN - 0 == 0

#include <stdlib.h>

static void addINode(int i_stream_number, FILE *file);
static void delINode(FILE *file);
static int get_i_stream_number(void);

struct iListNode
{
  int i_stream_number;
  FILE* file;
  struct iListNode *pnext;
};

static struct iListNode *iList = NULL;

static void
addINode(int i_stream_number, FILE *file)
{
  struct iListNode **pcur = &iList;
  struct iListNode *node = calloc(1, sizeof(struct iListNode));
  if(node == NULL)
    abort();

  while((*pcur) && (*pcur)->i_stream_number < i_stream_number)
    pcur = &((*pcur)->pnext);

  node->pnext = *pcur;
  node->i_stream_number = i_stream_number;
  node->file = file;
  (*pcur) = node;
}

static void
delINode(FILE *file)
{
  struct iListNode **pcur = &iList;
  struct iListNode *todel;
  char file_name[30];

  while((*pcur) && (*pcur)->file != file)
    pcur = &((*pcur)->pnext);

  todel = (*pcur);
  if(todel == NULL){ //not found
    // WARNING: (("Trying to close a simple FILE* with fmemclose()"));
  } else {
    sprintf(file_name,"i_stream_%d",todel->i_stream_number);
    remove(file_name);
      
    (*pcur) = todel->pnext;
    free(todel);
  }
}

static int
get_i_stream_number(void)
{
  int i_stream_number = 1;
  struct iListNode *cur = iList;
  
  while(cur && i_stream_number >= cur->i_stream_number){
    i_stream_number++;
    cur = cur->pnext;
  }
  return i_stream_number;
}

FILE *
fmemopen(void *buf, size_t size, const char *mode)
{
  FILE *f;
  char file_name[30];
  int i_stream_number;
  
  i_stream_number = get_i_stream_number();
  sprintf(file_name,"i_stream_%d",i_stream_number);
  f = fopen(file_name,"w+");
  
  if(!f)
    return NULL;
  
  if(size != fwrite(buf, 1, size, f)){
    fclose(f);
    remove(file_name);
    return NULL;
  }
  if(EOF == fseek(f, 0, SEEK_SET)){
    fclose(f);
    remove(file_name);
    return NULL;
  }
  
  addINode(i_stream_number, f);
  
  return f;
}

void
fmemclose(FILE *f)
{
  delINode(f);
  fclose(f);
}

#else

void
fmemclose(FILE *f)
{
  fclose(f);
}

#endif

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
