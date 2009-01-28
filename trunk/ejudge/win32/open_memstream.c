/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2009 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef HAVE_OPEN_MEMSTREAM

static void
addONode(int o_stream_number, FILE *file, char **buf, size_t *length);
static void delONode(FILE *file);
static int get_o_stream_number(void);

struct oListNode
{
  int o_stream_number;
  FILE *file;
  char **buf;
  size_t *length;
  struct oListNode *pnext;
};

static struct oListNode *oList = NULL;

static void addONode(
        int o_stream_number,
        FILE *file,
        char **buf,
        size_t *length)
{
  struct oListNode **pcur = &oList;
  struct oListNode *node = calloc(1, sizeof(struct oListNode));
  
  if(node == NULL)
    abort();
  
  while((*pcur) && (*pcur)->o_stream_number < o_stream_number)
    pcur = &((*pcur)->pnext);
        
  node->pnext = *pcur;
  node->o_stream_number = o_stream_number;
  node->file = file;
  node->buf = buf;
  node->length = length;
  (*pcur) = node;
}

static void delONode(FILE *file)
{
  struct oListNode **pcur = &oList;
  struct oListNode *todel;
  char file_name[30];

  while((*pcur) && (*pcur)->file != file)
    pcur = &((*pcur)->pnext);

  todel = (*pcur);
  if(todel == NULL){ //not found
    // WARNING(("Trying to close a simple FILE* with close_memstream()"));
  } else {
    if(EOF == fflush(file))
      abort();
    if((*(todel->length) = ftell(file)) == -1)
      abort();
    if((*(todel->buf) = calloc(1, *(todel->length) + 1)) == NULL)
      abort();
    if(EOF == fseek(file, 0, SEEK_SET))
      abort();
    fread(*(todel->buf), 1, *(todel->length), file);

    sprintf(file_name,"o_stream_%d",todel->o_stream_number);
    if(-1 == remove(file_name))
      abort();

    (*pcur) = todel->pnext;
    free(todel);
  }
}


static int get_o_stream_number(void)
{
  int o_stream_number = 1;
  struct oListNode *cur = oList;
  
  while(cur && o_stream_number >= cur->o_stream_number){
    o_stream_number++;
        cur = cur->pnext;
  }
  return o_stream_number;
}


FILE *
open_memstream(char **ptr, size_t *sizeloc)
{
  FILE *f;
  char file_name[30];
  int o_stream_number;
  
  o_stream_number = get_o_stream_number();
  sprintf(file_name,"o_stream_%d",o_stream_number);
  f = fopen(file_name,"w+");
  
  if(!f)
    return NULL;
  
  addONode(o_stream_number, f, ptr, sizeloc);
  
  return f;
}


void
close_memstream(FILE *f)
{
  delONode(f);
  fclose(f);
}

#else

void
close_memstream(FILE *f)
{
  fclose(f);
}

#endif /* HAVE_OPEN_MEMSTREAM */

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
