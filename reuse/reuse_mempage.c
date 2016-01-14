/* Copyright (C) 1995-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xalloc.h"
#include "ejudge/mempage.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>

#define DEFAULT_SIZE   32000
#define ALIGN_SIZE(sz) ((sz+7) & ~7)

struct tPageDesc
{
struct tPageBlock  *Blocks;
size_t             Size;       /* size of each memory chunk */
size_t             Wasted;     /* wasted for alignment */
#ifdef KEEP_CALLER
char               *File;
line_t             Line;
#endif
};

typedef struct tPageBlock
{
  struct tPageBlock  *Next;
  size_t             Size_Left;
  size_t             Size_Allocated;
  void               *Free_Ptr;
} tPageBlock;

tPageDesc*
pgCreate(size_t size)
{
  tPageDesc *res;
  
  if (size == 0)
    size = DEFAULT_SIZE;

  res = (tPageDesc*) xmalloc(sizeof(tPageDesc));

  assert(res != NULL);

#ifdef KEEP_CALLER
  res->File = CALLER_FILE;
  res->Line = CALLER_LINE;
#endif

  res->Size   = size;
  res->Blocks = NULL;

  return res;
}

void*
pgMalloc(tPageDesc *desc, size_t size)
{
  size_t     needed_size;
  tPageBlock *block_ptr;
  void       *ret_ptr;

  assert(desc != NULL);
  assert(size != 0);

  needed_size = ALIGN_SIZE(size);
  desc->Wasted += needed_size - size;
  for (block_ptr = desc->Blocks;
       block_ptr != NULL;
       block_ptr = block_ptr->Next)
    {
      if (block_ptr->Size_Left >= needed_size)
        break;
    }

  if (block_ptr == NULL)
    {
      size_t alloc_size = desc->Size;

      if (needed_size > desc->Size)
        alloc_size = needed_size;

      block_ptr = (tPageBlock*) xmalloc(alloc_size + sizeof(tPageBlock));
      assert(block_ptr != NULL);
      block_ptr->Size_Allocated = alloc_size;
      block_ptr->Size_Left = alloc_size;
      block_ptr->Free_Ptr = (void*)(block_ptr + 1);
      block_ptr->Next = desc->Blocks;
      desc->Blocks = block_ptr;
    }

  ret_ptr = block_ptr->Free_Ptr;
  block_ptr->Size_Left -= needed_size;
  block_ptr->Free_Ptr = (void*)((char*) ret_ptr + needed_size);
  
  return ret_ptr;
}

void *
pgCalloc(tPageDesc *page, size_t nelem, size_t elem_size)
{
  size_t  sz = nelem * elem_size;
  void   *p = pgMalloc(page, sz);

  memset((char*) p, 0, sz);
  return p;
}

void
pgDestroy(tPageDesc *pchk)
{
  tPageBlock *ptr;
  tPageBlock *saved;

  assert(pchk != NULL);

  for (ptr = pchk->Blocks;
       ptr != NULL;)
    {
      saved = ptr->Next;
      free(ptr);
      ptr = saved;
    }
  free(pchk);
}

void
pgPageStatistics(tPageDesc *desc, FILE *f)
{
  tPageBlock *block_ptr;
  int        Chunk_Num = 0;
  size_t     Allocated = 0;
  size_t     Used      = 0;

  assert(desc != NULL);

  for (block_ptr = desc->Blocks;
       block_ptr != NULL;
       block_ptr = block_ptr->Next, Chunk_Num++)
    {
      Used += block_ptr->Size_Allocated - block_ptr->Size_Left;
      Allocated += block_ptr->Size_Allocated;
    }

  fprintf(f,
          "Number of chunks:            %d\n"
          "Total allocated memory size: %zu\n"
          "Total used memory size:      %zu\n"
          "Wasted for alignment:        %zu\n",  
          /*"Detailed statistics for each Chunk:\n"*/
          Chunk_Num, Allocated, Used, desc->Wasted);

/*
  for (block_ptr = desc->Blocks, Chunk_Num = 0;
       block_ptr != NULL;
       block_ptr = block_ptr->Next, Chunk_Num++)
    {
      fprintf(f, "Chunk %d: Allocated %u, Used %u, Free %u\n",
              Chunk_Num, block_ptr->Size_Allocated,
              block_ptr->Size_Allocated - block_ptr->Size_Left,
              block_ptr->Size_Left);
    }
*/
}

void
pgInitModule(void)
{
}

void
pgCloseModule(void)
{
}

void
pgStatistics(FILE *f)
{
}
