/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `search.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Declarations for System V style searching functions.
   Copyright (C) 1995-1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_SEARCH_H__
#define __RCC_SEARCH_H__ 1

#include <features.h>
#include <sys/types.h>

struct qelem
{
  struct qelem *q_forw;
  struct qelem *q_back;
  char q_data[1];
};

void insque(void *elem, void *prev);
void remque(void *elem);

/* For use with hsearch(3).  */
#ifndef __RCC_COMPAR_FN_T__
#define __RCC_COMPAR_FN_T__
typedef int (*__compar_fn_t) (const void *, const void *);
typedef __compar_fn_t comparison_fn_t;
#endif /* __RCC_COMPAR_FN_T__ */

/* Action which shall be performed in the call the hsearch.  */
typedef int enum
{
  FIND,
  ENTER
} ACTION;

typedef struct entry
{
  char *key;
  void *data;
} ENTRY;

/* Opaque type for internal use.  */
struct _ENTRY;

/* Family of hash table handling functions.  The functions also
   have reentrant counterparts ending with _r.  The non-reentrant
   functions all work on a signle internal hashing table.  */

ENTRY *hsearch(ENTRY item, ACTION action);
int hcreate(size_t nel);
void hdestroy(void);

/* Data type for reentrant functions.  */
struct hsearch_data
{
  struct _ENTRY *table;
  unsigned int size;
  unsigned int filled;
};

int hsearch_r(ENTRY item, ACTION action, ENTRY **retval,
              struct hsearch_data *htab);
int hcreate_r(size_t nel, struct hsearch_data *htab);
void hdestroy_r(struct hsearch_data *htab);

/* The tsearch routines are very interesting. They make many
   assumptions about the compiler.  It assumes that the first field
   in node must be the "key" field, which points to the datum.
   Everything depends on that.  */
/* For tsearch */
typedef int enum
{
  preorder,
  postorder,
  endorder,
  leaf
} VISIT;

void *tsearch(const void *key, void **rootp, __compar_fn_t compar);
void *tfind(const void *key, void *const *rootp, __compar_fn_t compar);
void *tdelete(const void *key, void **rootp, __compar_fn_t compar);

#ifndef __RCC_ACTION_FN_T__
#define __RCC_ACTION_FN_T__
typedef void (*__action_fn_t)(const void *nodep, VISIT value, int level);
#endif /* __RCC_ACTION_FN_T__ */

void twalk(const void *root, __action_fn_t action);

typedef void (*__free_fn_t)(void *nodep);

void tdestroy(void *root, __free_fn_t freefct);
void *lfind(const void *key, const void *base,
            size_t *nmemb, size_t size, __compar_fn_t compar);
void *lsearch(const void *key, void *base,
              size_t *nmemb, size_t size, __compar_fn_t compar);

#endif /* __RCC_SEARCH_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "ENTRY" "ACTION" "VISIT")
 * End:
 */
