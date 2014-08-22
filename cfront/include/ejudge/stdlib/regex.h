/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `regex.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Definitions for data structures and routines for the regular
   expression library.
   Copyright (C) 1985,1989-93,1995-98,2000,2001,2002
   Free Software Foundation, Inc.
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

#ifndef __RCC_REGEX_H__
#define __RCC_REGEX_H__ 1

#include <features.h>

/* Allow the use in C++ code.  */

/* POSIX says that <sys/types.h> must be included (by the caller) before
   <regex.h>.  */

/* The following two types have to be signed and unsigned integer type
   wide enough to hold a value of a pointer.  For most ANSI compilers
   ptrdiff_t and size_t should be likely OK.  Still size of these two
   types is 2 for Microsoft C.  Ugh... */
typedef long int s_reg_t;
typedef unsigned long int active_reg_t;

/* The following bits are used to determine the regexp syntax we
   recognize.  The set/not-set meanings are chosen so that Emacs syntax
   remains the value 0.  The bits are given in alphabetical order, and
   the definitions shifted by one from the previous bit; thus, when we
   add or remove a bit, only one other definition need change.  */
typedef unsigned long int reg_syntax_t;

int enum
{
  RE_BACKSLASH_ESCAPE_IN_LISTS = ((unsigned long int) 1),
#define RE_BACKSLASH_ESCAPE_IN_LISTS RE_BACKSLASH_ESCAPE_IN_LISTS
  RE_BK_PLUS_QM = (RE_BACKSLASH_ESCAPE_IN_LISTS << 1),
#define RE_BK_PLUS_QM RE_BK_PLUS_QM
  RE_CHAR_CLASSES = (RE_BK_PLUS_QM << 1),
#define RE_CHAR_CLASSES RE_CHAR_CLASSES
  RE_CONTEXT_INDEP_ANCHORS = (RE_CHAR_CLASSES << 1),
#define RE_CONTEXT_INDEP_ANCHORS RE_CONTEXT_INDEP_ANCHORS
  RE_CONTEXT_INDEP_OPS = (RE_CONTEXT_INDEP_ANCHORS << 1),
#define RE_CONTEXT_INDEP_OPS RE_CONTEXT_INDEP_OPS
  RE_CONTEXT_INVALID_OPS = (RE_CONTEXT_INDEP_OPS << 1),
#define RE_CONTEXT_INVALID_OPS RE_CONTEXT_INVALID_OPS
  RE_DOT_NEWLINE = (RE_CONTEXT_INVALID_OPS << 1),
#define RE_DOT_NEWLINE RE_DOT_NEWLINE
  RE_DOT_NOT_NULL = (RE_DOT_NEWLINE << 1),
#define RE_DOT_NOT_NULL RE_DOT_NOT_NULL
  RE_HAT_LISTS_NOT_NEWLINE = (RE_DOT_NOT_NULL << 1),
#define RE_HAT_LISTS_NOT_NEWLINE RE_HAT_LISTS_NOT_NEWLINE
  RE_INTERVALS = (RE_HAT_LISTS_NOT_NEWLINE << 1),
#define RE_INTERVALS RE_INTERVALS
  RE_LIMITED_OPS = (RE_INTERVALS << 1),
#define RE_LIMITED_OPS RE_LIMITED_OPS
  RE_NEWLINE_ALT = (RE_LIMITED_OPS << 1),
#define RE_NEWLINE_ALT RE_NEWLINE_ALT
  RE_NO_BK_BRACES = (RE_NEWLINE_ALT << 1),
#define RE_NO_BK_BRACES RE_NO_BK_BRACES
  RE_NO_BK_PARENS = (RE_NO_BK_BRACES << 1),
#define RE_NO_BK_PARENS RE_NO_BK_PARENS
  RE_NO_BK_REFS = (RE_NO_BK_PARENS << 1),
#define RE_NO_BK_REFS RE_NO_BK_REFS
  RE_NO_BK_VBAR = (RE_NO_BK_REFS << 1),
#define RE_NO_BK_VBAR RE_NO_BK_VBAR
  RE_NO_EMPTY_RANGES = (RE_NO_BK_VBAR << 1),
#define RE_NO_EMPTY_RANGES RE_NO_EMPTY_RANGES
  RE_UNMATCHED_RIGHT_PAREN_ORD = (RE_NO_EMPTY_RANGES << 1),
#define RE_UNMATCHED_RIGHT_PAREN_ORD RE_UNMATCHED_RIGHT_PAREN_ORD
  RE_NO_POSIX_BACKTRACKING = (RE_UNMATCHED_RIGHT_PAREN_ORD << 1),
#define RE_NO_POSIX_BACKTRACKING RE_NO_POSIX_BACKTRACKING
  RE_NO_GNU_OPS = (RE_NO_POSIX_BACKTRACKING << 1),
#define RE_NO_GNU_OPS RE_NO_GNU_OPS
  RE_DEBUG = (RE_NO_GNU_OPS << 1),
#define RE_DEBUG RE_DEBUG
  RE_INVALID_INTERVAL_ORD = (RE_DEBUG << 1),
#define RE_INVALID_INTERVAL_ORD RE_INVALID_INTERVAL_ORD
  RE_ICASE = (RE_INVALID_INTERVAL_ORD << 1),
#define RE_ICASE RE_ICASE
  /*
  RE_SYNTAX_EMACS = 0,
#define RE_SYNTAX_EMACS RE_SYNTAX_EMACS
  RE_SYNTAX_AWK = (RE_BACKSLASH_ESCAPE_IN_LISTS | RE_DOT_NOT_NULL | RE_NO_BK_PARENS | RE_NO_BK_REFS | RE_NO_BK_VBAR | RE_NO_EMPTY_RANGES | RE_DOT_NEWLINE | RE_CONTEXT_INDEP_ANCHORS | RE_UNMATCHED_RIGHT_PAREN_ORD | RE_NO_GNU_OPS),
#define RE_SYNTAX_AWK RE_SYNTAX_AWK
  RE_SYNTAX_GNU_AWK = ((RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS | RE_DEBUG) & ~(RE_DOT_NOT_NULL | RE_INTERVALS | RE_CONTEXT_INDEP_OPS | RE_CONTEXT_INVALID_OPS )),
#define RE_SYNTAX_GNU_AWK RE_SYNTAX_GNU_AWK
  RE_SYNTAX_POSIX_AWK = (RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS | RE_INTERVALS | RE_NO_GNU_OPS),
#define RE_SYNTAX_POSIX_AWK RE_SYNTAX_POSIX_AWK
  RE_SYNTAX_GREP = (RE_BK_PLUS_QM | RE_CHAR_CLASSES | RE_HAT_LISTS_NOT_NEWLINE | RE_INTERVALS | RE_NEWLINE_ALT),
#define RE_SYNTAX_GREP RE_SYNTAX_GREP
  RE_SYNTAX_EGREP = (RE_CHAR_CLASSES | RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INDEP_OPS | RE_HAT_LISTS_NOT_NEWLINE | RE_NEWLINE_ALT | RE_NO_BK_PARENS | RE_NO_BK_VBAR),
#define RE_SYNTAX_EGREP RE_SYNTAX_EGREP
  RE_SYNTAX_POSIX_EGREP = (RE_SYNTAX_EGREP | RE_INTERVALS | RE_NO_BK_BRACES | RE_INVALID_INTERVAL_ORD),
#define RE_SYNTAX_POSIX_EGREP RE_SYNTAX_POSIX_EGREP
  RE_SYNTAX_ED = RE_SYNTAX_POSIX_BASIC,
#define RE_SYNTAX_ED RE_SYNTAX_ED
  RE_SYNTAX_SED = RE_SYNTAX_POSIX_BASIC,
#define RE_SYNTAX_SED RE_SYNTAX_SED
  _RE_SYNTAX_POSIX_COMMON = (RE_CHAR_CLASSES | RE_DOT_NEWLINE | RE_DOT_NOT_NULL | RE_INTERVALS  | RE_NO_EMPTY_RANGES),
#define _RE_SYNTAX_POSIX_COMMON _RE_SYNTAX_POSIX_COMMON
  RE_SYNTAX_POSIX_BASIC = (_RE_SYNTAX_POSIX_COMMON | RE_BK_PLUS_QM),
#define RE_SYNTAX_POSIX_BASIC RE_SYNTAX_POSIX_BASIC
  RE_SYNTAX_POSIX_MINIMAL_BASIC = (_RE_SYNTAX_POSIX_COMMON | RE_LIMITED_OPS),
#define RE_SYNTAX_POSIX_MINIMAL_BASIC RE_SYNTAX_POSIX_MINIMAL_BASIC
  RE_SYNTAX_POSIX_EXTENDED = (_RE_SYNTAX_POSIX_COMMON | RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INDEP_OPS | RE_NO_BK_BRACES | RE_NO_BK_PARENS | RE_NO_BK_VBAR | RE_CONTEXT_INVALID_OPS | RE_UNMATCHED_RIGHT_PAREN_ORD),
#define RE_SYNTAX_POSIX_EXTENDED RE_SYNTAX_POSIX_EXTENDED
  RE_SYNTAX_POSIX_MINIMAL_EXTENDED = (_RE_SYNTAX_POSIX_COMMON | RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INVALID_OPS | RE_NO_BK_BRACES | RE_NO_BK_PARENS | RE_NO_BK_REFS | RE_NO_BK_VBAR | RE_UNMATCHED_RIGHT_PAREN_ORD),
#define RE_SYNTAX_POSIX_MINIMAL_EXTENDED RE_SYNTAX_POSIX_MINIMAL_EXTENDED
  */
};

#define RE_SYNTAX_EMACS 0
#define RE_SYNTAX_AWK (RE_BACKSLASH_ESCAPE_IN_LISTS | RE_DOT_NOT_NULL | RE_NO_BK_PARENS | RE_NO_BK_REFS | RE_NO_BK_VBAR | RE_NO_EMPTY_RANGES | RE_DOT_NEWLINE | RE_CONTEXT_INDEP_ANCHORS | RE_UNMATCHED_RIGHT_PAREN_ORD | RE_NO_GNU_OPS)
#define RE_SYNTAX_GNU_AWK ((RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS | RE_DEBUG) & ~(RE_DOT_NOT_NULL | RE_INTERVALS | RE_CONTEXT_INDEP_OPS | RE_CONTEXT_INVALID_OPS ))
#define RE_SYNTAX_POSIX_AWK (RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS | RE_INTERVALS | RE_NO_GNU_OPS)
#define RE_SYNTAX_GREP (RE_BK_PLUS_QM | RE_CHAR_CLASSES | RE_HAT_LISTS_NOT_NEWLINE | RE_INTERVALS | RE_NEWLINE_ALT)
#define RE_SYNTAX_EGREP (RE_CHAR_CLASSES | RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INDEP_OPS | RE_HAT_LISTS_NOT_NEWLINE | RE_NEWLINE_ALT | RE_NO_BK_PARENS | RE_NO_BK_VBAR)
#define RE_SYNTAX_POSIX_EGREP (RE_SYNTAX_EGREP | RE_INTERVALS | RE_NO_BK_BRACES | RE_INVALID_INTERVAL_ORD)
#define RE_SYNTAX_ED RE_SYNTAX_POSIX_BASIC
#define RE_SYNTAX_SED RE_SYNTAX_POSIX_BASIC
#define _RE_SYNTAX_POSIX_COMMON (RE_CHAR_CLASSES | RE_DOT_NEWLINE | RE_DOT_NOT_NULL | RE_INTERVALS  | RE_NO_EMPTY_RANGES)
#define RE_SYNTAX_POSIX_BASIC (_RE_SYNTAX_POSIX_COMMON | RE_BK_PLUS_QM)
#define RE_SYNTAX_POSIX_MINIMAL_BASIC (_RE_SYNTAX_POSIX_COMMON| RE_LIMITED_OPS)
#define RE_SYNTAX_POSIX_EXTENDED (_RE_SYNTAX_POSIX_COMMON | RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INDEP_OPS | RE_NO_BK_BRACES | RE_NO_BK_PARENS | RE_NO_BK_VBAR | RE_CONTEXT_INVALID_OPS | RE_UNMATCHED_RIGHT_PAREN_ORD)
#define RE_SYNTAX_POSIX_MINIMAL_EXTENDED (_RE_SYNTAX_POSIX_COMMON | RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INVALID_OPS | RE_NO_BK_BRACES | RE_NO_BK_PARENS | RE_NO_BK_REFS | RE_NO_BK_VBAR | RE_UNMATCHED_RIGHT_PAREN_ORD)

/* This global variable defines the particular regexp syntax to use (for
   some interfaces).  When a regexp is compiled, the syntax used is
   stored in the pattern buffer, so changing this does not affect
   already-compiled regexps.  */
extern reg_syntax_t re_syntax_options;

#ifdef RE_DUP_MAX
#undef RE_DUP_MAX
#endif
#define RE_DUP_MAX (0x7fff)

int enum
{
  REG_EXTENDED = 1,
#define REG_EXTENDED REG_EXTENDED
  REG_ICASE = (REG_EXTENDED << 1),
#define REG_ICASE REG_ICASE
  REG_NEWLINE = (REG_ICASE << 1),
#define REG_NEWLINE REG_NEWLINE
  REG_NOSUB = (REG_NEWLINE << 1),
#define REG_NOSUB REG_NOSUB
  REG_NOTBOL = 1,
#define REG_NOTBOL REG_NOTBOL
  REG_NOTEOL = (1 << 1),
#define REG_NOTEOL REG_NOTEOL
};

/* If any error codes are removed, changed, or added, update the
   `re_error_msg' table in regex.c.  */
typedef int enum
{
  REG_ENOSYS = -1,
  REG_NOERROR = 0,
  REG_NOMATCH,
  REG_BADPAT,
  REG_ECOLLATE,
  REG_ECTYPE,
  REG_EESCAPE,
  REG_ESUBREG,
  REG_EBRACK,
  REG_EPAREN,
  REG_EBRACE,
  REG_BADBR,
  REG_ERANGE,
  REG_ESPACE,
  REG_BADRPT,
  REG_EEND,
  REG_ESIZE,
  REG_ERPAREN
} reg_errcode_t;

/* This data structure represents a compiled pattern.  Before calling
   the pattern compiler, the fields `buffer', `allocated', `fastmap',
   `translate', and `no_sub' can be set.  After the pattern has been
   compiled, the `re_nsub' field is available.  All other fields are
   private to the regex routines.  */
#ifndef RE_TRANSLATE_TYPE
#define RE_TRANSLATE_TYPE char *
#endif

struct re_pattern_buffer
{
  unsigned char *buffer;
  unsigned long int allocated;
  unsigned long int used;
  reg_syntax_t syntax;
  char *fastmap;
  RE_TRANSLATE_TYPE translate;
  size_t re_nsub;
  unsigned can_be_null : 1;
  unsigned regs_allocated : 2;
  unsigned fastmap_accurate : 1;
  unsigned no_sub : 1;
  unsigned not_bol : 1;
  unsigned not_eol : 1;
  unsigned newline_anchor : 1;
};

int enum
{
  REGS_UNALLOCATED = 0,
#define REGS_UNALLOCATED REGS_UNALLOCATED
  REGS_REALLOCATE = 1,
#define REGS_REALLOCATE REGS_REALLOCATE
  REGS_FIXED = 2,
#define REGS_FIXED REGS_FIXED
};

typedef struct re_pattern_buffer regex_t;

/* Type for byte offsets within the string.  POSIX mandates this.  */
typedef int regoff_t;

/* This is the structure we store register match data in.  See
   regex.texinfo for a full description of what registers match.  */
struct re_registers
{
  unsigned num_regs;
  regoff_t *start;
  regoff_t *end;
};

/* If `regs_allocated' is REGS_UNALLOCATED in the pattern buffer,
   `re_match_2' returns information about at least this many registers
   the first time a `regs' structure is passed.  */
#ifndef RE_NREGS
#define RE_NREGS 30
#endif


/* POSIX specification for registers.  Aside from the different names than
   `re_registers', POSIX uses an array of structures, instead of a
   structure of arrays.  */
typedef struct
{
  regoff_t rm_so;
  regoff_t rm_eo;
} regmatch_t;

/* Declarations for routines.  */

/* To avoid duplicating every routine declaration -- once with a
   prototype (if we are ANSI), and once without (if we aren't) -- we
   use the following macro to declare argument types.  This
   unfortunately clutters up the declarations a bit, but I think it's
   worth it.  */

reg_syntax_t re_set_syntax(reg_syntax_t syntax);
const char *re_compile_pattern(const char *pattern, size_t length,
                               struct re_pattern_buffer *buffer);
int re_compile_fastmap(struct re_pattern_buffer *buffer);
int re_search(struct re_pattern_buffer *buffer, const char *string,
              int length, int start, int range, struct re_registers *regs);
int re_search_2(struct re_pattern_buffer *buffer, const char *string1,
                int length1, const char *string2, int length2,
                int start, int range, struct re_registers *regs, int stop);
int re_match(struct re_pattern_buffer *buffer, const char *string,
             int length, int start, struct re_registers *regs);
int re_match_2(struct re_pattern_buffer *buffer, const char *string1,
               int length1, const char *string2, int length2,
               int start, struct re_registers *regs, int stop);
void re_set_registers(struct re_pattern_buffer *buffer,
                      struct re_registers *regs,
                      unsigned num_regs, regoff_t *starts, regoff_t *ends);
char *re_comp(const char *);
int re_exec(const char *);
int regcomp(regex_t *preg, const char *pattern, int cflags);
int regexec(const regex_t *preg, const char *string, size_t nmatch,
            regmatch_t pmatch[], int eflags);
size_t regerror(int errcode, const regex_t *preg,
                char *errbuf, size_t errbuf_size);
void regfree(regex_t *preg);

#endif /* __RCC_REGEX_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "RE_TRANSLATE_TYPE")
 * End:
 */
