/* -*- mode: C -*- */
/* $Id$ */

#ifndef __SEMA_DATA_H__
#define __SEMA_DATA_H__

/* Copyright (C) 1999-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "tree.h"

#include "ejudge/hash.h"

/* type information */
enum
{
  STI_CONST    = 0x00000001,    /* const */
  STI_VOLATILE = 0x00000002,    /* volatile */
  STI_RESTRICT = 0x00000004,    /* restrict */
  STI_CVMASK   = 0x0000000F,    /* the corresponding mask */

  STI_TYPEMASK = 0x000000F0,    /* type mask */
  STI_ARITH    = 0x00000010,    /* arithmetic type (char...long double) */
  STI_BUILTIN  = 0x00000020,    /* other primitive types (void, va_list) */
  STI_STRUCT   = 0x00000030,    /* structure type */
  STI_UNION    = 0x00000040,    /* union type */
  STI_ENUM     = 0x00000050,    /* enumerated type */
  STI_TYPEDEF  = 0x00000060,    /* transient flag: never preserved */

  STI_LMASK    = 0x30000000,    /* lvalue and addressable flag mask */
  STI_LVALUE   = 0x10000000,    /* is this lvalue */
  STI_ADDRESS  = 0x20000000,    /* may take address of */

  // this bits are used in function specifier
  STI_FMASK    = 0x00000F00,
  STI_FNORMAL  = 0x00000000,
  STI_FKR      = 0x00000100,    /* old-style parameters */
  STI_FVAR     = 0x00000200,    /* variadic parameters */
  STI_FVOID    = 0x00000300,    /* no arguments */
};

/* lvalue, const, volatile */
#define STI_CLONE_SETABLE 0x3000000F
#define STI_CLONE_CLEAR   0x30000000

#define STI_IS_ARITH(x)    (((x) & STI_TYPEMASK) == STI_ARITH)
#define STI_IS_BUILTIN(x)  (((x) & STI_TYPEMASK) == STI_BUILTIN)
#define STI_IS_STRUCT(x)   (((x) & STI_TYPEMASK) == STI_STRUCT)
#define STI_IS_UNION(x)    (((x) & STI_TYPEMASK) == STI_UNION)
#define STI_IS_ENUM(x)     (((x) & STI_TYPEMASK) == STI_ENUM)
#define STI_IS_TYPEDEF(x)  (((x) & STI_TYPEMASK) == STI_TYPEDEF)

#define STI_IS_CONST(x)    ((x) & STI_CONST)
#define STI_IS_VOLATILE(x) ((x) & STI_VOLATILE)
#define STI_IS_RESTRICT(x) ((x) & STI_RESTRICT)
#define STI_GET_CV(x)      ((x) & STI_CVMASK)

#define STI_IS_LVALUE(x)   ((x) & STI_LVALUE)
#define STI_IS_ADDRESS(x)  ((x) & STI_ADDRESS)

#define STI_GET_FFLAGS(x)  ((x) & STI_FMASK)
#define STI_IS_FNORM(x)    (!((x) & STI_FMASK))
#define STI_IS_FKR(x)      (((x) & STI_FMASK) == STI_FKR)
#define STI_IS_FVAR(x)     (((x) & STI_FMASK) == STI_FVAR)
#define STI_IS_FVOID(x)    (((x) & STI_FMASK) == STI_FVOID)

union s_typeinfo;
typedef union s_typeinfo *typeinfo_t;

struct sema_scope;
struct sema_scope_list;
struct sema_init;
struct sema_def;
struct s_c_value;

/* This are the types from code generator */
#ifndef RCC_MIFELEM_T_DEFINED
#define RCC_MIFELEM_T_DEFINED 1
struct s_mifelem;
typedef struct s_mifelem *mifelem_t;
#endif /* RCC_MIFELEM_T_DEFINED */

/* built-in types (void, va_list, char...long double) */
struct s_builtin
{
  int                tag;
  unsigned long      size;      /* size of the type */
  int                bits;      /* declaration specifier bits */
  int                ind;       /* type index (C_*) */

  mifelem_t          gen_data;  /* extra info for code generation pass */
};

/* pointer to a type */
struct s_pointer
{
  int                tag;
  unsigned long      size;
  int                bits;
  typeinfo_t         type;      /* type to which it points to */

  mifelem_t          gen_data;  /* extra info for code generation pass */
};

/* function */
struct s_function
{
  int                tag;
  unsigned long      size;      /* just a placeholder */
  int                bits;      /* storage class & parameter flags */
  int                nparam;    /* number of fixed parameters */
  typeinfo_t         ret_type;  /* return type */
  struct sema_scope *par_scope; /* definition parameter scope */
  struct sema_scope *impl_par_scope; /* implementation parameter scope */

  mifelem_t          gen_data;  /* extra info for code generation pass */
};
/*
 * params      - caller-visible function parameters
 * impl_params - the function implementation parameters
 * for ANSI functions both `params' and `impl_params' are the same
 *  and actually are links to the same structure
 * for K&R functions they may be different:
 *  params may be NULL
 */

/* array of a type */
struct s_array
{
  int                tag;
  unsigned long      size;
  int                bits;
  typeinfo_t         type;      /* type of elements */
  rulong_t           elnum;     /* number of elements, -1 - undefined */
  tree_t             size_expr; /* expression for variable size arrays */
  typeinfo_t         size_def;  /* primary s_array for variable size array */

  mifelem_t          gen_data;  /* extra info for code generation pass */
  mifelem_t          size_reg;  /* for variable-sized arrays */
};

/* aggregate type usage */
struct s_aggreg
{
  int                tag;
  unsigned long      size;
  int                bits;
  ident_t            id;
  struct sema_def   *def;

  mifelem_t          gen_data;
};

/* enumerated type */
struct s_enum
{
  int                tag;
  unsigned long      size;
  int                bits;
  ident_t            id;
  struct sema_def   *def;

  mifelem_t          gen_data;
};

struct s_typedef
{
  int                tag;
  unsigned long      size;
  int                bits;
  ident_t            id;
  struct sema_def   *def;

  mifelem_t          gen_data;
};

/* partial type specifier kind */
enum
{
  CPT_ARITH,
  CPT_BUILTIN,
  CPT_ENUM,
  CPT_POINTER,
  CPT_ARRAY,
  CPT_FUNCTION,
  CPT_AGGREG,
  CPT_TYPEDEF
};

#define CPT_IS_SCALAR(x) ((x) >= CPT_ARITH && (x) <= CPT_POINTER)
#define CPT_IS_AGGREG(x) ((x) == CPT_ARRAY || (x) == CPT_FUNCTION)

/* typeinfo specification */
union s_typeinfo
{
  int               tag;
  struct s_builtin  t_builtin;
  struct s_enum     t_enum;
  struct s_pointer  t_pointer;
  struct s_array    t_array;
  struct s_function t_function;
  struct s_aggreg   t_aggreg;
  struct s_typedef  t_typedef;
};

/* declaration flags */
enum
{
  /* namespaces */
  SSC_NSPACE_MASK = 0x00FF0000,
  SSC_REGULAR     = 0x00010000,
  SSC_LABEL       = 0x00020000,
  SSC_STRUCT      = 0x00100000,
  SSC_UNION       = 0x00200000,
  SSC_ENUM        = 0x00400000,
  SSC_TAG         = 0x00700000,

  /* storage class */
  SSC_SCLASS_MASK = 0x0000000F,
  SSC_GLOBAL      = 0x00000001,
  SSC_EXTERN      = 0x00000002,
  SSC_STATIC      = 0x00000003,
  SSC_LOCAL       = 0x00000004,
  SSC_REGISTER    = 0x00000005,
  SSC_ENUMCONST   = 0x00000006,
  SSC_BUILTIN     = 0x00000007, /* a built-in function or variable */

  /* object type */
  SSC_OTYPE_MASK  = 0x000000F0,
  SSC_PLAIN       = 0x00000000,
  SSC_FUNCTION    = 0x00000010,
  SSC_TYPEDEF     = 0x00000020,
  SSC_PROTO       = 0x00000030
};

#define SSC_GET_SCLASS(x)   ((x) & SSC_SCLASS_MASK)
#define SSC_SET_SCLASS(x,y) (((x) & ~SSC_SCLASS_MASK) | (y))
#define SSC_IS_GLOBAL(x)    (((x) & SSC_SCLASS_MASK) == SSC_GLOBAL)
#define SSC_IS_EXTERN(x)    (((x) & SSC_SCLASS_MASK) == SSC_EXTERN)
#define SSC_IS_COMMON(x)    (((x) & SSC_SCLASS_MASK) == SSC_COMMON)
#define SSC_IS_STATIC(x)    (((x) & SSC_SCLASS_MASK) == SSC_STATIC)
#define SSC_IS_LOCAL(x)     (((x) & SSC_SCLASS_MASK) == SSC_LOCAL)
#define SSC_IS_REGISTER(x)  (((x) & SSC_SCLASS_MASK) == SSC_REGISTER)
#define SSC_IS_ENUMCONST(x) (((x) & SSC_SCLASS_MASK) == SSC_ENUMCONST)
#define SSC_IS_BUILTIN(x)   (((x) & SSC_SCLASS_MASK) == SSC_BUILTIN)

#define SSC_GET_OTYPE(x)    ((x) & SSC_OTYPE_MASK)
#define SSC_IS_PLAIN(x)     (((x) & SSC_OTYPE_MASK) == SSC_PLAIN)
#define SSC_IS_FUNCTION(x)  (((x) & SSC_OTYPE_MASK) == SSC_FUNCTION)
#define SSC_IS_TYPEDEF(x)   (((x) & SSC_OTYPE_MASK) == SSC_TYPEDEF)
#define SSC_IS_PROTO(x)     (((x) & SSC_OTYPE_MASK) == SSC_PROTO)

#define SSC_GET_NSPACE(x)   (((x) & SSC_NSPACE_MASK))

/* attribute flags */
enum
{
  C_BIT_NORETURN = 1,
};

#define IS_C_BIT_NORETURN(d) (d->attr_flags & C_ATTR_NORETURN)

struct sema_generic
{
  int tag;
};

struct sema_def
{
  struct sema_def   *next;

  ident_t            name;
  int                flags;     /* storage class, object type */
  typeinfo_t         type;      /* type information */
  typeinfo_t         display_type; /* for variable-size objects */
  struct sema_scope *scope;     /* the containing scope */
  struct sema_scope *nest;      /* the nested scope */
  tree_t             tree;      /* pointer to the tree node */
  struct sema_def   *root;      /* corresponding global definition */
  struct sema_def   *impl;      /* reference to implementation */
  struct sema_def   *host;      /* the hosting type (for enums) */
  struct sema_def   *link;      /* a link for enumerated consts */
  int                bit_num;   /* bitfield width */
  int                bit_first; /* first bit in the bitfield */

  size_t             size;
  size_t             align;
  
  struct s_c_value  *value;     /* attached value (for enum constants) */
  struct sema_init  *init;      /* initializer (for non-local vars) */
  pos_t             *ppos;      /* definition position */
  int                use_cntr;  /* use counter */
  int                nomif_flag; /* do not generate MIF for it */

  mifelem_t          gen_data;  /* pointer to the code generator data */
  mifelem_t          gen_data2; /* another pointer */

  unsigned           attr_flags;
};

struct sema_deflist
{
  struct sema_def *first;
  struct sema_def *last;
};

struct sema_switem
{
  struct sema_switem *next;     /* next item in the list */
  struct sema_switem *gnext;    /* next item in the label group */

  struct s_c_value  *val;       /* switch value */
  pos_t             *ppos;     /* label position */
  tree_t             tree;      /* reference to the tree node */
  struct sema_scope *scope;     /* the containing scope */
  struct sema_scope *sw_scope;  /* the switch operator's scope */
  struct sema_scope_list *scopes; /* list of scopes to enter */

  mifelem_t gen_data;           /* entry code for this label */
  mifelem_t gen_scope_list;     /* generated scope list */
};

struct sema_swarr
{
  int default_def;      /* number of redefinitions of default */
  struct sema_switem *default_label; /* the default label */
  struct sema_switem *case_labels; /* the list of case labels */
  int nlabel;                   /* the number of case labels */
  struct sema_switem **sorted_labels; /* the sorted list of labels */
  typeinfo_t type;              /* selector type */

  mifelem_t gen_data; /* reference to generated switch table  */
  mifelem_t next_instr;      /* next instruction after switch */
};

struct sema_list
{
  struct sema_list *next;
  void *item;
};

/* tags for sema_scope */
enum { SSC_STRUCT_SCOPE = 1, SSC_ARG_SCOPE = 2 };

struct sema_scope
{
  struct sema_generic  g;
  struct sema_scope   *up;      /* the upper scope */
  struct sema_scope   *func;    /* the function scope */
  struct sema_scope   *next;    /* the next scope */
  struct sema_scope   *nest;    /* implicitly nested scope */
  struct sema_scope   *same_scope;

  struct sema_def     *def;     /* reference to the definition */

  struct sema_deflist  reg;     /* regular identifiers */
  struct sema_deflist  tags;    /* structs, unions, enums */
  struct sema_deflist  labels;  /* labels */
  struct sema_swarr   *swlab;   /* switch labels */
  struct sema_list    *gotos;   /* list of all `goto', `break', etc */

  pos_t               *ppos;     /* position */
  unsigned int         size;    /* size of the scope unit */

  mifelem_t            gen_data; /* code generation extra data */
  mifelem_t            use_instr; /* place, where the scope is used */

  int                  generated; /* already generated? */
  int                  varsized; /* contains variable-size objects */
};

enum
  {
    ST_SCOPE_ENTRY,
    ST_SCOPE_EXIT
  };
struct sema_scope_list
{
  struct sema_scope_list *next;
  int mode;
  struct sema_scope      *scope;
};

/* valid tags for semantics nodes */
enum
{
  ST_SCOPE,                     /* scope unit */
  ST_IDUSE,                     /* use of an identifier */
  ST_SWLAB,                     /* switch label */
  ST_TYPE,                      /* type information (for exprs) */
  ST_GOTO,                      /* goto information */

  ST_LAST
};

/* */
struct s_scope
{
  int                 tag;
  struct sema_scope  *scope;
};

struct s_iduse
{
  int                 tag;
  struct sema_def    *def;
};

struct s_swlab
{
  int                 tag;
  struct sema_switem *def;
};

struct s_type
{
  int         tag;
  typeinfo_t  type;
  mifelem_t   gen_data;
};

struct s_goto
{
  int tag;
  struct sema_def *def;
  struct sema_scope *use_scope;
  struct sema_scope_list *scopes;
  mifelem_t gen_data;
};

union s_semainfo
{
  int            tag;
  struct s_scope s_scope;
  struct s_iduse s_iduse;
  struct s_swlab s_swlab;
  struct s_type  s_type;
  struct s_goto  s_goto;
};

#ifndef RCC_SEMAINFO_T_DEFINED
#define RCC_SEMAINFO_T_DEFINED 1
typedef union s_semainfo *semainfo_t;
#endif /* RCC_SEMAINFO_T_DEFINED */

/* valid expression contexts */
enum
{
  EK_VOID,
  EK_TEST,
  EK_VALUE,
  EK_LVALUE,
  EK_MAX                        /* maximum value */
};

enum s_aftag
  {
    SAF_FIELD,
    SAF_ARRAY
  };

struct s_afaccess
{
  struct s_afaccess *next;      /* next item */
  struct s_afaccess *prev;      /* previous item */
  enum s_aftag       tag;       /* access tag */
  tree_t             tree;      /* tree reference */
  void              *tree_expr; /* array expr, field definition */
  unsigned int       mult;      /* array index multiplier */
  typeinfo_t         size_def;
  typeinfo_t         type;      /* the result type */

  mifelem_t static_offset;      /* static offset reference (for fields) */
  mifelem_t gen_type;           /* generated type information */
};
#ifndef RCC_AFACCESS_T_DEFINED
#define RCC_AFACCESS_T_DEFINED 1
typedef struct s_afaccess *afaccess_t;
#endif /* RCC_AFACCESS_T_DEFINED */

struct sema_init
{
  typeinfo_t type;              /* initializer type */
  tree_t tree_init;             /* reference to Init1 expression node */
  int nitem;                    /* number of subinitializers */
  struct sema_init **inits;     /* subinitializers */
  tree_t assign_expr;           /* assignment statement for non-const inits */

  mifelem_t gen_data;           /* initializer description */
};
typedef struct sema_init *sema_init_t;


struct sema_scope *sema_function_scope_create(struct sema_scope *, struct sema_def *);
struct sema_scope *sema_scope_create(struct sema_scope *);

void sema_add_to_gotos(struct sema_scope *, void *);

semainfo_t sinfo_create_scope(struct sema_scope *);
semainfo_t sinfo_create_iduse(struct sema_def *);
semainfo_t sinfo_create_type(typeinfo_t);
semainfo_t sinfo_create_goto(struct sema_def *, struct sema_scope *, struct sema_scope_list *);
semainfo_t sinfo_create_swlab(struct sema_switem *);

typeinfo_t typeinfo_clone(typeinfo_t, int);
typeinfo_t typeinfo_create_arith(int, int);
typeinfo_t typeinfo_create_builtin(int, int);
typeinfo_t typeinfo_create_array(typeinfo_t, rulong_t, typeinfo_t);
typeinfo_t typeinfo_create_function(int, typeinfo_t, struct sema_scope *,
                                    struct sema_scope *);
typeinfo_t typeinfo_create_pointer(int, typeinfo_t);
typeinfo_t typeinfo_create_aggreg(int, ident_t, struct sema_def *);
typeinfo_t typeinfo_create_enum(int, ident_t, struct sema_def *);
typeinfo_t typeinfo_create_typedef(int, ident_t, struct sema_def *);

typeinfo_t ti_create_void_pointer(void);

void typeinfo_set_bits(typeinfo_t, int);
void typeinfo_clear_bits(typeinfo_t, int);
int  typeinfo_get_bits(typeinfo_t);
int  typeinfo_get_cv(typeinfo_t);

#endif /* __SEMA_DATA_H__ */
