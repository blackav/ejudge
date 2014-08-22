/* $Id$ */

/* Copyright (C) 1997-2014 Alexander Chernov <cher@ejudge.ru> */

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

/**
 * FILE:    getopt.c
 * PURPOSE: option parser
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/getopt.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/xfile.h"
#include "ejudge/osdeps.h"
#include "ejudge/flexstring.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
/* FIXME: does not exist on win32 #include <unistd.h> */
#include <stdarg.h>

/* option reading types */
#define OSRC_ARRAY 0            /* read options from array */
#define OSRC_FILE  1            /* read options from file */

//char opt_default[]="<default>"; /* default option string */

/* options source stack */
typedef struct opt_stack_t
{
  int   opt_src;                /* option reading source */
  union {
    FILE  *opt_file;            /* source file */
    int    opt_argi;            /* argument counter */
    struct {
      char   **v;               /* argument pointer */
      int      u;               /* argument array size */
      int      i;               /* argument index */
    }      opt_arr;             /* array argument source */
  }     x;
} opt_stack_t;

#define OPT_STMAX   5           /* maxumum stack nest */

static int         opt_sp = -1; /* option source stack pointer */
static opt_stack_t opt_stack[OPT_STMAX]; /* option source stack */

static char      *opt_desc;     /* tool description (provided by used) */
static char     **opt_versions; /* tool versions */
static char      *opt_progname; /* program name (basename(argv[0]) */
static char      *opt_version;       /* overall version */
static char      *opt_copyright;     /* copyright information */
static int        opt_counter = 0; /* option counter */
static char       opt_id[1024]; /* program identification string */
static int        opt_flags;         /* various flags */
static short      opt_quiet = 0; /* quiet? */

#define OPTTOTAL 1024           /* maximum number of options */
static optrec_t   opt_data[OPTTOTAL]; /* option descriptors */
static int        opt_cntr[OPTTOTAL]; /* option usage counter */
static int        opt_data_u;   /* number of used entries in opt_data */

/* option error reporting handler */
static int      (*opt_error)(int, char *, ...) = 0;

static tFString buf;            /* string buffer */

#define OPT_STRBUFMAX 10        /* max word buffer length */
static char *strbuf[OPT_STRBUFMAX]; /* word buffer (reads from file) */
static int   strbuf_used = 0;

static int initialized = 0;
static void
opt_free_module(void)
{
  int i;

  if (!initialized) return;
  initialized = 0;

  for (i = 0; i < OPT_STRBUFMAX; i++) {
    xfree(strbuf[i]); strbuf[i] = 0;
  }
  fsDestroy(buf);
  xfree(opt_progname); opt_progname = 0;
}
static void
opt_initialize(void)
{
  if (initialized) return;
  initialized = 1;
  atexit(opt_free_module);
}

static int builtin_handler(int, char *, ...);
static int empty_handler(int, char *, ...);

/**
 * NAME:    opt_getword
 * PURPOSE: get a word from an option source
 * RETURNS: options word
 */
  static char *
opt_getword(void)
{
  int          c;
  opt_stack_t *ss = 0;

  if (opt_sp < 0) return 0;
  if (opt_sp >= OPT_STMAX)
    {
      opt_sp--;
      return opt_getword();
    }

  ss = &opt_stack[opt_sp];

  switch (ss->opt_src)
    {
    case OSRC_ARRAY:
      if (ss->x.opt_arr.i >= ss->x.opt_arr.u)
        {
          opt_sp--;
          return opt_getword();
        }
      if (ss->x.opt_arr.v[ss->x.opt_arr.i] == NULL)
        {
          opt_sp--;
          return opt_getword();
        }
      return ss->x.opt_arr.v[ss->x.opt_arr.i++];

    case OSRC_FILE:
      /* read word from file */
      fsClear(buf);

      while (isspace(c = getc(ss->x.opt_file)));

      if (c == EOF)
        {
          
          fclose(ss->x.opt_file);
          opt_sp--;
          return opt_getword();
        }

      while (c != EOF && !isspace(c))
        {
          fsAdd(buf, (char) c);
          c = getc(ss->x.opt_file);
        }

      if (c != EOF)
        ungetc(c, ss->x.opt_file);

      if (strbuf_used == OPT_STRBUFMAX)
        {
          int i;

          xfree(strbuf[0]);
          for (i = 0; i < OPT_STRBUFMAX - 1; i++)
            strbuf[i] = strbuf[i + 1];
          strbuf_used--;
        }

      strbuf[strbuf_used] = fsDup(buf);
      return strbuf[strbuf_used++];
      
    default:
      abort();
    }
  return NULL;
}

/**
 * NAME:    handle_s
 * PURPOSE: handle 's' option parse type
 * NOTE:    all handle_* functions handles various option parse types
 *          their arguments are only described here
 * NOTE:    's' option parse type used to read short integers
 *          either from arguments, or from option parse type string
 *          itself. The following parse types are supported:
 *            "s+" - read short integer argument from options
 *            "s*" - read short integer from extra data pointer
 *            "s<short>" - read short integer from parse type string
 */
  static int
handle_s(optrec_t *rec,         /* Option record */
         char     *modif,       /* parsed modifier */
         int       mod_type,    /* modifier type */
         char     *w1,          /* first option word */
         char     *w2,          /* second option word */
         short    *pdata,       /* data pointer */
         int      *args         /* extra args */
         )
{
  long  val;
  char *p;

  switch (mod_type)
    {
    case 1:                     /* s+ */
      val = strtol(w2, &p, 10);
      if (*p != 0 || val < SHRT_MIN || val > SHRT_MAX)
        {
          opt_banner();
          return opt_error(OPTE_SHORT,
                           "Error: short integer argument expected for %s\n",
                           rec->opt_name);
        }            
      *pdata = (short) val;
      break;
    case 2:                     /* s<number> */
      *pdata = (short) args[0];
      break;
    case 3:                     /* s* */
      *pdata = (short) (long) rec->opt_extra;
      break;
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}

/**
 * NAME:    handle_l
 * PURPOSE: handle 'l' option parse type
 * NOTE:    'l' option parse type used to read long integers
 *          either from arguments, or from option parse type string
 *          itself. The following parse types are supported:
 *            "l+" - read long integer argument from options
 *            "l*" - read long integer from extra data pointer
 *            "l<long>" - read long integer from parse type string
 */
  static int
handle_l(optrec_t *rec,         /* Option record */
         char     *modif,       /* parsed modifier */
         int       mod_type,    /* modifier type */
         char     *w1,          /* first option word */
         char     *w2,          /* second option word */
         long     *pdata,       /* data pointer */
         int      *args         /* extra args */
         )
{
  long  val;
  char *p;

  switch (mod_type)
    {
    case 111:                   /* l+ */
      val = strtol(w2, &p, 10);
      if (*p != 0)
        {
          opt_banner();
          return opt_error(OPTE_SHORT,
                           "Error: short integer argument expected for %s\n",
                           rec->opt_name);
        }            
      *pdata = val;
      break;
    case 112:                   /* s<number> */
      *pdata = (long) args[0];
      break;
    case 113:                   /* s* */
      *pdata = (long) rec->opt_extra;
      break;
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}

/**
 * NAME:    handle_m
 * PURPOSE: handle 'm' option parse type
 * NOTE:    'm' option parse type used to set up individual
 *          flags in flags word.
 *          Flags are kept in optmask_t structure
 *          field 'mask' has bits set for all flags, which have been
 *          altered (either set to 1, or set to 0), field 'flags'
 *          contains flags value. Bits that should be flipped for
 *          a given option are taken from 'opt_extra' field
 *          of option descriptor structure optrec_t.
 *          The following option parse types are supported:
 *            "m-" - clear bits specified in opt_extra field
 *            "m+" - set bits specified in opt_extra field
 *            "m*" - toggle bits
 */
  static int
handle_m(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         optmask_t *pdata,
         int       *args)
{
  switch (mod_type)
    {
    case 91:                    /* m- */
      pdata->mask  |=  (unsigned long) rec->opt_extra;
      pdata->flags &= ~(unsigned long) rec->opt_extra;
      break;
    case 92:                    /* m+ */
      pdata->mask  |=  (unsigned long) rec->opt_extra;
      pdata->flags |=  (unsigned long) rec->opt_extra;
      break;
    case 93:                    /* m* */
      pdata->mask  |=  (unsigned long) rec->opt_extra;
      pdata->mask  ^=  (unsigned long) rec->opt_extra;
      break;
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}

/**
 * NAME:    handle_c
 * PURPOSE: handle 'c' option parse type
 * NOTE:    'c' option parse type is used to substitute one option
 *          with several other options. When an option with 'c'
 *          parse type is parsed, all options from specified
 *          array of options are parsed and executed.
 */
  static int
handle_c(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         char     **pdata,
         int       *args)
{
  switch (mod_type)
    {
    case 101:                   /* c */
      if (opt_sp == OPT_STMAX - 1)
        {
          opt_banner();
          return opt_error(OPTE_TOONEST,
                           "Error: too many indirect levels");
        }
      opt_sp++;
      opt_stack[opt_sp].opt_src = OSRC_ARRAY;
      opt_stack[opt_sp].x.opt_arr.v = pdata;
      opt_stack[opt_sp].x.opt_arr.i = 0;
      opt_stack[opt_sp].x.opt_arr.u = 32767;
      break;
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}

/**
 * NAME:    handle_f
 * PURPOSE: handle 'f' option parse type
 * NOTE:    'f' option parse type is used to treat the argument
 *          of the option (or the option itself in case of default option),
 *          as the file path that should be opened and its FILE structure
 *          to be stored to the specified structure (of type optfile_t)
 *          along with the name of the file.
 */
  static int
handle_f(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         optfile_t *pdata,
         int       *args)
{
  if (pdata->name != NULL)
    {
      xfclose(pdata->file); pdata->file = 0;
      xfree(pdata->name);   pdata->name = 0;
    }

  if (!(pdata->file = xfopen(w2, modif + 1)))
    return -OPTE_CANNOTOPEN;
  pdata->name = xstrdup(w2);
  return 0;
}

/**
 * NAME:    handle_a
 * PURPOSE: handle 'a' option parse type
 * NOTE:    when 'a' option parse type is used, a user provided
 *          function (callback) is called when the option is parsed.
 *          Arguments passed to the function vary slightly depending
 *          option modifier. The following parse types are supported:
 *            "a+" - requires extra option value after option name.
 *                   the callback is called with three arguments:
 *                     option name
 *                     option value
 *                     option identifier
 *            "a-" - requires extra option value after option name,
 *                   but do not pass option name to the callback.
 *                   The callback parameters as follows:
 *                     option value
 *                     option identifier
 *            "a"  - do not requires option value.
 *                   The callback parameters as follows:
 *                     option name
 *                     option identifier
 */
  static int
handle_a(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         int      (*pdata)(),
         int        args)
{
  switch (mod_type)
    {
    case 21:                    /* a+ */
      return pdata(w1, w2, rec->opt_id);
    case 22:                    /* a- */
      return pdata(w2, rec->opt_id);
    case 23:                    /* a */
      return pdata(w1, rec->opt_id);
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}

/**
 * NAME:    handle_A
 * PURPOSE: handle 'A' option parse type
 * NOTE:    'A' option parse type is basically the same as 'a' option
 *          parse type, except that value of 'opt_extra' field
 *          of the option descriptor structure is passed to the
 *          user provided handler as the first argument.
 */
  static int
handle_A(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         int      (*pdata)(),
         int        args)
{
  switch (mod_type)
    {
    case 31:                    /* A+ */
      return pdata(rec->opt_extra, w1, w2, rec->opt_id);
    case 32:                    /* A- */
      return pdata(rec->opt_extra, w2, rec->opt_id);
    case 33:                    /* A */
      return pdata(rec->opt_extra, w1, rec->opt_id);
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}
/**
 * NAME:    handle_t_
 * PURPOSE: handle 't' option parse type
 * NOTE:    't' option parse type used to store the value of the
 *          option in the string (char*) allocated in the heap.
 *          Only the last value of the option is stored.
 *          The following option parse types are supported:
 *            "t+" - store the value of the option in the string
 *            "t0" - clear the user provided string
 *            "t1" - store the value of the option once
 */
  static int
handle_t_(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         char     **pdata,
         int        args)
{
  switch (mod_type)
    {
    case 41:                    /* t+ */
      xfree(*pdata);
      *pdata = xstrdup(w2);
      return 0;
    case 42:                    /* t0 */
      xfree(*pdata);
      *pdata = 0;
      return 0;
    case 43:                    /* t1 */
      if (*pdata) {
        opt_banner();
        return opt_error(OPTE_ONCE,
                         "Error: `%s' may be specified only once\n",
                         rec->opt_name);
      }
      *pdata = xstrdup(w2);
      return 0;
    default:
      SWERR(("mod_type == %d", mod_type));
    }
  return 0;
}

/**
 * NAME:    handle_v
 * PURPOSE: handle 'v' option parse type
 * NOTE:    'v' option parse type used for options which purpose
 *          is to print the tool's version (eg --version)
 */
  static int
handle_v(void)
{
  int i;

  opt_banner();

  if (opt_versions != NULL)
    {
      for (i = 0; opt_versions[i] != NULL; i++)
        fprintf(stderr, "%s\n", opt_versions[i]);
    }
  
  exit(0);
#ifndef __GNUC__
  return 0;
#endif /* __GNUC__ */
}

/**
 * NAME:    handle_h
 * PURPOSE: handle 'h' option parse type
 * NOTE:    'h' option parse types are used for various
 *          option help messages
 */
  static int
handle_h(optrec_t      *rec,
         char          *modif,
         int            mod_type,
         char          *w1,
         char          *w2,
         unsigned long  pdata,
         int            args)
{
  int            i, j;
  char          *d = 0;
  unsigned long  um;
  char          buf[128];
  int           maxlen = -1;

  /* pdata is option mask to print */

  opt_banner();

  fprintf(stdout,
          "SYNOPSIS: %s <options>\n"
          "OPTIONS are:\n", opt_progname);

  for (j = 0; j < 2; j++)
    {
      for (i = 0; opt_data[i].opt_name != NULL; i++)
        {
          if (opt_data[i].opt_name == (char*) 1) continue;
          if (opt_data[i].opt_name == opt_default)
            {
              d = opt_data[i].opt_info;
              continue;
            }
          if ((opt_data[i].opt_opts & OPT_HIDDEN)) continue;
          if (!opt_data[i].opt_info) continue;
          
          um = opt_data[i].opt_opts & OPT_USERMASK;
          
          if (mod_type == 62)   /* "h=" */
            {
              if (um != pdata) continue;
            }
          else if (mod_type == 63)      /* "h|" */
            {
              if (!(um & pdata)) continue;
            }
          else if (mod_type == 64)      /* "h<" */
            {
              /* um is subset of pdata */
              if (!(~um | pdata)) continue;
            }
          else if (mod_type == 65)      /* "h>" */
            {
              /* um is superset of pdata */
              if (!(um | ~pdata)) continue;
            }
          
          if (opt_data[i].opt_arginfo)
            {
              if (opt_data[i].opt_arginfo[0] == ' ')
                {
                  sprintf(buf, "%s <%s>",
                          opt_data[i].opt_name,
                          opt_data[i].opt_arginfo + 1);
                }
              else
                {
                  sprintf(buf, "%s<%s>",
                          opt_data[i].opt_name,
                          opt_data[i].opt_arginfo);
                }
            }
          else
            {
              strcpy(buf, opt_data[i].opt_name);
            }

          if (j == 0)
            {
              if (maxlen < (int) strlen(buf))
                maxlen = strlen(buf);
            }
          else
            {
              fprintf(stdout, "\t%*s - %s\n",
                      -maxlen, buf,
                      opt_data[i].opt_info);
            }
        }
    }

  if (d != NULL)
    {
      fprintf(stdout,
              "An argument, not recognized as option, is a %s\n",
              d);
    }
  
  exit(0);
#ifndef __GNUC__
  return 0;
#endif /* __GNUC__ */
}

/**
 * NAME:    handle_U
 * PURPOSE: handle 'U' option parse type
 * NOTE:    'U' option parse type is used when warning about
 *          unknown or unsupported error should be printed instead
 *          of error and termination of the program
 */
  static int
handle_U(optrec_t  *rec,
         char      *modif,
         int        mod_type,
         char      *w1,
         char      *w2,
         void      *pdata,
         int        args)
{
  if (!(opt_flags & OPTF_NOWARN))
    {
      opt_banner();
      opt_error(OPTE_IGNOPTION,
                "Warning: option '%s' is unknown (ignored)\n", w1);
    }
  return 0;
}

/**
 * NAME:    handle_V
 * PURPOSE: handle 'V' option parse type
 * NOTE:    'V' option parse type stores the value of the option
 *          of this type into the expandable array of strings.
 *            "V+" - read option value and store the value in the array
 *            "V-" - store option name in the array, do not read the value
 */
  static int
handle_V(optrec_t   *rec,
         char       *modif,
         int         mod_type,
         char       *w1,
         char       *w2,
         strarray_t *pdata,
         int         args)
{
  switch (mod_type)
    {
    case 81:                    /* V+ */
      break;
    case 82:                    /* V- */
      w2 = w1; break;
    case 83:                    /* V2 */
      xexpand(pdata);
      pdata->v[pdata->u++] = xstrdup(w1);
      break;
    default:
      SWERR(("mod_type == %d", mod_type));
    }

  xexpand(pdata);
  pdata->v[pdata->u++] = xstrdup(w2);
  return 0;
}

/* option parse type descriptor structure */
struct modif_info
{
  int    mod_type;              /* option parse type identifier */
  int    mod_args;              /* number of cmd args for this option type */
  int    mod_params;            /* if 1, integer parameter should be read
                                 * from option parse type string */
  char  *mod_format;            /* format for sscanf to check for option */
  int  (*mod_handler)(/* optrec_t*,char*,int,char*,char*,void*,int* */);
                                /* option parse handler */
};

/* option parse type descriptors */
static struct modif_info modifiers[] =
{
  {  1, 2, 0, "s+",     handle_s },
  {  2, 1, 1, "s%d%n",  handle_s },
  {  3, 1, 0, "s*",     handle_s },

  { 111, 2, 0, "l+",     handle_l },
  { 112, 1, 1, "l%d%n",  handle_l },
  { 113, 1, 0, "l*",     handle_l },

  { 11, 2, 0, "fr",     handle_f },
  { 12, 2, 0, "fw",     handle_f },

  { 21, 2, 0, "a+",     handle_a },
  { 22, 2, 0, "a-",     handle_a },
  { 23, 1, 0, "a",      handle_a },

  { 31, 2, 0, "A+",     handle_A },
  { 32, 2, 0, "A-",     handle_A },
  { 33, 1, 0, "A",      handle_A },

  { 41, 2, 0, "t+",     handle_t_ },
  { 42, 1, 0, "t0",     handle_t_ },
  { 43, 2, 0, "t1",     handle_t_ },

  { 51, 1, 0, "v",      handle_v },

  { 62, 1, 0, "h=",     handle_h },
  { 63, 1, 0, "h|",     handle_h },
  { 64, 1, 0, "h<",     handle_h },
  { 65, 1, 0, "h>",     handle_h },
  { 61, 1, 0, "h",      handle_h },

  { 71, 1, 0, "U",      handle_U },

  { 81, 2, 0, "V+",     handle_V },
  { 82, 1, 0, "V-",     handle_V },
  { 83, 2, 0, "V2",     handle_V },

  { 91, 1, 0, "m-",     handle_m },
  { 92, 1, 0, "m+",     handle_m },
  { 93, 1, 0, "m*",     handle_m },

  { 101,1, 0, "c",      handle_c },

  { 0, 0, 0, 0, 0 }
};

/**
 * NAME:    check_modif
 * PURPOSE: check the provided modifier against the modifier descriptor
 * ARGS:    info  - pointer to option parse type descriptor
 *          modif - modifier to check
 *          rec   - pointer to option descrptor
 *          w1    - option name (first option word)
 *          data  - user data pointer to store the value of the option
 * RETURN:  o result of the option parse type handler
 *          o -666, if option parse type does not match
 *          o <0, other errors
 */
  static int
check_modif(struct modif_info *info,
            char              *modif,
            optrec_t          *rec,
            char              *w1,
            void              *data)
{
  int     arg_buf[32];
  int     res;
  int     n;
  char   *w2 = 0;

  switch (info->mod_params)
    {
    case 0:
      if (strcmp(modif, info->mod_format)) return -666;
      break;
    case 1:
      res = sscanf(modif, info->mod_format, arg_buf, &n);
      if (res != info->mod_params) return -666;
      if (modif[n]) return -666;
      break;
    default:
      SWERR(("%d parameters not supported", info->mod_params));
    }

  switch (info->mod_args)
    {
    case 1:
      w2 = 0;
      break;
    case 2:
      if (rec->opt_name == (char*) 1)
        SWERR(("Attempt to read parameter when opt_name == 1"));
      if (rec->opt_name != opt_default)
        w2 = opt_getword();
      else
        w2 = w1;

      if (!w2)
        {
          opt_banner();
          return opt_error(OPTE_ARG,
                           "Error: argument expected for option '%s'\n",
                           rec->opt_name);
        }
      break;
    default:
      SWERR(("%d arguments not supported", info->mod_args));
    }

  return (info->mod_handler)(rec,modif,info->mod_type,w1,w2,data,arg_buf);
}

/**
 * NAME:    opt_parse
 * PURPOSE: process the given option according to option descriptor
 * ARGS:    rec    - pointer to the option descriptor
 *          w1     - option value
 *          offset - offset from the start of the option parse type string
 *          cntr   - pointer to the option usage counter
 * RETURN:  <0 - error, or
 *          return code of the check_modif function
 */
  static int
opt_parse(optrec_t *rec, char *w1, int offset, int *cntr)
{
  char  *s;
  char   opt_name[128];
  void  *pdata = rec->opt_data;
  int    i;
  int    res;
  int    read_next = 0;

  ASSERT(rec->opt_data);

  if (rec->opt_name == (char*) 1)
    sprintf(opt_name, "???");
  else if (rec->opt_name != opt_default)
    sprintf(opt_name, "option `%s'", rec->opt_name);
  else
    sprintf(opt_name, "%s", rec->opt_info);

  assert(rec != NULL);
  assert(rec->opt_flags != NULL);

  s = rec->opt_flags + offset;

  if (*s == '+')
    {
      read_next = 1;
      s++;
    }

  if (*s == '1')
    {
      if (*cntr >= 1)
        {
          opt_banner();
          return opt_error(OPTE_RESPECIFIED, 
                           "Error: %s can be specified only once\n",
                           opt_name);
        }
      (*cntr)++;
      s++;
    }

  if (*s == '#')
    {
      pdata = *(void **) pdata;
      if (!pdata)
        {
          opt_banner();
          return opt_error(OPTE_NOADDR,
                           "Error: module provided no support for %s\n",
                           w1);
        }
      s++;
    }


  if (*s == '@')
    {
      /* use indirect addressing */
      pdata = ((void *(*)(char const *, int))pdata)(w1, rec->opt_id);
      if (!pdata)
        {
          opt_banner();
          return opt_error(OPTE_NOADDR,
                           "Error: module provided no support for %s\n",
                           w1);
        }
      s++;
    }

  if (*s == '$')
    {
      /* use resource table */
      optresource_t *res = (optresource_t*) pdata;

      for (i = 0; res[i].id != 0 && res[i].id != rec->opt_id; i++);

      if (!res[i].id || !res[i].ptr)
        {
          opt_banner();
          return opt_error(OPTE_NOADDR,
                           "Error: module provided no support for %s\n",
                           w1);
        }
      pdata = res[i].ptr;
      s++;
    }

  if (*s == '&')
    {
      /* use secondary option table */
      optrec_t *res = (optrec_t*) pdata;

      for (i = 0; res[i].opt_id != 0 && res[i].opt_id != rec->opt_id; i++);

      if (!res[i].opt_id)
        {
          opt_banner();
          return opt_error(OPTE_NOADDR,
                           "Error: module provided no support for %s\n",
                           w1);
        }
      return opt_parse(res + i, w1, 0, cntr);
    }

  for (i = 0; modifiers[i].mod_format; i++)
    {
      res = check_modif(modifiers + i, s, rec, w1, pdata);
      if (res != -666)
        {
          if (read_next)
            return opt_parse(rec + 1, w1, 0, cntr + 1);
          else
            return res;
        }
    }

  SWERR(("invalid modifier '%s'", s));
  return -1;
}

/**
 * NAME:    opt_banner
 * PURPOSE: print the program banner
 * NOTE:    the banner is printed only once
 */
static short opt_banner_flag = 0;
  void
opt_banner(void)
{
  opt_initialize();
  if (opt_banner_flag)
    return;

  fprintf(stderr, "%s\n", opt_id);

  if (opt_desc != NULL)
    {
      fprintf(stderr, "%s\n", opt_desc);
    }

  if (opt_copyright != NULL)
    {
      fprintf(stderr, "%s\n", opt_copyright);
    }

  opt_banner_flag = 1;
}

/**
 * NAME:    opt_setflags
 * PURPOSE: set option parse flags
 * ARGS:    flags - new value of option parse flags
 */
  void
opt_setflags(int flags)
{
  opt_initialize();
  opt_flags = flags;
}

/**
 * NAME:    opt_resetargs
 * PURPOSE: reset option tables and command arguments
 * ARGS:    data  - new option descriptor table
 *          argc  - number of arguments
 *          argv  - arguments
 *          flags - option parse flags
 */
  void
opt_resetargs(optrec_t *data, int argc, char **argv, int flags)
{
  opt_initialize();
  opt_sp = 0;
  opt_stack[0].opt_src = OSRC_ARRAY;
  opt_stack[0].x.opt_arr.u = argc;
  opt_stack[0].x.opt_arr.i = 1;
  opt_stack[0].x.opt_arr.v = argv;

  opt_flags = flags;

  opt_clearoptions();
  opt_setoptions(data);
}

/**
 * NAME:    opt_setargs
 * PURPOSE: setup option parse tables initially
 * ARGS:    data      - option descriptors table
 *          desc      - program description
 *          versions  - versions of separate modules of the program
 *          version   - program version
 *          copyright - copyright notice
 *          argc      - number of arguments
 *          argv      - arguments to parse
 *          flags     - option parse flags
 */
  void
opt_setargs(optrec_t *data, char *desc, char **versions,
            char *version, char *copyright,
            int argc, char **argv, int flags)
{
  assert(data != NULL);
  assert(argv != NULL);

  opt_initialize();

  opt_error = builtin_handler;
  
  opt_clearoptions();
  opt_setoptions(data);

  opt_sp = 0;
  opt_stack[0].opt_src = OSRC_ARRAY;
  opt_stack[0].x.opt_arr.u = argc;
  opt_stack[0].x.opt_arr.v = argv;
  opt_stack[0].x.opt_arr.i = 1;

  opt_desc = desc;
  opt_versions = versions;
  opt_version = version;
  opt_copyright = copyright;
  opt_flags = flags;
  opt_progname = os_GetBasename(argv[0]);

  /* Set program identification string */
  if (opt_version != NULL)
    {
      sprintf(opt_id, "%s: %s", opt_progname, opt_version);
    }
  else
    {
      sprintf(opt_id, "%s", opt_progname);
    }
}

/**
 * NAME:    opt_getname
 * PURPOSE: get program name (basename(argv[0]))
 * RETURN:  pointer to program name string for read-only
 */
  char *
opt_getname(void)
{
  opt_initialize();
  return opt_progname;
}

/**
 * NAME:    opt_getid
 * PURPOSE: get program identification string
 * RETURN:  pointer to the program idenfication string for read only
 */
  char *
opt_getid(void)
{
  opt_initialize();
  return opt_id;
}

/**
 * NAME:    opt_get
 * PURPOSE: parse one option
 * RETURN:  OPT_END - no more options
 *          <0      - error
 *          >=0     - option identifier (opt_id field of optrec_t structure)
 */
  int
opt_get(void)
{
  char *w1;
  int   i;
  int   r;

  opt_initialize();
  w1 = opt_getword();
  
  if (w1 == NULL)
    return OPT_END;

  if (w1[0] == '@' && !(opt_flags & OPTF_NOATSIGN))
    {
      char *n = 0;
      FILE *f = 0;

      /* get name of indirect file */
      if (w1[1] != 0)
        {
          n = w1 + 1;
        }
      else
        {
          n = opt_getword();
          if (n == NULL)
            {
              opt_banner();
              return opt_error(OPTE_INDIR,
                               "Error: indirect file name expected\n");
            }
        }

      if (opt_sp == OPT_STMAX - 1)
        {
          opt_banner();
          return opt_error(OPTE_TOONEST,
                           "Error: too many indirect levels");
        }

      if (!(f = xfopen(n, "r")))
        {
          opt_banner();
          return opt_error(OPTE_OPENINDIR,
                           "Error: cannot open indirect file\n");
        }

      opt_sp++;
      opt_stack[opt_sp].opt_src = OSRC_FILE;
      opt_stack[opt_sp].x.opt_file = f;

      return opt_get();
    }

  opt_counter++;

  for (i = 0; i < opt_data_u; i++)
    {
      if (opt_data[i].opt_name ==(char*) 1) continue;
      if (opt_data[i].opt_name == opt_default) continue;
      if (!strcmp(w1, opt_data[i].opt_name))
        {
          r = opt_parse(&opt_data[i], w1, 0, &opt_cntr[i]);
          if (r < 0)
            {
              if ((opt_flags & OPTF_NOEXIT))
                return r;
              exit(1);
            }
          return opt_data[i].opt_id;
        }
    }

  /* now try template rules like "*2" */
  for (i = 0; i < opt_data_u; i++)
    {
      int n;
      int v;

      if (opt_data[i].opt_name == (char*) 1) continue;
      if (opt_data[i].opt_name == opt_default) continue;
      if (opt_data[i].opt_flags[0] != '*')
        continue;
      if (sscanf(opt_data[i].opt_flags + 1, "%d%n", &v, &n) < 1)
        continue;
      if (strncmp(w1, opt_data[i].opt_name, v))
        continue;

      r = opt_parse(&opt_data[i], w1, n + 1, &opt_cntr[i]);
      if (r < 0)
        {
          if ((opt_flags & OPTF_NOEXIT))
            return r;
          exit(1);
        }
      return opt_data[i].opt_id;
    }

  /* not found as is */
  for (i = 0; i < opt_data_u; i++)
    {
      if (opt_data[i].opt_name == opt_default)
        {
          r = opt_parse(&opt_data[i], w1, 0, &opt_cntr[i]);
          if (r < 0)
            {
              if ((opt_flags & OPTF_NOEXIT))
                return r;
              exit(1);
            }
          return opt_data[i].opt_id;
        }
    }

  /* Issue an error */
  opt_banner();
  opt_error(OPTE_OPTION,
            "Error: invalid option `%s'\n", w1);
  if ((opt_flags & OPTF_NOEXIT))
    return -1;
  exit(1);
}

/**
 * NAME:    opt_close
 * PURPOSE: close the option parser
 * RETURN:  number of options parsed
 */
  int
opt_close(void)
{
  opt_initialize();
  return opt_counter;
}

/**
 * NAME:    opt_install_handler
 * PURPOSE: install error reporting handler
 * ARGS:    func - error reporting handler
 *          if func == NULL, empty error reporting handler is installed
 */
  void
opt_install_handler(int (*func)(int, char *, ...))
{
  opt_initialize();
  opt_error = func != NULL ? func : empty_handler;
}

/**
 * NAME:    opt_restore_handler
 * PURPOSE: restore default option reporting handler
 */
  void
opt_restore_handler(void)
{
  opt_initialize();
  opt_error = builtin_handler;
}

/**
 * NAME:    opt_setoptions
 * PURPOSE: add option descriptors to the currently installed
 * ARGS:    opts - option descriptors to add
 * RETURN:  <0 - error, >=0 - ok
 */
  int
opt_setoptions(optrec_t *opts)
{
  int i;

  opt_initialize();
  if (!opts) return 0;

  for (i = 0; opts[i].opt_name != NULL; i++)
    {
      if (!strcmp(opts[i].opt_flags, "@")) {
        opt_setoptions((optrec_t*) opts[i].opt_data);
        continue;
      } else if (!strcmp(opts[i].opt_flags, "@@")) {
        optrec_t **temp = (optrec_t**) opts[i].opt_data;
        if (!*temp) continue;
        opt_setoptions(*temp);
        continue;
      }
      if (opt_data_u >= OPTTOTAL - 1)
        {
          opt_error(OPTE_TOOMANY,
                    "Error: too many options");
          return -1;
        }
      opt_cntr[opt_data_u] = 0;
      opt_data[opt_data_u] = opts[i];
      opt_data_u++;
    }
  
  /* set a sentinel */
  opt_data[opt_data_u].opt_name = NULL;

  return 0;
}

/**
 * NAME:    opt_clearoptions
 * PURPOSE: clear installed option descriptors
 */
  void
opt_clearoptions(void)
{
  opt_initialize();
  opt_data_u = 0;
}

/**
 * NAME:    empty_handler
 * PURPOSE: empty option parse error reporting handler
 * ARGS:    code   - error code
 *          format - error message
 *          ...    - extra message specific arguments
 * RETURN:  -1
 */
  static int
empty_handler(int code, char *format, ...)
{
  return -1;
}

/**
 * NAME:    builtin_handler
 * PURPOSE: default option parse error reporting handler
 * ARGS:    code   - error code
 *          format - error message
 *          ...    - extra message specific arguments
 * RETURN:  -1
 */
  static int
builtin_handler(int code, char *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  return -1;
}

/**
 * NAME:    opt_setquiet
 * PURPOSE: set quiet option of the option parser
 * RETURN:  0
 */
  int
opt_setquiet()
{
  opt_initialize();
  opt_quiet = 1;
  opt_setflags(OPTF_NOWARN);
  return 0;
}

/**
 * NAME:    opt_getquiet
 * PURPOSE: get quiet option flag
 * RETURN:  quiet option flag
 */

  int
opt_getquiet()
{
  opt_initialize();
  return opt_quiet;
}

/**
 * NAME:    err_vStartup
 * PURPOSE: write a startup error message and exit
 * ARGS:    format - error message
 *          args   - extra message-specific arguments
 * NOTE:    the function never returns
 */
  void
err_vStartup(char *format, va_list args)
{
  opt_initialize();
  opt_banner();
  fprintf(stderr, "%s: ", opt_getname());
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  exit(2);
}

/**
 * NAME:    err_Startup
 * PURPOSE: write a startup error message end exit
 * ARGS:    format - error message
 *          ...    - extra message-specific args
 * NOTE:    the function never returns
 */
  void
err_Startup(char *format, ...)
{
  va_list args;

  opt_initialize();
  va_start(args, format);
  err_vStartup(format, args);
  va_end(args); /* dead code */
}
