/* $Id$ */

/* Copyright (C) 1997-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: Thu Feb 13 11:50:21 1997 by cher (Alexander Chernov) */

/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

/* cdeps.c: Extract dependencies from C files */
/* Implementation module */

/*
 * The utility is designed as a plug-in replacement for
 * shell script cdeps that was used in RASTA and REP
 * installation script. The main reason of such replacement is
 * drastic increase of speed, that would allow to rebuild dependencies
 * each time when one of source files is changed. However, C file must
 * be compiled before it can be used on each new architecture on which
 * REP tookit is to be installed. This could complicate installation
 * scheme as well.
 */

/* The following options supported:
 *     -s <suffix>      -- change suffix for object files (.o by default)
 *     -v <var_name>    -- change the name of object file list variable
 *                         ( OBJECTS by default )
 *     -d <dir_pref>    -- change directory for object files
 *                         ( empty by default, that means that object
 *                           files will be written to the same directory)
 *                         Don't forget to add '/' to the name of directory.
 *     -g               -- generate explicit command for C compilation
 *                         ( by default explicit command is not generated)
 *     -c               -- change explicit compilation command.
 *                         Makes sence only if -g option is used.
 *                         Line '<c_file> -c <o_file>' is always added
 *                         to the command. By default this command
 *                         is set to '$(CC) $(CALLFLAGS)'
 *     -C               -- change explicit compilation command for C++.
 *                         Makes sence only if -g option is used.
 *                         String '<c++_file> -c <o_file>' is always added
 *                         to the command. By default this command is set
 *                         to '$(CXX) $(CXXALLFLAGS)'
 *     -I               -- include directory
 *     -D               -- create directory structure in the
 *                         object directory, corresponding to the source
 *                         directory
 *     -c+ <opt> <files>-- specify the list of files for which the
 *                         specified option should be added to the
 *                         compilation string. The list of files should
 *                         terminate with "--"
 *     -o               -- specify the option of the compiler that
 *                         specifies the name of the output file
 *                         ( "-o " by default)
 *     -x               -- specify the compiler's compile-only option
 *                         ("-c" by default)
 *     -y               -- do not emit directory prefix (-d) to OBJECTS
 *                         variable
 *     -G1              -- specify, that generated files are located
 *                         in the "gen" directory.
 *     -G0, -G          -- specify, that generated files are located
 *                         in the standard platform-dependent directory
 *     -J1              -- specify, that dependency files are located
 *                         in the "dep" directory
 *     -J0, -J          -- specify, that dependency files are located
 *                         in the standard platform-dependent directory
 *     -b               -- specify the binary configuration name
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>

typedef struct fqueue_t
{
  struct fqueue_t *next;
  char *name;
} fqueue_t;

struct optlist
{
  struct optlist *next;
  char           *option;
  fqueue_t       *files;
};

#define STR_LENGTH 256
#define STR_MAXUSE 255

int use_compile_command = 0;
int print_banner = 1;
int use_object_subdirectories = 0;
int no_dir_in_objects=0;
int no_c_regen_mode = 0;
int no_c_redep_mode = 0;

char objvar_name[STR_LENGTH] = "OBJECTS";
char objdir_prefix[STR_LENGTH] = "";
char objdir_suffix[STR_LENGTH] = ".o";
char compile_command[STR_LENGTH] = "$(CC) $(CALLFLAGS)";
char output_option[STR_LENGTH] = "-o ";
char compile_option[STR_LENGTH] = "-c";
char cplus_command[STR_LENGTH] = "$(CXX) $(CXXALLFLAGS)";
char binary_config_name[STR_LENGTH] = "";

char *p_config = 0;

char incl_name[STR_LENGTH];
char incl_gen_name[STR_LENGTH];

char objname[STR_LENGTH];
char objbase[STR_LENGTH];
char objdir[STR_LENGTH];

char *objects = NULL;
char *cdeps_options = NULL;
char directive[STR_LENGTH];
char included_name[STR_LENGTH];

#define MAX_INCL 10
int  total_incl = 0;
char incl_dir[MAX_INCL][STR_LENGTH];

fqueue_t *qfirst = NULL;
fqueue_t **qlastp = &qfirst;
fqueue_t *qcur;

fqueue_t *qdir = NULL;

struct optlist *extra_options = NULL;

char *append_str(char *str_buf, char *str)
{
  if (str == NULL)
    return str_buf;
  if (str_buf == NULL)
    {
      str_buf = strdup(str);
      assert(str_buf != NULL);
      return str_buf;
    }

  str_buf = (char*) realloc(str_buf, strlen(str_buf) + strlen(str) + 1);
  assert(str_buf);
  strcat(str_buf, str);
  return str_buf;
}

char *strip_suffix(char *inbuf, char *outbuf, int maxlen)
{
  char *endpoint = strrchr(inbuf, '.');
  int  cpylen;

  if (endpoint == NULL) return NULL;
  cpylen = endpoint - inbuf;
  if (cpylen > maxlen - 1) cpylen = maxlen - 1;
  strncpy(outbuf, inbuf, cpylen);
  outbuf[cpylen] = 0;
  return endpoint;
}

void
get_directory(char *inbuf, char *outbuf, int maxlen)
{
  char *p;
  int   l;

  if (!(p = strrchr(inbuf, '/'))) {
    outbuf[0] = 0;
    return;
  } else if (p == inbuf) {
    outbuf[0] = '/';
    outbuf[1] = 0;
    return;
  }
  l = p - inbuf;
  if (l > maxlen - 1) l = maxlen - 1;
  strncpy(outbuf, inbuf, l);
  outbuf[l] = 0;
}

void
strip_directory(char *inbuf, char *outbuf, int maxlen)
{
  char *strippt;
  int   cpylen;

  strippt = strrchr(inbuf, '/');
  if (strippt == NULL)
    {
      cpylen = strlen(inbuf);
      strippt = inbuf;
    }
  else
    {
      strippt++;
      cpylen = strlen(strippt);
    }

  if (cpylen > maxlen - 1)
    cpylen = maxlen - 1;

  strncpy(outbuf, strippt, cpylen);
  outbuf[cpylen] = 0;
}

int add_if_unique(char *name)
{
  fqueue_t *qcur;

  assert(name != NULL);

  for (qcur = qfirst; qcur != NULL; qcur = qcur->next)
    {
      if (!strcmp(qcur->name, name))
        return 1;
    }
  *qlastp = qcur = (fqueue_t*) malloc(sizeof(fqueue_t));
  assert(qcur != NULL);
  qcur->next = NULL;
  qcur->name = strdup(name);
  assert(qcur->name != NULL);
  qlastp = &qcur->next;

  return 0;
}

fqueue_t *xadd_to_queue(fqueue_t *q, char *name)
{
  fqueue_t *p = q;

  for (p = q; p != NULL; p = p->next)
    {
      if (!strcmp(p->name, name))
        return q;
    }
  p = (fqueue_t*) malloc(sizeof(*p));
  assert(p != NULL);
  p->next = q;
  p->name = strdup(name);
  assert(p->name != NULL);
  return p;
}

fqueue_t *drop_fqueue(fqueue_t *q)
{
  fqueue_t *temp;

  while (q != NULL)
    {
      temp = q->next;
      free(q->name);
      free(q);
      q = temp;
    }

  return NULL;
}

  void
print_file_extra_options(struct optlist *p, FILE *f, char const *n)
{
  fqueue_t *q;

  for (; p; p = p->next) {
    for (q = p->files; q; q = q->next) {
      if (!strcmp(q->name, n)) {
        fprintf(f, " %s ", p->option);
      }
    }
  }
}

int skip_eol(FILE *f)
{
  int c;

  while ((c = getc(f)) != '\n' && c != EOF);
  c = getc(f);
  return c;
}

int parse_file(FILE *f)
{
  int c;
  int n;

  c = getc(f);
  while (c != EOF)
    {
      while (isspace(c))
        {
          c = getc(f);
        }
      if (c == '#')
        {
          n = fscanf(f, " %100[a-zA-Z_]", directive);
          if (n < 1)
            {
              c = skip_eol(f);
              continue;
            }

          if (!strcmp(directive, "include"))
            {
              for (c = getc(f); isspace(c); c = getc(f));

              if (c == '\"')
                {
                  n = fscanf(f, "%100[^\"]\" \n", incl_name);
                  if (n < 1)
                    {
                      c = skip_eol(f);
                      continue;
                    }
                }
              else if (c == 'C')
                {
                  char mname[16];
                  n = fscanf(f, "%11s", mname);
                  if (n < 1) {
                    c = skip_eol(f);
                    continue;
                  }
                  if (strcmp(mname, "ONF_GENFILE") &&
                      strcmp(mname, "ONF_DEPFILE")) {
                    c = skip_eol(f);
                    continue;
                  }
                  n = fscanf(f, "( \"%100[^\"]\" ) \n",
                             incl_gen_name);
                  if (n < 1)
                    {
                      c = skip_eol(f);
                      continue;
                    }
                  if (!strcmp(mname, "ONF_DEPFILE")) {
                    if (no_c_redep_mode) {
                      strcpy(incl_name, "dep/");
                      strcat(incl_name, incl_gen_name);
                    } else {
                      if (binary_config_name[0]) {
                        strcpy(incl_name, ".dep-");
                        strcat(incl_name, p_config);
                        strcat(incl_name, "/");
                        strcat(incl_name, incl_gen_name);
                      } else {
                        strcpy(incl_name, "d/");
                        strcat(incl_name, incl_gen_name);
                      }
                    }
                  } else {
                    if (no_c_regen_mode) {
                      strcpy(incl_name, "gen/");
                      strcat(incl_name, incl_gen_name);
                    } else {
                      if (binary_config_name[0])
                        {
                          strcpy(incl_name, ".gen-");
                          strcat(incl_name, p_config);
                          strcat(incl_name, "/");
                          strcat(incl_name, incl_gen_name);
                        }
                      else
                        {
                          strcpy(incl_name, "g/");
                          strcat(incl_name, incl_gen_name);
                        }
                    }
                  }
                }
              else
                {
                  c = skip_eol(f);
                  continue;
                }
            }
          else if (!strcmp(directive, "pragma"))
            {
              n = fscanf(f, " depend \"%100[^\"]s\" \n", incl_name);
              if (n < 1)
                {
                  c = skip_eol(f);
                  continue;
                }
            }
          else
            {
              c = skip_eol(f);
              continue;
            }

          if (n < 1)
            {
            }
        }
      else
        {
          c = skip_eol(f);
          continue;
        }
      add_if_unique(incl_name);
      c = getc(f);
    }
  return 0;
}

int process_file(char *name)
{
  char *suffix;
  /* fqueue_t *qelem; */
  FILE *f;
  char     *addstr;
  char     *lang_compile = 0;

  /* Strip away name suffix */
  suffix = strip_suffix(name, objname, STR_LENGTH);
  if (suffix == NULL)
    {
      fprintf(stderr, "File %s has empty suffix\n", name);
      return 1;
    }
  if (!strcmp(suffix, ".c"))
    {
      lang_compile = compile_command;
    }
  else if (!strcmp(suffix, ".C") || !strcmp(suffix, ".cc")
           || !strcmp(suffix, ".cpp"))
    {
      lang_compile = cplus_command;
    }
  else
    {
      fprintf(stderr, "File %s has invalid suffix %s\n",
              name, suffix);
      return 1;
    }

  if (!lang_compile) return 0;

  objects = append_str(objects, " ");
  if (!no_dir_in_objects) {
    objects = append_str(objects, objdir_prefix);
  }
  if (objdir_prefix[0] != 0)
    {
      if (use_object_subdirectories)
	{
	  int l;
	  
	  addstr = objname;
	  objdir[0] = 0;
	  strcpy(objdir, objdir_prefix);
	  l = strlen(objdir);
	  get_directory(objname, objdir + l, STR_LENGTH - l);
	  qdir = xadd_to_queue(qdir, objdir);
	}
      else
	{
	  strip_directory(objname, objbase, STR_LENGTH);
	  addstr = objbase;
	}
    }
  else
    {
      addstr = objname;
    }
  objects = append_str(objects, addstr);
  objects = append_str(objects, objdir_suffix);

  printf("%s%s%s :", objdir_prefix, addstr, objdir_suffix);

  add_if_unique(name);

  for (qcur = qfirst; qcur != NULL; qcur = qcur->next)
    {
      assert(qcur->name != NULL);
#if 0
      if (strrchr(qcur->name, '/') != NULL)
        {
          /* Not in the current directory, skip */
          continue;
        }
#endif
      f = fopen(qcur->name, "r");
      if (f == NULL)
        {
          int i;
          /* look through include directories */

          for (i = 0; i < total_incl; i++)
            {
              strcpy(included_name, incl_dir[i]);
              strcat(included_name, "/");
              strcat(included_name, qcur->name);
              if ((f = fopen(included_name, "r"))) break;
            }
          if (i >= total_incl) 
            {
              /* file not found */
              fprintf(stderr, "Warning: file '%s' not found\n",
                      qcur->name);
              continue;
            }

          free(qcur->name);
          qcur->name = strdup(included_name);
        }
      printf(" %s", qcur->name);
      parse_file(f);
      fclose(f);
    }
  
  qfirst = drop_fqueue(qfirst);
  qlastp = &qfirst;
  qcur = qfirst;

  printf("\n");
  if (use_compile_command)
    {
      if (use_object_subdirectories && objdir_prefix[0]) {
        printf("\t[ -d %s ] || mkdir -p %s\n", objdir, objdir);
      }
      printf("\t%s ", lang_compile);
      print_file_extra_options(extra_options, stdout, name);
      printf("%s %s%s%s%s %s\n",
	     compile_option,
	     output_option, objdir_prefix, addstr, objdir_suffix,
	     name);
    }

  return 0;
}

int main(int argc, char *argv[])
{
  int i;
  int j;
  time_t systime;
  struct optlist *new_extra;

  fprintf(stderr, "C/C++ dependencies generator, $Revision: 44 $\n");

  objects = append_str(objects, "");
  cdeps_options = append_str(cdeps_options, "");

  /* Parse command line options (which are described above) */
  for (i = 1; i < argc; i++)
    {
      if (!strcmp(argv[i], "-g"))
        {
          use_compile_command = 1;
        }
      else if (!strcmp(argv[i], "-D"))
        {
          use_object_subdirectories = 1;
        }
      else if (!strcmp(argv[i], "-h"))
        {
          print_banner = 0;
        }
      else if (!strcmp(argv[i], "-G0") || !strcmp(argv[i], "-G"))
        {
          no_c_regen_mode=0;
        }
      else if (!strcmp(argv[i], "-G1"))
        {
          no_c_regen_mode=1;
        }
      else if (!strcmp(argv[i], "-J0") || !strcmp(argv[i], "-J"))
        {
          no_c_redep_mode=0;
        }
      else if (!strcmp(argv[i], "-J1"))
        {
          no_c_redep_mode=1;
        }
      else if (!strcmp(argv[i], "-y"))
	{
	  no_dir_in_objects = 1;
	}
      else if (!strcmp(argv[i], "-x"))
	{
	  if (i >= argc - 1)
	    {
	      fprintf(stderr, "%s: Compile option expected\n", argv[0]);
	      exit(1);
	    }
	  strncpy(compile_option, argv[++i], STR_MAXUSE);
	  compile_option[STR_MAXUSE] = 0;
	}
      else if (!strcmp(argv[i], "-o"))
	{
	  if (i >= argc - 1)
	    {
	      fprintf(stderr, "%s: Output option expected\n", argv[0]);
	      exit(1);
	    }
	  strncpy(output_option, argv[++i], STR_MAXUSE);
	  output_option[STR_MAXUSE] = 0;
	}
      else if (!strcmp(argv[i], "-c"))
        {
          if (i >= argc - 1)
            {
              fprintf(stderr, "%s: Compile command expected\n", argv[0]);
              exit(1);
            }
          strncpy(compile_command, argv[++i], STR_MAXUSE);
          compile_command[STR_MAXUSE] = 0;
        }
      else if (!strcmp(argv[i], "-C"))
        {
          if (i >= argc - 1)
            {
              fprintf(stderr, "%s: C++ compile command expected\n", argv[0]);
              exit(1);
            }
          strncpy(cplus_command, argv[++i], STR_MAXUSE);
          cplus_command[STR_MAXUSE] = 0;
        }
      else if (!strcmp(argv[i], "-s"))
        {
          if (i >= argc - 1)
            {
              fprintf(stderr, "%s: Object file suffix expected\n", argv[0]);
              exit(1);
            }
          strncpy(objdir_suffix, argv[++i], STR_MAXUSE);
          objdir_suffix[STR_MAXUSE] = 0;
        }
      else if (!strcmp(argv[i], "-v"))
        {
          if (i >= argc - 1)
            {
              fprintf(stderr, "%s: Object variable name expected\n", argv[0]);
              exit(1);
            }
          strncpy(objvar_name, argv[++i], STR_MAXUSE);
          objvar_name[STR_MAXUSE] = 0;
        }
      else if (!strcmp(argv[i], "-d"))
        {
          if (i >= argc - 1)
            {
              fprintf(stderr, "%s: Object file directory expected\n",
                      argv[0]);
              exit(1);
            }
          strncpy(objdir_prefix, argv[++i], STR_MAXUSE);
          objdir_prefix[STR_MAXUSE] = 0;
        }
      else if (!strcmp(argv[i], "-I"))
        {
          if (i >= argc - 1)
            {
              fprintf(stderr, "%s: Include directory expected\n", argv[0]);
              exit(1);
            }
          if (total_incl >= MAX_INCL)
            {
              fprintf(stderr, "%s: Too many include directories\n", argv[0]);
              exit(1);
            }
          strcpy(incl_dir[total_incl++], argv[++i]);
        }
      else if (!strcmp(argv[i], "-c+"))
        {
          if (++i >= argc) {
            fprintf(stderr, "%s: Option expected\n", argv[0]);
            exit(1);
          }
          new_extra = (struct optlist*) calloc(1, sizeof(*new_extra));
          new_extra->next = extra_options;
          extra_options = new_extra;
          new_extra->option = strdup(argv[i++]);
          for (; i < argc && strcmp(argv[i], "--"); i++) {
            fqueue_t *q = (fqueue_t*) calloc(1, sizeof(*q));
            q->next = new_extra->files;
            q->name = strdup(argv[i]);
            new_extra->files = q;
          }
        }
      else if (!strcmp(argv[i], "-b"))
        {
          if (++i >= argc) {
            fprintf(stderr, "%s: Option expected\n", argv[0]);
            exit(1);
          }
          strncpy(binary_config_name, argv[++i], STR_MAXUSE);
          binary_config_name[STR_MAXUSE] = 0;
        }
      else
        {
          break;
        }
    }

  for (j = 1; j < i; j++)
    {
      cdeps_options = append_str(cdeps_options, " ");
      cdeps_options = append_str(cdeps_options, argv[j]);
    }

  /* Obtain current time */
  systime = time(NULL);

  /* Print the banner */
  if (print_banner)
    {
      printf("# C/C++ file dependencies\n"
             "# Automatically generated by %s, $Revision: 44 $\n"
             "# Generation date %s\n",
             argv[0],
             asctime(localtime(&systime)));
    }

  for (; i < argc; i++)
    {
      process_file(argv[i]);
    }

  printf("%s =%s\n", objvar_name, objects);

/*
  {
    fqueue_t *p;
    for (p = qdir; p; p = p->next) {
      printf("%s:\n\tmkdir -p %s\n", p->name, p->name);
    }
  }
*/

  return 0;
}

