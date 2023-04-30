/* -*- mode: c -*- */

/* Copyright (C) 2010-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/prepare.h"
#include "ejudge/common_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/compat.h"

#define EJUDGE_SKIP_MYSQL 1
#include "plugins/common-mysql/common_mysql.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static const unsigned char *program_name = "";
static const unsigned char *ejudge_xml_path = 0;
static unsigned char compile_cfg_path[PATH_MAX];

//static struct ejudge_cfg *config = 0;
static struct generic_section_config *cs_config;
static int cs_lang_total;
static struct section_language_data **cs_langs;

static const struct common_loaded_plugin *mysql_plugin;
static struct common_mysql_state *mysql_state;
static struct common_mysql_iface *mysql_iface;

static void
die(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
die(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", program_name, buf);
  exit(1);
}

static void
error(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
static void
error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: error: %s\n", program_name, buf);
}

static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: Ejudge database normalizer\n"
         "Usage: %s [OPTIONS]\n"
         "  OPTIONS:\n"
         "    --help    write this message and exit\n"
         "    --version report version and exit\n"
         "    -f CFG    specify the ejudge configuration file\n",
         program_name, program_name);
  exit(0);
}
static void write_version(void) __attribute__((noreturn));
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

struct textline
{
  int a, u;
  unsigned char *s;
};

struct textfile
{
  int a, u;
  struct textline *v;
};

static int
gettextline(FILE *in, struct textline *inf)
{
  int c;

  memset(inf, 0, sizeof(*inf));
  c = getc(in);
  if (c == EOF) return -1;
  while (c != EOF) {
    if (!inf->a) {
      inf->a = 16;
      inf->s = (unsigned char*) xmalloc(inf->a);
    } else if (inf->u + 1 >= inf->a) {
      inf->a *= 2;
      inf->s = (unsigned char*) xrealloc(inf->s, inf->a);
    }
    inf->s[inf->u++] = c;
    if (c == '\n') break;
    c = getc(in);
  }

  inf->s[inf->u] = 0;
  return inf->u;
}

static int
gettextfile(FILE *in, struct textfile *txt)
{
  struct textline buf;

  memset(txt, 0, sizeof(*txt));
  while (gettextline(in, &buf) >= 0) {
    if (!txt->a) {
      txt->a = 16;
      XCALLOC(txt->v, txt->a);
    } else if (txt->u >= txt->a) {
      txt->a *= 2;
      XREALLOC(txt->v, txt->a);
    }
    txt->v[txt->u++] = buf;
  }

  return txt->u;
}

static void
normalize_line(struct textline *inf)
{
  if (!inf || !inf->u) return;

  while (inf->u > 0 && isspace(inf->s[inf->u - 1])) {
    inf->u--;
  }
  inf->s[inf->u] = 0;
}

static void
normalize_text(struct textfile *txt)
{
  int i;

  if (!txt || !txt->u) return;

  for (i = 0; i < txt->u; ++i) {
    normalize_line(&txt->v[i]);
  }

  while (txt->u > 0 && !txt->v[txt->u - 1].u) {
    txt->u--;
  }
}

static void
puttext(FILE *out, struct textfile *txt)
{
  int i;

  if (!out || !txt) return;

  for (i = 0; i < txt->u; ++i) {
    fputs(txt->v[i].s, out);
    putc('\n', out);
  }
}

static void
handle_cs_config(void)
{
  struct generic_section_config *p;
  struct section_language_data *lang;
  int cur_lang = 1;
  int max_lang = 0;

  for (p = cs_config; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lang = (struct section_language_data*) p;
    if (lang->id < 0) {
      die("%s: language identifier is invalid", compile_cfg_path);
    }
    if (!lang->id) lang->id = cur_lang;
    cur_lang = lang->id + 1;
    if (lang->id > max_lang) max_lang = lang->id;
  }

  if (max_lang <= 0) {
    die("no languages defined");
  }

  cs_lang_total = max_lang + 1;
  XCALLOC(cs_langs, cs_lang_total);

  for (p = cs_config; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lang = (struct section_language_data*) p;
    if (cs_langs[lang->id]) {
      die("%s: duplicated language id %d", compile_cfg_path, lang->id);
    }
    cs_langs[lang->id] = lang;
  }
}

static void
load_mysql_plugin(void)
{
  if (!(mysql_plugin = plugin_load_external(0, "common", "mysql", ejudge_config))) {
    die("cannot load common_mysql plugin");
  }

  mysql_state = (struct common_mysql_state*) mysql_plugin->data;
  if (!mysql_state) {
    die("mysql plugin loading failed: mysql_state == NULL");
  }
  mysql_iface = (struct common_mysql_iface*) mysql_plugin->iface;
  if (!mysql_iface) {
    die("mysql plugin loading failed mysql_iface == NULL");
  }

  if (mysql_iface->connect(mysql_state) < 0) {
    die("cannot connect to MySQL");
  }
}

/*
  -1 - not a section
  0 - some section
  1 - [language] section
 */
static int
is_section(const unsigned char *str, int lineno)
{
  const unsigned char *s = str;
  const unsigned char *p = 0, *q = 0;
  unsigned char sectname[256];

  if (!str) return -1;
  while (*s && isspace(*s)) ++s;
  if (*s != '[') return -1;
  ++s;
  while (*s && isspace(*s)) ++s;
  if (!*s || !isalnum(*s)) return -1;
  p = s;
  while (*s && isalnum(*s)) ++s;
  q = s;
  if (!*s) return -1;
  while (*s && isspace(*s)) ++s;
  if (*s != ']') return -1;
  ++s;
  while (*s && isspace(*s)) ++s;
  if (*s && (*s != '#' || *s != ';')) return -1;
  if (q - p + 1 >= sizeof(sectname)) return -1;
  memcpy(sectname, p, q - p);
  sectname[q - p] = 0;
  //fprintf(stderr, "Section: %s at %d\n", sectname, lineno);
  return !strcmp(sectname, "language");
}

static int
is_id(const unsigned char *str, int lineno)
{
  const unsigned char *s = str;

  if (!str) return 0;
  while (*s && isspace(*s)) ++s;
  if (*s != 'i') return 0;
  ++s;
  if (*s != 'd') return 0;
  ++s;
  while (*s && isspace(*s)) ++s;
  if (*s != '=') return 0;
  return 1;
}

static int
is_short_name(
        const unsigned char *str,
        unsigned char *short_name_buf,
        int short_name_buf_len,
        int lineno)
{
  const unsigned char *s = str;
  const unsigned char *p;

  if (!str) return 0;
  while (*s && isspace(*s)) ++s;
  if (strncmp(s, "short_name", 10) != 0) return 0;
  s += 10;
  while (*s && isspace(*s)) ++s;
  if (*s != '=') return 0;
  ++s;
  while (*s && isspace(*s)) ++s;
  if (*s != '"') return 0;
  ++s;
  p = s;
  while (*s && *s != '"') ++s;
  snprintf(short_name_buf, short_name_buf_len, "%.*s", (int) (s - p), p);
  if (*s != '"') return 0;
  return 1;
}

static void
map_lang_aliases(unsigned char *buf, int len)
{
  if (!strcmp(buf, "java")) {
    snprintf(buf, len, "%s", "javac");
  } else if (!strcmp(buf, "scheme")) {
    snprintf(buf, len, "%s", "mzscheme");
  } else if (!strcmp(buf, "basic")) {
    snprintf(buf, len, "%s", "yabasic");
  } else if (!strcmp(buf, "g77")) {
    snprintf(buf, len, "%s", "gfortran");
  } else if (!strcmp(buf, "bc")) {
    snprintf(buf, len, "%s", "bcc");
  } else if (!strcmp(buf, "bc++")) {
    snprintf(buf, len, "%s", "bpp");
  }
}

static void
process_text(
        struct textfile *txt,
        int lang_count,
        int *lang_map,
        unsigned char **lang_shorts)
{
  int i;
  int lang_sect_lineno = -1;
  int lang_id_lineno = -1;
  int res;
  unsigned char short_name_buf[1024];
  int j, lineno;
  int *lang_id_linenos;
  unsigned char id_buf[1024];
  int id_buf_len;

  short_name_buf[0] = 0;
  XCALLOC(lang_id_linenos, lang_count);

  for (i = 0; i < txt->u; ++i) {
    res = is_section(txt->v[i].s, i + 1);
    if (res >= 0) {
      if (lang_sect_lineno > 0) {
        if (lang_id_lineno <= 0) {
          fprintf(stderr, "language section at line %d has no id\n", lang_sect_lineno);
          return;
        }
        if (!short_name_buf[0]) {
          fprintf(stderr, "language section at line %d has no short_name\n", lang_sect_lineno);
          return;
        }
      }
      for (j = 1; j < lang_count; ++j) {
        if (lang_shorts[j] && lang_map[j] > 0 && !strcmp(lang_shorts[j], short_name_buf))
          break;
      }
      if (j < lang_count)
        lang_id_linenos[j] = lang_id_lineno;
    }

    if (res == 1) {
      lang_sect_lineno = i + 1;
      lang_id_lineno = -1;
      short_name_buf[0] = 0;
    } else if (!res) {
      lang_sect_lineno = -1;
    }
    if (lang_sect_lineno > 0 && is_id(txt->v[i].s, i + 1)) {
      //fprintf(stderr, "id: %d\n", i + 1);
      lang_id_lineno = i + 1;
    }
    if (lang_sect_lineno > 0
        && is_short_name(txt->v[i].s, short_name_buf,
                         sizeof(short_name_buf), i + 1)) {
      //fprintf(stderr, "short_name: %s, %d\n", short_name_buf, i + 1);
      //map_lang_aliases(short_name_buf, sizeof(short_name_buf));
    }
  }

  if (lang_sect_lineno > 0) {
    if (lang_id_lineno <= 0) {
      fprintf(stderr, "language section at line %d has no id\n", lang_sect_lineno);
      return;
    }
    if (!short_name_buf[0]) {
      fprintf(stderr, "language section at line %d has no short_name\n", lang_sect_lineno);
      return;
    }
  }
  for (j = 1; j < lang_count; ++j) {
    if (lang_shorts[j] && lang_map[j] > 0 && !strcmp(lang_shorts[j], short_name_buf))
      break;
  }
  if (j < lang_count)
    lang_id_linenos[j] = lang_id_lineno;

  for (j = 1; j < lang_count; ++j) {
    if (lang_map[j] > 0 && lang_id_linenos[j] <= 0) {
      fprintf(stderr, "language %s lineno is not found\n", lang_shorts[j]);
      return;
    }
  }

  for (j = 1; j < lang_count; ++j) {
    if (lang_map[j] > 0) {
      lineno = lang_id_linenos[j] - 1;
      if (lineno < 0 || lineno >= txt->u) {
        die("invalid lineno %d", lineno);
      }
      snprintf(id_buf, sizeof(id_buf), "id = %d", lang_map[j]);
      id_buf_len = strlen(id_buf);
      txt->v[lineno].a = id_buf_len + 1;
      txt->v[lineno].u = id_buf_len;
      xfree(txt->v[lineno].s);
      txt->v[lineno].s = xstrdup(id_buf);
    }
  }
}

static void
process_db(int contest_id, int lang_count, int *lang_map)
{
  int lang_id;
  unsigned char qbuf[1024];
  int qlen;

  for (lang_id = 1; lang_id < lang_count; ++lang_id) {
    if (lang_map[lang_id] <= 0) continue;
    snprintf(qbuf, sizeof(qbuf), "UPDATE runs SET lang_id = %d WHERE lang_id = %d AND contest_id = %d", lang_id + 100, lang_id, contest_id);
    qlen = strlen(qbuf);
    //fprintf(stderr, "Query: %s\n", qbuf);
    if (mysql_iface->simple_query(mysql_state, qbuf, qlen) < 0) {
      die("MySQL request failed");
    }
  }

  for (lang_id = 1; lang_id < lang_count; ++lang_id) {
    if (lang_map[lang_id] <= 0) continue;
    snprintf(qbuf, sizeof(qbuf), "UPDATE runs SET lang_id = %d WHERE lang_id = %d AND contest_id = %d", lang_map[lang_id], lang_id + 100, contest_id);
    qlen = strlen(qbuf);
    //fprintf(stderr, "Query: %s\n", qbuf);
    if (mysql_iface->simple_query(mysql_state, qbuf, qlen) < 0) {
      die("MySQL request failed");
    }
  }
}

static int
process_contest(int contest_id)
{
  const struct contest_desc *cnts = 0;
  unsigned char config_path[PATH_MAX];
  unsigned char out_config_path[PATH_MAX];
  unsigned char old_config_path[PATH_MAX];
  const unsigned char *conf_dir = 0;
  struct stat stbuf;
  serve_state_t state = 0;
  struct section_global_data *global = 0;
  int lang_id;
  struct section_language_data *lang, *cs_lang_by_short, *cs_lang_by_id, *cs_lang;
  int compile_id;
  int i;
  int has_to_convert = 0, has_errors = 0;
  int *lang_map = 0;
  unsigned char **lang_shorts = 0;
  unsigned char short_name[1024];
  struct textfile config_text;
  FILE *config_file = NULL;
  FILE *out_config_file = NULL;
  unsigned char cmd_buf[PATH_MAX];

  memset(&config_text, 0, sizeof(config_text));

  fprintf(stderr, "Processing contest %d\n", contest_id);

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    error("cannot read contest XML for contest %d", contest_id);
    goto failure;
  }

  if (cnts->conf_dir && os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(config_path, sizeof(config_path), "%s/serve.cfg", cnts->conf_dir);
  } else {
    if (!cnts->root_dir) {
      error("contest %d root_dir is not set", contest_id);
      goto failure;
    } else if (!os_IsAbsolutePath(cnts->root_dir)) {
      error("contest %d root_dir %s is not absolute", contest_id, cnts->root_dir);
      goto failure;
    }
    if (!(conf_dir = cnts->conf_dir)) conf_dir = "conf";
    snprintf(config_path, sizeof(config_path),
             "%s/%s/serve.cfg", cnts->root_dir, conf_dir);
  }

  if (stat(config_path, &stbuf) < 0) {
    error("contest %d config file %s does not exist", contest_id, config_path);
    goto failure;
  }
  if (!S_ISREG(stbuf.st_mode)) {
    error("contest %d config file %s is not a regular file",
          contest_id, config_path);
    goto failure;
  }
  if (access(config_path, R_OK) < 0) {
    error("contest %d config file %s is not readable",
          contest_id, config_path);
    goto failure;
  }

  state = serve_state_init(contest_id);
  state->config_path = xstrdup(config_path);
  state->current_time = time(0);
  state->load_time = state->current_time;
  if (prepare(NULL, NULL, state, state->config_path, 0, PREPARE_SERVE, "", 1, 0, 0) < 0)
    goto failure;
  global = state->global;
  if (!global) {
    error("contest %d has no global section", contest_id);
    goto failure;
  }
  if (!global->rundb_plugin || strcmp(global->rundb_plugin, "mysql") != 0) {
    fprintf(stderr, "contest %d does not use mysql\n", contest_id);
    goto failure;
  }

  if (state->max_lang >= 0) {
    XCALLOC(lang_map, state->max_lang + 1);
    XCALLOC(lang_shorts, state->max_lang + 1);
  }

  for (lang_id = 1; lang_id <= state->max_lang; ++lang_id) {
    if (!(lang = state->langs[lang_id])) continue;
    compile_id = lang->compile_id;
    if (compile_id <= 0) compile_id = lang->id;

    if (lang->id > 1000) {
      fprintf(stderr, "  language %s id > 1000 (%d)\n",
              lang->short_name, lang->id);
      has_errors = 1;
      continue;
    }

    snprintf(short_name, sizeof(short_name), "%s", lang->short_name);
    map_lang_aliases(short_name, sizeof(short_name));

    /* search the language in the compilation server by short_name and by id */
    cs_lang_by_short = 0;
    cs_lang_by_id = 0;
    for (i = 1; i < cs_lang_total; ++i) {
      if ((cs_lang = cs_langs[i]) && cs_lang->id == compile_id) {
        cs_lang_by_id = cs_lang;
        break;
      }
    }
    for (i = 1; i < cs_lang_total; ++i) {
      if ((cs_lang = cs_langs[i]) && !strcmp(cs_lang->short_name, short_name)) {
        cs_lang_by_short = cs_lang;
        break;
      }
    }

    /*
      condition to convert:
        1) contest language id does not match to compilation server language id;
        2) contest language short name, compilation server language short name match.
     */
    if (lang->id != compile_id && cs_lang_by_short != NULL
        && cs_lang_by_short == cs_lang_by_id) {
      has_to_convert = 1;
      fprintf(stderr, "  language %s id %d to be changed to %d\n",
              lang->short_name, lang->id, compile_id);
      lang_map[lang_id] = compile_id;
      lang_shorts[lang_id] = xstrdup(lang->short_name);
    } else if (lang->id == compile_id && cs_lang_by_short != NULL
               && cs_lang_by_short == cs_lang_by_id) {
      /*
        condition to do nothing:
          1) contest language id match compilation server language id;
          2) contest language short name, compilation server language short name match.
      */
    } else {
      has_errors = 1;
      fprintf(stderr, "  unexpected language %s, id %d, compile id %d\n",
              lang->short_name, lang->id, lang->compile_id);
      if (cs_lang_by_id) {
        fprintf(stderr, "    CS lang by id: id %d, short %s\n",
                cs_lang_by_id->id, cs_lang_by_id->short_name);
      } else {
        fprintf(stderr, "    CS lang by id: NULL\n");
      }
      if (cs_lang_by_short) {
        fprintf(stderr, "    CS lang by short name: id %d, short %s\n",
                cs_lang_by_short->id, cs_lang_by_short->short_name);
      } else {
        fprintf(stderr, "    CS lang by short name: NULL\n");
      }
    }
  }

  if (has_errors) {
    fprintf(stderr, "contest %d cannot be converted\n", contest_id);
    return 0;
  }
  if (!has_to_convert) {
    fprintf(stderr, "contest %d is ok\n", contest_id);
    return 0;
  }

  config_file = fopen(config_path, "r");
  if (!config_file) {
    fprintf(stderr, "cannot open %s\n", config_path);
    return 0;
  }
  if (gettextfile(config_file, &config_text) <= 0) {
    fprintf(stderr, "configuration file %s is empty\n", config_path);
    return 0;
  }
  fclose(config_file); config_file = NULL;

  normalize_text(&config_text);

  process_text(&config_text, state->max_lang + 1,
               lang_map, lang_shorts);

  snprintf(out_config_path, sizeof(out_config_path),
           "%s.out", config_path);
  out_config_file = fopen(out_config_path, "w");
  if (!out_config_file) {
    fprintf(stderr, "cannot open %s\n", out_config_path);
    return 0;
  }
  puttext(out_config_file, &config_text);
  fclose(out_config_file); out_config_file = NULL;

  snprintf(cmd_buf, sizeof(cmd_buf), "diff -u %s %s",
           config_path, out_config_path);
  //fprintf(stderr, ">>%s\n", cmd_buf);
  __attribute__((unused)) int _;
  _ = system(cmd_buf);

  process_db(contest_id, state->max_lang + 1, lang_map);

  snprintf(old_config_path, sizeof(old_config_path),
           "%s.old", config_path);
  fprintf(stderr, "Rename: %s->%s, %s->%s\n", config_path, old_config_path,
          out_config_path, config_path);
  if (rename(config_path, old_config_path) < 0) {
    fprintf(stderr, "Rename: %s->%s failed\n", config_path, old_config_path);
  }
  if (rename(out_config_path, config_path) < 0) {
    fprintf(stderr, "Rename: %s->%s failed\n", out_config_path, config_path);
  }

  return 0;

 failure:
  return 1;
}

static int
process_all_contests(void)
{
  const int *contests_list = 0;
  int contest_count, i, res = 0;

  contest_count = contests_get_list(&contests_list);
  if (contest_count < 0) {
    die("cannot obtain the list of contests");
  }
  if (!contest_count) {
    printf("no contests\n");
    return 0;
  }

  for (i = 0; i < contest_count; ++i) {
    res |= process_contest(contests_list[i]);
  }

  return res;
}

int
main(int argc, char *argv[])
{
  program_name = os_GetBasename(argv[0]);
  logger_set_level(-1, LOG_WARNING);

  if (argc < 1) die("not enough parameters");

  if (argc == 2) {
    if (!strcmp(argv[1], "--help")) {
      write_help();
    } else if (!strcmp(argv[1], "--version")) {
      write_version();
    }
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) die("ejudge.xml path is not specified");
  if (!(ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 1))) return 1;
  if (!ejudge_config->contests_dir) die("<contests_dir> tag is not set!");
  if (contests_set_directory(ejudge_config->contests_dir) < 0)
    die("contests directory is invalid");

  load_mysql_plugin();

  /* consult the main compilation configuration */
  compile_cfg_path[0] = 0;
  if (ejudge_config->compile_home_dir) {
    snprintf(compile_cfg_path, sizeof(compile_cfg_path), "%s/conf/compile.cfg",
             ejudge_config->compile_home_dir);
  }
  if (!compile_cfg_path[0] && ejudge_config->contests_home_dir) {
    snprintf(compile_cfg_path, sizeof(compile_cfg_path), "%s/compile/conf/compile.cfg",
             ejudge_config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!compile_cfg_path[0]) {
    snprintf(compile_cfg_path, sizeof(compile_cfg_path), "%s/compile/conf/compile.cfg",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif

  cs_config = prepare_parse_config_file(compile_cfg_path, 0);
  if (!cs_config) {
    die("failed to parse compilation configuration file %s", compile_cfg_path);
  }
  handle_cs_config();

  process_all_contests();

  return 0;
}

/* force linking of certain functions that may be needed by plugins */
static void *forced_link_table[] __attribute__((unused));
static void *forced_link_table[] =
{
  xml_parse_ip,
  xml_parse_date,
  xml_parse_int,
  xml_parse_ip_mask,
  xml_parse_bool,
  xml_unparse_text,
  xml_unparse_bool,
  xml_unparse_ip,
  xml_unparse_date,
  xml_unparse_ip_mask,
  xml_err_get_elem_name,
  xml_err_get_attr_name,
  xml_err,
  xml_err_a,
  xml_err_attrs,
  xml_err_nested_elems,
  xml_err_attr_not_allowed,
  xml_err_elem_not_allowed,
  xml_err_elem_redefined,
  xml_err_top_level,
  xml_err_top_level_s,
  xml_err_attr_invalid,
  xml_err_elem_undefined,
  xml_err_elem_undefined_s,
  xml_err_attr_undefined,
  xml_err_attr_undefined_s,
  xml_err_elem_invalid,
  xml_err_elem_empty,
  xml_leaf_elem,
  xml_empty_text,
  xml_empty_text_c,
  xml_attr_bool,
  xml_attr_bool_byte,
  xml_attr_int,
  xml_attr_date,
  //xml_elem_ip_mask,
  close_memstream,
};
