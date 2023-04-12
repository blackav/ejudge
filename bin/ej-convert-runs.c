/* -*- mode: c -*- */

/* Copyright (C) 2008-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/runlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/compat.h"
#include "ejudge/base64.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

static const unsigned char *program_name = "";
static const unsigned char *ejudge_xml_path = 0;
static const unsigned char *src_plugin_name = 0;
static const unsigned char *dst_plugin_name = 0;

static int contest_id = 0;

static struct ejudge_cfg *config = 0;
static const struct contest_desc *cnts = 0;
static runlog_state_t src_runlog = 0;
static runlog_state_t dst_runlog = 0;

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

  fprintf(stderr, "%s: %s\n", program_name,
          buf);
  exit(1);
}

static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: run database converter\n"
         "Usage: %s [OPTIONS] CNTS-ID SRC-PLUGIN DST-PLUGIN\n"
         "  OPTIONS:\n"
         "    --help    write this message and exit\n"
         "    --version report version and exit\n"
         "    -f CFG    specify the ejudge configuration file\n"
         /*"  COMMAND:\n"*/
         /*"    status    report the new-server status\n"*/,
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

/* force linking of certain functions that may be needed by plugins */
void *forced_link_table[] =
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
  xml_attr_ulong,
  xml_attr_date,
  xml_do_parse_ipv6,
  xml_parse_ipv6_2,
  xml_parse_ipv6,
  xml_unparse_ipv6,
  ipv6cmp,
  ipv6_match_mask,
  xml_msg,
  xml_unparse_ipv6_mask,
  xml_parse_ipv6_mask,
  xml_elem_ipv6_mask,
  ipv6_is_empty,
  xml_unparse_full_cookie,
  xml_parse_full_cookie,
  base64u_decode,

  close_memstream,
};

int
main(int argc, char *argv[])
{
  int i = 1;
  char *eptr = 0;
  int total_runs, run_id;
  struct run_entry re;
  struct run_header rh;

  program_name = os_GetBasename(argv[0]);

  if (argc <= 1) die("not enough parameters");

  if (!strcmp(argv[1], "--help")) {
    write_help();
  } else if (!strcmp(argv[1], "--version")) {
    write_version();
  }

  i = 1;
  while (i < argc) {
    if (!strcmp(argv[i], "-f")) {
      if (i + 1 >= argc) die("argument expected for `-f'");
      ejudge_xml_path = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      die("invalid option `%s'", argv[i]);
    } else {
      break;
    }
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) die("ejudge.xml path is not specified");
  if (!(config = ejudge_cfg_parse(ejudge_xml_path, 1))) return 1;
  if (!config->contests_dir) die("<contests_dir> tag is not set!");
  if (contests_set_directory(config->contests_dir) < 0)
    die("contests directory is invalid");

  if (i >= argc) die("contest-id is expected");
  if (!argv[i][0]) die("contest-id is not specified");
  errno = 0;
  contest_id = strtol(argv[i], &eptr, 10);
  if (*eptr || errno || contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID)
    die("contest-id is invalid");
  i++;

  if (i >= argc) die("source plugin name is expected");
  src_plugin_name = argv[i];
  i++;

  if (i >= argc) die("destination plugin name is expected");
  dst_plugin_name = argv[i];
  i++;

  if (i < argc) die("extra parameters");
  if (!src_plugin_name || !*src_plugin_name) src_plugin_name = "file";
  if (!dst_plugin_name || !*dst_plugin_name) dst_plugin_name = "file";

  if (!strcmp(src_plugin_name, dst_plugin_name))
    die("plugins are the same");

  if (contests_get(contest_id, &cnts) < 0 || !cnts)
    die("cannot load contest %d", contest_id);

  if (!(src_runlog = run_init(0)))
    die("cannot open the source runlog");
  if (!(dst_runlog = run_init(0)))
    die("cannot open the destination runlog");

  if (run_open(src_runlog, config, cnts, 0, src_plugin_name,
               NULL, /* metrics */
               RUN_LOG_NOINDEX, 0, 0, 0) < 0)
    die("cannot open the source runlog");
  if (run_open(dst_runlog, config, cnts, 0, dst_plugin_name,
               NULL, /* metrics */
               0, 0, 0, 0) < 0)
    die("cannot open the destination runlog");

  run_get_header(src_runlog, &rh);
  if (run_put_header(dst_runlog, &rh) < 0)
    die("failed to insert the header");

  total_runs = run_get_total(src_runlog);
  for (run_id = 0; run_id < total_runs; run_id++) {
    if (run_get_entry(src_runlog, run_id, &re) < 0) continue;
    if (re.status == RUN_EMPTY) continue;
    if (run_put_entry(dst_runlog, &re) > 0)
      die("failed to insert entry %d", re.run_id);
  }
  return 0;
}
