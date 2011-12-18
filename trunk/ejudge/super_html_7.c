/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2011 Alexander Chernov <cher@ejudge.ru> */

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
#include "version.h"
#include "ej_limits.h"

#include "super-serve.h"
#include "super_proto.h"
#include "super_html.h"
#include "ejudge_cfg.h"
#include "contests.h"
#include "mischtml.h"
#include "xml_utils.h"
#include "serve_state.h"
#include "misctext.h"
#include "prepare.h"
#include "prepare_dflt.h"
#include "fileutl.h"
#include "testinfo.h"
#include "file_perms.h"
#include "ej_process.h"
#include "sformat.h"

#include "reuse_xalloc.h"
#include "reuse_osdeps.h"
#include "reuse_logger.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#define MAKE_PATH "/usr/bin/make"
#define SAVED_TEST_PREFIX      "s_"
#define TEMP_TEST_PREFIX       "t_"
#define DEL_TEST_PREFIX        "d_"
#define NEW_TEST_PREFIX        "n_"
#define MAX_ONLINE_EDITOR_SIZE (10*1024)

#define ARMOR(s)  html_armor_buf(&ab, (s))
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static unsigned char *
ss_url_unescaped(
        unsigned char *buf,
        size_t size,
        const struct super_http_request_info *phr,
        int action,
        int op,
        const char *format,
        ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  unsigned char obuf[64];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&action=%d", action);
  obuf[0] = 0;
  if (op > 0) snprintf(obuf, sizeof(obuf), "&op=%d", op);

  snprintf(buf, size, "%s?SID=%016llx%s%s%s%s", phr->self_url,
           phr->session_id, abuf, obuf, sep, fbuf);
  return buf;
}

static void
ss_redirect_2(
        FILE *fout,
        struct super_http_request_info *phr,
        int new_op,
        int contest_id,
        int prob_id,
        int variant,
        int test_num,
        const unsigned char *extra)
{
  unsigned char url[1024];
  char *o_str = 0;
  size_t o_len = 0;
  FILE *o_out = 0;

  o_out = open_memstream(&o_str, &o_len);
  if (contest_id > 0) {
    fprintf(o_out, "&contest_id=%d", contest_id);
  }
  if (prob_id > 0) {
    fprintf(o_out, "&prob_id=%d", prob_id);
  }
  if (variant > 0) {
    fprintf(o_out, "&variant=%d", variant);
  }
  if (test_num > 0) {
    fprintf(o_out, "&test_num=%d", test_num);
  }
  if (extra && extra[0]) {
    fprintf(o_out, "&%s", extra);
  }
  fclose(o_out); o_out = 0;

  if (o_str && *o_str) {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, "%s", o_str);
  } else {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, 0);
  }

  xfree(o_str); o_str = 0; o_len = 0;

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
}

void
super_html_7_force_link()
{
}

static int
get_full_caps(const struct super_http_request_info *phr, const struct contest_desc *cnts, opcap_t *pcap)
{
  opcap_t caps1 = 0, caps2 = 0;

  opcaps_find(&phr->config->capabilities, phr->login, &caps1);
  opcaps_find(&cnts->capabilities, phr->login, &caps2);
  *pcap = caps1 | caps2;
  return 0;
}



static int
check_other_editors(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr,
        int contest_id,
        const struct contest_desc *cnts)
{
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  const unsigned char *cl = " class=\"b0\"";
  time_t current_time = time(0);
  serve_state_t cs = NULL;
  struct stat stb;

  // check if this contest is already edited by anybody else
  const struct sid_state *other_session = super_serve_sid_state_get_cnts_editor(contest_id);

  if (other_session == phr->ss) {
    snprintf(buf, sizeof(buf), "serve-control: %s, the contest is being edited by you",
             phr->html_name);
    ss_write_html_header(out_f, phr, buf, 0, NULL);
    fprintf(out_f, "<h1>%s</h1>\n", buf);

    fprintf(out_f, "<ul>");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, NULL),
            "Main page");
    fprintf(out_f, "</ul>\n");

    fprintf(out_f, "<p>To edit the tests you should finish editing the contest settings.</p>\n");

    ss_write_html_footer(out_f);
    return 0;
  }

  if (other_session) {
    snprintf(buf, sizeof(buf), "serve-control: %s, the contest is being edited by someone else",
             phr->html_name);
    ss_write_html_header(out_f, phr, buf, 0, NULL);
    fprintf(out_f, "<h1>%s</h1>\n", buf);

    fprintf(out_f, "<ul>");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, NULL),
            "Main page");
    fprintf(out_f, "</ul>\n");

    fprintf(out_f, "<p>This contest is being edited by another user or in another session.</p>");
    fprintf(out_f, "<table%s><tr><td%s>%s</td><td%s>%016llx</td></tr>",
            cl, cl, "Session", cl, other_session->sid);
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr>",
            cl, "IP address", cl, xml_unparse_ip(other_session->remote_addr));
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr></table>\n",
            cl, "User login", cl, other_session->user_login);
    ss_write_html_footer(out_f);
    return 0;
  }

  other_session = super_serve_sid_state_get_test_editor(contest_id);
  if (other_session && other_session != phr->ss) {
    snprintf(buf, sizeof(buf), "serve-control: %s, the tests are being edited by someone else",
             phr->html_name);
    ss_write_html_header(out_f, phr, buf, 0, NULL);
    fprintf(out_f, "<h1>%s</h1>\n", buf);

    fprintf(out_f, "<ul>");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, NULL),
            "Main page");
    fprintf(out_f, "</ul>\n");

    fprintf(out_f, "<p>This tests are being edited by another user or in another session.</p>");
    fprintf(out_f, "<table%s><tr><td%s>%s</td><td%s>%016llx</td></tr>",
            cl, cl, "Session", cl, other_session->sid);
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr>",
            cl, "IP address", cl, xml_unparse_ip(other_session->remote_addr));
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr></table>\n",
            cl, "User login", cl, other_session->user_login);
    ss_write_html_footer(out_f);
    return 0;
  }

  if ((cs = phr->ss->te_state) && cs->last_timestamp > 0 && cs->last_check_time + 10 >= current_time) {
    return 1;
  }

  if (cs && cs->last_timestamp > 0) {
    if (!cs->config_path) goto invalid_serve_cfg;
    if (stat(cs->config_path, &stb) < 0) goto invalid_serve_cfg;
    if (!S_ISREG(stb.st_mode)) goto invalid_serve_cfg;
    if (stb.st_mtime == cs->last_timestamp) {
      cs->last_check_time = current_time;
      return 1;
    }
  }

  phr->ss->te_state = serve_state_destroy(phr->config, cs, cnts, NULL);

  if (serve_state_load_contest_config(phr->config, contest_id, cnts, &phr->ss->te_state) < 0)
    goto invalid_serve_cfg;

  cs = phr->ss->te_state;
  if (!cs) goto invalid_serve_cfg;
  if (!cs->config_path) goto invalid_serve_cfg;
  if (stat(cs->config_path, &stb) < 0) goto invalid_serve_cfg;
  if (!S_ISREG(stb.st_mode)) goto invalid_serve_cfg;
  cs->last_timestamp = stb.st_mtime;
  cs->last_check_time = current_time;

  return 1;

invalid_serve_cfg:
  phr->ss->te_state = serve_state_destroy(phr->config, cs, cnts, NULL);
  return -S_ERR_INV_SERVE_CONFIG_PATH;
}

int
super_serve_op_TESTS_MAIN_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  path_t adv_path;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl, *s;
  int prob_id, variant;
  serve_state_t cs;
  const struct section_problem_data *prob;
  int need_variant = 0;
  int need_statement = 0;
  int need_style_checker = 0;
  int need_valuer = 0;
  int need_interactor = 0;
  int need_test_checker = 0;
  int need_makefile = 0;
  int need_header = 0;
  int need_footer = 0;
  int need_solution = 0;
  int variant_num = 0;

  FILE *prb_f = NULL;
  char *prb_t = NULL;
  size_t prb_z = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;

  for (prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    if (!(prob = cs->probs[prob_id])) continue;
    if (prob->variant_num > 0) need_variant = 1;
    if (prob->xml_file && prob->xml_file[0]) need_statement = 1;
    if (prob->style_checker_cmd && prob->style_checker_cmd[0]) need_style_checker = 1;
    if (prob->valuer_cmd && prob->valuer_cmd[0]) need_valuer = 1;
    if (prob->interactor_cmd && prob->interactor_cmd[0]) need_interactor = 1;
    if (prob->test_checker_cmd && prob->test_checker_cmd[0]) need_test_checker = 1;
    if (prob->source_header && prob->source_header[0]) need_header = 1;
    if (prob->source_footer && prob->source_footer[0]) need_footer = 1;
    if (prob->solution_src && prob->solution_src[0]) need_solution = 1;
  }
  if (cs->global->advanced_layout > 0) need_makefile = 1;

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s)",
           phr->html_name, contest_id, ARMOR(cnts->name));
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "</ul>\n");

  fprintf(out_f, "<h2>%s</h2>\n", "Problems");

  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>", cl);
  fprintf(out_f,
          "<tr>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>",
          cl, "Prob. ID", cl, "Short name", cl, "Long name", cl, "Int. name", cl, "Type", cl, "Config");
  if (need_variant > 0) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Variant");
  }
  if (need_statement > 0) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Statement");
  }
  if (need_header > 0) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Source header");
  }
  if (need_footer > 0) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Source footer");
  }
  if (need_solution > 0) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Solution");
  }  
  if (need_style_checker > 0) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Style checker");
  }
  fprintf(out_f, "<th%s>%s</th>", cl, "Tests");
  fprintf(out_f, "<th%s>%s</th>", cl, "Checker");
  if (need_valuer) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Valuer");
  }
  if (need_interactor) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Interactor");
  }
  if (need_test_checker) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Test checker");
  }
  if (need_makefile) {
    fprintf(out_f, "<th%s>%s</th>", cl, "Makefile");
  }
  fprintf(out_f, "</tr>\n");
  for (prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    if (!(prob = cs->probs[prob_id])) continue;

    variant_num = prob->variant_num;
    if (variant_num < 0) variant_num = 0;
    variant = 0;
    if (prob->variant_num > 0) variant = 1;
    do {
      fprintf(out_f, "<tr>");
      if (variant <= 1) {
        prb_f = open_memstream(&prb_t, &prb_z);
        prepare_unparse_actual_prob(prb_f, prob, cs->global, 0);
        fclose(prb_f); prb_f = NULL;

        fprintf(out_f, "<td%s>%d</td>", cl, prob_id);
        fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(prob->short_name));
        fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(prob->long_name));
        s = prob->short_name;
        if (prob->internal_name[0]) {
          s = prob->internal_name;
        }
        fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(s));
        fprintf(out_f, "<td%s>%s</td>", cl, problem_unparse_type(prob->type));
        fprintf(out_f, "<td%s><div style=\"width: 200px; height: 200px; overflow: auto;\"><pre>%s</pre></div></td>", cl, ARMOR(prb_t));
        free(prb_t); prb_t = NULL; prb_z = 0;
      } else {
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
      }

      // variant
      if (need_variant) {
        if (prob->variant_num <= 0) {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        } else {
          fprintf(out_f, "<td%s>%d</td>", cl, variant);
        }
      }
      // statement
      if (need_statement) {
        if (prob->xml_file && prob->xml_file[0]) {
          if (cs->global->advanced_layout > 0) {
            get_advanced_layout_path(adv_path, sizeof(adv_path), cs->global,
                                     prob, prob->xml_file, variant);
          } else if (variant > 0) {
            prepare_insert_variant_num(adv_path, sizeof(adv_path), prob->xml_file, variant);
          } else {
            snprintf(adv_path, sizeof(adv_path), "%s", prob->xml_file);
          }
          fprintf(out_f, "<td title=\"%s\"%s>%s%s</a></td>",
                  ARMOR(adv_path), cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_STATEMENT_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }

      // source header
      if (need_header) {
        if (prob->source_header && prob->source_header[0]) {
          fprintf(out_f, "<td title=\"%s\"%s>%s%s</a></td>",
                  ARMOR(prob->source_header), cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_SOURCE_HEADER_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }

      // source footer
      if (need_footer) {
        if (prob->source_footer && prob->source_footer[0]) {
          fprintf(out_f, "<td title=\"%s\"%s>%s%s</a></td>",
                  ARMOR(prob->source_footer), cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_SOURCE_FOOTER_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }

      // solution
      if (need_solution) {
        if (prob->solution_src && prob->solution_src[0]) {
          fprintf(out_f, "<td title=\"%s\"%s>%s%s</a></td>",
                  ARMOR(prob->solution_src), cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_SOLUTION_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }

      // style checker
      if (need_style_checker) {
        if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
          fprintf(out_f, "<td%s>%s%s</a></td>",
                  cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_STYLE_CHECKER_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }

      // tests
      if (cs->global->advanced_layout > 0) {
        get_advanced_layout_path(adv_path, sizeof(adv_path), cs->global,
                                 prob, DFLT_P_TEST_DIR, variant);
      } else if (variant > 0) {
        snprintf(adv_path, sizeof(adv_path), "%s-%d", prob->test_dir, variant);
      } else {
        snprintf(adv_path, sizeof(adv_path), "%s", prob->test_dir);
      }
      fprintf(out_f, "<td title=\"%s\"%s>%s%s</a></td>",
              ARMOR(adv_path), cl, 
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_TESTS_VIEW_PAGE,
                            contest_id, variant, prob_id),
              "View");

      // checker
      if (prob->standard_checker && prob->standard_checker[0]) {
        s = super_html_get_standard_checker_description(prob->standard_checker);
        if (!s) s = "???";
        fprintf(out_f, "<td title=\"%s\"%s>", ARMOR(s), cl);
        fprintf(out_f, "<tt>%s</tt></td>", ARMOR(prob->standard_checker));
      } else if (prob->check_cmd && prob->check_cmd[0]) {
        fprintf(out_f, "<td%s>%s%s</a></td>",
                cl, 
                html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                              NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                              SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_CHECKER_EDIT_PAGE,
                              contest_id, variant, prob_id),
                "Edit");
      } else {
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
      }
      // valuer
      if (need_valuer) {
        if (prob->valuer_cmd && prob->valuer_cmd[0]) {
          fprintf(out_f, "<td%s>%s%s</a></td>",
                  cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_VALUER_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }
      // interactor
      if (need_interactor) {
        if (prob->interactor_cmd && prob->interactor_cmd[0]) {
          fprintf(out_f, "<td%s>%s%s</a></td>",
                  cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_INTERACTOR_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }
      // test checker
      if (need_test_checker) {
        if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
          fprintf(out_f, "<td%s>%s%s</a></td>",
                  cl, 
                  html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_TEST_CHECKER_EDIT_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }
      if (need_makefile) {
        fprintf(out_f, "<td%s>", cl);
        fprintf(out_f, "%s%s</a>",
                html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                              NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                              SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_MAKEFILE_EDIT_PAGE,
                              contest_id, variant, prob_id),
                "Edit");
        fprintf(out_f, "<br/>%s%s</a>",
                html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                              NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                              SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_MAKE,
                              contest_id, variant, prob_id),
                "Run");
        fprintf(out_f, "</td>");
      }
      fprintf(out_f, "</tr>");
    } while (++variant <= prob->variant_num);
  }
  fprintf(out_f, "</table>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

static void
write_problem_editing_links(
        FILE *out_f,
        struct super_http_request_info *phr,
        int contest_id,
        int prob_id,
        int variant,
        const struct section_global_data *global,
        const struct section_problem_data *prob)
{
  unsigned char hbuf[1024];

  fprintf(out_f, "<ul>");
  if (prob->xml_file && prob->xml_file[0]) {
    fprintf(out_f, "<li>%s%s</a></li>\n",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&op=%d&contest_id=%d&prob_id=%d&variant=%d&plain_view=1", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_STATEMENT_EDIT_PAGE, contest_id, prob_id, variant),
            "Edit the statement as a text file");
    fprintf(out_f, "<li>%s%s</a></li>\n",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&op=%d&contest_id=%d&prob_id=%d&variant=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_STATEMENT_EDIT_PAGE, contest_id, prob_id, variant),
            "Edit the statement by sections");
  }
  if (prob->source_header && prob->source_header[0]) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_SOURCE_HEADER_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit source header");
  }
  if (prob->source_footer && prob->source_footer[0]) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_SOURCE_FOOTER_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit source footer");
  }
  if (prob->solution_src && prob->solution_src[0]) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_SOLUTION_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit solution");
  }
  if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_STYLE_CHECKER_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit style checker");
  }
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d&prob_id=%d&variant=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant),
          "View tests");
  if (!(prob->standard_checker && prob->standard_checker[0])
      && (prob->check_cmd && prob->check_cmd[0])) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_CHECKER_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit checker");
  }
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    fprintf(out_f, "<li>%s%s</a><li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_VALUER_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit valuer");
  }
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_INTERACTOR_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit interactor");
  }
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    fprintf(out_f, "<li>%s%s</a><li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_TEST_CHECKER_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit test checker");
  }
  if (global->advanced_layout > 0) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_MAKEFILE_EDIT_PAGE,
                          contest_id, variant, prob_id),
            "Edit Makefile");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_MAKE,
                          contest_id, variant, prob_id),
            "Run make");
  }
  fprintf(out_f, "</ul>\n");
}



// file classification
enum
{
  TESTS_TEST_FILE = 1,
  TESTS_CORR_FILE = 2,
  TESTS_INFO_FILE = 3,
  TESTS_TGZ_FILE = 4,
  TESTS_TGZDIR_FILE = 5,
  TESTS_SAVED_TEST_FILE = 6,
  TESTS_SAVED_CORR_FILE = 7,
  TESTS_SAVED_INFO_FILE = 8,
  TESTS_SAVED_TGZ_FILE = 9,
  TESTS_SAVED_TGZDIR_FILE = 10,
  TESTS_README_FILE = 11,
};

struct test_file_info
{
  unsigned char *name;
  int mode;
  int user;
  int group;
  long long size;
  time_t mtime;
  int use;
  int use_idx;
};
struct test_info
{
  int test_idx;
  int corr_idx;
  int info_idx;
  int tgz_idx;
  int tgzdir_idx;
};
struct test_dir_info
{
  int u, a;
  struct test_file_info *v;
  int test_ref_count;
  struct test_info *test_refs;
  int saved_ref_count;
  struct test_info *saved_refs;
  int readme_idx;
};

static void
test_dir_info_free(struct test_dir_info *ptd)
{
  int i;

  if (!ptd) return;

  xfree(ptd->test_refs);
  xfree(ptd->saved_refs);
  for (i = 0; i < ptd->u; ++i) {
    xfree(ptd->v[i].name);
  }
  xfree(ptd->v);
  memset(ptd, 0, sizeof(*ptd));
}

static int
files_sort_func(const void *vp1, const void *vp2)
{
  const struct test_file_info *i1 = (const struct test_file_info *) vp1;
  const struct test_file_info *i2 = (const struct test_file_info *) vp2;
  return strcmp(i1->name, i2->name);
}

static int
scan_test_directory(
        FILE *log_f,
        struct test_dir_info *files,
        const struct contest_desc *cnts,
        const unsigned char *test_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        const unsigned char *info_pat,
        const unsigned char *tgz_pat,
        const unsigned char *tgzdir_pat)
{
  struct stat stb;
  DIR *d = NULL;
  struct dirent *dd = NULL;
  int retval = 0;
  unsigned char fullpath[PATH_MAX];
  unsigned char name[PATH_MAX];
  unsigned char saved_pat[PATH_MAX];
  int new_a = 0;
  struct test_file_info *new_v = NULL;
  int test_count, corr_count, info_count, common_count, low, high, mid, v, i;
  int tgz_count, tgzdir_count;

  if (stat(test_dir, &stb) < 0) {
    if (os_MakeDirPath2(test_dir, cnts->dir_mode, cnts->dir_group) < 0) {
      fprintf(log_f, "failed to created test directory '%s'\n", test_dir);
      FAIL(S_ERR_INV_CNTS_SETTINGS);
    }
  }
  if (stat(test_dir, &stb) < 0) {
    fprintf(log_f, "test directory does not exist and cannot be created\n");
    FAIL(S_ERR_INV_CNTS_SETTINGS);
  }
  if (!S_ISDIR(stb.st_mode)) {
    fprintf(log_f, "test directory is not a directory\n");
    FAIL(S_ERR_INV_CNTS_SETTINGS);
  }
  if (access(test_dir, R_OK | X_OK) < 0) {
    fprintf(log_f, "test directory is not readable\n");
    FAIL(S_ERR_INV_CNTS_SETTINGS);
  }

  if (!(d = opendir(test_dir))) {
    fprintf(log_f, "test directory cannot be opened\n");
    FAIL(S_ERR_INV_CNTS_SETTINGS);
  }
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    snprintf(fullpath, sizeof(fullpath), "%s/%s", test_dir, dd->d_name);
    if (stat(fullpath, &stb) < 0) continue;
    if (access(fullpath, R_OK) < 0) continue;

    if (files->u >= files->a) {
      if (!(new_a = files->a * 2)) new_a= 32;
      XCALLOC(new_v, new_a);
      if (files->u > 0) {
        memcpy(new_v, files->v, files->u * sizeof(new_v[0]));
      }
      xfree(files->v);
      files->v = new_v;
      files->a = new_a;
    }
    files->v[files->u].name = xstrdup(dd->d_name);
    files->v[files->u].mode = stb.st_mode & 07777;
    files->v[files->u].user = stb.st_uid;
    files->v[files->u].group = stb.st_gid;
    files->v[files->u].size = stb.st_size;
    files->v[files->u].mtime = stb.st_mtime;
    ++files->u;
  }
  closedir(d); d = NULL;

  qsort(files->v, files->u, sizeof(files->v[0]), files_sort_func);

  // detect how many test files
  test_count = 0;
  do {
    ++test_count;
    snprintf(name, sizeof(name), test_pat, test_count);
    low = 0; high = files->u;
    while (low < high) {
      mid = (low + high) / 2;
      if (!(v = strcmp(files->v[mid].name, name))) break;
      if (v < 0) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
  } while (low < high);
  --test_count;

  // detect how many answer files
  corr_count = 0;
  if (corr_pat && corr_pat[0]) {
    do {
      ++corr_count;
      snprintf(name, sizeof(name), corr_pat, corr_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --corr_count;
  }

  // detect how many info files
  info_count = 0;
  if (info_pat && info_pat[0]) {
    do {
      ++info_count;
      snprintf(name, sizeof(name), info_pat, info_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --info_count;
  }

  // detect how many tgz files
  tgz_count = 0;
  if (tgz_pat && tgz_pat[0]) {
    do {
      ++tgz_count;
      snprintf(name, sizeof(name), tgz_pat, tgz_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --tgz_count;
  }

  // detect how many tgzdir files
  tgzdir_count = 0;
  if (tgzdir_pat && tgzdir_pat[0]) {
    do {
      ++tgzdir_count;
      snprintf(name, sizeof(name), tgzdir_pat, tgzdir_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --tgzdir_count;
  }

  common_count = test_count;
  if (corr_count > common_count) common_count = corr_count;
  if (info_count > common_count) common_count = info_count;
  if (tgz_count > common_count) common_count = tgz_count;
  if (tgzdir_count > common_count) common_count = tgzdir_count;
  if (common_count > 0) {
    files->test_ref_count = common_count;
    XCALLOC(files->test_refs, common_count);
    for (i = 0; i < common_count; ++i) {
      files->test_refs[i].test_idx = -1;
      files->test_refs[i].corr_idx = -1;
      files->test_refs[i].info_idx = -1;
      files->test_refs[i].tgz_idx = -1;
      files->test_refs[i].tgzdir_idx = -1;
    }
  }

  // scan for saved files
  test_count = 0;
  snprintf(saved_pat, sizeof(saved_pat), "%s%s", SAVED_TEST_PREFIX, test_pat);
  do {
    ++test_count;
    snprintf(name, sizeof(name), saved_pat, test_count);
    low = 0; high = files->u;
    while (low < high) {
      mid = (low + high) / 2;
      if (!(v = strcmp(files->v[mid].name, name))) break;
      if (v < 0) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }    
  } while (low < high);
  --test_count;

  corr_count = 0;
  if (corr_pat && corr_pat[0]) {
    snprintf(saved_pat, sizeof(saved_pat), "%s%s", SAVED_TEST_PREFIX, corr_pat);
    do {
      ++corr_count;
      snprintf(name, sizeof(name), saved_pat, corr_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --corr_count;
  }

  info_count = 0;
  if (info_pat && info_pat[0]) {
    snprintf(saved_pat, sizeof(saved_pat), "%s%s", SAVED_TEST_PREFIX, info_pat);
    do {
      ++info_count;
      snprintf(name, sizeof(name), saved_pat, info_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --info_count;
  }

  tgz_count = 0;
  if (tgz_pat && tgz_pat[0]) {
    snprintf(saved_pat, sizeof(saved_pat), "%s%s", SAVED_TEST_PREFIX, tgz_pat);
    do {
      ++tgz_count;
      snprintf(name, sizeof(name), saved_pat, tgz_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --tgz_count;
  }

  tgzdir_count = 0;
  if (tgzdir_pat && tgzdir_pat[0]) {
    snprintf(saved_pat, sizeof(saved_pat), "%s%s", SAVED_TEST_PREFIX, tgzdir_pat);
    do {
      ++tgzdir_count;
      snprintf(name, sizeof(name), saved_pat, tgzdir_count);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
    } while (low < high);
    --tgzdir_count;
  }

  common_count = test_count;
  if (corr_count > common_count) common_count = corr_count;
  if (info_count > common_count) common_count = info_count;
  if (tgz_count > common_count) common_count = tgz_count;
  if (tgzdir_count > common_count) common_count = tgzdir_count;
  if (common_count > 0) {
    files->saved_ref_count = common_count;
    XCALLOC(files->saved_refs, common_count);
    for (i = 0; i < common_count; ++i) {
      files->saved_refs[i].test_idx = -1;
      files->saved_refs[i].corr_idx = -1;
      files->saved_refs[i].info_idx = -1;
      files->saved_refs[i].tgz_idx = -1;
      files->saved_refs[i].tgzdir_idx = -1;
    }
  }

  // sort out the files
  for (i = 1; i <= files->test_ref_count; ++i) {
    snprintf(name, sizeof(name), test_pat, i);
    low = 0; high = files->u;
    while (low < high) {
      mid = (low + high) / 2;
      if (!(v = strcmp(files->v[mid].name, name))) break;
      if (v < 0) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    if (low < high) {
      files->test_refs[i - 1].test_idx = mid;
      files->v[mid].use = TESTS_TEST_FILE;
      files->v[mid].use_idx = i;
    }
    if (corr_pat && corr_pat[0]) {
      snprintf(name, sizeof(name), corr_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->test_refs[i - 1].corr_idx = mid;
        files->v[mid].use = TESTS_CORR_FILE;
        files->v[mid].use_idx = i;
      }
    }
    if (info_pat && info_pat[0]) {
      snprintf(name, sizeof(name), info_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->test_refs[i - 1].info_idx = mid;
        files->v[mid].use = TESTS_INFO_FILE;
        files->v[mid].use_idx = i;
      }
    }
    if (tgz_pat && tgz_pat[0]) {
      snprintf(name, sizeof(name), tgz_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->test_refs[i - 1].tgz_idx = mid;
        files->v[mid].use = TESTS_TGZ_FILE;
        files->v[mid].use_idx = i;
      }
    }
    if (tgzdir_pat && tgzdir_pat[0]) {
      snprintf(name, sizeof(name), tgzdir_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->test_refs[i - 1].tgzdir_idx = mid;
        files->v[mid].use = TESTS_TGZDIR_FILE;
        files->v[mid].use_idx = i;
      }
    }
  }

  for (i = 1; i <= files->saved_ref_count; ++i) {
    snprintf(saved_pat, sizeof(saved_pat), "s_%s", test_pat);
    snprintf(name, sizeof(name), saved_pat, i);
    low = 0; high = files->u;
    while (low < high) {
      mid = (low + high) / 2;
      if (!(v = strcmp(files->v[mid].name, name))) break;
      if (v < 0) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    if (low < high) {
      files->saved_refs[i - 1].test_idx = mid;
      files->v[mid].use = TESTS_SAVED_TEST_FILE;
      files->v[mid].use_idx = i;
    }
    if (corr_pat && corr_pat[0]) {
      snprintf(saved_pat, sizeof(saved_pat), "s_%s", corr_pat);
      snprintf(name, sizeof(name), saved_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->saved_refs[i - 1].corr_idx = mid;
        files->v[mid].use = TESTS_SAVED_CORR_FILE;
        files->v[mid].use_idx = i;
      }
    }
    if (info_pat && info_pat[0]) {
      snprintf(saved_pat, sizeof(saved_pat), "s_%s", info_pat);
      snprintf(name, sizeof(name), saved_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->saved_refs[i - 1].info_idx = mid;
        files->v[mid].use = TESTS_SAVED_INFO_FILE;
        files->v[mid].use_idx = i;
      }
    }
    if (tgz_pat && tgz_pat[0]) {
      snprintf(saved_pat, sizeof(saved_pat), "s_%s", tgz_pat);
      snprintf(name, sizeof(name), saved_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->saved_refs[i - 1].tgz_idx = mid;
        files->v[mid].use = TESTS_SAVED_TGZ_FILE;
        files->v[mid].use_idx = i;
      }
    }
    if (tgzdir_pat && tgzdir_pat[0]) {
      snprintf(saved_pat, sizeof(saved_pat), "s_%s", tgzdir_pat);
      snprintf(name, sizeof(name), saved_pat, i);
      low = 0; high = files->u;
      while (low < high) {
        mid = (low + high) / 2;
        if (!(v = strcmp(files->v[mid].name, name))) break;
        if (v < 0) {
          low = mid + 1;
        } else {
          high = mid;
        }
      }
      if (low < high) {
        files->saved_refs[i - 1].tgzdir_idx = mid;
        files->v[mid].use = TESTS_SAVED_TGZDIR_FILE;
        files->v[mid].use_idx = i;
      }
    }
  }

  // scan for README
  files->readme_idx = -1;
  snprintf(name, sizeof(name), "README");
  low = 0; high = files->u;
  while (low < high) {
    mid = (low + high) / 2;
    if (!(v = strcmp(files->v[mid].name, name))) break;
    if (v < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  if (low < high) {
    files->readme_idx = mid;
    files->v[mid].use = TESTS_README_FILE;
  }

cleanup:
  if (d) closedir(d);
  return retval;
}

static int
is_text_file(const unsigned char *txt, size_t size)
{
  size_t i;

  if (!txt) return 0;
  for (i = 0; i < size; ++i) {
    if (txt[i] == 0177) return 0;
    if (txt[i] < ' ' && !isspace(txt[i])) return 0;
  }
  return 1;
}

static void
output_text_file(FILE *out_f, const unsigned char *txt, size_t size)
{
  enum { MAX_LINE_COUNT = 10, MAX_COLUMN_COUNT = 40 };
  size_t i;
  int column_count = 0;
  int line_count = 0;

  // show no more than 10 lines with no more than 40 characters in line
  fprintf(out_f, "<br/><hr/><pre>");
  for (i = 0; i < size; ++i) {
    if (line_count >= MAX_LINE_COUNT) {
      fprintf(out_f, "<i>...</i>\n");
      break;
    }
    if (column_count >= MAX_COLUMN_COUNT && txt[i] != '\n') {
      fprintf(out_f, "<i>...</i>\n");
      for (; i < size && txt[i] != '\n'; ++i) {}
      column_count = 0;
      ++line_count;
      continue;
    }
    switch (txt[i]) {
    case '<':
      fprintf(out_f, "&lt;");
      ++column_count;
      break;
    case '>':
      fprintf(out_f, "&gt;");
      ++column_count;
      break;
    case '&':
      fprintf(out_f, "&amp;");
      ++column_count;
      break;
    case '"':
      fprintf(out_f, "&quot;");
      ++column_count;
      break;
    case '\t':
      fprintf(out_f, "&rarr;");
      ++column_count;
      break;
    case '\r':
      fprintf(out_f, "&crarr;");
      break;
    case '\n':
      fprintf(out_f, "&para;\n");
      column_count = 0;
      ++line_count;
      break;
    default:
      putc(txt[i], out_f);
      ++column_count;
      break;
    }
  }
  fprintf(out_f, "</pre>");
}

static void
report_file(
        FILE *out_f,
        const unsigned char *dir_path,
        const struct test_dir_info *files,
        int index,
        const unsigned char *cl)
{
  char *file_t = 0;
  size_t file_z = 0;

  if (index < 0 || index >= files->u) {
    fprintf(out_f, "<td%s valign=\"top\"><i>%s</i></td>", cl, "nonexisting");
    return;
  }
  fprintf(out_f, "<td%s valign=\"top\">", cl);
  fprintf(out_f, "<i>%s</i><br/>", xml_unparse_date(files->v[index].mtime));
  fprintf(out_f, "<i>%lld</i>", files->v[index].size);
  if (generic_read_file(&file_t, 0, &file_z, 0, dir_path, files->v[index].name, "") < 0) {
    fprintf(out_f, "<br/><i>%s</i>", "read error");
  } else if (!is_text_file(file_t, file_z)) {
    xfree(file_t); file_t = 0; file_z = 0;
    fprintf(out_f, "<br/><i>%s</i>", "binary file");
  } else {
    output_text_file(out_f, file_t, file_z);
    xfree(file_t); file_t = 0; file_z = 0;
  }
  
  /*
  if (files->v[index].size > 0 && files->v[index].size <= 256) {
    if (generic_read_file(&file_t, 0, &file_z, 0, dir_path, files->v[index].name, "") < 0) {
      fprintf(out_f, "<br/><i>%s</i>", "read error");
    } else if (!is_text_file(file_t, file_z)) {
      xfree(file_t); file_t = 0; file_z = 0;
      fprintf(out_f, "<br/><i>%s</i>", "binary file");
    } else {
      output_text_file(out_f, file_t, file_z);
      xfree(file_t); file_t = 0; file_z = 0;
    }
  }
  */
  fprintf(out_f, "</td>");
}

static int
prepare_test_file_names(
        FILE *log_f,
        struct super_http_request_info *phr,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant,
        const unsigned char *pat_prefix,
        int buf_size,
        unsigned char *test_dir,
        unsigned char *test_pat,
        unsigned char *corr_pat,
        unsigned char *info_pat,
        unsigned char *tgz_pat,
        unsigned char *tgzdir_pat)
{
  int retval = 0;
  unsigned char corr_dir[PATH_MAX];
  unsigned char info_dir[PATH_MAX];
  unsigned char tgz_dir[PATH_MAX];
  unsigned char name1[PATH_MAX];
  unsigned char name2[PATH_MAX];

  if (pat_prefix == NULL) pat_prefix = "";

  test_dir[0] = 0;
  test_pat[0] = 0;
  corr_pat[0] = 0;
  info_pat[0] = 0;
  tgz_pat[0] = 0;
  tgzdir_pat[0] = 0;
  corr_dir[0] = 0;
  info_dir[0] = 0;
  tgz_dir[0] = 0;

  if (global->advanced_layout > 0) {
    get_advanced_layout_path(test_dir, buf_size, global, prob, DFLT_P_TEST_DIR, variant);
  } else if (variant > 0) {
    snprintf(test_dir, buf_size, "%s-%d", prob->test_dir, variant);
  } else {
    snprintf(test_dir, buf_size, "%s", prob->test_dir);
  }
  if (prob->test_pat[0] >= ' ') {
    snprintf(test_pat, buf_size, "%s%s", pat_prefix, prob->test_pat);
  } else if (prob->test_sfx[0] >= ' ') {
    snprintf(test_pat, buf_size, "%s%%03d%s", pat_prefix, prob->test_sfx);
  } else {
    snprintf(test_pat, buf_size, "%s%%03d%s", pat_prefix, ".dat");
  }
  snprintf(name1, sizeof(name1), test_pat, 1);
  snprintf(name2, sizeof(name2), test_pat, 2);
  if (!strcmp(name1, name2)) {
    fprintf(log_f, "invalid test files pattern\n");
    FAIL(S_ERR_UNSUPPORTED_SETTINGS);
  }

  corr_dir[0] = 0;
  corr_pat[0] = 0;
  if (prob->use_corr > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(corr_dir, sizeof(corr_dir), global, prob, DFLT_P_CORR_DIR, variant);
    } else if (variant > 0) {
      snprintf(corr_dir, sizeof(corr_dir), "%s-%d", prob->corr_dir, variant);
    } else {
      snprintf(corr_dir, sizeof(corr_dir), "%s", prob->corr_dir);
    }
    if (strcmp(corr_dir, test_dir) != 0) {
      fprintf(log_f, "corr_dir and test_dir cannot be different\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->corr_pat[0] >= ' ' ) {
      snprintf(corr_pat, buf_size, "%s%s", pat_prefix, prob->corr_pat);
    } else if (prob->corr_sfx[0] >= ' ') {
      snprintf(corr_pat, buf_size, "%s%%03d%s", pat_prefix, prob->corr_sfx);
    } else {
      snprintf(corr_pat, buf_size, "%s%%03d%s", pat_prefix, ".ans");
    }
    snprintf(name1, sizeof(name1), corr_pat, 1);
    snprintf(name2, sizeof(name2), corr_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid correct files pattern\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
  }

  info_dir[0] = 0;
  info_pat[0] = 0;
  if (prob->use_info > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(info_dir, sizeof(info_dir), global, prob, DFLT_P_INFO_DIR, variant);
    } else if (variant > 0) {
      snprintf(info_dir, sizeof(info_dir), "%s-%d", prob->info_dir, variant);
    } else {
      snprintf(info_dir, sizeof(info_dir), "%s", prob->info_dir);
    }
    if (strcmp(info_dir, test_dir) != 0) {
      fprintf(log_f, "info_dir and test_dir cannot be different\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->info_pat[0] >= ' ' ) {
      snprintf(info_pat, buf_size, "%s%s", pat_prefix, prob->info_pat);
    } else if (prob->corr_sfx[0] >= ' ') {
      snprintf(info_pat, buf_size, "%s%%03d%s", pat_prefix, prob->info_sfx);
    } else {
      snprintf(info_pat, buf_size, "%s%%03d%s", pat_prefix, ".inf");
    }
    snprintf(name1, sizeof(name1), info_pat, 1);
    snprintf(name2, sizeof(name2), info_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid info files pattern\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
  }

  tgz_dir[0] = 0;
  tgz_pat[0] = 0;
  tgzdir_pat[0] = 0;
  if (prob->use_tgz > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(tgz_dir, sizeof(tgz_dir), global, prob, DFLT_P_TGZ_DIR, variant);
    } else if (variant > 0) {
      snprintf(tgz_dir, sizeof(tgz_dir), "%s-%d", prob->tgz_dir, variant);
    } else {
      snprintf(tgz_dir, sizeof(tgz_dir), "%s", prob->tgz_dir);
    }
    if (strcmp(tgz_dir, test_dir) != 0) {
      fprintf(log_f, "tgz_dir and test_dir cannot be different\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->tgz_pat[0] >= ' ' ) {
      snprintf(tgz_pat, buf_size, "%s%s", pat_prefix, prob->tgz_pat);
    } else if (prob->corr_sfx[0] >= ' ') {
      snprintf(tgz_pat, buf_size, "%s%%03d%s", pat_prefix, prob->tgz_sfx);
    } else {
      snprintf(tgz_pat, buf_size, "%s%%03d%s", pat_prefix, ".inf");
    }
    snprintf(name1, sizeof(name1), tgz_pat, 1);
    snprintf(name2, sizeof(name2), tgz_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid tgz files pattern\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->tgzdir_pat[0] >= ' ' ) {
      snprintf(tgzdir_pat, buf_size, "%s%s", pat_prefix, prob->tgzdir_pat);
    } else if (prob->corr_sfx[0] >= ' ') {
      snprintf(tgzdir_pat, buf_size, "%s%%03d%s", pat_prefix, prob->tgzdir_sfx);
    } else {
      snprintf(tgzdir_pat, buf_size, "%s%%03d%s", pat_prefix, ".dir");
    }
    snprintf(name1, sizeof(name1), tgzdir_pat, 1);
    snprintf(name2, sizeof(name2), tgzdir_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid tgzdir files pattern\n");
      FAIL(S_ERR_UNSUPPORTED_SETTINGS);
    }
  }

cleanup:
  return retval;
}

int
super_serve_op_TESTS_TESTS_VIEW_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  int prob_id = 0, variant = 0;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  struct test_dir_info td_info;
  int i;
  unsigned char buf[1024], hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl = "";

  memset(&td_info, 0, sizeof(td_info));

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  retval = scan_test_directory(log_f, &td_info, cnts, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), tests for problem %s",
           phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  if (td_info.readme_idx >= 0) {
    fprintf(out_f, "<h2>%s</h2>\n", "README");

    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr><td%s>", cl, cl);
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_README_EDIT_PAGE, contest_id, prob_id),
            "Edit");
    fprintf(out_f, "</td><td%s>", cl);
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_README_DELETE_PAGE, contest_id, prob_id),
            "Delete");
    fprintf(out_f, "</td></tr></table>\n");
  } else {
    fprintf(out_f, "<h2>%s</h2>\n", "README");

    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr><td%s>", cl, cl);
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_README_CREATE_PAGE, contest_id, prob_id),
            "Create");
    fprintf(out_f, "</td></tr></table>\n");
  }

  fprintf(out_f, "<h2>%s</h2>\n", "Active tests");

  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>", cl);
  for (i = 0; i < td_info.test_ref_count; ++i) {
    fprintf(out_f, "<tr>");
    fprintf(out_f, "<td%s>%d</td>", cl, i + 1);
    // test file info
    report_file(out_f, test_dir, &td_info, td_info.test_refs[i].test_idx, cl);
    if (corr_pat[0]) {
      report_file(out_f, test_dir, &td_info, td_info.test_refs[i].corr_idx, cl);
    }
    if (info_pat[0]) {
      report_file(out_f, test_dir, &td_info, td_info.test_refs[i].info_idx, cl);
    }
    fprintf(out_f, "<td%s>", cl);
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_MOVE_UP_ACTION, contest_id, prob_id, i + 1),
            "Move up");
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_MOVE_DOWN_ACTION, contest_id, prob_id, i + 1),
            "Move down");
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_MOVE_TO_SAVED_ACTION, contest_id, prob_id, i + 1),
            "Move to saved");
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_INSERT_PAGE, contest_id, prob_id, i + 1),
            "Insert before");
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_EDIT_PAGE, contest_id, prob_id, i + 1),
            "Edit");
    fprintf(out_f, "&nbsp;%s[%s]</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_DELETE_PAGE, contest_id, prob_id, i + 1),
            "Delete");
    fprintf(out_f, "</td>");
    fprintf(out_f, "</tr>\n");
  }
  fprintf(out_f, "</table>\n");

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr><td%s>", cl, cl);
  fprintf(out_f, "&nbsp;%s[%s]</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TEST_INSERT_PAGE, contest_id, prob_id, i + 1),
          "Add a new test after the last test");
  fprintf(out_f, "</td><td%s>", cl);
  fprintf(out_f, "&nbsp;%s[%s]</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TEST_UPLOAD_ARCHIVE_1_PAGE, contest_id, prob_id),
          "Upload an archive of tests");
  fprintf(out_f, "</td></tr></table>\n");

  if (td_info.saved_ref_count > 0) {
    fprintf(out_f, "<h2>%s</h2>\n", "Saved tests");

    cl = " class=\"b1\"";
    fprintf(out_f, "<table%s>", cl);
    for (i = 0; i < td_info.saved_ref_count; ++i) {
      fprintf(out_f, "<tr>");
      fprintf(out_f, "<td%s>%d</td>", cl, i + 1);
      report_file(out_f, test_dir, &td_info, td_info.saved_refs[i].test_idx, cl);
      if (corr_pat[0]) {
        report_file(out_f, test_dir, &td_info, td_info.saved_refs[i].corr_idx, cl);
      }
      if (info_pat[0]) {
        report_file(out_f, test_dir, &td_info, td_info.saved_refs[i].info_idx, cl);
      }
      fprintf(out_f, "<td%s>", cl);
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_SAVED_MOVE_UP_ACTION, contest_id, prob_id, i + 1),
              "Move up");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_SAVED_MOVE_DOWN_ACTION, contest_id, prob_id, i + 1),
              "Move down");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_SAVED_MOVE_TO_TEST_ACTION, contest_id, prob_id, i + 1),
              "Move to tests");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d", SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_SAVED_DELETE_PAGE, contest_id, prob_id, i + 1),
              "Delete");
      fprintf(out_f, "</td>");
      fprintf(out_f, "</tr>\n");
    }
    fprintf(out_f, "</table>\n");
  }

  ss_write_html_footer(out_f);

cleanup:
  test_dir_info_free(&td_info);
  html_armor_free(&ab);

  return retval;
}

static void
make_prefixed_path(
        unsigned char *path,
        size_t size,
        const unsigned char *dir,
        const unsigned char *prefix,
        const unsigned char *format,
        int value)
{
  unsigned char name[1024];

  if (!format || !*format) {
    memset(path, 0, size);
  } else {
    if (!prefix) prefix = "";
    snprintf(name, sizeof(name), format, value);
    snprintf(path, size, "%s/%s%s", dir, prefix, name);
  }
}

static int
logged_rename(
        FILE *log_f,
        const unsigned char *oldpath,
        const unsigned char *newpath)
{
  if (!*oldpath || !*newpath) return 0;

  if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
    fprintf(log_f, "rename: %s->%s failed: %s\n", oldpath, newpath, os_ErrorMsg());
    return -1;
  }
  return 0;
}

static int
logged_unlink(
        FILE *log_f,
        const unsigned char *path)
{
  if (!*path) return 0;

  if (unlink(path) < 0 && errno != ENOENT) {
    fprintf(log_f, "unlink: %s failed: %s\n", path, os_ErrorMsg());
    return -1;
  }
  return 0;
}

static int
swap_files(
        FILE *log_f,
        const unsigned char *test_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        const unsigned char *info_pat,
        const unsigned char *tgz_pat,
        const unsigned char *tgzdir_pat,
        const unsigned char *src_prefix,
        const unsigned char *dst_prefix,
        const unsigned char *tmp_prefix,
        int src_num,
        int dst_num)
{
  int retval = 0, stage = 0;
  unsigned char test_src_path[PATH_MAX];
  unsigned char test_dst_path[PATH_MAX];
  unsigned char test_tmp_path[PATH_MAX];
  unsigned char corr_src_path[PATH_MAX];
  unsigned char corr_dst_path[PATH_MAX];
  unsigned char corr_tmp_path[PATH_MAX];
  unsigned char info_src_path[PATH_MAX];
  unsigned char info_dst_path[PATH_MAX];
  unsigned char info_tmp_path[PATH_MAX];
  unsigned char tgz_src_path[PATH_MAX];
  unsigned char tgz_dst_path[PATH_MAX];
  unsigned char tgz_tmp_path[PATH_MAX];
  unsigned char tgzdir_src_path[PATH_MAX];
  unsigned char tgzdir_dst_path[PATH_MAX];
  unsigned char tgzdir_tmp_path[PATH_MAX];

  make_prefixed_path(test_src_path, sizeof(test_src_path), test_dir, src_prefix, test_pat, src_num);
  make_prefixed_path(test_dst_path, sizeof(test_dst_path), test_dir, dst_prefix, test_pat, dst_num);
  make_prefixed_path(test_tmp_path, sizeof(test_tmp_path), test_dir, tmp_prefix, test_pat, dst_num);
  make_prefixed_path(corr_src_path, sizeof(corr_src_path), test_dir, src_prefix, corr_pat, src_num);
  make_prefixed_path(corr_dst_path, sizeof(corr_dst_path), test_dir, dst_prefix, corr_pat, dst_num);
  make_prefixed_path(corr_tmp_path, sizeof(corr_tmp_path), test_dir, tmp_prefix, corr_pat, dst_num);
  make_prefixed_path(info_src_path, sizeof(info_src_path), test_dir, src_prefix, info_pat, src_num);
  make_prefixed_path(info_dst_path, sizeof(info_dst_path), test_dir, dst_prefix, info_pat, dst_num);
  make_prefixed_path(info_tmp_path, sizeof(info_tmp_path), test_dir, tmp_prefix, info_pat, dst_num);
  make_prefixed_path(tgz_src_path, sizeof(tgz_src_path), test_dir, src_prefix, tgz_pat, src_num);
  make_prefixed_path(tgz_dst_path, sizeof(tgz_dst_path), test_dir, dst_prefix, tgz_pat, dst_num);
  make_prefixed_path(tgz_tmp_path, sizeof(tgz_tmp_path), test_dir, tmp_prefix, tgz_pat, dst_num);
  make_prefixed_path(tgzdir_src_path, sizeof(tgzdir_src_path), test_dir, src_prefix, tgzdir_pat, src_num);
  make_prefixed_path(tgzdir_dst_path, sizeof(tgzdir_dst_path), test_dir, dst_prefix, tgzdir_pat, dst_num);
  make_prefixed_path(tgzdir_tmp_path, sizeof(tgzdir_tmp_path), test_dir, tmp_prefix, tgzdir_pat, dst_num);

  if (logged_unlink(log_f, test_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_unlink(log_f, corr_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_unlink(log_f, info_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_unlink(log_f, tgz_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (remove_directory_recursively(tgzdir_tmp_path, 0) < 0) FAIL(S_ERR_FS_ERROR);

  // DST->TMP
  if (logged_rename(log_f, test_dst_path, test_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, corr_dst_path, corr_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, info_dst_path, info_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgz_dst_path, tgz_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgzdir_dst_path, tgzdir_tmp_path) < 0) goto fs_error;
  ++stage;

  // SRC->DST
  if (logged_rename(log_f, test_src_path, test_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, corr_src_path, corr_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, info_src_path, info_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgz_src_path, tgz_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgzdir_src_path, tgzdir_dst_path) < 0) goto fs_error;
  ++stage;

  // TMP->SRC
  if (logged_rename(log_f, test_tmp_path, test_src_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, corr_tmp_path, corr_src_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, info_tmp_path, info_src_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgz_tmp_path, tgz_src_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgzdir_tmp_path, tgzdir_src_path) < 0) goto fs_error;
  ++stage;

cleanup:
  return retval;

fs_error:
  if (stage >= 15) logged_rename(log_f, tgzdir_src_path, tgzdir_tmp_path);
  if (stage >= 14) logged_rename(log_f, tgz_src_path, tgz_tmp_path);
  if (stage >= 13) logged_rename(log_f, info_src_path, info_tmp_path);
  if (stage >= 12) logged_rename(log_f, corr_src_path, corr_tmp_path);
  if (stage >= 11) logged_rename(log_f, test_src_path, test_tmp_path);
  if (stage >= 10) logged_rename(log_f, tgzdir_dst_path, tgzdir_src_path);
  if (stage >= 9) logged_rename(log_f, tgz_dst_path, tgz_src_path);
  if (stage >= 8) logged_rename(log_f, info_dst_path, info_src_path);
  if (stage >= 7) logged_rename(log_f, corr_dst_path, corr_src_path);
  if (stage >= 6) logged_rename(log_f, test_dst_path, test_src_path);
  if (stage >= 5) logged_rename(log_f, tgzdir_tmp_path, tgzdir_dst_path);
  if (stage >= 4) logged_rename(log_f, tgz_tmp_path, tgz_dst_path);
  if (stage >= 3) logged_rename(log_f, info_tmp_path, info_dst_path);
  if (stage >= 2) logged_rename(log_f, corr_tmp_path, corr_dst_path);
  if (stage >= 1) logged_rename(log_f, test_tmp_path, test_dst_path);
  FAIL(S_ERR_FS_ERROR);
}

static int
move_files(
        FILE *log_f,
        const unsigned char *test_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        const unsigned char *info_pat,
        const unsigned char *tgz_pat,
        const unsigned char *tgzdir_pat,        
        const unsigned char *src_prefix,
        const unsigned char *dst_prefix,
        const unsigned char *tmp_prefix,
        int src_num,
        int dst_num)
{
  int retval = 0, stage = 0;
  unsigned char test_src_path[PATH_MAX];
  unsigned char test_dst_path[PATH_MAX];
  unsigned char test_tmp_path[PATH_MAX];
  unsigned char corr_src_path[PATH_MAX];
  unsigned char corr_dst_path[PATH_MAX];
  unsigned char corr_tmp_path[PATH_MAX];
  unsigned char info_src_path[PATH_MAX];
  unsigned char info_dst_path[PATH_MAX];
  unsigned char info_tmp_path[PATH_MAX];
  unsigned char tgz_src_path[PATH_MAX];
  unsigned char tgz_dst_path[PATH_MAX];
  unsigned char tgz_tmp_path[PATH_MAX];
  unsigned char tgzdir_src_path[PATH_MAX];
  unsigned char tgzdir_dst_path[PATH_MAX];
  unsigned char tgzdir_tmp_path[PATH_MAX];

  make_prefixed_path(test_src_path, sizeof(test_src_path), test_dir, src_prefix, test_pat, src_num);
  make_prefixed_path(test_dst_path, sizeof(test_dst_path), test_dir, dst_prefix, test_pat, dst_num);
  make_prefixed_path(test_tmp_path, sizeof(test_tmp_path), test_dir, tmp_prefix, test_pat, dst_num);
  make_prefixed_path(corr_src_path, sizeof(corr_src_path), test_dir, src_prefix, corr_pat, src_num);
  make_prefixed_path(corr_dst_path, sizeof(corr_dst_path), test_dir, dst_prefix, corr_pat, dst_num);
  make_prefixed_path(corr_tmp_path, sizeof(corr_tmp_path), test_dir, tmp_prefix, corr_pat, dst_num);
  make_prefixed_path(info_src_path, sizeof(info_src_path), test_dir, src_prefix, info_pat, src_num);
  make_prefixed_path(info_dst_path, sizeof(info_dst_path), test_dir, dst_prefix, info_pat, dst_num);
  make_prefixed_path(info_tmp_path, sizeof(info_tmp_path), test_dir, tmp_prefix, info_pat, dst_num);
  make_prefixed_path(tgz_src_path, sizeof(tgz_src_path), test_dir, src_prefix, tgz_pat, src_num);
  make_prefixed_path(tgz_dst_path, sizeof(tgz_dst_path), test_dir, dst_prefix, tgz_pat, dst_num);
  make_prefixed_path(tgz_tmp_path, sizeof(tgz_tmp_path), test_dir, tmp_prefix, tgz_pat, dst_num);
  make_prefixed_path(tgzdir_src_path, sizeof(tgzdir_src_path), test_dir, src_prefix, tgzdir_pat, src_num);
  make_prefixed_path(tgzdir_dst_path, sizeof(tgzdir_dst_path), test_dir, dst_prefix, tgzdir_pat, dst_num);
  make_prefixed_path(tgzdir_tmp_path, sizeof(tgzdir_tmp_path), test_dir, tmp_prefix, tgzdir_pat, dst_num);

  if (logged_unlink(log_f, test_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_unlink(log_f, corr_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_unlink(log_f, info_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_unlink(log_f, tgz_tmp_path) < 0) FAIL(S_ERR_FS_ERROR);
  if (remove_directory_recursively(tgzdir_tmp_path, 0) < 0) FAIL(S_ERR_FS_ERROR);

  // DST->TMP
  if (logged_rename(log_f, test_dst_path, test_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, corr_dst_path, corr_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, info_dst_path, info_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgz_dst_path, tgz_tmp_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgzdir_dst_path, tgzdir_tmp_path) < 0) goto fs_error;
  ++stage;

  // SRC->DST
  if (logged_rename(log_f, test_src_path, test_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, corr_src_path, corr_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, info_src_path, info_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgz_src_path, tgz_dst_path) < 0) goto fs_error;
  ++stage;
  if (logged_rename(log_f, tgzdir_src_path, tgzdir_dst_path) < 0) goto fs_error;
  ++stage;

  // remove TMP
  logged_unlink(log_f, test_tmp_path);
  logged_unlink(log_f, corr_tmp_path);
  logged_unlink(log_f, info_tmp_path);
  logged_unlink(log_f, tgz_tmp_path);
  remove_directory_recursively(tgzdir_tmp_path, 0);

cleanup:
  return retval;

fs_error:
  if (stage >= 10) logged_rename(log_f, tgzdir_dst_path, tgzdir_src_path);
  if (stage >= 9) logged_rename(log_f, tgz_dst_path, tgz_src_path);
  if (stage >= 8) logged_rename(log_f, info_dst_path, info_src_path);
  if (stage >= 7) logged_rename(log_f, corr_dst_path, corr_src_path);
  if (stage >= 6) logged_rename(log_f, test_dst_path, test_src_path);
  if (stage >= 5) logged_rename(log_f, tgzdir_tmp_path, tgzdir_dst_path);
  if (stage >= 4) logged_rename(log_f, tgz_tmp_path, tgz_dst_path);
  if (stage >= 3) logged_rename(log_f, info_tmp_path, info_dst_path);
  if (stage >= 2) logged_rename(log_f, corr_tmp_path, corr_dst_path);
  if (stage >= 1) logged_rename(log_f, test_tmp_path, test_dst_path);
  FAIL(S_ERR_FS_ERROR);
}

static int
delete_test(
        FILE *log_f,
        const unsigned char *test_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        const unsigned char *info_pat,
        const unsigned char *tgz_pat,
        const unsigned char *tgzdir_pat,
        const unsigned char *prefix,
        int test_count, // 0-based
        int test_num) // 1-based
{
  int retval = 0;
  unsigned char test_src_path[PATH_MAX];
  unsigned char test_dst_path[PATH_MAX];
  unsigned char corr_src_path[PATH_MAX];
  unsigned char corr_dst_path[PATH_MAX];
  unsigned char info_src_path[PATH_MAX];
  unsigned char info_dst_path[PATH_MAX];
  unsigned char tgz_src_path[PATH_MAX];
  unsigned char tgz_dst_path[PATH_MAX];
  unsigned char tgzdir_src_path[PATH_MAX];
  unsigned char tgzdir_dst_path[PATH_MAX];

  if (test_num <= 0 || test_num > test_count) return retval;

  make_prefixed_path(test_dst_path, sizeof(test_dst_path), test_dir, prefix, test_pat, test_num);
  make_prefixed_path(corr_dst_path, sizeof(corr_dst_path), test_dir, prefix, corr_pat, test_num);
  make_prefixed_path(info_dst_path, sizeof(info_dst_path), test_dir, prefix, info_pat, test_num);
  make_prefixed_path(tgz_dst_path, sizeof(tgz_dst_path), test_dir, prefix, tgz_pat, test_num);
  make_prefixed_path(tgzdir_dst_path, sizeof(tgzdir_dst_path), test_dir, prefix, tgzdir_pat, test_num);
  logged_unlink(log_f, test_dst_path);
  logged_unlink(log_f, corr_dst_path);
  logged_unlink(log_f, info_dst_path);
  logged_unlink(log_f, tgz_dst_path);
  remove_directory_recursively(tgzdir_dst_path, 0);

  for (++test_num; test_num <= test_count; ++test_num) {
    make_prefixed_path(test_dst_path, sizeof(test_dst_path), test_dir, prefix, test_pat, test_num - 1);
    make_prefixed_path(corr_dst_path, sizeof(corr_dst_path), test_dir, prefix, corr_pat, test_num - 1);
    make_prefixed_path(info_dst_path, sizeof(info_dst_path), test_dir, prefix, info_pat, test_num - 1);
    make_prefixed_path(tgz_dst_path, sizeof(tgz_dst_path), test_dir, prefix, tgz_pat, test_num - 1);
    make_prefixed_path(tgzdir_dst_path, sizeof(tgzdir_dst_path), test_dir, prefix, tgzdir_pat, test_num - 1);
    make_prefixed_path(test_src_path, sizeof(test_src_path), test_dir, prefix, test_pat, test_num);
    make_prefixed_path(corr_src_path, sizeof(corr_src_path), test_dir, prefix, corr_pat, test_num);
    make_prefixed_path(info_src_path, sizeof(info_src_path), test_dir, prefix, info_pat, test_num);
    make_prefixed_path(tgz_src_path, sizeof(tgz_src_path), test_dir, prefix, tgz_pat, test_num);
    make_prefixed_path(tgzdir_src_path, sizeof(tgzdir_src_path), test_dir, prefix, tgzdir_pat, test_num);
    // FIXME: check for errors
    logged_rename(log_f, test_src_path, test_dst_path);
    logged_rename(log_f, corr_src_path, corr_dst_path);
    logged_rename(log_f, info_src_path, info_dst_path);
    logged_rename(log_f, tgz_src_path, tgz_dst_path);
    logged_rename(log_f, tgzdir_src_path, tgzdir_dst_path);
  }

  return retval;
}

static int
insert_test(
        FILE *log_f,
        const unsigned char *test_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        const unsigned char *info_pat,
        const unsigned char *tgz_pat,
        const unsigned char *tgzdir_pat,
        const unsigned char *prefix,
        int test_count, // 0-based
        int test_num) // 1-based
{
  int retval = 0, cur_test;
  unsigned char test_src_path[PATH_MAX];
  unsigned char test_dst_path[PATH_MAX];
  unsigned char corr_src_path[PATH_MAX];
  unsigned char corr_dst_path[PATH_MAX];
  unsigned char info_src_path[PATH_MAX];
  unsigned char info_dst_path[PATH_MAX];
  unsigned char tgz_src_path[PATH_MAX];
  unsigned char tgz_dst_path[PATH_MAX];
  unsigned char tgzdir_src_path[PATH_MAX];
  unsigned char tgzdir_dst_path[PATH_MAX];

  if (test_num <= 0 || test_num > test_count) return retval;

  for (cur_test = test_count; cur_test >= test_num; --cur_test) {
    make_prefixed_path(test_dst_path, sizeof(test_dst_path), test_dir, prefix, test_pat, cur_test + 1);
    make_prefixed_path(corr_dst_path, sizeof(corr_dst_path), test_dir, prefix, corr_pat, cur_test + 1);
    make_prefixed_path(info_dst_path, sizeof(info_dst_path), test_dir, prefix, info_pat, cur_test + 1);
    make_prefixed_path(tgz_dst_path, sizeof(tgz_dst_path), test_dir, prefix, tgz_pat, cur_test + 1);
    make_prefixed_path(tgzdir_dst_path, sizeof(tgzdir_dst_path), test_dir, prefix, tgzdir_pat, cur_test + 1);
    make_prefixed_path(test_src_path, sizeof(test_src_path), test_dir, prefix, test_pat, cur_test);
    make_prefixed_path(corr_src_path, sizeof(corr_src_path), test_dir, prefix, corr_pat, cur_test);
    make_prefixed_path(info_src_path, sizeof(info_src_path), test_dir, prefix, info_pat, cur_test);
    make_prefixed_path(tgz_src_path, sizeof(tgz_src_path), test_dir, prefix, tgz_pat, cur_test);
    make_prefixed_path(tgzdir_src_path, sizeof(tgzdir_src_path), test_dir, prefix, tgzdir_pat, cur_test);
    // FIXME: check for errors
    logged_rename(log_f, test_src_path, test_dst_path);
    logged_rename(log_f, corr_src_path, corr_dst_path);
    logged_rename(log_f, info_src_path, info_dst_path);
    logged_rename(log_f, tgz_src_path, tgz_dst_path);
    logged_rename(log_f, tgzdir_src_path, tgzdir_dst_path);
  }

  return retval;
}

static int
check_test_existance(
        FILE *log_f,
        const unsigned char *test_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        const unsigned char *info_pat,
        const unsigned char *tgz_pat,
        const unsigned char *tgzdir_pat,
        const unsigned char *prefix,
        int test_num) // 1-based
{
  unsigned char test_path[PATH_MAX];
  unsigned char corr_path[PATH_MAX];
  unsigned char info_path[PATH_MAX];
  unsigned char tgz_path[PATH_MAX];
  unsigned char tgzdir_path[PATH_MAX];
  int exists = 0;

  make_prefixed_path(test_path, sizeof(test_path), test_dir, prefix, test_pat, test_num);
  make_prefixed_path(corr_path, sizeof(corr_path), test_dir, prefix, corr_pat, test_num);
  make_prefixed_path(info_path, sizeof(info_path), test_dir, prefix, info_pat, test_num);
  make_prefixed_path(tgz_path, sizeof(tgz_path), test_dir, prefix, tgz_pat, test_num);
  make_prefixed_path(tgzdir_path, sizeof(tgzdir_path), test_dir, prefix, tgzdir_pat, test_num);

  if (test_path[0] && access(test_path, F_OK) >= 0) exists = 1;
  if (corr_path[0] && access(corr_path, F_OK) >= 0) exists = 1;
  if (info_path[0] && access(info_path, F_OK) >= 0) exists = 1;
  if (tgz_path[0] && access(tgz_path, F_OK) >= 0) exists = 1;
  if (tgzdir_path[0] && access(tgzdir_path, F_OK) >= 0) exists = 1;
  return exists;
}

int
super_serve_op_TESTS_TEST_MOVE_UP_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int test_num = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  const unsigned char *pat_prefix = NULL;
  int from_test_num = 0;
  int to_test_num = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "test_num", &test_num, 0);
  if (test_num <= 0 || test_num >= 1000000) FAIL(S_ERR_INV_TEST_NUM);

  if (phr->opcode == SSERV_OP_TESTS_SAVED_MOVE_UP_ACTION || phr->opcode == SSERV_OP_TESTS_SAVED_MOVE_DOWN_ACTION) {
    pat_prefix = SAVED_TEST_PREFIX;
  }
  if (phr->opcode == SSERV_OP_TESTS_TEST_MOVE_UP_ACTION || phr->opcode == SSERV_OP_TESTS_SAVED_MOVE_UP_ACTION) {
    to_test_num = test_num - 1;
    from_test_num = test_num;
  } else if (phr->opcode == SSERV_OP_TESTS_TEST_MOVE_DOWN_ACTION || phr->opcode == SSERV_OP_TESTS_SAVED_MOVE_DOWN_ACTION) {
    to_test_num = test_num + 1;
    from_test_num = test_num;
  } else {
    FAIL(S_ERR_INV_OPER);
  }
  if (to_test_num <= 0 || from_test_num <= 0) goto done;

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, pat_prefix,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  if (phr->opcode == SSERV_OP_TESTS_TEST_MOVE_DOWN_ACTION || phr->opcode == SSERV_OP_TESTS_SAVED_MOVE_DOWN_ACTION) {
    if (!check_test_existance(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat,
                              pat_prefix, to_test_num))
      goto done;
  }

  retval = swap_files(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat,
                      pat_prefix, pat_prefix, TEMP_TEST_PREFIX, from_test_num, to_test_num);
  if (retval < 0) goto cleanup;
  retval = 0;

done:
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  return retval;
}

int
super_serve_op_TESTS_TEST_MOVE_TO_SAVED_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int test_num = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  struct test_dir_info td_info;

  memset(&td_info, 0, sizeof(td_info));
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "test_num", &test_num, 0);
  if (test_num <= 0 || test_num >= 1000000) FAIL(S_ERR_INV_TEST_NUM);

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  retval = scan_test_directory(log_f, &td_info, cnts, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;

  if (phr->opcode == SSERV_OP_TESTS_TEST_MOVE_TO_SAVED_ACTION) {
    if (test_num <= 0 || test_num > td_info.test_ref_count) goto done;
    if (move_files(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat,
                   NULL, SAVED_TEST_PREFIX, TEMP_TEST_PREFIX,
                   test_num, td_info.saved_ref_count + 1) < 0)
      goto cleanup;
    if (delete_test(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat,
                    NULL, td_info.test_ref_count, test_num) < 0)
      goto cleanup;
  } else if (phr->opcode == SSERV_OP_TESTS_SAVED_MOVE_TO_TEST_ACTION) {
    if (test_num <= 0 || test_num > td_info.saved_ref_count) goto done;
    if (move_files(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat,
                   SAVED_TEST_PREFIX, NULL, TEMP_TEST_PREFIX,
                   test_num, td_info.test_ref_count + 1) < 0)
      goto cleanup;
    if (delete_test(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat,
                    SAVED_TEST_PREFIX, td_info.saved_ref_count, test_num) < 0)
      goto cleanup;
  } else {
    FAIL(S_ERR_INV_OPER);
  }

done:
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  test_dir_info_free(&td_info);
  return retval;
}

static void
norm_type_select(FILE *out_f, int norm_type)
{
  const unsigned char *ss[TEST_NORM_LAST];
  int i;

  if (norm_type < TEST_NORM_FIRST || norm_type >= TEST_NORM_LAST) {
    norm_type = TEST_NORM_NONE;
  }
  if (norm_type == TEST_NORM_DEFAULT) norm_type = TEST_NORM_NL;
  for (i = 0; i < TEST_NORM_LAST; ++i) {
    ss[i] = "";
    if (norm_type == i) ss[i] = " selected=\"selected\"";
  }
  fprintf(out_f, "<select name=\"norm_type\">"
          "<option value=\"%d\"%s>None</option>"
          "<option value=\"%d\"%s>End of line</option>"
          "<option value=\"%d\"%s>End of line and trailing space</option>"
          "<option value=\"%d\"%s>End of line, trailing space, and non-printable</option>"
          "<option value=\"%d\"%s>End of line, and non-printable</option>"
          "</select>",
          TEST_NORM_NONE, ss[TEST_NORM_NONE],
          TEST_NORM_NL, ss[TEST_NORM_NL],
          TEST_NORM_NLWS, ss[TEST_NORM_NLWS],
          TEST_NORM_NLWSNP, ss[TEST_NORM_NLWSNP],
          TEST_NORM_NLNP, ss[TEST_NORM_NLNP]);
}

static int
is_binary_file(const unsigned char *text, size_t size)
{
  const unsigned char *p = text;

  if (!text || size > 1000000000) return 1;
  if (strlen(text) != size) return 1;
  for (; *p; ++p) {
    if (*p == 127 || (*p < ' ' && !isspace(*p))) {
      return 1;
    }
  }
  return 0;
}

static int
report_file_info(
        FILE *out_f,
        const unsigned char *path,
        int binary_input,
        unsigned char **p_text,
        ssize_t *p_size,
        struct testinfo_struct *pti,
        int insert_mode)
{
  int retval = 0;
  struct stat stb;
  const unsigned char *cl = " class=\"b0\"";
  char *text = NULL;
  size_t size = 0;

  *p_text = NULL;
  *p_size = 0;
  fprintf(out_f, "<table%s>", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><tt>%s</tt></td></tr>\n", cl ,"Path", cl, path);
  if (insert_mode) {
    fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><i>%s</i></td></tr>\n",
            cl, "New file");
    fprintf(out_f, "</table>\n");
    *p_text = xstrdup("");
    *p_size = 0;
    return retval;
  }
  if (stat(path, &stb) < 0) {
    fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s</font></td></tr>\n",
            cl, "File does not exist");
    retval = -1;
  } else {
    if (access(path, R_OK) < 0) {
      fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s</font></td></tr>\n",
              cl, "File is not readable");
      retval = -1;
    }
    if (access(path, W_OK) < 0) {
      fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s</font></td></tr>\n",
              cl, "File is not writeable");
    }
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%lld</td></tr>\n",
            cl, "Size", cl, (long long) stb.st_size);
    if (stb.st_size > MAX_ONLINE_EDITOR_SIZE) {
      fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s</font></td></tr>\n",
              cl, "File is too big to be edited online");
      retval = -2;
    }

    if (retval != -2 && binary_input <= 0) {
      if (pti) {
        retval = testinfo_parse(path, pti);
        if (retval < 0) {
          fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s: %s</font></td></tr>\n",
                  cl, "Testinfo error", testinfo_strerror(retval));
        }
        retval = 0;
      } else {
        if (generic_read_file(&text, 0, &size, 0, 0, path, 0) < 0 || !text) {
          fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s</font></td></tr>\n",
                  cl, "Input error");
          retval = -2;
        } else if (is_binary_file(text, size)) {
          fprintf(out_f, "<tr><td%s colspan=\"2\" align=\"center\"><font color=\"red\">%s</font></td></tr>\n",
                  cl, "Text file contains invalid characters");
          retval = -2;
          xfree(text); text = NULL; size = 0;
        }
      }
    }

    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%03o</td></tr>\n",
            cl, "Mode", cl, stb.st_mode & 07777);
    struct passwd *ui = getpwuid(stb.st_uid);
    if (!ui) {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
              cl, "Owner UID", cl, stb.st_uid);
    } else {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
              cl, "Owner", cl, ui->pw_name);
    }
    struct group *gi = getgrgid(stb.st_gid);
    if (!gi) {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
              cl, "Owner GID", cl, stb.st_gid);
    } else {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
              cl, "Group", cl, gi->gr_name);
    }
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            cl, "Last modification", cl, xml_unparse_date(stb.st_mtime));
  }
  fprintf(out_f, "</table>\n");

  *p_text = text;
  *p_size = size;

  return retval;
}


static void
edit_file_textarea(
        FILE *out_f,
        const unsigned char *name,
        int cols,
        int rows,
        const unsigned char *text)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (cols <= 0) cols = 60;
  if (rows <= 0) rows = 10;
  if (!text) text = "";
  fprintf(out_f, "<textarea name=\"%s\" cols=\"%d\" rows=\"%d\">%s</textarea>\n", name, cols, rows, ARMOR(text));
  html_armor_free(&ab);
}

int
super_serve_op_TESTS_TEST_EDIT_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int test_num = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl, *s, *s2;
  const unsigned char *prefix = NULL;
  unsigned char path[PATH_MAX];
  int r;
  unsigned char *text = NULL;
  ssize_t size = 0;
  struct testinfo_struct testinfo;
  int norm_type = TEST_NORM_NONE;
  int insert_mode = 0;

  memset(&testinfo, 0, sizeof(testinfo));

  if (phr->opcode == SSERV_OP_TESTS_TEST_INSERT_PAGE) insert_mode = 1;
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);
  if (prob->binary_input <= 0) {
    norm_type = test_normalization_parse(prob->normalization);
    if (norm_type < TEST_NORM_FIRST || norm_type >= TEST_NORM_LAST) norm_type = TEST_NORM_NONE;
    if (norm_type == TEST_NORM_DEFAULT) norm_type = TEST_NORM_NL;
  }

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "test_num", &test_num, 0);
  if (test_num <= 0 || test_num >= 1000000) FAIL(S_ERR_INV_TEST_NUM);

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  if (insert_mode) {
    snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), insert test at position %d for problem %s",
             phr->html_name, contest_id, ARMOR(cnts->name), test_num, prob->short_name);
  } else {
    snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), test %d for problem %s",
             phr->html_name, contest_id, ARMOR(cnts->name), test_num, prob->short_name);
  }
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);
  html_hidden(out_f, "test_num", "%d", test_num);

  if (test_pat[0] > ' ') {
    fprintf(out_f, "<h2>%s</h2>\n", "Input file");
    make_prefixed_path(path, sizeof(path), test_dir, prefix, test_pat, test_num);
    r = report_file_info(out_f, path, prob->binary_input, &text, &size, NULL, insert_mode);
    if (prob->binary_input > 0 || r == -2) {
      // what to do?
    } else {
      edit_file_textarea(out_f, "test_txt", 60, 10, text);
    }
    xfree(text); text = NULL; size = 0;
    if (!insert_mode) {
      cl = " class=\"b0\"";
      fprintf(out_f, "<table%s><tr>", cl);
      fprintf(out_f, "<td%s>%s%s</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;variant=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_DOWNLOAD, contest_id, prob_id, variant, test_num, 1),
              "Download file");
      fprintf(out_f, "<td%s>%s%s</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;variant=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_UPLOAD_PAGE, contest_id, prob_id, variant, test_num, 1),
              "Upload file");
      fprintf(out_f, "</table>\n");
    }
  }

  if (corr_pat[0] > ' ') {
    fprintf(out_f, "<h2>%s</h2>\n", "Answer file");
    make_prefixed_path(path, sizeof(path), test_dir, prefix, corr_pat, test_num);
    r = report_file_info(out_f, path, prob->binary_input, &text, &size, NULL, insert_mode);
    if (prob->binary_input > 0 || r == -2) {
      // what to do?
    } else {
      edit_file_textarea(out_f, "corr_txt", 60, 10, text);
    }
    xfree(text); text = NULL; size = 0;
    if (!insert_mode) {
      cl = " class=\"b0\"";
      fprintf(out_f, "<table%s><tr>", cl);
      fprintf(out_f, "<td%s>%s%s</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;variant=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_DOWNLOAD, contest_id, prob_id, variant, test_num, 2),
              "Download file");
      fprintf(out_f, "<td%s>%s%s</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;variant=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_UPLOAD_PAGE, contest_id, prob_id, variant, test_num, 2),
              "Upload file");
      fprintf(out_f, "</table>\n");
    }
  }

  if (info_pat[0] > ' ') {
    fprintf(out_f, "<h2>%s</h2>\n", "Info file");
    make_prefixed_path(path, sizeof(path), test_dir, prefix, info_pat, test_num);
    r = report_file_info(out_f, path, 0, &text, &size, &testinfo, insert_mode);
    xfree(text); text = NULL; size = 0;
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s>", cl);
    text = testinfo_unparse_cmdline(&testinfo);
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>",
            cl, "Command line",
            cl, html_input_text(hbuf, sizeof(hbuf), "testinfo_cmdline", 60, "%s", ARMOR(text)));
    xfree(text); text = NULL;
    text = testinfo_unparse_environ(&testinfo);
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>",
            cl, "Environment",
            cl, html_input_text(hbuf, sizeof(hbuf), "testinfo_environ", 60, "%s", ARMOR(text)));
    xfree(text); text = NULL;
    buf[0] = 0;
    if (testinfo.exit_code > 0 && testinfo.exit_code < 128) {
      snprintf(buf, sizeof(buf), "%d", testinfo.exit_code);
    }
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>",
            cl, "Expected exit code",
            cl, html_input_text(hbuf, sizeof(hbuf), "testinfo_exit_code", 60, "%s", buf));
    s = ""; s2 = "";
    if (testinfo.check_stderr > 0) {
      s2 = " selected=\"selected\"";
    } else {
      s = " selected=\"selected\"";
    }
    fprintf(out_f, "<tr><td%s>%s:</td><td%s><select name=\"testinfo_check_stderr\"><option value=\"0\"%s>%s</option><option value=\"1\"%s>%s</option></select></td></tr>",
            cl, "Check stderr instead of stdout", cl, s, "No", s2, "Yes");
    s = testinfo.team_comment;
    if (!s) s = "";
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>",
            cl, "User comment",
            cl, html_input_text(hbuf, sizeof(hbuf), "testinfo_user_comment", 60, "%s", ARMOR(s)));
    s = testinfo.comment;
    if (!s) s = "";
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>",
            cl, "Judge comment",
            cl, html_input_text(hbuf, sizeof(hbuf), "testinfo_comment", 60, "%s", ARMOR(s)));
    fprintf(out_f, "</table>\n");
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr>", cl);
    fprintf(out_f, "<td%s>%s%s</a></td>", cl,
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;variant=%d&amp;test_num=%d&amp;file_type=%d",
                          SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_CLEAR_INF_ACTION, contest_id, prob_id, variant, test_num, 3),
            "Clear file");
    fprintf(out_f, "</table>\n");
    xfree(text); text = NULL;
  }

  if (prob->binary_input <= 0) {
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr><td%s>%s:</td><td%s>", cl, cl, "File normalization type", cl);
    norm_type_select(out_f, norm_type);
    fprintf(out_f, "</td></tr></table>\n");
  }

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_CANCEL_ACTION, "Cancel");
  if (insert_mode) {
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_TEST_INSERT_ACTION, "Insert test");
  } else {
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_TEST_EDIT_ACTION, "Save changes");
  }
  fprintf(out_f, "<td%s width=\"100px\">&nbsp;</td>", cl);
  if (!insert_mode) {
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_TEST_DELETE_PAGE, "Delete this test");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_TEST_MOVE_TO_SAVED_ACTION, "Move this test to saved");
  }
  fprintf(out_f, "</tr></table>\n");

  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  testinfo_free(&testinfo);
  return retval;
}

int
super_serve_op_TESTS_CANCEL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  const struct contest_desc *cnts = 0;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  int prob_id = 0;
  int variant = 0;
  int next_op = SSERV_OP_TESTS_TESTS_VIEW_PAGE;

  if (phr->opcode == SSERV_OP_TESTS_CANCEL_2_ACTION) {
    next_op = SSERV_OP_TESTS_MAIN_PAGE;
  }

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_redirect_2(out_f, phr, next_op, contest_id, prob_id, variant, 0, NULL);

cleanup:
  return retval;
}

static unsigned char *
fix_string(const unsigned char *s)
{
  if (!s) return NULL;

  int len = strlen(s);
  if (len < 0) return NULL;

  while (len > 0 && (s[len - 1] <= ' ' || s[len - 1] == 127)) --len;
  if (len <= 0) return xstrdup("");

  int i = 0;
  while (i < len && (s[i] <= ' ' || s[i] == 127)) ++i;
  if (i >= len) return xstrdup("");

  unsigned char *out = (unsigned char *) xmalloc(len + 1);
  int j = 0;
  for (; i < len; ++i, ++j) {
    if (s[i] <= ' ' || s[i] == 127) {
      out[j] = ' ';
    } else {
      out[j] = s[i];
    }
  }
  out[j] = 0;

  return out;
}

static int
need_file_update(const unsigned char *out_path, const unsigned char *tmp_path)
{
  FILE *f1 = NULL;
  FILE *f2 = NULL;
  int c1, c2;

  if (!(f1 = fopen(out_path, "r"))) return 1;
  if (!(f2 = fopen(tmp_path, "r"))) {
    fclose(f1);
    return -1;
  }
  do {
    c1 = getc_unlocked(f1);
    c2 = getc_unlocked(f2);
  } while (c1 != EOF && c2 != EOF && c1 == c2);
  fclose(f2);
  fclose(f1);
  return c1 != EOF || c2 != EOF;
}

static unsigned char *
normalize_text(int mode, const unsigned char *text)
{
  size_t tlen = strlen(text);
  int op_mask = 0;
  unsigned char *out_text = NULL;
  size_t out_count = 0;
  int done_mask = 0;

  switch (mode) {
  case TEST_NORM_NONE:
    return xstrdup(text);
  case TEST_NORM_NLWSNP:
    op_mask |= TEXT_FIX_NP;
  case TEST_NORM_NLWS:          // fallthrough
    op_mask |= TEXT_FIX_TR_SP | TEXT_FIX_TR_NL;
  case TEST_NORM_NL:            // fallthrough
    op_mask |= TEXT_FIX_CR | TEXT_FIX_FINAL_NL;
    break;
  case TEST_NORM_NLNP:
    op_mask |= TEXT_FIX_CR | TEXT_FIX_FINAL_NL | TEXT_FIX_NP;
    break;
  default:
    abort();
  }

  text_normalize_dup(text, tlen, op_mask, &out_text, &out_count, &done_mask);
  return out_text;
}

static int
write_file(const unsigned char *path, const unsigned char *data)
{
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  for (;*data; ++data) {
    if (putc_unlocked(*data, f) < 0) {
      fclose(f);
      return -1;
    }
  }
  fclose(f);
  return 0;
}

static int
set_cnts_file_perms(
        FILE *log_f,
        const unsigned char *path,
        const struct contest_desc *cnts)
{
  int file_group = -1;
  int file_mode = -1;

  if (cnts->file_group && cnts->file_group[0]) {
    file_group = file_perms_parse_group(cnts->file_group);
    if (file_group <= 0) {
      fprintf(log_f, "Invalid group '%s'\n", cnts->file_group);
      return -1;
    }
  }
  if (cnts->file_mode && cnts->file_mode[0]) {
    file_mode = file_perms_parse_mode(cnts->file_mode);
    if (file_mode <= 0) {
      fprintf(log_f, "Invalid file mode '%s'\n", cnts->file_mode);
      return -1;
    }
  }
  if (path && path[0] && (file_group > 0 || file_mode > 0)) {
    file_perms_set(log_f, path, file_group, file_mode, -1, -1);
  }
  return 0;
}

int
super_serve_op_TESTS_TEST_EDIT_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  int prob_id = 0;
  int variant = 0;
  int test_num = 0;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  unsigned char test_tmp_path[PATH_MAX];
  unsigned char corr_tmp_path[PATH_MAX];
  unsigned char info_tmp_path[PATH_MAX];
  unsigned char test_out_path[PATH_MAX];
  unsigned char corr_out_path[PATH_MAX];
  unsigned char info_out_path[PATH_MAX];
  unsigned char test_del_path[PATH_MAX];
  unsigned char corr_del_path[PATH_MAX];
  unsigned char info_del_path[PATH_MAX];
  FILE *tmp_f = NULL;
  int testinfo_exit_code = 0;
  int testinfo_check_stderr = 0;
  const unsigned char *testinfo_cmdline = NULL;
  const unsigned char *testinfo_environ = NULL;
  const unsigned char *testinfo_comment = NULL;
  const unsigned char *testinfo_user_comment = NULL;
  const unsigned char *test_txt = NULL;
  const unsigned char *corr_txt = NULL;
  int norm_type = -1;
  unsigned char *text = NULL;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int r;
  int file_group = -1;
  int file_mode = -1;
  struct testinfo_struct tinfo;
  struct test_dir_info td_info;
  int insert_mode = 0;

  test_tmp_path[0] = 0;
  corr_tmp_path[0] = 0;
  info_tmp_path[0] = 0;
  test_del_path[0] = 0;
  corr_del_path[0] = 0;
  info_del_path[0] = 0;
  memset(&tinfo, 0, sizeof(tinfo));
  memset(&td_info, 0, sizeof(td_info));
  if (phr->opcode == SSERV_OP_TESTS_TEST_INSERT_ACTION) insert_mode = 1;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (cnts->file_group) {
    file_group = file_perms_parse_group(cnts->file_group);
    if (file_group <= 0) FAIL(S_ERR_INV_SYS_GROUP);
  }
  if (cnts->file_mode) {
    file_mode = file_perms_parse_mode(cnts->file_mode);
    if (file_mode <= 0) FAIL(S_ERR_INV_SYS_MODE);
  }

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "test_num", &test_num, 0);
  if (test_num <= 0 || test_num >= 1000000) FAIL(S_ERR_INV_TEST_NUM);

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  if (prob->use_info > 0 && info_pat[0] > ' ') {
    ss_cgi_param_int_opt(phr, "testinfo_exit_code", &testinfo_exit_code, 0);
    if (testinfo_exit_code < 0 || testinfo_exit_code >= 128) FAIL(S_ERR_INV_EXIT_CODE);
    ss_cgi_param_int_opt(phr, "testinfo_check_stderr", &testinfo_check_stderr, 0);
    if (testinfo_check_stderr != 1) testinfo_check_stderr = 0;
    ss_cgi_param(phr, "testinfo_cmdline", &testinfo_cmdline);
    ss_cgi_param(phr, "testinfo_environ", &testinfo_environ);
    ss_cgi_param(phr, "testinfo_user_comment", &testinfo_user_comment);
    ss_cgi_param(phr, "testinfo_comment", &testinfo_comment);

    make_prefixed_path(info_tmp_path, sizeof(info_tmp_path), test_dir, NEW_TEST_PREFIX, info_pat, test_num);
    make_prefixed_path(info_out_path, sizeof(info_out_path), test_dir, NULL, info_pat, test_num);
    make_prefixed_path(info_del_path, sizeof(info_del_path), test_dir, DEL_TEST_PREFIX, info_pat, test_num);
    if (!(tmp_f = fopen(info_tmp_path, "w"))) FAIL(S_ERR_FS_ERROR);
    if (testinfo_exit_code > 0) {
      fprintf(tmp_f, "exit_code = %d\n", testinfo_exit_code);
    }
    if (testinfo_check_stderr) {
      fprintf(tmp_f, "check_stderr = %d\n", testinfo_check_stderr);
    }
    text = fix_string(testinfo_cmdline);
    if (text) {
      fprintf(tmp_f, "params = %s\n", text);
    }
    xfree(text); text = NULL;
    text = fix_string(testinfo_environ);
    if (text) {
      fprintf(tmp_f, "environ = %s\n", text);
    }
    xfree(text); text = NULL;
    text = fix_string(testinfo_comment);
    if (text) {
      fprintf(tmp_f, "comment = %s\n", c_armor_buf(&ab, text));
    }
    xfree(text); text = NULL;
    text = fix_string(testinfo_user_comment);
    if (text) {
      fprintf(tmp_f, "team_comment = %s\n", c_armor_buf(&ab, text));
    }
    xfree(text); text = NULL;
    fclose(tmp_f); tmp_f = NULL;
    if (testinfo_parse(info_tmp_path, &tinfo) < 0) {
      FAIL(S_ERR_INV_TESTINFO);
    }
    testinfo_free(&tinfo);
    memset(&tinfo, 0, sizeof(tinfo));
    if (!insert_mode) {
      r = need_file_update(info_out_path, info_tmp_path);
      if (r < 0) FAIL(S_ERR_FS_ERROR);
      if (!r) {
        unlink(info_tmp_path);
        info_tmp_path[0] = 0;
      }
    }
  }
  if (info_tmp_path[0] && (file_group > 0 || file_mode > 0)) {
    file_perms_set(log_f, info_tmp_path, file_group, file_mode, -1, -1);
  }

  ss_cgi_param_int_opt(phr, "norm_type", &norm_type, -1);
  if (norm_type < TEST_NORM_FIRST || norm_type >= TEST_NORM_LAST) norm_type = TEST_NORM_NONE;
  if (norm_type == TEST_NORM_DEFAULT) norm_type = TEST_NORM_NL;

  if (prob->binary_input <= 0 && prob->use_corr > 0 && corr_pat[0] > ' ') {
    r = ss_cgi_param(phr, "corr_txt", &corr_txt);
    if (r < 0) FAIL(S_ERR_INV_VALUE);
    if (r > 0) {
      make_prefixed_path(corr_tmp_path, sizeof(corr_tmp_path), test_dir, NEW_TEST_PREFIX, corr_pat, test_num);
      make_prefixed_path(corr_out_path, sizeof(corr_out_path), test_dir, NULL, corr_pat, test_num);
      make_prefixed_path(corr_del_path, sizeof(corr_del_path), test_dir, DEL_TEST_PREFIX, corr_pat, test_num);
      text = normalize_text(norm_type, corr_txt);
      r = write_file(corr_tmp_path, text);
      if (r < 0) FAIL(S_ERR_FS_ERROR);
      xfree(text); text = NULL;
      if (!insert_mode) {
        r = need_file_update(corr_out_path, corr_tmp_path);
        if (r < 0) FAIL(S_ERR_FS_ERROR);
        if (!r) {
          unlink(corr_tmp_path);
          corr_tmp_path[0] = 0;
        }
      }
    }
  }
  if (corr_tmp_path[0] && (file_group > 0 || file_mode > 0)) {
    file_perms_set(log_f, corr_tmp_path, file_group, file_mode, -1, -1);
  }

  if (prob->binary_input <= 0) {
    r = ss_cgi_param(phr, "test_txt", &test_txt);
    if (r < 0) FAIL(S_ERR_INV_VALUE);
    if (r > 0) {
      make_prefixed_path(test_tmp_path, sizeof(test_tmp_path), test_dir, NEW_TEST_PREFIX, test_pat, test_num);
      make_prefixed_path(test_out_path, sizeof(test_out_path), test_dir, NULL, test_pat, test_num);
      make_prefixed_path(test_del_path, sizeof(test_del_path), test_dir, DEL_TEST_PREFIX, test_pat, test_num);
      text = normalize_text(norm_type, test_txt);
      r = write_file(test_tmp_path, text);
      if (r < 0) FAIL(S_ERR_FS_ERROR);
      xfree(text); text = NULL;
      if (!insert_mode) {
        r = need_file_update(test_out_path, test_tmp_path);
        if (r < 0) FAIL(S_ERR_FS_ERROR);
        if (!r) {
          unlink(test_tmp_path);
          test_tmp_path[0] = 0;
        }
      }
    }
  }
  if (test_tmp_path[0] && (file_group > 0 || file_mode > 0)) {
    file_perms_set(log_f, test_tmp_path, file_group, file_mode, -1, -1);
  }

  if (insert_mode) {
    retval = scan_test_directory(log_f, &td_info, cnts, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat);
    if (retval < 0) goto cleanup;
    retval = 0;

    if (test_num <= td_info.test_ref_count) {
      retval = insert_test(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat, NULL,
                           td_info.test_ref_count, test_num);
      if (retval < 0) goto cleanup;
      retval = 0;
    }

    test_dir_info_free(&td_info);
    memset(&td_info, 0, sizeof(td_info));
  }

  if (test_tmp_path[0]) {
    if (logged_rename(log_f, test_out_path, test_del_path) < 0) {
      FAIL(S_ERR_FS_ERROR);
    }
    if (logged_rename(log_f, test_tmp_path, test_out_path) < 0) {
      logged_rename(log_f, test_del_path, test_out_path);
      FAIL(S_ERR_FS_ERROR);
    }
  }
  if (corr_tmp_path[0]) {
    if (logged_rename(log_f, corr_out_path, corr_del_path) < 0) {
      logged_rename(log_f, test_del_path, test_out_path);
      FAIL(S_ERR_FS_ERROR);
    }
    if (logged_rename(log_f, corr_tmp_path, corr_out_path) < 0) {
      logged_rename(log_f, corr_del_path, corr_out_path);
      logged_rename(log_f, test_del_path, test_out_path);
      FAIL(S_ERR_FS_ERROR);
    }
  }
  if (info_tmp_path[0]) {
    if (logged_rename(log_f, info_out_path, info_del_path) < 0) {
      if (corr_tmp_path[0]) {
        logged_rename(log_f, corr_del_path, corr_out_path);
      }
      logged_rename(log_f, test_del_path, test_out_path);
      FAIL(S_ERR_FS_ERROR);
    }
    if (logged_rename(log_f, info_tmp_path, info_out_path) < 0) {
      logged_rename(log_f, info_del_path, info_out_path);
      if (corr_tmp_path[0]) {
        logged_rename(log_f, corr_del_path, corr_out_path);
      }
      logged_rename(log_f, test_del_path, test_out_path);
      FAIL(S_ERR_FS_ERROR);
    }
  }

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  test_dir_info_free(&td_info);
  xfree(text);
  if (tmp_f) fclose(tmp_f);
  if (test_tmp_path[0]) unlink(test_tmp_path);
  if (corr_tmp_path[0]) unlink(corr_tmp_path);
  if (info_tmp_path[0]) unlink(info_tmp_path);
  if (test_del_path[0]) unlink(test_del_path);
  if (corr_del_path[0]) unlink(corr_del_path);
  if (info_del_path[0]) unlink(info_del_path);
  html_armor_free(&ab);
  return retval;
}

static void
report_file_2(
        FILE *out_f,
        const unsigned char *path,
        const unsigned char *cl)
{
  char *file_t = 0;
  size_t file_z = 0;
  struct stat stb;

  if (stat(path, &stb) < 0) {
    fprintf(out_f, "<td%s valign=\"top\"><i>%s</i></td>", cl, "nonexisting");
    return;
  }
  fprintf(out_f, "<td%s valign=\"top\">", cl);
  fprintf(out_f, "<i>%s</i><br/>", xml_unparse_date(stb.st_mtime));
  fprintf(out_f, "<i>%lld</i>", (long long) stb.st_size);
  if (generic_read_file(&file_t, 0, &file_z, 0, NULL, path, "") < 0) {
    fprintf(out_f, "<br/><i>%s</i>", "read error");
  } else if (!is_text_file(file_t, file_z)) {
    xfree(file_t); file_t = 0; file_z = 0;
    fprintf(out_f, "<br/><i>%s</i>", "binary file");
  } else {
    output_text_file(out_f, file_t, file_z);
    xfree(file_t); file_t = 0; file_z = 0;
  }
  fprintf(out_f, "</td>");
}

int
super_serve_op_TESTS_TEST_DELETE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int test_num = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl = NULL;
  unsigned char path[PATH_MAX];
  struct testinfo_struct testinfo;

  memset(&testinfo, 0, sizeof(testinfo));

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "test_num", &test_num, 0);
  if (test_num <= 0 || test_num >= 1000000) FAIL(S_ERR_INV_TEST_NUM);

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), delete test at position %d for problem %s",
             phr->html_name, contest_id, ARMOR(cnts->name), test_num, prob->short_name);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d&prob_id=%d&variant=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant),
          "Tests page");
  fprintf(out_f, "</ul>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);
  html_hidden(out_f, "test_num", "%d", test_num);

  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>", cl);
  fprintf(out_f, "<tr>");
  fprintf(out_f, "<td%s>%d</td>", cl, test_num);
  make_prefixed_path(path, sizeof(path), test_dir, NULL, test_pat, test_num);
  report_file_2(out_f, path, cl);
  if (corr_pat[0] > ' ') {
    make_prefixed_path(path, sizeof(path), test_dir, NULL, corr_pat, test_num);
    report_file_2(out_f, path, cl);
  }
  if (info_pat[0] > ' ') {
    make_prefixed_path(path, sizeof(path), test_dir, NULL, info_pat, test_num);
    report_file_2(out_f, path, cl);
  }
  fprintf(out_f, "</tr>\n");
  fprintf(out_f, "</table>\n");

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_CANCEL_ACTION, "Cancel");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_TEST_DELETE_ACTION, "Delete test!");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_TEST_EDIT_PAGE, "Edit this test");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_TEST_MOVE_TO_SAVED_ACTION, "Move this test to saved");
  fprintf(out_f, "</tr></table>\n");

  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  testinfo_free(&testinfo);
  return retval;
}

int
super_serve_op_TESTS_TEST_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int test_num = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  struct test_dir_info td_info;

  memset(&td_info, 0, sizeof(td_info));

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "test_num", &test_num, 0);
  if (test_num <= 0 || test_num >= 1000000) FAIL(S_ERR_INV_TEST_NUM);

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  retval = scan_test_directory(log_f, &td_info, cnts, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat);
  if (retval < 0) goto cleanup;
  retval = 0;

  retval = delete_test(log_f, test_dir, test_pat, corr_pat, info_pat, tgz_pat, tgzdir_pat, NULL,
                       td_info.test_ref_count, test_num);
  if (retval < 0) goto cleanup;
  retval = 0;

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  test_dir_info_free(&td_info);
  return retval;
}

int
super_serve_op_TESTS_MAKEFILE_EDIT_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char makefile_path[PATH_MAX];
  int r;
  unsigned char *text = NULL;
  ssize_t size = 0;
  const unsigned char *cl = NULL;
  unsigned char buf[1024], hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  FILE *prb_f = NULL;
  char *prb_t = NULL;
  size_t prb_z = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  if (global->advanced_layout <= 0) FAIL(S_ERR_INV_CONTEST);

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  prb_f = open_memstream(&prb_t, &prb_z);
  prepare_unparse_actual_prob(prb_f, prob, cs->global, 0);
  fclose(prb_f); prb_f = NULL;

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, editing Makefile",
             phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  fprintf(out_f, "<h3>%s</h3>\n", "Config parameters");

  fprintf(out_f, "<pre>%s</pre>\n", ARMOR(prb_t));

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);

  fprintf(out_f, "<h3>%s</h3>\n", "Makefile");

  get_advanced_layout_path(makefile_path, sizeof(makefile_path), global, prob, DFLT_P_MAKEFILE, variant);
  r = report_file_info(out_f, makefile_path, 0, &text, &size, NULL, 0);
  edit_file_textarea(out_f, "text", 100, 30, text);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_CANCEL_2_ACTION, "Cancel");
  if (r != -2) {
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_MAKEFILE_EDIT_ACTION, "Save");
  }
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_MAKEFILE_DELETE_ACTION, "Delete!");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_MAKEFILE_GENERATE_ACTION, "Generate");
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  if (prb_f) fclose(prb_f);
  xfree(prb_t);
  html_armor_free(&ab);
  xfree(text);
  return retval;
}

int
super_serve_op_TESTS_MAKEFILE_EDIT_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char makefile_path[PATH_MAX];
  unsigned char tmp_makefile_path[PATH_MAX];
  const unsigned char *text = NULL;
  unsigned char *text2 = NULL;
  int r;
  int file_group = -1;
  int file_mode = -1;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  if (cnts->file_group) {
    file_group = file_perms_parse_group(cnts->file_group);
    if (file_group <= 0) FAIL(S_ERR_INV_SYS_GROUP);
  }
  if (cnts->file_mode) {
    file_mode = file_perms_parse_mode(cnts->file_mode);
    if (file_mode <= 0) FAIL(S_ERR_INV_SYS_MODE);
  }

  if (global->advanced_layout <= 0) FAIL(S_ERR_INV_CONTEST);

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }
  if (ss_cgi_param(phr, "text", &text) <= 0) FAIL(S_ERR_INV_VALUE);

  get_advanced_layout_path(tmp_makefile_path, sizeof(tmp_makefile_path), global, prob, "tmp_Makefile", variant);
  get_advanced_layout_path(makefile_path, sizeof(makefile_path), global, prob, DFLT_P_MAKEFILE, variant);

  text2 = normalize_text(TEST_NORM_NL, text);
  if (write_file(tmp_makefile_path, text2) < 0) FAIL(S_ERR_FS_ERROR);
  if (file_group > 0 || file_mode > 0) {
    file_perms_set(log_f, tmp_makefile_path, file_group, file_mode, -1, -1);
  }

  r = need_file_update(makefile_path, tmp_makefile_path);
  if (r < 0) FAIL(S_ERR_FS_ERROR);
  if (!r) {
    unlink(tmp_makefile_path);
    goto done;
  }
  if (logged_rename(log_f, tmp_makefile_path, makefile_path) < 0) {
    FAIL(S_ERR_FS_ERROR);
  }

done:
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  xfree(text2);
  return retval;
}

int
super_serve_op_TESTS_MAKEFILE_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char makefile_path[PATH_MAX];

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  if (global->advanced_layout <= 0) FAIL(S_ERR_INV_CONTEST);

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  get_advanced_layout_path(makefile_path, sizeof(makefile_path), global, prob, DFLT_P_MAKEFILE, variant);
  if (logged_unlink(log_f, makefile_path) < 0) FAIL(S_ERR_FS_ERROR);

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  return retval;
}

static const unsigned char ej_makefile_begin[] = "### BEGIN ejudge auto-generated makefile ###";
static const unsigned char ej_makefile_end[] = "### END ejudge auto-generated makefile ###";

static unsigned char *
merge_lines(unsigned char **lines, int beg, int end)
{
  int i, totlen = 0;
  unsigned char *str = NULL, *p;

  for (i = beg; i < end; ++i) {
    totlen += strlen(lines[i]) + 1;
  }
  if (totlen <= 0) return NULL;

  p = str = (unsigned char *) xmalloc((totlen + 1) * sizeof(*str));
  for (i = beg; i < end; ++i) {
    p = stpcpy(p, lines[i]);
    *p++ = '\n';
  }
  *p = 0;
  return str;
}

static void
extract_makefile_header_footer(
        const unsigned char *text,
        unsigned char **p_header,
        unsigned char **p_footer)
{
  unsigned char **lines = NULL;
  int i, slen, begin_idx = -1, end_idx = -1;

  if (!text || !*text) return;
  split_to_lines(text, (char***) &lines, 0);
  if (lines == NULL) return;

  for (i = 0; lines[i]; ++i) {
    slen = strlen(lines[i]);
    while (slen > 0 && isspace(lines[i][slen - 1])) --slen;
    lines[i][slen] = 0;
    if (begin_idx < 0 && !strcmp(lines[i], ej_makefile_begin)) {
      begin_idx = i;
    }
    if (!strcmp(lines[i], ej_makefile_end)) {
      end_idx = i;
    }
  }
  if (begin_idx >= 0 && end_idx >= 0 && begin_idx >= end_idx) {
    begin_idx = -1;
    end_idx = -1;
  }
  if (begin_idx >= 0) {
    *p_header = merge_lines(lines, 0, begin_idx);
  }
  if (end_idx >= 0) {
    *p_footer = merge_lines(lines, end_idx + 1, i);
  }
}

static void
pattern_to_shell_pattern(
        unsigned char *buf,
        int len,
        const unsigned char *pattern)
{
  const unsigned char *src = pattern;
  unsigned char *dst = buf;
  int width = -1, prec = -1;

  while (*src) {
    if (*src == '%') {
      ++src;
      if (!*src) continue;
      if (*src == '%') {
        *dst++ = *src++;
        continue;
      }
      if (*src == '#' || *src == '0' || *src == '-' || *src == ' ' || *src == '+' || *src == '\'' || *src == 'I') {
        ++src;
      }
      if (*src >= '0' && *src <= '9') {
        width = 0;
        while (*src >= '0' && *src <= '9') {
          width = width * 10 + (*src - '0');
          ++src;
        }
      }
      if (*src == '.') {
        ++src;
        if (*src >= '0' && *src <= '9') {
          prec = 0;
          while (*src >= '0' && *src <= '9') {
            prec = prec * 10 + (*src - '0');
            ++src;
          }
        }
      }
      if (*src == 'h') {
        ++src;
        if (*src == 'h') ++src;
      } else if (*src == 'l') {
        ++src;
        if (*src == 'l') ++src;
      } else if (*src == 'L' && *src == 'q' && *src == 'j' && *src == 'z' && *src == 't') {
        ++src;
      }
      if (*src == 'd' || *src == 'i' || *src == 'o' || *src == 'u' || *src == 'x' || *src == 'X'
          || *src == 'e' || *src == 'E' || *src == 'f' || *src == 'F'
          || *src == 'g' || *src == 'G' || *src == 'a' || *src == 'A'
          || *src == 'c' || *src == 's' || *src == 'p' || *src == 'n'
          || *src == 'C' || *src == 'S' || *src == 'm') {
        ++src;
        if (width <= 0) {
          *dst++ = '*';
        } else {
          for (; width; --width) {
            *dst++ = '?';
          }
        }
      }
    } else {
      *dst++ = *src++;
    }
  }
  *dst = 0;
}

enum
{
  LANG_C = 1,
  LANG_CPP = 2,
  LANG_JAVA = 4,
  LANG_FPC = 8,
  LANG_DCC = 16,
  LANG_PY = 32,
  LANG_PL = 64,
  LANG_SH = 128,
  LANG_OTHER = 0x100,
};

struct source_suffixes_s
{
  unsigned char *suffix;
  unsigned long mask;
};
static const struct source_suffixes_s source_suffixes[] =
{
  { ".c", LANG_C },
  { ".cpp", LANG_CPP },
  { ".java", LANG_JAVA },
  { ".pas", LANG_FPC },
  { ".dpr", LANG_DCC },
  { ".py", LANG_PY },
  { ".pl", LANG_PL },
  { ".sh", LANG_SH },
  { 0, 0 },
};

static const unsigned char *
get_source_suffix(int mask)
{
  int i;
  for (i = 0; source_suffixes[i].suffix; ++i) {
    if (source_suffixes[i].mask == mask)
      return source_suffixes[i].suffix;
  }
  return NULL;
}

static unsigned long
guess_language_by_cmd(unsigned char *cmd, int *p_count)
{
  int len, i;
  unsigned char path2[PATH_MAX];
  struct stat stb;
  unsigned long mask = 0;
  int count = 0;

  if (!cmd || !*cmd) return 0;
  len = strlen(cmd);
  i = len - 1;
  while (i >= 0 && cmd[i] != '/' && cmd[i] != '.') --i;
  if (i >= 0 && cmd[i] == '.') {
    if (!strcmp(cmd + i, ".class") || !strcmp(cmd + i, ".jar")) {
      if (i > 0 && cmd[i - 1] != '/' && cmd[i - 1] != '.') {
        cmd[i] = 0;
        mask |= LANG_JAVA;
        ++count;
      }
    } else if (!strcmp(cmd + i, ".exe")) {
      if (i > 0 && cmd[i - 1] != '/' && cmd[i - 1] != '.') {
        cmd[i] = 0;
      }
    }
  }
  for (i = 0; source_suffixes[i].suffix; ++i) {
    snprintf(path2, sizeof(path2), "%s%s", cmd, source_suffixes[i].suffix);
    if (access(path2, R_OK) >= 0 && stat(path2, &stb) >= 0 && S_ISREG(stb.st_mode)
        && !(mask & source_suffixes[i].mask)) {
      mask |= source_suffixes[i].mask;
      ++count;
    }
  }
  if (p_count) *p_count = count;
  return mask;
}

static unsigned long
guess_language_by_src(const unsigned char *src)
{
  int len, i, j;

  if (!src || !*src) return 0;
  len = strlen(src);
  i = len - 1;
  while (i >= 0 && src[i] != '/' && src[i] != '.') --i;
  if (i <= 0 || src[i] == '/') return 0;
  if (src[i - 1] == '/' || src[i - 1] == '.') return 0;
  for (j = 0; source_suffixes[j].suffix; ++j) {
    if (!strcmp(src + i, source_suffixes[j].suffix))
      return source_suffixes[j].mask;
  }
  return 0;
}

static unsigned char *
get_compiler_path(
        FILE *log_f,
        const struct ejudge_cfg *config,
        const unsigned char *script_dir_default,
        const unsigned char *lang_short_name)
{
  unsigned char script_dir[PATH_MAX];
  unsigned char version_script[PATH_MAX];
  char *args[3];
  unsigned char *stdout_text = NULL;
  unsigned char *stderr_text = NULL;
  int retval = 0, slen;

  script_dir[0] = 0;
  if (!config) config = ejudge_config;
  if (script_dir_default && script_dir_default[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s", script_dir_default);
  }
  if (!script_dir[0] && config && config->compile_home_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s/scripts",
             config->compile_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!script_dir[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s/compile/scripts",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif
  snprintf(version_script, sizeof(version_script), "%s/%s-version", script_dir, lang_short_name);
  args[0] = version_script;
  args[1] = "-p";
  args[2] = NULL;
  retval = ejudge_invoke_process(args, NULL, NULL, NULL, 0, &stdout_text, &stderr_text);
  if (retval != 0) {
    if (stderr_text && *stderr_text) {
      fprintf(log_f, "%s failed:\n---\n%s\n---\n", version_script, stderr_text);
    } else {
      fprintf(log_f, "%s failed\n", version_script);
    }
    xfree(stdout_text);
    xfree(stderr_text);
    return NULL;
  }
  xfree(stderr_text); stderr_text = NULL;
  if (!stdout_text || !*stdout_text) {
    fprintf(log_f, "%s output is empty\n", version_script);
    xfree(stdout_text);
    return NULL;
  }
  slen = strlen(stdout_text);
  while (slen > 0 && isspace(stdout_text[slen - 1])) --slen;
  stdout_text[slen] = 0;
  if (!slen) {
    fprintf(log_f, "%s output is empty\n", version_script);
    xfree(stdout_text);
    return NULL;
  }
  return stdout_text;
}

static const unsigned char *
get_compiler_flags(serve_state_t cs, const unsigned char *lang_short_name)
{
  static const unsigned char compiler_flags_prefix[] = "EJUDGE_FLAGS=";

  int lang_id, i;
  const struct section_language_data *lang;
  for (lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
    if (!(lang = cs->langs[lang_id]) || strcmp(lang->short_name, lang_short_name)) continue;
    if (!lang->compiler_env) return NULL;
    for (i = 0; lang->compiler_env[i]; ++i) {
      if (!strncmp(compiler_flags_prefix, lang->compiler_env[i], sizeof(compiler_flags_prefix) - 1))
        return lang->compiler_env[i] + sizeof(compiler_flags_prefix) - 1;
    }
  }
  return NULL;
}

static void
generate_checker_compilation_rule(
        FILE *out_f,
        const unsigned char *what,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant,
        const unsigned char *cmd)
{
  unsigned char tmp_path[PATH_MAX];
  unsigned long languages = 0;
  const unsigned char *source_suffix = NULL;
  int count = 0;

  if (!cmd || !cmd[0]) return;
  get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, cmd, variant);
  languages = guess_language_by_cmd(tmp_path, &count);
  if (count <= 0) {
    fprintf(out_f, "# no known source language is detected for %s '%s'\n", what, cmd);
  } else if (count > 1) {
    fprintf(out_f, "# several source languages are detected for %s '%s'\n", what, cmd);
  } else {
    source_suffix = get_source_suffix(languages);
    if (languages == LANG_C) {
      fprintf(out_f, "%s : %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${CC} ${CLIBCHECKERFLAGS} %s%s -o%s ${CLIBCHECKERLIBS}\n",
              cmd, source_suffix, cmd);
    } else if (languages == LANG_CPP) {
      fprintf(out_f, "%s : %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${CXX} ${CXXLIBCHECKERFLAGS} %s%s -o%s ${CXXLIBCHECKERLIBS}\n",
              cmd, source_suffix, cmd);
    } else {
      fprintf(out_f, "# no information how to build %s '%s'\n", what, cmd);
    }
  }
  fprintf(out_f, "\n");
}

static void
generate_makefile(
        FILE *log_f,
        FILE *mk_f,
        struct super_http_request_info *phr,
        const struct contest_desc *cnts,
        serve_state_t cs,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant)
{
  int retval = 0;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  unsigned char test_pr_pat[PATH_MAX];
  unsigned char tgzdir_pr_pat[PATH_MAX];
  unsigned long languages = 0;
  unsigned char tmp_path[PATH_MAX];
  unsigned char *compiler_path = NULL;
  const unsigned char *compiler_flags = NULL;
  int has_header = 0, need_c_libchecker = 0, need_cpp_libchecker = 0;
  const unsigned char *source_suffix = NULL;
  int count = 0;

  test_dir[0] = 0;
  test_pat[0] = 0;
  corr_pat[0] = 0;
  info_pat[0] = 0;
  tgz_pat[0] = 0;
  tgzdir_pat[0] = 0;
  test_pr_pat[0] = 0;

  retval = prepare_test_file_names(log_f, phr, cnts, global, prob, variant, NULL,
                                   sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                   tgz_pat, tgzdir_pat);
  if (retval < 0) return;
  pattern_to_shell_pattern(test_pr_pat, sizeof(test_pr_pat), test_pat);

  // tmp_path is modified by guess_language_by_cmd
  if (prob->check_cmd && prob->check_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->check_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path, NULL);
  }
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->valuer_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path, NULL);
  }
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->interactor_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path, NULL);
  }
  if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->style_checker_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path, NULL);
  }
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->test_checker_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path, NULL);
  }
  if ((languages & LANG_C)) need_c_libchecker = 1;
  if ((languages & LANG_CPP)) need_cpp_libchecker = 1;

  /* detect which languages we'll need */
  if (prob->source_header && prob->source_header[0]) {
    languages |= guess_language_by_src(prob->source_header);
  }
  if (prob->source_footer && prob->source_footer[0]) {
    languages |= guess_language_by_src(prob->source_footer);
  }
  if (prob->solution_src && prob->solution_src[0]) {
    languages |= guess_language_by_src(prob->solution_src);
  }

  if (prob->solution_cmd && prob->solution_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->solution_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path, NULL);
  }

  fprintf(mk_f, "%s\n", ej_makefile_begin);
  fprintf(mk_f, "EJUDGE_PREFIX_DIR ?= %s\n", EJUDGE_PREFIX_DIR);
  fprintf(mk_f, "EJUDGE_CONTESTS_HOME_DIR ?= %s\n", EJUDGE_CONTESTS_HOME_DIR);
#if defined EJUDGE_LOCAL_DIR
  fprintf(mk_f, "EJUDGE_LOCAL_DIR ?= %s\n", EJUDGE_LOCAL_DIR);
#endif /* EJUDGE_LOCAL_DIR */
  fprintf(mk_f, "\n");

  if ((languages & LANG_C)) {
    compiler_path = get_compiler_path(log_f, NULL, NULL, "gcc");
    if (!compiler_path) {
      fprintf(mk_f, "# C compiler is not found\nCC ?= /bin/false\n");
    } else {
      fprintf(mk_f, "CC = %s\n", compiler_path);
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = get_compiler_flags(cs, "gcc");
    if (!compiler_flags) {
      fprintf(mk_f, "CFLAGS = -Wall -g -O2 -std=gnu99 -Wno-pointer-sign\n");
    } else {
      fprintf(mk_f, "CFLAGS = %s\n", compiler_flags);
    }
    compiler_flags = NULL;
    fprintf(mk_f, "CLIBS = -lm\n");
    if (need_c_libchecker) {
      fprintf(mk_f, "CLIBCHECKERFLAGS = -Wall -Wno-pointer-sign -g -std=gnu99 -O2 -I${EJUDGE_PREFIX_DIR}/include/ejudge -L${EJUDGE_PREFIX_DIR}/lib -Wl,--rpath,${EJUDGE_PREFIX_DIR}/lib\n");
      fprintf(mk_f, "CLIBCHECKERLIBS = -lchecker -lm\n");
    }
  }
  fprintf(mk_f, "\n");

  if ((languages & LANG_CPP)) {
    compiler_path = get_compiler_path(log_f, NULL, NULL, "g++");
    if (!compiler_path) {
      fprintf(mk_f, "# C++ compiler is not found\nCXX ?= /bin/false\n");
    } else {
      fprintf(mk_f, "CXX = %s\n", compiler_path);
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = get_compiler_flags(cs, "g++");
    if (!compiler_flags) {
      fprintf(mk_f, "CXXFLAGS = -Wall -g -O2\n");
    } else {
      fprintf(mk_f, "CXXFLAGS = %s\n", compiler_flags);
    }
    compiler_flags = NULL;
    if (need_cpp_libchecker) {
      fprintf(mk_f, "CXXLIBCHECKERFLAGS = -Wall -g -O2 -I${EJUDGE_PREFIX_DIR}/include/ejudge -L${EJUDGE_PREFIX_DIR}/lib -Wl,--rpath,${EJUDGE_PREFIX_DIR}/lib\n");
      fprintf(mk_f, "CXXLIBCHECKERLIBS = -lchecker -lm\n");
    }
  }
  fprintf(mk_f, "\n");

  fprintf(mk_f, "EXECUTE = ${EJUDGE_PREFIX_DIR}/bin/ejudge-execute\n");
  fprintf(mk_f, "EXECUTE_FLAGS = --quiet");
  if (prob->use_stdin > 0) fprintf(mk_f, " --use-stdin");
  if (prob->use_stdout > 0) fprintf(mk_f, " --use-stdout");
  if (test_pat[0] > ' ') fprintf(mk_f, " --test-pattern=%s", test_pat);
  if (corr_pat[0] > ' ') fprintf(mk_f, " --corr-pattern=%s", corr_pat);
  if (info_pat[0] > ' ') fprintf(mk_f, " --info-pattern=%s", info_pat);
  if (cnts->file_group && cnts->file_group[0]) fprintf(mk_f, " --group=%s", cnts->file_group);
  if (cnts->file_mode && cnts->file_mode[0]) fprintf(mk_f, " --mode=%s", cnts->file_mode);
  if (prob->time_limit_millis > 0) {
    fprintf(mk_f, " --time-limit-millis=%d", prob->time_limit_millis);
  } else if (prob->time_limit > 0) {
    fprintf(mk_f, " --time-limit=%d", prob->time_limit);
  }
  fprintf(mk_f, "\n");

  if (prob->use_tgz > 0) {
    fprintf(mk_f, "MAKE_ARCHIVE = ${EJUDGE_PREFIX_DIR}/libexec/ejudge/lang/ej-make-archive\n");
    fprintf(mk_f, "MAKE_ARCHIVE_FLAGS = --tgzdir-pattern=%s --tgz-pattern=%s\n",
            tgzdir_pat, tgz_pat);
  }

  fprintf(mk_f, "\n");

  fprintf(mk_f, "all :");
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(mk_f, " %s", prob->solution_cmd);
  }
  if ((!prob->standard_checker || !prob->standard_checker[0])
      && prob->check_cmd && prob->check_cmd[0]) {
    fprintf(mk_f, " %s", prob->check_cmd);
  }
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    fprintf(mk_f, " %s", prob->valuer_cmd);
  }
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    fprintf(mk_f, " %s", prob->interactor_cmd);
  }
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    fprintf(mk_f, " %s", prob->test_checker_cmd);
  }
  fprintf(mk_f, "\n");
  fprintf(mk_f, "ejudge_make_problem : all\n");
  fprintf(mk_f, "\n");

  /* solution compilation part  */
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    if (prob->source_header && prob->source_header[0]) has_header = 1;
    if (prob->source_footer && prob->source_footer[0]) has_header = 1;
    if (prob->solution_src && prob->solution_src[0]) {
      languages = guess_language_by_src(prob->solution_src);
      source_suffix = get_source_suffix(languages);
      if (has_header) {
        fprintf(mk_f, "%s%s :", prob->solution_cmd, source_suffix);
        if (prob->source_header && prob->source_header[0]) {
          fprintf(mk_f, " %s", prob->source_header);
        }
        fprintf(mk_f, " %s", prob->solution_src);
        if (prob->source_footer && prob->source_footer[0]) {
          fprintf(mk_f, " %s", prob->source_footer);
        }
        fprintf(mk_f, "\n");
        fprintf(mk_f, "\tcat $^ > $@\n");
      }
      if (languages == LANG_C) {
        fprintf(mk_f, "%s : %s%s\n", prob->solution_cmd, prob->solution_cmd, source_suffix);
        fprintf(mk_f, "\t${CC} ${CFLAGS} %s%s -o%s ${CLIBS}\n",
                prob->solution_cmd, source_suffix, prob->solution_cmd);
      } else if (languages == LANG_CPP) {
        fprintf(mk_f, "%s : %s%s\n", prob->solution_cmd, prob->solution_cmd, source_suffix);
        fprintf(mk_f, "\t${CXX} ${CXXFLAGS} %s%s -o%s ${CXXLIBS}\n",
                prob->solution_cmd, source_suffix, prob->solution_cmd);
      } else {
        fprintf(mk_f, "# no information how to build solution '%s' from '%s'\n",
                prob->solution_cmd, prob->solution_src);
      }
    } else if (!has_header) {
      get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->solution_cmd, variant);
      languages = guess_language_by_cmd(tmp_path, &count);
      if (count <= 0) {
        fprintf(mk_f, "# no source language to build solution '%s'\n", prob->solution_cmd);
      } else if (count > 1) {
        fprintf(mk_f, "# several source languages to build solution '%s'\n", prob->solution_cmd);
      } else {
        source_suffix = get_source_suffix(languages);
        if (languages == LANG_C) {
          fprintf(mk_f, "%s : %s%s\n", prob->solution_cmd, prob->solution_cmd, source_suffix);
          fprintf(mk_f, "\t${CC} ${CFLAGS} %s%s -o%s ${CLIBS}\n",
                  prob->solution_cmd, source_suffix, prob->solution_cmd);
        } else if (languages == LANG_CPP) {
          fprintf(mk_f, "%s : %s%s\n", prob->solution_cmd, prob->solution_cmd, source_suffix);
          fprintf(mk_f, "\t${CXX} ${CXXFLAGS} %s%s -o%s ${CXXLIBS}\n",
                  prob->solution_cmd, source_suffix, prob->solution_cmd);
        } else {
          fprintf(mk_f, "# no information how to build solution '%s'\n", prob->solution_cmd);
        }
      }
    } else {
      fprintf(mk_f, "# no information how to build solution '%s' with header or footer\n", prob->solution_cmd);
    }
  }
  fprintf(mk_f, "\n");

  /* checker compilation part */
  if (!prob->standard_checker || !prob->standard_checker[0]) {
    generate_checker_compilation_rule(mk_f, "check", global, prob, variant, prob->check_cmd);
  }

  generate_checker_compilation_rule(mk_f, "valuer", global, prob, variant, prob->valuer_cmd);
  generate_checker_compilation_rule(mk_f, "interactor", global, prob, variant, prob->interactor_cmd);
  generate_checker_compilation_rule(mk_f, "test_checker", global, prob, variant, prob->test_checker_cmd);

  /* test generation part */
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(mk_f, "answers : %s\n", prob->solution_cmd);
    fprintf(mk_f, "\tcd tests; for i in %s; do ${EXECUTE} ${EXECUTE_FLAGS} --test-file=$$i ../%s; done\n",
            test_pr_pat, prob->solution_cmd);
    fprintf(mk_f, "\n");
    fprintf(mk_f, "answer : %s\n", prob->solution_cmd);
    fprintf(mk_f, "\tcd tests && ${EXECUTE} ${EXECUTE_FLAGS} --test-num=${TEST_NUM} ../%s\n", prob->solution_cmd);
    fprintf(mk_f, "\n");
  }
  fprintf(mk_f, "\n");

  /* archiving */
  if (prob->use_tgz > 0) {
    pattern_to_shell_pattern(tgzdir_pr_pat, sizeof(tgzdir_pr_pat), tgzdir_pat);
    fprintf(mk_f, "archives : \n");
    fprintf(mk_f, "\tcd tests; for i in %s; do ${MAKE_ARCHIVE} ${MAKE_ARCHIVE_FLAGS} $$i; done;\n",
            tgzdir_pr_pat);
  }

  fprintf(mk_f, "clean :\n");
  fprintf(mk_f, "\t-rm -f *.o");
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(mk_f, " %s", prob->solution_cmd);
  }
  if ((!prob->standard_checker || !prob->standard_checker[0])
      && prob->check_cmd && prob->check_cmd[0]) {
    fprintf(mk_f, " %s", prob->check_cmd);
  }  
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    fprintf(mk_f, " %s", prob->valuer_cmd);
  }  
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    fprintf(mk_f, " %s", prob->interactor_cmd);
  }  
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    fprintf(mk_f, " %s", prob->test_checker_cmd);
  }  
  fprintf(mk_f, "\n\n");

  fprintf(mk_f, "%s\n", ej_makefile_end);
}

int
super_serve_op_TESTS_MAKEFILE_GENERATE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char makefile_path[PATH_MAX];
  unsigned char tmp_makefile_path[PATH_MAX];
  int file_group = -1;
  int file_mode = -1;
  char *text = 0;
  size_t size = 0;
  unsigned char *header = NULL;
  unsigned char *footer = NULL;
  FILE *mk_f = NULL;
  int r;

  tmp_makefile_path[0] = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  if (cnts->file_group) {
    file_group = file_perms_parse_group(cnts->file_group);
    if (file_group <= 0) FAIL(S_ERR_INV_SYS_GROUP);
  }
  if (cnts->file_mode) {
    file_mode = file_perms_parse_mode(cnts->file_mode);
    if (file_mode <= 0) FAIL(S_ERR_INV_SYS_MODE);
  }

  if (global->advanced_layout <= 0) FAIL(S_ERR_INV_CONTEST);

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  get_advanced_layout_path(tmp_makefile_path, sizeof(tmp_makefile_path), global, prob, "tmp_Makefile", variant);
  get_advanced_layout_path(makefile_path, sizeof(makefile_path), global, prob, DFLT_P_MAKEFILE, variant);

  if (generic_read_file(&text, 0, &size, 0, 0, makefile_path, 0) >= 0) {
    extract_makefile_header_footer(text, &header, &footer);
  }

  mk_f = fopen(tmp_makefile_path, "w");
  if (!mk_f) FAIL(S_ERR_FS_ERROR);
  if (header) fprintf(mk_f, "%s", header);
  generate_makefile(log_f, mk_f, phr, cnts, cs, global, prob, variant);
  if (footer) fprintf(mk_f, "%s", footer);
  fclose(mk_f); mk_f = NULL;

  if (file_group > 0 || file_mode > 0) {
    file_perms_set(log_f, tmp_makefile_path, file_group, file_mode, -1, -1);
  }

  r = need_file_update(makefile_path, tmp_makefile_path);
  if (r < 0) FAIL(S_ERR_FS_ERROR);
  if (!r) {
    unlink(tmp_makefile_path);
    goto done;
  }
  if (logged_rename(log_f, tmp_makefile_path, makefile_path) < 0) {
    FAIL(S_ERR_FS_ERROR);
  }

done:
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAKEFILE_EDIT_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  if (mk_f) fclose(mk_f);
  if (tmp_makefile_path[0]) unlink(tmp_makefile_path);
  xfree(header);
  xfree(footer);
  xfree(text);
  return retval;
}

static int
write_file_info(
        FILE *out_f,
        const unsigned char *path,
        const unsigned char *title,
        int is_binary_file)
{
  const unsigned char *cl = "";
  struct stat stb;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int may_read = 0;

  fprintf(out_f, "<h3>%s %s</h3>\n", title, "file info");
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><tt>%s</tt></td></tr>\n", cl, "Path", cl, ARMOR(path));
  do {
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>", cl, "File existance", cl);
    if (stat(path, &stb) < 0) {
      fprintf(out_f, "<font color=\"red\">%s</font></td></tr>\n", "File does not exist");
      break;
    }
    fprintf(out_f, "<font color=\"green\">%s</font></td></tr>\n", "OK");

    fprintf(out_f, "<tr><td%s>%s:</td><td%s>", cl, "File readability", cl);
    if (access(path, R_OK) < 0) {
      fprintf(out_f, "<font color=\"red\">%s</font></td></tr>\n", "File is not readable");
      break;
    }
    fprintf(out_f, "<font color=\"green\">%s</font></td></tr>\n", "OK");
    may_read = 1;

    if (is_binary_file) {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>", cl, "File is binary", cl);
      fprintf(out_f, "<font color=\"red\">%s</font></td></tr>\n", "YES");
    }

    fprintf(out_f, "<tr><td%s>%s:</td><td%s>", cl, "File writeability", cl);
    if (access(path, W_OK) < 0) {
      fprintf(out_f, "<font color=\"red\">%s</font>", "File is not writable");
    } else {
      fprintf(out_f, "<font color=\"green\">%s</font>", "OK");
    }
    fprintf(out_f, "</td></tr>\n");

    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%lld</td></tr>\n", cl, "Size", cl, (long long) stb.st_size);
    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%04o</td></tr>\n", cl, "Permissions", cl, stb.st_mode & 07777);

    struct passwd *ui = getpwuid(stb.st_uid);
    if (!ui) {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
              cl, "Owner UID", cl, stb.st_uid);
    } else {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
              cl, "Owner", cl, ui->pw_name);
    }
    struct group *gi = getgrgid(stb.st_gid);
    if (!gi) {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
              cl, "Owner GID", cl, stb.st_gid);
    } else {
      fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
              cl, "Group", cl, gi->gr_name);
    }

    fprintf(out_f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, "Last modification", cl,
            xml_unparse_date(stb.st_mtime));
  } while (0);
  fprintf(out_f, "</table>\n");

  html_armor_free(&ab);
  return may_read;
}

int
super_serve_op_TESTS_STATEMENT_EDIT_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char buf[1024], hbuf[1024], vbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char xml_path[PATH_MAX];
  const unsigned char *cl = NULL;
  FILE *err_f = NULL;
  char *err_t = NULL;
  size_t err_z = 0;
  problem_xml_t prob_xml = NULL;
  int may_read = 0, plain_view = 0;
  FILE *file_f = NULL;
  char *file_t = NULL;
  size_t file_z = 0;
  struct problem_stmt *prob_stmt = NULL;
  struct xml_tree *p, *q;
  int serial;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }
  ss_cgi_param_int_opt(phr, "plain_view", &plain_view, 0);
  if (plain_view != 1) plain_view = 0;

  if (!prob->xml_file || !prob->xml_file[0]) FAIL(S_ERR_INV_PROB_ID);
  if (cs->global->advanced_layout > 0) {
    get_advanced_layout_path(xml_path, sizeof(xml_path), cs->global, prob, prob->xml_file, variant);
  } else if (variant > 0) {
    prepare_insert_variant_num(xml_path, sizeof(xml_path), prob->xml_file, variant);
  } else {
    snprintf(xml_path, sizeof(xml_path), "%s", prob->xml_file);
  }

  /*
  prb_f = open_memstream(&prb_t, &prb_z);
  prepare_unparse_actual_prob(prb_f, prob, cs->global, 0);
  fclose(prb_f); prb_f = NULL;
  */

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, editing statement",
             phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  may_read = write_file_info(out_f, xml_path, "Statement", 0);

  if (may_read && !plain_view) {
    err_f = open_memstream(&err_t, &err_z);
    prob_xml = problem_xml_parse(err_f, xml_path);
    fclose(err_f); err_f = NULL;

    if (!prob_xml) {
      fprintf(out_f, "<h3>%s</h3>\n", "XML parse errors");
      fprintf(out_f, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(err_t));
    }
    xfree(err_t); err_t = NULL; err_z = 0;
  }

  if (plain_view || (may_read && !prob_xml)) {
    fprintf(out_f, "<h3>%s</h3>\n", "Problem XML file");

    if (generic_read_file(&file_t, 0, &file_z, 0, NULL, xml_path, "") < 0) {
      file_t = xstrdup("");
      file_z = 0;
    }

    html_start_form(out_f, 1, phr->self_url, "");
    html_hidden(out_f, "SID", "%016llx", phr->session_id);
    html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
    html_hidden(out_f, "contest_id", "%d", contest_id);
    html_hidden(out_f, "prob_id", "%d", prob_id);
    html_hidden(out_f, "variant", "%d", variant);
    html_hidden(out_f, "plain_view", "%d", 1);

    edit_file_textarea(out_f, "xml_text", 100, 40, file_t);

    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr>", cl);
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_CANCEL_2_ACTION, "Cancel");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_EDIT_5_ACTION, "Save");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_EDIT_2_ACTION, "Save and view");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_DELETE_ACTION, "Delete!");
    fprintf(out_f, "</tr></table>\n");

    fprintf(out_f, "</form>\n");
  } else {
    fprintf(out_f, "<h3>%s</h3>\n", "Problem description");

    fprintf(out_f, "<script language=\"javascript\">\n"
            "function setSampleNumToDelete(num)\n"
            "{\n"
            "  form_obj = document.getElementById(\"EditForm\");\n"
            "  form_obj.delete_num.value = num;\n"
            "}\n"
            "</script>\n");

    html_start_form_id(out_f, 1, phr->self_url, "EditForm", "");
    html_hidden(out_f, "SID", "%016llx", phr->session_id);
    html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
    html_hidden(out_f, "contest_id", "%d", contest_id);
    html_hidden(out_f, "prob_id", "%d", prob_id);
    html_hidden(out_f, "variant", "%d", variant);
    html_hidden(out_f, "delete_num", "%d", -1);

    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s>", cl);
    vbuf[0] = 0;
    if (prob_xml && prob_xml->package) {
      snprintf(vbuf, sizeof(vbuf), "%s", prob_xml->package);
    }
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr>", cl, "Package",
            cl, html_input_text(buf, sizeof(buf), "prob_package", 60, "%s", vbuf));
    vbuf[0] = 0;
    if (prob_xml && prob_xml->id) {
      snprintf(vbuf, sizeof(vbuf), "%s", prob_xml->id);
    }
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr>", cl, "Name",
            cl, html_input_text(buf, sizeof(buf), "prob_name", 60, "%s", vbuf));

    // for now allow editing of only one (russian or default) statement
    if (prob_xml) prob_stmt = prob_xml->stmts;

    if (prob_stmt && prob_stmt->title) {
      file_f = open_memstream(&file_t, &file_z);
      problem_xml_unparse_node(file_f, prob_stmt->title, NULL, NULL);
      fclose(file_f); file_f = NULL;
    }
    if (file_t == NULL) file_t = xstrdup("");
    fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr>", cl, "Title",
            cl, html_input_text(buf, sizeof(buf), "prob_title", 60, "%s", ARMOR(file_t)));
    xfree(file_t); file_t = NULL; file_z = 0;

    if (prob_stmt && prob_stmt->desc) {
      file_f = open_memstream(&file_t, &file_z);
      problem_xml_unparse_node(file_f, prob_stmt->desc, NULL, NULL);
      fclose(file_f); file_f = NULL;
    }
    if (file_t == NULL) file_t = xstrdup("");
    fprintf(out_f, "<tr><td%s>%s</td><td%s>", cl, "Description", cl);
    edit_file_textarea(out_f, "prob_desc", 100, 20, file_t);
    fprintf(out_f, "</td></tr>\n");
    xfree(file_t); file_t = NULL; file_z = 0;

    if (prob_stmt && prob_stmt->input_format) {
      file_f = open_memstream(&file_t, &file_z);
      problem_xml_unparse_node(file_f, prob_stmt->input_format, NULL, NULL);
      fclose(file_f); file_f = NULL;
    }
    if (file_t == NULL) file_t = xstrdup("");
    fprintf(out_f, "<tr><td%s>%s</td><td%s>", cl, "Input format", cl);
    edit_file_textarea(out_f, "prob_input_format", 100, 20, file_t);
    fprintf(out_f, "</td></tr>\n");
    xfree(file_t); file_t = NULL; file_z = 0;

    if (prob_stmt && prob_stmt->output_format) {
      file_f = open_memstream(&file_t, &file_z);
      problem_xml_unparse_node(file_f, prob_stmt->output_format, NULL, NULL);
      fclose(file_f); file_f = NULL;
    }
    if (file_t == NULL) file_t = xstrdup("");
    fprintf(out_f, "<tr><td%s>%s</td><td%s>", cl, "Output format", cl);
    edit_file_textarea(out_f, "prob_output_format", 100, 20, file_t);
    fprintf(out_f, "</td></tr>\n");
    xfree(file_t); file_t = NULL; file_z = 0;

    if (prob_stmt && prob_stmt->notes) {
      file_f = open_memstream(&file_t, &file_z);
      problem_xml_unparse_node(file_f, prob_stmt->notes, NULL, NULL);
      fclose(file_f); file_f = NULL;
    }
    if (file_t == NULL) file_t = xstrdup("");
    fprintf(out_f, "<tr><td%s>%s</td><td%s>", cl, "Notes", cl);
    edit_file_textarea(out_f, "prob_notes", 100, 20, file_t);
    fprintf(out_f, "</td></tr>\n");
    xfree(file_t); file_t = NULL; file_z = 0;

    if (prob_xml && prob_xml->examples) {
      serial = 0;
      for (p = prob_xml->examples->first_down; p; p = p->right) {
        if (p->tag != PROB_T_EXAMPLE) continue;
        ++serial;
        for (q = p->first_down; q && q->tag != PROB_T_INPUT; q = q->right);
        if (q && q->tag == PROB_T_INPUT) {
          file_f = open_memstream(&file_t, &file_z);
          problem_xml_unparse_node(file_f, q, NULL, NULL);
          fclose(file_f); file_f = NULL;
        }
        if (file_t == NULL) file_t = xstrdup("");
        fprintf(out_f, "<tr><td%s>%s %d<br/>", cl, "Sample input", serial);
        fprintf(out_f, "<input onclick=\"setSampleNumToDelete(%d)\" type=\"submit\" name=\"op_%d\" value=\"%s\" />",
                serial, SSERV_OP_TESTS_STATEMENT_DELETE_SAMPLE_ACTION, "Delete");
        fprintf(out_f, "</td><td%s>", cl);
        snprintf(hbuf, sizeof(hbuf), "prob_sample_input_%d", serial);
        edit_file_textarea(out_f, hbuf, 100, 20, file_t);
        fprintf(out_f, "</td></tr>\n");
        xfree(file_t); file_t = NULL; file_z = 0;

        for (q = p->first_down; q && q->tag != PROB_T_OUTPUT; q = q->right);
        if (q && q->tag == PROB_T_OUTPUT) {
          file_f = open_memstream(&file_t, &file_z);
          problem_xml_unparse_node(file_f, q, NULL, NULL);
          fclose(file_f); file_f = NULL;
        }
        if (file_t == NULL) file_t = xstrdup("");
        fprintf(out_f, "<tr><td%s>%s %d<br/>", cl, "Sample output", serial);
        fprintf(out_f, "<input onclick=\"setSampleNumToDelete(%d)\" type=\"submit\" name=\"op_%d\" value=\"%s\" />",
                serial, SSERV_OP_TESTS_STATEMENT_DELETE_SAMPLE_ACTION, "Delete");
        fprintf(out_f, "</td><td%s>", cl);
        snprintf(hbuf, sizeof(hbuf), "prob_sample_output_%d", serial);
        edit_file_textarea(out_f, hbuf, 100, 20, file_t);
        fprintf(out_f, "</td></tr>\n");
        xfree(file_t); file_t = NULL; file_z = 0;
      }
    }

    fprintf(out_f, "</table>\n");

    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr>", cl);
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_CANCEL_2_ACTION, "Cancel");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_EDIT_ACTION, "Save");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_EDIT_4_ACTION, "Save and add a sample");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_EDIT_3_ACTION, "Save and view as file");
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_OP_TESTS_STATEMENT_DELETE_ACTION, "Delete!");
    fprintf(out_f, "</tr></table>\n");

    fprintf(out_f, "</form>\n");
  }

  ss_write_html_footer(out_f);

cleanup:
  problem_xml_free(prob_xml);
  if (err_f) fclose(err_f);
  xfree(err_t);
  if (file_f) fclose(file_f);
  xfree(file_t);
  html_armor_free(&ab);
  return retval;
}

static unsigned char *
normalize_textarea(const unsigned char *text)
{
  if (!text) return NULL;
  return normalize_text(TEST_NORM_NLWS, text);
}

int
super_serve_op_TESTS_STATEMENT_EDIT_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int delete_num = 0;
  int plain_view = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char xml_path[PATH_MAX];
  unsigned char xml_path_bak[PATH_MAX];
  unsigned char xml_path_tmp[PATH_MAX];
  problem_xml_t prob_xml = NULL;
  FILE *xml_f = NULL;
  const unsigned char *s = NULL;
  unsigned char *prob_package = NULL;
  unsigned char *prob_name = NULL;
  unsigned char *text = NULL;
  struct xml_tree *title_node = NULL;
  struct xml_tree *desc_node = NULL;
  struct xml_tree *input_format_node = NULL;
  struct xml_tree *output_format_node = NULL;
  struct xml_tree *notes_node = NULL;
  int test_count = 1, i;
  unsigned char test_param_name[64];
  struct xml_tree **test_input_nodes = NULL;
  struct xml_tree **test_output_nodes = NULL;
  struct problem_stmt *prob_stmt = NULL;
  int next_action = SSERV_OP_TESTS_MAIN_PAGE;
  unsigned char extra_redirect_args[1024];

  xml_path_tmp[0] = 0;
  extra_redirect_args[0] = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }
  ss_cgi_param_int_opt(phr, "plain_view", &plain_view, 0);
  if (plain_view != 1) plain_view = 0;

  ss_cgi_param_int_opt(phr, "delete_num", &delete_num, 0);

  if (!prob->xml_file || !prob->xml_file[0]) FAIL(S_ERR_INV_PROB_ID);
  if (cs->global->advanced_layout > 0) {
    get_advanced_layout_path(xml_path, sizeof(xml_path), cs->global, prob, prob->xml_file, variant);
  } else if (variant > 0) {
    prepare_insert_variant_num(xml_path, sizeof(xml_path), prob->xml_file, variant);
  } else {
    snprintf(xml_path, sizeof(xml_path), "%s", prob->xml_file);
  }
  snprintf(xml_path_tmp, sizeof(xml_path_tmp), "%s.tmp", xml_path);
  snprintf(xml_path_bak, sizeof(xml_path_bak), "%s.bak", xml_path);

  // prob_package, prob_name, prob_title, prob_desc, prob_input_format, prob_output_format, prob_notes
  s = NULL;
  ss_cgi_param(phr, "prob_package", &s);
  prob_package = fix_string(s);
  if (!prob_package || !*prob_package) FAIL(S_ERR_UNSPEC_PROB_PACKAGE);

  s = NULL;
  ss_cgi_param(phr, "prob_name", &s);
  prob_name = fix_string(s);
  if (!prob_name || !*prob_name) FAIL(S_ERR_UNSPEC_PROB_NAME);

  s = NULL;
  ss_cgi_param(phr, "prob_title", &s);
  text = fix_string(s);
  if (text && *text) {
    if (!(title_node = problem_xml_parse_text(log_f, text, PROB_T_TITLE))) FAIL(S_ERR_INV_XHTML);
  }
  xfree(text); text = NULL;

  s = NULL;
  ss_cgi_param(phr, "prob_desc", &s);
  text = normalize_textarea(s);
  if (text && *text) {
    if (!(desc_node = problem_xml_parse_text(log_f, text, PROB_T_DESCRIPTION))) FAIL(S_ERR_INV_XHTML);
  }
  xfree(text); text = NULL;

  s = NULL;
  ss_cgi_param(phr, "prob_input_format", &s);
  text = normalize_textarea(s);
  if (text && *text) {
    if (!(input_format_node = problem_xml_parse_text(log_f, text, PROB_T_INPUT_FORMAT))) FAIL(S_ERR_INV_XHTML);
  }
  xfree(text); text = NULL;

  s = NULL;
  ss_cgi_param(phr, "prob_output_format", &s);
  text = normalize_textarea(s);
  if (text && *text) {
    if (!(output_format_node = problem_xml_parse_text(log_f, text, PROB_T_OUTPUT_FORMAT))) FAIL(S_ERR_INV_XHTML);
  }
  xfree(text); text = NULL;

  s = NULL;
  ss_cgi_param(phr, "prob_notes", &s);
  text = normalize_textarea(s);
  if (text && *text) {
    if (!(notes_node = problem_xml_parse_text(log_f, text, PROB_T_NOTES))) FAIL(S_ERR_INV_XHTML);
  }
  xfree(text); text = NULL;

  // count how many samples
  // prob_sample_input_%d, prob_sample_output_%d
  while (1) {
    snprintf(test_param_name, sizeof(test_param_name), "prob_sample_input_%d", test_count);
    if (ss_cgi_param(phr, test_param_name, &s) <= 0) break;
    snprintf(test_param_name, sizeof(test_param_name), "prob_sample_output_%d", test_count);
    if (ss_cgi_param(phr, test_param_name, &s) <= 0) break;
    ++test_count;
  }

  XCALLOC(test_input_nodes, test_count);
  XCALLOC(test_output_nodes, test_count);
  for (i = 1; i < test_count; ++i) {
    s = NULL;
    snprintf(test_param_name, sizeof(test_param_name), "prob_sample_input_%d", i);
    ss_cgi_param(phr, test_param_name, &s);
    text = normalize_textarea(s);
    if (!(test_input_nodes[i] = problem_xml_parse_text(log_f, text, PROB_T_INPUT))) FAIL(S_ERR_INV_XHTML);
    xfree(text); text = NULL;

    s = NULL;
    snprintf(test_param_name, sizeof(test_param_name), "prob_sample_output_%d", i);
    ss_cgi_param(phr, test_param_name, &s);
    text = normalize_textarea(s);
    if (!(test_output_nodes[i] = problem_xml_parse_text(log_f, text, PROB_T_OUTPUT))) FAIL(S_ERR_INV_XHTML);
    xfree(text); text = NULL;
  }

  prob_xml = problem_xml_create(prob_package, prob_name);
  prob_stmt = problem_xml_create_statement(prob_xml, "ru_RU");
  problem_xml_attach_title(prob_stmt, title_node); title_node = NULL;
  problem_xml_attach_description(prob_stmt, desc_node); desc_node = NULL;
  problem_xml_attach_input_format(prob_stmt, input_format_node); input_format_node = NULL;
  problem_xml_attach_output_format(prob_stmt, output_format_node); output_format_node = NULL;
  problem_xml_attach_notes(prob_stmt, notes_node); notes_node = NULL;
  for (i = 1; i < test_count; ++i) {
    problem_xml_add_example(prob_xml, test_input_nodes[i], test_output_nodes[i]);
    test_input_nodes[i] = NULL;
    test_output_nodes[i] = NULL;
  }

  if (phr->opcode == SSERV_OP_TESTS_STATEMENT_EDIT_3_ACTION) {
    // save and view as text file
    snprintf(extra_redirect_args, sizeof(extra_redirect_args), "plain_view=1");
    next_action = SSERV_OP_TESTS_STATEMENT_EDIT_PAGE;
  } else if (phr->opcode == SSERV_OP_TESTS_STATEMENT_EDIT_4_ACTION) {
    // save and add a sample
    problem_xml_add_example(prob_xml,
                            problem_xml_parse_text(log_f, "", PROB_T_INPUT),
                            problem_xml_parse_text(log_f, "", PROB_T_OUTPUT));
    next_action = SSERV_OP_TESTS_STATEMENT_EDIT_PAGE;
  } else if (phr->opcode == SSERV_OP_TESTS_STATEMENT_DELETE_SAMPLE_ACTION) {
    // save and delete a sample
    problem_xml_delete_test(prob_xml, delete_num);
    next_action = SSERV_OP_TESTS_STATEMENT_EDIT_PAGE;
  }

  xml_f = fopen(xml_path_tmp, "w");
  if (!xml_f) FAIL(S_ERR_FS_ERROR);
  problem_xml_unparse(xml_f, prob_xml);
  fclose(xml_f); xml_f = NULL;
  if (!need_file_update(xml_path, xml_path_tmp)) goto done;

  prob_xml = problem_xml_free(prob_xml);
  prob_xml = problem_xml_parse(log_f, xml_path_tmp);
  if (!prob_xml) FAIL(S_ERR_INV_PROB_XML);
  prob_xml = problem_xml_free(prob_xml);

  if (logged_rename(log_f, xml_path, xml_path_bak) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_rename(log_f, xml_path_tmp, xml_path) < 0) FAIL(S_ERR_FS_ERROR);
  set_cnts_file_perms(log_f, xml_path, cnts);
  xml_path_tmp[0] = 0;

done:
  ss_redirect_2(out_f, phr, next_action, contest_id, prob_id, variant, 0, extra_redirect_args);

cleanup:
  xfree(prob_package);
  xfree(prob_name);
  xfree(text);
  problem_xml_free_text(title_node);
  problem_xml_free_text(desc_node);
  problem_xml_free_text(input_format_node);
  problem_xml_free_text(output_format_node);
  problem_xml_free_text(notes_node);
  if (test_input_nodes) {
    for (i = 0; i < test_count; ++i)
      problem_xml_free_text(test_input_nodes[i]);
    xfree(test_input_nodes);
  }
  if (test_output_nodes) {
    for (i = 0; i < test_count; ++i)
      xfree(test_output_nodes[i]);
    xfree(test_output_nodes);
  }
  problem_xml_free(prob_xml);
  if (xml_f) fclose(xml_f);
  if (xml_path_tmp[0]) unlink(xml_path_tmp);
  return retval;
}

int
super_serve_op_TESTS_STATEMENT_EDIT_2_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char xml_path[PATH_MAX];
  unsigned char xml_path_bak[PATH_MAX];
  unsigned char xml_path_tmp[PATH_MAX];
  problem_xml_t prob_xml = NULL;
  const unsigned char *s = NULL;
  unsigned char *text = NULL;
  int next_action = SSERV_OP_TESTS_MAIN_PAGE;

  xml_path_tmp[0] = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  if (!prob->xml_file || !prob->xml_file[0]) FAIL(S_ERR_INV_PROB_ID);
  if (cs->global->advanced_layout > 0) {
    get_advanced_layout_path(xml_path, sizeof(xml_path), cs->global, prob, prob->xml_file, variant);
  } else if (variant > 0) {
    prepare_insert_variant_num(xml_path, sizeof(xml_path), prob->xml_file, variant);
  } else {
    snprintf(xml_path, sizeof(xml_path), "%s", prob->xml_file);
  }
  snprintf(xml_path_tmp, sizeof(xml_path_tmp), "%s.tmp", xml_path);
  snprintf(xml_path_bak, sizeof(xml_path_bak), "%s.bak", xml_path);

  // xml_text
  s = NULL;
  ss_cgi_param(phr, "xml_text", &s);
  text = normalize_textarea(s);

  if (phr->opcode == SSERV_OP_TESTS_STATEMENT_EDIT_2_ACTION) {
    // save and view
    next_action = SSERV_OP_TESTS_STATEMENT_EDIT_PAGE;
  }

  write_file(xml_path_tmp, text);
  if (!need_file_update(xml_path, xml_path_tmp)) goto done;

  prob_xml = problem_xml_free(prob_xml);
  prob_xml = problem_xml_parse(log_f, xml_path_tmp);
  if (!prob_xml) FAIL(S_ERR_INV_PROB_XML);
  prob_xml = problem_xml_free(prob_xml);

  if (logged_rename(log_f, xml_path, xml_path_bak) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_rename(log_f, xml_path_tmp, xml_path) < 0) FAIL(S_ERR_FS_ERROR);
  set_cnts_file_perms(log_f, xml_path, cnts);
  xml_path_tmp[0] = 0;

done:
  ss_redirect_2(out_f, phr, next_action, contest_id, prob_id, variant, 0, NULL);

cleanup:
  xfree(text);
  problem_xml_free(prob_xml);
  if (xml_path_tmp[0]) unlink(xml_path_tmp);
  return retval;
}

int
super_serve_op_TESTS_STATEMENT_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char xml_path[PATH_MAX];
  unsigned char xml_path_bak[PATH_MAX];

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  if (!prob->xml_file || !prob->xml_file[0]) FAIL(S_ERR_INV_PROB_ID);
  if (cs->global->advanced_layout > 0) {
    get_advanced_layout_path(xml_path, sizeof(xml_path), cs->global, prob, prob->xml_file, variant);
  } else if (variant > 0) {
    prepare_insert_variant_num(xml_path, sizeof(xml_path), prob->xml_file, variant);
  } else {
    snprintf(xml_path, sizeof(xml_path), "%s", prob->xml_file);
  }
  snprintf(xml_path_bak, sizeof(xml_path_bak), "%s.bak", xml_path);

  if (logged_rename(log_f, xml_path, xml_path_bak) < 0) FAIL(S_ERR_FS_ERROR);

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  return retval;
}

int
super_serve_op_TESTS_SOURCE_HEADER_EDIT_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  const unsigned char *title = NULL;
  int action = 0, delete_action = 0;
  unsigned char tmp_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];
  unsigned char buf[1024], hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  char *file_t = NULL;
  size_t file_z = 0;
  const unsigned char *cl = NULL;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  if (phr->opcode == SSERV_OP_TESTS_SOURCE_HEADER_EDIT_PAGE) {
    file_name = prob->source_header;
    title = "source header";
    action = SSERV_OP_TESTS_SOURCE_HEADER_EDIT_ACTION;
    delete_action = SSERV_OP_TESTS_SOURCE_HEADER_DELETE_ACTION;
  } else if (phr->opcode == SSERV_OP_TESTS_SOURCE_FOOTER_EDIT_PAGE) {
    file_name = prob->source_footer;
    title = "source footer";
    action = SSERV_OP_TESTS_SOURCE_FOOTER_EDIT_ACTION;
    delete_action = SSERV_OP_TESTS_SOURCE_FOOTER_DELETE_ACTION;
  } else if (phr->opcode == SSERV_OP_TESTS_SOLUTION_EDIT_PAGE) {
    file_name = prob->solution_src;
    title = "solution";
    action = SSERV_OP_TESTS_SOLUTION_EDIT_ACTION;
    delete_action = SSERV_OP_TESTS_SOLUTION_DELETE_ACTION;
  } else {
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(file_path, sizeof(file_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(file_path, sizeof(file_path), global, prob, tmp_path, variant);
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", global->statement_dir, tmp_path);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, editing %s",
           phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name, title);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  write_file_info(out_f, file_path, title, 0);

  fprintf(out_f, "<h3>%s %s</h3>\n", title, "file");

  if (generic_read_file(&file_t, 0, &file_z, 0, NULL, file_path, "") < 0) {
    file_t = xstrdup("");
    file_z = 0;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);

  edit_file_textarea(out_f, "text", 100, 40, file_t);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_CANCEL_2_ACTION, "Cancel");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, action, "Save");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, delete_action, "Delete!");
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  xfree(file_t);
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_TESTS_SOURCE_HEADER_EDIT_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  unsigned char tmp_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];
  unsigned char file_path_tmp[PATH_MAX];
  unsigned char file_path_bak[PATH_MAX];
  const unsigned char *s = NULL;
  unsigned char *text = NULL;
  int next_action = SSERV_OP_TESTS_MAIN_PAGE;

  file_path_tmp[0] = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  if (phr->opcode == SSERV_OP_TESTS_SOURCE_HEADER_EDIT_ACTION) {
    file_name = prob->source_header;
  } else if (phr->opcode == SSERV_OP_TESTS_SOURCE_FOOTER_EDIT_ACTION) {
    file_name = prob->source_footer;
  } else if (phr->opcode == SSERV_OP_TESTS_SOLUTION_EDIT_ACTION) {
    file_name = prob->solution_src;
  } else {
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(file_path, sizeof(file_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(file_path, sizeof(file_path), global, prob, tmp_path, variant);
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", global->statement_dir, tmp_path);
  }
  snprintf(file_path_tmp, sizeof(file_path_tmp), "%s.tmp", file_path);
  snprintf(file_path_bak, sizeof(file_path_bak), "%s.bak", file_path);

  ss_cgi_param(phr, "text", &s);
  text = normalize_textarea(s);

  write_file(file_path_tmp, text);
  if (!need_file_update(file_path, file_path_tmp)) goto done;

  if (logged_rename(log_f, file_path, file_path_bak) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_rename(log_f, file_path_tmp, file_path) < 0) FAIL(S_ERR_FS_ERROR);
  set_cnts_file_perms(log_f, file_path, cnts);
  file_path_tmp[0] = 0;
  next_action = SSERV_OP_TESTS_MAKE;

done:
  ss_redirect_2(out_f, phr, next_action, contest_id, prob_id, variant, 0, NULL);

cleanup:
  if (file_path_tmp[0]) unlink(file_path_tmp);
  xfree(text);
  return retval;
}

int
super_serve_op_TESTS_SOURCE_HEADER_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  unsigned char tmp_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  if (phr->opcode == SSERV_OP_TESTS_SOURCE_HEADER_DELETE_ACTION) {
    file_name = prob->source_header;
  } else if (phr->opcode == SSERV_OP_TESTS_SOURCE_FOOTER_DELETE_ACTION) {
    file_name = prob->source_footer;
  } else if (phr->opcode == SSERV_OP_TESTS_SOLUTION_DELETE_ACTION) {
    file_name = prob->solution_src;
  } else {
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(file_path, sizeof(file_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(file_path, sizeof(file_path), global, prob, tmp_path, variant);
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", global->statement_dir, tmp_path);
  }

  if (logged_unlink(log_f, file_path) < 0) FAIL(S_ERR_FS_ERROR);

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  return retval;
}

int
super_serve_op_TESTS_CHECKER_CREATE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *title = "";
  const unsigned char *file_name = NULL;
  unsigned char tmp_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int action = 0;
  const unsigned char *cl = "";

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  switch (phr->opcode) {
  case SSERV_OP_TESTS_STYLE_CHECKER_CREATE_PAGE:
    if (!prob->style_checker_cmd || !prob->style_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Style checker";
    file_name = prob->style_checker_cmd;
    action = SSERV_OP_TESTS_STYLE_CHECKER_CREATE_ACTION;
    break;
  case SSERV_OP_TESTS_CHECKER_CREATE_PAGE:
    if (prob->standard_checker && prob->standard_checker[0]) FAIL(S_ERR_INV_OPER);
    if (!prob->check_cmd || !prob->check_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Checker";
    file_name = prob->check_cmd;
    action = SSERV_OP_TESTS_CHECKER_CREATE_ACTION;
    break;
  case SSERV_OP_TESTS_VALUER_CREATE_PAGE:
    if (!prob->valuer_cmd || !prob->valuer_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Valuer";
    file_name = prob->valuer_cmd;
    action = SSERV_OP_TESTS_VALUER_CREATE_ACTION;
    break;
  case SSERV_OP_TESTS_INTERACTOR_CREATE_PAGE:
    if (!prob->interactor_cmd || !prob->interactor_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Interactor";
    file_name = prob->interactor_cmd;
    action = SSERV_OP_TESTS_INTERACTOR_CREATE_ACTION;
    break;
  case SSERV_OP_TESTS_TEST_CHECKER_CREATE_PAGE:
    if (!prob->test_checker_cmd || !prob->test_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Test checker";
    file_name = prob->test_checker_cmd;
    action = SSERV_OP_TESTS_TEST_CHECKER_CREATE_ACTION;
    break;
  default:
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(file_path, sizeof(file_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(file_path, sizeof(file_path), global, prob, tmp_path, variant);
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", global->checker_dir, tmp_path);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, create %s",
           phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name, title);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  fprintf(out_f, "<h3>%s</h3>\n", "Choose a language");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><select name=\"language\">", cl, "Programming language", cl);
  fprintf(out_f, "<option value=\"0\"></option>");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_C, "C");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_CPP, "C++");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_JAVA, "Java");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_FPC, "Free Pascal");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_DCC, "Kylix (Delphi)");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_PY, "Python");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_PL, "Perl");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_SH, "Shell");
  fprintf(out_f, "<option value=\"%d\">%s</option>", LANG_OTHER, "Other scripting language");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"use_testlib\" value=\"1\" /></td></tr>\n",
          cl, "Use testlib (C++, FPC, DCC)", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"use_libchecker\" value=\"1\" /></td></tr>\n",
          cl, "Use libchecker (C, C++)", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"use_python3\" value=\"1\" /></td></tr>\n",
          cl, "Use python3", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"gen_makefile\" value=\"1\" /></td></tr>\n",
          cl, "Regenerate Makefile", cl);
  fprintf(out_f, "</table>\n");

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_CANCEL_2_ACTION, "Cancel");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, action, "Create");
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
create_program(
        FILE *log_f,
        const struct contest_desc *cnts,
        const unsigned char *cmd,
        int lang,
        int use_testlib,
        int use_libchecker,
        int use_python3,
        int use_corr,
        int use_info,
        int use_tgz)
{
  int retval = 0;
  FILE *out_f = NULL;
  char *out_t = NULL;
  size_t out_z = 0;
  unsigned char *compiler_path = NULL;
  const unsigned char *suffix = NULL;
  time_t current_time = time(NULL);
  unsigned char src_path[PATH_MAX];
  unsigned char src_path_tmp[PATH_MAX];
  unsigned char src_path_bak[PATH_MAX];

  src_path_tmp[0] = 0;
  src_path_bak[0] = 0;

  out_f = open_memstream(&out_t, &out_z);
  switch (lang) {
  case LANG_C:
    suffix = ".c";
    fprintf(out_f, "/* Generated %s by ejudge %s */\n\n", xml_unparse_date(current_time), compile_version);
    if (use_libchecker > 0) {
      if (use_corr > 0) {
        fprintf(out_f, "#define NEED_CORR 1\n");
      }
      if (use_info > 0) {
        fprintf(out_f, "#define NEED_INFO 1\n");
      }
      if (use_tgz > 0) {
        fprintf(out_f, "#define NEED_TGZ 1\n");
      }
      fprintf(out_f, "#include \"checker.h\"\n\n");
      fprintf(out_f,
              "int\n"
              "checker_main(int argc, char *argv[])\n"
              "{\n"
              "    checker_OK();\n"
              "}\n");
    } else {
      fprintf(out_f,
              "int\n"
              "main(int argc, char *argv[])\n"
              "{\n"
              "    return 0;\n"
              "}\n");
    }
    break;
  case LANG_CPP:
    suffix = ".cpp";
    fprintf(out_f, "/* Generated %s by ejudge %s */\n\n", xml_unparse_date(current_time), compile_version);
    if (use_libchecker > 0) {
      if (use_corr > 0) {
        fprintf(out_f, "#define NEED_CORR 1\n");
      }
      if (use_info > 0) {
        fprintf(out_f, "#define NEED_INFO 1\n");
      }
      if (use_tgz > 0) {
        fprintf(out_f, "#define NEED_TGZ 1\n");
      }
      fprintf(out_f, "#include \"checker.h\"\n\n");
      fprintf(out_f,
              "int\n"
              "checker_main(int argc, char *argv[])\n"
              "{\n"
              "    checker_OK();\n"
              "}\n");
    } else if (use_testlib > 0) {
      fprintf(out_f, "#include \"testlib.h\"\n\n");
      fprintf(out_f,
              "int\n"
              "main(int argc, char *argv[])\n"
              "{\n"
              "    return 0;\n"
              "}\n");
    } else {
      fprintf(out_f,
              "int\n"
              "main(int argc, char *argv[])\n"
              "{\n"
              "    return 0;\n"
              "}\n");
    }
    break;
  case LANG_JAVA:
    suffix = ".java";
    fprintf(out_f, "/* Generated %s by ejudge %s */\n\n", xml_unparse_date(current_time), compile_version);
    break;
  case LANG_FPC:
    suffix = ".pas";
    fprintf(out_f, "{ Generated %s by ejudge %s }\n\n", xml_unparse_date(current_time), compile_version);
    break;
  case LANG_DCC:
    suffix = ".dpr";
    fprintf(out_f, "{ Generated %s by ejudge %s }\n\n", xml_unparse_date(current_time), compile_version);
    break;
  case LANG_PY:
    if (use_python3) {
      compiler_path = get_compiler_path(log_f, NULL, NULL, "python3");
      if (compiler_path == NULL) compiler_path = xstrdup("/usr/bin/python3");
    } else {
      compiler_path = get_compiler_path(log_f, NULL, NULL, "python");
      if (compiler_path == NULL) compiler_path = xstrdup("/usr/bin/python");
    }
    suffix = ".py";
    fprintf(out_f, "#! %s\n\n", compiler_path);
    fprintf(out_f, "# Generated %s by ejudge %s\n\n", xml_unparse_date(current_time), compile_version);
    break;
  case LANG_PL:
    compiler_path = get_compiler_path(log_f, NULL, NULL, "perl");
    if (compiler_path == NULL) compiler_path = xstrdup("/usr/bin/perl");
    suffix = ".pl";
    fprintf(out_f, "#! %s\n\n", compiler_path);
    fprintf(out_f, "# Generated %s by ejudge %s\n\n", xml_unparse_date(current_time), compile_version);
    break;
  case LANG_SH:
    compiler_path = xstrdup("/bin/sh");
    suffix = ".sh";
    fprintf(out_f, "#! %s\n\n", compiler_path);
    fprintf(out_f, "# Generated %s by ejudge %s\n\n", xml_unparse_date(current_time), compile_version);
    break;
  case LANG_OTHER:
  default:
    fprintf(log_f, "Unsupported language %d\n", lang);
    FAIL(S_ERR_INV_VALUE);
  }
  fclose(out_f); out_f = NULL;

  if (!out_z) {
    fprintf(log_f, "Generated source file is empty\n");
    FAIL(S_ERR_INV_VALUE);
  }

  snprintf(src_path, sizeof(src_path), "%s%s", cmd, suffix);
  snprintf(src_path_tmp, sizeof(src_path_tmp), "%s.tmp", src_path);
  snprintf(src_path_bak, sizeof(src_path_bak), "%s.bak", src_path);

  write_file(src_path_tmp, out_t);
  if (!need_file_update(src_path, src_path_tmp)) goto cleanup;

  if (logged_rename(log_f, src_path, src_path_bak) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_rename(log_f, src_path_tmp, src_path) < 0) FAIL(S_ERR_FS_ERROR);
  set_cnts_file_perms(log_f, src_path, cnts);
  src_path_tmp[0] = 0;

cleanup:
  if (src_path_tmp[0]) unlink(src_path_tmp);
  if (out_f) fclose(out_f);
  xfree(out_t);
  xfree(compiler_path);
  return retval;
}

int
super_serve_op_TESTS_CHECKER_CREATE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  int language = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  int use_testlib = 0;
  int use_libchecker = 0;
  int use_python3 = 0;
  int gen_makefile = 0;
  int i;
  const unsigned char *file_name = NULL;
  int action = 0;
  unsigned char tmp_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  ss_cgi_param_int_opt(phr, "language", &language, 0);
  if (language <= 0) FAIL(S_ERR_INV_LANG_ID);
  for (i = 0; source_suffixes[i].mask; ++i) {
    if (language == source_suffixes[i].mask)
      break;
  }
  if (!source_suffixes[i].mask) FAIL(S_ERR_INV_LANG_ID);

  ss_cgi_param_int_opt(phr, "use_testlib", &use_testlib, 0);
  if (use_testlib != 1) use_testlib = 0;
  ss_cgi_param_int_opt(phr, "use_libchecker", &use_libchecker, 0);
  if (use_libchecker != 1) use_libchecker = 0;
  ss_cgi_param_int_opt(phr, "use_python3", &use_python3, 0);
  if (use_python3 != 1) use_python3 = 0;
  ss_cgi_param_int_opt(phr, "gen_makefile", &gen_makefile, 0);
  if (gen_makefile != 1) gen_makefile = 0;

  switch (phr->opcode) {
  case SSERV_OP_TESTS_STYLE_CHECKER_CREATE_ACTION:
    if (!prob->style_checker_cmd || !prob->style_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->style_checker_cmd;
    action = SSERV_OP_TESTS_STYLE_CHECKER_EDIT_PAGE;
    break;
  case SSERV_OP_TESTS_CHECKER_CREATE_ACTION:
    if (prob->standard_checker && prob->standard_checker[0]) FAIL(S_ERR_INV_OPER);
    if (!prob->check_cmd || !prob->check_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->check_cmd;
    action = SSERV_OP_TESTS_CHECKER_EDIT_PAGE;
    break;
  case SSERV_OP_TESTS_VALUER_CREATE_ACTION:
    if (!prob->valuer_cmd || !prob->valuer_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->valuer_cmd;
    action = SSERV_OP_TESTS_VALUER_EDIT_PAGE;
    break;
  case SSERV_OP_TESTS_INTERACTOR_CREATE_ACTION:
    if (!prob->interactor_cmd || !prob->interactor_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->interactor_cmd;
    action = SSERV_OP_TESTS_INTERACTOR_EDIT_PAGE;
    break;
  case SSERV_OP_TESTS_TEST_CHECKER_CREATE_ACTION:
    if (!prob->test_checker_cmd || !prob->test_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->test_checker_cmd;
    action = SSERV_OP_TESTS_TEST_CHECKER_EDIT_PAGE;
    break;
  default:
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(file_path, sizeof(file_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(file_path, sizeof(file_path), global, prob, tmp_path, variant);
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", global->checker_dir, tmp_path);
  }

  retval = create_program(log_f, cnts, file_path, language,
                          use_testlib, use_libchecker,
                          use_python3, prob->use_corr,
                          prob->use_info, prob->use_tgz);

  ss_redirect_2(out_f, phr, action, contest_id, prob_id, variant, 0, NULL);

cleanup:
  return retval;
}

static void
test_checker_edit_page_actions(FILE *out_f, int action, int delete_page)
{
  const unsigned char *cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, SSERV_OP_TESTS_CANCEL_2_ACTION, "Cancel");
  if (action > 0) {
    fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, action, "Save");
  }
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
          cl, delete_page, "Delete");
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");
}

int
super_serve_op_TESTS_CHECKER_EDIT_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  int action = 0;
  int create_page = 0;
  int delete_page = 0;
  const unsigned char *title = NULL;
  unsigned char tmp_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];
  unsigned char src_file_path[PATH_MAX];
  unsigned long langs = 0;
  int count = 0;
  int i;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[1024], hbuf[1024];
  struct stat stb;
  char *text = 0;
  size_t size = 0;
  const unsigned char *src_suffix = NULL;
  int is_binary = 0;
  const unsigned char *src_code_title = "";

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  switch (phr->opcode) {
  case SSERV_OP_TESTS_STYLE_CHECKER_EDIT_PAGE:
    if (!prob->style_checker_cmd || !prob->style_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Style checker";
    file_name = prob->style_checker_cmd;
    create_page = SSERV_OP_TESTS_STYLE_CHECKER_CREATE_PAGE;
    action = SSERV_OP_TESTS_STYLE_CHECKER_EDIT_ACTION;
    delete_page = SSERV_OP_TESTS_STYLE_CHECKER_DELETE_PAGE;
    break;
  case SSERV_OP_TESTS_CHECKER_EDIT_PAGE:
    if (prob->standard_checker && prob->standard_checker[0]) FAIL(S_ERR_INV_OPER);
    if (!prob->check_cmd || !prob->check_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Checker";
    file_name = prob->check_cmd;
    create_page = SSERV_OP_TESTS_CHECKER_CREATE_PAGE;
    action = SSERV_OP_TESTS_CHECKER_EDIT_ACTION;
    delete_page = SSERV_OP_TESTS_CHECKER_DELETE_PAGE;
    break;
  case SSERV_OP_TESTS_VALUER_EDIT_PAGE:
    if (!prob->valuer_cmd || !prob->valuer_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Valuer";
    file_name = prob->valuer_cmd;
    create_page = SSERV_OP_TESTS_VALUER_CREATE_PAGE;
    action = SSERV_OP_TESTS_VALUER_EDIT_ACTION;
    delete_page = SSERV_OP_TESTS_VALUER_DELETE_PAGE;
    break;
  case SSERV_OP_TESTS_INTERACTOR_EDIT_PAGE:
    if (!prob->interactor_cmd || !prob->interactor_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Interactor";
    file_name = prob->interactor_cmd;
    create_page = SSERV_OP_TESTS_INTERACTOR_CREATE_PAGE;
    action = SSERV_OP_TESTS_INTERACTOR_EDIT_ACTION;
    delete_page = SSERV_OP_TESTS_INTERACTOR_DELETE_PAGE;
    break;
  case SSERV_OP_TESTS_TEST_CHECKER_EDIT_PAGE:
    if (!prob->test_checker_cmd || !prob->test_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    title = "Test checker";
    file_name = prob->test_checker_cmd;
    create_page = SSERV_OP_TESTS_TEST_CHECKER_CREATE_PAGE;
    action = SSERV_OP_TESTS_TEST_CHECKER_EDIT_ACTION;
    delete_page = SSERV_OP_TESTS_TEST_CHECKER_DELETE_PAGE;
    break;
  default:
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(file_path, sizeof(file_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(file_path, sizeof(file_path), global, prob, tmp_path, variant);
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", global->checker_dir, tmp_path);
  }

  snprintf(tmp_path, sizeof(tmp_path), "%s", file_path);
  langs = guess_language_by_cmd(tmp_path, &count);

  if (count <= 0 && access(file_path, F_OK) < 0) {
    ss_redirect_2(out_f, phr, create_page, contest_id, prob_id, variant, 0, NULL);
    goto cleanup;
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, edit %s",
           phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name, title);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);

  if (count > 1) {
    fprintf(out_f, "<h2>Several source files are detected for %s</h2>\n", title);
    fprintf(out_f, "<pre>");
    for (i = 0; source_suffixes[i].suffix; ++i) {
      snprintf(file_path, sizeof(file_path), "%s%s", tmp_path, source_suffixes[i].suffix);
      if (access(file_path, R_OK) >= 0 && stat(file_path, &stb) >= 0 && S_ISREG(stb.st_mode)) {
        fprintf(out_f, "%s\n", ARMOR(file_path));
      }
    }
    fprintf(out_f, "</pre\n");
    test_checker_edit_page_actions(out_f, 0, delete_page);
    goto done;
  }

  if (count == 0 && access(file_path, F_OK) >= 0) {
    if (generic_read_file(&text, 0, &size, 0, 0, file_path, 0) < 0 || !text) {
      fprintf(out_f, "<h2>File is not readable for %s</h2>\n", title);
      fprintf(out_f, "<p>Failed to read file %s.</p>", ARMOR(file_path));
      test_checker_edit_page_actions(out_f, 0, delete_page);
      goto done;
    }
    if (is_binary_file(text, size)) {
      fprintf(out_f, "<h2>Can't do anything with binary file for %s</h2>\n", title);
      fprintf(out_f, "<p>File %s is binary.</p>", ARMOR(file_path));
      test_checker_edit_page_actions(out_f, 0, delete_page);
      goto done;
    }
    html_hidden(out_f, "no_source", "%d", 1);
    snprintf(src_file_path, sizeof(src_file_path), "%s", file_path);
  } else {
    src_suffix = get_source_suffix(langs);
    if (!src_suffix) {
      fprintf(out_f, "<h2>Invalid language mask %lu for %s</h2>\n", langs, title);
      test_checker_edit_page_actions(out_f, 0, delete_page);
      goto done;
    }
    html_hidden(out_f, "lang_mask", "%lu", langs);
    snprintf(src_file_path, sizeof(src_file_path), "%s%s", file_path, src_suffix);
    if (generic_read_file(&text, 0, &size, 0, 0, src_file_path, 0) >= 0 && text
        && is_binary_file(text, size)) {
      is_binary = 1;
    }
    src_code_title = " source code";
  }

  write_file_info(out_f, src_file_path, title, is_binary);
  fprintf(out_f, "<h3>Edit %s%s</h3>", title, src_code_title);
  edit_file_textarea(out_f, "text", 100, 40, text);
  test_checker_edit_page_actions(out_f, action, delete_page);

done:
  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  xfree(text);
  return retval;
}

int
super_serve_op_TESTS_CHECKER_EDIT_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  unsigned char tmp_path[PATH_MAX];
  unsigned char tmp2_path[PATH_MAX];
  unsigned char file_path[PATH_MAX];
  unsigned char file_path_tmp[PATH_MAX];
  unsigned char file_path_bak[PATH_MAX];
  int no_source = 0;
  int lang_mask = 0;
  unsigned char *text = NULL;
  const unsigned char *src_suffix = NULL, *s = NULL;
  int next_action = SSERV_OP_TESTS_MAIN_PAGE;

  file_path_tmp[0] = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  switch (phr->opcode) {
  case SSERV_OP_TESTS_STYLE_CHECKER_EDIT_ACTION:
    if (!prob->style_checker_cmd || !prob->style_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->style_checker_cmd;
    break;
  case SSERV_OP_TESTS_CHECKER_EDIT_ACTION:
    if (prob->standard_checker && prob->standard_checker[0]) FAIL(S_ERR_INV_OPER);
    if (!prob->check_cmd || !prob->check_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->check_cmd;
    break;
  case SSERV_OP_TESTS_VALUER_EDIT_ACTION:
    if (!prob->valuer_cmd || !prob->valuer_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->valuer_cmd;
    break;
  case SSERV_OP_TESTS_INTERACTOR_EDIT_ACTION:
    if (!prob->interactor_cmd || !prob->interactor_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->interactor_cmd;
    break;
  case SSERV_OP_TESTS_TEST_CHECKER_EDIT_PAGE:
    if (!prob->test_checker_cmd || !prob->test_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->test_checker_cmd;
    break;
  default:
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(tmp2_path, sizeof(tmp2_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(tmp2_path, sizeof(tmp2_path), global, prob, tmp_path, variant);
  } else {
    snprintf(tmp2_path, sizeof(tmp2_path), "%s/%s", global->checker_dir, tmp_path);
  }

  ss_cgi_param_int_opt(phr, "no_source", &no_source, 0);
  if (no_source != 1) no_source = 0;
  if (!no_source) {
    ss_cgi_param_int_opt(phr, "lang_mask", &lang_mask, 0);
    src_suffix = get_source_suffix(lang_mask);
    if (!src_suffix) FAIL(S_ERR_INV_LANG_ID);
    snprintf(file_path, sizeof(file_path), "%s%s", tmp2_path, src_suffix);
  } else {
    snprintf(file_path, sizeof(file_path), "%s", tmp2_path);
  }

  snprintf(file_path_tmp, sizeof(file_path_tmp), "%s.tmp", file_path);
  snprintf(file_path_bak, sizeof(file_path_bak), "%s.bak", file_path);

  ss_cgi_param(phr, "text", &s);
  text = normalize_textarea(s);

  write_file(file_path_tmp, text);
  if (!need_file_update(file_path, file_path_tmp)) goto done;

  if (logged_rename(log_f, file_path, file_path_bak) < 0) FAIL(S_ERR_FS_ERROR);
  if (logged_rename(log_f, file_path_tmp, file_path) < 0) FAIL(S_ERR_FS_ERROR);
  set_cnts_file_perms(log_f, file_path, cnts);
  file_path_tmp[0] = 0;
  next_action = SSERV_OP_TESTS_MAKE;

done:
  ss_redirect_2(out_f, phr, next_action, contest_id, prob_id, variant, 0, NULL);

cleanup:
  xfree(text);
  if (file_path_tmp[0]) unlink(file_path_tmp);
  return retval;
}

static void
strip_known_exe_suffixes(char *str)
{
  int len, i;

  if (str == NULL) return;
  len = strlen(str);
  for (i = len - 1; i >= 0 && str[i] != '.' && str[i] != '/'; --i) {}
  if (i <= 0 || str[i] != '.' || str[i - 1] == '/') return;
  if (!strcmp(str + i, ".class") || !strcmp(str + i, ".jar") || !strcmp(str + i, ".exe")) {
    str[i] = 0;
  }
}

static void
write_ls_like_line(FILE *out_f, const unsigned char *name, struct stat *stb)
{
  static const unsigned char *all_modes = "rwxrwxrwx";
  int mode = stb->st_mode & 0777;
  int bit = 0400;
  int i = 0;
  for (; bit > 0; bit >>= 1, ++i) {
    if ((mode & bit) != 0) {
      putc(all_modes[i], out_f);
    } else {
      putc('-', out_f);
    }
  }
  fprintf(out_f, " %4d", (int) stb->st_nlink);
  struct passwd *ui = getpwuid(stb->st_uid);
  if (!ui) {
    fprintf(out_f, " %10d", stb->st_uid);
  } else {
    fprintf(out_f, " %10s", ui->pw_name);
  }
  struct group *gi = getgrgid(stb->st_gid);
  if (!gi) {
    fprintf(out_f, " %10d", stb->st_gid);
  } else {
    fprintf(out_f, " %10s", gi->gr_name);
  }
  fprintf(out_f, " %16lld", (long long) stb->st_size);
  fprintf(out_f, " %s", xml_unparse_date(stb->st_mtime));
  fprintf(out_f, " %s\n", name);
}

int
super_serve_op_TESTS_CHECKER_DELETE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  unsigned char tmp_path[PATH_MAX];
  unsigned char tmp2_path[PATH_MAX];
  unsigned char *dirname = NULL;
  unsigned char *lastname = NULL;
  int action = 0;
  FILE *lst_f = NULL;
  char *lst_t = NULL;
  size_t lst_z = 0;
  int count = 0;
  DIR *d = NULL;
  struct dirent *dd;
  struct stat stb;
  int lastname_len, len;
  unsigned char buf[1024], hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *title = NULL;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  switch (phr->opcode) {
  case SSERV_OP_TESTS_STYLE_CHECKER_DELETE_PAGE:
    if (!prob->style_checker_cmd || !prob->style_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->style_checker_cmd;
    action = SSERV_OP_TESTS_STYLE_CHECKER_DELETE_ACTION;
    title = "Style checker";
    break;
  case SSERV_OP_TESTS_CHECKER_DELETE_PAGE:
    if (prob->standard_checker && prob->standard_checker[0]) FAIL(S_ERR_INV_OPER);
    if (!prob->check_cmd || !prob->check_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->check_cmd;
    action = SSERV_OP_TESTS_CHECKER_DELETE_ACTION;
    title = "Checker";
    break;
  case SSERV_OP_TESTS_VALUER_DELETE_PAGE:
    if (!prob->valuer_cmd || !prob->valuer_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->valuer_cmd;
    action = SSERV_OP_TESTS_VALUER_DELETE_ACTION;
    title = "Valuer";
    break;
  case SSERV_OP_TESTS_INTERACTOR_DELETE_PAGE:
    if (!prob->interactor_cmd || !prob->interactor_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->interactor_cmd;
    action = SSERV_OP_TESTS_INTERACTOR_DELETE_ACTION;
    title = "Interactor";
    break;
  case SSERV_OP_TESTS_TEST_CHECKER_DELETE_PAGE:
    if (!prob->test_checker_cmd || !prob->test_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->test_checker_cmd;
    action = SSERV_OP_TESTS_TEST_CHECKER_DELETE_ACTION;
    title = "Test checker";
    break;
  default:
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(tmp2_path, sizeof(tmp2_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(tmp2_path, sizeof(tmp2_path), global, prob, tmp_path, variant);
  } else {
    snprintf(tmp2_path, sizeof(tmp2_path), "%s/%s", global->checker_dir, tmp_path);
  }

  strip_known_exe_suffixes(tmp2_path);
  dirname = os_DirName(tmp2_path);
  if (!dirname || !*dirname) {
    FAIL(S_ERR_FS_ERROR);
  }
  lastname = os_GetLastname(tmp2_path);
  lastname_len = strlen(lastname);
  if (!lastname || !*lastname) {
    FAIL(S_ERR_FS_ERROR);
  }

  d = opendir(dirname);
  if (!d) FAIL(S_ERR_FS_ERROR);
  lst_f = open_memstream(&lst_t, &lst_z);
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    len = strlen(dd->d_name);
    if (len < lastname_len || strncmp(dd->d_name, lastname, lastname_len) != 0) continue;
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dirname, dd->d_name);
    if (stat(tmp_path, &stb) < 0 || !S_ISREG(stb.st_mode)) continue;
    write_ls_like_line(lst_f, dd->d_name, &stb);
    ++count;
  }
  fclose(lst_f); lst_f = 0;
  closedir(d); d = NULL;

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, delete %s",
           phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name, title);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
  html_hidden(out_f, "variant", "%d", variant);

  fprintf(out_f, "<h3>The following %d files to be deleted</h3>\n", count);
  fprintf(out_f, "<pre>%s</pre>\n", ARMOR(lst_t));

  test_checker_edit_page_actions(out_f, 0, action);
  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  if (d) closedir(d);
  xfree(lst_t);
  if (lst_f) fclose(lst_f);
  xfree(lastname);
  xfree(dirname);
  return retval;
}

int
super_serve_op_TESTS_CHECKER_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *file_name = NULL;
  unsigned char tmp_path[PATH_MAX], tmp2_path[PATH_MAX];
  unsigned char *dirname = NULL;
  unsigned char *lastname = NULL;
  int lastname_len, len;
  DIR *d = NULL;
  struct dirent *dd = NULL;
  struct stat stb;
  int files_u = 0, files_a = 0;
  unsigned char **files = NULL;
  int i;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  switch (phr->opcode) {
  case SSERV_OP_TESTS_STYLE_CHECKER_DELETE_ACTION:
    if (!prob->style_checker_cmd || !prob->style_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->style_checker_cmd;
    break;
  case SSERV_OP_TESTS_CHECKER_DELETE_ACTION:
    if (prob->standard_checker && prob->standard_checker[0]) FAIL(S_ERR_INV_OPER);
    if (!prob->check_cmd || !prob->check_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->check_cmd;
    break;
  case SSERV_OP_TESTS_VALUER_DELETE_ACTION:
    if (!prob->valuer_cmd || !prob->valuer_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->valuer_cmd;
    break;
  case SSERV_OP_TESTS_INTERACTOR_DELETE_ACTION:
    if (!prob->interactor_cmd || !prob->interactor_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->interactor_cmd;
    break;
  case SSERV_OP_TESTS_TEST_CHECKER_DELETE_ACTION:
    if (!prob->test_checker_cmd || !prob->test_checker_cmd[0]) FAIL(S_ERR_INV_OPER);
    file_name = prob->test_checker_cmd;
    break;
  default:
    FAIL(S_ERR_INV_OPER);
  }

  if (!file_name || !file_name) FAIL(S_ERR_INV_PROB_ID);
  sformat_message(tmp_path, sizeof(tmp_path), 0, file_name, global, prob, NULL, 0, 0, 0, 0, 0);
  if (os_IsAbsolutePath(tmp_path)) {
    snprintf(tmp2_path, sizeof(tmp2_path), "%s", tmp_path);
  } else if (global->advanced_layout > 0) {
    get_advanced_layout_path(tmp2_path, sizeof(tmp2_path), global, prob, tmp_path, variant);
  } else {
    snprintf(tmp2_path, sizeof(tmp2_path), "%s/%s", global->checker_dir, tmp_path);
  }

  strip_known_exe_suffixes(tmp2_path);
  dirname = os_DirName(tmp2_path);
  if (!dirname || !*dirname) {
    FAIL(S_ERR_FS_ERROR);
  }
  lastname = os_GetLastname(tmp2_path);
  lastname_len = strlen(lastname);
  if (!lastname || !*lastname) {
    FAIL(S_ERR_FS_ERROR);
  }

  d = opendir(dirname);
  if (!d) FAIL(S_ERR_FS_ERROR);
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    len = strlen(dd->d_name);
    if (len < lastname_len || strncmp(dd->d_name, lastname, lastname_len) != 0) continue;
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dirname, dd->d_name);
    if (stat(tmp_path, &stb) < 0 || !S_ISREG(stb.st_mode)) continue;
    if (files_u == files_a) {
      if (!files_a) files_a = 16;
      files = xrealloc(files, (files_a *= 2) * sizeof(files[0]));
    }
    files[files_u++] = xstrdup(dd->d_name);
  }
  closedir(d); d = NULL;

  for (i = 0; i < files_u; ++i) {
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dirname, files[i]);
    unlink(tmp_path);
  }

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0, NULL);

cleanup:
  if (d) closedir(d);
  xfree(dirname);
  xfree(lastname);
  return retval;
}

static void
write_pre(FILE *f, int status, const unsigned char *txt)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *font1 = "";
  const unsigned char *font2 = "";
  if (!txt) {
    status = 0;
    txt = "";
  }
  if (status < 0) {
    font1 = "<font color=\"red\">";
    font2 = "</font>";
  }
  fprintf(f, "<pre>%s%s%s</pre>", font1, ARMOR(txt), font2);
  html_armor_free(&ab);
}

struct tests_make_context
{
  FILE *start_f;
  char *start_t;
  size_t start_z;
  struct super_http_request_info *phr;
};

static void
super_serve_op_TESTS_MAKE_continuation(struct background_process *);

int
super_serve_op_TESTS_MAKE(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  int prob_id = 0;
  int variant = 0;
  const struct contest_desc *cnts = NULL;
  opcap_t caps = 0LL;
  serve_state_t cs = NULL;
  const struct section_global_data *global = NULL;
  const struct section_problem_data *prob = NULL;
  unsigned char prob_dir[PATH_MAX];
  unsigned char makefile_path[PATH_MAX];
  unsigned char buf[1024], hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct stat stb;
  struct tests_make_context *cntx = NULL;
  unsigned char prefix_buf[4096];
  unsigned char home_buf[4096];
  unsigned char local_buf[4096];

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level < PRIV_LEVEL_JUDGE) FAIL(S_ERR_PERM_DENIED);
  get_full_caps(phr, cnts, &caps);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) FAIL(S_ERR_PERM_DENIED);

  retval = check_other_editors(log_f, out_f, phr, contest_id, cnts);
  if (retval <= 0) goto cleanup;
  retval = 0;
  cs = phr->ss->te_state;
  global = cs->global;

  ss_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id <= 0 || prob_id > cs->max_prob) FAIL(S_ERR_INV_PROB_ID);
  if (!(prob = cs->probs[prob_id])) FAIL(S_ERR_INV_PROB_ID);

  variant = -1;
  if (prob->variant_num > 0) {
    ss_cgi_param_int_opt(phr, "variant", &variant, 0);
    if (variant <= 0 || variant > prob->variant_num) FAIL(S_ERR_INV_VARIANT);
  }

  if (global->advanced_layout <= 0) FAIL(S_ERR_INV_CONTEST);
  get_advanced_layout_path(prob_dir, sizeof(prob_dir), global, prob, NULL, variant);
  snprintf(makefile_path, sizeof(makefile_path), "%s/%s", prob_dir, "Makefile");

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d (%s), problem %s, running make",
           phr->html_name, contest_id, ARMOR(cnts->name), prob->short_name);
  ss_write_html_header(out_f, phr, buf, 0, NULL);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_MAIN_PAGE, contest_id),
          "Problems page");
  fprintf(out_f, "</ul>\n");

  write_problem_editing_links(out_f, phr, contest_id, prob_id, variant, global, prob);

  fprintf(out_f, "<h2>%s</h2>\n", "Running make");

  if (stat(prob_dir, &stb) < 0 || !S_ISDIR(stb.st_mode)) {
    snprintf(buf, sizeof(buf), "Path %s does not exist or not a directory", prob_dir);
    write_pre(out_f, -1, buf);
    goto done;
  }
  if (access(makefile_path, R_OK) < 0) {
    snprintf(buf, sizeof(buf), "Makefile %s does not exist or is not readable", makefile_path);
    write_pre(out_f, -1, buf);
    goto done;
  }

  struct background_process *prc = super_serve_find_process("make");
  if (prc) {
    snprintf(buf, sizeof(buf), "Another make is running on this server");
    write_pre(out_f, -1, buf);
    goto done;
  }

  char *args[16];
  int argc = 0;

  args[argc++] = MAKE_PATH;
  snprintf(prefix_buf, sizeof(prefix_buf), "EJUDGE_PREFIX_DIR=%s", EJUDGE_PREFIX_DIR);
  args[argc++] = prefix_buf;
  snprintf(home_buf, sizeof(home_buf), "EJUDGE_CONTESTS_HOME_DIR=%s", EJUDGE_CONTESTS_HOME_DIR);
  args[argc++] = home_buf;
#if defined EJUDGE_LOCAL_DIR
  snprintf(local_buf, sizeof(local_buf), "EJUDGE_LOCAL_DIR=%s", EJUDGE_LOCAL_DIR);
  args[argc++] = local_buf;
#endif
  args[argc++] = "all";
  args[argc] = NULL;

  XCALLOC(cntx, 1);
  cntx->start_f = open_memstream(&cntx->start_t, &cntx->start_z);
  cntx->phr = phr;

  for (int i = 0; args[i]; ++i)
    fprintf(cntx->start_f, "%s ", args[i]);
  fprintf(cntx->start_f, "\n");

  prc = ejudge_start_process(cntx->start_f, "make", args, NULL, prob_dir, NULL, 1, 30000,
                             super_serve_op_TESTS_MAKE_continuation, cntx);
  if (!prc) {
    fclose(cntx->start_f); cntx->start_f = NULL;
    write_pre(out_f, -1, cntx->start_t);
    goto done;
  }
  fprintf(cntx->start_f, "%s: %s.%04d\n", "Start time", xml_unparse_date(prc->start_time_ms / 1000),
          (int) (prc->start_time_ms % 1000));
          
  cntx = NULL;
  phr->suspend_reply = 1;
  super_serve_register_process(prc);
  goto cleanup;

done:
  ss_write_html_footer(out_f);

cleanup:
  if (cntx) {
    if (cntx->start_f) fclose(cntx->start_f);
    xfree(cntx->start_t);
  }
  xfree(cntx);
  html_armor_free(&ab);
  return retval;
}

static void
super_serve_op_TESTS_MAKE_continuation(struct background_process *prc)
{
  ASSERT(prc);
  ASSERT(prc->state = BACKGROUND_PROCESS_FINISHED);

  struct tests_make_context *cntx = (typeof(cntx)) prc->user;
  int status_ok = -1;
  struct super_http_request_info *phr = cntx->phr;
  cntx->phr = NULL;

  fprintf(cntx->start_f, "%s", prc->out.buf);

  fprintf(cntx->start_f, "%s: %s.%04d\n", "Stop time", xml_unparse_date(prc->stop_time_ms / 1000),
          (int) (prc->stop_time_ms % 1000));
  if (prc->is_exited && !prc->exit_code) status_ok = 0;
  if (prc->is_exited) {
    fprintf(cntx->start_f, "Process exited with code %d\n", prc->exit_code);
  } else if (prc->is_signaled) {
    fprintf(cntx->start_f, "Process terminated with signal %d (%s)\n", prc->term_signal,
            os_GetSignalString(prc->term_signal));
  } else {
    fprintf(cntx->start_f, "!!! Process did not exit nor it was signaled!\n");
  }
  fprintf(cntx->start_f, "User: %lld ms\n", prc->utime_ms);
  fprintf(cntx->start_f, "System: %lld ms\n", prc->stime_ms);
  fprintf(cntx->start_f, "Max RSS: %ld KiB\n", prc->maxrss);

  if (cntx->start_f) fclose(cntx->start_f);
  cntx->start_f = NULL;

  write_pre(phr->out_f, status_ok, cntx->start_t);
  ss_write_html_footer(phr->out_f);
  xfree(cntx->start_t); cntx->start_t = NULL; cntx->start_z = 0;
  xfree(cntx); prc->user = NULL;
  prc->continuation = NULL;
  prc->state = BACKGROUND_PROCESS_GARBAGE;
  phr->continuation(phr);
}
