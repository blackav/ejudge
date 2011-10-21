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

#include "reuse_xalloc.h"
#include "reuse_osdeps.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

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
        int test_num)
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

  phr->ss->te_state = serve_state_destroy(cs, cnts, NULL);

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
  phr->ss->te_state = serve_state_destroy(cs, cnts, NULL);
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
        fprintf(out_f, "<td%s><font size=\"-1\"><pre>%s</pre></font></td>", cl, ARMOR(prb_t));
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
        fprintf(out_f, "<td%s>%s%s</a></td>",
                cl, 
                html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                              NULL, "action=%d&amp;op=%d&amp;contest_id=%d&amp;variant=%d&amp;prob_id=%d",
                              SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_MAKEFILE_EDIT_PAGE,
                              contest_id, variant, prob_id),
                "Edit");
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
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0);

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
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0);

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
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d&prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id),
          "Tests page");
  fprintf(out_f, "</ul>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
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
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_DOWNLOAD, contest_id, prob_id, test_num, 1),
              "Download file");
      fprintf(out_f, "<td%s>%s%s</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_UPLOAD_PAGE, contest_id, prob_id, test_num, 1),
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
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_DOWNLOAD, contest_id, prob_id, test_num, 2),
              "Download file");
      fprintf(out_f, "<td%s>%s%s</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                            "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d&amp;file_type=%d",
                            SSERV_CMD_HTTP_REQUEST,
                            SSERV_OP_TESTS_TEST_UPLOAD_PAGE, contest_id, prob_id, test_num, 2),
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
                          "action=%d&amp;op=%d&amp;contest_id=%d&amp;prob_id=%d&amp;test_num=%d&amp;file_type=%d",
                          SSERV_CMD_HTTP_REQUEST,
                          SSERV_OP_TESTS_TEST_CLEAR_INF_ACTION, contest_id, prob_id, test_num, 3),
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

  ss_redirect_2(out_f, phr, next_op, contest_id, prob_id, variant, 0);

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

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0);

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
                        "action=%d&op=%d&contest_id=%d&prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id),
          "Tests page");
  fprintf(out_f, "</ul>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);
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

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id, variant, 0);

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
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d&prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id),
          "Tests page");
  fprintf(out_f, "</ul>\n");

  fprintf(out_f, "<h3>%s</h3>\n", "Config parameters");

  fprintf(out_f, "<pre>%s</pre>\n", ARMOR(prb_t));

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_hidden(out_f, "prob_id", "%d", prob_id);

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
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0);

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

  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAIN_PAGE, contest_id, prob_id, variant, 0);

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
guess_language_by_cmd(unsigned char *cmd)
{
  int len, i;
  unsigned char path2[PATH_MAX];
  struct stat stb;

  if (!cmd || !*cmd) return 0;
  len = strlen(cmd);
  i = len - 1;
  while (i >= 0 && cmd[i] != '/' && cmd[i] != '.') --i;
  if (i >= 0 && cmd[i] == '.') {
    if (!strcmp(cmd + i, ".class") || !strcmp(cmd + i, ".jar")) return LANG_JAVA;
    if (!strcmp(cmd + i, ".exe")) {
      if (i > 0 && cmd[i - 1] != '/' && cmd[i - 1] != '.') {
        cmd[i] = 0;
      }
    }
  }
  for (i = 0; source_suffixes[i].suffix; ++i) {
    snprintf(path2, sizeof(path2), "%s%s", cmd, source_suffixes[i].suffix);
    if (access(path2, R_OK) >= 0 && stat(path2, &stb) >= 0 && S_ISREG(stb.st_mode)) {
      return source_suffixes[i].mask;
    }
  }
  return 0;
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

  if (!cmd || !cmd[0]) return;
  get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, cmd, variant);
  languages = guess_language_by_cmd(tmp_path);
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
    languages |= guess_language_by_cmd(tmp_path);
  }
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->valuer_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path);
  }
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->interactor_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path);
  }
  if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->style_checker_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path);
  }
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->test_checker_cmd, variant);
    languages |= guess_language_by_cmd(tmp_path);
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
    languages |= guess_language_by_cmd(tmp_path);
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
      languages = guess_language_by_cmd(tmp_path);
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
  ss_redirect_2(out_f, phr, SSERV_OP_TESTS_MAKEFILE_EDIT_PAGE, contest_id, prob_id, variant, 0);

cleanup:
  if (mk_f) fclose(mk_f);
  if (tmp_makefile_path[0]) unlink(tmp_makefile_path);
  xfree(header);
  xfree(footer);
  xfree(text);
  return retval;
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
  unsigned char buf[1024], hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

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
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "action=%d&op=%d&contest_id=%d&prob_id=%d", SSERV_CMD_HTTP_REQUEST,
                        SSERV_OP_TESTS_TESTS_VIEW_PAGE, contest_id, prob_id),
          "Tests page");
  fprintf(out_f, "</ul>\n");

  fprintf(out_f, "<h3>%s</h3>\n", "Statement file");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}
