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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ARMOR(s)  html_armor_buf(&ab, (s))
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_STATEMENT_PAGE,
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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_SOURCE_HEADER_PAGE,
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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_SOURCE_FOOTER_PAGE,
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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_STYLE_CHECKER_PAGE,
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
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_VIEW_TESTS_PAGE,
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
                              SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_CHECKER_PAGE,
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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_VALUER_PAGE,
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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_INTERACTOR_PAGE,
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
                                SSERV_CMD_HTTP_REQUEST, SSERV_OP_TESTS_EDIT_TEST_CHECKER_PAGE,
                                contest_id, variant, prob_id),
                  "Edit");
        } else {
          fprintf(out_f, "<td%s>&nbsp;</td>", cl);
        }
      }
      if (need_makefile) {
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
