/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2004-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "ncurses_utils.h"
#include "sha.h"
#include "base64.h"
#include "startstop.h"
#include "cpu.h"
#include "misctext.h"
#include "pathutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <stdarg.h>
#include <fcntl.h>

#include <libintl.h>
#include <locale.h>
#include <langinfo.h>

static unsigned char uudecode_path[PATH_MAX];
static int utf8_mode;

#ifndef CGI_PROG_SUFFIX
#define CGI_PROG_SUFFIX ""
#endif /* CGI_PROG_SUFFIX */

#if !defined CONF_STYLE_PREFIX
#define CONF_STYLE_PREFIX "/ejudge/"
#endif

#define DEFAULT_SERIALIZATION_KEY 22723

static unsigned char config_socket_path[PATH_MAX];
static int config_socket_path_modified;
static unsigned char config_super_serve_socket[PATH_MAX];
static int config_super_serve_socket_modified;
static unsigned char config_ejudge_xml_path[PATH_MAX];
static int config_ejudge_xml_path_modified;
static unsigned char config_ejudge_conf_dir[PATH_MAX];
static int config_ejudge_conf_dir_modified;
static unsigned char config_ejudge_contests_dir[PATH_MAX];
static int config_ejudge_contests_dir_modified;
static unsigned char config_ejudge_contests_home_dir[PATH_MAX];
static int config_ejudge_contests_home_dir_modified;
static unsigned char config_ejudge_local_dir[PATH_MAX];
static int config_ejudge_local_dir_modified;
static unsigned char config_cgi_data_dir[PATH_MAX];
static unsigned char config_full_cgi_data_dir[PATH_MAX];

static unsigned char config_userlist_xml_path[PATH_MAX];
static int config_userlist_xml_path_modified;
static unsigned char config_compile_home_dir[PATH_MAX];
static int config_compile_home_dir_modified;
static unsigned char config_contest1_home_dir[PATH_MAX];
static int config_contest1_home_dir_modified;
static unsigned char config_var_dir[PATH_MAX];
static int config_var_dir_modified;
static unsigned char config_testing_work_dir[PATH_MAX];
static int config_testing_work_dir_modified;
static unsigned char config_cgi_bin_dir[PATH_MAX];
static int config_cgi_bin_dir_modified;
static unsigned char config_htdocs_dir[PATH_MAX];
static int config_htdocs_dir_modified;
static unsigned char config_workdisk_image_path[PATH_MAX];
static unsigned char config_workdisk_mount_dir[PATH_MAX];
static unsigned char config_stand_html_path[PATH_MAX];
static unsigned char config_full_stand_html_path[PATH_MAX];

static unsigned char config_ejudge_cgi_bin_dir[PATH_MAX];
static int config_ejudge_cgi_bin_dir_modified;
static unsigned char config_ejudge_locale_dir[PATH_MAX];
static int config_ejudge_locale_dir_modified;
static unsigned char config_ejudge_script_dir[PATH_MAX];
static int config_ejudge_script_dir_modified;
static unsigned char config_ejudge_serve_path[PATH_MAX];
static int config_ejudge_serve_path_modified;
static unsigned char config_ejudge_run_path[PATH_MAX];
static int config_ejudge_run_path_modified;

static unsigned char config_user_id[64];
static unsigned char config_login[64];
static unsigned char config_email[256];
static unsigned char config_name[256];
static unsigned char config_password_txt[256];
static unsigned char config_password_sha1[64];

static unsigned char config_charset[256];
static int config_charset_modified;
static unsigned char config_sendmail[PATH_MAX];
static unsigned char config_reg_email[256];
static unsigned char config_reg_url[256];
static unsigned char config_server_name[256];
static unsigned char config_server_name_en[256];
static unsigned char config_server_main_url[256];
static unsigned char config_serialization_key[64];
static unsigned char config_system_uid[256];
static unsigned char config_system_gid[256];

static int system_uid;
static int system_gid;
static unsigned char system_login[256];
static unsigned char system_hostname[256];
static unsigned char system_domainname[256];
static unsigned char system_group[256];

static unsigned char config_workdisk_flag[64];
static unsigned char config_workdisk_size[64];
static unsigned char config_install_flag[64];

static unsigned char const login_accept_chars[] =
"._-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static unsigned char const email_accept_chars[] =
"@.%!+=_-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static unsigned char const name_accept_chars[] =
" !#$%()*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~"
" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß"
"àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";
static unsigned char const password_accept_chars[] =
" !#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿"
"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";

/* enumeration for path editing */
enum
{
  PATH_LINE_RETURN = 0,

  PATH_LINE_BUILTIN,
  PATH_LINE_SOCKET_PATH,
  PATH_LINE_SUPER_SERVE_SOCKET,
  PATH_LINE_CONFIG_DIR,
  PATH_LINE_EJUDGE_XML,
  PATH_LINE_CONTESTS_DIR,
  PATH_LINE_CONTESTS_HOME_DIR,
  PATH_LINE_EJUDGE_LOCAL_DIR,
  PATH_LINE_CGI_BIN_DIR,
  PATH_LINE_HTDOCS_DIR,
  PATH_LINE_CGI_DATA_DIR,
  PATH_LINE_FULL_CGI_DATA_DIR,

  PATH_LINE_OTHER,
  PATH_LINE_USERLIST_XML,
  PATH_LINE_COMPILE_DIR,
  PATH_LINE_CONTEST1_DIR,
  PATH_LINE_VAR_DIR,
  PATH_LINE_TESTING_DIR,
  PATH_LINE_STAND_HTML_DIR,
  PATH_LINE_FULL_STAND_HTML_PATH,
  PATH_LINE_WORKDISK_IMAGE_PATH,
  PATH_LINE_WORKDISK_MOUNT_DIR,

  PATH_LINE_TOOLS,
  PATH_LINE_EJUDGE_CGI_BIN_DIR,
  PATH_LINE_LOCALE_DIR,
  PATH_LINE_SCRIPT_DIR,
  PATH_LINE_SERVE_PATH,
  PATH_LINE_RUN_PATH,

  PATH_LINE_LAST,
};

enum
{
  SET_LINE_RETURN,
  SET_LINE_SETTINGS,
  SET_LINE_CHARSET,
  SET_LINE_SENDMAIL,
  SET_LINE_REG_EMAIL,
  SET_LINE_REG_URL,
  SET_LINE_SERVER_NAME,
  SET_LINE_SERVER_NAME_EN,
  SET_LINE_SERVER_MAIN_URL,
  SET_LINE_SER_KEY,
  SET_LINE_SYSTEM_UID,
  SET_LINE_SYSTEM_GID,
  SET_LINE_WORKDISK_FLAG,
  SET_LINE_WORKDISK_SIZE,
  SET_LINE_INSTALL_FLAG,
  SET_LINE_LAST,
};

struct path_edit_item
{
  unsigned char *descr;
  int is_builtin;
  unsigned char *buf;
  size_t size;
  int *updated_ptr;
  unsigned char *default_value;
};
static const struct path_edit_item set_edit_items[];
static const struct path_edit_item path_edit_items[] =
{
  [PATH_LINE_SOCKET_PATH] = 
  {
    "Socket path", 1, config_socket_path,
    sizeof(config_socket_path),
    &config_socket_path_modified,
#if defined EJUDGE_SOCKET_PATH
    EJUDGE_SOCKET_PATH,
#endif /* EJUDGE_SOCKET_PATH */
  },
  [PATH_LINE_SUPER_SERVE_SOCKET] = 
  {
    "Super-serve socket path", 1, config_super_serve_socket,
    sizeof(config_super_serve_socket),
    &config_super_serve_socket_modified,
#if defined EJUDGE_SUPER_SERVE_SOCKET
    EJUDGE_SUPER_SERVE_SOCKET,
#endif /* EJUDGE_SUPER_SERVE_SOCKET */
  },
  [PATH_LINE_CONFIG_DIR] =
  {
    "Config directory", 1, config_ejudge_conf_dir,
    sizeof(config_ejudge_conf_dir),
    &config_ejudge_conf_dir_modified,
#if defined EJUDGE_CONF_DIR
    EJUDGE_CONF_DIR,
#endif /* EJUDGE_CONF_DIR */
  },
  [PATH_LINE_EJUDGE_XML] =
  {
    "Path to ejudge.xml", 1, config_ejudge_xml_path,
    sizeof(config_ejudge_xml_path),
    &config_ejudge_xml_path_modified,
#if defined EJUDGE_XML_PATH
    EJUDGE_XML_PATH,
#endif /* EJUDGE_XML_PATH */
  },
  [PATH_LINE_CONTESTS_DIR] =
  {
    "Contest XML dir", 1, config_ejudge_contests_dir,
    sizeof(config_ejudge_contests_dir),
    &config_ejudge_contests_dir_modified,
#if defined EJUDGE_CONTESTS_DIR
    EJUDGE_CONTESTS_DIR,
#endif /* EJUDGE_CONTESTS_DIR */
  },
  [PATH_LINE_CONTESTS_HOME_DIR] =
  {
    "Contests home dir", 0, config_ejudge_contests_home_dir,
    sizeof(config_ejudge_contests_home_dir),
    &config_ejudge_contests_home_dir_modified,
#if defined EJUDGE_CONTESTS_HOME_DIR
    EJUDGE_CONTESTS_HOME_DIR,
#endif /* EJUDGE_CONTESTS_HOME_DIR */
  },
  [PATH_LINE_EJUDGE_LOCAL_DIR] =
  {
    "Local state directory", 0, config_ejudge_local_dir,
    sizeof(config_ejudge_local_dir),
    &config_ejudge_local_dir_modified,
#if defined EJUDGE_LOCAL_DIR
    EJUDGE_LOCAL_DIR
#endif /* EJUDGE_LOCAL_DIR */
  },
  [PATH_LINE_CGI_DATA_DIR] =
  {
    "CGI config dir", 0, config_cgi_data_dir,
    sizeof(config_cgi_data_dir),
  },
  [PATH_LINE_FULL_CGI_DATA_DIR] =
  {
    "Full CGI config dir", 0, config_full_cgi_data_dir,
    sizeof(config_full_cgi_data_dir),
  },
  [PATH_LINE_USERLIST_XML] =
  {
    "User XML database", 0, config_userlist_xml_path,
    sizeof(config_userlist_xml_path),
    &config_userlist_xml_path_modified,
  },
  [PATH_LINE_COMPILE_DIR] =
  {
    "Compile server dir", 0, config_compile_home_dir,
    sizeof(config_compile_home_dir),
    &config_compile_home_dir_modified,
  },
  [PATH_LINE_CONTEST1_DIR] =
  {
    "Sample contest dir", 0, config_contest1_home_dir,
    sizeof(config_contest1_home_dir),
    &config_contest1_home_dir_modified,
  },
  [PATH_LINE_VAR_DIR] =
  {
    "Log file dir", 0, config_var_dir,
    sizeof(config_var_dir),
    &config_var_dir_modified,
  },
  [PATH_LINE_CGI_BIN_DIR] =
  {
    "httpd cgi-bin dir", 0, config_cgi_bin_dir,
    sizeof(config_cgi_bin_dir),
    &config_cgi_bin_dir_modified,
#if defined EJUDGE_HTTPD_CGI_BIN_DIR
    EJUDGE_HTTPD_CGI_BIN_DIR,
#endif /* EJUDGE_HTTPD_CGI_BIN_DIR */
  },
  [PATH_LINE_HTDOCS_DIR] =
  {
    "httpd html dir", 0, config_htdocs_dir,
    sizeof(config_htdocs_dir),
    &config_htdocs_dir_modified,
#if defined EJUDGE_HTTPD_HTDOCS_DIR
    EJUDGE_HTTPD_HTDOCS_DIR,
#endif /* EJUDGE_HTTPD_HTDOCS_DIR */
  },
  [PATH_LINE_TESTING_DIR] =
  {
    "Testing working dir", 0, config_testing_work_dir,
    sizeof(config_testing_work_dir),
    &config_testing_work_dir_modified,
  },
  [PATH_LINE_STAND_HTML_DIR] =
  {
    "standings.html path", 0, config_stand_html_path,
    sizeof(config_stand_html_path),
  },
  [PATH_LINE_FULL_STAND_HTML_PATH] =
  {
    "Full standings path", 0, config_full_stand_html_path,
    sizeof(config_full_stand_html_path),
  },
  [PATH_LINE_WORKDISK_IMAGE_PATH] =
  {
    "Workdisk image path", 0, config_workdisk_image_path,
    sizeof(config_workdisk_image_path),
  },
  [PATH_LINE_WORKDISK_MOUNT_DIR] =
  {
    "Workdisk mount dir", 0, config_workdisk_mount_dir,
    sizeof(config_workdisk_mount_dir),
  },
  [PATH_LINE_EJUDGE_CGI_BIN_DIR] =
  {
    "Ejudge cgi-bin dir", 1, config_ejudge_cgi_bin_dir,
    sizeof(config_ejudge_cgi_bin_dir),
    &config_ejudge_cgi_bin_dir_modified,
#if defined EJUDGE_CGI_BIN_DIR
    EJUDGE_CGI_BIN_DIR,
#endif /* EJUDGE_CGI_BIN_DIR */
  },
#if CONF_HAS_LIBINTL - 0 == 1
  [PATH_LINE_LOCALE_DIR] =
  {
    "Localization dir", 1, config_ejudge_locale_dir,
    sizeof(config_ejudge_locale_dir),
    &config_ejudge_locale_dir_modified,
#if defined EJUDGE_LOCALE_DIR
    EJUDGE_LOCALE_DIR,
#endif /* EJUDGE_LOCALE_DIR */
  },
#endif /* CONF_HAS_LIBINTL */
  [PATH_LINE_SCRIPT_DIR] =
  {
    "Script dir", 1, config_ejudge_script_dir,
    sizeof(config_ejudge_script_dir),
    &config_ejudge_script_dir_modified,
#if defined EJUDGE_SCRIPT_DIR
    EJUDGE_SCRIPT_DIR,
#endif /* EJUDGE_SCRIPT_DIR */
  },
  [PATH_LINE_SERVE_PATH] =
  {
    "Path to `serve'", 1, config_ejudge_serve_path,
    sizeof(config_ejudge_serve_path),
    &config_ejudge_serve_path_modified,
#if defined EJUDGE_SERVE_PATH
    EJUDGE_SERVE_PATH,
#endif /* EJUDGE_SERVE_PATH */
  },
  [PATH_LINE_RUN_PATH] =
  {
    "Path to `run'", 1, config_ejudge_run_path,
    sizeof(config_ejudge_run_path),
    &config_ejudge_run_path_modified,
#if defined EJUDGE_RUN_PATH
    EJUDGE_RUN_PATH,
#endif /* EJUDGE_RUN_PATH */
  },
};

static void
initialize_config_var(int idx)
{
  ASSERT(idx >= 0 && idx < PATH_LINE_LAST);
  if (!path_edit_items[idx].buf) return;
  if (path_edit_items[idx].default_value) {
    snprintf(path_edit_items[idx].buf, path_edit_items[idx].size,
             "%s", path_edit_items[idx].default_value);
    *path_edit_items[idx].updated_ptr = 0;
    return;
  }
  switch (idx) {
  case PATH_LINE_SOCKET_PATH:
  case PATH_LINE_SUPER_SERVE_SOCKET:
  case PATH_LINE_CONFIG_DIR:
  case PATH_LINE_EJUDGE_XML:
  case PATH_LINE_CONTESTS_DIR:
  case PATH_LINE_CONTESTS_HOME_DIR:
  case PATH_LINE_EJUDGE_LOCAL_DIR:
  case PATH_LINE_CGI_BIN_DIR:
  case PATH_LINE_HTDOCS_DIR:
  case PATH_LINE_EJUDGE_CGI_BIN_DIR:
  case PATH_LINE_LOCALE_DIR:
  case PATH_LINE_SCRIPT_DIR:
  case PATH_LINE_SERVE_PATH:
  case PATH_LINE_RUN_PATH:
    path_edit_items[idx].buf[0] = 0;
    return;

  case PATH_LINE_CGI_DATA_DIR:
#if defined CGI_DATA_PATH
    snprintf(config_cgi_data_dir, sizeof(config_cgi_data_dir),
             "%s", CGI_DATA_PATH);
#else
    snprintf(config_cgi_data_dir, sizeof(config_cgi_data_dir),
             "%s", "../cgi-data");
#endif /* CGI_DATA_PATH */
    break;
  case PATH_LINE_FULL_CGI_DATA_DIR:
    if (config_cgi_data_dir[0] == '/') {
      snprintf(config_full_cgi_data_dir, sizeof(config_full_cgi_data_dir),
               "%s", config_cgi_data_dir);
    } else if (config_cgi_bin_dir[0]) {
      snprintf(config_full_cgi_data_dir, sizeof(config_full_cgi_data_dir),
               "%s/%s", config_cgi_bin_dir, config_cgi_data_dir);
    } else {
      config_full_cgi_data_dir[0] = 0;
    }
    break;
  case PATH_LINE_STAND_HTML_DIR:
    config_stand_html_path[0] = 0;
    break;
  case PATH_LINE_FULL_STAND_HTML_PATH:
    if (config_stand_html_path[0] && config_htdocs_dir[0]) {
      snprintf(config_full_stand_html_path,sizeof(config_full_stand_html_path),
               "%s/%s/standings.html", config_htdocs_dir,
               config_stand_html_path);
      os_normalize_path(config_full_stand_html_path);
    } else {
      config_full_stand_html_path[0] = 0;
    }
    break;
  case PATH_LINE_USERLIST_XML:
    if (config_ejudge_conf_dir[0]) {
      snprintf(config_userlist_xml_path, sizeof(config_userlist_xml_path),
               "%s/db/userlist.xml", config_ejudge_conf_dir);
    } else {
      config_userlist_xml_path[0] = 0;
    }
    config_userlist_xml_path_modified = 0;
    break;
  case PATH_LINE_COMPILE_DIR:
    if (config_ejudge_contests_home_dir[0]) {
      snprintf(config_compile_home_dir, sizeof(config_compile_home_dir),
               "%s/compile", config_ejudge_contests_home_dir);
    } else {
      config_compile_home_dir[0] = 0;
    }
    config_compile_home_dir_modified = 0;
    break;
  case PATH_LINE_CONTEST1_DIR:
    if (config_ejudge_contests_home_dir[0]) {
      snprintf(config_contest1_home_dir, sizeof(config_contest1_home_dir),
               "%s/000001", config_ejudge_contests_home_dir);
    } else {
      config_contest1_home_dir[0] = 0;
    }
    config_contest1_home_dir_modified = 0;
    break;
  case PATH_LINE_VAR_DIR:
    if (config_ejudge_contests_home_dir[0]) {
      snprintf(config_var_dir, sizeof(config_var_dir),
               "%s/var", config_ejudge_contests_home_dir);
    } else {
      config_var_dir[0] = 0;
    }
    config_var_dir_modified = 0;
    break;
  case PATH_LINE_TESTING_DIR:
    config_testing_work_dir[0] = 0;
    config_testing_work_dir_modified = 0;
    break;
  case PATH_LINE_WORKDISK_IMAGE_PATH:
    if (config_ejudge_local_dir[0]) {
      snprintf(config_workdisk_image_path, sizeof(config_workdisk_image_path),
               "%s/work-img", config_ejudge_local_dir);
    } else if (config_ejudge_contests_home_dir[0]) {
      snprintf(config_workdisk_image_path, sizeof(config_workdisk_image_path),
               "%s/work-img", config_ejudge_contests_home_dir);
    } else {
      config_workdisk_image_path[0] = 0;
    }
    break;
  case PATH_LINE_WORKDISK_MOUNT_DIR:
    if (config_ejudge_local_dir[0]) {
      snprintf(config_workdisk_mount_dir, sizeof(config_workdisk_mount_dir),
               "%s/work-disk", config_ejudge_local_dir);
    } else if (config_ejudge_contests_home_dir[0]) {
      snprintf(config_workdisk_mount_dir, sizeof(config_workdisk_mount_dir),
               "%s/work-disk", config_ejudge_contests_home_dir);
    } else {
      config_workdisk_mount_dir[0] = 0;
    }
    break;
  default:
    SWERR(("unhandled initialization for %d", idx));
  }
}

static void
initialize_config_vars(void)
{
  int i;

  for (i = 0; i < PATH_LINE_LAST; i++) {
    initialize_config_var(i);
  }
  initialize_config_var(PATH_LINE_FULL_CGI_DATA_DIR);
}

static int
is_valid_path(int idx)
{
  struct stat stbuf;
  const struct path_edit_item *pi;

  ASSERT(idx >= 0 && idx < PATH_LINE_LAST);
  switch (idx) {
  case PATH_LINE_RETURN:
  case PATH_LINE_BUILTIN:
  case PATH_LINE_OTHER:
  case PATH_LINE_TOOLS:
  case PATH_LINE_CGI_DATA_DIR:
  case PATH_LINE_FULL_CGI_DATA_DIR:
  case PATH_LINE_TESTING_DIR:
  case PATH_LINE_FULL_STAND_HTML_PATH:
  case PATH_LINE_STAND_HTML_DIR:
    return 1;

  case PATH_LINE_WORKDISK_IMAGE_PATH:
  case PATH_LINE_WORKDISK_MOUNT_DIR:
    if (!strcmp(config_workdisk_flag, "no")) return 1;
    if (path_edit_items[idx].buf[0]) return 1;
    return 0;

  case PATH_LINE_SOCKET_PATH:
  case PATH_LINE_SUPER_SERVE_SOCKET:
  case PATH_LINE_CONFIG_DIR:
  case PATH_LINE_EJUDGE_XML:
  case PATH_LINE_CONTESTS_DIR:
  case PATH_LINE_CONTESTS_HOME_DIR:
  case PATH_LINE_EJUDGE_LOCAL_DIR:
    if (path_edit_items[idx].buf[0]) return 1;
    return 0;

  case PATH_LINE_USERLIST_XML:
  case PATH_LINE_COMPILE_DIR:
  case PATH_LINE_CONTEST1_DIR:
  case PATH_LINE_VAR_DIR:
    if (path_edit_items[idx].buf[0]) return 1;
    return 0;

  case PATH_LINE_CGI_BIN_DIR:
    if (path_edit_items[PATH_LINE_CGI_DATA_DIR].buf[0] == '/') return 1;
    if ((pi = &path_edit_items[PATH_LINE_SOCKET_PATH])->default_value
        && !strcmp(pi->buf, pi->default_value)
        && (pi = &path_edit_items[PATH_LINE_SUPER_SERVE_SOCKET])->default_value
        && !strcmp(pi->buf, pi->default_value)
        && (pi = &path_edit_items[PATH_LINE_CONTESTS_DIR])->default_value
        && !strcmp(pi->buf, pi->default_value)
#if CONF_HAS_LIBINTL - 0 == 1
        && (pi = &path_edit_items[PATH_LINE_LOCALE_DIR])->default_value
        && !strcmp(pi->buf, pi->default_value)
#endif /* CONF_HAS_LIBINTL */
        && (pi = &set_edit_items[SET_LINE_CHARSET])->default_value
        && !strcmp(pi->buf, pi->default_value)) return 1;
    if (!path_edit_items[idx].buf[0]) return 0;
    if (stat(path_edit_items[idx].buf, &stbuf) < 0 || !S_ISDIR(stbuf.st_mode))
      return 0;
    return 1;

  case PATH_LINE_HTDOCS_DIR:
    if (path_edit_items[PATH_LINE_STAND_HTML_DIR].buf[0] == '/' ||
        !path_edit_items[PATH_LINE_STAND_HTML_DIR].buf[0]) return 1;
    if (stat(path_edit_items[idx].buf, &stbuf) < 0 || !S_ISDIR(stbuf.st_mode))
      return 0;
    return 1;

  case PATH_LINE_LOCALE_DIR:
#if CONF_HAS_LIBINTL - 0 == 1
    if (!path_edit_items[idx].buf[0]) return 0;
    if (stat(path_edit_items[idx].buf, &stbuf) < 0 || !S_ISDIR(stbuf.st_mode))
      return 0;
    return 1;
#else
    return 1;
#endif

  case PATH_LINE_SCRIPT_DIR:
  case PATH_LINE_EJUDGE_CGI_BIN_DIR:
    if (!path_edit_items[idx].buf[0]) return 0;
    if (stat(path_edit_items[idx].buf, &stbuf) < 0 || !S_ISDIR(stbuf.st_mode))
      return 0;
    return 1;
    
  case PATH_LINE_SERVE_PATH:
  case PATH_LINE_RUN_PATH:
    if (!path_edit_items[idx].buf[0]) return 0;
    if (stat(path_edit_items[idx].buf, &stbuf) < 0 || !S_ISREG(stbuf.st_mode)
        || access(path_edit_items[idx].buf, X_OK) < 0)
      return 0;
    return 1;
  default:
    SWERR(("is_valid_path: unhandled idx == %d", idx));
  }
  return 0;
}

static const unsigned char *
valid_var_str(int idx)
{
  int res = is_valid_path(idx);
  if (res) return " ";
  return "!";
}

static const unsigned char builtin_change_warning[] =
"\\begin{center}\n"
"WARNING!\n"
"\\end{center}\n"
"You are about to change the value of the built-in configuration variable.\n"
"Note, that the non-default variable value has to be specified explicitly\n"
" in all the configuration files, where this variable is necessary!\n"
"\\begin{center}\n"
"Are you sure you want to change the value\n"
"\\end{center}\n";

static const unsigned char paths_menu_help[] =
"Q - quit, D - reset, Enter - edit, B - browse | * - modified, ! - invalid";
static int
do_paths_menu(int *p_cur_item)
{
  int ret_val = 0;
  int cur_item = *p_cur_item, first_row;
  int nitem, i, c, cmd, j, menu_nitem = 0;
  char **descs;
  ITEM **items;
  MENU *menu;
  WINDOW *in_win, *out_win;
  PANEL *in_pan, *out_pan;
  unsigned char tmp_buf[PATH_MAX];
  const struct path_edit_item *cur_path_item;
  struct stat stbuf;
  int *inv_map = 0;

  nitem = PATH_LINE_LAST;
  XCALLOC(descs, nitem);
  XCALLOC(inv_map, nitem);

  for (i = 0; i < PATH_LINE_LAST; i++) {
    switch (i) {
    case PATH_LINE_RETURN:
      asprintf(&descs[menu_nitem], "Return to upper-level menu");
      inv_map[menu_nitem++] = i;
      break;
    case PATH_LINE_BUILTIN:
      asprintf(&descs[menu_nitem], "*** Built-in configuration paths ***");
      inv_map[menu_nitem++] = i;
      break;
    case PATH_LINE_OTHER:
      asprintf(&descs[menu_nitem], "*** Other configuration paths ***");
      inv_map[menu_nitem++] = i;
      break;
    case PATH_LINE_TOOLS:
      asprintf(&descs[menu_nitem], "*** Built-in ejudge tool paths ***");
      inv_map[menu_nitem++] = i;
      break;

    case PATH_LINE_SOCKET_PATH:
    case PATH_LINE_SUPER_SERVE_SOCKET:
    case PATH_LINE_CONFIG_DIR:
    case PATH_LINE_EJUDGE_XML:
    case PATH_LINE_CONTESTS_DIR:
    case PATH_LINE_SCRIPT_DIR:
    case PATH_LINE_SERVE_PATH:
    case PATH_LINE_RUN_PATH:
    case PATH_LINE_CGI_BIN_DIR:
    case PATH_LINE_HTDOCS_DIR:
    case PATH_LINE_EJUDGE_CGI_BIN_DIR:
      asprintf(&descs[menu_nitem], "%-20.20s%s%s: %-53.53s",
               path_edit_items[i].descr,
               (*path_edit_items[i].updated_ptr)?"*":" ",
               valid_var_str(i), path_edit_items[i].buf);
      inv_map[menu_nitem++] = i;
      break;

    case PATH_LINE_CONTESTS_HOME_DIR:
    case PATH_LINE_EJUDGE_LOCAL_DIR:
    case PATH_LINE_CGI_DATA_DIR:
    case PATH_LINE_FULL_CGI_DATA_DIR:
    case PATH_LINE_USERLIST_XML:
    case PATH_LINE_COMPILE_DIR:
    case PATH_LINE_CONTEST1_DIR:
    case PATH_LINE_VAR_DIR:
    case PATH_LINE_STAND_HTML_DIR:
    case PATH_LINE_FULL_STAND_HTML_PATH:
      asprintf(&descs[menu_nitem], "%-20.20s %s: %-53.53s",
               path_edit_items[i].descr,
               valid_var_str(i), path_edit_items[i].buf);
      inv_map[menu_nitem++] = i;
      break;

    case PATH_LINE_TESTING_DIR:
      if (!strcmp(config_workdisk_flag, "no")) {
        asprintf(&descs[menu_nitem], "%-20.20s %s: %-53.53s",
                 path_edit_items[i].descr,
                 valid_var_str(i), path_edit_items[i].buf);
        inv_map[menu_nitem++] = i;
      }
      break;

    case PATH_LINE_WORKDISK_IMAGE_PATH:
    case PATH_LINE_WORKDISK_MOUNT_DIR:
      if (!strcmp(config_workdisk_flag, "yes")) {
        asprintf(&descs[menu_nitem], "%-20.20s %s: %-53.53s",
                 path_edit_items[i].descr,
                 valid_var_str(i), path_edit_items[i].buf);
        inv_map[menu_nitem++] = i;
      }
      break;

    case PATH_LINE_LOCALE_DIR:
#if CONF_HAS_LIBINTL - 0 == 1
      asprintf(&descs[menu_nitem], "%-20.20s%s%s: %-53.53s",
               path_edit_items[i].descr,
               (*path_edit_items[i].updated_ptr)?"*":" ",
               valid_var_str(i), path_edit_items[i].buf);
      inv_map[menu_nitem++] = i;
#else
      /*
      asprintf(&descs[menu_nitem], "%-20.20s  : %-53.53s",
               path_edit_items[i].descr, "N/A");
      */
#endif /* CONF_HAS_LIBINTL */
      break;

    default:
      SWERR(("unhandled index %d", i));
    }
  }

  XCALLOC(items, menu_nitem + 1);
  for (i = 0; i < menu_nitem; i++)
    items[i] = new_item(descs[i], 0);
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  if (cur_item < 0) cur_item = 0;
  if (cur_item >= menu_nitem) cur_item = menu_nitem - 1;
  first_row = cur_item - (LINES - 4)/2;
  if (first_row + LINES - 4 > menu_nitem) first_row = menu_nitem - (LINES - 4);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[cur_item]);

  while (1) {
    mvwprintw(stdscr, 0, 0, "Ejudge %s configurator > Path settings",
              compile_version);
    wclrtoeol(stdscr);
    ncurses_print_help(paths_menu_help);
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      cmd = -1;
      switch (c) {
      case KEY_BACKSPACE: case KEY_DC: case 127: case 8:
      case 'd': case 'D': case '÷' & 255: case '×' & 255:
        c = 'd';
        goto menu_done;
      case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case 'b': case 'B': case 'É' & 255: case 'é' & 255:
        c = 'b';
        goto menu_done;
      case '\n': case '\r':
        c = '\n';
        goto menu_done;
      case KEY_UP: case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN: case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= menu_nitem) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;

      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }

    // handle menu command
  menu_done:
    ;
    i = inv_map[item_index(current_item(menu))];
    if (c == 'q') {
      cur_item = i;
      break;
    }
    if (c == '\n') {
      if (i == PATH_LINE_RETURN) {
        cur_item = i;
        break;
      }
      if (i == PATH_LINE_BUILTIN || i == PATH_LINE_OTHER
          || i == PATH_LINE_TOOLS)
        continue;
      if (i == PATH_LINE_CGI_DATA_DIR || i == PATH_LINE_FULL_CGI_DATA_DIR) {
        ncurses_msgbox("\\begin{center}\nNOTICE!\n\\end{center}\n\nThis configuration variable value is built-in into the CGI programs (`users', `register', `team', `master', `judge') and cannot be edited.\n");
        continue;
      }
      if (i == PATH_LINE_FULL_STAND_HTML_PATH) {
        ncurses_msgbox("\\begin{center}\nNOTICE!\n\\end{center}\n\nThis configuration variable cannot be edited.\n");
        continue;
      }
      cur_path_item = &path_edit_items[i];
      if (!cur_path_item->buf) continue;
      // edit the variable
      snprintf(tmp_buf, sizeof(tmp_buf), "%s", cur_path_item->buf);
      j = ncurses_edit_string(LINES/2, COLS, cur_path_item->descr,
                              tmp_buf, sizeof(tmp_buf), utf8_mode);
      if (j < 0) continue;
    check_variable_value:
      if (!strcmp(cur_path_item->buf, tmp_buf)) continue;
      if (cur_path_item->is_builtin && !*cur_path_item->updated_ptr
          && cur_path_item->default_value
          && cur_path_item->default_value[0]) {
        j = ncurses_yesno(0, builtin_change_warning);
        if (j != 1) continue;
      }

      if ((i == PATH_LINE_LOCALE_DIR || i == PATH_LINE_SCRIPT_DIR
           || i == PATH_LINE_SERVE_PATH || i == PATH_LINE_RUN_PATH
           || i == PATH_LINE_CGI_BIN_DIR || i == PATH_LINE_HTDOCS_DIR
           || i == PATH_LINE_EJUDGE_CGI_BIN_DIR)
          && tmp_buf[0] && stat(tmp_buf, &stbuf) < 0) {
        j = ncurses_yesno(0, "\\begin{center}WARNING!\n\nSuch file or directory does not exist! Still set the variable to the new value?\n\\end{center}\n");
        if (j != 1) continue;
      }
      if ((i == PATH_LINE_LOCALE_DIR || i == PATH_LINE_SCRIPT_DIR
           || i == PATH_LINE_CGI_BIN_DIR || i == PATH_LINE_HTDOCS_DIR
           || i == PATH_LINE_EJUDGE_CGI_BIN_DIR)
          && tmp_buf[0] && stat(tmp_buf, &stbuf) >= 0
          && !S_ISDIR(stbuf.st_mode)) {
        j = ncurses_yesno(0, "\\begin{center}WARNING!\n\nThis is not a directory! Still set the variable to the new value?\n\\end{center}\n");
        if (j != 1) continue;
      }
      if ((i == PATH_LINE_SERVE_PATH || i == PATH_LINE_RUN_PATH)
          && tmp_buf[0] && stat(tmp_buf, &stbuf) >= 0
          && (!S_ISREG(stbuf.st_mode) || access(tmp_buf, X_OK) < 0)) {
        j = ncurses_yesno(0, "\\begin{center}WARNING!\n\nThis is not a regular file or it is not executable! Still set the variable to the new value?\n\\end{center}\n");
        if (j != 1) continue;
      }

      snprintf(cur_path_item->buf, cur_path_item->size, "%s", tmp_buf);
      if (cur_path_item->updated_ptr) *cur_path_item->updated_ptr = 1;
      if (i == PATH_LINE_CGI_BIN_DIR) {
        initialize_config_var(PATH_LINE_FULL_CGI_DATA_DIR);
      }
      if (i == PATH_LINE_HTDOCS_DIR || i == PATH_LINE_STAND_HTML_DIR) {
        initialize_config_var(PATH_LINE_FULL_STAND_HTML_PATH);
      }
      cur_item = i;
      ret_val = 1;
      break;
    }
    if (c == 'd') {
      if (i == PATH_LINE_RETURN || i == PATH_LINE_BUILTIN
          || i == PATH_LINE_OTHER || i == PATH_LINE_TOOLS
          || i == PATH_LINE_CGI_DATA_DIR || i == PATH_LINE_FULL_CGI_DATA_DIR
          || i == PATH_LINE_FULL_STAND_HTML_PATH)
        continue;
      // clear the variable
      j = ncurses_yesno(0, "\\begin{center}\nReset the variable to the initial value?\n\\end{center}\n");
      if (j == 1) {
        initialize_config_var(i);
        if (i == PATH_LINE_CGI_BIN_DIR) {
          initialize_config_var(PATH_LINE_FULL_CGI_DATA_DIR);
        }
        if (i == PATH_LINE_HTDOCS_DIR || i == PATH_LINE_STAND_HTML_DIR) {
          initialize_config_var(PATH_LINE_FULL_STAND_HTML_PATH);
        }
        cur_item = i;
        ret_val = 1;
        break;
      }
      continue;
    }
    if (c == 'b') {
      if (i != PATH_LINE_LOCALE_DIR && i != PATH_LINE_SCRIPT_DIR
          && i != PATH_LINE_SERVE_PATH && i != PATH_LINE_RUN_PATH
          && i != PATH_LINE_CGI_BIN_DIR && i != PATH_LINE_TESTING_DIR
          && i != PATH_LINE_HTDOCS_DIR && i != PATH_LINE_EJUDGE_CGI_BIN_DIR)
        continue;
      cur_path_item = &path_edit_items[i];
      if (!cur_path_item->buf) continue;
      snprintf(tmp_buf, sizeof(tmp_buf), "%s", cur_path_item->buf);
      j = ncurses_choose_file(cur_path_item->descr, tmp_buf, sizeof(tmp_buf),
                              utf8_mode);
      if (j < 0) continue;
      goto check_variable_value;
    }
  }

  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);
  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  for (i = 0; i < menu_nitem; i++) {
    free_item(items[i]);
    free(descs[i]);
  }
  xfree(items);
  xfree(descs);

  *p_cur_item = cur_item;
  return ret_val;
}

enum
{
  ID_LINE_RETURN,
  ID_LINE_SETTINGS,
  ID_LINE_USER_ID,
  ID_LINE_LOGIN,
  ID_LINE_EMAIL,
  ID_LINE_NAME,
  ID_LINE_PASSWORD,
  ID_LINE_LAST,
};

static const struct path_edit_item id_edit_items[] =
{
  [ID_LINE_USER_ID] =
  {
    "Admin ID", 0, config_user_id, sizeof(config_user_id),
  },
  [ID_LINE_LOGIN] =
  {
    "Admin login", 0, config_login, sizeof(config_login),
  },
  [ID_LINE_EMAIL] =
  {
    "Admin e-mail", 0, config_email, sizeof(config_email),
  },
  [ID_LINE_NAME] =
  {
    "Admin name", 0, config_name, sizeof(config_name),
  },
  [ID_LINE_PASSWORD] =
  {
    "Admin password", 0, config_password_txt, sizeof(config_password_txt),
  },
};

static int
is_valid_id_var(int idx)
{
  switch (idx) {
  case ID_LINE_RETURN:
  case ID_LINE_SETTINGS:
    return 1;
  case ID_LINE_USER_ID:
  case ID_LINE_LOGIN:
  case ID_LINE_EMAIL:
  case ID_LINE_NAME:
    if (id_edit_items[idx].buf[0]) return 1;
    return 0;
  case ID_LINE_PASSWORD:
    if (config_password_sha1[0]) return 1;
    return 0;
  default:
    SWERR(("is_valid_id_var: unhandled idx == %d", idx));
  }
  return 0;
}
static const unsigned char *
valid_id_str(int idx)
{
  int res = is_valid_id_var(idx);
  if (res) return " ";
  return "!";
}

static int
do_identity_menu(int *p_cur_item)
{
  int ret_val = 0;
  int cur_item = *p_cur_item;
  int nitem, i, c, cmd, first_row, j, val, n;
  char **descs = 0;
  ITEM **items = 0;
  MENU *menu = 0;
  WINDOW *in_win = 0, *out_win = 0;
  PANEL *in_pan = 0, *out_pan = 0;
  const struct path_edit_item *cur_id_item;
  unsigned char buf1[PATH_MAX], buf2[PATH_MAX];

  nitem = ID_LINE_LAST;
  XCALLOC(descs, nitem);
  asprintf(&descs[ID_LINE_RETURN], "Return to upper-level menu");
  asprintf(&descs[ID_LINE_SETTINGS], "*** Ejudge administrator identity ***");

  for (i = 0; i < ID_LINE_LAST; i++) {
    switch (i) {
    case ID_LINE_RETURN:
    case ID_LINE_SETTINGS:
      break;
    case ID_LINE_USER_ID:
    case ID_LINE_LOGIN:
    case ID_LINE_EMAIL:
    case ID_LINE_NAME:
    case ID_LINE_PASSWORD:
      asprintf(&descs[i], "%-20.20s %s: %-53.53s",
               id_edit_items[i].descr,
               valid_id_str(i), id_edit_items[i].buf);
      break;
    default:
      SWERR(("do_identity_menu: unhandled index i == %d", i));
    }
  }

  XCALLOC(items, nitem + 1);
  for (i = 0; i < nitem; i++)
    items[i] = new_item(descs[i], 0);
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  if (cur_item < 0) cur_item = 0;
  if (cur_item >= nitem) cur_item = nitem - 1;
  first_row = cur_item - (LINES - 4)/2;
  if (first_row + LINES - 4 > nitem) first_row = nitem - (LINES - 4);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[cur_item]);

  while (1) {
    mvwprintw(stdscr, 0, 0, "Ejudge %s configurator > Administrator identity",
              compile_version);
    wclrtoeol(stdscr);
    ncurses_print_help("Q - quit, D - reset, Enter - edit | Legend: ! - invalid");
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      cmd = -1;
      switch (c) {
      case KEY_BACKSPACE: case KEY_DC: case 127: case 8:
      case 'd': case 'D': case '÷' & 255: case '×' & 255:
        c = 'd';
        goto menu_done;
      case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case '\n': case '\r':
        c = '\n';
        goto menu_done;
      case KEY_UP: case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN: case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= nitem) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;

      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }

    // handle menu command
  menu_done:
    ;
    i = item_index(current_item(menu));
    if (c == 'q') {
      cur_item = i;
      break;
    }
    if (c == '\n') {
      if (i == ID_LINE_RETURN) {
        cur_item = i;
        break;
      }
      if (i == ID_LINE_SETTINGS) continue;
      cur_id_item = &id_edit_items[i];
      if (!cur_id_item->buf) continue;

      if (i == ID_LINE_PASSWORD) {
        buf1[0] = 0;
        j = ncurses_edit_password(LINES / 2, COLS, "Password",
                                  buf1, sizeof(buf1));
        if (j < 0) continue;
        if (!buf1[0]) continue;

        buf2[0] = 0;
        j = ncurses_edit_password(LINES / 2, COLS, "Password (retype)",
                                  buf2, sizeof(buf2));
        if (j < 0) continue;
        if (!buf2[0]) continue;

        if (strcmp(buf1, buf2) != 0) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nPasswords do not match!\n\\end{center}\n");
          continue;
        }

        j = strlen(buf1);
        if (j > 64) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nPasswords is too long!\n\\end{center}\n");
          continue;
        }

        if (strspn(buf1, password_accept_chars) != j) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe password contains invalid characters!\n\\end{center}\n");
          continue;
        }

        memset(config_password_txt, '*', j);
        config_password_txt[j] = 0;
        sha_buffer(buf1, j, buf2);
        for (j = 0; j < 20; j++) {
          sprintf(config_password_sha1 + j * 2, "%02x", buf2[j]);
        }
        ncurses_msgbox("\\begin{center}\nNOTICE!\n\nThe password sha1 hash is %s!\n\\end{center}\n", config_password_sha1);

        cur_item = i;
        ret_val = 1;
        break;
      }

      snprintf(buf1, sizeof(buf1), "%s", cur_id_item->buf);
      j = ncurses_edit_string(LINES / 2, COLS, cur_id_item->descr,
                              buf1, sizeof(buf1), utf8_mode);
      if (j < 0) continue;
      if (!buf1[0]) {
        cur_id_item->buf[0] = 0;
        cur_item = i;
        ret_val = 1;
        break;
      }

      switch (i) {
      case ID_LINE_USER_ID:
        val = n = 0;
        if (sscanf(buf1, "%d%n", &val, &n) != 1 || buf1[n]
            || val <= 0 || val >= 1000000) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe administrator user identifier must be an integer number in range [1,999999]!\n\\end{center}\n");
          continue;
        }
        snprintf(config_user_id, sizeof(config_user_id), "%d", val);
        break;
      case ID_LINE_LOGIN:
        j = strlen(buf1);
        if (j > 32) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe administrator login is too long!\n\\end{center}\n");
          continue;
        }
        if (strspn(buf1, login_accept_chars) != j) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe administrator login contains invalid characters!\n\\end{center}\n");
          continue;
        }
        snprintf(config_login, sizeof(config_login), "%s", buf1);
        break;
      case ID_LINE_EMAIL:
        if (strspn(buf1, email_accept_chars) != strlen(buf1)) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe administrator e-mail contains invalid characters!\n\\end{center}\n");
          continue;
        }
        snprintf(config_email, sizeof(config_email), "%s", buf1);
        break;
      case ID_LINE_NAME:
        if (strspn(buf1, name_accept_chars) != strlen(buf1)) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe administrator name contains invalid characters!\n\\end{center}\n");
          continue;
        }
        snprintf(config_name, sizeof(config_name), "%s", buf1);
        break;
      default:
        abort();
      }

      cur_item = i;
      ret_val = 1;
      break;
    }
    if (c == 'd') {
      if (i == ID_LINE_RETURN || i == ID_LINE_SETTINGS) continue;

      j = ncurses_yesno(0, "\\begin{center}\nReset the variable to the initial value?\n\\end{center}\n");
      if (j <= 0) continue;

      cur_id_item = &id_edit_items[i];
      cur_id_item->buf[0] = 0;
      cur_item = i;
      ret_val = 1;
      break;
    }
  }

  // clear screen
  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);

  // free resources
  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (menu) free_menu(menu);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
  if (items) {
    for (i = 0; i < nitem; i++)
      if (items[i])
        free_item(items[i]);
    xfree(items);
  }
  if (descs) {
    for (i = 0; i < nitem; i++)
      xfree(descs[i]);
    xfree(descs);
  }

  *p_cur_item = cur_item;
  return ret_val;
}

static const struct path_edit_item set_edit_items[] =
{
  [SET_LINE_CHARSET] =
  {
    "Default charset", 1, config_charset, sizeof(config_charset),
    &config_charset_modified,
#if defined EJUDGE_CHARSET
    EJUDGE_CHARSET,
#endif /* EJUDGE_CHARSET */
  },
  [SET_LINE_SENDMAIL] =
  {
    "Sendmail program", 0, config_sendmail, sizeof(config_sendmail),
  },
  [SET_LINE_REG_EMAIL] =
  {
    "`register' email", 0, config_reg_email, sizeof(config_reg_email),
  },
  [SET_LINE_REG_URL] =
  {
    "`register' URL", 0, config_reg_url, sizeof(config_reg_url),
  },
  [SET_LINE_SERVER_NAME] =
  {
    "Server description", 0, config_server_name, sizeof(config_server_name),
  },
  [SET_LINE_SERVER_NAME_EN] =
  {
    "Server description (En)", 0, config_server_name_en, sizeof(config_server_name_en),
  },
  [SET_LINE_SERVER_MAIN_URL] =
  {
    "Server main URL", 0, config_server_main_url, sizeof(config_server_main_url),
  },
  [SET_LINE_SER_KEY] =
  {
    "Serialization key", 0, config_serialization_key,
    sizeof(config_serialization_key),
  },
  [SET_LINE_SYSTEM_UID] =
  {
    "System uid", 0, config_system_uid, sizeof(config_system_uid),
  },
  [SET_LINE_SYSTEM_GID] =
  {
    "System gid", 0, config_system_gid, sizeof(config_system_gid),
  },
  [SET_LINE_WORKDISK_FLAG] =
  {
    "Create workdisk?", 0, config_workdisk_flag, sizeof(config_workdisk_flag),
  },
  [SET_LINE_WORKDISK_SIZE] =
  {
    "Workdisk size (MB)", 0, config_workdisk_size,sizeof(config_workdisk_size),
  },
  [SET_LINE_INSTALL_FLAG] =
  {
    "Install to cgi-bin?", 0, config_install_flag, sizeof(config_install_flag),
  },
};

static void
initialize_setting_var(int idx)
{
  ASSERT(idx >= 0 && idx < SET_LINE_LAST);
  switch(idx) {
  case SET_LINE_RETURN:
  case SET_LINE_SETTINGS:
    break;
  case SET_LINE_CHARSET:
    if (set_edit_items[idx].default_value) {
      snprintf(config_charset, sizeof(config_charset), "%s",
               set_edit_items[idx].default_value);
    } else {
      config_charset[0] = 0;
    }
    config_charset_modified = 0;
    break;
  case SET_LINE_SENDMAIL:
    if (access("/usr/sbin/sendmail", X_OK) >= 0) {
      snprintf(config_sendmail, sizeof(config_sendmail), "%s",
               "/usr/sbin/sendmail");
    } else {
      config_sendmail[0] = 0;
    }
    break;
  case SET_LINE_REG_EMAIL:
    if (system_domainname[0]) {
      snprintf(config_reg_email, sizeof(config_reg_email), "%s@%s.%s",
               system_login, system_hostname, system_domainname);
    } else {
      snprintf(config_reg_email, sizeof(config_reg_email), "%s@%s",
               system_login, system_hostname);
    }
    break;
  case SET_LINE_REG_URL:
    if (system_domainname[0]) {
      snprintf(config_reg_url, sizeof(config_reg_url),
               "http://%s.%s/cgi-bin/register",
               system_hostname, system_domainname);
    } else {
      snprintf(config_reg_url, sizeof(config_reg_url),
               "http://%s/cgi-bin/register",
               system_hostname);
    }
    break;
  case SET_LINE_SERVER_NAME:
    snprintf(config_server_name, sizeof(config_server_name),
             "Novyi server turnirov");
    break;
  case SET_LINE_SERVER_NAME_EN:
    snprintf(config_server_name_en, sizeof(config_server_name_en),
             "New contest server");
    break;
  case SET_LINE_SERVER_MAIN_URL:
    if (system_domainname[0]) {
      snprintf(config_server_main_url, sizeof(config_server_main_url),
               "http://%s.%s",
               system_hostname, system_domainname);
    } else {
      snprintf(config_server_main_url, sizeof(config_server_main_url),
               "http://%s",
               system_hostname);
    }
    break;
  case SET_LINE_SER_KEY:
    snprintf(config_serialization_key, sizeof(config_serialization_key),
             "%d", DEFAULT_SERIALIZATION_KEY);
    break;
  case SET_LINE_SYSTEM_UID:
    snprintf(config_system_uid, sizeof(config_system_uid), "%s",
             system_login);
    break;
  case SET_LINE_SYSTEM_GID:
    snprintf(config_system_gid, sizeof(config_system_gid), "%s",
             system_group);
    break;
  case SET_LINE_WORKDISK_FLAG:
    snprintf(config_workdisk_flag, sizeof(config_workdisk_flag),
             "%s", "yes");
    break;
  case SET_LINE_INSTALL_FLAG:
    snprintf(config_install_flag, sizeof(config_install_flag),
             "%s", "yes");
    break;
  case SET_LINE_WORKDISK_SIZE:
    snprintf(config_workdisk_size, sizeof(config_workdisk_size),
             "%d", 32);
    break;
  default:
    SWERR(("initialize_setting_var: unhandled idx == %d", idx));
  }
}
static void
initialize_setting_vars(void)
{
  int i;

  for (i = 0; i < SET_LINE_LAST; i++)
    initialize_setting_var(i);
}
static int
is_valid_setting_var(int idx)
{
  ASSERT(idx >= 0 && idx < SET_LINE_LAST);
  switch(idx) {
  case SET_LINE_RETURN:
  case SET_LINE_SETTINGS:
  case SET_LINE_WORKDISK_FLAG:
  case SET_LINE_WORKDISK_SIZE:
  case SET_LINE_INSTALL_FLAG:
    return 1;
  case SET_LINE_CHARSET:
  case SET_LINE_REG_EMAIL:
  case SET_LINE_REG_URL:
  case SET_LINE_SER_KEY:
  case SET_LINE_SERVER_NAME:
  case SET_LINE_SERVER_NAME_EN:
  case SET_LINE_SERVER_MAIN_URL:
  case SET_LINE_SYSTEM_UID:
  case SET_LINE_SYSTEM_GID:
    if (set_edit_items[idx].buf[0]) return 1;
    return 0;
  case SET_LINE_SENDMAIL:
    if (!set_edit_items[idx].buf[0]) return 0;
    if (access(set_edit_items[idx].buf, X_OK) < 0) return 0;
    return 1;
  default:
    SWERR(("is_valid_setting_var: unhandled idx == %d", idx));
  }
}
static const unsigned char *
valid_setting_str(int idx)
{
  int res = is_valid_setting_var(idx);
  if (res) return " ";
  return "!";
}

static int
do_settings_menu(int *p_cur_item)
{
  int ret_val = 0;
  int cur_item = *p_cur_item;
  int nitem, i, c, cmd, first_row, j, n, val, menu_nitem = 0;
  char **descs = 0;
  ITEM **items = 0;
  MENU *menu = 0;
  WINDOW *in_win = 0, *out_win = 0;
  PANEL *in_pan = 0, *out_pan = 0;
  const struct path_edit_item *cur_set_item;
  unsigned char buf[PATH_MAX];
  struct stat stbuf;
  struct group *gg = 0;
  struct passwd *pp = 0;
  int *inv_map = 0;

  nitem = SET_LINE_LAST;
  XCALLOC(descs, nitem);
  XCALLOC(inv_map, nitem);

  for (i = 0; i < SET_LINE_LAST; i++) {
    switch (i) {
    case SET_LINE_RETURN:
      asprintf(&descs[menu_nitem], "Return to upper-level menu");
      inv_map[menu_nitem++] = SET_LINE_RETURN;
      break;
    case SET_LINE_SETTINGS:
      asprintf(&descs[menu_nitem], "*** Ejudge settings ***");
      inv_map[menu_nitem++] = SET_LINE_SETTINGS;
      break;
    case SET_LINE_CHARSET:
      asprintf(&descs[menu_nitem], "%-20.20s%s%s: %-53.53s",
               set_edit_items[i].descr,
               (*set_edit_items[i].updated_ptr)?"*":" ",
               valid_setting_str(i), set_edit_items[i].buf);
      inv_map[menu_nitem++] = i;
      break;
    case SET_LINE_REG_EMAIL:
    case SET_LINE_REG_URL:
    case SET_LINE_SENDMAIL:
    case SET_LINE_SER_KEY:
    case SET_LINE_SERVER_NAME:
    case SET_LINE_SERVER_NAME_EN:
    case SET_LINE_SERVER_MAIN_URL:
    case SET_LINE_SYSTEM_UID:
    case SET_LINE_SYSTEM_GID:
    case SET_LINE_WORKDISK_FLAG:
    case SET_LINE_INSTALL_FLAG:
      asprintf(&descs[menu_nitem], "%-20.20s %s: %-53.53s",
               set_edit_items[i].descr,
               valid_setting_str(i), set_edit_items[i].buf);
      inv_map[menu_nitem++] = i;
      break;
    case SET_LINE_WORKDISK_SIZE:
      if (!strcmp(config_workdisk_flag, "yes")) {
        asprintf(&descs[menu_nitem], "%-20.20s %s: %-53.53s",
                 set_edit_items[i].descr,
                 valid_setting_str(i), set_edit_items[i].buf);
        inv_map[menu_nitem++] = i;
      }
      break;
    default:
      SWERR(("do_settings_menu: unhandled index i == %d", i));
    }
  }

  XCALLOC(items, menu_nitem + 1);
  for (i = 0; i < menu_nitem; i++)
    items[i] = new_item(descs[i], 0);
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  set_menu_grey(menu, COLOR_PAIR(5));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  if (cur_item < 0) cur_item = 0;
  if (cur_item >= menu_nitem) cur_item = menu_nitem - 1;
  first_row = cur_item - (LINES - 4)/2;
  if (first_row + LINES - 4 > menu_nitem) first_row = menu_nitem - (LINES - 4);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[cur_item]);

  while (1) {
    mvwprintw(stdscr, 0, 0, "Ejudge %s configurator > Ejudge settings",
              compile_version);
    wclrtoeol(stdscr);
    ncurses_print_help("Q - quit, D - reset, Enter - edit, B - browse | * - modified, ! - invalid");
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      cmd = -1;
      switch (c) {
      case KEY_BACKSPACE: case KEY_DC: case 127: case 8:
      case 'd': case 'D': case '÷' & 255: case '×' & 255:
        c = 'd';
        goto menu_done;
      case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case '\n': case '\r':
        c = '\n';
        goto menu_done;
      case 'b': case 'B': case 'É' & 255: case 'é' & 255:
        c = 'b';
        goto menu_done;
      case KEY_UP: case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN: case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= menu_nitem) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;

      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }

    // handle menu command
  menu_done:
    ;
    i = inv_map[item_index(current_item(menu))];
    if (c == 'q') {
      cur_item = i;
      break;
    }
    if (c == '\n') {
      if (i == SET_LINE_RETURN) {
        cur_item = i;
        break;
      }
      if (i == SET_LINE_SETTINGS) continue;
      /*
      if (i == SET_LINE_SYSTEM_UID && system_uid != 0) {
        ncurses_msgbox("\\begin{center}\nNOTICE!\n\nYou cannot change this variable since you are not a root user.\n\\end{center}\n");
        continue;
      }
      */
      cur_set_item = &set_edit_items[i];
      if (!cur_set_item->buf) continue;

      if (i == SET_LINE_WORKDISK_FLAG) {
        j = ncurses_yesno(0, "\\begin{center}\nCreate working disk during installation?\n\\end{center}\n");
        if (j < 0) continue; 
        snprintf(config_workdisk_flag, sizeof(config_workdisk_flag),
                 "%s", j?"yes":"no");
        cur_item = i;
        ret_val = 1;
        break;
      }
      if (i == SET_LINE_INSTALL_FLAG) {
        j = ncurses_yesno(0, "\\begin{center}\nInstall symlinks to CGI tools to the web server cgi-bin directory?\n\\end{center}\n");
        if (j < 0) continue; 
        snprintf(config_install_flag, sizeof(config_install_flag),
                 "%s", j?"yes":"no");
        cur_item = i;
        ret_val = 1;
        break;
      }

      snprintf(buf, sizeof(buf), "%s", cur_set_item->buf);
      j = ncurses_edit_string(LINES/2, COLS, cur_set_item->descr,
                              buf, sizeof(buf), utf8_mode);
      if (j < 0) continue;

    check_variable_value:
      if (!strcmp(cur_set_item->buf, buf)) continue;

      if (i == SET_LINE_SYSTEM_UID) {
        if (!(pp = getpwnam(buf))) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nSuch user does not exist!\n\\end{center}\n");
          continue;
        }
        snprintf(config_system_uid, sizeof(config_system_uid), "%s", buf);
        cur_item = i;
        ret_val = 1;
        break;
      }
      if (i == SET_LINE_SYSTEM_GID) {
        if (!(gg = getgrnam(buf))) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nSuch group does not exist!\n\\end{center}\n");
          continue;
        }
        snprintf(config_system_gid, sizeof(config_system_gid), "%s", buf);
        cur_item = i;
        ret_val = 1;
        break;
      }
      if (i == SET_LINE_SER_KEY && buf[0]) {
        if (sscanf(buf, "%d%n", &val, &n) != 1 || buf[n]
            || val <= 0 || val >= 32768) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe serialization key must be an integer number in range [1,32767]!\n\\end{center}\n");
          continue;
        }
        snprintf(config_serialization_key, sizeof(config_serialization_key),
                 "%d", val);
        cur_item = i;
        ret_val = 1;
        break;
      }
      if (i == SET_LINE_WORKDISK_SIZE) {
        val = n = 0;
        if (sscanf(buf, "%d%n", &val, &n) != 1 || buf[n]
            || val < 8 || val > 1024) {
          ncurses_errbox("\\begin{center}\nERROR!\n\nThe work disk size must be an integer number in range [8,1024]!\n\\end{center}\n");
          continue;
        }
        snprintf(config_workdisk_size, sizeof(config_workdisk_size),
                 "%d", val);
        cur_item = i;
        ret_val = 1;
        break;
      }

      if (cur_set_item->is_builtin && !*cur_set_item->updated_ptr
          && cur_set_item->default_value && cur_set_item->default_value[0]) {
        j = ncurses_yesno(0, builtin_change_warning);
        if (j != 1) continue;
      }

      if (i == SET_LINE_SENDMAIL && buf[0]
          && (stat(buf, &stbuf) < 0 || !S_ISREG(stbuf.st_mode)
              || access(buf, X_OK) < 0)) {
        j = ncurses_yesno(0, "\\begin{center}WARNING!\n\nThis is not a regular file or it is not executable! Still set the variable to the new value?\n\\end{center}\n");
        if (j != 1) continue;
      }

      snprintf(cur_set_item->buf, cur_set_item->size, "%s", buf);
      if (cur_set_item->updated_ptr) *cur_set_item->updated_ptr = 1;
      cur_item = i;
      ret_val = 1;
      break;
    }
    if (c == 'd') {
      if (i == SET_LINE_RETURN || i == SET_LINE_SETTINGS) continue;

      j = ncurses_yesno(0, "\\begin{center}\nReset the variable to the initial value?\n\\end{center}\n");
      if (j <= 0) continue;

      initialize_setting_var(i);
      cur_item = i;
      ret_val = 1;
      break;
    }
    if (c == 'b') {
      if (i != SET_LINE_SENDMAIL) continue;
      cur_set_item = &set_edit_items[i];
      if (!cur_set_item->buf) continue;
      snprintf(buf, sizeof(buf), "%s", cur_set_item->buf);
      j = ncurses_choose_file(cur_set_item->descr, buf, sizeof(buf), utf8_mode);
      if (j < 0) continue;
      goto check_variable_value;
    }
  }

  // clear screen
  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);

  // free resources
  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (menu) free_menu(menu);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
  if (items) {
    for (i = 0; i < menu_nitem; i++)
      if (items[i])
        free_item(items[i]);
    xfree(items);
  }
  if (descs) {
    for (i = 0; i < nitem; i++)
      xfree(descs[i]);
    xfree(descs);
  }

  *p_cur_item = cur_item;
  return ret_val;
}

static void
base64_encode_file(FILE *f, const unsigned char *path, int mode,
                   const unsigned char *str)
{
  size_t in_len, out_len, i;
  unsigned char *out_buf;

  if (!str) str = "";
  in_len = strlen(str);
  XCALLOC(out_buf, in_len * 2 + 10);
  out_len = base64_encode(str, in_len, out_buf);
  fprintf(f, "begin-base64 %03o %s\n", mode & 0777, path);
  for (i = 0; i < out_len; i++) {
    if (i > 0 && (i % 60) == 0) fprintf(f, "\n");
    putc(out_buf[i], f);
  }
  fprintf(f, "\n====\n");
  xfree(out_buf);
}

static void
generate_current_date(unsigned char *buf, size_t size)
{
  time_t curtime;
  struct tm *ptm;

  curtime = time(0);
  ptm = localtime(&curtime);
  snprintf(buf, size, "%04d/%02d/%02d %02d:%02d:%02d",
          ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

static const unsigned char *
c_armor_2(
        struct html_armor_buffer *pa,
        const unsigned char *str, 
        const unsigned char *pfx)
{
  int plen;
  const unsigned char *s;

  // FIXME: do armoring
  if (!os_IsAbsolutePath(str) || !pfx || !pfx[0]
      || !os_IsAbsolutePath(pfx)) return str;
  plen = strlen(pfx);
  if (strncmp(str, pfx, plen) != 0) return str;
  s = str + plen;
  while (*s == '/') s++;
  return s;
}
static const unsigned char *
xml_armor_2(
        struct html_armor_buffer *pa,
        const unsigned char *str, 
        const unsigned char *pfx)
{
  int plen;
  const unsigned char *s;

  // FIXME: do armoring
  if (!os_IsAbsolutePath(str) || !pfx || !pfx[0]
      || !os_IsAbsolutePath(pfx))
    return html_armor_buf(pa, str);
  plen = strlen(pfx);
  if (strncmp(str, pfx, plen) != 0)
    return html_armor_buf(pa, str);
  s = str + plen;
  while (*s == '/') s++;
  return html_armor_buf(pa, s);
}

static int
is_cgi_config_needed(void)
{
  const struct path_edit_item *cur = 0;

  // check, that socket_path, contests_dir, l10n_dir and charset have
  // default values

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (!cur->default_value || !cur->default_value[0]
      || strcmp(cur->buf, cur->default_value) != 0)
    return 1;

  cur = &path_edit_items[PATH_LINE_SUPER_SERVE_SOCKET];
  if (!cur->default_value || !cur->default_value[0]
      || strcmp(cur->buf, cur->default_value) != 0)
    return 1;

  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (!cur->default_value || !cur->default_value[0]
      || strcmp(cur->buf, cur->default_value) != 0)
    return 1;

  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (!cur->default_value || !cur->default_value[0]
      || strcmp(cur->buf, cur->default_value) != 0)
    return 1;

  cur = &set_edit_items[SET_LINE_CHARSET];
  if (!cur->default_value || !cur->default_value[0]
      || strcmp(cur->buf, cur->default_value) != 0)
    return 1;

  return 0;
}

static void
generate_users_xml(FILE *f, const unsigned char *prefix)
{
  unsigned char date_buf[64];
  const struct path_edit_item *cur = 0;
  int nbuiltin = 0;

  generate_current_date(date_buf, sizeof(date_buf));
  if (config_charset[0]) {
    fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", config_charset);
  } else {
    fprintf(f, "<?xml version=\"1.0\" ?>\n");
  }
  fprintf(f, "<!-- Generated by ejudge-setup, version %s -->\n",
          compile_version);
  fprintf(f, "<!-- Generation date: %s -->\n", date_buf);

  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "<%s_config>\n", prefix);
  } else {
    fprintf(f, "<%s_config charset=\"%s\">\n", prefix, cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "  <socket_path>%s</socket_path>\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "  <contests_dir>%s</contests_dir>\n", cur->buf);
  }
#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "  <l10n_dir>%s</l10n_dir>\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */

  if (nbuiltin) {
    fprintf(f, "\n  <!-- The built-in variables are as follows -->\n");
  }

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- <socket_path>%s</socket_path> -->\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- <contests_dir>%s</contests_dir> -->\n", cur->buf);
  }
#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- <l10n_dir>%s</l10n_dir> -->\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */

  fprintf(f, "</%s_config>\n", prefix);
}

static void
generate_master_cfg(FILE *f)
{
  unsigned char date_buf[64];
  const struct path_edit_item *cur = 0;
  int nbuiltin = 0;

  generate_current_date(date_buf, sizeof(date_buf));

  fprintf(f, "# Generated by ejudge-setup, version %s\n", compile_version);
  fprintf(f, "# Generation date: %s\n\n", date_buf);

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "socket_path = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "contests_dir = \"%s\"\n", cur->buf);
  }
#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "l10n_dir = \"%s\"\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */
  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "charset = \"%s\"\n", cur->buf);
  }

  if (nbuiltin) {
    fprintf(f, "\n; The built-in variables are as follows\n");
  }

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# socket_path = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# contests_dir = \"%s\"\n", cur->buf);
  }
#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# l10n_dir = \"%s\"\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */
  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# charset = \"%s\"\n", cur->buf);
  }
}

static void
generate_serve_cfg(FILE *f)
{
  unsigned char date_buf[64];
  const struct path_edit_item *cur = 0;
  int nbuiltin = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t check_dir;

  generate_current_date(date_buf, sizeof(date_buf));

  fprintf(f, "# %cId%c\n", '$', '$');
  fprintf(f, "# Generated by ejudge-setup, version %s\n", compile_version);
  fprintf(f, "# Generation date: %s\n\n", date_buf);

  fprintf(f, "contest_id = 1\n");
  fprintf(f, "root_dir = \"%s\"\n\n",
          c_armor_2(&ab, config_contest1_home_dir,
                    config_ejudge_contests_home_dir));

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "socket_path = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "contests_dir = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_SCRIPT_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "script_dir = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_HTDOCS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "htdocs_dir = \"%s\"\n", cur->buf);
  }
#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "l10n_dir = \"%s\"\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */
  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    nbuiltin++;
  } else {
    fprintf(f, "charset = \"%s\"\n", cur->buf);
  }

  if (nbuiltin) {
    fprintf(f, "# The built-in variables are as follows\n");
  }

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# socket_path = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# contests_dir = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_SCRIPT_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# script_dir = \"%s\"\n", cur->buf);
  }
  cur = &path_edit_items[PATH_LINE_HTDOCS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# htdocs_dir = \"%s\"\n", cur->buf);
  }
#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# l10n_dir = \"%s\"\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */
  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "# charset = \"%s\"\n", cur->buf);
  }

  fprintf(f, "\n");
  fprintf(f,
          "test_dir = \"../tests\"\n"
          "checker_dir = \"../checkers\"\n"
          "statement_dir = \"../statements\"\n"
          "corr_dir = \"../tests\"\n"
          "test_sfx = \".dat\"\n"
          "corr_sfx = \".ans\"\n"
          "\n"
          "standings_locale = \"ru\"\n"
          "standings_file_name = \"standings.html\"\n");
  if (config_stand_html_path[0]) {
    fprintf(f, "stand_symlink_dir = \"%s\"\n", config_stand_html_path);
  }
  fprintf(f,
          "team_download_time = 0\n"
          "problem_navigation\n"
          "\n"
          "contest_time = 300\n"
          "sleep_time = 1000\n"
          "cr_serialization_key = %s\n"
          "ignore_duplicated_runs\n"
          "score_system = \"acm\"\n"
          "enable_continue\n"
          "compile_dir = \"%s/var/compile\"\n"
          "cpu_bogomips = %d\n\n",
          config_serialization_key, config_compile_home_dir,
          cpu_get_bogomips());

#if CONF_HAS_SECURE_EXEC - 0 == 1
  fprintf(f, "secure_run\n");
  fprintf(f, "detect_violations\n");
#endif

#if defined COMPILE_FPC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 1\n"
          "short_name = \"fpc\"\n"
          "long_name = \"Free Pascal %s\"\n"
          "src_sfx = \".pas\"\n"
          "\n",
          COMPILE_FPC_VERSION);
#endif /* COMPILE_FPC_VERSION */
  
#if defined COMPILE_GCC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 2\n"
          "short_name = \"gcc\"\n"
          "long_name = \"GNU C %s\"\n"
          "src_sfx = \".c\"\n"
          "\n",
          COMPILE_GCC_VERSION);
#endif /* COMPILE_GCC_VERSION */

#if defined COMPILE_GPP_VERSION
  fprintf(f,
          "[language]\n"
          "id = 3\n"
          "short_name = \"g++\"\n"
          "long_name = \"GNU C++ %s\"\n"
          "src_sfx = \".cpp\"\n"
          "\n",
          COMPILE_GPP_VERSION);
#endif /* COMPILE_GPP_VERSION */

#if defined COMPILE_GPC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 4\n"
          "short_name = \"gpc\"\n"
          "long_name = \"GNU Pascal %s\"\n"
          "src_sfx = \".pas\"\n"
          "\n",
          COMPILE_GPC_VERSION);
#endif /* COMPILE_GPC_VERSION */

#if defined COMPILE_GCJ_VERSION
  fprintf(f,
          "[language]\n"
          "id = 5\n"
          "short_name = \"gcj\"\n"
          "long_name = \"GNU Java (GCJ) %s\"\n"
          "src_sfx = \".java\"\n"
          "arch = linux-shared\n"
          "\n",
          COMPILE_GCJ_VERSION);
#endif /* COMPILE_GCJ_VERSION */

#if defined COMPILE_G77_VERSION
  fprintf(f,
          "[language]\n"
          "id = 6\n"
          "short_name = \"g77\"\n"
          "long_name = \"GNU Fortran 77 %s\"\n"
          "src_sfx = \".for\"\n"
          "\n",
          COMPILE_G77_VERSION);
#endif /* COMPILE_G77_VERSION */

  // not yet supported, so always commented out
#if defined COMPILE_TPC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 7\n"
          "short_name = \"tpc\"\n"
          "long_name = \"Turbo Pascal %s\"\n"
          "src_sfx = \".pas\"\n"
          "exe_sfx = \".exe\"\n"
          "arch = dos\n"
          "\n",
          COMPILE_TPC_VERSION);
#endif /* COMPILE_TPC_VERSION */

#if defined COMPILE_DCC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 8\n"
          "short_name = \"dcc\"\n"
          "long_name = \"Borland Delphi %s\"\n"
          "src_sfx = \".pas\"\n"
          "arch = linux-shared\n"
          "\n",
          COMPILE_DCC_VERSION);
#endif /* COMPILE_DCC_VERSION */

  // not yet supported, so always commented out
#if defined COMPILE_BCC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 9\n"
          "short_name = \"bcc\"\n"
          "long_name = \"Borland C %s\"\n"
          "src_sfx = \".c\"\n"
          "exe_sfx = \".exe\"\n"
          "arch = dos\n"
          "\n",
          COMPILE_BCC_VERSION);
#endif /* COMPILE_BCC_VERSION */

  // not yet supported, so always commented out
#if defined COMPILE_BPP_VERSION
  fprintf(f,
          "[language]\n"
          "id = 10\n"
          "short_name = \"bpp\"\n"
          "long_name = \"Borland C++ %s\"\n"
          "src_sfx = \".cpp\"\n"
          "exe_sfx = \".exe\"\n"
          "cmd = \"bppemu\"\n"
          "\n",
          COMPILE_BPP_VERSION);
#endif /* COMPILE_BPP_VERSION */

#if defined COMPILE_YABASIC_VERSION
  fprintf(f,
          "[language]\n"
          "id = 11\n"
          "short_name = \"basic\"\n"
          "long_name = \"Yabasic %s\"\n"
          "src_sfx = \".bas\"\n"
          "arch = linux-shared\n"
          "\n",
          COMPILE_YABASIC_VERSION);
#endif /* COMPILE_YABASIC_VERSION */

#if defined COMPILE_MZSCHEME_VERSION
  fprintf(f,
          "[language]\n"
          "id = 12\n"
          "short_name = \"scheme\"\n"
          "long_name = \"Mz Scheme %s\"\n"
          "src_sfx = \".scm\"\n"
          "arch = linux-shared\n"
          "\n",
          COMPILE_MZSCHEME_VERSION);
#endif /* COMPILE_MZSCHEME_VERSION */

#if defined COMPILE_PYTHON_VERSION
  fprintf(f,
          "[language]\n"
          "id = 13\n"
          "short_name = \"python\"\n"
          "long_name = \"Python %s\"\n"
          "src_sfx = \".py\"\n"
          "arch = linux-shared\n"
          "\n",
          COMPILE_PYTHON_VERSION);
#endif /* COMPILE_PYTHON_VERSION */

#if defined COMPILE_PERL_VERSION
  fprintf(f,
          "[language]\n"
          "id = 14\n"
          "short_name = \"perl\"\n"
          "long_name = \"Perl %s\"\n"
          "src_sfx = \".pl\"\n"
          "arch = \"linux-shared\"\n"
          "\n",
          COMPILE_PERL_VERSION);
#endif /* COMPILE_PERL_VERSION */

#if defined COMPILE_GPROLOG_VERSION
  fprintf(f,
          "[language]\n"
          "id = 15\n"
          "short_name = \"prolog\"\n"
          "long_name = \"GNU Prolog %s\"\n"
          "src_sfx = \".pro\"\n"
          "arch = \"linux-shared\"\n"
          "\n",
          COMPILE_GPROLOG_VERSION);
#endif /* COMPILE_GPROLOG_VERSION */

  // not yet supported, so always commented out
#if defined COMPILE_QB_VERSION
  fprintf(f,
          "[language]\n"
          "id = 16\n"
          "short_name = \"qb\"\n"
          "long_name = \"Quick Basic %s\"\n"
          "src_sfx = \".bas\"\n"
          "exe_sfx = \".exe\"\n"
          "arch = dos\n"
          "\n",
          COMPILE_QB_VERSION);
#endif /* COMPILE_QB_VERSION */

#if defined COMPILE_JAVA_VERSION
  fprintf(f,
          "[language]\n"
          "id = 18\n"
          "short_name = \"java\"\n"
          "long_name = \"Java %s\"\n"
          "src_sfx = \".java\"\n"
          "exe_sfx = \".jar\"\n"
          "arch = \"java\"\n"
          "\n",
          COMPILE_JAVA_VERSION);
#endif /* COMPILE_JAVA_VERSION */

#if defined COMPILE_MONO_VERSION
  fprintf(f,
          "# Note, support for Mono C# is experimental!\n"
          "# [language]\n"
          "# id = 19\n"
          "# short_name = \"CS\"\n"
          "# long_name = \"Mono C# %s\"\n"
          "# disabled = 1 # Enable manually!\n"
          "# src_sfx = \".cs\"\n"
          "# exe_sfx = \".exe\"\n"
          "# arch = \"msil\"\n"
          "# \n",
          COMPILE_MONO_VERSION);
#endif /* COMPILE_MONO_VERSION */

#if defined COMPILE_MBAS_VERSION
  fprintf(f,
          "# Note, support for Mono Visual Basic is experimental!\n"
          "# [language]\n"
          "# id = 20\n"
          "# short_name = \"VB\"\n"
          "# long_name = \"Mono Visual Basic %s\"\n"
          "# disabled = 1 # Enable manually!\n"
          "# src_sfx = \".vb\"\n"
          "# exe_sfx = \".exe\"\n"
          "# arch = \"msil\"\n"
          "# \n",
          COMPILE_MBAS_VERSION);
#endif /* COMPILE_MBAS_VERSION */

  fputs("[problem]\n"
        "short_name = Generic\n"
        "abstract\n"
        "use_stdin = 1\n"
        "use_stdout = 1\n"
        "use_corr = 1\n"
        "corr_dir = \"%Ps\"\n"
        "real_time_limit = 30\n"
        "check_cmd = \"check_%lPs\"\n"
        "xml_file = \"%Ps.xml\"\n"
        "max_vm_size = 64M\n"
        "time_limit = 1\n"
        "\n"
        "[problem]\n"
        "short_name = \"A\"\n"
        "super = Generic\n"
        "long_name = \"Sum 1\"\n"
        "standard_checker = cmp_int\n"
        "\n"
        "[problem]\n"
        "short_name = \"B\"\n"
        "super = Generic\n"
        "long_name = \"Sum 2\"\n"
        "standard_checker = cmp_int\n"
        "\n",
        f);

  fputs("[tester]\n"
        "name = Generic\n"
        "abstract\n"
        "no_core_dump\n"
        "kill_signal = KILL\n"
        "memory_limit_type = \"default\"\n"
        "secure_exec_type = \"static\"\n"
        "clear_env\n",
        f);
  /*
#if CONF_HAS_LIBCAP - 0 == 1
  fprintf(f, "start_cmd = \"capexec\"\n");
#endif
  */
  check_dir[0] = 0;
  if (!strcmp(config_workdisk_flag, "yes")) {
    snprintf(check_dir, sizeof(check_dir), "%s/work",
             config_workdisk_mount_dir);
  } else {
    if (config_testing_work_dir[0]) {
      snprintf(check_dir, sizeof(check_dir), "%s", config_testing_work_dir);
    }
  }
  if (check_dir[0]) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor_2(&ab, check_dir, config_ejudge_contests_home_dir));
  }
  fputs("\n", f);
  
  fputs("[tester]\n"
        "name = Linux-shared\n"
        "arch = linux-shared\n"
        "abstract\n"
        "no_core_dump\n"
        "kill_signal = KILL\n"
        "memory_limit_type = \"default\"\n"
        "secure_exec_type = \"dll\"\n"
        "clear_env\n",
        f);
  /*
#if CONF_HAS_LIBCAP - 0 == 1
  fprintf(f,
          "start_env = \"LD_BIND_NOW=1\"\n"
          "start_env = \"LD_PRELOAD=${script_dir}/libdropcaps.so\"\n");
#endif
  */
  if (check_dir[0]) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor_2(&ab, check_dir, config_ejudge_contests_home_dir));
  }
  fputs("\n", f);

#if defined COMPILE_JAVA_VERSION
  fputs("[tester]\n"
        "name = Linux-java\n"
        "arch = java\n"
        "abstract\n"
        "no_core_dump\n"
        "kill_signal = TERM\n"
        "memory_limit_type = \"java\"\n"
        "secure_exec_type = \"java\"\n"
        "start_cmd = runjava\n"
        "start_env = \"LANG=C\"\n"
        "start_env = \"EJUDGE_PREFIX_DIR\"\n",
        f);

  if (check_dir[0]) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor_2(&ab, check_dir, config_ejudge_contests_home_dir));
  }
  fputs("\n", f);
#endif /* COMPILE_JAVA_VERSION */

#if 0 // disable it for now...
#if defined COMPILE_MONO_VERSION
  fputs("[tester]\n"
        "name = Linux-msil\n"
        "arch = msil\n"
        "abstract\n"
        "no_core_dump\n"
        "kill_signal = TERM\n"
        "memory_limit_type = \"default\"\n"
        //        "secure_exec_type = \"mono\"\n" -- not implemented
        "start_cmd = runmono\n"
        "start_env = \"EJUDGE_PREFIX_DIR\"\n"
        "# start_env = \"EJUDGE_MONO_FLAGS=\"\n",
        f);

  if (check_dir[0]) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor_2(&ab, check_dir, config_ejudge_contests_home_dir));
  }
  fputs("\n", f);
#endif /* COMPILE_MONO_VERSION */
#endif

  fputs("[tester]\n"
        "any\n"
        "super = Generic\n"
        "\n"
        "[tester]\n"
        "any\n"
        "super = Linux-shared\n"
        "arch = linux-shared\n",
        f);

#if defined COMPILE_JAVA_VERSION
  fputs("\n"
        "[tester]\n"
        "any\n"
        "super = Linux-java\n"
        "arch = java\n",
        f);
#endif /* COMPILE_JAVA_VERSION */

  // disable it for now...
#if 0
#if defined COMPILE_MONO_VERSION
  fputs("\n"
        "[tester]\n"
        "any\n"
        "super = Linux-msil\n"
        "arch = msil\n",
        f);
#endif /* COMPILE_MONO_VERSION */
#endif

  html_armor_free(&ab);
}

static void
generate_compile_cfg(FILE *f)
{
  unsigned char date_buf[64];
  const unsigned char *cmt, *version;

  generate_current_date(date_buf, sizeof(date_buf));

  fprintf(f, "# Generated by ejudge-setup, version %s\n", compile_version);
  fprintf(f, "# Generation date: %s\n\n", date_buf);
  fprintf(f, "root_dir = %s\n", config_compile_home_dir);
  fprintf(f, "cr_serialization_key = %s\n\n", config_serialization_key);

  fprintf(f,
          "sleep_time = 1000\n"
          "\n");

#if defined COMPILE_FPC_VERSION
  cmt = ""; version = COMPILE_FPC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_FPC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 1\n"
          "%sshort_name = \"fpc\"\n"
          "%slong_name = \"Free Pascal %s\"\n"
          "%ssrc_sfx = \".pas\"\n"
          "%scmd = \"fpc\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt);
  
#if defined COMPILE_GCC_VERSION
  cmt = ""; version = COMPILE_GCC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_GCC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 2\n"
          "%sshort_name = \"gcc\"\n"
          "%slong_name = \"GNU C %s\"\n"
          "%ssrc_sfx = \".c\"\n"
          "%scmd = \"gcc\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt);

#if defined COMPILE_GPP_VERSION
  cmt = ""; version = COMPILE_GPP_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_GPP_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 3\n"
          "%sshort_name = \"g++\"\n"
          "%slong_name = \"GNU C++ %s\"\n"
          "%ssrc_sfx = \".cpp\"\n"
          "%scmd = \"g++\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt);

#if defined COMPILE_GPC_VERSION
  cmt = ""; version = COMPILE_GPC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_GPC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 4\n"
          "%sshort_name = \"gpc\"\n"
          "%slong_name = \"GNU Pascal %s\"\n"
          "%ssrc_sfx = \".pas\"\n"
          "%scmd = \"gpc\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt);

#if defined COMPILE_GCJ_VERSION
  cmt = ""; version = COMPILE_GCJ_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_GCJ_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 5\n"
          "%sshort_name = \"gcj\"\n"
          "%slong_name = \"GNU Java (GCJ) %s\"\n"
          "%ssrc_sfx = \".java\"\n"
          "%scmd = \"gcj\"\n"
          "arch = linux-shared\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt);

#if defined COMPILE_G77_VERSION
  cmt = ""; version = COMPILE_G77_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_G77_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 6\n"
          "%sshort_name = \"g77\"\n"
          "%slong_name = \"GNU Fortran 77 %s\"\n"
          "%ssrc_sfx = \".for\"\n"
          "%scmd = \"g77\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt);

  // not yet supported, so always commented out
#if defined COMPILE_TPC_VERSION
  cmt = ""; version = COMPILE_TPC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_TPC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 7\n"
          "%sshort_name = \"tpc\"\n"
          "%slong_name = \"Turbo Pascal %s\"\n"
          "%ssrc_sfx = \".pas\"\n"
          "%sexe_sfx = \".exe\"\n"
          "%scmd = \"bpcemu2\"\n"
          "%sarch = dos\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

#if defined COMPILE_DCC_VERSION
  cmt = ""; version = COMPILE_DCC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_DCC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 8\n"
          "%sshort_name = \"dcc\"\n"
          "%slong_name = \"Borland Delphi %s\"\n"
          "%ssrc_sfx = \".pas\"\n"
          "%scmd = \"dcc\"\n"
          "%sarch = linux-shared\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt);

  // not yet supported, so always commented out
#if defined COMPILE_BCC_VERSION
  cmt = ""; version = COMPILE_BCC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_BCC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 9\n"
          "%sshort_name = \"bcc\"\n"
          "%slong_name = \"Borland C %s\"\n"
          "%ssrc_sfx = \".c\"\n"
          "%sexe_sfx = \".exe\"\n"
          "%scmd = \"bccemu\"\n"
          "%sarch = dos\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

  // not yet supported, so always commented out
#if defined COMPILE_BPP_VERSION
  cmt = ""; version = COMPILE_BPP_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_BPP_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 10\n"
          "%sshort_name = \"bpp\"\n"
          "%slong_name = \"Borland C++ %s\"\n"
          "%ssrc_sfx = \".cpp\"\n"
          "%sexe_sfx = \".exe\"\n"
          "%scmd = \"bppemu\"\n"
          "%sarch = dos\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

#if defined COMPILE_YABASIC_VERSION
  cmt = ""; version = COMPILE_YABASIC_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_YABASIC_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 11\n"
          "%sshort_name = \"basic\"\n"
          "%slong_name = \"Yabasic %s\"\n"
          "%ssrc_sfx = \".bas\"\n"
          "%scmd = \"yabasic\"\n"
          "%sarch = linux-shared\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt);

#if defined COMPILE_MZSCHEME_VERSION
  cmt = ""; version = COMPILE_MZSCHEME_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_MZSCHEME_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 12\n"
          "%sshort_name = \"scheme\"\n"
          "%slong_name = \"Mz Scheme %s\"\n"
          "%ssrc_sfx = \".scm\"\n"
          "%scmd = \"mzscheme\"\n"
          "%sarch = linux-shared\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt);

#if defined COMPILE_PYTHON_VERSION
  cmt = ""; version = COMPILE_PYTHON_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_PYTHON_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 13\n"
          "%sshort_name = \"python\"\n"
          "%slong_name = \"Python %s\"\n"
          "%ssrc_sfx = \".py\"\n"
          "%scmd = \"python\"\n"
          "%sarch = linux-shared\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt);

#if defined COMPILE_PERL_VERSION
  cmt = ""; version = COMPILE_PERL_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_PERL_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 14\n"
          "%sshort_name = \"perl\"\n"
          "%slong_name = \"Perl %s\"\n"
          "%ssrc_sfx = \".pl\"\n"
          "%scmd = \"perl\"\n"
          "%sarch = \"linux-shared\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt);

#if defined COMPILE_GPROLOG_VERSION
  cmt = ""; version = COMPILE_GPROLOG_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_GPROLOG_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 15\n"
          "%sshort_name = \"prolog\"\n"
          "%slong_name = \"GNU Prolog %s\"\n"
          "%ssrc_sfx = \".pro\"\n"
          "%scmd = \"gprolog\"\n"
          "%sarch = \"linux-shared\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt);

  // not yet supported, so always commented out
#if defined COMPILE_QB_VERSION
  cmt = ""; version = COMPILE_QB_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_QB_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 16\n"
          "%sshort_name = \"qb\"\n"
          "%slong_name = \"Quick Basic %s\"\n"
          "%ssrc_sfx = \".bas\"\n"
          "%sexe_sfx = \".exe\"\n"
          "%scmd = \"qbemu\"\n"
          "%sarch = dos\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

#if defined COMPILE_JAVA_VERSION
  cmt = ""; version = COMPILE_JAVA_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_JAVA_VERSION */
  fprintf(f,
          "%s[language]\n"
          "%sid = 18\n"
          "%sshort_name = \"java\"\n"
          "%slong_name = \"Java %s\"\n"
          "%ssrc_sfx = \".java\"\n"
          "%sexe_sfx = \".jar\"\n"
          "%scmd = \"javac\"\n"
          "%sarch = \"java\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

#if defined COMPILE_MONO_VERSION
  cmt = ""; version = COMPILE_MONO_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_MONO_VERSION */

  // disable it for now...
  cmt = "#";

  fprintf(f,
          "%s[language]\n"
          "%sid = 19\n"
          "%sshort_name = \"CS\"\n"
          "%slong_name = \"Mono C# %s\"\n"
          "%ssrc_sfx = \".cs\"\n"
          "%sexe_sfx = \".exe\"\n"
          "%scmd = \"mcs\"\n"
          "%sarch = \"msil\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

#if defined COMPILE_MBAS_VERSION
  cmt = ""; version = COMPILE_MBAS_VERSION;
#else
  cmt = "# "; version = "";
#endif /* COMPILE_MBAS_VERSION */

  // disable it for now...
  cmt = "#";

  fprintf(f,
          "%s[language]\n"
          "%sid = 20\n"
          "%sshort_name = \"VB\"\n"
          "%slong_name = \"Mono Visual Basic %s\"\n"
          "%ssrc_sfx = \".vb\"\n"
          "%sexe_sfx = \".exe\"\n"
          "%scmd = \"mbas\"\n"
          "%sarch = \"msil\"\n"
          "%s\n",
          cmt, cmt, cmt, cmt, version, cmt, cmt, cmt, cmt, cmt);

  /*
  fprintf(f,
          "[language]\n"
          "id = 21\n"
          "short_name = \"txt\"\n"
          "long_name = \"Plain text\"\n"
          "src_sfx = \".txt\"\n"
          "cmd = \"txt\"\n"
          "\n");
  */
}

static void
generate_contest_xml(FILE *f)
{
  unsigned char date_buf[64];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  generate_current_date(date_buf, sizeof(date_buf));

  if (config_charset[0]) {
    fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", config_charset);
  } else {
    fprintf(f, "<?xml version=\"1.0\" ?>\n");
  }
  fprintf(f, "<!-- %cId%c -->\n", '$', '$');
  fprintf(f, "<!-- Generated by ejudge-setup, version %s -->\n",
          compile_version);
  fprintf(f, "<!-- Generation date: %s -->\n", date_buf);

  fprintf(f,
          "<contest id=\"1\" disable_team_password=\"yes\" new_managed=\"yes\" run_managed=\"yes\">\n"
          "  <name>Test contest</name>\n"
          "  <name_en>Test contest</name_en>\n"
          "\n"
          "  <register_access default=\"deny\">\n"
          "    <ip allow=\"yes\">127.</ip>\n"
          "  </register_access>\n"
          "  <users_access default=\"deny\">\n"
          "    <ip allow=\"yes\">127.</ip>\n"
          "  </users_access>\n"
          "  <team_access default=\"deny\">\n"
          "    <ip allow=\"yes\">127.</ip>\n"
          "  </team_access>\n"
          "  <judge_access default=\"deny\">\n"
          "    <ip allow=\"yes\">127.</ip>\n"
          "  </judge_access>\n"
          "  <master_access default=\"deny\">\n"
          "    <ip allow=\"yes\">127.</ip>\n"
          "  </master_access>\n"
          "  <serve_control_access default=\"deny\">\n"
          "    <ip allow=\"yes\">127.</ip>\n"
          "  </serve_control_access>\n"
          "\n"
          "  <caps>\n"
          "    <cap login=\"%s\">\n"
          "      MASTER_LOGIN,\n"
          "      JUDGE_LOGIN,\n"
          "      SUBMIT_RUN,\n"
          "      MAP_CONTEST,\n"
          "      LIST_USERS,\n"
          "      GET_USER,\n"
          "      EDIT_USER,\n"
          "      CREATE_REG,\n"
          "      EDIT_REG,\n"
          "      DELETE_REG,\n"
          "      PRIV_CREATE_REG,\n"
          "      DUMP_USERS,\n"
          "      DUMP_RUNS,\n"
          "      DUMP_STANDINGS,\n"
          "      VIEW_STANDINGS,\n"
          "      VIEW_SOURCE,\n"
          "      VIEW_REPORT,\n"
          "      VIEW_CLAR,\n"
          "      EDIT_RUN,\n"
          "      REJUDGE_RUN,\n"
          "      NEW_MESSAGE,\n"
          "      REPLY_MESSAGE,\n"
          "      CONTROL_CONTEST,\n"
          "      IMPORT_XML_RUNS,\n"
          "      PRINT_RUN,\n"
          "      EDIT_CONTEST,\n"
          "      PRIV_EDIT_REG,\n"
          "      EDIT_PASSWD,\n"
          "      PRIV_EDIT_REG,\n"
          "    </cap>\n"
          "  </caps>\n"
          "\n"
          "  <client_flags>\n"
          "    IGNORE_TIME_SKEW,\n"
          "  </client_flags>\n"
          "\n"
          "  <root_dir>%s</root_dir>\n"
          "</contest>\n", config_login,
          xml_armor_2(&ab, config_contest1_home_dir,
                      config_ejudge_contests_home_dir));
  html_armor_free(&ab);
}

static void
generate_userlist_xml(FILE *f)
{
  unsigned char date_buf[64];

  generate_current_date(date_buf, sizeof(date_buf));

  if (config_charset[0]) {
    fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", config_charset);
  } else {
    fprintf(f, "<?xml version=\"1.0\" ?>\n");
  }

  fprintf(f, "<userlist member_serial=\"1\" name=\"unknown\">\n");
  fprintf(f, "  <user id=\"%s\" never_clean=\"yes\" registered=\"%s\" last_login=\"%s\">\n", config_user_id, date_buf, date_buf);
  fprintf(f, "    <login public=\"no\">%s</login>\n", config_login);
  fprintf(f, "    <password method=\"sha1\">%s</password>\n",
          config_password_sha1);
  fprintf(f, "    <team_password method=\"sha1\">%s</team_password>\n",
          config_password_sha1);
  fprintf(f, "    <name>%s</name>\n", config_name);
  fprintf(f, "    <email public=\"no\">%s</email>\n", config_email);
  fprintf(f,
          "    <contests>\n"
          "      <contest id=\"1\" status=\"ok\"/>\n"
          "    </contests>\n");
  fprintf(f, "  </user>\n");
  fprintf(f, "</userlist>\n");
}

static void
generate_ejudge_xml(FILE *f)
{
  const struct path_edit_item *cur;
  unsigned char date_buf[64];
  unsigned char tmppath[PATH_MAX];

  generate_current_date(date_buf, sizeof(date_buf));

  if (config_charset[0]) {
    fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", config_charset);
  } else {
    fprintf(f, "<?xml version=\"1.0\" ?>\n");
  }
  fprintf(f, "<!-- Generated by ejudge-setup, version %s -->\n",
          compile_version);
  fprintf(f, "<!-- Generation date: %s -->\n", date_buf);

#if CONF_HAS_LIBINTL - 0 == 1
  fprintf(f, "<config l10n=\"yes\">\n");
#else
  fprintf(f, "<config>\n");
#endif /* CONF_HAS_LIBINTL */

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <socket_path>%s</socket_path>\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_SUPER_SERVE_SOCKET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <super_serve_socket>%s</super_serve_socket>\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <contests_dir>%s</contests_dir>\n", cur->buf);
  }

#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <l10n_dir>%s</l10n_dir>\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */

  cur = &path_edit_items[PATH_LINE_SCRIPT_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <script_dir>%s</script_dir>\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_SERVE_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <serve_path>%s</serve_path>\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_RUN_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <run_path>%s</run_path>\n", cur->buf);
  }

  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <charset>%s</charset>\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_CONFIG_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <config_dir>%s</config_dir>\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_CONTESTS_HOME_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
  } else {
    fprintf(f, "  <contests_home_dir>%s</contests_home_dir>\n", cur->buf);
  }

  fprintf(f, "\n");

  fprintf(f, "  <userdb_file>%s</userdb_file>\n", config_userlist_xml_path);

  if (config_full_cgi_data_dir[0]) {
    fprintf(f, "  <full_cgi_data_dir>%s</full_cgi_data_dir>\n",
            config_full_cgi_data_dir);
  }

  if (config_compile_home_dir[0]) {
    fprintf(f, "  <compile_home_dir>%s</compile_home_dir>\n",
            config_compile_home_dir);
  }

  if (!strcmp(config_workdisk_flag, "yes")) {
    fprintf(f, "  <testing_work_dir>%s/work</testing_work_dir>\n",
            config_workdisk_mount_dir);
  } else {
    if (config_testing_work_dir[0]) {
      fprintf(f, "  <testing_work_dir>%s</testing_work_dir>\n",
              config_testing_work_dir);
    }
  }

  if (config_serialization_key[0]) {
    fprintf(f, "  <serialization_key>%s</serialization_key>\n",
            config_serialization_key);
  }

  if (config_var_dir[0]) {
    fprintf(f, "  <var_dir>%s</var_dir>\n", config_var_dir);
    // FIXME: should make configurable paths?
    fprintf(f, "  <userlist_log>userlist.log</userlist_log>\n");
    fprintf(f, "  <super_serve_log>super_serve.log</super_serve_log>\n");
    //fprintf(f, "  <compile_log>%s</compile_log>\n");
  }

  fprintf(f, "\n");

  fprintf(f, "  <email_program>%s</email_program>\n", config_sendmail);
  fprintf(f, "  <register_url>%s</register_url>\n", config_reg_url);
  fprintf(f, "  <register_email>%s</register_email>\n", config_reg_email);
  if (*config_server_name) {
    fprintf(f, "  <server_name>%s</server_name>\n", config_server_name);
  }
  if (*config_server_name_en) {
    fprintf(f, "  <server_name_en>%s</server_name_en>\n",
            config_server_name_en);
  }
  if (*config_server_main_url) {
    fprintf(f, "  <server_main_url>%s</server_main_url>\n",
            config_server_main_url);
  }
  fprintf(f,
          "  <user_map>\n"
          "    <map system_user=\"%s\" ejudge_user=\"%s\"/>\n"
          "  </user_map>\n",
          system_login, config_login);
  fprintf(f,
          "  <caps>\n"
          "    <cap login=\"%s\">\n"
          "      MASTER_LOGIN,\n"
          "      JUDGE_LOGIN,\n"
          "      LIST_USERS,\n"
          "      CREATE_USER,\n"
          "      GET_USER,\n"
          "      EDIT_USER,\n"
          "      DELETE_USER,\n"
          "      PRIV_EDIT_USER,\n"
          "      PRIV_DELETE_USER,\n"
          "      DUMP_USERS,\n"
          "      EDIT_CONTEST,\n"
          "      CONTROL_CONTEST,\n"
          "      EDIT_PASSWD,\n"
          "      PRIV_EDIT_PASSWD,\n"
          "    </cap>\n"
          "  </caps>\n", config_login);

  fprintf(f, "\n");

  // plugin configurations
  snprintf(tmppath, sizeof(tmppath), "%s", config_ejudge_conf_dir);
#if defined EJUDGE_CONF_DIR
  snprintf(tmppath, sizeof(tmppath), "%s", EJUDGE_CONF_DIR);
#endif
  fprintf(f,
          "  <plugins>\n"
          "    <plugin type=\"nsdb\" name=\"files\">\n"
          "       <config>\n"
          "         <data_dir>%s/new-serve-db</data_dir>\n"
          "       </config>\n"
          "    </plugin>\n"
          "  </plugins>\n\n",
          tmppath);

  cur = &path_edit_items[PATH_LINE_SOCKET_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<socket_path>%s</socket_path>-->\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_SUPER_SERVE_SOCKET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<super_serve_socket>%s</super_serve_socket>-->\n",
            cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_CONTESTS_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<contests_dir>%s</contests_dir>-->\n", cur->buf);
  }

#if CONF_HAS_LIBINTL - 0 == 1
  cur = &path_edit_items[PATH_LINE_LOCALE_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<l10n_dir>%s</l10n_dir>-->\n", cur->buf);
  }
#endif /* CONF_HAS_LIBINTL */

  cur = &path_edit_items[PATH_LINE_SCRIPT_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<script_dir>%s</script_dir>-->\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_SERVE_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<serve_path>%s</serve_path>-->\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_RUN_PATH];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<run_path>%s</run_path>-->\n", cur->buf);
  }

  cur = &set_edit_items[SET_LINE_CHARSET];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<charset>%s</charset>-->\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_CONFIG_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f, "  <!--<config_dir>%s</config_dir>-->\n", cur->buf);
  }

  cur = &path_edit_items[PATH_LINE_CONTESTS_HOME_DIR];
  if (cur->default_value && !strcmp(cur->default_value, cur->buf)) {
    fprintf(f, "  <!-- The default value is built-in -->\n");
    fprintf(f,"  <!--<contests_home_dir>%s</contests_home_dir>-->\n",cur->buf);
  }

  fprintf(f, "</config>\n");
}

static const unsigned char * const preview_menu_items[] =
{
  "To upper level menu",
  "ejudge.xml",
  "userlist.xml",
  "000001.xml",
  "compile.cfg",
  "serve.cfg",
  "master.cfg",
  "judge.cfg",
  "team.cfg",
  "register.xml",
  "users.xml",
};
static const unsigned char * const preview_menu_hotkeys[] =
{
  "qQÊê", "1", "2", "3", "4", "5", "6", "7", "8", "9", "aAÆæ",
};

static void
do_preview_menu(void)
{
  int answer = 0;
  FILE *f = 0;
  char *txt_ptr = 0;
  size_t txt_len = 0;
  unsigned char preview_header[PATH_MAX];

  while (1) {
    mvwprintw(stdscr, 0, 0, "Ejudge %s configurator > File preview",
              compile_version);
    wclrtoeol(stdscr);
    answer = ncurses_generic_menu(-1, -1, -1, -1, answer, 11, -1, -1,
                                  preview_menu_items, preview_menu_hotkeys,
                                  "", "Choose file to view");
    if (answer <= 0) break;

    if (answer > 10) continue;
    if (answer >= 6 && answer <= 10 && !is_cgi_config_needed()) {
      ncurses_msgbox("\\begin{center}\nNOTICE!\n\nThis configuration file is not needed!\n\\end{center}\n");
      continue;
    }
    f = open_memstream(&txt_ptr, &txt_len);
    switch (answer) {
    case 1:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s", config_ejudge_xml_path);
      generate_ejudge_xml(f);
      break;
    case 2:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s", config_userlist_xml_path);
      generate_userlist_xml(f);
      break;
    case 3:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/000001.xml", config_ejudge_contests_dir);
      generate_contest_xml(f);
      break;
    case 4:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/conf/compile.cfg",
               config_compile_home_dir);
      generate_compile_cfg(f);
      break;
    case 5:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/conf/serve.cfg",
               config_contest1_home_dir);
      generate_serve_cfg(f);
      break;
    case 6:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/master.cfg",
               config_full_cgi_data_dir);
      generate_master_cfg(f);
      break;
    case 7:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/judge.cfg",
               config_full_cgi_data_dir);
      generate_master_cfg(f);
      break;
    case 8:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/team.cfg",
               config_full_cgi_data_dir);
      generate_master_cfg(f);
      break;
    case 9:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/register.xml",
               config_full_cgi_data_dir);
      generate_users_xml(f, "register");
      break;
    case 10:
      snprintf(preview_header, sizeof(preview_header),
               "To be installed to %s/users.xml",
               config_full_cgi_data_dir);
      generate_users_xml(f, "users");
      break;
    }
    fclose(f); f = 0;
    //fprintf(stderr, "%s\n", txt_ptr);
    ncurses_view_text(preview_header, txt_ptr);
    free(txt_ptr); txt_ptr = 0; txt_len = 0;
  }
}

static int
check_install_script_validity(void)
{
  int i;

  for (i = 0; i < PATH_LINE_LAST; i++) {
    if (!is_valid_path(i)) {
      ncurses_errbox("\\begin{center}\nERROR!\n\nPath variable `%s' value is invalid!\n\\end{center}\n", path_edit_items[i].descr);
      return -1;
    }
  }
  for (i = 0; i < SET_LINE_LAST; i++) {
    if (!is_valid_setting_var(i)) {
      ncurses_errbox("\\begin{center}\nERROR!\n\nSettings variable `%s' value is invalid!\n\\end{center}\n", set_edit_items[i].descr);
      return -1;
    }
  }
  for (i = 0; i < ID_LINE_LAST; i++) {
    if (!is_valid_id_var(i)) {
      ncurses_errbox("\\begin{center}\nERROR!\n\nIdentity variable `%s' value is invalid!\n\\end{center}\n", id_edit_items[i].descr);
      return -1;
    }
  }
  return 1;
}

static void
generate_dir_creation(FILE *f, strarray_t *pcr,
                      int not_last, /* for files */
                      const unsigned char *in_path)
{
  unsigned char path[PATH_MAX];
  int i;

  if (not_last) {
    os_rDirName(in_path, path, sizeof(path));
  } else {
    snprintf(path, sizeof(path), "%s", in_path);
  }
  os_normalize_path(path);
  for (i = 0; i < pcr->u; i++)
    if (!strcmp(pcr->v[i], path))
      break;
  if (i < pcr->u) return;

  fprintf(f, "install -d -m 02775 -g \"%s\" -o \"%s\" \"%s\"\n",
          config_system_gid, config_system_uid, path);
  fprintf(f,
          "if [ $? != 0 ]\n"
          "then\n"
          "  echo \"creation of %s failed\" 2>&1\n"
          "  exit 1\n"
          "fi\n\n", path);

  xexpand(pcr);
  pcr->v[pcr->u++] = xstrdup(path);
}

static void
gen_cmd_run(FILE *f, const unsigned char *format, ...)
{
  unsigned char buf[PATH_MAX * 4];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(f, "%s\n", buf);
  fprintf(f,
          "if [ $? != 0 ]\n"
          "then\n"
          "  echo \'Command failed: %s' >&2\n"
          "  exit 1\n"
          "fi\n\n", buf);
}

static void
gen_check_retcode(FILE *f, const unsigned char *path)
{
  fprintf(f,
          "if [ $? != 0 ]\n"
          "then\n"
          "  echo \'Installation of \"%s\" failed' >&2\n"
          "  exit 1\n"
          "fi\n\n", path);
}

// solutions and tests for the sample contest 1
const unsigned char b64_contest1_tgz[] =
"begin-base64 664 contest-1.tar.gz\n"
"H4sIAJ58bkcAA+1c3W7jxhX2NZ9ioO4GlFemOfzTOpYV2LtG4RsjsB30oi0M\n"
"ihrLTChSICn/JAiQ3aBJgGxatDcFChR9BTeNm02967wC9UY9M6Qkeu1deYEl\n"
"Ja/OJwjkzJz5EWe+M+fMDBUFXj92Az9aXigMKqBeN/nV0PR6/jrEAlVN06ib\n"
"1KIgR6lpaQvELK5JY/Sj2A4JWXAOWfgmuUnpdxTRqP/t/YdKLwwKqIN3sGUZ\n"
"r+1/aunQ/zAAVMOgFOSoVteNBaIW0JZrmPP+v0+WFpcI9LsXdPit9OEScX03\n"
"dm3P/dzmI0Pu2q5fVSR+IZAaMru97/e7LRbK69XalfAGhB8RNyLr5AHZqJHj\n"
"0I2Z/Ahifa9GDm0vViRp2j8ZkUOe/5ri9HoF1DGR/3Uq+G/UNa1etwT/tTry\n"
"vwz8xvUdr99mpOEGUQxc7jalfuT6HeLbXRb1bIeRKG6vSq4fE64C5Kr0hUQI\n"
"D9o10lqFewcUQ7NJ7Nx9Gh/0Y9JoEBuUgYgIWdwPfaKuSl+iFpgN5PlPFaeQ\n"
"OibP/9oCNxB1TQUFoHH+69z+Q/4XjzH/geVuoBw2pTHVjwK3/SrdIRA5tn8g\n"
"V+6377crNfIBxH/QqnJ+90KQEyl/8CFF8L6KxJ9l5Pm/ovROi6hjEv8hcWj/\n"
"W5quc/6bdR35XwZsssbJLYf28b7r9/qxXK1KrZsiBblTTiOH3xvk+W8qLTsq\n"
"oI6J/DfVof1f1826sP8pRf6Xga3tjz/ZI5UKsaXRbUtyQAGkTP94Z2t7jzjI\n"
"+PcUef4byqf2kf3u65jAf6pq4/VfTaPAf1010f4vBW63F4Qx4R2vgPm/CAZ+\n"
"r9/yXIccuL7tEcezo4jA2BBuQJYEjyyGC3cPUkdhNw75koEddqLf/7EKglyY\n"
"kF2xoLAXfMZ893MWQj7QKz47fjVB5nEb/YMDFrL2DrPbWdQWtz1S2Sx29zSK\n"
"WVdx/WpVOBaveCbgm8RKyCIW7576sX0iZ0IQywJvK9p1O7574IL/EssHthex\n"
"cfpxELYfHdphJOt6jWimmUs6dON0KSQVUGtE16pZhXF4mv1aIeuzk1j8Lqia\n"
"cONqy49Zh4VKD3IyCMggFB3ZXlb89Uyt22TKnkPQjxVhl3m+PPa2CPmSOHbs\n"
"HBJ588RhPc5vclIdNTPLzE7cWKbDHBL/onc2b8jr/7rS84qoY6L9N1r/1VVq\n"
"mcL/M9H/KwXOYdDtyfe4pmrs7j3e2m6CQsgiW1ciU//vHlcz90DbTrvhiHeC\n"
"PP8tJXK6BdQxkf9GfeT/mUa2/4v8LwVy2416nn1K5AdE5lu51exSrUrcBvNc\n"
"n1Vxz/a9RZ7/ren4f6pBtZH/Z1K+/qNTA89/lILr/l8+BoaGp+yCu+Sz8HWe\n"
"YestPEMSH4bBcURGbsnYVUwrIdHQQ0zDOYfvRneP2y2R8J+4l5TJtG6KfKPH\n"
"NL+eT57/tnIQFDHGJ+7/6lq2/2NaFlXF/I/7P+UgXRHY2t7b/O3mzqIB3GrV\n"
"nGydYGdz/TGRF2uLVUG5LHa8NpyGf7eztbeZiQ1zbm4/nlM+3TXk+a8rvans\n"
"/8CkP7T/da4LxP4Prv+Wgl4YdEK7S6J+d1U6gifBmV4Dkn9IvMDvwES5KrUY\n"
"XDmzuWPA5810Ss1C2Zoj5Fgbn/RKT35CqgOpzG8rqA5mE2P+t6Z2/ktTjdH5\n"
"L92op+e/cP4vBW9x/oub5mqNnAjT+/jQ9RiRR0fB+EGwkypZWyO0mu6bkAdr\n"
"XPbaqbAIT4TNELjDxrrMjwt8AUgs8U98/6euA/ctTdj/tA4qAd//KQG5/t9Q\n"
"TrrT2P+hlmGN+p+qYv8HxgHq/zLQ+Ag6nRyxMAIjYK1CFbVCmO8EbdfvrFX6\n"
"8cHSwwr5qCk1wFBseazLdXvPdj6zOwymg0rYV9in/XaHKZHd7Xls3wn8mEVx\n"
"hcu5bS6yIe7j057IAE/bb9thu9KE2MZo9BHP9jt9KHQNitzf+UQkg0Dsxh5r\n"
"Jn9PzpKfkrPBt8kZ2Wgsp7GpRJtFTuiKxSTeymbyT5AZPBk8hSwvRaav4P5l\n"
"cpm8IMmvySUELpP/Jeck+RE+l1yCJD9n5f918BSy/iUVfJJcJOcQfQlyZ5Dt\n"
"PLkYPOMl8dIHz8jgGxH1/eBPBBr2HOQhqEjJP6Cw/4p858OEi+TyFmUmzwnc\n"
"QsteQPzLwbPBdxBY0jKakFHyvyH7RZY8TIV6/yZa8J9bVcWb/ySr9RKa+DRf\n"
"NIiKlp/zR/Y8+ZkY6tVf+K9bFC+e6Y/JOTz+7+DufPRkB1/xMkHyDLpB9Aq/\n"
"vISneZbrE6jl5o4cfJ/8kutIyAIxo47kpf4KlX0r2nSW/MJbxkv5Gh7qi8HX\n"
"ZPADf86vdFljuZeNpuUrw4lHjIaoCLITMcyjTDwLNrNlj4Y4LNukRCM6MRrL\n"
"aXCYGPRjkao2lrPbrM5cKaMA1ACtSjnXLNBCyun/9Wnpf5gARvpf1cT7X/w1\n"
"YNT/JaB4/b/+jvX/eoH6/89DLfUT12o3aPiL5Kx2TUk/T86lJV17jY6GVCIS\n"
"77hKe40602dJmyHeFpysRf73A8dt/L/h+g8V//+gWqaF/l8ZSPt/vdARcDv/\n"
"P33/29L4+h9VDYr9XwaG/a+qumL7Rez+3OL8lzp6/1c30vOfKp7/KAcqzsZz\n"
"jTH/tRnhPxX81/H/P0qBifyfa4z5T2eD/6aVzv94/qMUaMj/uUZ+/m/bcSF1\n"
"CP4bb+K/Mfb/1JT/uP9XDjRJRw0wx8j7/9Pjv5lb/xHnv1WK9n8pWDIkAxXA\n"
"/GLMf2M27P86Rfu/RDxE8s818v7/LMz/ppXZ/xbyvwxQieLb3XOM/Pw/E/6/\n"
"2P9F/pcFNP/nGyn/N2bg/If4/wcNBMX5DxPPf5SCYf9P9fwHpeP+N030/0rE\n"
"yoppWvDkcRKYT4z5P83zH6P3f3VTz9Z/VOR/GVhZsZD6c4wx/6d5/kMf81/L\n"
"5n/c/y0FFA+AzTXy83+R6z/Gm9Z/NH38/oeZrf/g/m8poKoqafDV4WvAdwmX\n"
"g+YKef9/Wvynes7/V42U/+j/lwKaQaKawPAKNysprt2MI0YxK1eu/IJa5G4g\n"
"b/9Pbf6n2vX5H9//KgVU4idADQndAAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQC\n"
"gUAgEIi7if8D7y3zIACgAAA=\n"
"====\n";

static void
generate_install_script(FILE *f)
{
  FILE *floc = 0;
  char *txt_ptr = 0;
  size_t txt_len = 0, style_len = 0;
  unsigned char fpath[PATH_MAX]; 
  int cgi_config_needed = is_cgi_config_needed();
  unsigned char date_buf[64];
  strarray_t created_dirs;
  unsigned char serve_cfg_path[PATH_MAX];
  unsigned char compile_cfg_path[PATH_MAX];
  unsigned char workdir_path[PATH_MAX];
  unsigned char style_prefix[PATH_MAX];
  unsigned char style_dir[PATH_MAX];
  unsigned char style_src_dir[PATH_MAX];
  struct stat sb1, sb2;

  XMEMZERO(&created_dirs, 1);
  generate_current_date(date_buf, sizeof(date_buf));

  snprintf(compile_cfg_path, sizeof(compile_cfg_path),
           "%s/conf/compile.cfg",config_compile_home_dir);
  snprintf(serve_cfg_path, sizeof(serve_cfg_path),
           "%s/conf/serve.cfg",config_contest1_home_dir);

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "# Generated by ejudge-setup, version %s\n", compile_version);
  fprintf(f, "# Generation date: %s\n\n", date_buf);

  // create all the necessary directories
  fprintf(f, "# create all necessary directories\n");
  generate_dir_creation(f, &created_dirs, 0, config_ejudge_contests_home_dir);
  generate_dir_creation(f, &created_dirs, 0, config_ejudge_local_dir);
  generate_dir_creation(f, &created_dirs, 0, config_ejudge_conf_dir);
  generate_dir_creation(f, &created_dirs, 1, config_ejudge_xml_path);
  generate_dir_creation(f, &created_dirs, 0, config_ejudge_contests_dir);
  if (cgi_config_needed) {
    generate_dir_creation(f, &created_dirs, 0, config_full_cgi_data_dir);
  }
  generate_dir_creation(f, &created_dirs, 1, config_userlist_xml_path);
  generate_dir_creation(f, &created_dirs, 0, config_compile_home_dir);
  generate_dir_creation(f, &created_dirs, 0, config_contest1_home_dir);
  if (config_full_stand_html_path[0]) {
    generate_dir_creation(f, &created_dirs, 1, config_full_stand_html_path);
  }
  if (!strcmp(config_workdisk_flag, "yes")) {
    generate_dir_creation(f, &created_dirs, 1, config_workdisk_image_path);
    generate_dir_creation(f, &created_dirs, 0, config_workdisk_mount_dir);
  }
  generate_dir_creation(f, &created_dirs, 1, compile_cfg_path);
  generate_dir_creation(f, &created_dirs, 1, serve_cfg_path);
  generate_dir_creation(f, &created_dirs, 0, config_var_dir);

  fprintf(f, "\n");

  if (!strcmp(config_workdisk_flag, "yes")) {
    fprintf(f, "if [ -f \"%s\" ]\n"
            "then\n"
            "echo \"%s already exists, not overwriting\" 1>&2\n"
            "else\n", config_workdisk_image_path, config_workdisk_image_path);
    fprintf(f, "# create the working disk\n");
    gen_cmd_run(f, "dd if=/dev/zero of=\"%s\" bs=1M count=%s",
                config_workdisk_image_path, config_workdisk_size);
    gen_cmd_run(f, "mke2fs -F -q \"%s\"", config_workdisk_image_path);
    gen_cmd_run(f, "mount \"%s\" \"%s\" -o loop",
                config_workdisk_image_path, config_workdisk_mount_dir);
    fprintf(f, "fi\n");
    snprintf(workdir_path, sizeof(workdir_path),
             "%s/work", config_workdisk_mount_dir);
    generate_dir_creation(f, &created_dirs, 0, workdir_path);
  }

  if (!strcmp(config_install_flag, "yes")
      && config_ejudge_cgi_bin_dir[0] && config_cgi_bin_dir[0]) {
    if (stat(config_ejudge_cgi_bin_dir, &sb1) >= 0
        && stat(config_cgi_bin_dir, &sb2) >= 0
        && ( sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)) {
      fprintf(f, "# install symlimks to cgi-bin directory\n");
      gen_cmd_run(f, "ln -sf \"%s/master%s\" \"%s/master%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/judge%s\" \"%s/judge%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/team%s\" \"%s/team%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/register%s\" \"%s/register%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/users%s\" \"%s/users%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/serve-control%s\" \"%s/serve-control%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/new-client%s\" \"%s/new-client%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/new-master%s\" \"%s/new-master%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
      gen_cmd_run(f, "ln -sf \"%s/new-judge%s\" \"%s/new-judge%s\"",
                  config_ejudge_cgi_bin_dir, CGI_PROG_SUFFIX,
                  config_cgi_bin_dir, CGI_PROG_SUFFIX);
    }
  }

  if (!strcmp(config_install_flag, "yes") && config_htdocs_dir[0]) {
    if (CONF_STYLE_PREFIX[0] != '/') {
      gen_cmd_run(f, "echo 'NOTE: HTML style files are not linked to the HTTP server'");
      gen_cmd_run(f, "echo 'directories because --enable-style-prefix specifies'");
      gen_cmd_run(f, "echo 'prefix not starting with /'. You should symlink or copy'");
      gen_cmd_run(f, "echo 'the style files manually'");
    } else {
      snprintf(style_prefix, sizeof(style_prefix), "%s%s", config_htdocs_dir,
               CONF_STYLE_PREFIX);
      style_len = strlen(style_prefix);
      if (style_len > 0 && style_prefix[style_len - 1] != '/') {
        os_rDirName(style_prefix, style_dir, sizeof(style_dir));
      } else {
        snprintf(style_dir, sizeof(style_dir), "%s", style_prefix);
      }
      generate_dir_creation(f, &created_dirs, 0, style_dir);
      snprintf(style_src_dir, sizeof(style_src_dir),
               "%s/share/ejudge/style", EJUDGE_PREFIX_DIR);
      gen_cmd_run(f, "ln -sf \"%s/actions.js\" \"%sactions.js\"",
                  style_src_dir, style_prefix);
      gen_cmd_run(f, "ln -sf \"%s/logo.gif\" \"%slogo.gif\"",
                  style_src_dir, style_prefix);
      gen_cmd_run(f, "ln -sf \"%s/priv.css\" \"%spriv.css\"",
                  style_src_dir, style_prefix);
      gen_cmd_run(f, "ln -sf \"%s/unpriv.css\" \"%sunpriv.css\"",
                  style_src_dir, style_prefix);
      gen_cmd_run(f, "ln -sf \"%s/unpriv.js\" \"%sunpriv.js\"",
                  style_src_dir, style_prefix);
    }
  }

  // ejudge.xml
  fprintf(f, "if [ -f \"%s\" ]\n"
          "then\n"
          "echo \"%s already exists, not overwriting\" 1>&2\n"
          "else\n", config_ejudge_xml_path, config_ejudge_xml_path);
  floc = open_memstream(&txt_ptr, &txt_len);
  generate_ejudge_xml(floc);
  fclose(floc); floc = 0;
  snprintf(fpath, sizeof(fpath), "%s", config_ejudge_xml_path);
  fprintf(f, "# copy ejudge.xml to its location\n");
  fprintf(f, "cat << _EOF | %s\n", uudecode_path);
  base64_encode_file(f, fpath, 0664, txt_ptr);
  fprintf(f, "_EOF\n");
  gen_check_retcode(f, fpath);
  gen_cmd_run(f, "chown %s:%s \"%s\"", config_system_uid, config_system_gid,
              fpath);
  fprintf(f, "fi\n");
  free(txt_ptr); txt_ptr = 0; txt_len = 0;

  // userlist.xml
  fprintf(f, "if [ -f \"%s\" ]\n"
          "then\n"
          "echo \"%s already exists, not overwriting\" 1>&2\n"
          "else\n", config_userlist_xml_path, config_userlist_xml_path);
  floc = open_memstream(&txt_ptr, &txt_len);
  generate_userlist_xml(floc);
  fclose(floc); floc = 0;
  snprintf(fpath, sizeof(fpath), "%s", config_userlist_xml_path);
  fprintf(f, "# copy userlist.xml to its location\n");
  fprintf(f, "cat << _EOF | %s\n", uudecode_path);
  base64_encode_file(f, fpath, 0664, txt_ptr);
  fprintf(f, "_EOF\n");
  gen_check_retcode(f, fpath);
  gen_cmd_run(f, "chown %s:%s \"%s\"", config_system_uid, config_system_gid,
              fpath);
  fprintf(f, "fi\n");
  free(txt_ptr); txt_ptr = 0; txt_len = 0;

  // 000001.xml
  fprintf(f, "if [ -f \"%s/000001.xml\" ]\n"
          "then\n"
          "echo \"%s/000001.xml already exists, not overwriting\" 1>&2\n"
          "else\n", config_ejudge_contests_dir, config_ejudge_contests_dir);
  floc = open_memstream(&txt_ptr, &txt_len);
  generate_contest_xml(floc);
  fclose(floc); floc = 0;
  snprintf(fpath, sizeof(fpath), "%s/000001.xml", config_ejudge_contests_dir);
  fprintf(f, "# copy 000001.xml to its location\n");
  fprintf(f, "cat << _EOF | %s\n", uudecode_path);
  base64_encode_file(f, fpath, 0664, txt_ptr);
  fprintf(f, "_EOF\n");
  gen_check_retcode(f, fpath);
  gen_cmd_run(f, "chown %s:%s \"%s\"", config_system_uid, config_system_gid,
              fpath);
  fprintf(f, "fi\n");
  free(txt_ptr); txt_ptr = 0; txt_len = 0;

  // compile.cfg
  fprintf(f, "if [ -f \"%s\" ]\n"
          "then\n"
          "echo \"%s already exists, not overwriting\" 1>&2\n"
          "else\n", compile_cfg_path, compile_cfg_path);
  floc = open_memstream(&txt_ptr, &txt_len);
  generate_compile_cfg(floc);
  fclose(floc); floc = 0;
  fprintf(f, "# copy compile.cfg to its location\n");
  fprintf(f, "cat << _EOF | %s\n", uudecode_path);
  base64_encode_file(f, compile_cfg_path, 0664, txt_ptr);
  fprintf(f, "_EOF\n");
  gen_check_retcode(f, compile_cfg_path);
  gen_cmd_run(f, "chown %s:%s \"%s\"", config_system_uid, config_system_gid,
              compile_cfg_path);
  fprintf(f, "fi\n");
  free(txt_ptr); txt_ptr = 0; txt_len = 0;

  // serve.cfg
  fprintf(f, "if [ -f \"%s\" ]\n"
          "then\n"
          "echo \"%s already exists, not overwriting\" 1>&2\n"
          "else\n", serve_cfg_path, serve_cfg_path);
  floc = open_memstream(&txt_ptr, &txt_len);
  generate_serve_cfg(floc);
  fclose(floc); floc = 0;
  fprintf(f, "# copy serve.cfg to its location\n");
  fprintf(f, "cat << _EOF | %s\n", uudecode_path);
  base64_encode_file(f, serve_cfg_path, 0664, txt_ptr);
  fprintf(f, "_EOF\n");
  gen_check_retcode(f, serve_cfg_path);
  gen_cmd_run(f, "chown %s:%s \"%s\"", config_system_uid, config_system_gid,
              serve_cfg_path);
  fprintf(f, "fi\n");
  free(txt_ptr); txt_ptr = 0; txt_len = 0;

  if (cgi_config_needed) {
    // master.cfg, judge.cfg, team.cfg
    floc = open_memstream(&txt_ptr, &txt_len);
    generate_master_cfg(floc);
    fclose(floc); floc = 0;
    snprintf(fpath, sizeof(fpath),"%s/master.cfg",config_full_cgi_data_dir);
    fprintf(f, "if [ -f \"%s\" ]\n"
            "then\n"
            "echo \"%s already exists, not overwriting\" 1>&2\n"
            "else\n", fpath, fpath);
    fprintf(f, "# copy master.cfg to its location\n");
    fprintf(f, "cat << _EOF | %s\n", uudecode_path);
    base64_encode_file(f, fpath, 0664, txt_ptr);
    fprintf(f, "_EOF\n");
    gen_check_retcode(f, fpath);
    gen_cmd_run(f, "chown %s:%s \"%s\"",
                config_system_uid, config_system_gid, fpath);
    fprintf(f, "fi\n");
    snprintf(fpath, sizeof(fpath),"%s/judge.cfg",config_full_cgi_data_dir);
    fprintf(f, "if [ -f \"%s\" ]\n"
            "then\n"
            "echo \"%s already exists, not overwriting\" 1>&2\n"
            "else\n", fpath, fpath);
    fprintf(f, "# copy judge.cfg to its location\n");
    fprintf(f, "cat << _EOF | %s\n", uudecode_path);
    base64_encode_file(f, fpath, 0664, txt_ptr);
    fprintf(f, "_EOF\n");
    gen_check_retcode(f, fpath);
    gen_cmd_run(f, "chown %s:%s \"%s\"",
                config_system_uid, config_system_gid, fpath);
    fprintf(f, "fi\n");
    snprintf(fpath, sizeof(fpath),"%s/team.cfg",config_full_cgi_data_dir);
    fprintf(f, "if [ -f \"%s\" ]\n"
            "then\n"
            "echo \"%s already exists, not overwriting\" 1>&2\n"
            "else\n", fpath, fpath);
    fprintf(f, "# copy team.cfg to its location\n");
    fprintf(f, "cat << _EOF | %s\n", uudecode_path);
    base64_encode_file(f, fpath, 0664, txt_ptr);
    fprintf(f, "_EOF\n");
    gen_check_retcode(f, fpath);
    gen_cmd_run(f, "chown %s:%s \"%s\"",
                config_system_uid, config_system_gid, fpath);
    fprintf(f, "fi\n");
    free(txt_ptr); txt_ptr = 0; txt_len = 0;

    // register.xml
    floc = open_memstream(&txt_ptr, &txt_len);
    generate_users_xml(floc, "register");
    fclose(floc); floc = 0;
    snprintf(fpath, sizeof(fpath),"%s/register.xml",config_full_cgi_data_dir);
    fprintf(f, "if [ -f \"%s\" ]\n"
            "then\n"
            "echo \"%s already exists, not overwriting\" 1>&2\n"
            "else\n", fpath, fpath);
    fprintf(f, "# copy register.xml to its location\n");
    fprintf(f, "cat << _EOF | %s\n", uudecode_path);
    base64_encode_file(f, fpath, 0664, txt_ptr);
    fprintf(f, "_EOF\n");
    gen_check_retcode(f, fpath);
    gen_cmd_run(f, "chown %s:%s \"%s\"",
                config_system_uid, config_system_gid, fpath);
    fprintf(f, "fi\n");
    free(txt_ptr); txt_ptr = 0; txt_len = 0;

    // users.xml
    floc = open_memstream(&txt_ptr, &txt_len);
    generate_users_xml(floc, "users");
    fclose(floc); floc = 0;
    snprintf(fpath, sizeof(fpath),"%s/users.xml",config_full_cgi_data_dir);
    fprintf(f, "if [ -f \"%s\" ]\n"
            "then\n"
            "echo \"%s already exists, not overwriting\" 1>&2\n"
            "else\n", fpath, fpath);
    fprintf(f, "# copy users.xml to its location\n");
    fprintf(f, "cat << _EOF | %s\n", uudecode_path);
    base64_encode_file(f, fpath, 0664, txt_ptr);
    fprintf(f, "_EOF\n");
    gen_check_retcode(f, fpath);
    gen_cmd_run(f, "chown %s:%s \"%s\"",
                config_system_uid, config_system_gid, fpath);
    fprintf(f, "fi\n");
    free(txt_ptr); txt_ptr = 0; txt_len = 0;
  } else {
    fprintf(f, "# configuration files for CGI programs are not needed\n\n");
  }
  
  fprintf(f, "# install tests and answer files\n");
  fprintf(f, "cat << _EOF | %s -o - | tar xvfz - -C \"%s\"\n",
          uudecode_path, config_contest1_home_dir);
  fprintf(f, "%s_EOF\n", b64_contest1_tgz);
  gen_check_retcode(f, config_contest1_home_dir);
  gen_cmd_run(f, "chown -R %s:%s \"%s\"",
              config_system_uid, config_system_gid, config_contest1_home_dir);

  fprintf(f, "# Do probe run of the compile server to create dirs\n");
  gen_cmd_run(f, "%s/compile -u %s -g %s -C \"%s\" -i conf/compile.cfg",
              EJUDGE_SERVER_BIN_PATH, config_system_uid, config_system_gid,
              config_compile_home_dir);
  /*
  fprintf(f, "# Do probe run of the contest server to create dirs\n");
  gen_cmd_run(f, "%s -u %s -g %s -C \"%s\" -i conf/serve.cfg",
              config_ejudge_serve_path, config_system_uid,
              config_system_gid, config_contest1_home_dir);
  */
  fprintf(f, "# Create necessary files for `new-server'\n");
  gen_cmd_run(f, "%s/new-server -u %s -g %s -C \"%s\" --create",
              EJUDGE_SERVER_BIN_PATH, config_system_uid,
              config_system_gid, config_ejudge_contests_home_dir);
}

static void
preview_install_script(void)
{
  FILE *f = 0;
  char *txt_ptr = 0;
  size_t txt_len = 0;

  if (check_install_script_validity() < 0) return;

  f = open_memstream(&txt_ptr, &txt_len);
  generate_install_script(f);
  fclose(f); f = 0;
  ncurses_view_text("Setup script preview", txt_ptr);
  free(txt_ptr); txt_ptr = 0; txt_len = 0;
}

static void
save_install_script(void)
{
  FILE *f = 0;
  char *txt_ptr = 0, *p;
  size_t txt_len = 0;
  unsigned char filepath[PATH_MAX];
  int j, fd, r, w;

  if (check_install_script_validity() < 0) return;

  f = open_memstream(&txt_ptr, &txt_len);
  generate_install_script(f);
  fclose(f); f = 0;

  snprintf(filepath, sizeof(filepath), "ejudge-install.sh");
  j = ncurses_edit_string(LINES/2, COLS, "Setup script name",
                          filepath, sizeof(filepath), utf8_mode);
  if (j < 0) {
    goto cleanup;
  }

  if ((fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0770)) < 0) {
    ncurses_errbox("\\begin{center}\nERROR!\n\nCannot create %s: %s!\n\\end{center}\n", filepath, os_ErrorString());
    goto cleanup;
  }
  r = txt_len; p = txt_ptr;
  while (r > 0) {
    if ((w = write(fd, p, r)) <= 0) {
      ncurses_errbox("\\begin{center}\nERROR!\n\nWrite error on %s: %s!\n\\end{center}\n", filepath, os_ErrorString());
      unlink(filepath);
      goto cleanup;
    }
    p += w, r -= w;
  }
  if (close(fd) < 0) {
    ncurses_errbox("\\begin{center}\nERROR!\n\nWrite error on %s: %s!\n\\end{center}\n", filepath, os_ErrorString());
    unlink(filepath);
    goto cleanup;
  }
  
 cleanup:
  free(txt_ptr); txt_ptr = 0; txt_len = 0;
}

static const unsigned char * const main_menu_items[] =
{
  "Edit paths",
  "Edit global settings",
  "Edit administrator identity",
  "Preview files",
  "Preview setup script",
  "Save setup script",
  "Quit",
};
static const unsigned char * const main_menu_hotkeys[] =
{
  "PpúÚ",
  "SsùÙ",
  "AaæÆ",
  "VvíÍ",
  "IiûÛ",
  "TtåÅ",
  "QqêÊ",
};
static const unsigned char main_menu_help_string[] =
"P - paths, S - settings, A - admin, I - install, V - preview, Q - quit";
static void
do_main_menu(void)
{
  int answer = 6;
  int cur_paths_item = 0;
  int cur_id_item = 0;
  int cur_settings_item = 0;

  while (1) {
    mvwprintw(stdscr, 0, 0,
              "The ejudge %s initial setup configuration utility",
              compile_version);
    wclrtoeol(stdscr);
    answer = ncurses_generic_menu(-1, -1, -1, -1, answer, 7, -1, -1,
                                  main_menu_items, main_menu_hotkeys,
                                  main_menu_help_string, "Choose action");
    if (answer == 6) break;
    switch (answer) {
    case 0:
      while (do_paths_menu(&cur_paths_item));
      break;
    case 1:
      while (do_settings_menu(&cur_settings_item));
      break;
    case 2:
      while (do_identity_menu(&cur_id_item));
      break;
    case 3:
      do_preview_menu();
      break;
    case 4:
      preview_install_script();
      break;
    case 5:
      save_install_script();
      break;
    }
  }
}

static void
get_system_identity(void)
{
  struct passwd *pp;
  struct group *gg;

  system_uid = getuid();
  if (system_uid < 0) {
    fprintf(stderr, "Your uid %d is negative!\n", system_uid);
    exit(1);
  }
  /*
  if (!system_uid) {
    // root must fill the system_login and system_group
    return;
  }
  */

  pp = getpwuid(system_uid);
  if (!pp) {
    fprintf(stderr, "Cannot map your uid %d to login!\n", system_uid);
    exit(1);
  }
  if (!pp->pw_name || !pp->pw_name[0]) {
    fprintf(stderr, "Your uid %d has empty name!\n", system_uid);
    exit(1);
  }
  snprintf(system_login, sizeof(system_login), "%s", pp->pw_name);
  gethostname(system_hostname, sizeof(system_hostname));
  if (!system_hostname[0]) {
    fprintf(stderr, "Cannot determine the host name!\n");
    exit(1);
  }
  getdomainname(system_domainname, sizeof(system_domainname));
  if (!strcmp(system_domainname, "(none)")) system_domainname[0] = 0;

  system_gid = getgid();
  if (system_gid < 0) {
    fprintf(stderr, "Your gid %d is negative!\n", system_gid);
    exit(1);
  }
  if (!(gg = getgrgid(system_gid))) {
    fprintf(stderr, "Cannot map your gid %d to group name!\n", system_gid);
    exit(1);
  }
  if (!pp->pw_name || !pp->pw_name[0]) {
    fprintf(stderr, "Your uid %d has empty name!\n", system_gid);
    exit(1);
  }
  if (!gg->gr_name || !gg->gr_name[0]) {
    fprintf(stderr, "Your gid %d has empty name!\n", system_gid);
    exit(1);
  }
  snprintf(system_group, sizeof(system_group), "%s", gg->gr_name);
}

static const unsigned char initial_warning[] =
"\\begin{center}\n"
"WARNING!\n"
"\\end{center}\n"
"\n"
"This is ejudge setup utility. This utility creates INITIAL configuration\n"
"files for freshly installed ejudge contest management system.\n"
"If you already have configured ejudge, you should quit the setup\n"
"utility, or your configuration files will be overwritten.\n"
"\n"
"\\begin{center}\n"
"Are you sure you want to continue?\n"
"\\end{center}\n";

static void
arg_expected(const unsigned char *progname)
{
  fprintf(stderr, "%s: invalid number of arguments\n", progname);
  exit(1);
}

int
main(int argc, char **argv)
{
  int answer = 1;
  int cur_arg = 1;
  const unsigned char *user = 0, *group = 0, *workdir = 0;

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "-u")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      user = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-g")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      group = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-C")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      workdir = argv[cur_arg + 1];
      cur_arg += 2;
    } else {
      break;
    }
  }
  if (cur_arg != argc) {
    fprintf(stderr, "%s: invalid number of arguments\n", argv[0]);
    return 1;
  }

#if CONF_HAS_LIBINTL - 0 == 1 && defined EJUDGE_LOCALE_DIR
  bindtextdomain("ejudge", EJUDGE_LOCALE_DIR);
  textdomain("ejudge");
#endif /* CONF_HAS_LIBINTL */

  if (start_prepare(user, group, workdir) < 0) return 1;

  setlocale(LC_ALL, "");
  if (!strcmp(nl_langinfo(CODESET), "UTF-8")) utf8_mode = 1;
  get_system_identity();

  if (ncurses_init() < 0) return 1;

  snprintf(uudecode_path, sizeof(uudecode_path), "%s/uudecode",
           EJUDGE_SERVER_BIN_PATH);
  initialize_config_vars();
  initialize_setting_vars();
  //answer = ncurses_yesno(0, initial_warning);
  if (answer == 1) {
    do_main_menu();
  }

  ncurses_shutdown();
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU")
 * End:
 */
