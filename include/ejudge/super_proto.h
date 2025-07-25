/* -*- c -*- */

#ifndef __SUPER_PROTO_H__
#define __SUPER_PROTO_H__

/* Copyright (C) 2004-2025 Alexander Chernov <cher@ejudge.ru> */

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

#define PROT_SUPER_PACKET_MAGIC (0xf249)
struct prot_super_packet
{
  unsigned short magic;
  short id;
};

/* client-server requests */
enum
{
  SSERV_CMD_PASS_FD = 1,
  SSERV_CMD_STOP,
  SSERV_CMD_RESTART,
  SSERV_CMD_OPEN_CONTEST,
  SSERV_CMD_CLOSE_CONTEST,
  SSERV_CMD_INVISIBLE_CONTEST,
  SSERV_CMD_VISIBLE_CONTEST,
  SSERV_CMD_SHOW_HIDDEN,
  SSERV_CMD_HIDE_HIDDEN,
  SSERV_CMD_SHOW_CLOSED,
  SSERV_CMD_HIDE_CLOSED,
  SSERV_CMD_SHOW_UNMNG,
  SSERV_CMD_HIDE_UNMNG,

  SSERV_CMD_RUN_LOG_TRUNC,
  SSERV_CMD_RUN_LOG_DEV_NULL,
  SSERV_CMD_RUN_LOG_FILE,
  SSERV_CMD_RUN_MNG_TERM,
  SSERV_CMD_CONTEST_RESTART,
  SSERV_CMD_CLEAR_MESSAGES,

  SSERV_CMD_RUN_MNG_RESET_ERROR,

  SSERV_CMD_CNTS_FORGET,

  SSERV_CMD_CNTS_DEFAULT_ACCESS,
  SSERV_CMD_CNTS_ADD_RULE,
  SSERV_CMD_CNTS_CHANGE_RULE,
  SSERV_CMD_CNTS_DELETE_RULE,
  SSERV_CMD_CNTS_UP_RULE,
  SSERV_CMD_CNTS_DOWN_RULE,
  SSERV_CMD_CNTS_COPY_ACCESS,
  SSERV_CMD_CNTS_DELETE_PERMISSION,
  SSERV_CMD_CNTS_ADD_PERMISSION,
  SSERV_CMD_CNTS_SAVE_PERMISSIONS,
  SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS, /* implemented in serve-control */
  SSERV_CMD_CNTS_SAVE_FORM_FIELDS,
  SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS, /* NOTE: the following 5 commands must */
  SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS,    /* be sequental */
  SSERV_CMD_CNTS_SAVE_COACH_FIELDS,
  SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS,
  SSERV_CMD_CNTS_SAVE_GUEST_FIELDS,

  SSERV_CMD_LANG_SHOW_DETAILS,
  SSERV_CMD_LANG_HIDE_DETAILS,
  SSERV_CMD_LANG_DEACTIVATE,
  SSERV_CMD_LANG_ACTIVATE,

  SSERV_CMD_PROB_ADD_ABSTRACT,
  SSERV_CMD_PROB_ADD,
  SSERV_CMD_PROB_SHOW_DETAILS,
  SSERV_CMD_PROB_HIDE_DETAILS,
  SSERV_CMD_PROB_SHOW_ADVANCED,
  SSERV_CMD_PROB_HIDE_ADVANCED,

  SSERV_CMD_PROB_DELETE,
  SSERV_CMD_PROB_CHANGE_VARIANTS,
  SSERV_CMD_PROB_DELETE_VARIANTS,

  SSERV_CMD_LANG_UPDATE_VERSIONS,

  SSERV_CMD_PROB_CLEAR_VARIANTS,
  SSERV_CMD_PROB_RANDOM_VARIANTS,

  SSERV_CMD_LOGOUT,
  SSERV_CMD_HTTP_REQUEST,

  SSERV_CMD_HTTP_REQUEST_FIRST,

/* subcommands for SSERV_CMD_HTTP_REQUEST */
  SSERV_CMD_EDITED_CNTS_BACK = SSERV_CMD_HTTP_REQUEST_FIRST,
  SSERV_CMD_EDITED_CNTS_CONTINUE,
  SSERV_CMD_EDITED_CNTS_START_NEW,
  SSERV_CMD_LOCKED_CNTS_FORGET,
  SSERV_CMD_LOCKED_CNTS_CONTINUE,

  SSERV_CMD_USER_FILTER_CHANGE_ACTION,          /* OK */
  SSERV_CMD_USER_FILTER_FIRST_PAGE_ACTION,      /* OK */
  SSERV_CMD_USER_FILTER_PREV_PAGE_ACTION,       /* OK */
  SSERV_CMD_USER_FILTER_NEXT_PAGE_ACTION,       /* OK */
  SSERV_CMD_USER_FILTER_LAST_PAGE_ACTION,       /* OK */
  SSERV_CMD_USER_JUMP_CONTEST_ACTION,
  SSERV_CMD_USER_JUMP_GROUP_ACTION,
  SSERV_CMD_USER_BROWSE_MARK_ALL_ACTION,
  SSERV_CMD_USER_BROWSE_UNMARK_ALL_ACTION,
  SSERV_CMD_USER_BROWSE_TOGGLE_ALL_ACTION,
  SSERV_CMD_USER_CREATE_ONE_PAGE,               /* OK */
  SSERV_CMD_USER_CREATE_ONE_ACTION,             /* OK */
  SSERV_CMD_USER_CREATE_MANY_PAGE,              /* OK */
  SSERV_CMD_USER_CREATE_MANY_ACTION,            /* OK */
  SSERV_CMD_USER_CREATE_FROM_CSV_PAGE,          /* OK */
  SSERV_CMD_USER_CREATE_FROM_CSV_ACTION,        /* OK */
  SSERV_CMD_USER_DETAIL_PAGE,                   /* OK */
  SSERV_CMD_USER_PASSWORD_PAGE,                 /* OK */
  SSERV_CMD_USER_CHANGE_PASSWORD_ACTION,        /* OK */
  SSERV_CMD_USER_CNTS_PASSWORD_PAGE,            /* OK */
  SSERV_CMD_USER_CHANGE_CNTS_PASSWORD_ACTION,   /* OK */
  SSERV_CMD_USER_CLEAR_FIELD_ACTION,
  SSERV_CMD_USER_CREATE_MEMBER_ACTION,          /* OK */
  SSERV_CMD_USER_DELETE_MEMBER_PAGE,            /* OK */
  SSERV_CMD_USER_DELETE_MEMBER_ACTION,          /* OK */
  SSERV_CMD_USER_SAVE_AND_PREV_ACTION,          /* OK */
  SSERV_CMD_USER_SAVE_ACTION,                   /* OK */
  SSERV_CMD_USER_SAVE_AND_NEXT_ACTION,          /* OK */
  SSERV_CMD_USER_CANCEL_AND_PREV_ACTION,        /* OK */
  SSERV_CMD_USER_CANCEL_ACTION,                 /* OK */
  SSERV_CMD_USER_CANCEL_AND_NEXT_ACTION,        /* OK */
  SSERV_CMD_USER_CREATE_REG_PAGE,               /* OK */
  SSERV_CMD_USER_CREATE_REG_ACTION,             /* OK */
  SSERV_CMD_USER_EDIT_REG_PAGE,                 /* OK */
  SSERV_CMD_USER_EDIT_REG_ACTION,               /* OK */
  SSERV_CMD_USER_DELETE_REG_PAGE,               /* OK */
  SSERV_CMD_USER_DELETE_REG_ACTION,             /* OK */
  SSERV_CMD_USER_DELETE_SESSION_ACTION,
  SSERV_CMD_USER_DELETE_ALL_SESSIONS_ACTION,
  SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  SSERV_CMD_USER_SEL_RANDOM_PASSWD_ACTION,
  SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE,
  SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION,
  SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE,
  SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION,
  SSERV_CMD_USER_SEL_CREATE_REG_PAGE,
  SSERV_CMD_USER_SEL_CREATE_REG_ACTION,
  SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE,
  SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION,
  SSERV_CMD_USER_SEL_DELETE_REG_PAGE,
  SSERV_CMD_USER_SEL_DELETE_REG_ACTION,
  SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE,
  SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION,
  SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE,
  SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION,
  SSERV_CMD_USER_SEL_CANCEL_ACTION,
  SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE,
  SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE,
  SSERV_CMD_USER_SEL_VIEW_PASSWD_REDIRECT,
  SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_REDIRECT,
  SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_PAGE,
  SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION,
  SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE,
  SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION,
  SSERV_CMD_USER_IMPORT_CSV_PAGE,
  SSERV_CMD_USER_IMPORT_CSV_ACTION,

  SSERV_CMD_GROUP_BROWSE_PAGE,
  SSERV_CMD_GROUP_FILTER_CHANGE_ACTION,
  SSERV_CMD_GROUP_FILTER_FIRST_PAGE_ACTION,
  SSERV_CMD_GROUP_FILTER_PREV_PAGE_ACTION,
  SSERV_CMD_GROUP_FILTER_NEXT_PAGE_ACTION,
  SSERV_CMD_GROUP_FILTER_LAST_PAGE_ACTION,
  SSERV_CMD_GROUP_CREATE_PAGE,
  SSERV_CMD_GROUP_CREATE_ACTION,
  SSERV_CMD_GROUP_MODIFY_PAGE,
  SSERV_CMD_GROUP_MODIFY_PAGE_ACTION,
  SSERV_CMD_GROUP_MODIFY_ACTION,
  SSERV_CMD_GROUP_DELETE_PAGE,
  SSERV_CMD_GROUP_DELETE_PAGE_ACTION,
  SSERV_CMD_GROUP_DELETE_ACTION,
  SSERV_CMD_GROUP_CANCEL_ACTION,

  SSERV_CMD_TESTS_MAIN_PAGE,
  SSERV_CMD_TESTS_STATEMENT_EDIT_PAGE,
  SSERV_CMD_TESTS_STATEMENT_EDIT_ACTION,
  SSERV_CMD_TESTS_STATEMENT_EDIT_2_ACTION,
  SSERV_CMD_TESTS_STATEMENT_EDIT_3_ACTION,
  SSERV_CMD_TESTS_STATEMENT_EDIT_4_ACTION,
  SSERV_CMD_TESTS_STATEMENT_EDIT_5_ACTION,
  SSERV_CMD_TESTS_STATEMENT_DELETE_ACTION,
  SSERV_CMD_TESTS_STATEMENT_DELETE_SAMPLE_ACTION,
  SSERV_CMD_TESTS_TESTS_VIEW_PAGE,
  SSERV_CMD_TESTS_CHECK_TESTS_PAGE,
  SSERV_CMD_TESTS_GENERATE_ANSWERS_PAGE,
  SSERV_CMD_TESTS_SOURCE_HEADER_EDIT_PAGE,
  SSERV_CMD_TESTS_SOURCE_HEADER_EDIT_ACTION,
  SSERV_CMD_TESTS_SOURCE_HEADER_DELETE_ACTION,
  SSERV_CMD_TESTS_SOURCE_FOOTER_EDIT_PAGE,
  SSERV_CMD_TESTS_SOURCE_FOOTER_EDIT_ACTION,
  SSERV_CMD_TESTS_SOURCE_FOOTER_DELETE_ACTION,
  SSERV_CMD_TESTS_SOLUTION_EDIT_PAGE,
  SSERV_CMD_TESTS_SOLUTION_EDIT_ACTION,
  SSERV_CMD_TESTS_SOLUTION_DELETE_ACTION,
  SSERV_CMD_TESTS_STYLE_CHECKER_CREATE_PAGE,
  SSERV_CMD_TESTS_STYLE_CHECKER_CREATE_ACTION,
  SSERV_CMD_TESTS_STYLE_CHECKER_EDIT_PAGE,
  SSERV_CMD_TESTS_STYLE_CHECKER_EDIT_ACTION,
  SSERV_CMD_TESTS_STYLE_CHECKER_DELETE_PAGE,
  SSERV_CMD_TESTS_STYLE_CHECKER_DELETE_ACTION,
  SSERV_CMD_TESTS_CHECKER_CREATE_PAGE,
  SSERV_CMD_TESTS_CHECKER_CREATE_ACTION,
  SSERV_CMD_TESTS_CHECKER_EDIT_PAGE,
  SSERV_CMD_TESTS_CHECKER_EDIT_ACTION,
  SSERV_CMD_TESTS_CHECKER_DELETE_PAGE,
  SSERV_CMD_TESTS_CHECKER_DELETE_ACTION,
  SSERV_CMD_TESTS_VALUER_CREATE_PAGE,
  SSERV_CMD_TESTS_VALUER_CREATE_ACTION,
  SSERV_CMD_TESTS_VALUER_EDIT_PAGE,
  SSERV_CMD_TESTS_VALUER_EDIT_ACTION,
  SSERV_CMD_TESTS_VALUER_DELETE_PAGE,
  SSERV_CMD_TESTS_VALUER_DELETE_ACTION,
  SSERV_CMD_TESTS_INTERACTOR_CREATE_PAGE,
  SSERV_CMD_TESTS_INTERACTOR_CREATE_ACTION,
  SSERV_CMD_TESTS_INTERACTOR_EDIT_PAGE,
  SSERV_CMD_TESTS_INTERACTOR_EDIT_ACTION,
  SSERV_CMD_TESTS_INTERACTOR_DELETE_PAGE,
  SSERV_CMD_TESTS_INTERACTOR_DELETE_ACTION,
  SSERV_CMD_TESTS_TEST_CHECKER_CREATE_PAGE,
  SSERV_CMD_TESTS_TEST_CHECKER_CREATE_ACTION,
  SSERV_CMD_TESTS_TEST_CHECKER_EDIT_PAGE,
  SSERV_CMD_TESTS_TEST_CHECKER_EDIT_ACTION,
  SSERV_CMD_TESTS_TEST_CHECKER_DELETE_PAGE,
  SSERV_CMD_TESTS_TEST_CHECKER_DELETE_ACTION,
  SSERV_CMD_TESTS_INIT_CREATE_PAGE,
  SSERV_CMD_TESTS_INIT_CREATE_ACTION,
  SSERV_CMD_TESTS_INIT_EDIT_PAGE,
  SSERV_CMD_TESTS_INIT_EDIT_ACTION,
  SSERV_CMD_TESTS_INIT_DELETE_PAGE,
  SSERV_CMD_TESTS_INIT_DELETE_ACTION,
  SSERV_CMD_TESTS_MAKEFILE_EDIT_PAGE,
  SSERV_CMD_TESTS_MAKEFILE_EDIT_ACTION,
  SSERV_CMD_TESTS_MAKEFILE_DELETE_ACTION,
  SSERV_CMD_TESTS_MAKEFILE_GENERATE_ACTION,
  SSERV_CMD_TESTS_TEST_MOVE_UP_ACTION,
  SSERV_CMD_TESTS_TEST_MOVE_DOWN_ACTION,
  SSERV_CMD_TESTS_TEST_MOVE_TO_SAVED_ACTION,
  SSERV_CMD_TESTS_TEST_INSERT_PAGE,
  SSERV_CMD_TESTS_TEST_INSERT_ACTION,
  SSERV_CMD_TESTS_TEST_EDIT_PAGE,
  SSERV_CMD_TESTS_TEST_EDIT_ACTION,
  SSERV_CMD_TESTS_TEST_DELETE_PAGE,
  SSERV_CMD_TESTS_TEST_DELETE_ACTION,
  SSERV_CMD_TESTS_TEST_UPLOAD_ARCHIVE_1_PAGE,
  SSERV_CMD_TESTS_TEST_CHECK_ACTION,
  SSERV_CMD_TESTS_TEST_GENERATE_ACTION,
  SSERV_CMD_TESTS_SAVED_MOVE_UP_ACTION,
  SSERV_CMD_TESTS_SAVED_MOVE_DOWN_ACTION,
  SSERV_CMD_TESTS_SAVED_DELETE_PAGE,
  SSERV_CMD_TESTS_SAVED_MOVE_TO_TEST_ACTION,
  SSERV_CMD_TESTS_README_CREATE_PAGE,
  SSERV_CMD_TESTS_README_EDIT_PAGE,
  SSERV_CMD_TESTS_README_DELETE_PAGE,
  SSERV_CMD_TESTS_CANCEL_ACTION,
  SSERV_CMD_TESTS_CANCEL_2_ACTION,
  SSERV_CMD_TESTS_TEST_DOWNLOAD,
  SSERV_CMD_TESTS_TEST_UPLOAD_PAGE,
  SSERV_CMD_TESTS_TEST_CLEAR_INF_ACTION,
  SSERV_CMD_TESTS_MAKE,

  SSERV_CMD_USER_MAP_MAIN_PAGE,
  SSERV_CMD_USER_MAP_DELETE_ACTION,
  SSERV_CMD_USER_MAP_ADD_ACTION,

  SSERV_CMD_CAPS_MAIN_PAGE,
  SSERV_CMD_CAPS_DELETE_ACTION,
  SSERV_CMD_CAPS_ADD_ACTION,
  SSERV_CMD_CAPS_EDIT_PAGE,
  SSERV_CMD_CAPS_EDIT_SAVE_ACTION,
  SSERV_CMD_CAPS_EDIT_CANCEL_ACTION,

  SSERV_CMD_EJUDGE_XML_UPDATE_ACTION,
  SSERV_CMD_EJUDGE_XML_CANCEL_ACTION,
  SSERV_CMD_EJUDGE_XML_MUST_RESTART,

  SSERV_CMD_IMPORT_FROM_POLYGON_PAGE,
  SSERV_CMD_IMPORT_FROM_POLYGON_ACTION,
  SSERV_CMD_DOWNLOAD_PROGRESS_PAGE,
  SSERV_CMD_DOWNLOAD_CLEANUP_ACTION,
  SSERV_CMD_DOWNLOAD_KILL_ACTION,
  SSERV_CMD_DOWNLOAD_CLEANUP_AND_CHECK_ACTION,
  SSERV_CMD_DOWNLOAD_CLEANUP_AND_IMPORT_ACTION,
  SSERV_CMD_UPDATE_FROM_POLYGON_PAGE,
  SSERV_CMD_UPDATE_FROM_POLYGON_ACTION,
  SSERV_CMD_IMPORT_PROBLEMS_BATCH_ACTION,
  SSERV_CMD_CREATE_CONTEST_BATCH_ACTION,
  SSERV_CMD_IMPORT_CONTEST_FROM_POLYGON_PAGE,

  // CSP actions
  SSERV_CMD_LOGIN_PAGE,
  SSERV_CMD_MAIN_PAGE,
  SSERV_CMD_CONTEST_PAGE,
  SSERV_CMD_CONTEST_XML_PAGE,
  SSERV_CMD_SERVE_CFG_PAGE,
  SSERV_CMD_CREATE_CONTEST_PAGE,
  SSERV_CMD_CREATE_CONTEST_2_ACTION,
  SSERV_CMD_CONTEST_ALREADY_EDITED_PAGE,
  SSERV_CMD_CONTEST_LOCKED_PAGE,
  SSERV_CMD_CHECK_TESTS_PAGE,
  SSERV_CMD_CNTS_EDIT_PERMISSIONS_PAGE,
  SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_USERS_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_MASTER_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_JUDGE_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_TEAM_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_SERVE_CONTROL_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_USER_FIELDS_PAGE,
  SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS_PAGE,
  SSERV_CMD_CNTS_EDIT_COACH_FIELDS_PAGE,
  SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS_PAGE,
  SSERV_CMD_CNTS_EDIT_GUEST_FIELDS_PAGE,
  SSERV_CMD_CNTS_START_EDIT_ACTION,
  SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD_PAGE,
  SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE_PAGE,
  SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE_PAGE,
  SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE_PAGE,
  SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE_PAGE,
  SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE_PAGE,
  SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE_PAGE,
  SSERV_CMD_CNTS_EDIT_USERS_HEADER_PAGE,
  SSERV_CMD_CNTS_EDIT_USERS_FOOTER_PAGE,
  SSERV_CMD_CNTS_EDIT_COPYRIGHT_PAGE,
  SSERV_CMD_CNTS_EDIT_WELCOME_PAGE,
  SSERV_CMD_CNTS_EDIT_REG_WELCOME_PAGE,
  SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE_PAGE,
  SSERV_CMD_CNTS_RELOAD_FILE_ACTION,
  SSERV_CMD_CNTS_SAVE_FILE_ACTION,
  SSERV_CMD_CNTS_CLEAR_FILE_ACTION,
  SSERV_CMD_CNTS_EDIT_CUR_GLOBAL_PAGE,
  SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE,
  SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  SSERV_CMD_CNTS_EDIT_CUR_PROBLEM_PAGE,
  SSERV_CMD_CNTS_START_EDIT_PROBLEM_ACTION,
  SSERV_CMD_CNTS_START_EDIT_VARIANT_ACTION,
  SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,
  SSERV_CMD_CNTS_NEW_SERVE_CFG_PAGE,
  SSERV_CMD_CNTS_COMMIT_PAGE,

  SSERV_CMD_USER_BROWSE_PAGE,
  SSERV_CMD_USER_BROWSE_DATA,
  SSERV_CMD_GET_CONTEST_LIST,
  SSERV_CMD_CNTS_SAVE_BASIC_FORM,
  SSERV_CMD_CNTS_SAVE_FLAGS_FORM,
  SSERV_CMD_CNTS_SAVE_REGISTRATION_FORM,
  SSERV_CMD_CNTS_SAVE_TIMING_FORM,
  SSERV_CMD_CNTS_SAVE_URLS_FORM,
  SSERV_CMD_CNTS_SAVE_HEADERS_FORM,
  SSERV_CMD_CNTS_SAVE_ATTRS_FORM,
  SSERV_CMD_CNTS_SAVE_NOTIFICATIONS_FORM,
  SSERV_CMD_CNTS_SAVE_ADVANCED_FORM,

  SSERV_CMD_GLOB_SAVE_MAIN_FORM,
  SSERV_CMD_GLOB_SAVE_CAPABILITIES_FORM,
  SSERV_CMD_GLOB_SAVE_FILES_FORM,
  SSERV_CMD_GLOB_SAVE_QUOTAS_FORM,
  SSERV_CMD_GLOB_SAVE_URLS_FORM,
  SSERV_CMD_GLOB_SAVE_ATTRS_FORM,
  SSERV_CMD_GLOB_SAVE_ADVANCED_FORM,
  SSERV_CMD_GLOB_SAVE_LIMITS_FORM,
  SSERV_CMD_LANG_SAVE_MAIN_FORM,
  SSERV_CMD_PROB_SAVE_ID_FORM,
  SSERV_CMD_PROB_SAVE_FILES_FORM,
  SSERV_CMD_PROB_SAVE_VALIDATION_FORM,
  SSERV_CMD_PROB_SAVE_VIEW_FORM,
  SSERV_CMD_PROB_SAVE_SUBMISSION_FORM,
  SSERV_CMD_PROB_SAVE_COMPILING_FORM,
  SSERV_CMD_PROB_SAVE_RUNNING_FORM,
  SSERV_CMD_PROB_SAVE_LIMITS_FORM,
  SSERV_CMD_PROB_SAVE_CHECKING_FORM,
  SSERV_CMD_PROB_SAVE_SCORING_FORM,
  SSERV_CMD_PROB_SAVE_FEEDBACK_FORM,
  SSERV_CMD_PROB_SAVE_STANDING_FORM,

  SSERV_CMD_MAIN_PAGE_BUTTON,

  SSERV_CMD_MIGRATION_PAGE,
  SSERV_CMD_EDIT_SESSIONS_PAGE,
  SSERV_CMD_CLEAR_SESSION,

  SSERV_CMD_LANG_AJAX_ACTION,

  SSERV_CMD_LOGIN_ACTION_JSON,
  SSERV_CMD_CREATE_SESSION_JSON,
  SSERV_CMD_CNTS_START_EDIT_JSON,
  SSERV_CMD_CNTS_FORGET_JSON,
  SSERV_CMD_CNTS_LIST_SESSIONS_JSON,
  SSERV_CMD_CNTS_COMMIT_JSON,
  SSERV_CMD_CNTS_DRY_COMMIT_JSON,
  SSERV_CMD_CHECK_TESTS_JSON,
  SSERV_CMD_CNTS_GET_VALUE_JSON,
  SSERV_CMD_CNTS_DELETE_VALUE_JSON,
  SSERV_CMD_CNTS_SET_VALUE_JSON,
  SSERV_CMD_CNTS_MINIMIZE_PROBLEM_JSON,

  SSERV_CMD_LAST,
};

/* replies */
enum
{
  SSERV_RPL_OK = 0,

  SSERV_RPL_LAST,
};

/* error codes */
enum
{
  SSERV_ERR_NO_ERROR = 0,
  SSERV_ERR_1,                  /* to reserve -1 */
  SSERV_ERR_NOT_CONNECTED,
  SSERV_ERR_INVALID_FD,
  SSERV_ERR_WRITE_TO_SERVER,
  SSERV_ERR_BAD_SOCKET_NAME,
  SSERV_ERR_SYSTEM_ERROR,
  SSERV_ERR_CONNECT_FAILED,
  SSERV_ERR_READ_FROM_SERVER,
  SSERV_ERR_EOF_FROM_SERVER,
  SSERV_ERR_PROTOCOL_ERROR,
  SSERV_ERR_USERLIST_DOWN,
  SSERV_ERR_PERMISSION_DENIED,
  SSERV_ERR_INVALID_CONTEST,
  SSERV_ERR_BANNED_IP,
  SSERV_ERR_ROOT_DIR_NOT_SET,
  SSERV_ERR_FILE_NOT_EXIST,
  SSERV_ERR_LOG_IS_DEV_NULL,
  SSERV_ERR_FILE_READ_ERROR,
  SSERV_ERR_FILE_FORMAT_INVALID,
  SSERV_ERR_UNEXPECTED_USERLIST_ERROR,
  SSERV_ERR_CONTEST_ALREADY_USED,
  SSERV_ERR_CONTEST_EDITED,
  SSERV_ERR_NOT_IMPLEMENTED,
  SSERV_ERR_INVALID_PARAMETER,
  SSERV_ERR_CONTEST_NOT_EDITED,
  SSERV_ERR_DUPLICATED_LOGIN,
  SSERV_ERR_DUPLICATED_PROBLEM,
  SSERV_ERR_PROBLEM_IS_USED,
  SSERV_ERR_PARAM_OUT_OF_RANGE,
  SSERV_ERR_SLAVE_MODE,

  SSERV_ERR_EMPTY_REPLY,
  SSERV_ERR_INV_OPER,
  SSERV_ERR_INV_SID,
  SSERV_ERR_INV_CONTEST,
  SSERV_ERR_PERM_DENIED,
  SSERV_ERR_INTERNAL,
  SSERV_ERR_ALREADY_EDITED,
  SSERV_ERR_NO_EDITED_CNTS,
  SSERV_ERR_INV_FIELD_ID,
  SSERV_ERR_INV_VALUE,
  SSERV_ERR_CONTEST_ALREADY_EXISTS,
  SSERV_ERR_CONTEST_ALREADY_EDITED,
  SSERV_ERR_INV_LANG_ID,
  SSERV_ERR_INV_PROB_ID,
  SSERV_ERR_INV_PACKAGE,
  SSERV_ERR_ITEM_EXISTS,
  SSERV_ERR_OPERATION_FAILED,
  SSERV_ERR_INV_USER_ID,
  SSERV_ERR_NO_CONNECTION,
  SSERV_ERR_DB_ERROR,
  SSERV_ERR_UNSPEC_PASSWD1,
  SSERV_ERR_UNSPEC_PASSWD2,
  SSERV_ERR_INV_PASSWD1,
  SSERV_ERR_INV_PASSWD2,
  SSERV_ERR_PASSWDS_DIFFER,
  SSERV_ERR_UNSPEC_LOGIN,
  SSERV_ERR_INV_GROUP_ID,
  SSERV_ERR_INV_FIRST_SERIAL,
  SSERV_ERR_INV_LAST_SERIAL,
  SSERV_ERR_INV_RANGE,
  SSERV_ERR_INV_LOGIN_TEMPLATE,
  SSERV_ERR_INV_REG_PASSWORD_TEMPLATE,
  SSERV_ERR_INV_CNTS_PASSWORD_TEMPLATE,
  SSERV_ERR_INV_CNTS_NAME_TEMPLATE,
  SSERV_ERR_INV_CSV_FILE,
  SSERV_ERR_INV_CHARSET,
  SSERV_ERR_INV_SEPARATOR,
  SSERV_ERR_DATA_READ_ONLY,
  SSERV_ERR_TOO_MANY_MEMBERS,
  SSERV_ERR_INV_SERIAL,
  SSERV_ERR_INV_EMAIL,
  SSERV_ERR_INV_GROUP_NAME,
  SSERV_ERR_INV_DESCRIPTION,
  SSERV_ERR_GROUP_CREATION_FAILED,
  SSERV_ERR_INV_SERVE_CONFIG_PATH,
  SSERV_ERR_INV_VARIANT,
  SSERV_ERR_UNSUPPORTED_SETTINGS,
  SSERV_ERR_INV_CNTS_SETTINGS,
  SSERV_ERR_INV_TEST_NUM,
  SSERV_ERR_FS_ERROR,
  SSERV_ERR_INV_EXIT_CODE,
  SSERV_ERR_INV_SYS_GROUP,
  SSERV_ERR_INV_SYS_MODE,
  SSERV_ERR_INV_TESTINFO,
  SSERV_ERR_INV_PROB_XML,
  SSERV_ERR_UNSPEC_PROB_PACKAGE,
  SSERV_ERR_UNSPEC_PROB_NAME,
  SSERV_ERR_INV_XHTML,
  SSERV_ERR_INV_SESSION,

  SSERV_UNKNOWN_ERROR,

  SSERV_ERR_LAST,
  S_ERR_LAST = SSERV_ERR_LAST,

  // aliases
  SSERV_ERR_INV_PARAM = SSERV_ERR_INVALID_PARAMETER,
};

unsigned char const *super_proto_strerror(int n);

enum
{
  SSERV_VIEW_INVISIBLE = 1,
};

struct prot_super_pkt_simple_cmd
{
  struct prot_super_packet b;

  int contest_id;
};

struct prot_super_pkt_create_contest
{
  struct prot_super_packet b;

  int num_mode;
  int templ_mode;
  int contest_id;
  int templ_id;
  int self_url_len;
  int hidden_vars_len;
  int extra_args_len;
  unsigned char data[3];
};

struct prot_super_pkt_set_param
{
  struct prot_super_packet b;

  int param1;
  int param2_len;
  int param3;
  int param4;
  int param5;
  unsigned char data[1];
};

struct prot_super_pkt_http_request
{
  struct prot_super_packet b;
  int api_mode;
  int arg_num;
  int env_num;
  int param_num;
};

extern const int super_proto_op_redirect[SSERV_CMD_LAST];
extern unsigned char const * const super_proto_error_messages[];
extern const unsigned char * const super_proto_cmd_names[SSERV_CMD_LAST];
extern const unsigned char super_proto_is_http_request[];

#endif /* __SUPER_PROTO_H__ */
