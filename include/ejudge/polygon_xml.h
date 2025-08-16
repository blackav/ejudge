/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __POLYGON_XML_H__
#define __POLYGON_XML_H__

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/expat_iface.h"

#include <stdio.h>

enum
{
    PPXML_PROBLEM = 1,
    PPXML_NAME,
    PPXML_NAMES,
    PPXML_STATEMENT,
    PPXML_STATEMENTS,
    PPXML_TUTORIAL,
    PPXML_TUTORIALS,
    PPXML_JUDGING,
    PPXML_TESTSET,
    PPXML_TIME_LIMIT,
    PPXML_MEMORY_LIMIT,
    PPXML_TEST_COUNT,
    PPXML_INPUT_PATH_PATTERN,
    PPXML_ANSWER_PATH_PATTERN,
    PPXML_TEST,
    PPXML_TESTS,
    PPXML_GROUP,
    PPXML_GROUPS,
    PPXML_FILE,
    PPXML_FILES,
    PPXML_RESOURCES,
    PPXML_EXECUTABLE,
    PPXML_EXECUTABLES,
    PPXML_SOURCE,
    PPXML_BINARY,
    PPXML_ASSET,
    PPXML_ASSETS,
    PPXML_CHECKER,
    PPXML_COPY,
    PPXML_OUTPUT_PATH_PATTERN,
    PPXML_VALIDATOR,
    PPXML_VALIDATORS,
    PPXML_SOLUTION,
    PPXML_SOLUTIONS,
    PPXML_PROPERTY,
    PPXML_PROPERTIES,
    PPXML_STRESS,
    PPXML_STRESSES,
    PPXML_STRESS_COUNT,
    PPXML_STRESS_PATH_PATTERN,
    PPXML_LIST,
    PPXML_TAG,
    PPXML_TAGS,
    PPXML_DEPENDENCY,
    PPXML_DEPENDENCIES,
    PPXML_DOCUMENT,
    PPXML_DOCUMENTS,
    PPXML_EXTRA_TAG,
    PPXML_EXTRA_TAGS,
    PPXML_INTERACTOR,
    PPXML_ATTACHMENTS,
    PPXML_SCORER,
    PPXML_STAGE,
    PPXML_STAGES,
    PPXML_MATERIAL,
    PPXML_MATERIALS,

    PPXML_TAG_LAST,
};

enum
{
    PPXML_A_REVISION = 1,
    PPXML_A_SHORT_NAME,
    PPXML_A_URL,
    PPXML_A_LANGUAGE,
    PPXML_A_VALUE,
    PPXML_A_CHARSET,
    PPXML_A_MATHJAX,
    PPXML_A_PATH,
    PPXML_A_TYPE,
    PPXML_A_CPU_NAME,
    PPXML_A_CPU_SPEED,
    PPXML_A_INPUT_FILE,
    PPXML_A_OUTPUT_FILE,
    PPXML_A_RUN_COUNT,
    PPXML_A_NAME,
    PPXML_A_GROUP,
    PPXML_A_METHOD,
    PPXML_A_POINTS,
    PPXML_A_SAMPLE,
    PPXML_A_CMD,
    PPXML_A_FEEDBACK_POLICY,
    PPXML_A_POINTS_POLICY,
    PPXML_A_VERDICT,
    PPXML_A_TAG,
    PPXML_A_DESCRIPTION,
    PPXML_A_INDEX,
    PPXML_A_TESTSET,
    PPXML_A_NOTE,
    PPXML_A_FROM_FILE,
    PPXML_A_FOR_TYPES,
    PPXML_A_PUBLISH,
    PPXML_A_UUID_FROM_HISTORY,
    PPXML_A_EXTRA_CONFIG,
    PPXML_A_GENERATE_ANSWER,
    PPXML_A_AUTO_COUNT,
    PPXML_A_NORMALIZATION,
    PPXML_A_FILE_TYPE,
};

enum
{
    PPXML_LANG_UNKNOWN,
    PPXML_LANG_RUSSIAN,
    PPXML_LANG_ENGLISH,
    PPXML_LANG_AFRIKAANS,
    PPXML_LANG_ARMENIAN,
    PPXML_LANG_AZERBAIJANI,
    PPXML_LANG_BELARUSIAN,
    PPXML_LANG_BOSNIAN,
    PPXML_LANG_BULGARIAN,
    PPXML_LANG_CHINESE,
    PPXML_LANG_CROATIAN,
    PPXML_LANG_ESTONIAN,
    PPXML_LANG_FINNISH,
    PPXML_LANG_GERMAN,
    PPXML_LANG_HEBREW,
    PPXML_LANG_HUNGARIAN,
    PPXML_LANG_INDONESIAN,
    PPXML_LANG_MALAY,
    PPXML_LANG_POLISH,
    PPXML_LANG_ROMANIAN,
    PPXML_LANG_SERBIAN,
    PPXML_LANG_SLOVAK,
    PPXML_LANG_SLOVENE,
    PPXML_LANG_TURKISH,
    PPXML_LANG_UZBEK,
    PPXML_LANG_VIETNAMESE,
};

enum
{
    PPXML_CHARSET_UNKNOWN,
    PPXML_CHARSET_UTF_8,
};

enum
{
    PPXML_TYPE_UNKNOWN,
    PPXML_TYPE_TEXT,
    PPXML_TYPE_TEX,
    PPXML_TYPE_HTML,
    PPXML_TYPE_PDF,
    PPXML_TYPE_EJUDGE_XML,
};

enum
{
    PPXML_METHOD_UNKNOWN,
    PPXML_METHOD_MANUAL,
    PPXML_METHOD_GENERATED,
};

enum
{
    PPXML_FEEDBACK_UNKNOWN,
    PPXML_FEEDBACK_COMPLETE,
    PPXML_FEEDBACK_ICPC,
    PPXML_FEEDBACK_POINTS,
    PPXML_FEEDBACK_NONE,
};

enum
{
    PPXML_POINTS_UNKNOWN,
    PPXML_POINTS_EACH_TEST,
    PPXML_POINTS_COMPLETE_GROUP,
};

enum
{
    PPXML_VERDICT_UNKNOWN,
    PPXML_VERDICT_INVALID,
    PPXML_VERDICT_VALID,
    PPXML_VERDICT_OK,
    PPXML_VERDICT_WRONG_ANSWER,
    PPXML_VERDICT_CRASHED,
    PPXML_VERDICT_PRESENTATION_ERROR,
};

enum
{
    PPXML_SOLUTION_TAG_UNKNOWN,
    PPXML_SOLUTION_TAG_MAIN,
    PPXML_SOLUTION_TAG_ACCEPTED,
    PPXML_SOLUTION_TAG_REJECTED,
    PPXML_SOLUTION_TAG_WRONG_ANSWER,
    PPXML_SOLUTION_TAG_TIME_LIMIT,
    PPXML_SOLUTION_TAG_MEMORY_LIMIT,
    PPXML_SOLUTION_TAG_TIME_LIMIT_OR_ACCEPTED,
    PPXML_SOLUTION_TAG_TIME_LIMIT_OR_MEMORY_LIMIT,
    PPXML_SOLUTION_TAG_PRESENTATION_ERROR,
    PPXML_SOLUTION_TAG_FAILED,
};

enum
{
    PPXML_FILE_TYPE_UNKNOWN,
    PPXML_FILE_TYPE_TEXT,
    PPXML_FILE_TYPE_RELAXED_TEXT,
    PPXML_FILE_TYPE_BINARY,
};

struct ppxml_name
{
    struct xml_tree b;
    unsigned char *value;
    unsigned char language;
};

struct ppxml_names
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_name) n;
};

struct ppxml_statement
{
    struct xml_tree b;
    unsigned char *path;
    unsigned char charset;
    unsigned char language;
    unsigned char mathjax;
    unsigned char type;
};

struct ppxml_statements
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_statement) n;
};

struct ppxml_test
{
    struct xml_tree b;
    unsigned char *group;
    unsigned char *cmd;
    unsigned char *description;
    unsigned char *from_file;
    double points;
    unsigned char method;
    unsigned char sample;
    unsigned char verdict;
};

struct ppxml_tests
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_test) n;
};

struct ppxml_dependency
{
    struct xml_tree b;
    unsigned char *group;
};

struct ppxml_dependencies
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_dependency) n;
};

struct ppxml_group
{
    struct xml_tree b;
    unsigned char *name;
    struct ppxml_dependencies *dependencies;
    double points;
    unsigned char feedback_policy;
    unsigned char points_policy;
};

struct ppxml_groups
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_group) n;
};

struct ppxml_path_pattern
{
    struct xml_tree b;
    unsigned char *pattern;
    unsigned char file_type;
    unsigned char *charset;
    signed char normalization; // -1 for undefined value
};

struct ppxml_testset
{
    struct xml_tree b;
    unsigned char *name;
    struct ppxml_path_pattern *input;
    struct ppxml_path_pattern *output;
    struct ppxml_path_pattern *answer;
    struct ppxml_tests *tests;
    struct ppxml_groups *groups;
    long long memory_limit;
    int time_limit;
    int test_count;
    unsigned char generate_answer;
    unsigned char auto_count;
    signed char normalization; // -1 for undefined value
};

struct ppxml_judging
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_testset) testsets;
    unsigned char *cpu_name;
    unsigned char *input_file;
    unsigned char *output_file;
    double cpu_speed;
    int run_count;
    unsigned char extra_config;
};

struct ppxml_assets;
struct ppxml_stages;

struct ppxml_file
{
    struct xml_tree b;
    unsigned char *path;
    unsigned char *type;
    unsigned char *for_types;
    struct ppxml_assets *assets;
    struct ppxml_stages *stages;
};

struct ppxml_asset
{
    struct xml_tree b;
    unsigned char *name;
};

struct ppxml_stage
{
    struct xml_tree b;
    unsigned char *name;
};

struct ppxml_stages
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_stage) n;
};

struct ppxml_resources
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_file) n;
};

struct ppxml_attachments
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_file) n;
};

struct ppxml_source
{
    struct xml_tree b;
    unsigned char *path;
    unsigned char *type;
};

struct ppxml_binary
{
    struct xml_tree b;
    unsigned char *path;
    unsigned char *type;
};

struct ppxml_executable
{
    struct xml_tree b;
    struct ppxml_source *source;
    struct ppxml_binary *binary;
};

struct ppxml_executables
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_executable) n;
};

struct ppxml_files
{
    struct xml_tree b;
    struct ppxml_resources *resources;
    struct ppxml_attachments *attachments;
    struct ppxml_executables *executables;
};

struct ppxml_copy
{
    struct xml_tree b;
    unsigned char *path;
    unsigned char *type;
};

struct ppxml_checker
{
    struct xml_tree b;
    unsigned char *name;
    unsigned char *type;
    struct ppxml_source *source;
    struct ppxml_binary *binary;
    struct ppxml_copy *copy;
    struct ppxml_testset *testset;
};

struct ppxml_validator
{
    struct xml_tree b;
    struct ppxml_source *source;
    struct ppxml_binary *binary;
    struct ppxml_testset *testset;
};

struct ppxml_validators
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_validator) n;
};

struct ppxml_interactor
{
    struct xml_tree b;
    struct ppxml_source *source;
    struct ppxml_binary *binary;
};

struct ppxml_scorer
{
    struct xml_tree b;
    struct ppxml_source *source;
    struct ppxml_binary *binary;
};

struct ppxml_extra_tag
{
    struct xml_tree b;
    unsigned char *group;
    unsigned char *testset;
    unsigned char tag;
};

struct ppxml_extra_tags
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_extra_tag) n;
};

struct ppxml_solution
{
    struct xml_tree b;
    struct ppxml_source *source;
    struct ppxml_binary *binary;
    struct ppxml_extra_tags *extra_tags;
    unsigned char *note;
    unsigned char tag;
};

struct ppxml_solutions
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_solution) n;
};

struct ppxml_assets
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_asset) assets;
    struct ppxml_checker *checker;
    struct ppxml_interactor *interactor;
    struct ppxml_validators *validators;
    struct ppxml_solutions *solutions;
    struct ppxml_scorer *scorer;
};

struct ppxml_property
{
    struct xml_tree b;
    unsigned char *name;
    unsigned char *value;
};

struct ppxml_properties
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_property) n;
};

struct ppxml_tag
{
    struct xml_tree b;
    unsigned char *value;
};

struct ppxml_tags
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_tag) n;
};

struct ppxml_document
{
    struct xml_tree b;
    unsigned char *path;
    unsigned char *type;
};

struct ppxml_documents
{
    struct xml_tree b;
    XML_TREE_VECTOR_T(ppxml_documents) n;
};

/*
    <stresses>
        <stress-count>0</stress-count>
        <stress-path-pattern>stresses/%03d</stress-path-pattern>
        <list/>
    </stresses>
*/

struct ppxml_problem
{
    struct xml_tree b;
    int revision;
    unsigned char *short_name;
    unsigned char *url;
    struct ppxml_names *names;
    struct ppxml_statements *statements;
    struct ppxml_statements *tutorials;
    struct ppxml_judging *judging;
    struct ppxml_files *files;
    struct ppxml_assets *assets;
    struct ppxml_properties *properties;
    struct ppxml_tags *tags;
    struct ppxml_documents *documents;
    unsigned char uuid_from_history;
};

struct ppxml_parse_context;

struct ppxml_parse_ops
{
    void* (*free_context)(struct ppxml_parse_context *cntx);

    __attribute__((format(printf, 4, 5)))
    void* (*err)(struct ppxml_parse_context *cntx, int line, int column, const char *format, ...);

    void* (*err_elem_not_allowed)(struct ppxml_parse_context *cntx, const struct xml_tree *p);
    void* (*err_nested_elems)(struct ppxml_parse_context *cntx, const struct xml_tree *p);
    void* (*err_attr_not_allowed)(struct ppxml_parse_context *cntx, const struct xml_tree *p, const struct xml_attr *a);
    void* (*err_attr_undefined)(struct ppxml_parse_context *cntx, const struct xml_tree *p, int a);
    void* (*err_attr_invalid)(struct ppxml_parse_context *cntx, const struct xml_attr *a);
    void* (*err_elem_redefined)(struct ppxml_parse_context *cntx, const struct xml_tree *p);
    void* (*err_elem_invalid)(struct ppxml_parse_context *cntx, const struct xml_tree *p);
    void* (*err_elem_undefined)(struct ppxml_parse_context *cntx, const struct xml_tree *p, int q);
};

struct xml_parse_spec;

struct ppxml_parse_context
{
    const struct ppxml_parse_ops *ops;
    const struct xml_parse_spec *spec;
    FILE *log_f;
    const unsigned char *path;
    int error_count;
    unsigned char quiet_flag;
    unsigned char log_flag;
    unsigned char stderr_flag;
};

struct ppxml_problem *
ppxml_parse_str(FILE *log_f, const char *path, const char *str);
struct ppxml_problem *
ppxml_free(struct ppxml_problem *prob);

#endif /* __POLYGON_XML_H__ */
