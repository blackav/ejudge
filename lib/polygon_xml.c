/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/polygon_xml.h"
#include "ejudge/ej_types.h"
#include "ejudge/expat_iface.h"
#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char const * const problem_xml_elem_map[] =
{
    [0] = NULL,
    [PPXML_PROBLEM] = "problem",
    [PPXML_NAMES] = "names",
    [PPXML_NAME] = "name",
    [PPXML_STATEMENTS] = "statements",
    [PPXML_STATEMENT] = "statement",
    [PPXML_TUTORIALS] = "tutorials",
    [PPXML_TUTORIAL] = "tutorial",
    [PPXML_JUDGING] = "judging",
    [PPXML_TESTSET] = "testset",
    [PPXML_TIME_LIMIT] = "time-limit",
    [PPXML_MEMORY_LIMIT] = "memory-limit",
    [PPXML_TEST_COUNT] = "test-count",
    [PPXML_INPUT_PATH_PATTERN] = "input-path-pattern",
    [PPXML_ANSWER_PATH_PATTERN] = "answer-path-pattern",
    [PPXML_TESTS] = "tests",
    [PPXML_TEST] = "test",
    [PPXML_GROUPS] = "groups",
    [PPXML_GROUP] = "group",
    [PPXML_FILES] = "files",
    [PPXML_RESOURCES] = "resources",
    [PPXML_FILE] = "file",
    [PPXML_EXECUTABLES] = "executables",
    [PPXML_EXECUTABLE] = "executable",
    [PPXML_SOURCE] = "source",
    [PPXML_BINARY] = "binary",
    [PPXML_ASSETS] = "assets",
    [PPXML_CHECKER] = "checker",
    [PPXML_COPY] = "copy",
    [PPXML_OUTPUT_PATH_PATTERN] = "output-path-pattern",
    [PPXML_VALIDATORS] = "validators",
    [PPXML_VALIDATOR] = "validator",
    [PPXML_SOLUTIONS] = "solutions",
    [PPXML_SOLUTION] = "solution",
    [PPXML_PROPERTIES] = "properties",
    [PPXML_PROPERTY] = "property",
    [PPXML_STRESSES] = "stresses",
    [PPXML_STRESS] = "stress",
    [PPXML_STRESS_COUNT] = "stress-count",
    [PPXML_STRESS_PATH_PATTERN] = "stress-path-pattern",
    [PPXML_LIST] = "list",
    [PPXML_TAGS] = "tags",
    [PPXML_TAG] = "tag",
    [PPXML_DEPENDENCY] = "dependency",
    [PPXML_DEPENDENCIES] = "dependencies",
    [PPXML_DOCUMENT] = "document",
    [PPXML_DOCUMENTS] = "documents",
    [PPXML_EXTRA_TAG] = "extra-tag",
    [PPXML_EXTRA_TAGS] = "extra-tags",
    [PPXML_INTERACTOR] = "interactor",
    [PPXML_ATTACHMENTS] = "attachments",
    [PPXML_SCORER] = "scorer",
    [PPXML_ASSET] = "asset",
    [PPXML_STAGE] = "stage",
    [PPXML_STAGES] = "stages",
    [PPXML_MATERIAL] = "material",
    [PPXML_MATERIALS] = "materials",
    [PPXML_GENERATOR] = "generator",
    [PPXML_GENERATORS] = "generators",
    NULL,
};

static char const * const problem_xml_attr_map[] =
{
    NULL,
    [PPXML_A_REVISION] = "revision",
    [PPXML_A_SHORT_NAME] = "short-name",
    [PPXML_A_URL] = "url",
    [PPXML_A_LANGUAGE] = "language",
    [PPXML_A_VALUE] = "value",
    [PPXML_A_CHARSET] = "charset",
    [PPXML_A_MATHJAX] = "mathjax",
    [PPXML_A_PATH] = "path",
    [PPXML_A_TYPE] = "type",
    [PPXML_A_CPU_NAME] = "cpu-name",
    [PPXML_A_CPU_SPEED] = "cpu-speed",
    [PPXML_A_INPUT_FILE] = "input-file",
    [PPXML_A_OUTPUT_FILE] = "output-file",
    [PPXML_A_RUN_COUNT] = "run-count",
    [PPXML_A_NAME] = "name",
    [PPXML_A_GROUP] = "group",
    [PPXML_A_METHOD] = "method",
    [PPXML_A_POINTS] = "points",
    [PPXML_A_SAMPLE] = "sample",
    [PPXML_A_CMD] = "cmd",
    [PPXML_A_FEEDBACK_POLICY] = "feedback-policy", 
    [PPXML_A_POINTS_POLICY] = "points-policy",
    [PPXML_A_VERDICT] = "verdict",
    [PPXML_A_TAG] = "tag",
    [PPXML_A_DESCRIPTION] = "description",
    [PPXML_A_INDEX] = "index",
    [PPXML_A_TESTSET] = "testset",
    [PPXML_A_NOTE] = "note",
    [PPXML_A_FROM_FILE] = "from-file",
    [PPXML_A_FOR_TYPES] = "for-types",
    [PPXML_A_PUBLISH] = "publish",
    [PPXML_A_UUID_FROM_HISTORY] = "uuid-from-history",
    [PPXML_A_EXTRA_CONFIG] = "extra-config",
    [PPXML_A_GENERATE_ANSWER] = "generate-answer",
    [PPXML_A_AUTO_COUNT] = "auto-count",
    [PPXML_A_NORMALIZATION] = "normalization",
    [PPXML_A_FILE_TYPE] = "file-type",
    NULL,
};

static size_t const problem_xml_sizes[PPXML_TAG_LAST] =
{
    [PPXML_PROBLEM] = sizeof(struct ppxml_problem),
    [PPXML_NAMES] = sizeof(struct ppxml_names),
    [PPXML_NAME] = sizeof(struct ppxml_name),
    [PPXML_STATEMENTS] = sizeof(struct ppxml_statements),
    [PPXML_STATEMENT] = sizeof(struct ppxml_statement),
    [PPXML_TUTORIALS] = sizeof(struct ppxml_statements),
    [PPXML_TUTORIAL] = sizeof(struct ppxml_statement),
    [PPXML_JUDGING] = sizeof(struct ppxml_judging),
    [PPXML_INPUT_PATH_PATTERN] = sizeof(struct ppxml_path_pattern),
    [PPXML_OUTPUT_PATH_PATTERN] = sizeof(struct ppxml_path_pattern),
    [PPXML_ANSWER_PATH_PATTERN] = sizeof(struct ppxml_path_pattern),
    [PPXML_TESTSET] = sizeof(struct ppxml_testset),
    [PPXML_TESTS] = sizeof(struct ppxml_tests),
    [PPXML_TEST] = sizeof(struct ppxml_test),
    [PPXML_GROUPS] = sizeof(struct ppxml_groups),
    [PPXML_GROUP] = sizeof(struct ppxml_group),
    [PPXML_FILES] = sizeof(struct ppxml_files),
    [PPXML_RESOURCES] = sizeof(struct ppxml_resources),
    [PPXML_FILE] = sizeof(struct ppxml_file),
    [PPXML_EXECUTABLES] = sizeof(struct ppxml_executables),
    [PPXML_EXECUTABLE] = sizeof(struct ppxml_executable),
    [PPXML_SOURCE] = sizeof(struct ppxml_source),
    [PPXML_BINARY] = sizeof(struct ppxml_binary),
    [PPXML_ASSETS] = sizeof(struct ppxml_assets),
    [PPXML_CHECKER] = sizeof(struct ppxml_checker),
    [PPXML_COPY] = sizeof(struct ppxml_copy),
    [PPXML_VALIDATORS] = sizeof(struct ppxml_validators),
    [PPXML_VALIDATOR] = sizeof(struct ppxml_validator),
    [PPXML_SOLUTIONS] = sizeof(struct ppxml_solutions),
    [PPXML_SOLUTION] = sizeof(struct ppxml_solution),
    [PPXML_PROPERTIES] = sizeof(struct ppxml_properties),
    [PPXML_PROPERTY] = sizeof(struct ppxml_property),
    [PPXML_TAGS] = sizeof(struct ppxml_tags),
    [PPXML_TAG] = sizeof(struct ppxml_tag),
    [PPXML_DEPENDENCY] = sizeof(struct ppxml_dependency),
    [PPXML_DEPENDENCIES] = sizeof(struct ppxml_dependencies),
    [PPXML_DOCUMENT] = sizeof(struct ppxml_document),
    [PPXML_DOCUMENTS] = sizeof(struct ppxml_documents),
    [PPXML_EXTRA_TAG] = sizeof(struct ppxml_extra_tag),
    [PPXML_EXTRA_TAGS] = sizeof(struct ppxml_extra_tags),
    [PPXML_INTERACTOR] = sizeof(struct ppxml_interactor),
    [PPXML_ATTACHMENTS] = sizeof(struct ppxml_attachments),
    [PPXML_SCORER] = sizeof(struct ppxml_scorer),
    [PPXML_ASSET] = sizeof(struct ppxml_asset),
    [PPXML_STAGE] = sizeof(struct ppxml_stage),
    [PPXML_STAGES] = sizeof(struct ppxml_stages),
    [PPXML_GENERATOR] = sizeof(struct ppxml_generator),
    [PPXML_GENERATORS] = sizeof(struct ppxml_generators),
};

static void
node_free(struct xml_tree *t)
{
    if (!t) return;

    switch (t->tag) {
    case PPXML_NAMES: {
        struct ppxml_names *tt = (struct ppxml_names *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_STATEMENTS: {
        struct ppxml_statements *tt = (struct ppxml_statements *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_TUTORIALS: {
        struct ppxml_statements *tt = (struct ppxml_statements *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_JUDGING: {
        struct ppxml_judging *tt = (struct ppxml_judging *) t;
        free(tt->testsets.v);
        break;
    }
    case PPXML_TESTS: {
        struct ppxml_tests *tt = (struct ppxml_tests *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_GROUPS: {
        struct ppxml_groups *tt = (struct ppxml_groups *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_RESOURCES: {
        struct ppxml_resources *tt = (struct ppxml_resources *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_EXECUTABLES: {
        struct ppxml_executables *tt = (struct ppxml_executables *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_ASSETS: {
        struct ppxml_assets *tt = (struct ppxml_assets *) t;
        free(tt->assets.v);
        break;
    }
    case PPXML_VALIDATORS: {
        struct ppxml_validators *tt = (struct ppxml_validators *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_SOLUTIONS: {
        struct ppxml_solutions *tt = (struct ppxml_solutions *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_PROPERTIES: {
        struct ppxml_properties *tt = (struct ppxml_properties *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_TAGS: {
        struct ppxml_tags *tt = (struct ppxml_tags *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_DEPENDENCIES: {
        struct ppxml_dependencies *tt = (struct ppxml_dependencies *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_DOCUMENTS: {
        struct ppxml_documents *tt = (struct ppxml_documents *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_EXTRA_TAGS: {
        struct ppxml_extra_tags *tt = (struct ppxml_extra_tags *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_ATTACHMENTS: {
        struct ppxml_attachments *tt = (struct ppxml_attachments *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_STAGES: {
        struct ppxml_stages *tt = (struct ppxml_stages *) t;
        free(tt->n.v);
        break;
    }
    case PPXML_GENERATORS: {
        struct ppxml_generators *tt = (struct ppxml_generators *) t;
        free(tt->n.v);
        break;
    }
    }
}

static const struct xml_parse_spec polygon_xml_parse_spec =
{
  .elem_map = problem_xml_elem_map,
  .attr_map = problem_xml_attr_map,
  .elem_sizes = problem_xml_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = node_free,
  .attr_free = NULL,
};

static const char * const ppxml_lang_strings[] =
{
    [PPXML_LANG_RUSSIAN] = "russian",
    [PPXML_LANG_ENGLISH] = "english",
    [PPXML_LANG_AFRIKAANS] = "afrikaans",
    [PPXML_LANG_ARMENIAN] = "armenian",
    [PPXML_LANG_AZERBAIJANI] = "azerbaijani",
    [PPXML_LANG_BELARUSIAN] = "belarusian",
    [PPXML_LANG_BOSNIAN] = "bosnian",
    [PPXML_LANG_BULGARIAN] = "bulgarian",
    [PPXML_LANG_CHINESE] = "chinese",
    [PPXML_LANG_CROATIAN] = "croatian",
    [PPXML_LANG_ESTONIAN] = "estonian",
    [PPXML_LANG_FINNISH] = "finnish",
    [PPXML_LANG_GERMAN] = "german",
    [PPXML_LANG_HEBREW] = "hebrew",
    [PPXML_LANG_HUNGARIAN] = "hungarian",
    [PPXML_LANG_INDONESIAN] = "indonesian",
    [PPXML_LANG_MALAY] = "malay",
    [PPXML_LANG_POLISH] = "polish",
    [PPXML_LANG_ROMANIAN] = "romanian",
    [PPXML_LANG_SERBIAN] = "serbian",
    [PPXML_LANG_SLOVAK] = "slovak",
    [PPXML_LANG_SLOVENE] = "slovene",
    [PPXML_LANG_TURKISH] = "turkish",
    [PPXML_LANG_UZBEK] = "uzbek",
    [PPXML_LANG_VIETNAMESE] = "vietnamese",
};
static int ppxml_lang_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_lang_strings)/sizeof(ppxml_lang_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_lang_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_charset_strings[] =
{
    [PPXML_CHARSET_UTF_8] = "utf-8",
};
static int ppxml_charset_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_charset_strings)/sizeof(ppxml_charset_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_charset_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_type_strings[] =
{
    [PPXML_TYPE_TEXT] = "text/plain",
    [PPXML_TYPE_TEX] = "application/x-tex",
    [PPXML_TYPE_HTML] = "text/html",
    [PPXML_TYPE_PDF] = "application/pdf",
    [PPXML_TYPE_EJUDGE_XML] = "application/x-ejudge-xml",
    [PPXML_TYPE_MARKDOWN] = "text/markdown",
};
static int ppxml_type_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_type_strings)/sizeof(ppxml_type_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_type_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_method_strings[] =
{
    [PPXML_METHOD_MANUAL] = "manual",
    [PPXML_METHOD_GENERATED] = "generated",
};
static int ppxml_method_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_method_strings)/sizeof(ppxml_method_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_method_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_feedback_strings[] =
{
    [PPXML_FEEDBACK_COMPLETE] = "complete",
    [PPXML_FEEDBACK_ICPC] = "icpc",
    [PPXML_FEEDBACK_POINTS] = "points",
    [PPXML_FEEDBACK_NONE] = "none",
};
static int ppxml_feedback_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_feedback_strings)/sizeof(ppxml_feedback_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_feedback_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_points_strings[] =
{
    [PPXML_POINTS_EACH_TEST] = "each-test",
    [PPXML_POINTS_COMPLETE_GROUP] = "complete-group",
};
static int ppxml_points_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_points_strings)/sizeof(ppxml_points_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_points_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_verdict_strings[] =
{
    [PPXML_VERDICT_INVALID] = "invalid",
    [PPXML_VERDICT_VALID] = "valid",
    [PPXML_VERDICT_OK] = "ok",
    [PPXML_VERDICT_WRONG_ANSWER] = "wrong-answer",
    [PPXML_VERDICT_CRASHED] = "crashed",
    [PPXML_VERDICT_PRESENTATION_ERROR] = "presentation-error",
};
static int ppxml_verdict_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_verdict_strings)/sizeof(ppxml_verdict_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_verdict_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_solution_tag_strings[] =
{
    [PPXML_SOLUTION_TAG_MAIN] = "main",
    [PPXML_SOLUTION_TAG_ACCEPTED] = "accepted",
    [PPXML_SOLUTION_TAG_REJECTED] = "rejected",
    [PPXML_SOLUTION_TAG_WRONG_ANSWER] = "wrong-answer",
    [PPXML_SOLUTION_TAG_TIME_LIMIT] = "time-limit-exceeded",
    [PPXML_SOLUTION_TAG_MEMORY_LIMIT] = "memory-limit-exceeded",
    [PPXML_SOLUTION_TAG_TIME_LIMIT_OR_ACCEPTED] = "time-limit-exceeded-or-accepted",
    [PPXML_SOLUTION_TAG_TIME_LIMIT_OR_MEMORY_LIMIT] = "time-limit-exceeded-or-memory-limit-exceeded",
    [PPXML_SOLUTION_TAG_PRESENTATION_ERROR] = "presentation-error",
    [PPXML_SOLUTION_TAG_FAILED] = "failed",
};
static int ppxml_solution_tag_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_solution_tag_strings)/sizeof(ppxml_solution_tag_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_solution_tag_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static const char * const ppxml_file_type_strings[] =
{
    [PPXML_FILE_TYPE_TEXT] = "text",
    [PPXML_FILE_TYPE_RELAXED_TEXT] = "relaxed-text",
    [PPXML_FILE_TYPE_BINARY] = "binary",
};
static int ppxml_file_type_parse(const unsigned char *s)
{
    if (s) {
        for (int i = 1; i < sizeof(ppxml_file_type_strings)/sizeof(ppxml_file_type_strings[0]); ++i) {
            if (!strcasecmp(s, ppxml_file_type_strings[i])) {
                return i;
            }
        }
    }
    return 0;
}

static int
ppxml_parse_bool(const unsigned char *s, int *p_v)
{
    if (!s) return -1;
    if (!strcasecmp(s, "true") || !strcasecmp(s, "yes") || !strcasecmp(s, "on") || !strcmp(s, "1")) {
        if (p_v) *p_v = 1;
        return 1;
    }
    if (!strcasecmp(s, "false") || !strcasecmp(s, "no") || !strcasecmp(s, "off") || !strcmp(s, "0")) {
        if (p_v) *p_v = 1;
        return 1;
    }
    return -1;
}

static struct ppxml_tag *
ppxml_parse_tag(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_tag *pp = (struct ppxml_tag *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_VALUE) {
            pp->value = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->value) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_VALUE);
    return pp;
}

static struct ppxml_tags *
ppxml_parse_tags(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_tags *pp = (struct ppxml_tags *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_TAG) {
            struct ppxml_tag *tt = ppxml_parse_tag(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_property *
ppxml_parse_property(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_property *pp = (struct ppxml_property *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_NAME) {
            pp->name = a->text;
        } else if (a->tag == PPXML_A_VALUE) {
            pp->value = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->name) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_NAME);
    if (!pp->value) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_VALUE);
    return pp;
}

static struct ppxml_properties *
ppxml_parse_properties(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_properties *pp = (struct ppxml_properties *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_PROPERTY) {
            struct ppxml_property *tt = ppxml_parse_property(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_asset *
ppxml_parse_asset(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_asset *pp = (struct ppxml_asset *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_NAME) {
            pp->name = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->name) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_NAME);
    return pp;
}

static struct ppxml_stage *
ppxml_parse_stage(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_stage *pp = (struct ppxml_stage *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_NAME) {
            pp->name = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->name) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_NAME);
    return pp;
}

static struct ppxml_stages *
ppxml_parse_stages(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_stages *pp = (struct ppxml_stages *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_STAGE) {
            struct ppxml_stage *tt = ppxml_parse_stage(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_source *
ppxml_parse_source(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_source *pp = (struct ppxml_source *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_PATH) {
            pp->path = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            pp->type = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->path) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_PATH);
    return pp;
}

static struct ppxml_binary *
ppxml_parse_binary(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_binary *pp = (struct ppxml_binary *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_PATH) {
            pp->path = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            pp->type = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->path) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_PATH);
    if (!pp->type) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_TYPE);
    return pp;
}

static struct ppxml_extra_tag *
ppxml_parse_extra_tag(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_extra_tag *pp = (struct ppxml_extra_tag *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_GROUP) {
            pp->group = a->text;
        } else if (a->tag == PPXML_A_TESTSET) {
            pp->testset = a->text;
        } else if (a->tag == PPXML_A_TAG) {
            int t = ppxml_solution_tag_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->tag = t;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    return pp;
}

static struct ppxml_extra_tags *
ppxml_parse_extra_tags(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_extra_tags *pp = (struct ppxml_extra_tags *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_EXTRA_TAG) {
            struct ppxml_extra_tag *tt = ppxml_parse_extra_tag(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_solution *
ppxml_parse_solution(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_solution *pp = (struct ppxml_solution *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_TAG) {
            int t = ppxml_solution_tag_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->tag = t;
        } else if (a->tag == PPXML_A_NOTE) {
            pp->note = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else if (q->tag == PPXML_EXTRA_TAGS) {
            if (pp->extra_tags) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_extra_tags *t = ppxml_parse_extra_tags(cntx, q);
            if (!t) return NULL;
            pp->extra_tags = t;
        } else {
            return cntx->ops->err_elem_invalid(cntx, q);
        }
    }
    if (!pp->tag) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_TAG);
    if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);
    return pp;
}

static struct ppxml_solutions *
ppxml_parse_solutions(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_solutions *pp = (struct ppxml_solutions *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOLUTION) {
            struct ppxml_solution *tt = ppxml_parse_solution(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_generator *
ppxml_parse_generator(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_generator *pp = (struct ppxml_generator *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else {
            return cntx->ops->err_elem_invalid(cntx, q);
        }
    }
    if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);
    return pp;
}

static struct ppxml_generators *
ppxml_parse_generators(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_generators *pp = (struct ppxml_generators *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_GENERATOR) {
            struct ppxml_generator *tt = ppxml_parse_generator(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_test *
ppxml_parse_test(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_test *pp = (struct ppxml_test *) p;
    pp->points = -1;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_GROUP) {
            pp->group = a->text;
        } else if (a->tag == PPXML_A_METHOD) {
            int t = ppxml_method_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->method = t;
        } else if (a->tag == PPXML_A_POINTS) {
            char *e = NULL;
            errno = 0;
            double v = strtod(a->text, &e);
            if (errno || *e || e == a->text || isnan(v) || isinf(v) || v < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->points = v;
        } else if (a->tag == PPXML_A_SAMPLE) {
            int v = -1;
            if (ppxml_parse_bool(a->text, &v) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->sample = v;
        } else if (a->tag == PPXML_A_CMD) {
            pp->cmd = a->text;
        } else if (a->tag == PPXML_A_DESCRIPTION) {
            pp->description = a->text;
        } else if (a->tag == PPXML_A_FROM_FILE) {
            pp->from_file = a->text;
        } else if (a->tag == PPXML_A_VERDICT) {
            int t = ppxml_verdict_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->verdict = t;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }

    return pp;
}

static struct ppxml_tests *
ppxml_parse_tests(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_tests *pp = (struct ppxml_tests *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_TEST) {
            struct ppxml_test *tt = ppxml_parse_test(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_dependency *
ppxml_parse_dependency(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_dependency *pp = (struct ppxml_dependency *) p;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_GROUP) {
            pp->group = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->group) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_GROUP);

    return pp;
}

static struct ppxml_dependencies *
ppxml_parse_dependencies(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_dependencies *pp = (struct ppxml_dependencies *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_DEPENDENCY) {
            struct ppxml_dependency *tt = ppxml_parse_dependency(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_group *
ppxml_parse_group(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_group *pp = (struct ppxml_group *) p;
    pp->points = -1;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_NAME) {
            pp->name = a->text;
        } else if (a->tag == PPXML_A_FEEDBACK_POLICY) {
            int t = ppxml_feedback_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->feedback_policy = t;
        } else if (a->tag == PPXML_A_POINTS_POLICY) {
            int t = ppxml_points_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->points_policy = t;
        } else if (a->tag == PPXML_A_POINTS) {
            char *e = NULL;
            errno = 0;
            double v = strtod(a->text, &e);
            if (errno || *e || e == a->text || isnan(v) || isinf(v) || v < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->points = v;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_DEPENDENCIES) {
            if (pp->dependencies) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_dependencies *t = ppxml_parse_dependencies(cntx, q);
            if (!t) return NULL;
            pp->dependencies = t;
        } else {
            return cntx->ops->err_elem_invalid(cntx, q);
        }
    }
    if (!pp->name) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_NAME);
    if (!pp->points_policy) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_POINTS_POLICY);

    return pp;
}

static struct ppxml_groups *
ppxml_parse_groups(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_groups *pp = (struct ppxml_groups *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_GROUP) {
            struct ppxml_group *tt = ppxml_parse_group(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_path_pattern *
ppxml_parse_path_pattern(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_path_pattern *pp = (struct ppxml_path_pattern *) p;
    pp->normalization = -1;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_FILE_TYPE) {
            int t = ppxml_file_type_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->file_type = t;
        } else if (a->tag == PPXML_A_CHARSET) {
            pp->charset = a->text;
        } else if (a->tag == PPXML_A_NORMALIZATION) {
            int v = -1;
            if ((v = test_normalization_parse(a->text)) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->normalization = v;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (p->first_down) {
        return cntx->ops->err_elem_invalid(cntx, p->first_down);
    }
    pp->pattern = p->text;
    if (pp->normalization < 0) pp->normalization = TEST_NORM_DEFAULT;
    return pp;
}

static struct ppxml_testset *
ppxml_parse_testset(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_testset *pp = (struct ppxml_testset *) p;
    pp->normalization = -1;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_NAME) {
            pp->name = a->text;
        } else if (a->tag == PPXML_A_GENERATE_ANSWER) {
            int v = -1;
            if (ppxml_parse_bool(a->text, &v) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->generate_answer = v;
        } else if (a->tag == PPXML_A_AUTO_COUNT) {
            int v = -1;
            if (ppxml_parse_bool(a->text, &v) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->auto_count = v;
        } else if (a->tag == PPXML_A_NORMALIZATION) {
            int v = -1;
            if ((v = test_normalization_parse(a->text)) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->normalization = v;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (pp->normalization < 0) pp->normalization = TEST_NORM_DEFAULT;
    pp->time_limit = -1;
    pp->memory_limit = -1;
    pp->test_count = -1;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_TIME_LIMIT) {
            if (pp->time_limit >= 0) return cntx->ops->err_elem_redefined(cntx, q);
            if (q->first) return cntx->ops->err_attr_not_allowed(cntx, q, q->first);
            if (q->first_down) return cntx->ops->err_nested_elems(cntx, q);
            char *e = NULL;
            errno = 0;
            long v = strtol(q->text, &e, 10);
            if (errno || *e || q->text == e || (int) v != v || v <= 0) {
                return cntx->ops->err_elem_invalid(cntx, q);
            }
            pp->time_limit = v;
        } else if (q->tag == PPXML_MEMORY_LIMIT) {
            if (pp->memory_limit >= 0) return cntx->ops->err_elem_redefined(cntx, q);
            if (q->first) return cntx->ops->err_attr_not_allowed(cntx, q, q->first);
            if (q->first_down) return cntx->ops->err_nested_elems(cntx, q);
            char *e = NULL;
            errno = 0;
            long long v = strtoll(q->text, &e, 10);
            if (errno || *e || q->text == e || v < 0) {
                return cntx->ops->err_elem_invalid(cntx, q);
            }
            pp->memory_limit = v;
        } else if (q->tag == PPXML_TEST_COUNT) {
            if (pp->test_count >= 0) return cntx->ops->err_elem_redefined(cntx, q);
            if (q->first) return cntx->ops->err_attr_not_allowed(cntx, q, q->first);
            if (q->first_down) return cntx->ops->err_nested_elems(cntx, q);
            char *e = NULL;
            errno = 0;
            long v = strtol(q->text, &e, 10);
            if (errno || *e || q->text == e || (int) v != v || v < 0) {
                return cntx->ops->err_elem_invalid(cntx, q);
            }
            pp->test_count = v;
        } else if (q->tag == PPXML_INPUT_PATH_PATTERN) {
            if (pp->input) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_path_pattern *t = ppxml_parse_path_pattern(cntx, q);
            if (!t) return NULL;
            pp->input = t;
        } else if (q->tag == PPXML_OUTPUT_PATH_PATTERN) {
            if (pp->output) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_path_pattern *t = ppxml_parse_path_pattern(cntx, q);
            if (!t) return NULL;
            pp->output = t;
        } else if (q->tag == PPXML_ANSWER_PATH_PATTERN) {
            if (pp->answer) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_path_pattern *t = ppxml_parse_path_pattern(cntx, q);
            if (!t) return NULL;
            pp->answer = t;
        } else if (q->tag == PPXML_TESTS) {
            if (pp->tests) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_tests *t = ppxml_parse_tests(cntx, q);
            if (!t) return NULL;
            pp->tests = t;
        } else if (q->tag == PPXML_GROUPS) {
            if (pp->groups) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_groups *t = ppxml_parse_groups(cntx, q);
            if (!t) return NULL;
            pp->groups = t;
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    // FIXME: check match of tests count and test-count

    return pp;
}

static struct ppxml_validator *
ppxml_parse_validator(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_validator *pp = (struct ppxml_validator *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else if (q->tag == PPXML_TESTSET) {
            if (pp->testset) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_testset *t = ppxml_parse_testset(cntx, q);
            if (!t) return NULL;
            pp->testset = t;
        } else {
            return cntx->ops->err_elem_invalid(cntx, q);
        }
    }
    if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);
    return pp;
}

static struct ppxml_validators *
ppxml_parse_validators(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_validators *pp = (struct ppxml_validators *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_VALIDATOR) {
            struct ppxml_validator *tt = ppxml_parse_validator(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_interactor *
ppxml_parse_interactor(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_interactor *pp = (struct ppxml_interactor *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else {
            return cntx->ops->err_elem_invalid(cntx, q);
        }
    }
    if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);
    return pp;
}

static struct ppxml_scorer *
ppxml_parse_scorer(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_scorer *pp = (struct ppxml_scorer *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else {
            return cntx->ops->err_elem_invalid(cntx, q);
        }
    }
    if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);
    return pp;
}

static struct ppxml_copy *
ppxml_parse_copy(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_copy *pp = (struct ppxml_copy *) p;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_PATH) {
            pp->path = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            pp->type = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->path) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_PATH);

    return pp;
}

static struct ppxml_checker *
ppxml_parse_checker(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_checker *pp = (struct ppxml_checker *) p;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_NAME) {
            pp->name = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            pp->type = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else if (q->tag == PPXML_COPY) {
            if (pp->copy) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_copy *t = ppxml_parse_copy(cntx, q);
            if (!t) return NULL;
            pp->copy = t;
        } else if (q->tag == PPXML_TESTSET) {
            if (pp->testset) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_testset *t = ppxml_parse_testset(cntx, q);
            if (!t) return NULL;
            pp->testset = t;
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }
    if (!pp->type) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_TYPE);
    //if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);
    //if (!pp->copy) return cntx->ops->err_elem_undefined(cntx, p, PPXML_COPY);

    return pp;
}

static struct ppxml_assets *
ppxml_parse_assets(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_assets *pp = (struct ppxml_assets *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_CHECKER) {
            if (pp->checker) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_checker *t = ppxml_parse_checker(cntx, q);
            if (!t) return NULL;
            pp->checker = t;
        } else if (q->tag == PPXML_INTERACTOR) {
            if (pp->interactor) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_interactor *t = ppxml_parse_interactor(cntx, q);
            if (!t) return NULL;
            pp->interactor = t;
        } else if (q->tag == PPXML_VALIDATORS) {
            if (pp->validators) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_validators *t = ppxml_parse_validators(cntx, q);
            if (!t) return NULL;
            pp->validators = t;
        } else if (q->tag == PPXML_SCORER) {
            if (pp->validators) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_scorer *t = ppxml_parse_scorer(cntx, q);
            if (!t) return NULL;
            pp->scorer = t;
        } else if (q->tag == PPXML_SOLUTIONS) {
            if (pp->solutions) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_solutions *t = ppxml_parse_solutions(cntx, q);
            if (!t) return NULL;
            pp->solutions = t;
        } else if (q->tag == PPXML_GENERATORS) {
            if (pp->generators) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_generators *t = ppxml_parse_generators(cntx, q);
            if (!t) return NULL;
            pp->generators = t;
        } else if (q->tag == PPXML_ASSET) {
            struct ppxml_asset *t = ppxml_parse_asset(cntx, q);
            if (!t) return NULL;
            xml_tree_vector_push((struct xml_tree_vector *) &(pp->assets), &((t)->b));
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_executable *
ppxml_parse_executable(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_executable *pp = (struct ppxml_executable *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_SOURCE) {
            if (pp->source) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_source *t = ppxml_parse_source(cntx, q);
            if (!t) return NULL;
            pp->source = t;
        } else if (q->tag == PPXML_BINARY) {
            if (pp->binary) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_binary *t = ppxml_parse_binary(cntx, q);
            if (!t) return NULL;
            pp->binary = t;
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }
    if (!pp->source) return cntx->ops->err_elem_undefined(cntx, p, PPXML_SOURCE);

    return pp;
}

static struct ppxml_executables *
ppxml_parse_executables(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_executables *pp = (struct ppxml_executables *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_EXECUTABLE) {
            struct ppxml_executable *tt = ppxml_parse_executable(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_file *
ppxml_parse_file(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_file *pp = (struct ppxml_file *) p;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_PATH) {
            pp->path = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            pp->type = a->text;
        } else if (a->tag == PPXML_A_FOR_TYPES) {
            pp->for_types = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_ASSETS) {
            if (pp->assets) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_assets *tt = ppxml_parse_assets(cntx, q);
            if (!tt) return NULL;
            pp->assets = tt;
        } else if (q->tag == PPXML_STAGES) {
            if (pp->stages) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_stages *tt = ppxml_parse_stages(cntx, q);
            if (!tt) return NULL;
            pp->stages = tt;
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }
    if (!pp->path) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_PATH);

    return pp;
}

static struct ppxml_resources *
ppxml_parse_resources(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_resources *pp = (struct ppxml_resources *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_FILE) {
            struct ppxml_file *tt = ppxml_parse_file(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_attachments *
ppxml_parse_attachments(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_attachments *pp = (struct ppxml_attachments *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_FILE) {
            struct ppxml_file *tt = ppxml_parse_file(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_files *
ppxml_parse_files(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_files *pp = (struct ppxml_files *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_RESOURCES) {
            if (pp->resources) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_resources *t = ppxml_parse_resources(cntx, q);
            if (!t) return NULL;
            pp->resources = t;
        } else if (q->tag == PPXML_ATTACHMENTS) {
            if (pp->attachments) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_attachments *t = ppxml_parse_attachments(cntx, q);
            if (!t) return NULL;
            pp->attachments = t;
        } else if (q->tag == PPXML_EXECUTABLES) {
            if (pp->executables) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_executables *t = ppxml_parse_executables(cntx, q);
            if (!t) return NULL;
            pp->executables = t;
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_judging *
ppxml_parse_judging(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    struct ppxml_judging *pp = (struct ppxml_judging *) p;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_CPU_NAME) {
            pp->cpu_name = a->text;
        } else if (a->tag == PPXML_A_CPU_SPEED) {
            errno = 0;
            char *e = NULL;
            double v = strtod(a->text, &e);
            if (errno || *e || a->text == e || isnan(v) || isinf(v) || v <= 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->cpu_speed = v;
        } else if (a->tag == PPXML_A_INPUT_FILE) {
            pp->input_file = a->text;
        } else if (a->tag == PPXML_A_OUTPUT_FILE) {
            pp->output_file = a->text;
        } else if (a->tag == PPXML_A_RUN_COUNT) {
            errno = 0;
            char *e = NULL;
            long v = strtol(a->text, &e, 10);
            if (errno || *e || a->text == e || (int) v != v || v < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->run_count = v;
        } else if (a->tag == PPXML_A_EXTRA_CONFIG) {
            int v = -1;
            if (ppxml_parse_bool(a->text, &v) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->extra_config = v;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_TESTSET) {
            struct ppxml_testset *t = ppxml_parse_testset(cntx, q);
            if (!t) return NULL;
            xml_tree_vector_push((struct xml_tree_vector *) &(pp->testsets), &((t)->b));
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }
    return pp;
}

static struct ppxml_statement *
ppxml_parse_statement(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_statement *pp = (struct ppxml_statement *) p;

    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_CHARSET) {
            int t = ppxml_charset_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->charset = t;
        } else if (a->tag == PPXML_A_LANGUAGE) {
            int t = ppxml_lang_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->language = t;
        } else if (a->tag == PPXML_A_MATHJAX) {
            int v = -1;
            if (ppxml_parse_bool(a->text, &v) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->mathjax = v;
        } else if (a->tag == PPXML_A_PATH) {
            pp->path = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            int t = ppxml_type_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->type = t;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->path) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_PATH);

    return pp;
}

static struct ppxml_statements *
ppxml_parse_statements(struct ppxml_parse_context *cntx, struct xml_tree *p, int ltag)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_statements *pp = (struct ppxml_statements *) p;
    int etag = 0;
    if (ltag == PPXML_STATEMENTS) {
        etag = PPXML_STATEMENT;
    } else if (ltag == PPXML_TUTORIALS) {
        etag = PPXML_TUTORIAL;
    } else {
        abort();
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == etag) {
            struct ppxml_statement *tt = ppxml_parse_statement(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_name *
ppxml_parse_name(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_name *pp = (struct ppxml_name *) p;

    for (struct xml_attr *a = p->first; a; a = a->next) {
         if (a->tag == PPXML_A_LANGUAGE) {
            int t = ppxml_lang_parse(a->text);
            if (!t) return cntx->ops->err_attr_invalid(cntx, a);
            pp->language = t;
        } else if (a->tag == PPXML_A_VALUE) {
            pp->value = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->value) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_VALUE);

    return pp;
}

static struct ppxml_names *
ppxml_parse_names(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_names *pp = (struct ppxml_names *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_NAME) {
            struct ppxml_name *tt = ppxml_parse_name(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_document *
ppxml_parse_document(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first_down) return cntx->ops->err_nested_elems(cntx, p);
    struct ppxml_document *pp = (struct ppxml_document *) p;
    for (struct xml_attr *a = pp->b.first; a; a = a->next) {
        if (a->tag == PPXML_A_PATH) {
            pp->path = a->text;
        } else if (a->tag == PPXML_A_TYPE) {
            pp->type = a->text;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    if (!pp->path) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_PATH);
    if (!pp->type) return cntx->ops->err_attr_undefined(cntx, p, PPXML_A_TYPE);
    return pp;
}

static struct ppxml_documents *
ppxml_parse_documents(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->first) return cntx->ops->err_attr_not_allowed(cntx, p, p->first);
    struct ppxml_documents *pp = (struct ppxml_documents *) p;
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_DOCUMENT) {
            struct ppxml_document *tt = ppxml_parse_document(cntx, q);
            if (!tt) return NULL;
            XML_TREE_VECTOR_PUSH(pp, tt);
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static struct ppxml_problem *
ppxml_parse_problem(struct ppxml_parse_context *cntx, struct xml_tree *p)
{
    if (p->tag != PPXML_PROBLEM) {
        return cntx->ops->err_elem_invalid(cntx, p);
    }
    struct ppxml_problem *pp = (struct ppxml_problem *) p;
    for (struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == PPXML_A_REVISION) {
            errno = 0;
            char *e = NULL;
            long v = strtol(a->text, &e, 10);
            if (errno || *e || a->text == e || (int) v != v || v < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->revision = v;
        } else if (a->tag == PPXML_A_SHORT_NAME) {
            pp->short_name = a->text;
        } else if (a->tag == PPXML_A_URL) {
            pp->url = a->text;
        } else if (a->tag == PPXML_A_UUID_FROM_HISTORY) {
            int v = -1;
            if (ppxml_parse_bool(a->text, &v) < 0) {
                return cntx->ops->err_attr_invalid(cntx, a);
            }
            pp->uuid_from_history = v;
        } else {
            return cntx->ops->err_attr_not_allowed(cntx, p, a);
        }
    }
    for (struct xml_tree *q = p->first_down; q; q = q->right) {
        if (q->tag == PPXML_NAMES) {
            if (pp->names) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_names *t = ppxml_parse_names(cntx, q);
            if (!t) return NULL;
            pp->names = t;
        } else if (q->tag == PPXML_STATEMENTS) {
            if (pp->statements) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_statements *t = ppxml_parse_statements(cntx, q, PPXML_STATEMENTS);
            if (!t) return NULL;
            pp->statements = t;
        } else if (q->tag == PPXML_TUTORIALS) {
            if (pp->tutorials) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_statements *t = ppxml_parse_statements(cntx, q, PPXML_TUTORIALS);
            if (!t) return NULL;
            pp->tutorials = t;
        } else if (q->tag == PPXML_JUDGING) {
            if (pp->judging) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_judging *t = ppxml_parse_judging(cntx, q);
            if (!t) return NULL;
            pp->judging = t;
        } else if (q->tag == PPXML_FILES) {
            if (pp->files) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_files *t = ppxml_parse_files(cntx, q);
            if (!t) return NULL;
            pp->files = t;
        } else if (q->tag == PPXML_ASSETS) {
            if (pp->assets) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_assets *t = ppxml_parse_assets(cntx, q);
            if (!t) return NULL;
            pp->assets = t;
        } else if (q->tag == PPXML_PROPERTIES) {
            if (pp->properties) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_properties *t = ppxml_parse_properties(cntx, q);
            if (!t) return NULL;
            pp->properties = t;
        } else if (q->tag == PPXML_STRESSES) {
            // nothing
        } else if (q->tag == PPXML_MATERIALS) {
            // nothing
        } else if (q->tag == PPXML_TAGS) {
            if (pp->tags) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_tags *t = ppxml_parse_tags(cntx, q);
            if (!t) return NULL;
            pp->tags = t;
        } else if (q->tag == PPXML_DOCUMENTS) {
            if (pp->tags) return cntx->ops->err_elem_redefined(cntx, q);
            struct ppxml_documents *t = ppxml_parse_documents(cntx, q);
            if (!t) return NULL;
            pp->documents = t;
        } else {
            return cntx->ops->err_elem_not_allowed(cntx, q);
        }
    }

    return pp;
}

static void *free_context_func(struct ppxml_parse_context *cntx)
{
    return NULL;
}

static void* err_func(struct ppxml_parse_context *cntx, int line, int column, const char *format, ...)
{
    ++cntx->error_count;
    if (cntx->quiet_flag) return NULL;

    va_list args;
    char buf1[4096];
    char buf2[4096];
    va_start(args, format);
    vsnprintf(buf1, sizeof(buf1), format, args);
    va_end(args);
    if (cntx->path) {
        if (line > 0) {
            snprintf(buf2, sizeof(buf2), "%s:%d:%d:%s\n", cntx->path, line, column, buf1);
        } else {
            snprintf(buf2, sizeof(buf2), "%s:%s\n", cntx->path, buf1);
        }
    } else if (line > 0) {
        snprintf(buf2, sizeof(buf2), "%d:%d:%s\n", line, column, buf1);
    } else {
        snprintf(buf2, sizeof(buf2), "%s\n", buf1);
    }

    if (cntx->log_f) {
        fputs(buf2, cntx->log_f);
    }
    if (cntx->log_flag) {
        err("%s", buf2);
    }
    if (cntx->stderr_flag) {
        fputs(buf2, stderr);
    }
    return NULL;
}

static void*
err_elem_not_allowed_func(struct ppxml_parse_context *cntx, const struct xml_tree *p)
{
    return cntx->ops->err(cntx, p->line, p->column, "element <%s> is not allowed here", cntx->spec->elem_map[p->tag]);
}

static void*
err_nested_elems_func(struct ppxml_parse_context *cntx, const struct xml_tree *p)
{
    return cntx->ops->err(cntx, p->line, p->column, "nested elements are not allowed in <%s>", cntx->spec->elem_map[p->tag]);
}

static void*
err_attr_not_allowed_func(struct ppxml_parse_context *cntx, const struct xml_tree *p, const struct xml_attr *a)
{
    return cntx->ops->err(cntx, a->line, a->column, "attribute \"%s\" is not allowed in <%s>",
        cntx->spec->attr_map[a->tag], cntx->spec->elem_map[p->tag]);
}

static void*
err_attr_undefined_func(struct ppxml_parse_context *cntx, const struct xml_tree *p, int a)
{
    return cntx->ops->err(cntx, p->line, p->column, "attribute \"%s\" is missing in <%s>",
        cntx->spec->attr_map[a], cntx->spec->elem_map[p->tag]);
}

static void*
err_attr_invalid_func(struct ppxml_parse_context *cntx, const struct xml_attr *a)
{
    return cntx->ops->err(cntx, a->line, a->column, "attribute \"%s\" is invalid",
        cntx->spec->attr_map[a->tag]);
}

static void*
err_elem_redefined_func(struct ppxml_parse_context *cntx, const struct xml_tree *p)
{
    return cntx->ops->err(cntx, p->line, p->column, "element <%s> is redefined", cntx->spec->elem_map[p->tag]);
}

static void*
err_elem_invalid_func(struct ppxml_parse_context *cntx, const struct xml_tree *p)
{
    return cntx->ops->err(cntx, p->line, p->column, "element <%s> is invalid", cntx->spec->elem_map[p->tag]);
}

static void*
err_elem_undefined_func(struct ppxml_parse_context *cntx, const struct xml_tree *p, int t)
{
    return cntx->ops->err(cntx, p->line, p->column, "element <%s> is undefined", cntx->spec->elem_map[t]);
}

static const struct ppxml_parse_ops ops =
{
    .free_context = free_context_func,
    .err = err_func,
    .err_elem_not_allowed = err_elem_not_allowed_func,
    .err_nested_elems = err_nested_elems_func,
    .err_attr_not_allowed = err_attr_not_allowed_func,
    .err_attr_undefined = err_attr_undefined_func,
    .err_attr_invalid = err_attr_invalid_func,
    .err_elem_redefined = err_elem_redefined_func,
    .err_elem_invalid = err_elem_invalid_func,
    .err_elem_undefined = err_elem_undefined_func,
};

struct ppxml_problem *
ppxml_parse_str(FILE *log_f, const char *path, const char *str)
{
    struct xml_tree *tree = 0;

    xml_err_path = path;
    xml_err_spec = &polygon_xml_parse_spec;
    tree = xml_build_tree_str(log_f, str, &polygon_xml_parse_spec);
    if (!tree) {
        return NULL;
    }
    struct ppxml_parse_context cntx =
    {
        .ops = &ops,
        .spec = &polygon_xml_parse_spec,
        .log_f = log_f,
        .path = path,
    };
    struct ppxml_problem *prob = ppxml_parse_problem(&cntx, tree);
    if (!prob) {
        xml_tree_free(tree, &polygon_xml_parse_spec);
        return NULL;
    }
    return prob;
}

struct ppxml_problem *
ppxml_free(struct ppxml_problem *prob)
{
    if (prob) {
        xml_tree_free(&prob->b, &polygon_xml_parse_spec);
    }
    return NULL;
}
