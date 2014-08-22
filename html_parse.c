/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/html_parse.h"
#include "ejudge/list_ops.h"
#include "ejudge/misctext.h"

#include "ejudge/xalloc.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static int
is_xml_element_name_start_char(int c)
{
    return isalpha(c) || c == ':' || c == '_';
}
static int
is_xml_element_name_char(int c)
{
    return isalnum(c) || c == ':' || c == '_' || c == '-' || c == '.';
}

struct HtmlAttribute *
html_attribute_create(
        const unsigned char *ptr,
        int len,
        unsigned char *value)
{
    struct HtmlAttribute *attr = NULL;
    XCALLOC(attr, 1);
    if (len > 0) {
        attr->name = xmemdup(ptr, len);
    } else {
        attr->name = xstrdup(ptr);
    }
    // note, the pre-allocated memory for value is used
    attr->value = value;
    for (unsigned char *s = attr->name; *s; ++s) {
        *s = tolower(*s);
    }
    return attr;
}

struct HtmlAttribute *
html_attribute_free(struct HtmlAttribute *attr)
{
    if (!attr) return NULL;
    xfree(attr->name);
    xfree(attr->value);
    xfree(attr);
    return NULL;
}

struct HtmlElement *
html_element_create(const unsigned char *ptr, int len)
{
    struct HtmlElement *elem = NULL;
    XCALLOC(elem, 1);
    if (len <= 0) {
        elem->name = xstrdup(ptr);
    } else {
        elem->name = xmemdup(ptr, len);
    }
    for (unsigned char *s = elem->name; *s; ++s) {
        *s = tolower(*s);
    }
    return elem;
}

struct HtmlElement *
html_element_free(struct HtmlElement *elem)
{
    if (!elem) return NULL;
    xfree(elem->name);
    struct HtmlAttribute *p, *q;
    for (p = elem->first_attr; p; p = q) {
        q = p->next;
        html_attribute_free(p);
    }
    for (HtmlElement *child = elem->first_child; child; ) {
        HtmlElement *tmp = child->next_sibling;
        html_element_free(child);
        child = tmp;
    }
    xfree(elem);
    return NULL;
}

struct EntityTableEntry
{
    const unsigned char *name;
    int value;
};
static struct EntityTableEntry html_entities[] =
{
    { "amp", '&' },
    { "quot", '"' },
    { "apos", '\'' },
    { "lt", '<' },
    { "gt", '>' },

    { NULL, 0 },
};

static int
find_html_entity(const unsigned char *beg, const unsigned char *end)
{
    int len = (int) (end - beg);
    unsigned char buf[128], *s = buf;
    const unsigned char *p = beg;

    if (len <= 0 || len > 127) return -1;
    while (p != end) *s++ = tolower(*p++);
    *s = 0;
    for (int i = 0; html_entities[i].name; ++i) {
        if (!strcmp(html_entities[i].name, buf)) {
            return html_entities[i].value;
        }
    }
    return -1;
}

static int
convert_html_entity(const unsigned char *beg, const unsigned char *end, int base)
{
    int len = (int) (end - beg);
    unsigned char buf[32];
    if (len <= 0 || len > 31) return -1;
    memcpy(buf, beg, len);
    buf[len] = 0;
    errno = 0;
    int value = strtol(buf, NULL, base);
    if (errno || value < 0 || value >= 0x10000) return -1;
    return value;
}

static void
parse_html_decode(
        unsigned char *buf,
        const unsigned char *start,
        const unsigned char *end)
{
    const unsigned char *p = start;
    unsigned char *out = buf;
    while (*p && p != end) {
        if (*p != '&') {
            *out++ = *p++;
            continue;
        }
        ++p;
        if (!*p || p == end) {
            *out++ = '&';
            continue;
        }
        if (*p == '#' && p[1] == 'x') {
            const unsigned char *q = p;
            p += 2;
            while (isxdigit(*p)) ++p;
            int e = convert_html_entity(q + 2, p, 16);
            if (e >= 0) {
                out = ucs4_to_utf8_char(out, e);
                if (*p == ';') ++p;
            } else {
                *out++ = '&';
                p = q;
            }
        } else if (*p == '#') {
            const unsigned char *q = p;
            ++p;
            while (isdigit(*p)) ++p;
            int e = convert_html_entity(q + 1, p, 10);
            if (e >= 0) {
                out = ucs4_to_utf8_char(out, e);
                if (*p == ';') ++p;
            } else {
                *out++ = '&';
                p = q;
            }
        } else if (isalpha(*p)) {
            // entity expansion is not performed...
            const unsigned char *q = p;
            while (isalnum(*p)) ++p;
            int e = find_html_entity(q, p);
            if (e >= 0) {
                out = ucs4_to_utf8_char(out, e);
                if (*p == ';') ++p;
            } else {
                *out++ = '&';
                p = q;
            }
        } else {
            *out++ = '&';
            continue;
        }
    }
    *out = 0;
}

struct HtmlElement *
html_element_parse_start(
        const unsigned char *text,
        int start_pos,
        int *p_end_pos)
{
    const unsigned char *p = text + start_pos, *q, *r;
    const unsigned char *value_start, *value_end;
    struct HtmlElement *elem = NULL;
    struct HtmlAttribute *attr = NULL;
    unsigned char *value_buf = NULL;

    while (isspace(*p)) ++p;
    if (!*p) goto fail;
    if (*p != '<') goto fail;
    ++p;
    while (isspace(*p)) ++p;
    if (!is_xml_element_name_start_char(*p)) goto fail;
    q = p;
    while (is_xml_element_name_char(*p)) ++p;
    if (!isspace(*p) && *p != '>') goto fail;
    elem = html_element_create(q, (int) (p - q));
    while (1) {
        while (isspace(*p)) ++p;
        if (*p == '>') {
            ++p;
            break;
        }
        if (*p == '/' && p[1] == '>') {
            elem->no_body = 1;
            p += 2;
            break;
        }
        if (!is_xml_element_name_start_char(*p)) goto fail;
        q = p;
        while (is_xml_element_name_char(*p)) ++p;
        r = p;
        while (isspace(*p)) ++p;
        if (*p != '=') {
            // create an empty value attribute
            // FIXME: check attribute uniqueness
            attr = html_attribute_create(q, (int) (r - q), NULL);
            LINK_LAST(attr, elem->first_attr, elem->last_attr, prev, next);
            attr = NULL;
            continue;
        }
        ++p;
        while (isspace(*p)) ++p;
        if (*p == '\'') {
            ++p;
            value_start = p;
            while (*p && *p != '\'') ++p;
            if (!*p) goto fail;
            value_end = p;
            ++p;
        } else if (*p == '\"') {
            ++p;
            value_start = p;
            while (*p && *p != '\"') ++p;
            if (!*p) goto fail;
            value_end = p;
            ++p;
        } else if (is_xml_element_name_start_char(*p)) {
            value_start = p;
            while (*p && !isspace(*p)) ++p;
            if (!*p) goto fail;
            value_end = p;
        } else {
            // create an empty value attribute
            // FIXME: check attribute uniqueness
            attr = html_attribute_create(q, (int) (r - q), NULL);
            LINK_LAST(attr, elem->first_attr, elem->last_attr, prev, next);
            attr = NULL;
            continue;
        }

        // value is in [value_start; value_end), not entity-decoded...
        value_buf = malloc(((int) (value_end - value_start) + 1) * sizeof(*value_buf));
        if (!value_buf) goto fail;
        parse_html_decode(value_buf, value_start, value_end);
        attr = html_attribute_create(q, (int) (r - q), value_buf);
        LINK_LAST(attr, elem->first_attr, elem->last_attr, prev, next);
        attr = NULL; value_buf = NULL;
    }
    if (p_end_pos) *p_end_pos = (int)(p - text);
    return elem;

fail:
    xfree(value_buf);
    html_element_free(elem);
    if (p_end_pos) *p_end_pos = (int)(p - text);
    return NULL;
}

struct HtmlElement *
html_element_parse_end(
        const unsigned char *text,
        int start_pos,
        int *p_end_pos)
{
    const unsigned char *p = text + start_pos, *q;
    struct HtmlElement *elem = NULL;

    while (isspace(*p)) ++p;
    if (!*p) goto fail;
    if (*p != '<') goto fail;
    ++p;
    while (isspace(*p)) ++p;
    if (*p != '/') goto fail;
    ++p;
    while (isspace(*p)) ++p;
    if (!is_xml_element_name_start_char(*p)) goto fail;
    q = p;
    while (is_xml_element_name_char(*p)) ++p;
    if (!isspace(*p) && *p != '>') goto fail;
    elem = html_element_create(q, (int) (p - q));
    while (isspace(*p)) ++p;
    if (*p != '>') goto fail;
    ++p;

    if (p_end_pos) *p_end_pos = (int)(p - text);
    return elem;

fail:
    html_element_free(elem);
    if (p_end_pos) *p_end_pos = (int)(p - text);
    return NULL;
}

struct HtmlAttribute *
html_element_find_attribute(
        const struct HtmlElement *elem,
        const unsigned char *name)
{
    if (!elem) return NULL;
    for (struct HtmlAttribute *p = elem->first_attr; p; p = p->next) {
        if (!strcmp(p->name, name))
            return p;
    }
    return NULL;
}

void
html_element_print(
        FILE *out,
        const struct HtmlElement *elem)
{
    if (!elem) return;
    fprintf(out, "<%s", elem->name);
    for (struct HtmlAttribute *p = elem->first_attr; p; p = p->next) {
        // FIXME: do escaping
        fprintf(out, " %s=\"%s\"", p->name, p->value);
    }
    if (elem->no_body) putc('/', out);
    putc('>', out);
}

HtmlAttribute *
html_attribute_clone(const HtmlAttribute *attr)
{
    HtmlAttribute *res = NULL;
    if (attr) {
        XCALLOC(res, 1);
        if (attr->name) res->name = xstrdup(attr->name);
        if (attr->value) res->value = xstrdup(attr->value);
    }
    return res;
}

HtmlElement *
html_element_clone(const HtmlElement *elem)
{
    if (!elem) return NULL;

    HtmlElement *res = NULL;
    XCALLOC(res, 1);
    if (elem->name) res->name = xstrdup(elem->name);
    res->no_body = elem->no_body;

    for (const HtmlAttribute *asrc = elem->first_attr; asrc; asrc = asrc->next) {
        HtmlAttribute *adst = html_attribute_clone(asrc);
        LINK_LAST(adst, res->first_attr, res->last_attr, prev, next);
    }
    return res;
}

void
html_element_add_child(HtmlElement *elem, HtmlElement *child)
{
    if (!elem || !child) return;
    LINK_LAST(child, elem->first_child, elem->last_child, prev_sibling, next_sibling);
}

const unsigned char *
html_element_find_attribute_value(
        const struct HtmlElement *elem,
        const unsigned char *name)
{
    HtmlAttribute *attr = html_element_find_attribute(elem, name);
    if (!attr) return NULL;
    return attr->value;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
