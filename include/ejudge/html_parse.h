/* -*- c -*- */
/* $Id$ */
#ifndef __HTML_PARSE_H__
#define __HTML_PARSE_H__

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

#include <stdio.h>

typedef struct HtmlAttribute
{
    struct HtmlAttribute *prev;
    struct HtmlAttribute *next;
    unsigned char *name;
    unsigned char *value;
} HtmlAttribute;

typedef struct HtmlElement
{
    struct HtmlElement *prev_sibling;
    struct HtmlElement *next_sibling;
    unsigned char *name;
    struct HtmlAttribute *first_attr;
    struct HtmlAttribute *last_attr;
    struct HtmlElement *first_child;
    struct HtmlElement *last_child;
    int no_body; // 1, if <elem /> case
} HtmlElement;

struct HtmlElement *
html_element_parse_start(
        const unsigned char *text,
        int start_pos,
        int *p_end_pos);

struct HtmlElement *
html_element_parse_end(
        const unsigned char *text,
        int start_pos,
        int *p_end_pos);

struct HtmlElement *
html_element_free(struct HtmlElement *elem);

struct HtmlAttribute *
html_element_find_attribute(
        const struct HtmlElement *elem,
        const unsigned char *name);
const unsigned char *
html_element_find_attribute_value(
        const struct HtmlElement *elem,
        const unsigned char *name);

void
html_element_print(
        FILE *out_f,
        const struct HtmlElement *elem);

struct HtmlAttribute *
html_attribute_clone(const struct HtmlAttribute *attr);
struct HtmlElement *
html_element_clone(const struct HtmlElement *elem);
void
html_element_add_child(HtmlElement *elem, HtmlElement *child);

#endif /* __HTML_PARSE_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
