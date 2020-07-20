/* -*- mode: c -*- */

/* Copyright (C) 2008-2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "meta_gen.h"
#include "c_errors.h"

#include "ejudge/osdeps.h"
#include "ejudge/logger.h"

#include <string.h>
#include <ctype.h>

static int h_header_generated = 0;
static int c_header_generated = 0;

static int
is_meta_hidden(tree_t node)
{
  if (!node) return 0;
  if (node->kind == NODE_STRUCTDECLR) node = node->node.refs[3];
  if (!node) return 0;
  if (node->kind != NODE_DECLR) return 0;
  node = node->node.refs[5];
  if (!node) return 0;
  if (node->kind != NODE_ATTRIBUTE) return 0;
  for (node = node->node.refs[6]; node; node = node->node.refs[0]) {
    if (node->kind != NODE_ATTRITEM) return 0;
    if (node->node.refs[5]) return 0;
    if (!strcmp(ident_get(node->node.refs[3]->id.id), "meta_hidden"))
      return 1;
  }
  return 0;
}

static int
is_meta_private(tree_t node)
{
  if (!node) return 0;
  if (node->kind == NODE_STRUCTDECLR) node = node->node.refs[3];
  if (!node) return 0;
  if (node->kind != NODE_DECLR) return 0;
  node = node->node.refs[5];
  if (!node) return 0;
  if (node->kind != NODE_ATTRIBUTE) return 0;
  for (node = node->node.refs[6]; node; node = node->node.refs[0]) {
    if (node->kind != NODE_ATTRITEM) return 0;
    if (node->node.refs[5]) return 0;
    if (!strcmp(ident_get(node->node.refs[3]->id.id), "meta_private"))
      return 1;
  }
  return 0;
}

static void
generate_h_header(
        const unsigned char *h_name,
        const unsigned char *ts_buf,
        FILE *out_h)
{
  unsigned char h_base[1024];
  unsigned char h_guard[1024];
  int i;

  if (h_header_generated) return;
  h_header_generated = 1;

  os_rGetLastname(h_name, h_base, sizeof(h_base));
  snprintf(h_guard, sizeof(h_guard), "__%s__", h_base);
  for (i = 0; h_guard[i]; ++i) {
    h_guard[i] = toupper(h_guard[i]);
    if (!isalnum(h_guard[i])) h_guard[i] = '_';
  }

  fprintf(out_h, "// This is an auto-generated file, do not edit\n");
  if (ts_buf && ts_buf[0]) fprintf(out_h, "%s", ts_buf);
  fprintf(out_h, "\n");
  fprintf(out_h, "#ifndef %s\n", h_guard);
  fprintf(out_h, "#define %s\n\n", h_guard);
  fprintf(out_h, "#include <stdlib.h>\n");
}

static void
generate_h_footer(FILE *out_h)
{
  fprintf(out_h, "#endif\n");
}

static void
generate_c_header(
        const unsigned char *b_name,
        const unsigned char *h_name,
        const unsigned char *ts_buf,
        FILE *out_c)
{
  if (c_header_generated) return;
  c_header_generated = 1;

  unsigned char *basename = os_GetBasename(h_name);

  fprintf(out_c, "// This is an auto-generated file, do not edit\n");
  if (ts_buf && ts_buf[0]) fprintf(out_c, "%s", ts_buf);
  fprintf(out_c, "\n");
  fprintf(out_c, "#include \"ejudge/meta/%s.h\"\n", basename);
  fprintf(out_c, "#include \"ejudge/%s.h\"\n", b_name);
  fprintf(out_c, "#include \"ejudge/meta_generic.h\"\n\n");
  fprintf(out_c, "#include \"ejudge/xalloc.h\"\n\n");
  fprintf(out_c, "#include \"ejudge/logger.h\"\n");
  fprintf(out_c, "#include <string.h>\n");
  fprintf(out_c, "#include <stdlib.h>\n\n");
}

static int
generate_field_enum(
        FILE *out_h,
        tree_t tree,
        ident_t id,
        const unsigned char *in_func_pfx,
        const unsigned char *pfx)
{
  unsigned char rpfx[1024], buf[1024];
  unsigned char func_pfx[1024];
  tree_t decl, ideclr, idnode;
  int i;
  int first_item = 1;

  if (pfx) {
    snprintf(rpfx, sizeof(rpfx), "%s", pfx);
  } else {
    snprintf(rpfx, sizeof(rpfx), "meta_%s", ident_get(id));
  }
  for (i = 0; rpfx[i]; ++i)
    rpfx[i] = toupper(rpfx[i]);

  if (in_func_pfx) {
    snprintf(func_pfx, sizeof(func_pfx), "%s", in_func_pfx);
  } else {
    snprintf(func_pfx, sizeof(func_pfx), "meta_%s", ident_get(id));
  }

  fprintf(out_h, "\nenum\n{\n");
  for (decl = tree->node.refs[6]; decl; decl = decl->node.refs[0]) {
    if (decl->kind != NODE_DECL) {
      c_err(&decl->node.pos.beg, "structure contains non-fields");
      return -1;
    }
    if (!(ideclr = decl->node.refs[4])) continue;
    ASSERT(ideclr->kind == NODE_STRUCTDECLR);
    if (is_meta_hidden(ideclr->node.refs[3])) continue;
    if (ideclr->node.refs[5]) {
      c_err(&decl->node.pos.beg, "bitfields are not supported");
      return -1;
    }
    if (ideclr->node.refs[0]) {
      c_err(&decl->node.pos.beg, "multiple declarators are not supported");
      return -1;
    }
    if (!(idnode = tree_get_ident_node(ideclr))) continue;
    snprintf(buf, sizeof(buf), "%s_%s", rpfx,
             ident_get(idnode->id.id));
    if (first_item) {
      fprintf(out_h, "  %s = 1,\n", buf);
      first_item = 0;
    } else {
      fprintf(out_h, "  %s,\n", buf);
    }
  }
  snprintf(buf, sizeof(buf), "%s_LAST_FIELD", rpfx);
  fprintf(out_h, "\n  %s,\n", buf);
  fprintf(out_h, "};\n\n");

  fprintf(out_h, "struct %s;\n\n", ident_get(id));

  fprintf(out_h, "int %s_get_type(int tag);\n", func_pfx);
  fprintf(out_h, "size_t %s_get_size(int tag);\n", func_pfx);
  fprintf(out_h, "const char *%s_get_name(int tag);\n", func_pfx);
  fprintf(out_h, "const void *%s_get_ptr(const struct %s *ptr, int tag);\n",
          func_pfx, ident_get(id));
  fprintf(out_h, "void *%s_get_ptr_nc(struct %s *ptr, int tag);\n",
          func_pfx, ident_get(id));
  fprintf(out_h, "int %s_lookup_field(const char *name);\n", func_pfx);
  fprintf(out_h, "\n");
  fprintf(out_h, "struct meta_methods;\n");
  fprintf(out_h, "extern const struct meta_methods %s_methods;\n\n", func_pfx);

  return 0;
}

static int
is_plain_type(tree_t ds, tree_t declr)
{
  if (!declr) return 1;
  if (declr->kind == NODE_INITDECLR) declr = declr->node.refs[3];
  if (declr->kind == NODE_STRUCTDECLR) declr = declr->node.refs[3];
  if (!declr) return 1;
  ASSERT(declr->kind == NODE_DECLR);
  if (declr->node.refs[3]) return 0;
  declr = declr->node.refs[4];
  if (!declr) return 1;
  if (declr->kind == NODE_DIRDECLR1) return 1;
  return 0;
}

static int
is_pointer_type(tree_t ds, tree_t declr)
{
  tree_t ptr;

  if (!declr) return 0;
  if (declr->kind == NODE_INITDECLR) declr = declr->node.refs[3];
  if (declr->kind == NODE_STRUCTDECLR) declr = declr->node.refs[3];
  if (!declr) return 0;
  ASSERT(declr->kind == NODE_DECLR);
  if (!(ptr = declr->node.refs[3])) return 0;
  ASSERT(ptr->kind == NODE_POINTER);
  if (ptr->node.refs[0]) return 0;
  if (ptr->node.refs[4]) return 0;
  if (ptr->node.refs[5]) return 0;
  declr = declr->node.refs[4];
  if (!declr) return 1;
  if (declr->kind == NODE_DIRDECLR1) return 1;
  return 0;
}

static int
is_ptrptr_type(tree_t ds, tree_t declr)
{
  tree_t ptr;

  if (!declr) return 0;
  if (declr->kind == NODE_INITDECLR) declr = declr->node.refs[3];
  if (declr->kind == NODE_STRUCTDECLR) declr = declr->node.refs[3];
  if (!declr) return 0;
  ASSERT(declr->kind == NODE_DECLR);
  if (!(ptr = declr->node.refs[3])) return 0;
  ASSERT(ptr->kind == NODE_POINTER);
  if (ptr->node.refs[0]) return 0;
  if (ptr->node.refs[4]) return 0;
  if (!(ptr = ptr->node.refs[5])) return 0;
  ASSERT(ptr->kind == NODE_POINTER);
  if (ptr->node.refs[0]) return 0;
  if (ptr->node.refs[4]) return 0;
  if (ptr->node.refs[5]) return 0;
  declr = declr->node.refs[4];
  if (!declr) return 1;
  if (declr->kind == NODE_DIRDECLR1) return 1;
  return 0;
}

static int
is_array_type(tree_t ds, tree_t declr)
{
  if (!declr) return 0;
  if (declr->kind == NODE_INITDECLR) declr = declr->node.refs[3];
  if (declr->kind == NODE_STRUCTDECLR) declr = declr->node.refs[3];
  if (!declr) return 0;
  ASSERT(declr->kind == NODE_DECLR);
  if (declr->node.refs[3]) return 0;
  declr = declr->node.refs[4];
  if (!declr) return 0;
  if (declr->kind != NODE_DIRDECLR3) return 0;
  declr = declr->node.refs[3];
  if (!declr) return 1;
  if (declr->kind == NODE_DIRDECLR1) return 1;
  return 0;
}

static int
is_typedef_type(tree_t ds, tree_t declr)
{
  tree_t tdds = 0;

  for (; ds; ds = ds->node.refs[0]) {
    if (ds->kind == NODE_DSSTORAGE || ds->kind == NODE_DSQUAL
        || ds->kind == NODE_DSFUNCSPEC)
      continue;
    if (ds->kind != NODE_DSTYPENAME) return 0;
    if (tdds) return 0;
    tdds = ds;
  }
  if (!tdds) return 0;
  return tdds->node.refs[3]->id.id;
}

static int
is_any_char_type(tree_t ds, tree_t declr)
{
  tree_t k;
  int has_char = 0;

  for (; ds; ds = ds->node.refs[0]) {
    if (ds->kind == NODE_DSSTORAGE || ds->kind == NODE_DSQUAL
        || ds->kind == NODE_DSFUNCSPEC)
      continue;
    if (ds->kind != NODE_DSSTDTYPE)
      return 0;
    if (!(k = ds->node.refs[3])) return 0;
    if (k->kind != TOK_SIGNED && k->kind != TOK_UNSIGNED
        && k->kind != TOK_CHAR) return 0;
    if (k->kind == TOK_CHAR) has_char = 1;
  }
  return has_char;
}

static int
is_int_type(tree_t ds, tree_t declr)
{
  tree_t k;

  for (; ds; ds = ds->node.refs[0]) {
    if (ds->kind == NODE_DSSTORAGE || ds->kind == NODE_DSQUAL
        || ds->kind == NODE_DSFUNCSPEC)
      continue;
    if (ds->kind != NODE_DSSTDTYPE)
      return 0;
    if (!(k = ds->node.refs[3])) return 0;
    if (k->kind != TOK_INT) return 0;
  }
  return 1;
}

static int
get_type_letter(tree_t ds, tree_t declr)
{
  ident_t tid;

  if (is_plain_type(ds, declr)) {
    if ((tid = is_typedef_type(ds, declr)) > 0) {
      if (!strcmp(ident_get(tid), "time_t")) {
        return 't';
      } else if (!strcmp(ident_get(tid), "ejbytebool_t")) {
        return 'b';
      } else if (!strcmp(ident_get(tid), "ejintbool_t")) {
        return 'B';
      } else if (!strcmp(ident_get(tid), "ejbyteflag_t")) {
        return 'f';
      } else if (!strcmp(ident_get(tid), "ejintsize_t")) {
        return 'z';
      } else if (!strcmp(ident_get(tid), "path_t")) {
        return 'S';
      } else if (!strcmp(ident_get(tid), "ejstrlist_t")) {
        return 'x';
      } else if (!strcmp(ident_get(tid), "ejenvlist_t")) {
        return 'X';
      } else if (!strcmp(ident_get(tid), "size_t")) {
        return 'Z';
      } else if (!strcmp(ident_get(tid), "ej_size64_t")) {
        return 'E';
      } else if (!strcmp(ident_get(tid), "ej_int_opt_0_t")) {
        return '0';
      } else if (!strcmp(ident_get(tid), "ej_textbox_t")) {
        return '1';
      } else if (!strcmp(ident_get(tid), "ej_textbox_opt_t")) {
        return '2';
      } else if (!strcmp(ident_get(tid), "ej_checkbox_t")) {
        return '3';
      } else if (!strcmp(ident_get(tid), "ej_int_opt_1_t")) {
        return '4';
      } else if (!strcmp(ident_get(tid), "ej_int_opt_m1_t")) {
        return '5';
      } else {
        return '?';
      }
    } else if (is_int_type(ds, declr)) {
      return 'i';
    } else {
      return '?';
    }
  } else if (is_pointer_type(ds, declr)) {
    if (is_any_char_type(ds, declr)) {
      return 's';
    } else {
      return '?';
    }
  } else if (is_ptrptr_type(ds, declr)) {
    if (is_any_char_type(ds, declr)) {
      return 'x';
    } else {
      return '?';
    }
  } else if (is_array_type(ds, declr)) {
    if (is_any_char_type(ds, declr)) {
      return 'S';
    } else {
      return '?';
    }
  } else {
    return '?';
  }
}

static int
generate_field_description(
        FILE *out_c,
        tree_t tree,
        ident_t id,
        const unsigned char *in_func_pfx,
        const unsigned char *in_enum_pfx)
{
  unsigned char enum_pfx[1024];
  unsigned char func_pfx[1024];
  unsigned char buf[1024];
  int i, type_val;
  tree_t decl, ideclr, idnode;

  if (in_enum_pfx) {
    snprintf(enum_pfx, sizeof(enum_pfx), "%s", in_enum_pfx);
  } else {
    snprintf(enum_pfx, sizeof(enum_pfx), "meta_%s", ident_get(id));
  }
  for (i = 0; enum_pfx[i]; ++i)
    enum_pfx[i] = toupper(enum_pfx[i]);

  if (in_func_pfx) {
    snprintf(func_pfx, sizeof(func_pfx), "%s", in_func_pfx);
  } else {
    snprintf(func_pfx, sizeof(func_pfx), "meta_%s", ident_get(id));
  }

  fprintf(out_c, "static struct meta_info_item meta_info_%s_data[] =\n",
          ident_get(id));
  fprintf(out_c, "{\n");
  for (decl = tree->node.refs[6]; decl; decl = decl->node.refs[0]) {
    ASSERT(decl->kind == NODE_DECL);
    if (!(ideclr = decl->node.refs[4])) continue;
    ASSERT(ideclr->kind == NODE_STRUCTDECLR);
    if (is_meta_hidden(ideclr->node.refs[3])) continue;
    ASSERT(!ideclr->node.refs[5]);
    ASSERT(!ideclr->node.refs[0]);
    if (!(idnode = tree_get_ident_node(ideclr))) continue;
    /*
    fprintf(stderr, ">>%s,%d,%d,%d,%d,%d\n", ident_get(idnode->id.id),
            is_plain_type(decl->node.refs[3], ideclr),
            is_pointer_type(decl->node.refs[3], ideclr),
            is_array_type(decl->node.refs[3], ideclr),
            is_typedef_type(decl->node.refs[3], ideclr),
            is_any_char_type(decl->node.refs[3], ideclr));
    */
    type_val = get_type_letter(decl->node.refs[3], ideclr);
    snprintf(buf, sizeof(buf), "%s_%s", enum_pfx, ident_get(idnode->id.id));
    if (is_meta_private(ideclr->node.refs[3])) {
      fprintf(out_c, "  [%s] = { %s, '%c', XSIZE(struct %s, %s), NULL, XOFFSET(struct %s, %s) },\n",
              buf, buf, type_val, ident_get(id), ident_get(idnode->id.id),
              ident_get(id), ident_get(idnode->id.id));
    } else {
      fprintf(out_c, "  [%s] = { %s, '%c', XSIZE(struct %s, %s), \"%s\", XOFFSET(struct %s, %s) },\n",
              buf, buf, type_val, ident_get(id), ident_get(idnode->id.id),
              ident_get(idnode->id.id), ident_get(id),
              ident_get(idnode->id.id));
    }
  }
  fprintf(out_c, "};\n\n");
  fprintf(out_c,
          "int %s_get_type(int tag)\n"
          "{\n"
          "  ASSERT(tag > 0 && tag < %s_LAST_FIELD);\n"
          "  return meta_info_%s_data[tag].type;\n"
          "}\n\n", func_pfx, enum_pfx, ident_get(id));
  fprintf(out_c,
          "size_t %s_get_size(int tag)\n"
          "{\n"
          "  ASSERT(tag > 0 && tag < %s_LAST_FIELD);\n"
          "  return meta_info_%s_data[tag].size;\n"
          "}\n\n", func_pfx, enum_pfx, ident_get(id));
  fprintf(out_c,
          "const char *%s_get_name(int tag)\n"
          "{\n"
          "  ASSERT(tag > 0 && tag < %s_LAST_FIELD);\n"
          "  return meta_info_%s_data[tag].name;\n"
          "}\n\n", func_pfx, enum_pfx, ident_get(id));
  fprintf(out_c,
          "const void *%s_get_ptr(const struct %s *ptr, int tag)\n"
          "{\n"
          "  ASSERT(tag > 0 && tag < %s_LAST_FIELD);\n"
          "  return XPDEREF(void, ptr, meta_info_%s_data[tag].offset);\n"
          "}\n\n", func_pfx, ident_get(id), enum_pfx, ident_get(id));
  fprintf(out_c,
          "void *%s_get_ptr_nc(struct %s *ptr, int tag)\n"
          "{\n"
          "  ASSERT(tag > 0 && tag < %s_LAST_FIELD);\n"
          "  return XPDEREF(void, ptr, meta_info_%s_data[tag].offset);\n"
          "}\n\n", func_pfx, ident_get(id), enum_pfx, ident_get(id));
  fprintf(out_c,
          "int %s_lookup_field(const char *name)\n"
          "{\n"
          "  static struct meta_automaton *atm = 0;\n"
          "  ASSERT(name);\n"
          "  if (!atm) atm = meta_build_automaton(meta_info_%s_data, %s_LAST_FIELD);\n"
          "  return meta_lookup_string(atm, name);\n"
          "}\n\n", func_pfx, ident_get(id), enum_pfx);
  fprintf(out_c,
          "const struct meta_methods %s_methods =\n"
          "{\n"
          "  %s_LAST_FIELD,\n"
          "  sizeof(struct %s),\n"
          "  %s_get_type,\n"
          "  %s_get_size,\n"
          "  %s_get_name,\n"
          "  (const void *(*)(const void *ptr, int tag))%s_get_ptr,\n"
          "  (void *(*)(void *ptr, int tag))%s_get_ptr_nc,\n"
          "  %s_lookup_field,\n"
          "};\n\n",
          func_pfx, enum_pfx, ident_get(id), func_pfx, func_pfx, func_pfx, func_pfx, func_pfx,
          func_pfx);
  return 0;
}

int
meta_generate(
        tree_t tree,
        const unsigned char *ts_buf,
        const unsigned char *b_name,
        const unsigned char *h_name,
        FILE *out_c,
        FILE *out_h,
        const strarray_t *p_strs,
        const strarray_t *p_enum_pfxs,
        const strarray_t *p_func_pfxs)
{
  tree_t p = tree;
  tree_t ds, tok, id;
  const unsigned char *st_tag;
  int i;
  unsigned char *genset;
  unsigned char *enum_pfx;
  unsigned char *func_pfx;

  if (!p_strs || !p_strs->u) {
    fprintf(stderr, "no structs to generate\n");
    return -1;
  }
  if (p_strs->u > 1024) {
    fprintf(stderr, "too many structs to generate\n");
    return -1;
  }
  genset = (unsigned char*) alloca(p_strs->u);
  memset(genset, 0, p_strs->u);

  if (!p || p->kind != NODE_ROOT) {
    fprintf(stderr, "ROOT node expected\n");
    return -1;
  }
  for (p = p->node.refs[3]; p; p = p->node.refs[0]) {
    if (p->kind != NODE_DECL) continue;
    if (p->node.refs[4]) continue;
    if (!(ds = p->node.refs[3])) continue;
    if (ds->kind != NODE_DSAGGREG) continue;
    if (!(tok = ds->node.refs[3])) continue;
    if (tok->kind != TOK_STRUCT) continue;
    if (!(id = ds->node.refs[4])) continue;
    if (id->kind != TOK_IDENT) continue;
    if (!(ds->node.refs[6])) continue;
    st_tag = ident_get(id->id.id);
    for (i = 0; i < p_strs->u; ++i)
      if (!strcmp(st_tag, p_strs->v[i]))
        break;
    if (i >= p_strs->u) continue;
    enum_pfx = 0;
    if (i < p_enum_pfxs->u) enum_pfx = p_enum_pfxs->v[i];
    func_pfx = 0;
    if (i < p_func_pfxs->u) func_pfx = p_func_pfxs->v[i];

    genset[i] = 1;
    generate_h_header(h_name, ts_buf, out_h);
    generate_c_header(b_name, h_name, ts_buf, out_c);

    if (generate_field_enum(out_h, ds, id->id.id, func_pfx, enum_pfx) < 0) return -1;
    if (generate_field_description(out_c, ds, id->id.id, func_pfx, enum_pfx) < 0)
      return -1;
  }

  for (i = 0; i < p_strs->u; ++i) {
    if (!genset[i]) {
      fprintf(stderr, "struct %s is not found\n", p_strs->v[i]);
      return -1;
    }
  }

  generate_h_footer(out_h);

  return 0;
}
