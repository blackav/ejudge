/* -*- c -*- */

/* Copyright (C) 2014-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"

#include "ejudge/variant_map.h"
#include "ejudge/prepare.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/compat.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

void
variant_map_free(struct variant_map *p)
{
  int i;

  if (!p) return;

  for (i = 0; i < p->u; i++) {
    xfree(p->v[i].login);
    xfree(p->v[i].name);
    xfree(p->v[i].variants);
  }
  xfree(p->prob_map);
  xfree(p->prob_rev_map);
  xfree(p->v);
  xfree(p->user_inds);
  xfree(p->header_txt);
  xfree(p->footer_txt);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

void
variant_map_unparse(
        FILE *f,
        const struct variant_map *vmap,
        int mode)
{
  int i, j;
  int hlen;
  unsigned char *header_txt = vmap->header_txt;

  if (!header_txt) {
      unsigned char header_buf[1024];
      snprintf(header_buf, sizeof(header_buf), "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", INTERNAL_CHARSET);
      header_txt = header_buf;
  }

  // for header ignore the characters after the last '\n'
  if (header_txt) {
    hlen = strlen(header_txt);
    while (hlen > 0 && header_txt[hlen - 1] != '\n') hlen--;
    fprintf(f, "%.*s", hlen, header_txt);
  }

  fprintf(f, "<variant_map version=\"2\">\n");
  for (i = 0; i < vmap->u; i++) {
    fprintf(f, "%s", vmap->v[i].login);
    if (vmap->v[i].real_variant > 0) {
      fprintf(f, " variant %d", vmap->v[i].real_variant);
      if (vmap->v[i].virtual_variant > 0) {
        fprintf(f, " virtual %d", vmap->v[i].virtual_variant);
      }
    } else {
      if (mode == 1) {
        // in ej-contests
        for (j = 1; j <= vmap->var_prob_num; j++)
          fprintf(f, " %d", vmap->v[i].variants[j]);
      } else {
        for (j = 0; j < vmap->prob_rev_map_size; j++)
          fprintf(f, " %d", vmap->v[i].variants[j]);
      }
    }
    fprintf(f, "\n");
  }
  fprintf(f, "</variant_map>\n");
  if (vmap->footer_txt) fprintf(f, "%s", vmap->footer_txt);
}

int
variant_map_save(
        FILE *log_f,
        const struct variant_map *vmap,
        const unsigned char *path,
        int mode)
{
    unsigned char tmpname[PATH_MAX];

    snprintf(tmpname, sizeof(tmpname), "%s.tmp", path);
    FILE *f = fopen(tmpname, "w");
    if (!f) {
        fprintf(log_f, "variant_map_save: failed to open '%s': %s\n",
                tmpname, strerror(errno));
        unlink(tmpname);
        return -1;
    }
    variant_map_unparse(f, vmap, mode);
    fflush(f);
    if (ferror(f)) {
        fprintf(log_f, "variant_map_save: write error to '%s'\n", tmpname);
        unlink(tmpname);
        return -1;
    }
    fclose(f); f = NULL;
    if (rename(tmpname, path) < 0) {
        fprintf(log_f, "variant_map_save: rename to '%s' failed: %s\n",
                path, strerror(errno));
        unlink(tmpname);
        return -1;
    }
    return 0;
}

static int
get_variant_map_version(
        FILE *log_f,            /* to write diagnostic messages */
        FILE *f,                /* to read from */
        FILE *head_f)           /* to write the file header (m.b. NULL) */
{
  int vintage = -1;
  int c;
  const unsigned char *const pvm = "parse_variant_map";

  /* in stream mode ignore everything before variant_map,
     including <?xml ... ?>, <!-- ... -->
  */
  if ((c = getc(f)) == EOF) goto unexpected_EOF;
  if (head_f) putc(c, head_f);
  while (isspace(c)) {
    c = getc(f);
    if (head_f) putc(c, head_f);
  }
  if (c == EOF) goto unexpected_EOF;
  if (c != '<') goto invalid_header;
  if ((c = getc(f)) == EOF) goto unexpected_EOF;
  if (head_f) putc(c, head_f);
  if (c == '?') {
    if ((c = getc(f)) == EOF) goto unexpected_EOF;
    if (head_f) putc(c, head_f);
    while (1) {
      if (c != '?') {
        if ((c = getc(f)) == EOF) goto unexpected_EOF;
        if (head_f) putc(c, head_f);
        continue;
      }
      if ((c = getc(f)) == EOF) goto unexpected_EOF;
      if (head_f) putc(c, head_f);
      if (c == '>') break;
    }
    if ((c = getc(f)) == EOF) goto unexpected_EOF;
    if (head_f) putc(c, head_f);
  }
  while (1) {
    while (isspace(c)) {
      c = getc(f);
      if (head_f) putc(c, head_f);
    }
    if (c == EOF) goto unexpected_EOF;
    if (c != '<') goto invalid_header;
    if ((c = getc(f)) == EOF) goto unexpected_EOF;
    if (head_f) putc(c, head_f);
    if (c == 'v') break;
    if (c != '!') goto invalid_header;
    if ((c = getc(f)) == EOF) goto unexpected_EOF;
    if (head_f) putc(c, head_f);
    while (1) {
      if (c != '-') {
        if ((c = getc(f)) == EOF) goto unexpected_EOF;
        if (head_f) putc(c, head_f);
        continue;
      }
      if ((c = getc(f)) == EOF) goto unexpected_EOF;
      if (head_f) putc(c, head_f);
      if (c == '>') break;
    }
    if ((c = getc(f)) == EOF) goto unexpected_EOF;
    if (head_f) putc(c, head_f);
  }
  ungetc(c, f);

  if (fscanf(f, "variant_map version = \"%d\" >", &vintage) != 1)
    goto invalid_header;
  //if (head_f) fprintf(head_f, "ariant_map version = \"%d\" >", vintage);
  if ((c = getc(f)) == EOF) goto unexpected_EOF;
  //if (head_f) putc(c, head_f);
  while (c != '\n') {
    if ((c = getc(f)) == EOF)
      goto unexpected_EOF;
    //if (head_f) putc(c, head_f);
  }

  return vintage;

 unexpected_EOF:
  fprintf(log_f, "%s: unexpected EOF in variant map file header\n", pvm);
  return -1;

 invalid_header:
  fprintf(log_f, "%s: invalid variant map file header\n", pvm);
  return -1;
}

static int
parse_vm_v1(
        FILE *log_f,
        const unsigned char *path,
        FILE *f,
        struct variant_map *pmap,
        FILE *foot_f)
{
  unsigned char buf[1200];
  unsigned char login_buf[sizeof(buf)];
  unsigned char *p, *q;
  int len, n, j, v, c, rowcnt;
  const unsigned char * const pvm = "parse_variant_map";
  char *eptr;

  while (fgets(buf, sizeof(buf), f)) {
    if ((p = strchr(buf, '#'))) *p = 0;
    len = strlen(buf);
    if (len > 1024) {
      fprintf(log_f, "%s: line is too long in '%s'\n", pvm, path);
      goto failed;
    }
    while (len > 0 && isspace(buf[len - 1])) buf[--len] = 0;
    if (!len) continue;
    if (!strcmp(buf, "</variant_map>")) break;

    if (pmap->u >= pmap->a) {
      pmap->a *= 2;
      pmap->v = (typeof(pmap->v)) xrealloc(pmap->v,
                                           pmap->a * sizeof(pmap->v[0]));
    }
    memset(&pmap->v[pmap->u], 0, sizeof(pmap->v[0]));

    p = buf;
    if (sscanf(p, "%s%n", login_buf, &n) != 1) {
      fprintf(log_f, "%s: cannot read team login\n", pvm);
      goto failed;
    }
    p += n;
    pmap->v[pmap->u].login = xstrdup(login_buf);

    // count the number of digits in the row
    q = p;
    rowcnt = 0;
    while (1) {
      while (isspace(*q)) q++;
      if (!*q) break;
      if (*q < '0' || *q > '9') goto invalid_variant_line;
      errno = 0;
      v = strtol(q, &eptr, 10);
      if (errno) goto invalid_variant_line;
      q = eptr;
      if (*q && !isspace(*q)) goto invalid_variant_line;
      rowcnt++;
    }

    pmap->v[pmap->u].var_num = rowcnt;
    XCALLOC(pmap->v[pmap->u].variants, rowcnt + 1);

    for (j = 1; j <= rowcnt; j++) {
      if (sscanf(p, "%d%n", &v, &n) != 1) abort();
      if (v < 0) goto invalid_variant_line;
      p += n;
      pmap->v[pmap->u].variants[j] = v;
    }
    pmap->u++;
  }
  if (foot_f) {
    while ((c = getc(f)) != EOF)
      putc(c, foot_f);
  }
  return 0;

 invalid_variant_line:
  fprintf(log_f, "%s: invalid variant line `%s' for user %s\n",
          pvm, buf, login_buf);
  goto failed;

 failed:
  return -1;
}

static int
parse_vm_v2(
        FILE *log_f,
        const unsigned char *path,
        FILE *f,
        struct variant_map *pmap,
        FILE *foot_f)
{
  unsigned char buf[1200];
  unsigned char login_buf[sizeof(buf)];
  unsigned char *p, *q;
  char *eptr;
  int len, n, j, v, c, rowcnt;
  const unsigned char * const pvm = "parse_variant_map";

  while (fgets(buf, sizeof(buf), f)) {
    if ((p = strchr(buf, '#'))) *p = 0;
    len = strlen(buf);
    if (len > 1024) {
      fprintf(log_f, "%s: line is too long in '%s'\n", pvm, path);
      goto failed;
    }
    while (len > 0 && isspace(buf[len - 1])) buf[--len] = 0;
    if (!len) continue;
    if (!strcmp(buf, "</variant_map>")) break;

    if (pmap->u >= pmap->a) {
      pmap->a *= 2;
      pmap->v = (typeof(pmap->v)) xrealloc(pmap->v,
                                           pmap->a * sizeof(pmap->v[0]));
    }
    memset(&pmap->v[pmap->u], 0, sizeof(pmap->v[0]));

    p = buf;
    if (sscanf(p, "%s%n", login_buf, &n) != 1) {
      fprintf(log_f, "%s: cannot read team login\n", pvm);
      goto failed;
    }
    p += n;
    pmap->v[pmap->u].login = xstrdup(login_buf);

    if (sscanf(p, " variant %d%n", &v, &n) == 1) {
      if (v < 0) {
        fprintf(log_f, "%s: invalid variant\n", pvm);
        goto failed;
      }
      p += n;
      pmap->v[pmap->u].real_variant = v;
      if (!*p) {
        pmap->u++;
        continue;
      }
      if (sscanf(p, " virtual %d%n", &v, &n) != 1 || v < 0) {
        fprintf(log_f, "%s: invalid virtual variant\n", pvm);
        goto failed;
      }
      pmap->v[pmap->u].virtual_variant = v;
      pmap->u++;
      continue;
    }

    // count the number of digits in the row
    q = p;
    rowcnt = 0;
    while (1) {
      while (isspace(*q)) q++;
      if (!*q) break;
      if (*q < '0' || *q > '9') goto invalid_variant_line;
      errno = 0;
      v = strtol(q, &eptr, 10);
      if (errno) goto invalid_variant_line;
      q = eptr;
      if (*q && !isspace(*q)) goto invalid_variant_line;
      rowcnt++;
    }

    pmap->v[pmap->u].var_num = rowcnt;
    XCALLOC(pmap->v[pmap->u].variants, rowcnt + 1);

    for (j = 1; j <= rowcnt; j++) {
      if (sscanf(p, "%d%n", &v, &n) != 1) abort();
      if (v < 0) goto invalid_variant_line;
      p += n;
      pmap->v[pmap->u].variants[j] = v;
    }
    pmap->u++;
  }
  if (foot_f) {
    while ((c = getc(f)) != EOF)
      putc(c, foot_f);
  }
  return 0;

 invalid_variant_line:
  fprintf(log_f, "%s: invalid variant line `%s' for user %s\n",
          pvm, buf, login_buf);
  goto failed;

 failed:
  return -1;
}

struct variant_map *
variant_map_parse(
        FILE *log_f,
        const struct serve_state *state,
        const unsigned char *path)
{
  int vintage, i, j, k, var_prob_num;
  FILE *f = 0;
  struct variant_map *pmap = 0;
  const unsigned char * const pvm = "parse_variant_map";
  FILE *head_f = 0, *foot_f = 0;
  char *head_t = 0, *foot_t = 0;
#if HAVE_OPEN_MEMSTREAM - 0
  size_t head_z = 0, foot_z = 0;
#endif
  const struct section_problem_data *prob;
  int *newvar;

#if HAVE_OPEN_MEMSTREAM - 0
  head_f = open_memstream(&head_t, &head_z);
  foot_f = open_memstream(&foot_t, &foot_z);
#endif

  XCALLOC(pmap, 1);
  pmap->a = 16;
  XCALLOC(pmap->v, pmap->a);

  if (state) {
    pmap->prob_map_size = state->max_prob + 1;
    XCALLOC(pmap->prob_map, state->max_prob + 1);
    XCALLOC(pmap->prob_rev_map, state->max_prob + 1);
    pmap->var_prob_num = 0;
    for (i = 1; i <= state->max_prob; i++) {
      if (!state->probs[i] || state->probs[i]->variant_num <= 0) continue;
      pmap->prob_map[i] = ++pmap->var_prob_num;
      pmap->prob_rev_map[pmap->var_prob_num] = i;
    }
  }

  if (!(f = fopen(path, "r"))) {
    fprintf(log_f, "%s: cannot open variant map file '%s'\b", pvm, path);
    goto failed;
  }
  if ((vintage = get_variant_map_version(log_f, f, head_f)) < 0) goto failed;

  switch (vintage) {
  case 1:
    if (parse_vm_v1(log_f, path, f, pmap, foot_f) < 0) goto failed;
    break;
  case 2:
    if (parse_vm_v2(log_f, path, f, pmap, foot_f) < 0) goto failed;
    break;
  default:
    fprintf(log_f, "%s: cannot handle variant map file '%s' version %d\n",
            pvm, path, vintage);
    goto failed;
  }

  if (ferror(f)) {
    fprintf(log_f, "%s: input error from '%s'\n", pvm, path);
    goto failed;
  }

  if (state) {
    for (i = 0; i < pmap->u; i++) {
      if (pmap->v[i].real_variant > 0) {
        XCALLOC(pmap->v[i].variants, pmap->var_prob_num + 1);
        for (j = 1; j <= pmap->var_prob_num; j++) {
          pmap->v[i].variants[j] = pmap->v[i].real_variant;
        }
      } else {
        if (pmap->v[i].var_num > pmap->var_prob_num) {
          pmap->v[i].var_num = pmap->var_prob_num;
        } else if (pmap->v[i].var_num < pmap->var_prob_num) {
          int *vv = 0;
          XCALLOC(vv, pmap->var_prob_num + 1);
          if (pmap->v[i].variants) {
            memcpy(vv, pmap->v[i].variants,
                   (pmap->v[i].var_num + 1) * sizeof(vv[0]));
          }
          xfree(pmap->v[i].variants);
          pmap->v[i].variants = vv;
          pmap->v[i].var_num = pmap->var_prob_num;
        }
        if (pmap->v[i].var_num != pmap->var_prob_num) {
          fprintf(log_f, "%s: invalid number of entries for user %s\n",
                  pvm, pmap->v[i].login);
          goto failed;
        }
      }

      for (j = 1; j <= pmap->var_prob_num; j++) {
        k = pmap->prob_rev_map[j];
        ASSERT(k > 0 && k <= state->max_prob);
        prob = state->probs[k];
        ASSERT(prob && prob->variant_num > 0);
        if (pmap->v[i].real_variant > prob->variant_num) {
          fprintf(log_f, "%s: variant %d is invalid for (%s, %s)\n",
                  pvm, pmap->v[i].variants[j], pmap->v[i].login,
                  prob->short_name);
          goto failed;
        }
      }
    }
  } else {
    // set pmap->var_prob_num based on the given variant specifications
    // FIXME: super_html_3.c expects, that variants are listed starting
    // from 0, but parse_variant_map parses variants starting from 1...
    var_prob_num = 0;
    for (i = 0; i < pmap->u; i++) {
      if (pmap->v[i].var_num > var_prob_num)
        var_prob_num = pmap->v[i].var_num;
    }
    for (i = 0; i < pmap->u; i++) {
      if (pmap->v[i].var_num < var_prob_num) {
        XCALLOC(newvar, var_prob_num + 1);
        if (pmap->v[i].variants) {
          memcpy(newvar, pmap->v[i].variants, (pmap->v[i].var_num + 1) * sizeof(newvar[0]));
          xfree(pmap->v[i].variants);
        }
        pmap->v[i].variants = newvar;
        pmap->v[i].var_num = var_prob_num;
      }
      memmove(pmap->v[i].variants, pmap->v[i].variants + 1, pmap->v[i].var_num * sizeof(newvar[0]));
    }
    pmap->var_prob_num = var_prob_num;

    /*
    fprintf(stderr, "Parsed variant map version %d\n", vintage);
    for (i = 0; i < pmap->u; i++) {
      fprintf(stderr, "%s: ", pmap->v[i].login);
      for (j = 0; j < pmap->var_prob_num; j++)
        fprintf(stderr, "%d ",
                pmap->v[i].variants[j]);
      fprintf(stderr, "\n");
    }
    */
  }

  if (head_f) {
    close_memstream(head_f);
    head_f = 0;
  }
  pmap->header_txt = head_t; head_t = 0;

  if (foot_f) {
    close_memstream(foot_f);
    foot_f = 0;
  }
  pmap->footer_txt = foot_t; foot_t = 0;

  fclose(f);
  return pmap;

 failed:
  if (pmap) {
    for (i = 0; i < pmap->u; i++) {
      xfree(pmap->v[i].login);
      xfree(pmap->v[i].name);
      xfree(pmap->v[i].variants);
    }
    xfree(pmap->user_inds);
    xfree(pmap->v);
    xfree(pmap->prob_map);
    xfree(pmap->prob_rev_map);
    xfree(pmap);
  }
  if (f) fclose(f);
  if (head_f) fclose(head_f);
  xfree(head_t);
  return 0;
}

int
variant_map_set_variant(
        struct variant_map *vmap,
        int user_id,
        const unsigned char *user_login,
        int prob_id,
        int variant)
{
    int pind = 0;
    if (prob_id <= 0 || prob_id >= vmap->prob_map_size || (pind = vmap->prob_map[prob_id]) <= 0) {
        return -1;
    }
    if (user_id <= 0) {
        return -1;
    }
    if (variant <= 0) {
        return -1;
    }
    int ui;
    struct variant_map_item *vi = NULL;
    if (user_id < vmap->user_ind_size && (ui = vmap->user_inds[user_id]) >= 0) {
        vi = vmap->v + ui;
        if (vi->variants[pind] == variant) {
            // no change
            return 0;
        }
        vi->variants[pind] = variant;
        return 1;
    }
    if (user_id >= vmap->user_ind_size) {
        int newsz = 32;
        while (user_id >= newsz) {
            newsz *= 2;
        }
        int *newvm = xmalloc(newsz * sizeof(newvm[0]));
        memset(newvm, -1, newsz * sizeof(newvm[0]));
        if (vmap->user_ind_size > 0) {
            memcpy(newvm, vmap->user_inds, vmap->user_ind_size * sizeof(vmap->user_inds[0]));
        }
        xfree(vmap->user_inds);
        vmap->user_inds = newvm;
        vmap->user_ind_size = newsz;
    }
    if (vmap->u >= vmap->a) {
        if (!vmap->a) vmap->a = 16;
        vmap->a *= 2;
        XREALLOC(vmap->v, vmap->a);
    }
    vi = &vmap->v[vmap->u++];
    memset(vi, 0, sizeof(*vi));
    vmap->user_inds[user_id] = vmap->u - 1;
    vi->user_id = user_id;
    if (user_login) {
        vi->login = xstrdup(user_login);
    }
    XCALLOC(vi->variants, vmap->var_prob_num + 1);
    vi->variants[pind] = variant;
    return 1;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
