/* $Id$ */

#include "new-server.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "new_server_at.c"

void collect_chars(const int *act_set, int act_count, int pos, unsigned char *out, int *p_has_term)
{
  unsigned char cs[256];
  memset(cs, 0, sizeof(cs));
  *p_has_term = 0;
  out[0] = 0;

  for (int i = 0; i < act_count; ++i) {
    const unsigned char *ss = symbolic_action_table[act_set[i]];
    cs[tolower(ss[pos])] = 1;
  }

  if (cs[0]) *p_has_term = 1;
  unsigned char *q = out;
  for (int i = ' '; i < 127; ++i) {
    if (cs[i]) *q++ = i;
  }
  *q = 0;
}

void
generate(
        FILE *out,
        const unsigned char *indent,
        const unsigned char *prefix,
        int *act_set,
        int act_count,
        int pos);

void
generate2(
        FILE *out,
        const unsigned char *indent,
        const unsigned char *prefix,
        int *act_set,
        int act_count,
        int pos,
        const unsigned char *buf,
        int low,
        int high)
{
  if (low >= high) return;

  int mid = (low + high) / 2;
  fprintf(out, "%sif (c == '%c') {\n", indent, buf[mid]);
  unsigned char new_indent[256];
  snprintf(new_indent, sizeof(new_indent), "%s  ", indent);
  unsigned char new_prefix[256];
  snprintf(new_prefix, sizeof(new_prefix), "%s%c", prefix, buf[mid]);
  fprintf(stderr, "prefix: %s\n", new_prefix);
  int new_act_set[NEW_SRV_ACTION_LAST];
  int new_act_count = 0;
  for (int i = 0; i < act_count; ++i) {
    if (!strncasecmp(symbolic_action_table[act_set[i]], new_prefix, pos + 1)) {
      new_act_set[new_act_count++] = act_set[i];
    }
  }
  fprintf(stderr, "act_count: %d\n", new_act_count);
  generate(out, new_indent, new_prefix, new_act_set, new_act_count, pos + 1);

  if (low + 1 == high) {
    fprintf(out, "%s}\n", indent);
  } else {
    unsigned char new_indent[256];
    snprintf(new_indent, sizeof(new_indent), "%s  ", indent);
    fprintf(out, "%s} else if (c < '%c') {\n", indent, buf[mid]);
    generate2(out, new_indent, prefix, act_set, act_count, pos, buf, low, mid);
    fprintf(out, "%s} else {\n", indent);
    generate2(out, new_indent, prefix, act_set, act_count, pos, buf, mid + 1, high);
    fprintf(out, "%s}\n", indent);
  }
}

void
generate(
        FILE *out,
        const unsigned char *indent,
        const unsigned char *prefix,
        int *act_set,
        int act_count,
        int pos)
{
  int has_term = 0;
  unsigned char out_buf[257];
  collect_chars(act_set, act_count, pos, out_buf, &has_term);
  fprintf(stderr, "chars (%d): <%s>, %d\n", pos, out_buf, has_term);

  fprintf(out, "%sc = tolower(str[%d]);\n", indent, pos);
  if (has_term) {
    int value = 0;
    for (int i = 0; i < NEW_SRV_ACTION_LAST; ++i)
      if (symbolic_action_table[i] && !strcasecmp(prefix, symbolic_action_table[i])) {
        value = i;
      }
    if (value <= 0) abort();
    fprintf(out, "%sif (!c) return NEW_SRV_ACTION_%s;\n", indent, symbolic_action_table[value]);
    //fprintf(out, "%sif (!c) return %d;\n", indent, value);
  }
  int low = 0, high = strlen(out_buf);
  generate2(out, indent, prefix, act_set, act_count, pos, out_buf, low, high);
  fprintf(out, "%sreturn 0;\n", indent);
}

int main(void)
{
  printf("#include <ctype.h>\n"
         "#include \"new-server.h\"\n"
         "int ns_match_action(const unsigned char *str)\n"
         "{\n"
         "  int c;\n"
         "  if (!str) return 0;\n");

  fprintf(stderr, "action table size: %d\n", NEW_SRV_ACTION_LAST);
  int act0_set[NEW_SRV_ACTION_LAST + 1];
  int act0_count = 0;
  for (int i = 0; i < NEW_SRV_ACTION_LAST; ++i) {
    if (symbolic_action_table[i]) {
      act0_set[act0_count++] = i;
    }
  }
  fprintf(stderr, "non-null actions: %d\n", act0_count);

  generate(stdout, "  ", "", act0_set, act0_count, 0);

  printf("}\n");
  return 0;
}
