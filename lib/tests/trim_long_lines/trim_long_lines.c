#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ssize_t
utf8_trim_last_codepoint(
        const unsigned char *str,
        ssize_t size)
{
  if (size <= 0) return 0;
  ssize_t i = size - 1;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc0) {
    return i;
  }
  if (--i < 0) return 0;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc2 && str[i] <= 0xdf) {
    return i + 2;
  }
  if (str[i] >= 0xc0) {
    return i;
  }
  if (--i < 0) return 0;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc2 && str[i] <= 0xdf) {
    return i + 2;
  }
  if (str[i] >= 0xe0 && str[i] <= 0xef) {
    return i + 3;
  }
  if (str[i] >= 0xc0) {
    return i;
  }
  if (--i < 0) return 0;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc2 && str[i] <= 0xdf) {
    return i + 2;
  }
  if (str[i] >= 0xe0 && str[i] <= 0xef) {
    return i + 3;
  }
  if (str[i] >= 0xf0 && str[i] <= 0xf7) {
    return i + 4;
  }
  return i;
}

void
trim_long_lines(
        const unsigned char *data,
        ssize_t size,
        int utf8_mode,
        int max_line_length,
        unsigned char **p_out_data,
        ssize_t *p_out_size)
{
  char *out_s = NULL;
  size_t out_z = 0;
  FILE *out_f = open_memstream(&out_s, &out_z);
  ssize_t beg_ind = 0;
  ssize_t ind;

  for (ind = 0; ind < size; ++ind) {
    if (data[ind] == '\n') {
      if (ind - beg_ind > max_line_length) {
        if (utf8_mode) {
          ssize_t trimmed = utf8_trim_last_codepoint(&data[beg_ind], max_line_length);
          fwrite_unlocked(&data[beg_ind], 1, trimmed, out_f);
          fputs_unlocked("…\n", out_f);
        } else {
          fwrite_unlocked(&data[beg_ind], 1, max_line_length, out_f);
          fputs_unlocked("...\n", out_f);
        }
      } else {
        fwrite_unlocked(&data[beg_ind], 1, ind - beg_ind + 1, out_f);
      }
      beg_ind = ind + 1;
    } else if (ind == size - 1) {
      if (ind - beg_ind + 1 > max_line_length) {
        if (utf8_mode) {
          ssize_t trimmed = utf8_trim_last_codepoint(&data[beg_ind], max_line_length);
          fwrite_unlocked(&data[beg_ind], 1, trimmed, out_f);
          fputs_unlocked("…", out_f);
        } else {
          fwrite_unlocked(&data[beg_ind], 1, max_line_length, out_f);
          fputs_unlocked("...", out_f);
        }
      } else {
        fwrite_unlocked(&data[beg_ind], 1, ind - beg_ind + 1, out_f);
      }
    }
  }

  fclose(out_f);
  *p_out_data = out_s;
  *p_out_size = out_z;
}

void do_string(const unsigned char *str)
{
  ssize_t len = strlen(str);
  for (ssize_t i = len; i >= 0; --i) {
    ssize_t tr = utf8_trim_last_codepoint(str, i);
    printf("%.*s\n", (int) tr, str);
  }
}

void do_trim(const unsigned char *str, int max_width, const unsigned char *exp)
{
  ssize_t len = strlen(str);
  unsigned char *out_s = NULL;
  ssize_t out_z = 0;

  trim_long_lines(str, len, 1, max_width, &out_s, &out_z);
  if (strlen(out_s) != out_z) {
    fprintf(stderr, "out_z: %zd != len: %zu\n", out_z, strlen(out_s));
    abort();
  }
  /*
  if (strlen(out_s) != strlen(exp)) {
    fprintf(stderr, "out_len: %zu != exp_len: %zu\n", strlen(out_s), strlen(exp));
    abort();
  }
  */
  if (strcmp(out_s, exp)) {
    fprintf(stderr, "out_s: <%s> != exp: <%s>\n", out_s, exp);
    abort();
  }
  printf("OK\n");
  free(out_s);
}

int main()
{
  /*
  do_string("0123456789");
  do_string("абвгдеёжзи");
  do_string("ᚳᚹᚫᚦ ᚦᚫᛏ ᚻᛖ");
  do_string("有為の奥山");
  */
  do_trim("a\nb\nc\nd\n", 10,
          "a\nb\nc\nd\n");
  do_trim("a\nb\nc\nd", 10,
          "a\nb\nc\nd");
  do_trim("abcdefghijklm\nb\n01234567890123\nd\n",
          10,
          "abcdefghij…\nb\n0123456789…\nd\n");
  do_trim("абвгдеёзжийклмн\n1\n2\n абвгдеёжзи\n3\n",
          10,
          "абвгд…\n1\n2\n абвг…\n3\n");
  do_trim("абвгдеёзжийклмн\n1\n2\n абвгдеёжзи",
          10,
          "абвгд…\n1\n2\n абвг…");
  do_trim("абвгдеёзжийклмн\n",
          10,
          "абвгд…\n");
  do_trim("абвгдеёзжийклмн",
          10,
          "абвгд…");
}
