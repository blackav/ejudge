/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "clarlog.h"

#include "teamdb.h"

#include "unix/unix_fileutl.h"
#include "pathutl.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define CLAR_RECORD_SIZE 79
#define SUBJ_STRING_SIZE 24
#define IP_STRING_SIZE   15

struct clar_entry
{
  int           id;          /* 4 + 1 */
  unsigned long time;        /* 11 + 1 */
  unsigned long size;        /* 4 + 1 */
  int           from;        /* 4 + 1 */
  int           to;          /* 4 + 1 */
  int           flags;       /* 2 + 1 */
  char          ip[16];      /* 15 + 1 */
  char          subj[28];    /* 24 + 1 (up to 18 subj. chars) */
};

struct clar_array
{
  int                a, u;
  struct clar_entry *v;
};

static struct clar_array clars;
static int               clar_fd = -1;

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__, t , ##args); return -1; } while (0)

static int
clar_read_record(char *buf, int size)
{
  int rsz, i;

  if ((rsz = sf_read(clar_fd, buf, size, "clar")) < 0) return rsz;
  if (rsz != size) ERR_R("short read: %d", rsz);

  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

static int
clar_read_entry(int n)
{
  char buf[CLAR_RECORD_SIZE + 16];
  char b2[CLAR_RECORD_SIZE + 16];
  char b3[CLAR_RECORD_SIZE + 16];
  int  k, r;

  memset(buf, 0, sizeof(buf));
  if (clar_read_record(buf, CLAR_RECORD_SIZE) < 0) return -1;
  r = sscanf(buf, "%d %lu %lu %d %d %d %s %s %n",
             &clars.v[n].id, &clars.v[n].time, &clars.v[n].size,
             &clars.v[n].from,
             &clars.v[n].to, &clars.v[n].flags,
             b2, b3, &k);
  if (r != 8) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);

  /* do sanity checking */
  if (clars.v[n].id != n) ERR_R("[%d]: bad id: %d", n, clars.v[n].id);
  if (clars.v[n].size == 0 || clars.v[n].size >= 10000)
    ERR_R("[%d]: bad size: %d", n, clars.v[n].size);
  if (clars.v[n].from && !teamdb_lookup(clars.v[n].from))
    ERR_R("[%d]: bad from: %d", n, clars.v[n].from);
  if (clars.v[n].to && !teamdb_lookup(clars.v[n].to))
    ERR_R("[%d]: bad to: %d", n, clars.v[n].to);
  if (clars.v[n].flags < 0 || clars.v[n].flags > 255)
    ERR_R("[%d]: bad flags: %d", n, clars.v[n].flags);
  if (strlen(b2) > IP_STRING_SIZE) ERR_R("[%d]: ip is too long", n);
  if (strlen(b3) > SUBJ_STRING_SIZE) ERR_R("[%d]: subj is too long", n);

  strcpy(clars.v[n].ip, b2);
  strcpy(clars.v[n].subj, b3);
  return 0;
}

int
clar_open(char const *path, int flags)
{
  unsigned long filesize;
  int           i;

  info("clar_open: opening database %s", path);
  if (clars.v) {
    xfree(clars.v); clars.v = 0; clars.u = clars.a = 0;
  }
  if (clar_fd >= 0) {
    close(clar_fd); clar_fd = -1;
  }
  if ((clar_fd = sf_open(path, O_RDWR | O_CREAT, 0666)) < 0) return -1;

  if ((filesize = sf_lseek(clar_fd, 0, SEEK_END, "clar")) == (off_t) -1)
    return -1;
  if (sf_lseek(clar_fd, 0, SEEK_SET, "clar") == (off_t) -1) return -1;

  info("clar_open: file size %lu", filesize);
  if (filesize % CLAR_RECORD_SIZE != 0)
    ERR_R("bad file size: remainder %d", filesize % CLAR_RECORD_SIZE);

  clars.u = filesize / CLAR_RECORD_SIZE;
  clars.a = 128;
  while (clars.u > clars.a) clars.a *= 2;
  XCALLOC(clars.v, clars.a);
  for (i = 0; i < clars.u; i++) {
    if (clar_read_entry(i) < 0) return -1;
  }

  info("clar_open: success");
  return 0;
}

static int
clar_make_record(char *buf, int ser, unsigned long tim,
                 unsigned long size,
                 int orig, int to, int flags,
                 char const *ip, char const *subj)
{
  if (strlen(subj) > SUBJ_STRING_SIZE)
    ERR_R("invalid subj len: %d", strlen(subj));
  if (strlen(ip) > IP_STRING_SIZE)
    ERR_R("bad ip len: %d", strlen(ip));

  memset(buf, ' ', CLAR_RECORD_SIZE);
  buf[CLAR_RECORD_SIZE] = 0;
  buf[CLAR_RECORD_SIZE - 1] = '\n';
  sprintf(buf, "%-4d %-11lu %-4lu %-4d %-4d %-2d %s %s",
          ser, tim, size, orig, to, flags, ip, subj);
  buf[strlen(buf)] = ' ';
  if (strlen(buf)!=CLAR_RECORD_SIZE)
    ERR_R("record size bad: %d",strlen(buf));
  if (buf[CLAR_RECORD_SIZE - 1] != '\n')
    ERR_R("record terminator corrupted");
  return 0;
}

static int
clar_flush_entry(int num)
{
  char buf[CLAR_RECORD_SIZE + 16];
  int  wsz;

  if (clar_fd < 0) ERR_R("bad descriptor: %d", clar_fd);
  if (num < 0 || num >= clars.u) ERR_R("bad entry number: %d", num);
  if (clar_make_record(buf, clars.v[num].id, clars.v[num].time,
                       clars.v[num].size,
                       clars.v[num].from, clars.v[num].to,
                       clars.v[num].flags,
                       clars.v[num].ip, clars.v[num].subj) < 0)
    return -1;
  if (sf_lseek(clar_fd, CLAR_RECORD_SIZE * num, SEEK_SET, "clar") == (off_t) -1) return -1;

  if ((wsz = sf_write(clar_fd, buf, CLAR_RECORD_SIZE, "clar")) < 0) return -1;
  if (wsz != CLAR_RECORD_SIZE) ERR_R("short write: %d", wsz);
  return 0;
}

int
clar_add_record(unsigned long  time,
                unsigned long  size,
                char const    *ip,
                int            from,
                int            to,
                int            flags,
                char const    *subj)
{
  int i;

  if (size == 0 || size > 9999) ERR_R("bad size: %lu", size);
  if (from && !teamdb_lookup(from)) ERR_R("bad from: %d", from);
  if (to && !teamdb_lookup(to)) ERR_R("bad to: %d", to);
  if (flags < 0 || flags > 255) ERR_R("bad flags: %d", flags);
  if (strlen(subj) > SUBJ_STRING_SIZE)
    ERR_R("bad subj size: %d", strlen(subj));
  if (strlen(ip) > IP_STRING_SIZE) ERR_R("bad ip size: %d", strlen(ip));

  if (clars.u >= clars.a) {
    if (!(clars.a *= 2)) clars.a = 128;
    clars.v = xrealloc(clars.v, clars.a * sizeof(clars.v[0]));
    info("clar_add_record: array extended: %d", clars.a);
  }
  i = clars.u++;

  clars.v[i].id = i;
  clars.v[i].time = time;
  clars.v[i].size = size;
  clars.v[i].from = from;
  clars.v[i].to = to;
  clars.v[i].flags = flags;
  strcpy(clars.v[i].ip, ip);
  strcpy(clars.v[i].subj, subj);
  if (clar_flush_entry(i) < 0) return -1;
  return i;
}

int
clar_get_record(int id,
                unsigned long *ptime,
                unsigned long *psize,
                char          *ip,
                int           *pfrom,
                int           *pto,
                int           *pflags,
                char          *subj)
{
  if (id < 0 || id >= clars.u) ERR_R("bad id: %d", id);
  if (clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, clars.v[id].id);

  if (ptime)   *ptime   = clars.v[id].time;
  if (psize)   *psize   = clars.v[id].size;
  if (ip)                 strcpy(ip, clars.v[id].ip);
  if (pfrom)   *pfrom   = clars.v[id].from;
  if (pto)     *pto     = clars.v[id].to;
  if (pflags)  *pflags  = clars.v[id].flags;
  if (subj)               strcpy(subj, clars.v[id].subj);
  return 0;
}

int
clar_update_flags(int id, int flags)
{
  if (id < 0 || id >= clars.u) ERR_R("bad id: %d", id);
  if (clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, clars.v[id].id);
  if (flags < 0 || flags > 255) ERR_R("bad flags: %d", flags);

  clars.v[id].flags = flags;
  if (clar_flush_entry(id) < 0) return -1;
  return 0;
}

int
clar_get_total(void)
{
  return clars.u;
}

void
clar_get_team_usage(int from, int *pn, unsigned long *ps)
{
  int i;
  unsigned int total = 0;
  int n = 0;

  for (i = 0; i < clars.u; i++)
    if (clars.v[i].from == from) {
      total += clars.v[i].size;
      n++;
    }
  if (pn) *pn = n;
  if (ps) *ps = total;
}

char *
clar_flags_html(int flags, int from, int to, char *buf, int len)
{
  char *s = "";

  if (!from)           s = "&nbsp;";
  else if (flags == 0) s = "N";
  else if (flags == 1) s = "R";
  else if (flags == 2) s = "A";
  else s = "?";

  if (!buf) return s;
  if (len <= 0) return strcpy(buf, s);
  strncpy(buf, s, len);
  buf[len - 1] = 0;
  return buf;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
