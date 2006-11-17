/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "settings.h"
#include "ej_types.h"

#include "job_packet.h"
#include "errlog.h"
#include "pathutl.h"
#include "fileutl.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

int
send_job_packet(const unsigned char *q_dir, unsigned char **args,
                unsigned char **p_path)
{
  path_t q_path;
  int argc, pktlen, i, pid;
  int *argl;
  char *pkt, *p;
  unsigned char pkt_name[64];
  path_t pkt_path;
  struct timeval t;

  if (!args || !args[0]) {
    err("send_job_packet: no arguments");
    return -1;
  }
  if (q_dir) {
    snprintf(q_path, sizeof(q_path), "%s", q_dir);
  } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
    snprintf(q_path, sizeof(q_path), "%s/var/jspool", EJUDGE_CONTESTS_HOME_DIR);
#else
    err("send_job_packet: no queue dir defined");
    return -1;
#endif
  }

  for (argc = 0; args[argc]; argc++);
  XALLOCA(argl, argc);
  for (i = 0, pktlen = 0; i < argc; i++)
    pktlen += argl[i] = strlen(args[i]);
  pktlen += sizeof(int) + argc * sizeof(int);
  if (pktlen <= 0 || pktlen > 1 * 1024 * 1024) {
    err("send_job_packet: packet is too big");
    return -1;
  }
  XALLOCA(pkt, pktlen);
  p = pkt;
  memcpy(p, &argc, sizeof(int)); p += sizeof(int);
  memcpy(p, argl, argc * sizeof(int)); p += argc * sizeof(int);
  for (i = 0; i < argc; i++) {
    memcpy(p, args[i], argl[i]);
    p += argl[i];
  }

  gettimeofday(&t, 0);
  pid = getpid();
  snprintf(pkt_name, sizeof(pkt_name),
           "%08x%08x%04x", (unsigned )t.tv_sec, (unsigned) t.tv_usec, pid);
  if (generic_write_file(pkt, pktlen, SAFE, q_path, pkt_name, "") < 0) {
    return -1;
  }

  if (p_path) {
    snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s", q_path, pkt_name);
    *p_path = xstrdup(pkt_path);
  }
  return 0;
}
