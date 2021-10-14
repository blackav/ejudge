/* -*- mode: c -*- */

/* Copyright (C) 2006-2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/job_packet.h"
#include "ejudge/errlog.h"
#include "ejudge/pathutl.h"
#include "ejudge/fileutl.h"
#include "ejudge/sock_op.h"
#include "ejudge/ejudge_cfg.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

int
send_job_packet(
        const struct ejudge_cfg *config,
        unsigned char **args)
{
  path_t q_path;
  int argc, pktlen, i, pid;
  int *argl;
  char *pkt, *p;
  unsigned char pkt_name[64];
  struct timeval t;

  if (!args || !args[0]) {
    err("send_job_packet: no arguments");
    return -1;
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
  XALLOCA(pkt, pktlen + sizeof(int));
  p = pkt;
  memcpy(p, &pktlen, sizeof(int)); p += sizeof(int);
  memcpy(p, &argc, sizeof(int)); p += sizeof(int);
  memcpy(p, argl, argc * sizeof(int)); p += argc * sizeof(int);
  for (i = 0; i < argc; i++) {
    memcpy(p, args[i], argl[i]);
    p += argl[i];
  }

  unsigned char socket_path[PATH_MAX];
  socket_path[0] = 0;

#if defined EJUDGE_LOCAL_DIR
  if (snprintf(socket_path, sizeof(socket_path), "%s/%s", EJUDGE_LOCAL_DIR, "sockets/jobs") >= sizeof(socket_path)) {
    err("socket path is too long");
    return -1;
  }
#else
  if (snprintf(socket_path, sizeof(socket_path), "%s/%s", config->var_dir, "socket/jobs") >= sizeof(socket_path)) {
    err("socket path is too long");
    return -1;
  }
#endif

  while (1) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
      err("send_job_packet: socket() failed: %s", os_ErrorMsg());
      break;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (connect(sfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
      err("send_job_packet: connect() failed: %s", os_ErrorMsg());
      close(sfd);
      break;
    }
    if (sock_op_put_creds(sfd) < 0) {
      err("send_job_packet: failed to send credentials");
      close(sfd);
      break;
    }

    int len = pktlen + 4;
    unsigned char *p = pkt;
    while (len > 0) {
      int r = write(sfd, p, len);
      if (r < 0) {
        err("send_job_packet: write failed: %s", os_ErrorMsg());
        close(sfd);
        return -1;
      }
      if (!r) {
        err("send_job_packet: write returned 0");
        close(sfd);
        return -1;
      }
      len -= r;
      p += r;
    }

    close(sfd);
    return 0;
  }

#if defined EJUDGE_LOCAL_DIR
  snprintf(q_path, sizeof(q_path), "%s/jspool", EJUDGE_LOCAL_DIR);
#elif defined EJUDGE_CONTESTS_HOME_DIR
  snprintf(q_path, sizeof(q_path), "%s/var/jspool", EJUDGE_CONTESTS_HOME_DIR);
#else
  err("send_job_packet: no queue dir defined");
  return -1;
#endif

  gettimeofday(&t, 0);
  pid = getpid();
  snprintf(pkt_name, sizeof(pkt_name),
           "%08x%08x%04x", (unsigned )t.tv_sec, (unsigned) t.tv_usec, pid);
  if (generic_write_file(pkt + sizeof(int), pktlen, SAFE, q_path, pkt_name, "") < 0) {
    return -1;
  }

  return 0;
}
