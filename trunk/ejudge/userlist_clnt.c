/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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

#include "userlist_clnt.h"
#include "pathutl.h"
#include "userlist_proto.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

struct userlist_clnt
{
  int fd;
};

struct userlist_clnt*
userlist_clnt_open(char const *socketpath)
{
  int fd = -1;
  struct userlist_clnt *clnt = 0;
  int max_path_buf;
  int val;
  struct sockaddr_un addr;
  int ret;
  struct ucred *pcred;
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];

  return 0;

  ASSERT(socketpath);
  max_path_buf = sizeof(struct sockaddr_un) - 
    XOFFSET(struct sockaddr_un, sun_path);
  if (strlen(socketpath) >= max_path_buf) {
    err("socket path length is too long (%d)", strlen(socketpath));
    goto failure;
  }

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("socket() failed: %s", os_ErrorMsg());
    goto failure;
  }

  val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
    err("setsockopt() failed: %s", os_ErrorMsg());
    goto failure;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socketpath, max_path_buf - 1);
  if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    err("connect() failed: %s", os_ErrorMsg());
    goto failure;
  }

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = msgbuf;
  msg.msg_controllen = sizeof(msgbuf);
  pmsg = CMSG_FIRSTHDR(&msg);
  pcred = (struct ucred*) CMSG_DATA(pmsg);
  pcred->pid = getpid();
  pcred->uid = getuid();
  pcred->gid = getgid();
  pmsg->cmsg_level = SOL_SOCKET;
  pmsg->cmsg_type = SCM_CREDENTIALS;
  pmsg->cmsg_len = CMSG_LEN(sizeof(*pcred));
  msg.msg_controllen = CMSG_SPACE(sizeof(*pcred));
  send_vec[0].iov_base = &val;
  send_vec[0].iov_len = 4;
  msg.msg_iov = send_vec;
  msg.msg_iovlen = 1;
  val = 0;
  ret = sendmsg(fd, &msg, 0);
  if (ret < 0) {
    err("sendmsg() failed: %s", os_ErrorMsg());
    goto failure;
  }
  if (ret != 4) {
    err("sendmsg() short write: %d bytes", ret);
    goto failure;
  }

  clnt = (struct userlist_clnt*) xcalloc(1, sizeof(*clnt));
  clnt->fd = fd;
  return clnt;

 failure:
  if (fd >= 0) close(fd);
  if (clnt) xfree(clnt);
  return 0;
}

struct userlist_clnt*
userlist_clnt_close(struct userlist_clnt *clnt)
{
  return 0;

  close(clnt->fd);
  xfree(clnt);
  return 0;
}

int
userlist_clnt_register_new(struct userlist_clnt *clnt,
                           unsigned long origin_ip,
                           int contest_id,
                           int locale_id,
                           int use_cookies,
                           unsigned char const *login,
                           unsigned char const *email)
{
  if (!strcmp(login, "new")) {
    return ULS_OK;
  }

  // simulate an error
  return ULS_ERR_LOGIN_USED;
}

int
userlist_clnt_login(struct userlist_clnt *clnt,
                    unsigned long origin_ip,
                    int contest_id,
                    int locale_id,
                    int use_cookies,
                    unsigned char const *login,
                    unsigned char const *passwd,
                    int *p_user_id,
                    unsigned long long *p_cookie,
                    unsigned char **p_name,
                    int *p_locale_id)
{
  if (!strcmp(login, "t1")) {
    if (strcmp(passwd, "team1")) return ULS_ERR_INVALID_PASSWORD;
    *p_user_id = 1;
    *p_name = xstrdup("Team 1");
    *p_locale_id = -1;
    if (use_cookies) {
      *p_cookie = 0x0101010101010101;
      return ULS_LOGIN_COOKIE;
    }
    return ULS_LOGIN_OK;
  } else if (!strcmp(login, "t2")) {
    if (strcmp(passwd, "team2")) return ULS_ERR_INVALID_PASSWORD;
    *p_user_id = 2;
    *p_name = xstrdup("Team 2");
    *p_locale_id = -1;
    *p_cookie = 0x0202020202020202;
    return ULS_LOGIN_COOKIE;
  } else if (!strcmp(login, "t3")) {
    if (strcmp(passwd, "team3")) return ULS_ERR_INVALID_PASSWORD;
    *p_user_id = 3;
    *p_name = xstrdup("Team 3");
    *p_locale_id = 1;
    if (use_cookies) {
      *p_cookie = 0x0303030303030303;
      return ULS_LOGIN_COOKIE;
    }
    return ULS_LOGIN_OK;
  } else {
    return ULS_ERR_INVALID_LOGIN;
  }
}

int
userlist_clnt_lookup_cookie(struct userlist_clnt *clnt,
                            unsigned long origin_ip,
                            unsigned long long cookie,
                            int *p_user_id,
                            unsigned char **p_login,
                            unsigned char **p_name,
                            int *p_locale_id,
                            int *p_contest_id)
{
  //if (origin_ip != 0x7f000001) return ULS_ERR_NO_COOKIE;
  if (cookie == 0x0101010101010101) {
    *p_user_id = 1;
    *p_locale_id = 0;
    *p_contest_id = 0;
    *p_login = xstrdup("t1");
    *p_name = xstrdup("Team 1");
    return ULS_OK;
  } else if (cookie == 0x0202020202020202) {
    *p_user_id = 2;
    *p_locale_id = 0;
    *p_contest_id = 0;
    *p_login = xstrdup("t2");
    *p_name = xstrdup("Team 2");
    return ULS_OK;
  } else if (cookie == 0x0303030303030303) {
    *p_user_id = 3;
    *p_locale_id = 1;
    *p_contest_id = 0;
    *p_login = xstrdup("t3");
    *p_name = xstrdup("Team 3");
    return ULS_OK;
  } else {
    return ULS_ERR_NO_COOKIE;
  }
}

int
userlist_clnt_get_login(struct userlist_clnt *clnt,
                        int req_user_id, int my_user_id)
{
}

int
userlist_clnt_get_name(struct userlist_clnt *clnt,
                       int req_user_id, int my_user_id)
{
}

int
userlist_clnt_get_email(struct userlist_clnt *clnt,
                        int uid, unsigned char **p_email)
{
  switch (uid) {
  case 1: *p_email = xstrdup("team1@xxx"); return ULS_EMAIL;
  case 2: *p_email = xstrdup("team2@xxx"); return ULS_EMAIL;
  case 3: *p_email = xstrdup("team3@xxx"); return ULS_EMAIL;
  default:
    return ULS_ERR_BAD_UID;
  }
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
