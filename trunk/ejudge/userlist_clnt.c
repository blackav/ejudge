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

static int
do_userlist_clnt_pass_fd(struct userlist_clnt *clnt,
                         int fds_num,
                         int *fds)
{
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];
  int *fd2;
  int arrsize, val, ret;

  ASSERT(clnt);
  ASSERT(fds_num > 0 && fds_num <= 32);
  ASSERT(fds);

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = msgbuf;
  msg.msg_controllen = sizeof(msgbuf);
  arrsize = sizeof(int) * fds_num;
  pmsg = CMSG_FIRSTHDR(&msg);
  fd2 = (int*) CMSG_DATA(pmsg);
  memcpy(fd2, fds, arrsize);
  pmsg->cmsg_level = SOL_SOCKET;
  pmsg->cmsg_type = SCM_RIGHTS;
  pmsg->cmsg_len = CMSG_LEN(arrsize);
  msg.msg_controllen = CMSG_SPACE(arrsize);
  send_vec[0].iov_base = &val;
  send_vec[0].iov_len = 4;
  msg.msg_iov = send_vec;
  msg.msg_iovlen = 1;
  val = 0;
  ret = sendmsg(clnt->fd, &msg, 0);
  if (ret < 0) {
    err("sendmsg() failed: %s", os_ErrorMsg());
    return -ULS_ERR_WRITE_ERROR;
  }
  if (ret != 4) {
    err("sendmsg() short write: %d bytes", ret);
    return -ULS_ERR_WRITE_ERROR;
  }
  return 0;
}

static int
send_packet(struct userlist_clnt *clnt, int size, void const *buf)
{
  unsigned char *b;
  int w, n;

  ASSERT(clnt);
  ASSERT(size > 0);
  ASSERT(clnt->fd >= 0);

  b = (unsigned char*) alloca(size + 4);
  memcpy(b, &size, 4);          /* FIXME: non-portable */
  memcpy(b + 4, buf, size);
  w = size + 4;

  while (w > 0) {
    n = write(clnt->fd, b, w);
    if (n <= 0) {
      err("write() to userlist-server failed: %s", os_ErrorMsg());
      close(clnt->fd);
      clnt->fd = -1;
      exit(1);                  /* FIXME: do graceful exit! */
      return -ULS_ERR_WRITE_ERROR;
    }
    w -= n; b += n;
  }
  return 0;
}

static int
receive_packet(struct userlist_clnt *clnt, int *p_size, void **p_data)
{
  unsigned char len_buf[4], *b, *bb = 0;
  int r, n;
  int sz;
  int code = 0;

  ASSERT(clnt);
  ASSERT(p_size);
  ASSERT(p_data);
  ASSERT(clnt->fd >= 0);

  *p_size = 0;
  *p_data = 0;

  // read length
  b = len_buf;
  r = 4;
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
      err("read() from userlist-server failed: %s", os_ErrorMsg());
      code = -ULS_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      err("unexpected EOF from userlist-server");
      code = -ULS_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);
  if (sz <= 0) {
    err("invalid packet length %d from userlist-server", sz);
    code = -ULS_ERR_PROTOCOL;
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
      err("read() from userlist-server failed: %s", os_ErrorMsg());
      code = -ULS_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      err("unexpected EOF from userlist-server");
      code = -ULS_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }

  *p_size = sz;
  *p_data = bb;

  return 0;
 io_error:
  if (bb) xfree(bb);
  close(clnt->fd);
  clnt->fd = -1;
  return code;
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
  struct userlist_pk_do_login * data;
  struct userlist_pk_login_ok * answer;
  int len;
  int anslen;
  int res;


  len = sizeof(struct userlist_pk_do_login)+strlen(login)+strlen(passwd)+2;

  data = xcalloc(1,len);
  data->request_id = ULS_DO_LOGIN;
  data->origin_ip = origin_ip;
  data->contest_id = contest_id;
  data->locale_id = locale_id;
  data->use_cookies = use_cookies;
  data->login_length = strlen(login);
  data->password_length = strlen(passwd);
  strcpy(data->data,login);
  strcpy(data->data + data->login_length + 1,passwd);
  send_packet(clnt,len,data);
  free(data);
  receive_packet(clnt,&anslen,(void**) &answer);
  if ((answer->reply_id == ULS_LOGIN_OK)||
      (answer->reply_id == ULS_LOGIN_COOKIE)) {

    *p_user_id = answer->user_id;
    *p_cookie = answer->cookie;
    *p_locale_id = answer->locale_id;
    *p_name = xcalloc(1,answer->name_len + 1);
    strcpy(*p_name,answer->data + answer->login_len);
  }
  res = answer->reply_id;
  free(answer);
  return res;
}

int
userlist_clnt_team_login(struct userlist_clnt *clnt,
                         unsigned long origin_ip,
                         int contest_id,
                         int locale_id,
                         int use_cookies,
                         unsigned char const *login,
                         unsigned char const *passwd,
                         int *p_user_id,
                         unsigned long long *p_cookie,
                         int *p_locale_id,
                         unsigned char **p_name)
{
  struct userlist_pk_do_login *out = 0;
  struct userlist_pk_login_ok *in = 0;
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  int out_size = 0, in_size = 0, r, login_len, passwd_len;

  if (!login || !*login) return -ULS_ERR_INVALID_LOGIN;
  if (!passwd || !*passwd) return -ULS_ERR_INVALID_PASSWORD;
  if ((login_len = strlen(login)) > 255) return -ULS_ERR_INVALID_SIZE;
  if ((passwd_len = strlen(passwd)) > 255) return -ULS_ERR_INVALID_SIZE;
  out_size = sizeof(*out) + login_len + passwd_len + 2;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  passwd_ptr = login_ptr + login_len + 1;
  out->request_id = ULS_TEAM_LOGIN;
  out->origin_ip = origin_ip;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->use_cookies = use_cookies;
  out->login_length = login_len;
  out->password_length = passwd_len;
  strcpy(login_ptr, login);
  strcpy(passwd_ptr, passwd);
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void**) &in)) < 0) return r;
  if (in->reply_id != ULS_LOGIN_OK && in->reply_id != ULS_LOGIN_COOKIE) {
    r = in->reply_id;
    goto cleanup;
  }
  if (in_size < sizeof(*in)) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  login_ptr = in->data;
  if (strlen(login_ptr) != in->login_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  name_ptr = login_ptr + in->login_len + 1;
  if (strlen(name_ptr) != in->name_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  if (in_size != sizeof(*in) + in->login_len + in->name_len + 2) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  *p_user_id = in->user_id;
  *p_cookie = in->cookie;
  *p_locale_id = in->locale_id;
  *p_name = xstrdup(name_ptr);

  r = in->reply_id;
 cleanup:
  xfree(in);
  return r;
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
  struct userlist_pk_check_cookie * data;
  struct userlist_pk_login_ok * answer;
  int len;
  int anslen;
  int res;

  len = sizeof (struct userlist_pk_check_cookie);
  data = xcalloc(1,len);

  data->request_id = ULS_CHECK_COOKIE;
  data->origin_ip = origin_ip;
  //  data->contest_id = contest_id;
  data->cookie = cookie;
  data->locale_id = -1;
  send_packet(clnt,len,data);
  free(data);
  receive_packet(clnt,&anslen,(void**) &answer);
  if (answer->reply_id == ULS_LOGIN_COOKIE) {
    *p_user_id = answer->user_id;
    *p_locale_id = answer->locale_id;
    *p_login = xstrdup(answer->data);
    *p_name = xcalloc(1,answer->name_len + 1);
    *p_contest_id = answer->contest_id;
    strcpy(*p_name,answer->data + answer->login_len + 1);
  }
  res = answer->reply_id;
  free(answer);
  return res;
}

int
userlist_clnt_team_cookie(struct userlist_clnt *clnt,
                          unsigned long origin_ip,
                          int contest_id,
                          unsigned long long cookie,
                          int locale_id,
                          int *p_user_id,
                          int *p_contest_id,
                          int *p_locale_id,
                          unsigned char **p_login,
                          unsigned char **p_name)
{
  struct userlist_pk_check_cookie *out = 0;
  struct userlist_pk_login_ok *in = 0;
  int out_size = 0, in_size = 0, r;
  unsigned char *login_ptr, *name_ptr;

  if (!clnt) return -ULS_ERR_NO_CONNECT;
  if (!origin_ip) return -ULS_ERR_IP_NOT_ALLOWED;
  if (!cookie) return -ULS_ERR_NO_COOKIE;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_TEAM_CHECK_COOKIE;
  out->origin_ip = origin_ip;
  out->contest_id = contest_id;
  out->cookie = cookie;
  out->locale_id = locale_id;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void**) &in)) < 0) return r;
  if (in->reply_id != ULS_LOGIN_COOKIE) {
    r = in->reply_id;
    goto cleanup;
  }
  if (in_size < sizeof(*in)) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  login_ptr = in->data;
  if (strlen(login_ptr) != in->login_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  name_ptr = login_ptr + in->login_len + 1;
  if (strlen(name_ptr) != in->name_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  if (in_size != sizeof(*in) + in->login_len + in->name_len + 2) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  *p_user_id = in->user_id;
  *p_locale_id = in->locale_id;
  *p_contest_id = in->contest_id;
  *p_login = xstrdup(login_ptr);
  *p_name = xstrdup(name_ptr);

  r = in->reply_id;
 cleanup:
  xfree(in);
  return r;



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
  struct userlist_pk_register_new * data;
  int len;
  short * answer;
  int anslen;
  int res;

  len = sizeof(struct userlist_pk_register_new)+strlen(login)+strlen(email)+2;
  data = xcalloc(1,len);
  data->request_id = ULS_REGISTER_NEW;
  data->origin_ip = origin_ip;
  data->contest_id = contest_id;
  data->locale_id = locale_id;
  data->use_cookies = use_cookies;
  data->login_length = strlen(login);
  data->email_length = strlen(email);
  strcpy(data->data,login);
  strcpy(data->data+data->login_length+1,email);
  send_packet(clnt,len,data);
  free(data);
  receive_packet(clnt,&anslen,(void*) &answer);
  res = *answer;
  free(answer);
  return res;
  
}

int
userlist_clnt_get_info(struct userlist_clnt *clnt,
                       int uid, unsigned char **p_info)
{
  struct userlist_pk_get_user_info out_pkt;
  struct userlist_pk_xml_data *in_pkt = 0;
  int in_size;
  int info_len;
  int r;

  ASSERT(clnt);
  ASSERT(clnt->fd >= 0);

  memset(&out_pkt, 0, sizeof(out_pkt));
  out_pkt.request_id = ULS_GET_USER_INFO;
  out_pkt.user_id = uid;
  if ((r = send_packet(clnt, sizeof(out_pkt), &out_pkt)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in_pkt)) < 0) return -r;
  if (!in_size || !in_pkt) return -1;
  if (in_pkt->reply_id != ULS_XML_DATA) {
    r = in_pkt->reply_id;
    xfree(in_pkt);
    return r;
  }
  if (in_size <= sizeof(struct userlist_pk_xml_data)) return -1;
  info_len = strlen(in_pkt->data);
  if (info_len != in_pkt->info_len) {
    xfree(in_pkt);
    return -ULS_ERR_PROTOCOL;
  }
  *p_info = xstrdup(in_pkt->data);
  xfree(in_pkt);
  return ULS_XML_DATA;
}

int
userlist_clnt_list_all_users(struct userlist_clnt *clnt,
                             int contest_id,
                             unsigned char **p_info)
{
  struct userlist_pk_map_contest *out = 0;
  struct userlist_pk_xml_data *in = 0;
  int out_size = 0, in_size = 0, r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_LIST_ALL_USERS;
  out->contest_id = contest_id;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size < sizeof(struct userlist_packet)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (in->reply_id != ULS_XML_DATA) {
    r = in->reply_id;
    xfree(in);
    return r;
  }
  if (in_size < sizeof(struct userlist_pk_xml_data)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (strlen(in->data) != in->info_len) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  *p_info = xstrdup(in->data);
  xfree(in);
  return ULS_XML_DATA;
}

int
userlist_clnt_get_contests(struct userlist_clnt *clnt,
                           int uid, unsigned char **p_info)
{
  struct userlist_pk_get_user_info out_pkt;
  struct userlist_pk_xml_data *in_pkt = 0;
  int in_size;
  int info_len;

  ASSERT(clnt);
  ASSERT(clnt->fd >= 0);

  memset(&out_pkt, 0, sizeof(out_pkt));
  out_pkt.request_id = ULS_GET_USER_CONTESTS;
  out_pkt.user_id = uid;
  if (send_packet(clnt, sizeof(out_pkt), &out_pkt) < 0) return -1;
  if (receive_packet(clnt, &in_size, (void*) &in_pkt) < 0) return -1;
  if (!in_size || !in_pkt) return -1;
  if (in_pkt->reply_id != ULS_XML_DATA) {
    xfree(in_pkt);
    return -1;
  }
  if (in_size <= sizeof(struct userlist_pk_xml_data)) return -1;
  info_len = strlen(in_pkt->data);
  if (info_len != in_pkt->info_len) {
    xfree(in_pkt);
    return -1;
  }
  *p_info = xstrdup(in_pkt->data);
  xfree(in_pkt);
  return ULS_XML_DATA;
}

int
userlist_clnt_set_info(struct userlist_clnt *clnt,
                       int uid, unsigned char *info)
{
  struct userlist_pk_set_user_info *out;
  struct userlist_packet *in = 0;
  int out_size, in_size;
  int r;

  ASSERT(clnt);
  ASSERT(clnt->fd >= 0);
  ASSERT(info);

  out_size = sizeof(*out) + strlen(info) + 1;
  out = (struct userlist_pk_set_user_info*) alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  memset(out, 0, out_size);
  out->request_id = ULS_SET_USER_INFO;
  out->user_id = uid;
  strcpy(out->data, info);
  out->info_len = strlen(info);
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_set_passwd(struct userlist_clnt *clnt,
                         int uid, unsigned char *old_pwd,
                         unsigned char *new_pwd)
{
  struct userlist_pk_set_password *out;
  struct userlist_packet *in;
  int out_size, in_size, old_len, new_len, r;
  unsigned char *pkt_old_ptr;
  unsigned char *pkt_new_ptr;

  ASSERT(clnt);
  ASSERT(old_pwd);
  ASSERT(new_pwd);

  old_len = strlen(old_pwd);
  new_len = strlen(new_pwd);
  if (old_len > 255) return -ULS_ERR_INVALID_SIZE;
  if (new_len > 255) return -ULS_ERR_INVALID_SIZE;
  out_size = sizeof(*out) + old_len + new_len + 2;
  out = (struct userlist_pk_set_password *) alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  memset(out, 0, out_size);
  out->request_id = ULS_SET_PASSWD;
  out->user_id = uid;
  out->old_len = old_len;
  out->new_len = new_len;
  pkt_old_ptr = out->data;
  pkt_new_ptr = pkt_old_ptr + old_len + 1;
  memcpy(pkt_old_ptr, old_pwd, old_len + 1);
  memcpy(pkt_new_ptr, new_pwd, new_len + 1);
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_team_set_passwd(struct userlist_clnt *clnt,
                              int uid, unsigned char *old_pwd,
                              unsigned char *new_pwd)
{
  struct userlist_pk_set_password *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, old_len = 0, new_len = 0, r;
  unsigned char *old_ptr, *new_ptr;

  ASSERT(clnt);
  ASSERT(old_pwd);
  ASSERT(new_pwd);

  old_len = strlen(old_pwd);
  new_len = strlen(new_pwd);
  if (old_len > 255) return -ULS_ERR_INVALID_SIZE;
  if (new_len > 255) return -ULS_ERR_INVALID_SIZE;
  out_size = sizeof(*out) + old_len + new_len + 2;
  out = (struct userlist_pk_set_password *) alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_TEAM_SET_PASSWD;
  out->user_id = uid;
  out->old_len = old_len;
  out->new_len = new_len;
  old_ptr = out->data;
  new_ptr = old_ptr + old_len + 1;
  strcpy(old_ptr, old_pwd);
  strcpy(new_ptr, new_pwd);
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_register_contest(struct userlist_clnt *clnt,
                               int user_id,
                               int contest_id)
{
  struct userlist_pk_register_contest *out;
  struct userlist_packet *in = 0;
  int out_size, in_size = 0, r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  out->request_id = ULS_REGISTER_CONTEST;
  out->user_id = user_id;
  out->contest_id = contest_id;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_remove_member(struct userlist_clnt *clnt,
		            int user_id, int role_id, int pers_id,
			    int serial)
{
  struct userlist_pk_remove_member *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  out->request_id = ULS_REMOVE_MEMBER;
  out->user_id = user_id;
  out->role_id = role_id;
  out->pers_id = pers_id;
  out->serial = serial;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_map_contest(struct userlist_clnt *clnt,
                          int contest_id,
                          int *p_sem_key,
                          int *p_shm_key)
{
  struct userlist_pk_map_contest *out = 0;
  struct userlist_pk_contest_mapped *in = 0;
  int out_size = 0, in_size = 0, r;

  /* FIXME: check args? */

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_MAP_CONTEST;
  out->contest_id = contest_id;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in->reply_id != ULS_CONTEST_MAPPED) {
    r = in->reply_id;
    xfree(in);
    return r;
  }
  *p_sem_key = in->sem_key;
  *p_shm_key = in->shm_key;
  r = in->reply_id;
  xfree(in);
  return r;
}

int
userlist_clnt_pass_fd(struct userlist_clnt *clnt, int nfd, int *fds)
{
  struct userlist_packet *out = 0;
  int out_size = 0;
  int r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  out->id = ULS_PASS_FD;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  return do_userlist_clnt_pass_fd(clnt, nfd, fds);
}

/* FIXME: this function leaks file descriptors */
int
userlist_clnt_list_users(struct userlist_clnt *clnt,
                         unsigned long origin_ip, int contest_id,
                         int locale_id,
                         int user_id,
                         unsigned long flags,
                         unsigned char *url, unsigned char *srch)
{
  struct userlist_pk_list_users *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r;
  size_t url_len, srch_len;
  unsigned char *url_ptr, *srch_ptr;
  int pp[2];
  int pfd[2];
  char b;

  if (pipe(pp) < 0) {
    err("pipe() failed: %s", os_ErrorMsg());
    return -ULS_ERR_WRITE_ERROR;
  }
  pfd[0] = 1;
  pfd[1] = pp[1];

  if (!url) url = "";
  if (!srch) srch = "";
  url_len = strlen(url);
  srch_len = strlen(srch);
  if (url_len > 255) return -ULS_ERR_PROTOCOL;
  if (srch_len > 255) return -ULS_ERR_PROTOCOL;
  if (user_id < 0) return -ULS_ERR_PROTOCOL;
  out_size = sizeof(*out) + url_len + srch_len + 2;
  out = (struct userlist_pk_list_users*) alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  memset(out, 0, sizeof(*out));
  url_ptr = out->data;
  srch_ptr = url_ptr + url_len + 1;
  out->request_id = ULS_LIST_USERS;
  out->origin_ip = origin_ip;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->user_id = user_id;
  out->flags = flags;
  out->url_len = url_len;
  out->srch_len = srch_len;
  memcpy(url_ptr, url, url_len + 1);
  memcpy(srch_ptr, srch, srch_len + 1);

  if ((r = userlist_clnt_pass_fd(clnt, 2, pfd)) < 0) return r;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  if (r < 0) return r;

  close(pfd[1]);
  r = read(pp[0], &b, 1);
  if (r > 0) return -ULS_ERR_PROTOCOL;
  if (r < 0) return -ULS_ERR_READ_ERROR;
  return 0;
}

int
userlist_clnt_admin_process(struct userlist_clnt *clnt)
{
  struct userlist_packet *out = 0, *in = 0;
  size_t out_size = 0, in_size = 0, r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->id = ULS_ADMIN_PROCESS;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_generate_team_passwd(struct userlist_clnt *clnt,
                                   int contest_id, int out_fd)
{
  struct userlist_pk_map_contest *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r;
  int pfd[2], pp[2];

  if (pipe(pp) < 0) {
    err("pipe() failed: %s", os_ErrorMsg());
    return -ULS_ERR_WRITE_ERROR;
  }
  pfd[0] = out_fd;
  pfd[1] = pp[1];

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_GENERATE_TEAM_PASSWORDS;
  out->contest_id = contest_id;
  if ((r = userlist_clnt_pass_fd(clnt, 2, pfd)) < 0) return r;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_change_registration(struct userlist_clnt *clnt,
                                  int user_id,
                                  int contest_id,
                                  int new_status,
                                  int flags_cmd,
                                  unsigned int new_flags)
{
  struct userlist_pk_edit_registration *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_EDIT_REGISTRATION;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->new_status = new_status;
  out->flags_cmd = flags_cmd;
  out->new_flags = new_flags;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_edit_field(struct userlist_clnt *clnt,
                         int user_id,
                         int role,
                         int pers,
                         int field,
                         unsigned char const *value)
{
  struct userlist_pk_edit_field *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r, value_len;

  if (!value) value = "";
  value_len = strlen(value);
  if (value_len > 255) return -ULS_ERR_INVALID_SIZE;
  out_size = sizeof(*out) + value_len + 1;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_EDIT_FIELD;
  out->user_id = user_id;
  out->role = role;
  out->pers = pers;
  out->field = field;
  out->value_len = value_len;
  strcpy(out->data, value);
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_delete_field(struct userlist_clnt *clnt,
                           int user_id,
                           int role,
                           int pers,
                           int field)
{
  struct userlist_pk_edit_field *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r;

  out_size = sizeof(*out) + 1;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_DELETE_FIELD;
  out->user_id = user_id;
  out->role = role;
  out->pers = pers;
  out->field = field;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

int
userlist_clnt_add_field(struct userlist_clnt *clnt,
                        int user_id,
                        int role,
                        int pers,
                        int field)
{
  struct userlist_pk_edit_field *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, r;

  out_size = sizeof(*out) + 1;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_ADD_FIELD;
  out->user_id = user_id;
  out->role = role;
  out->pers = pers;
  out->field = field;
  if ((r = send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = receive_packet(clnt, &in_size, (void*) &in)) < 0) return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
