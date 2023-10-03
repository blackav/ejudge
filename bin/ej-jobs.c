/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/version.h"
#include "ejudge/config.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/startstop.h"
#include "ejudge/xalloc.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/sock_op.h"
#include "ejudge/logger.h"
#include "ejudge/misctext.h"
#include "ejudge/common_plugin.h"
#include "ejudge/telegram.h"
#include "ejudge/xml_utils.h"
#include "ejudge/cJSON.h"
#include "ejudge/bson_utils.h"
#include "ejudge/auth_plugin.h"
#include "ejudge/base64.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/vcs_plugin.h"
#include "ejudge/userprob_plugin.h"
#include "ejudge/exec.h"
#include "ejudge/contests.h"
#include "ejudge/random.h"

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

enum
{
    STATE_READ_CREDS,
    STATE_READ_FDS,
    STATE_READ_LEN,
    STATE_READ_DATA,
    STATE_READ_READY,
    STATE_WRITE,
    STATE_WRITECLOSE,
    STATE_DISCONNECT,
};

typedef void (*command_handler_t)(int uid, int argc, char **argv, void *self);
struct CommandItem
{
    unsigned char *command;
    command_handler_t handler;
    void *self;
};
typedef void (*timer_handler_t)(void *self);
struct TimerItem
{
    timer_handler_t handler;
    void *self;
};

struct AppState;
struct FDInfo;
struct ClientState;
struct ProcessState;

static void
app_state_disarm(struct AppState *as, struct FDInfo *fdi);

struct FDInfoOps
{
    void (*op_read)(struct AppState *as, struct FDInfo *fdi);
    void (*op_write)(struct AppState *as, struct FDInfo *fdi);
};

struct FDInfo
{
    struct FDInfo *prev, *next;
    const struct FDInfoOps *ops;
    struct ClientState *cs;
    struct ProcessState *prc;

    int fd;
    uint32_t events;

    unsigned char *rd_data;
    int rd_size, rd_rsrv;

    unsigned char *wr_data;
    int wr_size, wr_pos;
};

struct ClientState
{
    struct ClientState *prev, *next;
    struct FDInfo *fd;
    struct ClientState *rd_prev, *rd_next;
    unsigned char *read_buf;

    uint32_t client_id;
    int close_flag;
    int data_ready_flag;
    int state;
    int peer_pid;
    int peer_uid;
    int peer_gid;
    int read_len;
    int read_cur;
};

struct ProcessState
{
    struct ProcessState *prev, *next;
    struct ProcessState *rd_prev, *rd_next;
    struct FDInfo *prc_stdin, *prc_stdout, *prc_stderr;

    int pid;
    int is_finished;
    int wait_status;

    int is_notified;
};

struct AppState
{
    struct ejudge_cfg *config;

    unsigned char *job_server_log;
    unsigned char *job_server_spool;
    unsigned char *job_server_work;
    unsigned char *ejudge_socket_dir;
    unsigned char *job_server_socket;
    unsigned char *job_server_spool_watch;

    struct FDInfo *fd_first, *fd_last;
    struct ClientState *client_first, *client_last;
    struct ClientState *rd_first, *rd_last;
    struct ProcessState *prc_first, *prc_last;
    struct ProcessState *rd_prc_first, *rd_prc_last;

    uint32_t client_serial;

    // spool queue files to process
    int inq_a, inq_u;
    unsigned char **inq;

    // fd queue files to process
    int fdq_a, fdq_u;
    int *fdq;

    int cmds_a, cmds_u;
    struct CommandItem *cmds;

    int tmrs_a, tmrs_u;
    struct TimerItem *tmrs;

    // Telegram API plugin
    const struct telegram_plugin_iface *telegram_iface;
    struct telegram_plugin_data *telegram_data;

    // Google Auth plugin
    const struct auth_plugin_iface *auth_google_iface;
    void *auth_google_data;

    // VK Auth plugin
    const struct auth_plugin_iface *auth_vk_iface;
    void *auth_vk_data;

    // Yandex Auth plugin
    const struct auth_plugin_iface *auth_yandex_iface;
    void *auth_yandex_data;

    // Gitlab VCS plugin
    const struct vcs_plugin_iface *vcs_gitlab_iface;
    void *vcs_gitlab_data;

    int child_flag;
    int term_flag;
    int restart_flag;
    int timer_flag;
    int reopen_log_flag;
    int daemon_mode;

    int sfd;
    int tfd;
    int ifd;
    int afd;
    int efd;
    int spool_wd;
};

static struct FDInfo *
fdinfo_create(struct AppState *as, int fd, const struct FDInfoOps *ops)
{
    struct FDInfo *fdi = xcalloc(1, sizeof(*fdi));
    fdi->fd = fd;
    fdi->ops = ops;

    fdi->next = as->fd_first;
    if (!as->fd_first) {
        as->fd_last = fdi;
    } else {
        as->fd_first->prev = fdi;
    }
    as->fd_first = fdi;

    return fdi;
}

static struct FDInfo *
fdinfo_delete(struct FDInfo *fdi)
{
    if (fdi->fd >= 0) close(fdi->fd);
    free(fdi->rd_data);
    free(fdi->wr_data);
    free(fdi);
    return NULL;
}

static void
fdinfo_unlink(struct AppState *as, struct FDInfo *fdi)
{
    if (fdi->prev) {
        fdi->prev->next = fdi->next;
    } else {
        as->fd_first = fdi->next;
    }
    if (fdi->next) {
        fdi->next->prev = fdi->prev;
    } else {
        as->fd_last = fdi->prev;
    }
    fdi->prev = fdi->next = NULL;
}

static struct ClientState *
client_create(struct AppState *as)
{
    struct ClientState *cls = xcalloc(1, sizeof(*cls));

    cls->next = as->client_first;
    if (!as->client_first) {
        as->client_last = cls;
    } else {
        as->client_first->prev = cls;
    }
    as->client_first = cls;

    return cls;
}

static struct ClientState *
client_delete(struct ClientState *cs)
{
    free(cs->read_buf);
    free(cs);
    return NULL;
}

static void
client_unlink(struct AppState *as, struct ClientState *cls)
{
    if (cls->prev) {
        cls->prev->next = cls->next;
    } else {
        as->client_first = cls->next;
    }
    if (cls->next) {
        cls->next->prev = cls->prev;
    } else {
        as->client_last = cls->prev;
    }
    cls->prev = cls->next = NULL;
}

static void
client_mark_ready(struct AppState *as, struct ClientState *cs)
{
    cs->rd_prev = as->rd_last;
    cs->rd_next = NULL;
    if (cs->rd_prev) {
        cs->rd_prev->rd_next = cs;
    } else {
        as->rd_first = cs;
    }
    as->rd_last = cs;
}

static struct ProcessState *
process_state_create(struct AppState *as)
{
    struct ProcessState *prc = xcalloc(1, sizeof(*prc));

    prc->next = as->prc_first;
    if (!as->prc_first) {
        as->prc_last = prc;
    } else {
        as->prc_first->prev = prc;
    }
    as->prc_first = prc;

    return prc;
}

static struct ProcessState *
process_state_delete(struct ProcessState *prc)
{
    free(prc);
    return NULL;
}

static void
process_state_unlink(struct AppState *as, struct ProcessState *prc)
{
    if (prc->prev) {
        prc->prev->next = prc->next;
    } else {
        as->prc_first = prc->next;
    }
    if (prc->next) {
        prc->next->prev = prc->prev;
    } else {
        as->prc_last = prc->prev;
    }
    prc->prev = prc->next = NULL;
}

static void
process_state_notify(struct AppState *as, struct ProcessState *prc)
{
    if (prc->is_notified) return;

    prc->is_notified = 1;
    prc->rd_prev = as->rd_prc_last;
    prc->rd_next = NULL;
    if (prc->rd_prev) {
        prc->rd_prev->rd_next = prc;
    } else {
        as->rd_prc_first = prc;
    }
    as->rd_prc_last = prc;

}

static void
app_state_init(struct AppState *as)
{
    memset(as, 0, sizeof(*as));

    as->sfd = -1;
    as->tfd = -1;
    as->ifd = -1;
    as->afd = -1;
    as->efd = -1;
    as->spool_wd = -1;
}

static void
app_state_destroy(struct AppState *as)
{
    if (as->efd >= 0) close(as->efd);
    if (as->afd >= 0) close(as->afd);
    if (as->ifd >= 0) close(as->ifd);
    if (as->tfd >= 0) close(as->tfd);
    if (as->sfd >= 0) close(as->sfd);

    if (as->job_server_socket) unlink(as->job_server_socket);
}

static void
app_add_command_handler(struct AppState *as, const unsigned char *cmd, command_handler_t handler, void *self)
{
    if (as->cmds_a == as->cmds_u) {
        if (!(as->cmds_a *= 2)) as->cmds_a = 32;
        as->cmds = xrealloc(as->cmds, as->cmds_a * sizeof(as->cmds[0]));
    }
    struct CommandItem *item = &as->cmds[as->cmds_u++];
    item->command = xstrdup(cmd);
    item->handler = handler;
    item->self = self;
}

static void
add_handler_wrapper(
        void *self,
        const unsigned char *cmd,
        tg_command_handler_t handler,
        void *tg_self)
{
    app_add_command_handler((struct AppState *) self, cmd, handler, tg_self);
}

static struct CommandItem *
app_find_command_handler(struct AppState *as, const unsigned char *cmd)
{
    for (int i = 0; i < as->cmds_u; ++i) {
        struct CommandItem *item = &as->cmds[i];
        if (!strcmp(item->command, cmd)) {
            return item;
        }
    }
    return NULL;
}

static void
app_add_timer_handler(struct AppState *as, timer_handler_t handler, void *self)
{
    if (as->tmrs_a == as->tmrs_u) {
        if (!(as->tmrs_a *= 2)) as->tmrs_a = 32;
        as->tmrs = xrealloc(as->tmrs, as->tmrs_a * sizeof(as->tmrs[0]));
    }
    struct TimerItem *item = &as->tmrs[as->tmrs_u++];
    item->handler = handler;
    item->self = self;
}

static void
add_timer_wrapper(
        void *self,
        tg_timer_handler_t handler,
        void *tg_self)
{
    app_add_timer_handler((struct AppState*) self, handler, tg_self);
}

static void
signal_read_func(struct AppState *as, struct FDInfo *fdi)
{
    while (1) {
        struct signalfd_siginfo sss;
        errno = 0;
        int r = read(fdi->fd, &sss, sizeof(sss));
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("signal_read_func: read failed: %s", os_ErrorMsg());
            break;
        }
        if (r != sizeof(sss)) {
            err("signal_read_func: read returned invalid size %d", r);
            break;
        }
        switch (sss.ssi_signo) {
        case SIGHUP:  as->restart_flag = 1; break;
        case SIGINT:  as->term_flag = 1; break;
        case SIGTERM: as->term_flag = 1; break;
        case SIGCHLD: as->child_flag = 1; break;
        case SIGUSR1: as->reopen_log_flag = 1; break;
        default:
            err("signal_read_func: unexpected signal %d", sss.ssi_signo);
            break;
        }
    }
}

static const struct FDInfoOps signal_ops =
{
    .op_read = signal_read_func,
};

static void
timer_read_func(struct AppState *as, struct FDInfo *fdi)
{
    while (1) {
        uint64_t value;
        errno = 0;
        int r = read(fdi->fd, &value, sizeof(value));
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("timer_read_func: read failed: %s", os_ErrorMsg());
            break;
        }
        if (r != sizeof(value)) {
            err("timer_read_func: invalid read size %d", r);
            break;
        }
        as->timer_flag = 1;
    }
}

static const struct FDInfoOps timer_ops =
{
    .op_read = timer_read_func,
};

static __attribute__((unused)) const unsigned char *
inotify_mask_to_string(unsigned char *buf, uint32_t mask)
{
    char *p = buf;
    char *s = "";
    if ((mask & IN_ACCESS)) {
        p = stpcpy(stpcpy(p, s), "ACCESS"); s = "|";
    }
    if ((mask & IN_ATTRIB)) {
        p = stpcpy(stpcpy(p, s), "ATTRIB"); s = "|";
    }
    if ((mask & IN_CLOSE_WRITE)) {
        p = stpcpy(stpcpy(p, s), "CLOSE_WRITE"); s = "|";
    }
    if ((mask & IN_CLOSE_NOWRITE)) {
        p = stpcpy(stpcpy(p, s), "CLOSE_NOWRITE"); s = "|";
    }
    if ((mask & IN_CREATE)) {
        p = stpcpy(stpcpy(p, s), "CREATE"); s = "|";
    }
    if ((mask & IN_DELETE)) {
        p = stpcpy(stpcpy(p, s), "DELETE"); s = "|";
    }
    if ((mask & IN_DELETE_SELF)) {
        p = stpcpy(stpcpy(p, s), "DELETE_SELF"); s = "|";
    }
    if ((mask & IN_MODIFY)) {
        p = stpcpy(stpcpy(p, s), "MODIFY"); s = "|";
    }
    if ((mask & IN_MOVE_SELF)) {
        p = stpcpy(stpcpy(p, s), "MOVE_SELF"); s = "|";
    }
    if ((mask & IN_MOVED_FROM)) {
        p = stpcpy(stpcpy(p, s), "MOVED_FROM"); s = "|";
    }
    if ((mask & IN_MOVED_TO)) {
        p = stpcpy(stpcpy(p, s), "MOVED_TO"); s = "|";
    }
    if ((mask & IN_OPEN)) {
        p = stpcpy(stpcpy(p, s), "OPEN"); s = "|";
    }
    if ((mask & IN_IGNORED)) {
        p = stpcpy(stpcpy(p, s), "IGNORED"); s = "|";
    }
    if ((mask & IN_ISDIR)) {
        p = stpcpy(stpcpy(p, s), "ISDIR"); s = "|";
    }
    if ((mask & IN_Q_OVERFLOW)) {
        p = stpcpy(stpcpy(p, s), "Q_OVERFLOW"); s = "|";
    }
    if ((mask & IN_UNMOUNT)) {
        p = stpcpy(stpcpy(p, s), "UNMOUNT"); s = "|";
    }
    return buf;
}

static void
inotify_read_func(struct AppState *as, struct FDInfo *fdi)
{
    while (1) {
        unsigned char buf[4096];
	__attribute__((unused)) unsigned char sbuf[4096];
        errno = 0;
        int r = read(fdi->fd, buf, sizeof(buf));
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("inotify_read_func: read failed: %s", os_ErrorMsg());
            break;
        }
        if (!r) {
            err("inotify_read_func: read returned 0");
            break;
        }
        const unsigned char *bend = buf + r;
        const unsigned char *p = buf;
        while (p < bend) {
            const struct inotify_event *ev = (const struct inotify_event *) p;
            p += sizeof(*ev) + ev->len;
	    //fprintf(stderr, "inotify event: %d,%s,%s\n", ev->wd, inotify_mask_to_string(sbuf, ev->mask), ev->name);
            if (as->spool_wd != ev->wd) {
                err("inotify_read_func: unknown watch descriptor %d", ev->wd);
                continue;
            }
            if ((ev->mask & IN_MOVED_TO) != 0) {
                if (as->inq_u == as->inq_a) {
                    if (!(as->inq_a *= 2)) as->inq_a = 32;
                    as->inq = xrealloc(as->inq, as->inq_a * sizeof(as->inq[0]));
                }
                as->inq[as->inq_u++] = xstrdup(ev->name);
            }
        }
        if (p >  bend) {
            err("inotify_read_func: buffer overrun: end = %p, cur = %p", bend, p);
        }
    }
}

static const struct FDInfoOps inotify_ops =
{
    .op_read = inotify_read_func,
};

static void
accept_read_func(struct AppState *as, struct FDInfo *fdi)
{
    while (1) {
        struct sockaddr_un addr = {};
        int addrlen = sizeof(addr);

        errno = 0;
        int fd = accept4(fdi->fd, (struct sockaddr*) &addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0 && errno == EAGAIN) {
            break;
        }
        if (fd < 0) {
            err("accept_read_func: accept failed: %s", os_ErrorMsg());
            break;
        }

        int val = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
            err("accept_read_func: setsockopt failed: %s", os_ErrorMsg());
        }

        if (as->fdq_a == as->fdq_u) {
            if (!(as->fdq_a *= 2)) as->fdq_a = 32;
            as->fdq = xrealloc(as->fdq, as->fdq_a * sizeof(as->fdq[0]));
        }
        as->fdq[as->fdq_u++] = fd;
    }
}

static const struct FDInfoOps accept_ops =
{
    .op_read = accept_read_func,
};

static void
socket_read_func(struct AppState *as, struct FDInfo *fdi)
{
    struct ClientState *cs = fdi->cs;

    switch (cs->state) {
    case STATE_READ_CREDS:
        if (sock_op_get_creds(fdi->fd, cs->client_id,
                              &cs->peer_pid,
                              &cs->peer_uid,
                              &cs->peer_gid) < 0) {
            goto fail;
        }
        cs->state = STATE_READ_LEN;
        break;
    case STATE_READ_LEN: {
        int len = 0;
        int r = read(fdi->fd, &len, sizeof(len));
        if (r < 0) {
            err("socket_read_func: %d: read failed: %s", cs->client_id, os_ErrorMsg());
            goto fail;
        }
        if (!r) {
            goto fail;
        }
        if (r != sizeof(len)) {
            err("socket_read_func: %d: invalid read size: %d", cs->client_id, r);
            goto fail;
        }
        if (len <= 0 || len > 1024 * 1024) {
            err("socket_read_func: %d: bad packet length: %d", cs->client_id, len);
            goto fail;
        }
        if (cs->read_buf) xfree(cs->read_buf);
        cs->read_buf = xmalloc(len + 1);
        cs->read_len = len;
        cs->read_cur = 0;
        cs->state = STATE_READ_DATA;
        break;
    }
    case STATE_READ_DATA: {
        int len = cs->read_len - cs->read_cur;
        int r = read(fdi->fd, cs->read_buf + cs->read_cur, len);
        if (r < 0) {
            err("socket_read_func: %d: read failed: %s", cs->client_id, os_ErrorMsg());
            goto fail;
        }
        if (!r) {
            err("socket_read_func: %d: unexpected EOF", cs->client_id);
            goto fail;
        }
        cs->read_cur += r;
        if (cs->read_cur == cs->read_len) {
            cs->data_ready_flag = 1;
            client_mark_ready(as, cs);
        }
        break;
    }
    }
    return;

fail:
    cs->close_flag = 1;
    client_mark_ready(as, cs);
}

static const struct FDInfoOps socket_ops =
{
    .op_read = socket_read_func,
};

static void
pipe_read_func(struct AppState *as, struct FDInfo *fdi)
{
    char buf[65536];
    while (1) {
        errno = 0;
        int r = read(fdi->fd, buf, sizeof(buf));
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("pipe_read_func: read failed: %s", os_ErrorMsg());
            goto done;
        }
        if (!r) {
            goto done;
        }

        int exp_size = fdi->rd_size + r + 1;
        if (exp_size >= fdi->rd_rsrv) {
            int exp_rsrv = fdi->rd_rsrv * 2;
            if (!exp_rsrv) exp_rsrv = 32;
            while (exp_rsrv < exp_size) exp_rsrv *= 2;
            fdi->rd_data = xrealloc(fdi->rd_data, exp_rsrv);
            fdi->rd_rsrv = exp_rsrv;
        }
        memcpy(fdi->rd_data + fdi->rd_size, buf, r);
        fdi->rd_size += r;
        fdi->rd_data[fdi->rd_size] = 0;
    }
    return;

done:
    app_state_disarm(as, fdi);
    close(fdi->fd); fdi->fd = -1;
    process_state_notify(as, fdi->prc);
}

static void
pipe_write_func(struct AppState *as, struct FDInfo *fdi)
{
    while (1) {
        int wsz = fdi->wr_size - fdi->wr_pos;
        if (wsz <= 0) {
            goto done;
        }
        errno = 0;
        int r = write(fdi->fd, fdi->wr_data + fdi->wr_pos, wsz);
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("pipe_write_func: write failed: %s", os_ErrorMsg());
            goto done;
        }
        if (!r) {
            err("pipe_write_func: write returned 0");
            goto done;
        }
        fdi->wr_pos += r;
    }
    return;

done:
    app_state_disarm(as, fdi);
    close(fdi->fd); fdi->fd = -1;
    process_state_notify(as, fdi->prc);
}

static const struct FDInfoOps pipe_ops =
{
    .op_read = pipe_read_func,
    .op_write = pipe_write_func,
};

static void
app_state_arm_for_read(struct AppState *as, struct FDInfo *fdi)
{
    if ((fdi->events & EPOLLIN) != 0) return;

    if (!fdi->events) {
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = fdi };
        if (epoll_ctl(as->efd, EPOLL_CTL_ADD, fdi->fd, &ev) < 0) {
            err("epoll_ctl failed: %s", os_ErrorMsg());
            return;
        }
        fdi->events = EPOLLIN;
    }

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_MOD, fdi->fd, &ev) < 0) {
        err("epoll_ctl failed: %s", os_ErrorMsg());
        return;
    }
    fdi->events = EPOLLIN;
}

static void
app_state_arm_for_write(struct AppState *as, struct FDInfo *fdi)
{
    if ((fdi->events & EPOLLOUT) != 0) return;

    if (!fdi->events) {
        struct epoll_event ev = { .events = EPOLLOUT, .data.ptr = fdi };
        if (epoll_ctl(as->efd, EPOLL_CTL_ADD, fdi->fd, &ev) < 0) {
            err("epoll_ctl failed: %s", os_ErrorMsg());
            return;
        }
        fdi->events = EPOLLOUT;
    }

    struct epoll_event ev = { .events = EPOLLOUT, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_MOD, fdi->fd, &ev) < 0) {
        err("epoll_ctl failed: %s", os_ErrorMsg());
        return;
    }
    fdi->events = EPOLLOUT;
}

static void
app_state_disarm(struct AppState *as, struct FDInfo *fdi)
{
    if (!fdi->events) return;

    struct epoll_event ev = { .events = 0, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_DEL, fdi->fd, &ev) < 0) {
        err("epoll_ctl failed: %s", os_ErrorMsg());
        return;
    }
    fdi->events = 0;
}

static void dummy_handler(int s) {}

static int
app_state_prepare(struct AppState *as)
{
    sigaction(SIGINT, &(struct sigaction) { .sa_handler = dummy_handler }, NULL);
    sigaction(SIGTERM, &(struct sigaction) { .sa_handler = dummy_handler }, NULL);
    sigaction(SIGHUP, &(struct sigaction) { .sa_handler = dummy_handler }, NULL);
    sigaction(SIGUSR1, &(struct sigaction) { .sa_handler = dummy_handler }, NULL);

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGHUP);
    sigaddset(&ss, SIGCHLD);
    sigaddset(&ss, SIGUSR1);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    if ((as->sfd = signalfd(-1, &ss, SFD_CLOEXEC | SFD_NONBLOCK)) < 0) {
        err("signalfd failed: %s", os_ErrorMsg());
        return -1;
    }

    if ((as->tfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK)) < 0) {
        err("timerfd_create failed: %s", os_ErrorMsg());
        return -1;
    }

    {
        struct itimerspec spec =
        {
            .it_interval =
            {
                .tv_sec = 10,
                .tv_nsec = 0,
            },
            .it_value =
            {
                .tv_sec = 10,
                .tv_nsec = 0,
            },
        };
        if (timerfd_settime(as->tfd, 0, &spec, NULL) < 0) {
            err("timerfd_settime failed: %s", os_ErrorMsg());
            return -1;
        }
    }

    if ((as->ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK)) < 0) {
        err("inotify_init1 failed: %s", os_ErrorMsg());
        return -1;
    }

    if ((as->spool_wd = inotify_add_watch(as->ifd, as->job_server_spool_watch, IN_CREATE | IN_MOVED_TO)) < 0) {
        err("inotify_add_watch failed: %s", os_ErrorMsg());
        return -1;
    }

    if ((as->afd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) < 0) {
        err("socket failed: %s", os_ErrorMsg());
        return -1;
    }

    {
        struct sockaddr_un addr = {};

        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", as->job_server_socket);

        // remove stale socket file
        unlink(as->job_server_socket);

        if (bind(as->afd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            err("bind failed: %s", os_ErrorMsg());
            return -1;
        }
    }

    if (listen(as->afd, 5) < 0) {
        err("listen failed: %s", os_ErrorMsg());
        return -1;
    }

    if ((as->efd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        err("epoll_create failed: %s", os_ErrorMsg());
        return -1;
    }

    struct FDInfo *fdi = fdinfo_create(as, as->sfd, &signal_ops);
    app_state_arm_for_read(as, fdi);

    fdi = fdinfo_create(as, as->tfd, &timer_ops);
    app_state_arm_for_read(as, fdi);

    fdi = fdinfo_create(as, as->ifd, &inotify_ops);
    app_state_arm_for_read(as, fdi);

    fdi = fdinfo_create(as, as->afd, &accept_ops);
    app_state_arm_for_read(as, fdi);

    return 0;
}

static int
make_path_in_var_dir(
        unsigned char *buf,
        struct AppState *as,
        const unsigned char *file)
{
#if defined EJUDGE_LOCAL_DIR
    snprintf(buf, PATH_MAX, "%s/%s", EJUDGE_LOCAL_DIR, file);
#else
    if (!as->config->var_dir || !os_IsAbsolutePath(as->config->var_dir)) {
        err("<var_dir> is not set or not an absolute path");
        return -1;
    }
    snprintf(buf, PATH_MAX, "%s/%s", as->config->var_dir, file);
#endif
    return 0;
}

static int
prepare_config_vars(struct AppState *as)
{
    char buf[PATH_MAX];
    __attribute__((unused)) int _;

    if (as->config->job_server_log) {
        if (os_IsAbsolutePath(as->config->job_server_log)) {
            as->job_server_log = xstrdup(as->config->job_server_log);
        } else {
            if (make_path_in_var_dir(buf, as, as->config->job_server_log) < 0) {
                return -1;
            }
            as->job_server_log = xstrdup(buf);
        }
    } else {
        _ = asprintf((char**) &as->job_server_log, "%s/%s", as->config->var_dir, "ej-jobs.log");
    }

    if (as->config->job_server_spool) {
        if (os_IsAbsolutePath(as->config->job_server_spool)) {
            as->job_server_spool = xstrdup(as->config->job_server_spool);
        } else {
            if (make_path_in_var_dir(buf, as, as->config->job_server_spool) < 0)
                return -1;
            as->job_server_spool = xstrdup(buf);
        }
    } else {
        if (make_path_in_var_dir(buf, as, "jspool") < 0)
            return -1;
        as->job_server_spool = xstrdup(buf);
    }
    _ = asprintf((char**) &as->job_server_spool_watch, "%s/dir", as->job_server_spool);

    if (as->config->job_server_work) {
        if (os_IsAbsolutePath(as->config->job_server_work)) {
            as->job_server_work = xstrdup(as->config->job_server_work);
        } else {
            if (make_path_in_var_dir(buf, as, as->config->job_server_work) < 0)
                return -1;
            as->job_server_work = xstrdup(buf);
        }
    } else {
        if (make_path_in_var_dir(buf, as, "jwork") < 0)
            return -1;
        as->job_server_work = xstrdup(buf);
    }

#if defined EJUDGE_LOCAL_DIR
    _ = asprintf((char**) &as->ejudge_socket_dir, "%s/%s",
                 EJUDGE_LOCAL_DIR, "sockets");
#else
    if (!as->config->var_dir || !os_IsAbsolutePath(as->config->var_dir)) {
        err("<var_dir> is not set or not an absolute path");
        return -1;
    }
    _ = asprintf((char**) &as->ejudge_socket_dir, "%s/%s", as->config->var_dir, "socket");
#endif

    _ = asprintf((char **) &as->job_server_socket, "%s/%s", as->ejudge_socket_dir, "jobs");

    if (make_dir(as->ejudge_socket_dir, 0) < 0) return -1;
    if (make_dir(as->job_server_work, 0) < 0) return -1;
    if (make_all_dir(as->job_server_spool, 0) < 0) return -1;

    return 0;
}

static void
accept_new_client(struct AppState *as, int fd)
{
    struct ClientState *cs = client_create(as);
    cs->fd = fdinfo_create(as, fd, &socket_ops);
    cs->fd->cs = cs;
    cs->client_id = ++as->client_serial;
    cs->state = STATE_READ_CREDS;
    app_state_arm_for_read(as, cs->fd);
}

static void
close_client(struct AppState *as, struct ClientState *cs)
{
    app_state_disarm(as, cs->fd);
    fdinfo_unlink(as, cs->fd);
    cs->fd = fdinfo_delete(cs->fd);

    client_unlink(as, cs);
    client_delete(cs);
}

static int
parse_incoming_packet(
        const char *data,
        size_t length,
        int *p_argc,
        char ***p_argv);

static void
process_data(struct AppState *as, struct ClientState *cs)
{
    int argc = 0;
    char **argv = NULL;

    while (1) {
        if (parse_incoming_packet(cs->read_buf, cs->read_len, &argc, &argv) < 0) {
            err("packet parsing error");
            break;
        }
        if (!argc || !argv || !argv[0]) {
            err("empty packet");
            break;
        }
        struct CommandItem *item = app_find_command_handler(as, argv[0]);
        if (!item) {
            err("invalid command '%s'", argv[0]);
            break;
        }

        item->handler(cs->peer_uid, argc, argv, item->self);
        break;
    }

    for (int i = 0; i < argc; ++i) {
        free(argv[i]);
    }
    free(argv);

    // prepare for the next command
    cs->data_ready_flag = 0;
    cs->close_flag = 0;
    cs->state = STATE_READ_LEN;
    app_state_arm_for_read(as, cs->fd);
}

static int
parse_incoming_packet(
        const char *data,
        size_t length,
        int *p_argc,
        char ***p_argv)
{
    int argc = 0, i;
    char **argv = 0;
    int *argl;
    int arglength;

    if (length < sizeof(argc)) {
        err("packet is too small");
        return -1;
    }
    memcpy(&argc, data, sizeof(argc));
    data += sizeof(argc); length -= sizeof(argc);
    if (argc <= 0 || argc > 100) {
        err("bad number of arguments");
        return -1;
    }

    XCALLOC(argv, argc + 1);
    XALLOCAZ(argl, argc);

    if (argc * sizeof(argl[0]) > length) {
        err("packet is too small");
        goto failure;
    }
    memcpy(argl, data, argc * sizeof(argl[0]));
    data += argc * sizeof(argl[0]);
    length -= argc * sizeof(argl[0]);
    for (i = 0, arglength = 0; i < argc; i++) {
        if (argl[i] < 0 || argl[i] > 65535) {
            err("invalid argument length");
            goto failure;
        }
        arglength += argl[i];
        argv[i] = xmalloc(argl[i] + 1);
    }
    if (arglength != length) {
        err("invalid argument length");
        goto failure;
    }
    for (i = 0; i < argc; i++) {
        memcpy(argv[i], data, argl[i]);
        argv[i][argl[i]] = 0;
        data += argl[i]; length -= argl[i];
    }
    *p_argc = argc;
    *p_argv = argv;
    return 0;

failure:
    if (argv) {
        for (i = 0; i < argc; i++)
            xfree(argv[i]);
        xfree(argv);
    }
    return -1;
}

static void
process_job_file(struct AppState *as, const unsigned char *name)
{
    char *req_buf = NULL;
    size_t req_buf_size = 0;
    unsigned char pkt_path[PATH_MAX];
    int argc = 0;
    char **argv = NULL;

    snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s", as->job_server_spool, name);

    struct stat stb;
    if (lstat(pkt_path, &stb) < 0) return;
    if (!S_ISREG(stb.st_mode)) {
        unlink(pkt_path);
        return;
    }

    int r = generic_read_file(&req_buf, 0, &req_buf_size, SAFE | REMOVE, as->job_server_spool, name, "");
    if (r <= 0) {
        return;
    }

    if (parse_incoming_packet(req_buf, req_buf_size, &argc, &argv) < 0) {
        err("packet parsing error");
        goto done;
    }
    if (!argc || !argv || !argv[0]) {
        err("empty packet");
        goto done;
    }

    struct CommandItem *item = app_find_command_handler(as, argv[0]);
    if (!item) {
        err("invalid command '%s'", argv[0]);
        goto done;
    }

    item->handler(stb.st_uid, argc, argv, item->self);

done:
    free(req_buf);
    for (int i = 0; i < argc; ++i)
        free(argv[i]);
    free(argv);
}

static void
process_timer_event(struct AppState *as)
{
    for (int i = 0; i < as->tmrs_u; ++i) {
        struct TimerItem *item = &as->tmrs[i];
        item->handler(item->self);
    }

    char pkt_name[256];
    if (scan_dir(as->job_server_spool, pkt_name, sizeof(pkt_name), 0) > 0) {
        if (as->inq_u == as->inq_a) {
            if (!(as->inq_a *= 2)) as->inq_a = 32;
            as->inq = xrealloc(as->inq, as->inq_a * sizeof(as->inq[0]));
        }
        as->inq[as->inq_u++] = xstrdup(pkt_name);
    }
}

static void
process_child_event(struct AppState *as)
{
    int pid, status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        struct ProcessState *prc = NULL;
        for (prc = as->prc_first; prc; prc = prc->next) {
            if (prc->pid == pid) break;
        }
        if (!prc) {
            err("process with pid %d not found", pid);
            continue;
        }
        prc->is_finished = 1;
        prc->wait_status = status;
        process_state_notify(as, prc);
    }
}

static void
run_process(struct AppState *as, char * const *args, const char *stdin_buf)
{
    int p0[2] = { -1, -1 };
    int p1[2] = { -1, -1 };
    int p2[2] = { -1, -1 };
    struct FDInfo *fdi_stdin = NULL;
    struct FDInfo *fdi_stdout = NULL;
    struct FDInfo *fdi_stderr = NULL;
    struct ProcessState *prc = NULL;

    if (pipe2(p0, O_CLOEXEC) < 0) {
        err("run_process: pipe failed: %s", os_ErrorMsg());
        goto done;
    }
    if (pipe2(p1, O_CLOEXEC) < 0) {
        err("run_process: pipe failed: %s", os_ErrorMsg());
        goto done;
    }
    if (pipe2(p2, O_CLOEXEC) < 0) {
        err("run_process: pipe failed: %s", os_ErrorMsg());
        goto done;
    }
    int pid = fork();
    if (pid < 0) {
        err("run_process: fork failed: %s", os_ErrorMsg());
        goto done;
    }
    if (!pid) {
        sigset_t es;
        sigemptyset(&es);
        sigprocmask(SIG_SETMASK, &es, NULL);
        dup2(p0[0], 0);
        dup2(p1[1], 1);
        dup2(p2[1], 2);
        execv(args[0], args);
        err("run_process: execv() failed for '%s': %s", args[0], os_ErrorMsg());
        _exit(1);
    }

    close(p0[0]); p0[0] = -1;
    close(p1[1]); p1[1] = -1;
    close(p2[1]); p2[1] = -1;
    fcntl(p0[1], F_SETFL, fcntl(p0[1], F_GETFL) | O_NONBLOCK);
    fcntl(p1[0], F_SETFL, fcntl(p1[0], F_GETFL) | O_NONBLOCK);
    fcntl(p2[0], F_SETFL, fcntl(p2[0], F_GETFL) | O_NONBLOCK);

    fdi_stdin = fdinfo_create(as, p0[1], &pipe_ops); p0[1] = -1;
    fdi_stdin->wr_data = xstrdup(stdin_buf);
    fdi_stdin->wr_size = strlen(stdin_buf);
    app_state_arm_for_write(as, fdi_stdin);

    fdi_stdout = fdinfo_create(as, p1[0], &pipe_ops); p1[0] = -1;
    fdi_stdout->rd_data = xmalloc(fdi_stdout->rd_rsrv = 16);
    fdi_stdout->rd_data[0] = 0;
    app_state_arm_for_read(as, fdi_stdout);

    fdi_stderr = fdinfo_create(as, p2[0], &pipe_ops); p2[0] = -1;
    fdi_stderr->rd_data = xmalloc(fdi_stderr->rd_rsrv = 16);
    fdi_stderr->rd_data[0] = 0;
    app_state_arm_for_read(as, fdi_stderr);

    prc = process_state_create(as);
    prc->prc_stdin = fdi_stdin; fdi_stdin->prc = prc; fdi_stdin = NULL;
    prc->prc_stdout = fdi_stdout; fdi_stdout->prc = prc; fdi_stdout = NULL;
    prc->prc_stderr = fdi_stderr; fdi_stderr->prc = prc; fdi_stderr = NULL;
    prc->pid = pid;

    return;

done:
    if (p0[0] >= 0) close(p0[0]);
    if (p0[1] >= 0) close(p0[1]);
    if (p1[0] >= 0) close(p1[0]);
    if (p1[1] >= 0) close(p1[1]);
    if (p2[0] >= 0) close(p2[0]);
    if (p2[1] >= 0) close(p2[1]);
}

/*
 * [0] - "mail"
 * [1] - charset
 * [2] - subject
 * [3] - from
 * [4] - to
 * [5] - text
 */
static void
handle_mail_packet(int uid, int argc, char **argv, void *user)
{
    struct AppState *as = (struct AppState *) user;
    char *full_s = NULL;
    size_t full_z = 0;
    FILE *full_f = NULL;

    ASSERT(as->config->email_program);

    if (argc != 6) {
        err("mail: invalid number of arguments");
        goto cleanup;
    }

    const unsigned char *charset = NULL;
    if (argv[1][0]) charset = argv[1];
    if (!charset) charset = EJUDGE_CHARSET;

    if (!argv[3] || !*argv[3]) {
        err("mail: source email address is empty");
        goto cleanup;
    }
    if (!is_valid_email_address(argv[3])) {
        err("mail: source email address is invalid");
        goto cleanup;
    }
    if (!argv[4] || !*argv[4]) {
        err("mail: destination email address is empty");
        goto cleanup;
    }
    if (!is_valid_email_address(argv[4])) {
        err("mail: destination email address is invalid");
        goto cleanup;
    }

    time_t cur_time = time(0);
    struct tm ltm;
    localtime_r(&cur_time, &ltm);
    unsigned char date_buf[128];
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S %z", &ltm);

    full_f = open_memstream(&full_s, &full_z);
    fprintf(full_f,
            "Date: %s\n"
            "Content-type: text/plain; charset=\"%s\"\n"
            "To: %s\n"
            "From: %s\n"
            "Subject: %s\n"
            "\n"
            "%s\n",
            date_buf, charset, argv[4], argv[3], argv[2], argv[5]);
    fclose(full_f); full_f = NULL;

    char *prc_args[10];
    if (strstr(as->config->email_program, "sendmail")) {
        prc_args[0] = as->config->email_program;
        prc_args[1] = "-B8BITMIME";
        //    prc_args[2] = "-ba";
        prc_args[2] = "-t";
        prc_args[3] = NULL;
    } else {
        prc_args[0] = as->config->email_program;
        prc_args[1] = NULL;
    }

    run_process(as, prc_args, full_s);

cleanup:;
    if (full_f) fclose(full_f);
    xfree(full_s);
}

static void
handle_stop_packet(int uid, int argc, char **argv, void *user)
{
  if (uid != 0 && uid != getuid()) {
    err("stop: permission denied for user %d", uid);
    return;
  }
  raise(SIGTERM);
}

static void
handle_restart_packet(int uid, int argc, char **argv, void *user)
{
  if (uid != 0 && uid != getuid()) {
    err("stop: permission denied for user %d", uid);
    return;
  }
  raise(SIGHUP);
}

static void
handle_nop_packet(int uid, int argc, char **argv, void *user)
{
    info("NOP packet");
}

static void
handle_process_notification(struct AppState *as, struct ProcessState *prc)
{
    if (!prc->is_finished || prc->prc_stdin->fd >= 0 || prc->prc_stdout->fd >= 0 || prc->prc_stderr->fd >= 0) {
        return;
    }

    if (WIFEXITED(prc->wait_status)) {
        info("process %d exited with code %d", prc->pid, WEXITSTATUS(prc->wait_status));
    } else if (WIFSIGNALED(prc->wait_status)) {
        info("process %d terminated with signal %d", prc->pid, WTERMSIG(prc->wait_status));
    }

    if (prc->prc_stdout->rd_data) {
        info("process %d stdout: <%s>", prc->pid, prc->prc_stdout->rd_data);
    }
    if (prc->prc_stderr->rd_data) {
        info("process %d stderr: <%s>", prc->pid, prc->prc_stderr->rd_data);
    }
    fdinfo_unlink(as, prc->prc_stdin);
    fdinfo_unlink(as, prc->prc_stdout);
    fdinfo_unlink(as, prc->prc_stderr);
    fdinfo_delete(prc->prc_stdin); prc->prc_stdin = NULL;
    fdinfo_delete(prc->prc_stdout); prc->prc_stdout = NULL;
    fdinfo_delete(prc->prc_stderr); prc->prc_stderr = NULL;
    process_state_unlink(as, prc);
    process_state_delete(prc);
}

static void
do_loop(struct AppState *as)
{
    while (!as->term_flag && !as->restart_flag) {
        struct epoll_event evs[16];
        errno = 0;
        int n = epoll_wait(as->efd, evs, 16, -1);
        if (n < 0 && errno == EINTR) {
            info("epoll_wait interrupted by a signal");
            continue;
        }
        if (n < 0) {
            err("epoll_wait failed: %s", os_ErrorMsg());
            return;
        }
        if (!n) {
            err("epoll_wait returned 0");
            return;
        }

        as->rd_first = as->rd_last = NULL;
        for (int i = 0; i < n; ++i) {
            struct epoll_event *ev = &evs[i];
            if ((ev->events & (EPOLLIN | EPOLLHUP)) != 0) {
                struct FDInfo *fdi = (struct FDInfo *) ev->data.ptr;
                fdi->ops->op_read(as, fdi);
            }
            if ((ev->events & (EPOLLOUT | EPOLLERR)) != 0) {
                struct FDInfo *fdi = (struct FDInfo *) ev->data.ptr;
                fdi->ops->op_write(as, fdi);
            }
        }

        for (int i = 0; i < as->fdq_u; ++i) {
            accept_new_client(as, as->fdq[i]);
        }
        as->fdq_u = 0;

        {
            struct ClientState *p, *q;
            for (p = as->rd_first; p; p = q) {
                q = p->rd_next;
                p->rd_prev = p->rd_next = NULL;
                if (p->close_flag) {
                    close_client(as, p);
                } else if (p->data_ready_flag) {
                    process_data(as, p);
                }
            }
            as->rd_first = as->rd_last = NULL;
        }

        if (as->timer_flag) {
            process_timer_event(as);
            as->timer_flag = 0;
        }

        for (int i = 0; i < as->inq_u; ++i) {
            process_job_file(as, as->inq[i]);
            xfree(as->inq[i]);
            as->inq[i] = NULL;
        }
        as->inq_u = 0;

        if (as->child_flag) {
            process_child_event(as);
            as->child_flag = 0;
        }

        if (as->reopen_log_flag) {
            if (as->daemon_mode) {
                start_open_log(as->job_server_log);
            }
            as->reopen_log_flag = 0;
        }

        {
            struct ProcessState *p, *q;
            for (p = as->rd_prc_first; p; p = q) {
                q = p->rd_next;
                p->rd_prev = p->rd_next = NULL;
                p->is_notified = 0;
                handle_process_notification(as, p);
            }
            as->rd_prc_first = as->rd_prc_last = NULL;
        }
    }
}

static int
load_telegram_plugin(struct AppState *as)
{
    struct xml_tree *telegram_cfg = ejudge_cfg_get_plugin_config(as->config, "sn", "telegram");
    if (!telegram_cfg) return 0;

    const struct common_loaded_plugin *telegram_plugin = plugin_load_external(NULL, "sn", "telegram", as->config);
    if (!telegram_plugin) {
        err("failed to load Telegram plugin");
        return -1;
    }

    if (telegram_plugin->iface->b.size != sizeof(struct telegram_plugin_iface)) {
        err("Telegram plugin interface size mismatch");
        return -1;
    }

    const struct telegram_plugin_iface *telegram_iface = (const struct telegram_plugin_iface *) telegram_plugin->iface;
    if (telegram_iface->telegram_plugin_iface_version != TELEGRAM_PLUGIN_IFACE_VERSION) {
        err("Telegram plugin interface version mismatch\n");
        return -1;
    }
    struct telegram_plugin_data *telegram_data = (struct telegram_plugin_data *) telegram_plugin->data;
    as->telegram_iface = telegram_iface;
    as->telegram_data = telegram_data;

    as->telegram_iface->set_set_command_handler(as->telegram_data, add_handler_wrapper, as);
    as->telegram_iface->set_set_timer_handler(as->telegram_data, add_timer_wrapper, as);

    if (telegram_iface->start(as->telegram_data) < 0) {
        err("Telegram plugin start failed\n");
        return -1;
    }

    return 0;
}

static int
load_auth_google_plugin(struct AppState *as)
{
    struct xml_tree *google_cfg = ejudge_cfg_get_plugin_config(as->config, "auth", "google");
    if (!google_cfg) return 0;

    const struct common_loaded_plugin *google_plugin = plugin_load_external(NULL, "auth", "google", as->config);
    if (!google_plugin) {
        err("failed to load auth_google plugin");
        return -1;
    }

    if (google_plugin->iface->b.size != sizeof(struct auth_plugin_iface)) {
        err("auth_google plugin interface size mismatch");
        return -1;
    }

    const struct auth_plugin_iface *auth_iface = (const struct auth_plugin_iface *) google_plugin->iface;
    if (auth_iface->auth_version != AUTH_PLUGIN_IFACE_VERSION) {
        err("auth plugin interface version mismatch");
        return -1;
    }

    as->auth_google_iface = auth_iface;
    as->auth_google_data = google_plugin->data;

    as->auth_google_iface->set_set_command_handler(as->auth_google_data, add_handler_wrapper, as);

    if (as->auth_google_iface->open(as->auth_google_data) < 0) {
        err("auth_google plugin 'open' failed");
        return -1;
    }

    if (as->auth_google_iface->check(as->auth_google_data) < 0) {
        err("auth_google plugin 'check' failed");
        return -1;
    }

    if (as->auth_google_iface->start_thread(as->auth_google_data) < 0) {
        err("auth_google plugin 'start_thread' failed");
        return -1;
    }

    return 0;
}

static int
load_auth_vk_plugin(struct AppState *as)
{
    struct xml_tree *vk_cfg = ejudge_cfg_get_plugin_config(as->config, "auth", "vk");
    if (!vk_cfg) return 0;

    const struct common_loaded_plugin *vk_plugin = plugin_load_external(NULL, "auth", "vk", as->config);
    if (!vk_plugin) {
        err("failed to load auth_vk plugin");
        return -1;
    }

    if (vk_plugin->iface->b.size != sizeof(struct auth_plugin_iface)) {
        err("auth_vk plugin interface size mismatch");
        return -1;
    }

    const struct auth_plugin_iface *auth_iface = (const struct auth_plugin_iface *) vk_plugin->iface;
    if (auth_iface->auth_version != AUTH_PLUGIN_IFACE_VERSION) {
        err("auth plugin interface version mismatch");
        return -1;
    }

    as->auth_vk_iface = auth_iface;
    as->auth_vk_data = vk_plugin->data;

    as->auth_vk_iface->set_set_command_handler(as->auth_vk_data, add_handler_wrapper, as);

    if (as->auth_vk_iface->open(as->auth_vk_data) < 0) {
        err("auth_vk plugin 'open' failed");
        return -1;
    }

    if (as->auth_vk_iface->check(as->auth_vk_data) < 0) {
        err("auth_vk plugin 'check' failed");
        return -1;
    }

    if (as->auth_vk_iface->start_thread(as->auth_vk_data) < 0) {
        err("auth_vk plugin 'start_thread' failed");
        return -1;
    }

    return 0;
}

static int
load_auth_yandex_plugin(struct AppState *as)
{
    struct xml_tree *yandex_cfg = ejudge_cfg_get_plugin_config(as->config, "auth", "yandex");
    if (!yandex_cfg) return 0;

    const struct common_loaded_plugin *yandex_plugin = plugin_load_external(NULL, "auth", "yandex", as->config);
    if (!yandex_plugin) {
        err("failed to load auth_yandex plugin");
        return -1;
    }

    if (yandex_plugin->iface->b.size != sizeof(struct auth_plugin_iface)) {
        err("auth_yandex plugin interface size mismatch");
        return -1;
    }

    const struct auth_plugin_iface *auth_iface = (const struct auth_plugin_iface *) yandex_plugin->iface;
    if (auth_iface->auth_version != AUTH_PLUGIN_IFACE_VERSION) {
        err("auth plugin interface version mismatch");
        return -1;
    }

    as->auth_yandex_iface = auth_iface;
    as->auth_yandex_data = yandex_plugin->data;

    as->auth_yandex_iface->set_set_command_handler(as->auth_yandex_data, add_handler_wrapper, as);

    if (as->auth_yandex_iface->open(as->auth_yandex_data) < 0) {
        err("auth_yandex plugin 'open' failed");
        return -1;
    }

    if (as->auth_yandex_iface->check(as->auth_yandex_data) < 0) {
        err("auth_yandex plugin 'check' failed");
        return -1;
    }

    if (as->auth_yandex_iface->start_thread(as->auth_yandex_data) < 0) {
        err("auth_yandex plugin 'start_thread' failed");
        return -1;
    }

    return 0;
}

static int
load_vcs_gitlab_plugin(struct AppState *as)
{
    struct xml_tree *gitlab_cfg = ejudge_cfg_get_plugin_config(as->config, "vcs", "gitlab");
    if (!gitlab_cfg) return 0;

    const struct common_loaded_plugin *gitlab_plugin = plugin_load_external(NULL, "vcs", "gitlab", as->config);
    if (!gitlab_plugin) {
        err("failed to load vcs_gitlab plugin");
        return -1;
    }

    if (gitlab_plugin->iface->b.size != sizeof(struct vcs_plugin_iface)) {
        err("vcs_gitlab plugin interface size mismatch");
        return -1;
    }

    const struct vcs_plugin_iface *vcs_iface = (const struct vcs_plugin_iface *) gitlab_plugin->iface;
    if (vcs_iface->vcs_version != VCS_PLUGIN_IFACE_VERSION) {
        err("vcs plugin interface version mismatch");
        return -1;
    }

    as->vcs_gitlab_iface = vcs_iface;
    as->vcs_gitlab_data = gitlab_plugin->data;

    as->vcs_gitlab_iface->set_set_command_handler(as->vcs_gitlab_data, add_handler_wrapper, as);
    as->vcs_gitlab_iface->set_work_dir(as->vcs_gitlab_data, as->job_server_work);

    if (as->vcs_gitlab_iface->open(as->vcs_gitlab_data, as->config) < 0) {
        err("vcs_gitlab plugin 'open' failed");
        return -1;
    }

    /*
    if (as->auth_vk_iface->check(as->auth_vk_data) < 0) {
        err("auth_vk plugin 'check' failed");
        return -1;
    }

    if (as->auth_vk_iface->start_thread(as->auth_vk_data) < 0) {
        err("auth_vk plugin 'start_thread' failed");
        return -1;
    }
    */

    return 0;
}

static int
load_plugins(struct AppState *as)
{
    if (load_telegram_plugin(as) < 0) return -1;
    if (load_auth_google_plugin(as) < 0) return -1;
    if (load_auth_vk_plugin(as) < 0) return -1;
    if (load_auth_yandex_plugin(as) < 0) return -1;
    if (load_vcs_gitlab_plugin(as) < 0) return -1;

    return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    {
        sigset_t ss;
        sigemptyset(&ss);
        sigaddset(&ss, SIGPIPE);
        sigprocmask(SIG_BLOCK, &ss, NULL);
    }

    struct AppState as;
    app_state_init(&as);

    int cur_arg = 1, j = 0;
    start_set_self_args(argc, argv);

    char **argv_restart = NULL;
    XCALLOC(argv_restart, argc + 2);
    argv_restart[j++] = argv[0];

    int restart_mode = 0;
    const unsigned char *user = NULL;
    const unsigned char *group = NULL;
    const unsigned char *workdir = NULL;
    unsigned char *ejudge_xml_path = NULL;
    int disable_stack_trace = 0;

    while (cur_arg < argc) {
        if (!strcmp(argv[cur_arg], "-D")) {
            as.daemon_mode = 1;
            cur_arg++;
        } else if (!strcmp(argv[cur_arg], "-nst")) {
            disable_stack_trace = 1;
            cur_arg++;
        } else if (!strcmp(argv[cur_arg], "-R")) {
            restart_mode = 1;
            cur_arg++;
        } else if (!strcmp(argv[cur_arg], "-u")) {
            if (cur_arg + 1 >= argc) {
                err("argument expected for `-u' option");
                return 1;
            }
            user = argv[cur_arg + 1];
            cur_arg += 2;
        } else if (!strcmp(argv[cur_arg], "-g")) {
            if (cur_arg + 1 >= argc) {
                err("argument expected for `-g' option");
                return 1;
            }
            group = argv[cur_arg + 1];
            cur_arg += 2;
        } else if (!strcmp(argv[cur_arg], "-C")) {
            if (cur_arg + 1 >= argc) {
                err("argument expected for `-C' option");
                return 1;
            }
            workdir = argv[cur_arg + 1];
            cur_arg += 2;
        } else
            break;
    }

    argv_restart[j++] = "-R";
    if (cur_arg < argc) {
        argv_restart[j++] = argv[cur_arg];
        ejudge_xml_path = argv[cur_arg++];
    }
    if (cur_arg != argc) {
        err("invalid number of arguments");
        return 1;
    }
    argv_restart[j] = NULL;
    start_set_args(argv_restart);
    if (disable_stack_trace <= 0) {
        start_enable_stacktrace(NULL);
    }

    int pid;
    if ((pid = start_find_process("ej-jobs", NULL, 0)) > 0) {
        err("already running as pid %d", pid);
        return 1;
    }

#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) {
        ejudge_xml_path = EJUDGE_XML_PATH;
    }
#endif
    if (!ejudge_xml_path) {
        err("configuration file is not specified");
        return 1;
    }

    if (start_prepare(user, group, workdir) < 0) return 1;

    info("ej-jobs %s, compiled %s", compile_version, compile_date);

    if (!(as.config = ejudge_cfg_parse(ejudge_xml_path, 0))) {
        return 1;
    }

    if (contests_set_directory(as.config->contests_dir) < 0) {
        return 1;
    }

    random_init();

    if (prepare_config_vars(&as) < 0) {
        return 1;
    }

    if (chdir(as.job_server_work) < 0) {
        err("cannot change directory to %s", as.job_server_work);
        return 1;
    }

    if (as.daemon_mode) {
        if (start_open_log(as.job_server_log) < 0)
            return 1;

        if ((pid = fork()) < 0) return 1;
        if (pid > 0) _exit(0);
        setsid();
    } else if (restart_mode) {
        if (start_open_log(as.job_server_log) < 0)
            return 1;
    }

    if (load_plugins(&as) < 0) return 1;

    if (app_state_prepare(&as) < 0) {
        return 1;
    }

    app_add_command_handler(&as, "stop", handle_stop_packet, &as);
    app_add_command_handler(&as, "restart", handle_restart_packet, &as);
    app_add_command_handler(&as, "nop", handle_nop_packet, &as);
    app_add_command_handler(&as, "mail", handle_mail_packet, &as);

    do_loop(&as);

    int restart_flag = as.restart_flag;
    app_state_destroy(&as);

    if (restart_flag) {
        start_restart();
    }

    return 0;
}

void *__attribute__((unused))
job_server_force_link_2[] =
{
    base64u_decode,
    cJSON_Delete,
    cJSON_GetArrayItem,
    cJSON_GetArraySize,
    cJSON_GetObjectItem,
    cJSON_Parse,
    ej_uuid_parse,
    task_New,
    userprob_plugin_get,
    xml_err_elem_undefined_s,
    xml_parse_full_cookie,
    xml_parse_int,
    xml_parse_ip,
    xml_parse_ipv6_2,
    xml_unparse_full_cookie,
    xml_unparse_ip,
    xml_unparse_ipv6,
    contests_get_list,
};

#if HAVE_LIBMONGOC - 0 > 0
void *
job_server_force_link[] =
{
  ej_bson_parse_string_new,
};

#elif HAVE_LIBMONGO_CLIENT - 0 == 1

void *
job_server_force_link[] =
{
  ej_bson_parse_string,
};

#endif
