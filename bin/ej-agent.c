/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"
#include "ejudge/dyntrie.h"
#include "ejudge/prepare.h"
#include "ejudge/fileutl.h"
#include "ejudge/base64.h"
#include "ejudge/ej_lzma.h"
#include "ejudge/random.h"

#include <stdlib.h>
#include "ejudge/cJSON.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <ctype.h>
#include <sys/mman.h>
#include <zlib.h>
#include <dirent.h>

static const unsigned char *program_name;
static const unsigned char *log_file;

static void die(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}

struct AppState;
struct FDInfo;

struct FDInfoOps
{
    void (*op_read)(struct AppState *as, struct FDInfo *fdi);
    void (*op_write)(struct AppState *as, struct FDInfo *fdi);
    int (*is_in_ready)(struct AppState *as, struct FDInfo *fdi);
    void (*handle_read)(struct AppState *as, struct FDInfo *fdi);
};

struct FDChunk
{
    unsigned char *data;
    int size;
};

struct FDInfo
{
    struct FDInfo *prev, *next;
    const struct FDInfoOps *ops;

    int fd;
    uint32_t events;

    unsigned char *rd_data;
    int rd_size, rd_rsrv;

    unsigned char *wr_data;
    int wr_size, wr_pos;

    struct FDChunk *rchunks;
    int rchunku;
    int rchunka;

    struct FDChunk *wchunks;
    int wchunku;
    int wchunka;
};

struct FDCallback
{
    void (*callback)(struct AppState *as, struct FDInfo *fdi);
    struct FDInfo *fdi;
};

struct QueryCallback
{
    unsigned char *query;
    void *extra;
    int (*callback)(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply);
};

struct ContestInfo
{
    unsigned char *server;
    int contest_id;

    unsigned char *server_dir;
    unsigned char *server_contest_dir;
    unsigned char *status_dir;
    unsigned char *report_dir;
    unsigned char *output_dir;
};

struct AppState
{
    struct FDInfo *fd_first, *fd_last;

    struct FDInfo *stdin_fdi;
    struct FDInfo *stdout_fdi;
    struct FDInfo *signal_fdi;
    struct FDInfo *timer_fdi;
    struct FDInfo *inotify_fdi;

    struct FDCallback *ready_cbs;
    int ready_cba;
    int ready_cbu;

    struct QueryCallback *querys;
    int querya;
    int queryu;
    struct dyntrie_node *queryi;

    int cntsa;
    int cntsu;
    struct ContestInfo *cntss;

    int serial;

    int term_flag;
    int timer_flag;
    int wait_serial;
    long long wait_time_ms;
    int spool_wd;
    int wait_finished;
    int wait_random_mode;
    int reopen_log_flag;
    int wait_enable_file;

    int ifd;                    /* inotify file descriptor */
    int sfd;                    /* signal file descriptor */
    int efd;                    /* epoll file descriptor */
    int tfd;                    /* timer file descriptor */

    long long current_time_ms;
    unsigned char *queue_id;
    int mode;
    unsigned char *inst_id;

    unsigned char *unique_prefix;
    unsigned char *spool_dir;
    unsigned char *queue_dir;
    unsigned char *queue_packet_dir;
    unsigned char *queue_out_dir;
    unsigned char *data_dir;
    unsigned char *heartbeat_dir;
    unsigned char *heartbeat_packet_dir;
    unsigned char *heartbeat_in_dir;

    int verbose_mode;
};

static void
app_state_init(struct AppState *as)
{
    memset(as, 0, sizeof(*as));
    as->ifd = -1;
    as->sfd = -1;
    as->efd = -1;
    as->tfd = -1;
    as->spool_wd = -1;
}

static void
app_state_destroy(struct AppState *as)
{
    if (as->ifd >= 0) close(as->ifd);
    if (as->sfd >= 0) close(as->sfd);
    if (as->efd >= 0) close(as->efd);
    if (as->tfd >= 0) close(as->tfd);

    for (int i = 0; i < as->queryu; ++i) {
        free(as->querys[i].query);
    }
    free(as->querys);
    dyntrie_free(&as->queryi, NULL, NULL);
}

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

static void
fdinfo_clear_rchunks(struct FDInfo *fdi, int free_root_flag)
{
    for (int i = 0; i < fdi->rchunku; ++i) {
        free(fdi->rchunks[i].data);
    }
    fdi->rchunku = 0;
    if (free_root_flag) {
        free(fdi->rchunks);
        fdi->rchunks = NULL;
        fdi->rchunka = 0;
    }
}

static void
fdinfo_clear_wchunks(struct FDInfo *fdi, int free_root_flag)
{
    for (int i = 0; i < fdi->wchunku; ++i) {
        free(fdi->wchunks[i].data);
    }
    fdi->wchunku = 0;
    if (free_root_flag) {
        free(fdi->wchunks);
        fdi->wchunks = NULL;
        fdi->wchunka = 0;
    }
}

static __attribute__((unused)) struct FDInfo *
fdinfo_delete(struct FDInfo *fdi)
{
    if (fdi->fd >= 0) close(fdi->fd);
    free(fdi->rd_data);
    free(fdi->wr_data);
    fdinfo_clear_rchunks(fdi, 1);
    fdinfo_clear_wchunks(fdi, 1);
    free(fdi);
    return NULL;
}

static __attribute__((unused)) void
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

static void
fdinfo_add_rchunk(struct FDInfo *fdi, const unsigned char *data, int size)
{
    if (fdi->rchunka == fdi->rchunku) {
        if (!(fdi->rchunka *= 2)) fdi->rchunka = 4;
        XREALLOC(fdi->rchunks, fdi->rchunka);
    }
    struct FDChunk *c = &fdi->rchunks[fdi->rchunku++];
    c->data = malloc(size + 1);
    memcpy(c->data, data, size);
    c->data[size] = 0;
    c->size = size;
}

static __attribute__((unused)) void
fdinfo_add_write_data(struct FDInfo *fdi, const unsigned char *data, int size)
{
    if (size <= 0) return;

    if (!fdi->wr_data) {
        fdi->wr_data = malloc(size);
        memmove(fdi->wr_data, data, size);
        fdi->wr_size = size;
        fdi->wr_pos = 0;
    } else {
        if (fdi->wchunka == fdi->wchunku) {
            if (!(fdi->wchunka *= 2)) fdi->wchunka = 4;
            XREALLOC(fdi->wchunks, fdi->wchunka);
        }
        struct FDChunk *c = &fdi->wchunks[fdi->wchunku++];
        c->data = malloc(size);
        memmove(c->data, data, size);
        c->size = size;
    }
}

static void
fdinfo_add_write_data_2(struct FDInfo *fdi, unsigned char *data, int size)
{
    if (size <= 0) return;

    if (!fdi->wr_data) {
        fdi->wr_data = data;
        fdi->wr_size = size;
        fdi->wr_pos = 0;
    } else {
        if (fdi->wchunka == fdi->wchunku) {
            if (!(fdi->wchunka *= 2)) fdi->wchunka = 4;
            XREALLOC(fdi->wchunks, fdi->wchunka);
        }
        struct FDChunk *c = &fdi->wchunks[fdi->wchunku++];
        c->data = data;
        c->size = size;
    }
}

static void
app_state_arm_for_read(struct AppState *as, struct FDInfo *fdi)
{
    if ((fdi->events & EPOLLIN) != 0) return;

    if (!fdi->events) {
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = fdi };
        if (epoll_ctl(as->efd, EPOLL_CTL_ADD, fdi->fd, &ev) < 0) {
            err("%s: epoll_ctl failed: %s", as->inst_id, os_ErrorMsg());
            return;
        }
        fdi->events = EPOLLIN;
    }

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_MOD, fdi->fd, &ev) < 0) {
        err("%s: epoll_ctl failed: %s", as->inst_id, os_ErrorMsg());
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
            err("%s: epoll_ctl failed: %s", as->inst_id, os_ErrorMsg());
            return;
        }
        fdi->events = EPOLLOUT;
    }

    struct epoll_event ev = { .events = EPOLLOUT, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_MOD, fdi->fd, &ev) < 0) {
        err("%s: epoll_ctl failed: %s", as->inst_id, os_ErrorMsg());
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
        err("%s: epoll_ctl failed: %s", as->inst_id, os_ErrorMsg());
        return;
    }
    fdi->events = 0;
}

static void
app_state_add_to_ready(
        struct AppState *as,
        void (*callback)(struct AppState *as, struct FDInfo *fdi),
        struct FDInfo *fdi)
{
    if (as->ready_cbu == as->ready_cba) {
        if (!(as->ready_cba *= 2)) as->ready_cba = 16;
        XREALLOC(as->ready_cbs, as->ready_cba);
    }
    struct FDCallback *cb = &as->ready_cbs[as->ready_cbu++];
    cb->callback = callback;
    cb->fdi = fdi;
}

static void
app_state_add_query_callback(
        struct AppState *as,
        const unsigned char *query,
        void *extra,
        int (*callback)(
            struct AppState *as,
            const struct QueryCallback *cb,
            cJSON *query,
            cJSON *reply))
{
    if (as->querya == as->queryu) {
        if (!(as->querya *= 2)) as->querya = 8;
        XREALLOC(as->querys, as->querya);
    }
    int index = as->queryu++;
    struct QueryCallback *c = &as->querys[index];
    c->query = xstrdup(query);
    c->extra = extra;
    c->callback = callback;
    dyntrie_insert(&as->queryi, query, (void*) (intptr_t) (index + 1), 1, NULL);
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
            err("%s: signal_read_func: read failed: %s", as->inst_id, os_ErrorMsg());
            break;
        }
        if (r != sizeof(sss)) {
            err("%s: signal_read_func: read returned invalid size %d", as->inst_id, r);
            break;
        }
        switch (sss.ssi_signo) {
        case SIGINT:  as->term_flag = 1; break;
        case SIGTERM: as->term_flag = 1; break;
        case SIGUSR1:  as->reopen_log_flag = 1; break;
        default:
            err("%s: signal_read_func: unexpected signal %d", as->inst_id, sss.ssi_signo);
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
    uint64_t value;
    if (read(fdi->fd, &value, sizeof(value)) == (ssize_t) sizeof(value)) {
        as->timer_flag = 1;
    }
}

static const struct FDInfoOps timer_ops =
{
    .op_read = timer_read_func,
};

static void
inotify_read_func(struct AppState *as, struct FDInfo *fdi)
{
    unsigned char buf[4096];
    while (1) {
        errno = 0;
        int r = read(fdi->fd, buf, sizeof(buf));
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("%s: inotify_read_func: read failed: %s", as->inst_id, os_ErrorMsg());
            break;
        }
        if (!r) {
            err("%s: inotify_read_func: read returned 0", as->inst_id);
            break;
        }
        const unsigned char *bend = buf + r;
        const unsigned char *p = buf;
        while (p < bend) {
            const struct inotify_event *ev = (const struct inotify_event *) p;
            p += sizeof(*ev) + ev->len;
            if (as->spool_wd == ev->wd) {
                as->wait_finished = 1;
            }
        }
        if (p > bend) {
            err("%s: inotify_read_func: buffer overrun: end = %p, cur = %p", as->inst_id, bend, p);
        }
    }
}

static const struct FDInfoOps inotify_ops =
{
    .op_read = inotify_read_func,
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
            err("%s: pipe_read_func: read failed: %s", as->inst_id, os_ErrorMsg());
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
    if (fdi->ops->is_in_ready && fdi->ops->is_in_ready(as, fdi) > 0) {
        if (fdi->ops->handle_read) {
            app_state_add_to_ready(as, fdi->ops->handle_read, fdi);
        }
    }
    return;

done:
    app_state_disarm(as, fdi);
    close(fdi->fd); fdi->fd = -1;
    if (fdi->ops->handle_read) {
        app_state_add_to_ready(as, fdi->ops->handle_read, fdi);
    }
}

static int
separator_2nl_ready_func(struct AppState *as, struct FDInfo *fdi)
{
    if (fdi->rd_size < 2) return 0;
    int s = 0;
    for (int i = 1; i < fdi->rd_size; ++i) {
        if (fdi->rd_data[i] == '\n' && fdi->rd_data[i - 1] == '\n') {
            fdinfo_add_rchunk(fdi, &fdi->rd_data[s], i - s + 1);
            s = i + 1;
        }
    }
    if (!s) return 0;
    fdi->rd_size -= s;
    memcpy(fdi->rd_data, fdi->rd_data + s, fdi->rd_size);
    return 1;
}

static void
handle_stdin_rchunk(
        struct AppState *as,
        struct FDInfo *fdi,
        const unsigned char *data,
        int size)
{
    char *jstr = NULL;
    int jlen;
    cJSON *root = NULL;
    cJSON *reply = cJSON_CreateObject();
    int ok = 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    as->current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    cJSON_AddNumberToObject(reply, "tt", (double) as->current_time_ms);
    cJSON_AddNumberToObject(reply, "ss", (double) ++as->serial);

    if (strlen(data) != size) {
        cJSON_AddStringToObject(reply, "message", "binary data");
        err("%s: binary data on stdin", as->inst_id);
        goto done;
    }

    root = cJSON_Parse(data);
    if (!root) {
        cJSON_AddStringToObject(reply, "message", "JSON parse error");
        err("%s: JSON parsing failed", as->inst_id);
        goto done;
    }

    cJSON *jt = cJSON_GetObjectItem(root, "t");
    if (jt && jt->type == cJSON_Number) {
        cJSON_AddNumberToObject(reply, "t", jt->valuedouble);
    }
    cJSON *js = cJSON_GetObjectItem(root, "s");
    if (js && js->type == cJSON_Number) {
        cJSON_AddNumberToObject(reply, "s", js->valuedouble);
    }

    cJSON *jq = cJSON_GetObjectItem(root, "q");
    if (!jq || jq->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "Invalid json");
        err("%s: invalid json", as->inst_id);
        goto done;
    }
    const unsigned char *query = jq->valuestring;

    void *vp = dyntrie_get(&as->queryi, query);
    if (!vp) {
        cJSON_AddStringToObject(reply, "message", "Invalid query");
        err("%s: invalid query", as->inst_id);
        goto done;
    }
    const struct QueryCallback *c = &as->querys[((int)(intptr_t) vp) - 1];
    ok = c->callback(as, c, root, reply);

done:
    cJSON_AddBoolToObject(reply, "ok", ok);
    jstr = cJSON_PrintUnformatted(reply);
    jlen = strlen(jstr);
    if (as->verbose_mode) {
        info("%s: json: %s", as->inst_id, jstr);
    }
    jstr = realloc(jstr, jlen + 3);
    jstr[jlen++] = '\n';
    jstr[jlen++] = '\n';
    jstr[jlen] = 0;
    fdinfo_add_write_data_2(as->stdout_fdi, jstr, jlen);
    jstr = NULL;
    app_state_arm_for_write(as, as->stdout_fdi);

    if (root) cJSON_Delete(root);
    if (reply) cJSON_Delete(reply);
    free(jstr);
}

static void
handle_stdin_read_func(struct AppState *as, struct FDInfo *fdi)
{
    if (fdi->fd < 0) {
        as->term_flag = 1;
        return;
    }

    for (int i = 0; i < fdi->rchunku; ++i) {
        {
            unsigned char *data = fdi->rchunks[i].data;
            int size = fdi->rchunks[i].size;
            while (size > 0 && isspace(data[size - 1])) {
                --size;
            }
            data[size] = 0;
            fdi->rchunks[i].size = size;
        }
        if (as->verbose_mode) {
            info("%s: in: %s", as->inst_id, fdi->rchunks[i].data);
        }
        handle_stdin_rchunk(as, fdi, fdi->rchunks[i].data, fdi->rchunks[i].size);
    }
    fdinfo_clear_rchunks(fdi, 0);
}

static const struct FDInfoOps stdin_ops =
{
    .op_read = pipe_read_func,
    .is_in_ready = separator_2nl_ready_func,
    .handle_read = handle_stdin_read_func,
};

static void
pipe_write_func(struct AppState *as, struct FDInfo *fdi)
{
    while (1) {
        int wsz = fdi->wr_size - fdi->wr_pos;
        assert(wsz >= 0);
        if (!wsz) {
            if (fdi->wchunku <= 0) {
                app_state_disarm(as, fdi);
                return;
            }
            struct FDChunk *c = &fdi->wchunks[0];
            free(fdi->wr_data);
            fdi->wr_data = c->data;
            fdi->wr_size = c->size;
            fdi->wr_pos = 0;
            if (fdi->wchunku > 0) {
                memcpy(&fdi->wchunks[0], &fdi->wchunks[1], (fdi->wchunku - 1) * sizeof(fdi->wchunks[0]));
            }
            --fdi->wchunku;
            continue;
        }
        errno = 0;
        int r = write(fdi->fd, fdi->wr_data + fdi->wr_pos, wsz);
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("%s: pipe_write_func: write failed: %s", as->inst_id, os_ErrorMsg());
            goto done;
        }
        if (!r) {
            err("%s: pipe_write_func: write returned 0", as->inst_id);
            goto done;
        }
        fdi->wr_pos += r;
    }
    return;

done:
    app_state_disarm(as, fdi);
    close(fdi->fd); fdi->fd = -1;
}

static const struct FDInfoOps stdout_ops =
{
    .op_write = pipe_write_func,
};

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
    sigaddset(&ss, SIGUSR1);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    if ((as->sfd = signalfd(-1, &ss, SFD_CLOEXEC | SFD_NONBLOCK)) < 0) {
        err("%s: signalfd failed: %s", as->inst_id, os_ErrorMsg());
        goto fail;
    }

    if ((as->tfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK)) < 0) {
        err("%s: timerfd_create failed: %s", as->inst_id, os_ErrorMsg());
        goto fail;
    }
    {
        struct itimerspec spec =
        {
            .it_interval =
            {
                .tv_sec = 60,
                .tv_nsec = 0,
            },
            .it_value =
            {
                .tv_sec = 60,
                .tv_nsec = 0,
            },
        };
        if (timerfd_settime(as->tfd, 0, &spec, NULL) < 0) {
            err("%s: timerfd_settime failed: %s", as->inst_id, os_ErrorMsg());
            return -1;
        }
    }

    if ((as->ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK)) < 0) {
        err("%s: inotify_init1 failed: %s", as->inst_id, os_ErrorMsg());
        goto fail;
    }

    if ((as->efd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        err("%s: epoll_create failed: %s", as->inst_id, os_ErrorMsg());
        goto fail;
    }

    as->signal_fdi = fdinfo_create(as, as->sfd, &signal_ops);
    app_state_arm_for_read(as, as->signal_fdi);

    as->timer_fdi = fdinfo_create(as, as->tfd, &timer_ops);
    app_state_arm_for_read(as, as->timer_fdi);

    as->inotify_fdi = fdinfo_create(as, as->ifd, &inotify_ops);
    app_state_arm_for_read(as, as->inotify_fdi);
    
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
    as->stdin_fdi = fdinfo_create(as, 0, &stdin_ops);
    app_state_arm_for_read(as, as->stdin_fdi);

    fcntl(1, F_SETFL, fcntl(1, F_GETFL) | O_NONBLOCK);
    as->stdout_fdi = fdinfo_create(as, 1, &stdout_ops);

    return 0;

fail:
    return -1;
}

static __attribute__((warn_unused_result)) int
app_state_configure_directories(struct AppState *as)
{
    // attribute ((unused)) also disables "set but not used" warning
    int __attribute__((unused)) r;

    if (!as->mode || !as->queue_id) return 0;

    char *s = NULL;
    unsigned long long r64 = random_u64();
    r = asprintf(&s, "%llx_", r64);
    as->unique_prefix = s; s = NULL;

    if (as->mode == PREPARE_COMPILE) {
#if defined EJUDGE_COMPILE_SPOOL_DIR
        r = asprintf(&s, "%s/%s", EJUDGE_COMPILE_SPOOL_DIR, as->queue_id);
        as->spool_dir = s; s = NULL;
        r = asprintf(&s, "%s/queue", as->spool_dir);
        as->queue_dir = s; s = NULL;
        r = asprintf(&s, "%s/dir", as->queue_dir);
        as->queue_packet_dir = s; s = NULL;
        r = asprintf(&s, "%s/out", as->queue_dir);
        as->queue_out_dir = s; s = NULL;
        r = asprintf(&s, "%s/%s/src", EJUDGE_COMPILE_SPOOL_DIR, as->queue_id);
        as->data_dir = s; s = NULL;
        r = asprintf(&s, "%s/%s/heartbeat", EJUDGE_COMPILE_SPOOL_DIR, as->queue_id);
        as->heartbeat_dir = s; s = NULL;
        r = asprintf(&s, "%s/dir", as->heartbeat_dir);
        as->heartbeat_packet_dir = s; s = NULL;
        r = asprintf(&s, "%s/in", as->heartbeat_dir);
        as->heartbeat_in_dir = s; s = NULL;
#endif
    } else if (as->mode == PREPARE_RUN) {
#if defined EJUDGE_RUN_SPOOL_DIR
        r = asprintf(&s, "%s/%s", EJUDGE_RUN_SPOOL_DIR, as->queue_id);
        as->spool_dir = s; s = NULL;
        r = asprintf(&s, "%s/queue", as->spool_dir);
        as->queue_dir = s; s = NULL;
        r = asprintf(&s, "%s/dir", as->queue_dir);
        as->queue_packet_dir = s; s = NULL;
        r = asprintf(&s, "%s/out", as->queue_dir);
        as->queue_out_dir = s; s = NULL;
        r = asprintf(&s, "%s/%s/exe", EJUDGE_RUN_SPOOL_DIR, as->queue_id);
        as->data_dir = s; s = NULL;
        r = asprintf(&s, "%s/%s/heartbeat", EJUDGE_RUN_SPOOL_DIR, as->queue_id);
        as->heartbeat_dir = s; s = NULL;
        r = asprintf(&s, "%s/dir", as->heartbeat_dir);
        as->heartbeat_packet_dir = s; s = NULL;
        r = asprintf(&s, "%s/in", as->heartbeat_dir);
        as->heartbeat_in_dir = s; s = NULL;
#endif
    }

    // create directories
    if (as->spool_dir && as->spool_dir[0]) {
        if (make_dir(as->spool_dir, 0700) < 0) {
            return -1;
        }
    }
    if (as->queue_dir && as->queue_dir[0]) {
        if (make_all_dir(as->queue_dir, 0700) < 0) {
            return -1;
        }
    }
    if (as->data_dir && as->data_dir[0]) {
        if (make_dir(as->data_dir, 0700) < 0) {
            return -1;
        }
    }
    if (as->heartbeat_dir && as->heartbeat_dir[0]) {
        if (make_all_dir(as->heartbeat_dir, 0700) < 0) {
            return -1;
        }
    }

    return 0;
}

static int
safe_read_packet(
        struct AppState *as,
        const unsigned char *pkt_name,
        char **p_data,
        size_t *p_size);
static void
add_file_to_object(
        cJSON *j,
        const char *data,
        size_t size);

static void
check_spool_state(struct AppState *as)
{
    unsigned char pkt_name[PATH_MAX];
    int r = scan_dir(as->queue_dir, pkt_name, sizeof(pkt_name), as->wait_random_mode);
    if (r <= 0) return;

    char *data = NULL;
    size_t size = 0;

    if (as->wait_enable_file) {
        r = safe_read_packet(as, pkt_name, &data, &size);
        if (r <= 0) return;
    }

    cJSON *reply = cJSON_CreateObject();
    struct timeval tv;
    gettimeofday(&tv, NULL);
    as->current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    cJSON_AddNumberToObject(reply, "tt", (double) as->current_time_ms);
    cJSON_AddNumberToObject(reply, "ss", (double) ++as->serial);
    cJSON_AddNumberToObject(reply, "s", (double) as->wait_serial);
    cJSON_AddNumberToObject(reply, "t", (double) as->wait_time_ms);
    cJSON_AddTrueToObject(reply, "wake-up");
    if (data != NULL) {
        cJSON_AddStringToObject(reply, "q", "file-result");
        cJSON_AddTrueToObject(reply, "found");
        add_file_to_object(reply, data, size);
        free(data); data = NULL;
    } else {
        cJSON_AddStringToObject(reply, "q", "poll-result");
    }
    cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
    cJSON_AddTrueToObject(reply, "ok");
    char *jstr = cJSON_PrintUnformatted(reply);
    size_t jlen = strlen(jstr);
    if (as->verbose_mode) {
        info("%s: json: %s", as->inst_id, jstr);
    }
    jstr = realloc(jstr, jlen + 3);
    jstr[jlen++] = '\n';
    jstr[jlen++] = '\n';
    jstr[jlen] = 0;
    fdinfo_add_write_data_2(as->stdout_fdi, jstr, jlen);
    jstr = NULL;
    app_state_arm_for_write(as, as->stdout_fdi);

    info("%s: wake-up on directory: %d, %d, %s", as->inst_id, as->serial, as->wait_serial, pkt_name);

    cJSON_Delete(reply);
    as->wait_serial = 0;
    as->wait_time_ms = 0;
    as->wait_random_mode = 0;
    as->wait_enable_file = 0;
    if (as->spool_wd >= 0) {
        inotify_rm_watch(as->ifd, as->spool_wd);
        as->spool_wd = -1;
    }
}

static void
do_loop(struct AppState *as)
{
    while (!as->term_flag) {
        struct epoll_event evs[16];
        errno = 0;
        int n = epoll_wait(as->efd, evs, 16, -1);
        if (n < 0 && errno == EINTR) {
            info("%s: epoll_wait interrupted by a signal", as->inst_id);
            continue;
        }
        if (n < 0) {
            err("%s: epoll_wait failed: %s", as->inst_id, os_ErrorMsg());
            return;
        }
        if (!n) {
            err("%s: epoll_wait returned 0", as->inst_id);
            return;
        }

        as->ready_cbu = 0;
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

        if (as->reopen_log_flag) {
            if (log_file && *log_file) {
                int fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND | O_NOCTTY, 0600);
                if (fd < 0) {
                    err("%s: cannot open log file '%s': %s", as->inst_id, log_file, strerror(errno));
                } else {
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                }
            }
            as->reopen_log_flag = 0;
        }

        if (as->timer_flag) {
            as->timer_flag = 0;
        }
        if (as->wait_finished) {
            check_spool_state(as);
            as->wait_finished = 0;
        }

        for (int i = 0; i < as->ready_cbu; ++i) {
            as->ready_cbs[i].callback(as, as->ready_cbs[i].fdi);
        }
        as->ready_cbu = 0;
    }
}

static int
ping_query_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON_AddStringToObject(reply, "q", "pong");
    return 1;
}

static int
set_query_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON *jn = cJSON_GetObjectItem(query, "name");
    if (jn && jn->type == cJSON_String) {
        free(as->queue_id);
        as->queue_id = xstrdup(jn->valuestring);
    }
    cJSON *jm = cJSON_GetObjectItem(query, "mode");
    if (jm && jm->type == cJSON_String) {
        if (!strcmp(jm->valuestring, "compile")) {
            as->mode = PREPARE_COMPILE;
        } else if (!strcmp(jm->valuestring, "run")) {
            as->mode = PREPARE_RUN;
        } else {
            cJSON_AddStringToObject(reply, "message", "invalid mode");
            return 0;
        }
    }
    if (as->queue_id && as->queue_id[0]) {
        cJSON_AddStringToObject(reply, "name", as->queue_id);
    }
    if (as->mode == PREPARE_COMPILE) {
        cJSON_AddStringToObject(reply, "mode", "compile");
    } else if (as->mode == PREPARE_RUN) {
        cJSON_AddStringToObject(reply, "mode", "run");
    }
    cJSON_AddStringToObject(reply, "q", "get");
    return 1;
}

static void
add_file_to_object(cJSON *j, const char *data, size_t size)
{
    cJSON_AddNumberToObject(j, "size", (double) size);
    if (!size) {
        return;
    }
    // gzip mode
    if (size < 32) {
        cJSON_AddTrueToObject(j, "b64");
        char *ptr = malloc(size * 2 + 16);
        int n = base64u_encode(data, size, ptr);
        ptr[n] = 0;
        cJSON_AddStringToObject(j, "data", ptr);
        free(ptr);
    } else {
        z_stream zs = {};
        zs.next_in = (Bytef *) data;
        zs.avail_in = size;
        zs.total_in = size;

        if (deflateInit(&zs, 9) != Z_OK) {
            abort();
        }
        size_t bound = deflateBound(&zs, size);
        char *gz_buf = malloc(bound);
        zs.next_out = (Bytef*) gz_buf;
        zs.avail_out = bound;
        zs.total_out = 0;
        int r = deflate(&zs, Z_FINISH);
        if (r != Z_STREAM_END) {
            abort();
        }
        size_t gz_size = zs.total_out;
        if (deflateEnd(&zs) != Z_OK) {
            abort();
        }
        cJSON_AddTrueToObject(j, "gz");
        cJSON_AddNumberToObject(j, "gz_size", gz_size);
        char *b64_buf = malloc(gz_size * 2 + 16);
        int b64_size = base64u_encode(gz_buf, gz_size, b64_buf);
        b64_buf[b64_size] = 0;
        cJSON_AddTrueToObject(j, "b64");
        cJSON_AddStringToObject(j, "data", b64_buf);
        free(b64_buf);
        free(gz_buf);
    }
    // lzma mode (unused)
    if (size < 160) {
        cJSON_AddTrueToObject(j, "b64");
        char *ptr = malloc(size * 2 + 16);
        int n = base64u_encode(data, size, ptr);
        ptr[n] = 0;
        cJSON_AddStringToObject(j, "data", ptr);
        free(ptr);
    } else {
        unsigned char *lzma_buf = NULL;
        size_t lzma_size = 0;
        if (ej_lzma_encode_buf(data, size, &lzma_buf, &lzma_size) < 0) {
            // fallback to uncompressed
            cJSON_AddTrueToObject(j, "b64");
            char *ptr = malloc(size * 2 + 16);
            int n = base64u_encode(data, size, ptr);
            ptr[n] = 0;
            cJSON_AddStringToObject(j, "data", ptr);
            free(ptr);
        } else {
            cJSON_AddTrueToObject(j, "lzma");
            cJSON_AddNumberToObject(j, "lzma_size", (double) lzma_size);
            char *b64_buf = malloc(lzma_size * 2 + 16);
            int b64_size = base64u_encode(lzma_buf, lzma_size, b64_buf);
            b64_buf[b64_size] = 0;
            cJSON_AddTrueToObject(j, "b64");
            cJSON_AddStringToObject(j, "data", b64_buf);
            free(b64_buf);
            free(lzma_buf);
        }
    }
}

static int
safe_read_packet(
        struct AppState *as,
        const unsigned char *pkt_name,
        char **p_data,
        size_t *p_size)
{
    unsigned char dir_path[PATH_MAX];
    unsigned char out_path[PATH_MAX];
    __attribute__((unused)) int r;
    int fd = -1;
    char *data = NULL;

    r = snprintf(dir_path, sizeof(dir_path), "%s/%s", as->queue_packet_dir, pkt_name);
    r = snprintf(out_path, sizeof(out_path), "%s/%s%s", as->queue_out_dir, as->unique_prefix, pkt_name);

    r = rename(dir_path, out_path);
    if (r < 0 && errno == ENOENT) {
        return 0;
    }
    if (r < 0) {
        err("%s: rename failed: %s", as->inst_id, os_ErrorMsg());
        out_path[0] = 0;
        goto fail;
    }
    struct stat stb;
    if (lstat(out_path, &stb) < 0) {
        err("%s: %d: lstat failed: %s", as->inst_id, __LINE__, os_ErrorMsg());
        goto fail;
    }
    if (!S_ISREG(stb.st_mode)) {
        err("%s: %d: not regular file", as->inst_id, __LINE__);
        goto fail;
    }
    if (stb.st_nlink != 1) {
        // two processes renamed the file simultaneously
        rename(out_path, dir_path);
        unlink(out_path);
        info("%s: rename created two hardlinks, rollback", as->inst_id);
        return 0;
    }
    if (stb.st_size <= 0) {
        char *data = malloc(1);
        data[0] = 0;
        *p_data = data;
        *p_size = 0;
        unlink(out_path);
        return 1;
    }

    data = malloc(stb.st_size + 1);
    data[stb.st_size] = 0;
    fd = open(out_path, O_RDONLY, 0);
    if (fd < 0) {
        err("%s: %d: cannot open '%s': %s", as->inst_id, __LINE__, out_path, os_ErrorMsg());
        goto fail;
    }
    char *ptr = data;
    size_t remain = stb.st_size;
    while (remain > 0) {
        ssize_t rr = read(fd, ptr, remain);
        if (rr < 0) {
            err("%s: read error on '%s': %s", as->inst_id, out_path, os_ErrorMsg());
            goto fail;
        }
        if (!rr) {
            err("%s: unexpected EOF on '%s'", as->inst_id, out_path);
            goto fail;
        }
        remain -= rr;
    }

    close(fd);
    unlink(out_path);
    *p_data = data;
    *p_size = stb.st_size;

    info("%s: read file '%s', %lld", as->inst_id, pkt_name, (long long) stb.st_size);

    return 1;

fail:;
    if (out_path[0]) unlink(out_path);
    if (fd >= 0) close(fd);
    free(data);
    return -1;
}

static int
poll_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    unsigned char pkt_name[PATH_MAX];
    int random_mode = 0;
    int enable_file = 0;
    cJSON *jrm = cJSON_GetObjectItem(query, "random_mode");
    if (jrm && jrm->type == cJSON_True) {
        random_mode = 1;
    }
    cJSON *jef = cJSON_GetObjectItem(query, "enable_file");
    if (jef && jef->type == cJSON_True) {
        enable_file = 1;
    }
    while (1) {
        int r = scan_dir(as->queue_dir, pkt_name, sizeof(pkt_name), random_mode);
        if (r < 0) {
            cJSON_AddStringToObject(reply, "message", "scan_dir failed");
            err("%s: scan_dir failed: %s", as->inst_id, strerror(-r));
            return 0;
        }
        if (!r) {
            cJSON_AddStringToObject(reply, "q", "poll-result");
            return 1;
        }
        if (!enable_file) {
            cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
            cJSON_AddStringToObject(reply, "q", "poll-result");
            return 1;
        }

        char *data = NULL;
        size_t size = 0;
        r = safe_read_packet(as, pkt_name, &data, &size);
        if (r < 0) {
            cJSON_AddStringToObject(reply, "message", "read_packet failed");
            return 0;
        }
        if (r > 0) {
            cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
            cJSON_AddStringToObject(reply, "q", "file-result");
            cJSON_AddTrueToObject(reply, "found");
            add_file_to_object(reply, data, size);
            free(data);
            return 1;
        }
    }
}

static int
get_packet_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        err("%s: get_packet: missing pkt_name", as->inst_id);
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;
    char *pkt_ptr = NULL;
    size_t pkt_len = 0;
    int r = generic_read_file(&pkt_ptr, 0, &pkt_len, SAFE | REMOVE,
                              as->queue_dir, pkt_name, "");
    if (!r) {
        // just file not found
        cJSON_AddStringToObject(reply, "q", "file-result");
        return 1;
    }
    if (r < 0 || !pkt_ptr) {
        cJSON_AddStringToObject(reply, "message", "failed to read file");
        return 0;
    }
    cJSON_AddStringToObject(reply, "q", "file-result");
    cJSON_AddTrueToObject(reply, "found");
    add_file_to_object(reply, pkt_ptr, pkt_len);
    free(pkt_ptr);
    return 1;
}

static int
get_data_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        err("%s: get_packet: missing pkt_name", as->inst_id);
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;
    const unsigned char *suffix = NULL;
    cJSON *js = cJSON_GetObjectItem(query, "suffix");
    if (js && js->type == cJSON_String) {
        suffix = js->valuestring;
    }
    char *pkt_ptr = NULL;
    size_t pkt_len = 0;
    int r = generic_read_file(&pkt_ptr, 0, &pkt_len, REMOVE,
                              as->data_dir, pkt_name, suffix);
    if (!r) {
        // just file not found
        cJSON_AddStringToObject(reply, "q", "file-result");
        return 1;
    }
    if (r < 0 || !pkt_ptr) {
        cJSON_AddStringToObject(reply, "message", "failed to read file");
        return 0;
    }
    cJSON_AddStringToObject(reply, "q", "file-result");
    cJSON_AddTrueToObject(reply, "found");
    add_file_to_object(reply, pkt_ptr, pkt_len);
    free(pkt_ptr);
    return 1;
}

static int
extract_file(
        struct AppState *as,
        cJSON *j,
        char **p_pkt_ptr,
        size_t *p_pkt_len)
{
    cJSON *jz = cJSON_GetObjectItem(j, "size");
    if (!jz || jz->type != cJSON_Number) {
        err("%s: invalid json: no size", as->inst_id);
        return -1;
    }
    size_t size = (int) jz->valuedouble;
    if (size < 0 || size > 1000000000) {
        err("%s: invalid json: invalid size", as->inst_id);
        return -1;
    }
    if (!size) {
        char *ptr = malloc(1);
        *ptr = 0;
        *p_pkt_ptr = ptr;
        *p_pkt_len = 0;
        return 1;
    }
    cJSON *jb64 = cJSON_GetObjectItem(j, "b64");
    if (!jb64 || jb64->type != cJSON_True) {
        err("%s: invalid json: no encoding", as->inst_id);
        return -1;
    }
    cJSON *jd = cJSON_GetObjectItem(j, "data");
    if (!jd || jd->type != cJSON_String) {
        err("%s: invalid json: no data", as->inst_id);
        return -1;
    }
    int len = strlen(jd->valuestring);
    cJSON *jgz = cJSON_GetObjectItem(j, "gz");
    cJSON *jlzma = cJSON_GetObjectItem(j, "lzma");
    if (jgz && jgz->type == cJSON_True) {
        cJSON *jgzz = cJSON_GetObjectItem(j, "gz_size");
        if (!jgzz || jgzz->type != cJSON_Number) {
            err("invalid json: no gz_size");
            return -1;
        }
        size_t gz_size = (size_t) jgzz->valuedouble;
        char *gz_buf = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, gz_buf, &b64err);
        if (n != gz_size) {
            err("invalid json: size mismatch");
            free(gz_buf);
            return -1;
        }

        z_stream zs = {};
        if (inflateInit(&zs) != Z_OK) {
            err("invalid json: libz failed");
            free(gz_buf);
            return -1;
        }
        zs.next_in = (Bytef *) gz_buf;
        zs.avail_in = gz_size;
        zs.total_in = gz_size;
        unsigned char *ptr = malloc(size + 1);
        zs.next_out = (Bytef *) ptr;
        zs.avail_out = size;
        zs.total_out = 0;
        if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
            err("invalid json: libz inflate failed");
            free(gz_buf);
            free(ptr);
            inflateEnd(&zs);
            return -1;
        }
        if (inflateEnd(&zs) != Z_OK) {
            err("invalid json: libz inflate failed");
            free(gz_buf);
            free(ptr);
            return -1;
        }
        ptr[size] = 0;
        free(gz_buf);
        *p_pkt_ptr = ptr;
        *p_pkt_len = size;
    } else if (jlzma && jlzma->type == cJSON_True) {
        cJSON *jlzmaz = cJSON_GetObjectItem(j, "lzma_size");
        if (!jlzmaz || jlzmaz->type != cJSON_Number) {
            err("%s: invalid json: no lzma_size", as->inst_id);
            return -1;
        }
        size_t lzma_size = (size_t) jlzmaz->valuedouble;
        char *lzma_buf = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, lzma_buf, &b64err);
        if (n != lzma_size) {
            err("%s: invalid json: size mismatch", as->inst_id);
            free(lzma_buf);
            return -1;
        }
        unsigned char *ptr = NULL;
        size_t ptr_size = 0;
        if (ej_lzma_decode_buf(lzma_buf, lzma_size, size, &ptr, &ptr_size) < 0) {
            err("%s: invalid json: lzma decode error", as->inst_id);
            free(lzma_buf);
            return -1;
        }
        free(lzma_buf);
        *p_pkt_ptr = ptr;
        *p_pkt_len = ptr_size;
    } else {
        char *ptr = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, ptr, &b64err);
        if (n != size) {
            err("%s: invalid json: size mismatch", as->inst_id);
            free(ptr);
            return -1;
        }
        ptr[size] = 0;
        *p_pkt_ptr = ptr;
        *p_pkt_len = size;
    }
    return 1;
}

static struct ContestInfo *
create_contest_dirs(
        struct AppState *as,
        const unsigned char *server,
        int contest_id)
{
    for (int i = 0; i < as->cntsu; ++i) {
        if (!strcmp(as->cntss[i].server, server) && as->cntss[i].contest_id == contest_id) {
            return &as->cntss[i];
        }
    }

    const unsigned char *root_dir = NULL;
    if (as->mode == PREPARE_COMPILE) {
#if defined EJUDGE_COMPILE_SPOOL_DIR
        root_dir = EJUDGE_COMPILE_SPOOL_DIR;
#endif
    } else if (as->mode == PREPARE_RUN) {
#if defined EJUDGE_RUN_SPOOL_DIR
        root_dir = EJUDGE_RUN_SPOOL_DIR;
#endif
    }

    unsigned char server_dir[PATH_MAX];
    snprintf(server_dir, sizeof(server_dir), "%s/%s", root_dir, server);
    unsigned char server_contest_dir[PATH_MAX];
    strcpy(server_contest_dir, server_dir);
    unsigned char status_dir[PATH_MAX];
    snprintf(status_dir, sizeof(status_dir), "%s/status", server_contest_dir);
    unsigned char report_dir[PATH_MAX];
    snprintf(report_dir, sizeof(report_dir), "%s/report", server_contest_dir);
    unsigned char output_dir[PATH_MAX];
    snprintf(output_dir, sizeof(output_dir), "%s/output", server_contest_dir);

    if (as->cntsu == as->cntsa) {
        if (!(as->cntsa *= 2)) as->cntsa = 4;
        XREALLOC(as->cntss, as->cntsa);
    }

    struct ContestInfo *ci = &as->cntss[as->cntsu++];
    memset(ci, 0, sizeof(*ci));
    ci->server = xstrdup(server);
    ci->contest_id = contest_id;
    ci->server_dir = xstrdup(server_dir);
    ci->server_contest_dir = xstrdup(server_contest_dir);
    ci->status_dir = xstrdup(status_dir);
    ci->report_dir = xstrdup(report_dir);
    ci->output_dir = xstrdup(output_dir);

    return ci;
}

static int
put_reply_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    /*
{ "q" : "put-reply", "server" : "S", "contest" : C, "run_name" : "N", "b64" : T, "data" : "D", "size" : S }
     */
    char *data = NULL;
    size_t size = 0;
    int result = 0;

    if (extract_file(as, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }
    cJSON *jserver = cJSON_GetObjectItem(query, "server");
    if (!jserver || jserver->type != cJSON_String || !jserver->valuestring) {
        err("%s: invalid json: no server", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;
    cJSON *jcid = cJSON_GetObjectItem(query, "contest");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        err("%s: invalid json: invalid contest_id", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;
    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring) {
        err("%s: invalid json: no run_name", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;

    struct ContestInfo *ci = create_contest_dirs(as, server, contest_id);
    if (!ci) {
        err("%s: directory creation failed", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    if (generic_write_file(data, size, SAFE, ci->status_dir, run_name, 0) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    cJSON_AddStringToObject(reply, "q", "result");
    result = 1;

done:
    free(data);
    return result;
}

static int
put_output_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    /*
{ "q" : "put-output", "server" : "S", "contest" : C, "run_name" : "N", "b64" : T, "data" : "D", "size" : S }
     */
    char *data = NULL;
    size_t size = 0;
    int result = 0;

    if (extract_file(as, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }
    cJSON *jserver = cJSON_GetObjectItem(query, "server");
    if (!jserver || jserver->type != cJSON_String || !jserver->valuestring) {
        err("%s: invalid json: no server", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;
    cJSON *jcid = cJSON_GetObjectItem(query, "contest");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        err("%s: invalid json: invalid contest_id", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;
    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring) {
        err("%s: invalid json: no run_name", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;
    const unsigned char *suffix = NULL;
    cJSON *jsuffix = cJSON_GetObjectItem(query, "suffix");
    if (jsuffix && jsuffix->type == cJSON_String) {
        suffix = jsuffix->valuestring;
    }

    struct ContestInfo *ci = create_contest_dirs(as, server, contest_id);
    if (!ci) {
        err("%s: directory creation failed", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    if (generic_write_file(data, size, 0, ci->report_dir, run_name, suffix) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    cJSON_AddStringToObject(reply, "q", "result");
    result = 1;

done:
    free(data);
    return result;
}

static int
simple_count_files(
        struct AppState *as,
        const unsigned char *path)
{
    int count = 0;
    DIR *d = opendir(path);
    if (!d) return 0;

    struct dirent *dd;
    while ((dd = readdir(d))) {
        if (strcmp(dd->d_name, ".") != 0 && strcmp(dd->d_name, "..") != 0) {
            ++count;
        }
    }

    closedir(d);
    return count;
}

static int
wait_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON *jc = cJSON_GetObjectItem(query, "channel");
    if (!jc || jc->type != cJSON_Number || jc->valuedouble <= 0) {
        err("%s: invalid json: no channel", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }
    int channel = (int) jc->valuedouble;
    int random_mode = 0;
    cJSON *jr = cJSON_GetObjectItem(query, "random_mode");
    if (jr && jr->type == cJSON_True) {
        random_mode = 1;
    }
    int enable_file = 0;
    cJSON *jef = cJSON_GetObjectItem(query, "enable_file");
    if (jef && jef->type == cJSON_True) {
        enable_file = 1;
    }

    while (1) {
        unsigned char pkt_name[PATH_MAX];
        int r = scan_dir(as->queue_dir, pkt_name, sizeof(pkt_name), random_mode);
        if (r < 0) {
            cJSON_AddStringToObject(reply, "message", "scan_dir failed");
            err("%s: scan_dir failed: %s", as->inst_id, strerror(-r));
            return 0;
        }
        if (!r) break;

        if (!enable_file) {
            cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
            cJSON_AddStringToObject(reply, "q", "poll-result");
        }

        char *data = NULL;
        size_t size = 0;
        r = safe_read_packet(as, pkt_name, &data, &size);
        if (r < 0) {
            cJSON_AddStringToObject(reply, "message", "read_packet failed");
            return 0;
        }
        if (r > 0) {
            cJSON_AddStringToObject(reply, "q", "file-result");
            cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
            cJSON_AddTrueToObject(reply, "found");
            add_file_to_object(reply, data, size);
            free(data);
            return 1;
        }
    }

    as->wait_random_mode = random_mode;
    as->wait_enable_file = enable_file;
    as->wait_serial = channel;
    as->wait_time_ms = as->current_time_ms;
    as->spool_wd = inotify_add_watch(as->ifd, as->queue_packet_dir, IN_CREATE | IN_MOVED_TO);
    if (as->spool_wd < 0) {
        // for debug purposes: fail immediately
        err("%s: wait_func: inotify_add_watch failed: %s",
            as->inst_id, os_ErrorMsg());
        exit(1);
    }

    if (simple_count_files(as, as->queue_packet_dir) > 0) {
        // undo inotify watching and restart this function
        as->wait_serial = 0;
        as->wait_time_ms = 0;
        as->wait_random_mode = 0;
        as->wait_enable_file = 0;
        if (as->spool_wd >= 0) {
            inotify_rm_watch(as->ifd, as->spool_wd);
            as->spool_wd = -1;
        }

        return wait_func(as, cb, query, reply);
    }

    cJSON_AddNumberToObject(reply, "channel", as->wait_serial);
    cJSON_AddStringToObject(reply, "q", "channel-result");

    return 1;
}

static int
add_ignored_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        cJSON_AddStringToObject(reply, "q", "result");
        err("%s: get_packet: missing pkt_name", as->inst_id);
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;

    scan_dir_add_ignored(as->queue_dir, pkt_name);
    cJSON_AddStringToObject(reply, "q", "result");
    return 1;
}

static int
put_packet_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    int result = 0;
    char *data = NULL;
    size_t size = 0;
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        err("%s: get_packet: missing pkt_name", as->inst_id);
        goto done;
    }
    const unsigned char *pkt_name = jp->valuestring;

    if (extract_file(as, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }

    if (generic_write_file(data, size, SAFE, as->queue_dir, pkt_name, "") < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    result = 1;

done:
    cJSON_AddStringToObject(reply, "q", "result");
    free(data);
    return result;
}

static int
put_heartbeat_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    int result = 0;
    char *data = NULL;
    size_t size = 0;
    unsigned char in_path[PATH_MAX];
    int fd = -1;
    unsigned char *mem = MAP_FAILED;
    unsigned char dir_path[PATH_MAX];

    in_path[0] = 0;
    cJSON *jn = cJSON_GetObjectItem(query, "name");
    if (!jn || jn->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        err("%s: put_heartbeat: missing name", as->inst_id);
        goto done;
    }
    const unsigned char *file_name = jn->valuestring;
    if (extract_file(as, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }

    snprintf(in_path, sizeof(in_path), "%s/%s", as->heartbeat_in_dir, file_name);

    fd = open(in_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        err("%s: put_heartbeat: open failed: %s", as->inst_id, os_ErrorMsg());
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    if (ftruncate(fd, size) < 0) {
        err("%s: put_heartbeat: ftruncate failed: %s", as->inst_id, os_ErrorMsg());
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    if (size > 0) {
        mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
            err("%s: put_heartbeat: mmap failed: %s", as->inst_id, os_ErrorMsg());
            cJSON_AddStringToObject(reply, "message", "filesystem error");
            goto done;
        }
        close(fd); fd = -1;
        memmove(mem, data, size);
        munmap(mem, size); mem = MAP_FAILED;
    }

    snprintf(dir_path, sizeof(dir_path), "%s/%s", as->heartbeat_packet_dir, file_name);
    if (rename(in_path, dir_path) < 0) {
        err("%s: rename failed: %s", as->inst_id, os_ErrorMsg());
        goto done;
    }
    in_path[0] = 0;

    snprintf(dir_path, sizeof(dir_path), "%s/%s@S", as->heartbeat_packet_dir, file_name);
    if (access(dir_path, F_OK) >= 0) {
        cJSON_AddTrueToObject(reply, "stop_flag");
        unlink(dir_path);
    }
    snprintf(dir_path, sizeof(dir_path), "%s/%s@D", as->heartbeat_packet_dir, file_name);
    if (access(dir_path, F_OK) >= 0) {
        cJSON_AddTrueToObject(reply, "down_flag");
        unlink(dir_path);
    }
    snprintf(dir_path, sizeof(dir_path), "%s/%s@R", as->heartbeat_packet_dir, file_name);
    if (access(dir_path, F_OK) >= 0) {
        cJSON_AddTrueToObject(reply, "reboot_flag");
        unlink(dir_path);
    }

    result = 1;

done:;
    cJSON_AddStringToObject(reply, "q", "heartbeat-result");
    if (mem != MAP_FAILED) munmap(mem, size);
    if (fd >= 0) close(fd);
    if (in_path[0]) unlink(in_path);
    free(data);
    return result;
}

static int
delete_heartbeat_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    int result = 0;
    unsigned char path[PATH_MAX];

    cJSON *jn = cJSON_GetObjectItem(query, "name");
    if (!jn || jn->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        err("%s: delete_heartbeat: missing name", as->inst_id);
        goto done;
    }
    const unsigned char *file_name = jn->valuestring;

    snprintf(path, sizeof(path), "%s/%s", as->heartbeat_packet_dir, file_name);
    unlink(path);
    result = 1;

done:;
    cJSON_AddStringToObject(reply, "q", "result");

    return result;
}

static int
put_archive_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    char *data = NULL;
    size_t size = 0;
    int result = 0;

    if (extract_file(as, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }
    cJSON *jserver = cJSON_GetObjectItem(query, "server");
    if (!jserver || jserver->type != cJSON_String || !jserver->valuestring) {
        err("%s: invalid json: no server", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;
    cJSON *jcid = cJSON_GetObjectItem(query, "contest");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        err("%s: invalid json: invalid contest_id", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;
    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring) {
        err("%s: invalid json: no run_name", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;
    const unsigned char *suffix = NULL;
    cJSON *jsuffix = cJSON_GetObjectItem(query, "suffix");
    if (jsuffix && jsuffix->type == cJSON_String) {
        suffix = jsuffix->valuestring;
    }

    struct ContestInfo *ci = create_contest_dirs(as, server, contest_id);
    if (!ci) {
        err("%s: directory creation failed", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    if (generic_write_file(data, size, 0, ci->output_dir, run_name, suffix) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    cJSON_AddStringToObject(reply, "q", "result");
    result = 1;

done:
    free(data);
    return result;
}

static int
mirror_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    int fd = -1;
    int result = 0;
    unsigned char *pkt_ptr = MAP_FAILED;
    size_t pkt_size = 0;
    unsigned char perm_buf[64];

    /*
      query: { "path" : PATH, "size" : SIZE, "mtime" : MTIME, "mode" : MODE }
     */

    cJSON *jpath = cJSON_GetObjectItem(query, "path");
    if (!jpath || jpath->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        err("%s: mirror: missing path", as->inst_id);
        goto done;
    }
    const unsigned char *path = jpath->valuestring;

    cJSON *jsize = cJSON_GetObjectItem(query, "size");
    int64_t size = -1;
    if (jsize) {
        if (!jsize || jsize->type != cJSON_Number) {
            cJSON_AddStringToObject(reply, "message", "invalid json");
            err("%s: mirror: invalid size", as->inst_id);
            goto done;
        }
        size = jsize->valuedouble;
        if (size < 0) size = -1;
    }

    cJSON *jmtime = cJSON_GetObjectItem(query, "mtime");
    time_t mtime = 0;
    if (jmtime) {
        if (jmtime->type != cJSON_Number) {
            cJSON_AddStringToObject(reply, "message", "invalid json");
            err("%s: mirror: invalid mtime", as->inst_id);
            goto done;
        }
        if ((mtime = jmtime->valuedouble) < 0) mtime = 0;
    }

    int mode = -1;
    cJSON *jmode = cJSON_GetObjectItem(query, "mode");
    if (jmode) {
        if (jmode->type != cJSON_String) {
            cJSON_AddStringToObject(reply, "message", "invalid json");
            err("%s: mirror: invalid mode", as->inst_id);
            goto done;
        }
        // FIXME: check for errors
        mode = strtol(jmode->valuestring, NULL, 8);
        if (mode < 0 || mode > 07777) mode = -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
    if (fd < 0) {
        cJSON_AddStringToObject(reply, "message", "cannot open file");
        err("%s: mirror: open '%s' failed: %s ", as->inst_id, path,
            strerror(errno));
        goto done;
    }
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        err("%s: mirror: fstat '%s' failed: %s ", as->inst_id, path,
            strerror(errno));
        goto done;
    }
    if (!S_ISREG(stb.st_mode)) {
        cJSON_AddStringToObject(reply, "message", "not a regular file");
        err("%s: mirror: '%s' not a regular file", as->inst_id, path);
        goto done;
    }
    if (stb.st_size > 1073741824) {
        cJSON_AddStringToObject(reply, "message", "file is too big");
        err("%s: mirror: '%s' file is too big: %lld", as->inst_id, path,
            (long long) stb.st_size);
        goto done;
    }
    if (size >= 0 && size == stb.st_size
        && mtime > 0 && mtime == stb.st_mtime
        && mode >= 0 && mode == (stb.st_mode & 07777)) {
        cJSON_AddStringToObject(reply, "q", "file-unchanged");
        cJSON_AddTrueToObject(reply, "found");
        result = 1;
        goto done;
    }
    snprintf(perm_buf, sizeof(perm_buf), "%04o", stb.st_mode & 07777);
    cJSON_AddStringToObject(reply, "mode", perm_buf);
    cJSON_AddNumberToObject(reply, "mtime", stb.st_mtime);
    cJSON_AddNumberToObject(reply, "uid", stb.st_uid);
    cJSON_AddNumberToObject(reply, "gid", stb.st_gid);
    if (stb.st_size <= 0) {
        add_file_to_object(reply, NULL, 0);
        cJSON_AddStringToObject(reply, "q", "file-result");
        cJSON_AddTrueToObject(reply, "found");
        result = 1;
        goto done;
    }
    pkt_size = stb.st_size;
    pkt_ptr = mmap(NULL, pkt_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (pkt_ptr == MAP_FAILED) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        err("%s: mirror: mmap '%s' failed: %s ", as->inst_id, path,
            strerror(errno));
        goto done;
    }
    close(fd); fd = -1;
    cJSON_AddStringToObject(reply, "q", "file-result");
    cJSON_AddTrueToObject(reply, "found");
    add_file_to_object(reply, pkt_ptr, pkt_size);
    result = 1;

done:;
    if (pkt_ptr != MAP_FAILED) munmap(pkt_ptr, pkt_size);
    if (fd >= 0) close(fd);
    return result;
}

static int
cancel_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    cJSON *jc = cJSON_GetObjectItem(query, "channel");
    if (!jc || jc->type != cJSON_Number || jc->valuedouble <= 0) {
        err("%s: invalid json: no channel", as->inst_id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }
    int channel = (int) jc->valuedouble;

    if (as->wait_serial <= 0) {
        err("%s: cancel: requested %d but no wait channel registered",
            as->inst_id, channel);
        cJSON_AddStringToObject(reply, "message", "not in wait state");
        cJSON_AddTrueToObject(reply, "invalid-channel");
    } else if (as->wait_serial != channel) {
        err("%s: cancel: requested %d but registered %d",
            as->inst_id, channel, as->wait_serial);
        cJSON_AddStringToObject(reply, "message", "bad wait state");
        cJSON_AddTrueToObject(reply, "invalid-channel");
    }

    cJSON_ReplaceItemInObject(reply, "s", cJSON_CreateNumber(channel));
    if (as->wait_time_ms > 0) {
        cJSON_ReplaceItemInObject(reply, "t", cJSON_CreateNumber(as->wait_time_ms));
    }
    cJSON_AddStringToObject(reply, "q", "poll-result");


    as->wait_serial = 0;
    as->wait_time_ms = 0;
    as->wait_random_mode = 0;
    as->wait_enable_file = 0;
    if (as->spool_wd >= 0) {
        inotify_rm_watch(as->ifd, as->spool_wd);
        as->spool_wd = -1;
    }
    return 1;
}

int
main(int argc, char *argv[])
{
    int retval = 1;
    const unsigned char *inst_id = NULL;
    const unsigned char *queue_id = NULL;
    __attribute__((unused)) const unsigned char *ip_address = NULL;
    int mode = 0;
    int argi = 1;
    int verbose_mode = 0;

    {
        char *s = strrchr(argv[0], '/');
        if (s) {
            program_name = s + 1;
        } else {
            program_name = argv[0];
        }
    }

    signal(SIGPIPE, SIG_IGN);

    while (argi < argc) {
        if (!strcmp(argv[argi], "-n")) {
            if (argi + 1 >= argc) die("argument expected for -n");
            queue_id = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "-i")) {
            if (argi + 1 >= argc) die("argument expected for -i");
            inst_id = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "-l")) {
            if (argi + 1 >= argc) die("argument expected for -l");
            log_file = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--ip")) {
            if (argi + 1 >= argc) die("argument expected for --ip");
            ip_address = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "-m")) {
            if (argi + 1 >= argc) die("argument expected for -m");
            if (!strcmp(argv[argi + 1], "compile")) {
                mode = PREPARE_COMPILE;
            } else if (!strcmp(argv[argi + 1], "run")) {
                mode = PREPARE_RUN;
            } else die("invalid mode");
            argi += 2;
        } else if (!strcmp(argv[argi], "-v")) {
            verbose_mode = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        } else if (argv[argi][0] == '-') {
            die("invalid option");
        } else {
            break;
        }
    }
    if (argi != argc) {
        die("invalid arguments");
    }

    random_init();

    struct AppState app;
    app_state_init(&app);
    app.verbose_mode = verbose_mode;

    if (app_state_prepare(&app) < 0) goto done;

    {
        char *id_s = NULL;
        size_t id_z = 0;
        FILE *id_f = open_memstream(&id_s, &id_z);
        if (inst_id && inst_id[0]) {
            fprintf(id_f, "%s", inst_id);
        } else {
            const char *s = getenv("SSH_CLIENT");
            if (s && *s) {
                fprintf(id_f, "[%s]", s);
            } else {
                fprintf(id_f, "[pid %d]", getpid());
            }
        }
        fclose(id_f);
        app.inst_id = id_s;
    }

    if (queue_id && *queue_id) {
        app.queue_id = xstrdup(queue_id);
    }
    app.mode = mode;
    if (app_state_configure_directories(&app) < 0) {
        die("failed to create spool directories");
    }

    app_state_add_query_callback(&app, "ping", NULL, ping_query_func);
    app_state_add_query_callback(&app, "set", NULL, set_query_func);
    app_state_add_query_callback(&app, "poll", NULL, poll_func);
    app_state_add_query_callback(&app, "get-packet", NULL, get_packet_func);
    app_state_add_query_callback(&app, "get-data", NULL, get_data_func);
    app_state_add_query_callback(&app, "put-reply", NULL, put_reply_func);
    app_state_add_query_callback(&app, "put-output", NULL, put_output_func);
    app_state_add_query_callback(&app, "wait", NULL, wait_func);
    app_state_add_query_callback(&app, "add-ignored", NULL, add_ignored_func);
    app_state_add_query_callback(&app, "put-packet", NULL, put_packet_func);
    app_state_add_query_callback(&app, "put-heartbeat", NULL, put_heartbeat_func);
    app_state_add_query_callback(&app, "delete-heartbeat", NULL, delete_heartbeat_func);
    app_state_add_query_callback(&app, "put-archive", NULL, put_archive_func);
    app_state_add_query_callback(&app, "mirror", NULL, mirror_func);
    app_state_add_query_callback(&app, "cancel", NULL, cancel_func);

    if (log_file && *log_file) {
        int fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND | O_NOCTTY, 0600);
        if (fd < 0) {
            die("cannot open log file '%s': %s", log_file, strerror(errno));
        }
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    info("%s: started", app.inst_id);
    do_loop(&app);
    info("%s: finished", app.inst_id);

    retval = 0;

done:
    app_state_destroy(&app);
    return retval;
}
