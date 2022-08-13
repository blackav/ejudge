/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

static const unsigned char *program_name;

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
};

struct AppState
{
    struct FDInfo *fd_first, *fd_last;

    struct FDInfo *stdin_fdi;
    struct FDInfo *stdout_fdi;
    struct FDInfo *signal_fdi;

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

    int sfd;                    /* signal file descriptor */
    int efd;                    /* epoll file descriptor */

    long long current_time_us;
    unsigned char *name;
    int mode;
    unsigned char *id;

    unsigned char *spool_dir;
    unsigned char *queue_dir;
    unsigned char *queue_packet_dir;
    unsigned char *data_dir;
    unsigned char *heartbeat_spool_dir;
};

static void
app_state_init(struct AppState *as)
{
    memset(as, 0, sizeof(*as));
    as->sfd = -1;
    as->efd = -1;
}

static void
app_state_destroy(struct AppState *as)
{
    if (as->sfd >= 0) close(as->sfd);
    if (as->efd >= 0) close(as->efd);

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
            err("%s: epoll_ctl failed: %s", as->id, os_ErrorMsg());
            return;
        }
        fdi->events = EPOLLIN;
    }

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_MOD, fdi->fd, &ev) < 0) {
        err("%s: epoll_ctl failed: %s", as->id, os_ErrorMsg());
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
            err("%s: epoll_ctl failed: %s", as->id, os_ErrorMsg());
            return;
        }
        fdi->events = EPOLLOUT;
    }

    struct epoll_event ev = { .events = EPOLLOUT, .data.ptr = fdi };
    if (epoll_ctl(as->efd, EPOLL_CTL_MOD, fdi->fd, &ev) < 0) {
        err("%s: epoll_ctl failed: %s", as->id, os_ErrorMsg());
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
        err("%s: epoll_ctl failed: %s", as->id, os_ErrorMsg());
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
            err("%s: signal_read_func: read failed: %s", as->id, os_ErrorMsg());
            break;
        }
        if (r != sizeof(sss)) {
            err("%s: signal_read_func: read returned invalid size %d", as->id, r);
            break;
        }
        switch (sss.ssi_signo) {
        case SIGINT:  as->term_flag = 1; break;
        case SIGTERM: as->term_flag = 1; break;
        default:
            err("%s: signal_read_func: unexpected signal %d", as->id, sss.ssi_signo);
            break;
        }
    }
}

static const struct FDInfoOps signal_ops =
{
    .op_read = signal_read_func,
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
            err("%s: pipe_read_func: read failed: %s", as->id, os_ErrorMsg());
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
    as->current_time_us = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    cJSON_AddNumberToObject(reply, "T", (double) as->current_time_us);
    cJSON_AddNumberToObject(reply, "S", (double) ++as->serial);

    if (strlen(data) != size) {
        cJSON_AddStringToObject(reply, "message", "binary data");
        err("%s: binary data on stdin", as->id);
        goto done;
    }

    root = cJSON_Parse(data);
    if (!root) {
        cJSON_AddStringToObject(reply, "message", "JSON parse error");
        err("%s: JSON parsing failed", as->id);
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
        err("%s: invalid json", as->id);
        goto done;
    }
    const unsigned char *query = jq->valuestring;

    void *vp = dyntrie_get(&as->queryi, query);
    if (!vp) {
        cJSON_AddStringToObject(reply, "message", "Invalid query");
        err("%s: invalid query", as->id);
        goto done;
    }
    const struct QueryCallback *c = &as->querys[((int)(intptr_t) vp) - 1];
    ok = c->callback(as, c, root, reply);

done:
    cJSON_AddBoolToObject(reply, "ok", ok);
    jstr = cJSON_Print(reply);
    jlen = strlen(jstr);
    info("%s: json: %s", as->id, jstr);
    jstr = realloc(jstr, jlen + 2);
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
                memcpy(&fdi->wchunks[0], &fdi->wchunks[1], fdi->wchunku - 1);
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
            err("%s: pipe_write_func: write failed: %s", as->id, os_ErrorMsg());
            goto done;
        }
        if (!r) {
            err("%s: pipe_write_func: write returned 0", as->id);
            goto done;
        }
        fdi->wr_pos += r;
    }
    return;

done:
    app_state_disarm(as, fdi);
    close(fdi->fd); fdi->fd = -1;
    //process_state_notify(as, fdi->prc);
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

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGTERM);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    if ((as->sfd = signalfd(-1, &ss, SFD_CLOEXEC | SFD_NONBLOCK)) < 0) {
        err("%s: signalfd failed: %s", as->id, os_ErrorMsg());
        goto fail;
    }
    
    if ((as->efd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        err("%s: epoll_create failed: %s", as->id, os_ErrorMsg());
        goto fail;
    }

    as->signal_fdi = fdinfo_create(as, as->sfd, &signal_ops);
    app_state_arm_for_read(as, as->signal_fdi);
    
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
    as->stdin_fdi = fdinfo_create(as, 0, &stdin_ops);
    app_state_arm_for_read(as, as->stdin_fdi);

    fcntl(1, F_SETFL, fcntl(1, F_GETFL) | O_NONBLOCK);
    as->stdout_fdi = fdinfo_create(as, 1, &stdout_ops);

    return 0;

fail:
    return -1;
}

static void
app_state_configure_directories(struct AppState *as)
{
    if (!as->mode || !as->name) return;

    if (as->mode == PREPARE_COMPILE) {
#if defined EJUDGE_COMPILE_SPOOL_DIR
        char *s = NULL;
        asprintf(&s, "%s/%s", EJUDGE_COMPILE_SPOOL_DIR, as->name);
        as->spool_dir = s; s = NULL;
        asprintf(&s, "%s/queue", as->spool_dir);
        as->queue_dir = s; s = NULL;
        asprintf(&s, "%s/dir", as->queue_dir);
        as->queue_packet_dir = s; s = NULL;
        asprintf(&s, "%s/%s/src", EJUDGE_COMPILE_SPOOL_DIR, as->name);
        as->data_dir = s; s = NULL;
#endif
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
            info("%s: epoll_wait interrupted by a signal", as->id);
            continue;
        }
        if (n < 0) {
            err("%s: epoll_wait failed: %s", as->id, os_ErrorMsg());
            return;
        }
        if (!n) {
            err("%s: epoll_wait returned 0", as->id);
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
        free(as->name);
        as->name = xstrdup(jn->valuestring);
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
    if (as->name && as->name[0]) {
        cJSON_AddStringToObject(reply, "name", as->name);
    }
    if (as->mode == PREPARE_COMPILE) {
        cJSON_AddStringToObject(reply, "mode", "compile");
    } else if (as->mode == PREPARE_RUN) {
        cJSON_AddStringToObject(reply, "mode", "run");
    }
    cJSON_AddStringToObject(reply, "q", "get");
    return 1;
}

static int
poll_func(
        struct AppState *as,
        const struct QueryCallback *cb,
        cJSON *query,
        cJSON *reply)
{
    unsigned char pkt_name[PATH_MAX];
    int r = scan_dir(as->queue_dir, pkt_name, sizeof(pkt_name), 0);
    if (r < 0) {
        cJSON_AddStringToObject(reply, "message", "scan_dir failed");
        err("%s: scan_dir failed: %s", as->id, strerror(-r));
        return 0;
    }
    if (r > 0) {
        cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
    }
    cJSON_AddStringToObject(reply, "q", "poll-result");
    return 1;
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
        err("%s: get_packet: missing pkt_name", as->id);
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;
    char *pkt_ptr = NULL;
    size_t pkt_len = 0;
    int r = generic_read_file(&pkt_ptr, 0, &pkt_len, SAFE | REMOVE,
                              as->queue_dir, pkt_name, "");
    if (r < 0 || !pkt_ptr) {
        cJSON_AddStringToObject(reply, "message", "failed to read file");
        return 0;
    }
    cJSON_AddStringToObject(reply, "q", "file-result");
    if (!r) {
        // just file not found
        return 1;
    }
    cJSON_AddTrueToObject(reply, "found");
    cJSON_AddNumberToObject(reply, "size", (double) pkt_len);
    if (!pkt_len) {
        free(pkt_ptr);
        return 1;
    }
    cJSON_AddTrueToObject(reply, "b64");
    char *ptr = malloc(pkt_len * 2 + 16);
    int n = base64u_encode(pkt_ptr, pkt_len, ptr);
    ptr[n] = 0;
    cJSON_AddStringToObject(reply, "data", ptr);
    free(ptr);
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
        err("%s: get_packet: missing pkt_name", as->id);
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
    if (r < 0 || !pkt_ptr) {
        cJSON_AddStringToObject(reply, "message", "failed to read file");
        return 0;
    }
    cJSON_AddStringToObject(reply, "q", "file-result");
    if (!r) {
        // just file not found
        return 1;
    }
    cJSON_AddTrueToObject(reply, "found");
    cJSON_AddNumberToObject(reply, "size", (double) pkt_len);
    if (!pkt_len) {
        free(pkt_ptr);
        return 1;
    }
    cJSON_AddTrueToObject(reply, "b64");
    char *ptr = malloc(pkt_len * 2 + 16);
    int n = base64u_encode(pkt_ptr, pkt_len, ptr);
    ptr[n] = 0;
    cJSON_AddStringToObject(reply, "data", ptr);
    free(ptr);
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
        err("%s: invalid json: no size", as->id);
        return -1;
    }
    size_t size = (int) jz->valuedouble;
    if (size < 0 || size > 1000000000) {
        err("%s: invalid json: invalid size", as->id);
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
        err("%s: invalid json: no encoding", as->id);
        return -1;
    }
    cJSON *jd = cJSON_GetObjectItem(j, "data");
    if (!jd || jd->type != cJSON_String) {
        err("%s: invalid json: no data", as->id);
        return -1;
    }
    int len = strlen(jd->valuestring);
    char *ptr = malloc(len + 1);
    int b64err = 0;
    int n = base64u_decode(jd->valuestring, len, ptr, &b64err);
    if (n != size) {
        err("%s: invalid json: size mismatch", as->id);
        free(ptr);
        return -1;
    }
    ptr[size] = 0;
    *p_pkt_ptr = ptr;
    *p_pkt_len = size;
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

    unsigned char server_dir[PATH_MAX];
    snprintf(server_dir, sizeof(server_dir), "%s/%s", EJUDGE_COMPILE_SPOOL_DIR, server);
    unsigned char server_contest_dir[PATH_MAX];
    snprintf(server_contest_dir, sizeof(server_contest_dir), "%s/%06d", server_dir, contest_id);
    unsigned char status_dir[PATH_MAX];
    snprintf(status_dir, sizeof(status_dir), "%s/status", server_contest_dir);
    unsigned char report_dir[PATH_MAX];
    snprintf(report_dir, sizeof(report_dir), "%s/report", server_contest_dir);

    if (make_dir(server_dir, 0777) < 0) {
        return NULL;
    }
    if (make_dir(server_contest_dir, 0777) < 0) {
        return NULL;
    }
    if (make_all_dir(status_dir, 0777) < 0) {
        return NULL;
    }
    if (make_dir(report_dir, 0777) < 0) {
        return NULL;
    }

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
        err("%s: invalid json: no server", as->id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;
    cJSON *jcid = cJSON_GetObjectItem(query, "contest_id");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        err("%s: invalid json: invalid contest_id", as->id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;
    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring) {
        err("%s: invalid json: no run_name", as->id);
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;

    struct ContestInfo *ci = create_contest_dirs(as, server, contest_id);
    if (!ci) {
        err("%s: directory creation failed", as->id);
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

int
main(int argc, char *argv[])
{
    int retval = 1;
    const unsigned char *id = NULL;
    const unsigned char *name = NULL;
    int mode = 0;
    int argi = 1;

    signal(SIGPIPE, SIG_IGN);

    while (argi < argc) {
        if (!strcmp(argv[argi], "-n")) {
            if (argi + 1 >= argc) die("argument expected for -n");
            name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "-i")) {
            if (argi + 1 >= argc) die("argument expected for -i");
            id = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "-m")) {
            if (argi + 1 >= argc) die("argument expected for -m");
            if (!strcmp(argv[argi + 1], "compile")) {
                mode = PREPARE_COMPILE;
            } else if (!strcmp(argv[argi + 1], "run")) {
                mode = PREPARE_SERVE;
            } else die("invalid mode");
            argi += 2;
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

    struct AppState app;
    app_state_init(&app);

    if (app_state_prepare(&app) < 0) goto done;

    {
        char *id_s = NULL;
        size_t id_z = 0;
        FILE *id_f = open_memstream(&id_s, &id_z);
        if (id && id[0]) {
            fprintf(id_f, "%s", id);
        } else {
            const char *s = getenv("SSH_CLIENT");
            if (s && *s) {
                fprintf(id_f, "[%s]", s);
            } else {
                fprintf(id_f, "[pid %d]", getpid());
            }
        }
        fclose(id_f);
        app.id = id_s;
    }

    if (name && *name) {
        app.name = xstrdup(name);
    }
    app.mode = mode;
    app_state_configure_directories(&app);

    app_state_add_query_callback(&app, "ping", NULL, ping_query_func);
    app_state_add_query_callback(&app, "set", NULL, set_query_func);
    app_state_add_query_callback(&app, "poll", NULL, poll_func);
    app_state_add_query_callback(&app, "get-packet", NULL, get_packet_func);
    app_state_add_query_callback(&app, "get-data", NULL, get_data_func);
    app_state_add_query_callback(&app, "put-reply", NULL, put_reply_func);

    info("%s: started", app.id);
    do_loop(&app);
    info("%s: finished", app.id);

    retval = 0;

done:
    app_state_destroy(&app);
    return retval;
}
