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
#include "ejudge/agent_client.h"
#include "ejudge/prepare.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/base64.h"

#include <stdlib.h>
#include "ejudge/cJSON.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <ctype.h>

struct FDChunk
{
    unsigned char *data;
    int size;
};

struct Future
{
    int serial;
    int notify_signal;
    void (*callback)(struct Future *f, void *u);
    void *user;

    int ready;
    pthread_mutex_t m;
    pthread_cond_t c;

    cJSON *value;
};

struct AgentClientSsh
{
    struct AgentClient b;

    pthread_t tid;

    unsigned char *inst_id;
    unsigned char *endpoint;
    unsigned char *queue_id;
    int mode;
    int verbose_mode;

    // read buffer
    unsigned char *rd_data;
    int rd_size, rd_rsrv;

    unsigned char *wr_data;
    int wr_size, wr_pos;

    pthread_mutex_t rchunkm;
    pthread_cond_t rchunkc;
    struct FDChunk *rchunks;
    int rchunku;
    int rchunka;

    pthread_mutex_t wchunkm;
    struct FDChunk *wchunks;
    int wchunku;
    int wchunka;
    uint32_t wevents;

    pthread_mutex_t futurem;
    struct Future **futures;
    int futureu;
    int futurea;

    int efd;
    int pid;                    /* ssh pid */
    int from_ssh;               /* pipe to ssh */
    int to_ssh;                 /* pipe from ssh */
    int vfd;                    /* to wake up connect thread */
    int tfd;                    /* timer file descriptor */

    _Bool need_cleanup;         /* if read/write failed, clean-up */
    _Atomic _Bool stop_request;
    _Atomic _Bool is_stopped;
    pthread_mutex_t stop_m;
    pthread_cond_t stop_c;

    int serial;
    long long current_time_ms;
    long long last_write_ms;
    int timer_flag;

    long long ping_time_ms;
    struct Future *ping_future;
};

static void future_init(struct Future *f, int serial)
{
    memset(f, 0, sizeof(*f));
    f->serial = serial;
    pthread_mutex_init(&f->m, NULL);
    pthread_cond_init(&f->c, NULL);
}

static void future_fini(struct Future *f)
{
    pthread_mutex_destroy(&f->m);
    pthread_cond_destroy(&f->c);
    if (f->value) cJSON_Delete(f->value);
}

static void future_wait(struct Future *f)
{
    pthread_mutex_lock(&f->m);
    while (!f->ready) {
        pthread_cond_wait(&f->c, &f->m);
    }
    pthread_mutex_unlock(&f->m);
}

static struct AgentClient *
destroy_func(struct AgentClient *ac)
{
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    if (!acs) return NULL;

    pthread_mutex_destroy(&acs->futurem);
    free(acs->futures);
    pthread_mutex_destroy(&acs->stop_m);
    pthread_cond_destroy(&acs->stop_c);
    pthread_mutex_destroy(&acs->wchunkm);
    for (int i = 0; i < acs->wchunku; ++i) {
        free(acs->wchunks[i].data);
    }
    free(acs->wchunks);
    free(acs->wr_data);
    pthread_mutex_destroy(&acs->rchunkm);
    pthread_cond_destroy(&acs->rchunkc);
    for (int i = 0; i < acs->rchunku; ++i) {
        free(acs->rchunks[i].data);
    }
    free(acs->rchunks);
    free(acs->rd_data);
    if (acs->pid > 0) {
        kill(acs->pid, SIGKILL);
        waitpid(acs->pid, NULL, 0);
    }
    if (acs->efd >= 0) close(acs->efd);
    if (acs->from_ssh >= 0) close(acs->from_ssh);
    if (acs->to_ssh >= 0) close(acs->to_ssh);
    if (acs->vfd >= 0) close(acs->vfd);
    if (acs->tfd >= 0) close(acs->tfd);
    free(acs);
    return NULL;
}

static int
init_func(
        struct AgentClient *ac,
        const unsigned char *inst_id,
        const unsigned char *endpoint,
        const unsigned char *queue_id,
        int mode,
        int verbose_mode)
{
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    acs->inst_id = xstrdup(inst_id);
    acs->endpoint = xstrdup(endpoint);
    if (queue_id) {
        acs->queue_id = xstrdup(queue_id);
    }
    acs->mode = mode;
    acs->verbose_mode = verbose_mode;
    return 0;
}

static void
add_rchunk(struct AgentClientSsh *acs, const unsigned char *data, int size)
{
    pthread_mutex_lock(&acs->rchunkm);
    if (acs->rchunka == acs->rchunku) {
        if (!(acs->rchunka *= 2)) acs->rchunka = 4;
        XREALLOC(acs->rchunks, acs->rchunka);
    }
    struct FDChunk *c = &acs->rchunks[acs->rchunku++];
    c->data = malloc(size + 1);
    memcpy(c->data, data, size);
    c->data[size] = 0;
    c->size = size;
    if (acs->rchunku == 1) {
        pthread_cond_signal(&acs->rchunkc);
    }
    pthread_mutex_unlock(&acs->rchunkm);
}

static void
add_wchunk_move(struct AgentClientSsh *acs, unsigned char *data, int size)
{
    pthread_mutex_lock(&acs->wchunkm);
    if (acs->wchunka == acs->wchunku) {
        if (!(acs->wchunka *= 2)) acs->wchunka = 4;
        XREALLOC(acs->wchunks, acs->wchunka);
    }
    struct FDChunk *c = &acs->wchunks[acs->wchunku++];
    c->data = data;
    c->size = size;
    pthread_mutex_unlock(&acs->wchunkm);
    uint64_t v = 1;
    write(acs->vfd, &v, sizeof(v));
}

static void
add_future(struct AgentClientSsh *acs, struct Future *f)
{
    pthread_mutex_lock(&acs->futurem);
    if (acs->futurea == acs->futureu) {
        if (!(acs->futurea *= 2)) acs->futurea = 4;
        XREALLOC(acs->futures, acs->futurea);
    }
    acs->futures[acs->futureu++] = f;
    pthread_mutex_unlock(&acs->futurem);
}

static struct Future *
get_future(struct AgentClientSsh *acs, int serial)
{
    struct Future *result = NULL;
    pthread_mutex_lock(&acs->futurem);
    for (int i = 0; i < acs->futureu; ++i) {
        if (acs->futures[i]->serial == serial) {
            result = acs->futures[i];
            if (i < acs->futureu - 1) {
                memcpy(&acs->futures[i], &acs->futures[i + 1],
                       (acs->futureu - i - 1) * sizeof(acs->futures[0]));
            }
            --acs->futureu;
            break;
        }
    }
    pthread_mutex_unlock(&acs->futurem);
    return result;
}

static void
do_pipe_read(struct AgentClientSsh *acs)
{
    char buf[65536];
    while (1) {
        errno = 0;
        int r = read(acs->from_ssh, buf, sizeof(buf));
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("pipe_read_func: read failed: %s", os_ErrorMsg());
            acs->need_cleanup = 1;
            return;
        }
        if (!r) {
            acs->need_cleanup = 1;
            return;
        }
        int exp_size = acs->rd_size + r + 1;
        if (exp_size >= acs->rd_rsrv) {
            int exp_rsrv = acs->rd_rsrv * 2;
            if (!exp_rsrv) exp_rsrv = 32;
            while (exp_rsrv < exp_size) exp_rsrv *= 2;
            acs->rd_data = xrealloc(acs->rd_data, exp_rsrv);
            acs->rd_rsrv = exp_rsrv;
        }
        memcpy(acs->rd_data + acs->rd_size, buf, r);
        acs->rd_size += r;
        acs->rd_data[acs->rd_size] = 0;
    }
    if (acs->rd_size >= 2) {
        int s = 0;
        for (int i = 1; i < acs->rd_size; ++i) {
            if (acs->rd_data[i] == '\n' && acs->rd_data[i - 1] == '\n') {
                add_rchunk(acs, &acs->rd_data[s], i - s + 1);
                s = i + 1;
            }
        }
        if (s > 0) {
            acs->rd_size -= s;
            memcpy(acs->rd_data, acs->rd_data + s, acs->rd_size);
        }
    }
}

static void
do_pipe_write(struct AgentClientSsh *acs)
{
    while (1) {
        int wsz = acs->wr_size - acs->wr_pos;
        if (wsz < 0) abort();
        if (!wsz) {
            unsigned char *data = NULL;
            int size = 0;
            pthread_mutex_lock(&acs->wchunkm);
            if (acs->wchunku > 0) {
                data = acs->wchunks[0].data;
                size = acs->wchunks[0].size;
                if (acs->wchunku > 1) {
                    memcpy(&acs->wchunks[0], &acs->wchunks[1],
                           (acs->wchunku - 1) * sizeof(acs->wchunks[0]));
                }
                --acs->wchunku;
            }
            pthread_mutex_unlock(&acs->wchunkm);
            if (!size) {
                free(data);
                free(acs->wr_data); acs->wr_data = NULL;
                acs->wr_size = 0; acs->wr_pos = 0;
                epoll_ctl(acs->efd, EPOLL_CTL_DEL, acs->to_ssh, NULL);
                acs->wevents = 0;
                return;
            }
            free(acs->wr_data);
            acs->wr_data = data;
            acs->wr_size = size;
            acs->wr_pos = 0;
            continue;
        }
        errno = 0;
        int r = write(acs->to_ssh, acs->wr_data + acs->wr_pos, wsz);
        if (r < 0 && errno == EAGAIN) {
            break;
        }
        if (r < 0) {
            err("pipe_write_func: write failed: %s", os_ErrorMsg());
            acs->need_cleanup = 1;
            return;
        }
        if (!r) {
            err("pipe_write_func: write returned 0");
            acs->need_cleanup = 1;
            return;
        }
        acs->wr_pos += r;
        acs->last_write_ms = acs->current_time_ms;
    }
}

static void
do_notify_read(struct AgentClientSsh *acs)
{
    uint64_t value = 0;
    int r;
    if ((r = read(acs->vfd, &value, sizeof(value))) < 0) {
        err("notify_read: read error: %s", os_ErrorMsg());
        acs->need_cleanup = 1;
    }
    if (r == 0) {
        err("notify_read: unexpected EOF");
        acs->need_cleanup = 1;
    }
    if (acs->stop_request) return;
    if (acs->to_ssh < 0) return;

    if (!(acs->wevents & EPOLLOUT)) {
        struct epoll_event ev = { .events = EPOLLOUT, .data.fd = acs->to_ssh };
        epoll_ctl(acs->efd, EPOLL_CTL_ADD, acs->to_ssh, &ev);
        acs->wevents |= EPOLLOUT;
    }
}

static void
do_timer_read(struct AgentClientSsh *acs)
{
    uint64_t value = 0;
    int r;
    if ((r = read(acs->tfd, &value, sizeof(value))) < 0) {
        err("timer_read: read error: %s", os_ErrorMsg());
        acs->need_cleanup = 1;
    } else if (r == 0) {
        err("timer_read: unexpected EOF");
        acs->need_cleanup = 1;
    } else {
        acs->timer_flag = 1;
    }
}

static void
handle_rchunks(struct AgentClientSsh *acs)
{
    pthread_mutex_lock(&acs->rchunkm);
    if (acs->rchunku <= 0) goto done1;

    for (int i = 0; i < acs->rchunku; ++i) {
        struct FDChunk *c = &acs->rchunks[i];
        if (acs->verbose_mode) {
            while (c->size > 0 && isspace(c->data[c->size - 1])) {
                --c->size;
            }
            c->data[c->size] = 0;
            info("from agent: %s", c->data);
        }
        cJSON *j = cJSON_Parse(c->data);
        if (!j) {
            err("JSON parse error");
        } else {
            cJSON *js = cJSON_GetObjectItem(j, "s");
            if (!js || js->type != cJSON_Number) {
                err("invalid JSON");
            } else {
                int serial = js->valuedouble;
                struct Future *f = get_future(acs, serial);
                if (f) {
                    if (f->callback) {
                        f->value = j; j = NULL;
                        f->ready = 1;
                        f->callback(f, f->user);
                    } else {
                        f->value = j; j = NULL;
                        pthread_mutex_lock(&f->m);
                        f->ready = 1;
                        pthread_cond_signal(&f->c);
                        pthread_mutex_unlock(&f->m);
                        if (f->notify_signal > 0) {
                            kill(getpid(), f->notify_signal);
                        }
                    }
                }
            }
            if (j) cJSON_Delete(j);
        }
        free(c->data); c->data = NULL; c->size = 0;
    }
    acs->rchunku = 0;

done1:
    pthread_mutex_unlock(&acs->rchunkm);
}

static struct Future *
internal_ping(struct AgentClientSsh *acs);

static void *
thread_func(void *ptr)
{
    sigset_t ss;
    sigfillset(&ss);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);

    struct AgentClientSsh *acs = (struct AgentClientSsh *) ptr;

    while (1) {
        struct epoll_event evs[16];
        errno = 0;
        int n = epoll_wait(acs->efd, evs, 16, -1);
        if (n < 0 && errno == EINTR) {
            info("epoll_wait interrupted by a signal");
            continue;
        }
        if (n < 0) {
            err("epoll_wait failed: %s", os_ErrorMsg());
            break;
        }
        if (!n) {
            err("epoll_wait returned 0");
            break;
        }

        {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            acs->current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
        }

        for (int i = 0; i < n; ++i) {
            struct epoll_event *ev = &evs[i];
            if (ev->data.fd == acs->vfd) {
                if ((ev->events & (EPOLLIN | EPOLLHUP)) != 0) {
                    do_notify_read(acs);
                } else {
                    err("spurious wake-up on read from ssh");
                }
            }
            if (ev->data.fd == acs->from_ssh) {
                if ((ev->events & (EPOLLIN | EPOLLHUP)) != 0) {
                    do_pipe_read(acs);
                } else {
                    err("spurious wake-up on read from ssh");
                }
            }
            if (ev->data.fd == acs->tfd) {
                if ((ev->events & (EPOLLIN | EPOLLHUP)) != 0) {
                    do_timer_read(acs);
                } else {
                    err("spurious wake-up on timer");
                }
            }
            if (acs->to_ssh >= 0 && ev->data.fd == acs->to_ssh) {
                if ((ev->events & (EPOLLOUT | EPOLLERR)) != 0) {
                    do_pipe_write(acs);
                } else {
                    err("spurious wake-up on write from ssh");
                }
            }
        }
        if (acs->timer_flag) {
            acs->timer_flag = 0;
            if (!acs->ping_future) {
                if (acs->current_time_ms - acs->last_write_ms > 120000) {
                    acs->ping_future = internal_ping(acs);
                }
            }
        }
        if (acs->stop_request) {
            // forcefully close write fd
            if ((acs->wevents & EPOLLOUT) != 0) {
                epoll_ctl(acs->efd, EPOLL_CTL_DEL, acs->to_ssh, NULL);
                acs->wevents = 0;
            }
            if (acs->to_ssh >= 0) {
                close(acs->to_ssh);
                acs->to_ssh = -1;
            }
        }
        if (acs->need_cleanup) {
            // what else to do?
            break;
        }
        handle_rchunks(acs);
    }

    if (acs->pid > 0) {
        kill(acs->pid, SIGKILL);
        waitpid(acs->pid, NULL, 0);
        acs->pid = -1;
    }

    pthread_mutex_lock(&acs->stop_m);
    acs->is_stopped = 1;
    pthread_cond_signal(&acs->stop_c);
    pthread_mutex_unlock(&acs->stop_m);

    return NULL;
}

static int
connect_func(struct AgentClient *ac)
{
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    int tossh[2] = { -1, -1 }, fromssh[2] = { -1, -1 };

    pipe2(tossh, O_CLOEXEC);
    pipe2(fromssh, O_CLOEXEC);

    acs->pid = fork();
    if (acs->pid < 0) {
        err("fork failed: %s", os_ErrorMsg());
        goto fail;
    }
    if (!acs->pid) {
        // ssh -aTx ENDPOINT -i ID -n NAME -m MODE EJUDGE/ej-agent 2>>LOG
        char *cmd_s = NULL;
        size_t cmd_z = 0;
        FILE *cmd_f = open_memstream(&cmd_s, &cmd_z);
        fprintf(cmd_f, "exec %s/ej-agent", EJUDGE_SERVER_BIN_PATH);
        if (acs->inst_id && acs->inst_id[0]) {
            fprintf(cmd_f, " -i '%s'", acs->inst_id);
        }
        if (acs->queue_id) {
            fprintf(cmd_f, " -n '%s'", acs->queue_id);
        }
        if (acs->mode == PREPARE_COMPILE) {
            fprintf(cmd_f, " -m compile");
        } else if (acs->mode == PREPARE_RUN) {
            fprintf(cmd_f, " -m run");
        }
        if (acs->verbose_mode) {
            fprintf(cmd_f, " -v");
        }
        fprintf(cmd_f, " 2>>%s/var/ej-agent.log", EJUDGE_CONTESTS_HOME_DIR);
        fclose(cmd_f); cmd_f = NULL;

        dup2(tossh[0], 0); close(tossh[0]); close(tossh[1]);
        dup2(fromssh[1], 1); close(fromssh[0]); close(fromssh[1]);

        char *args[] =
        {
            "ssh",
            "-aTx",
            acs->endpoint,
            cmd_s,
            NULL,
        };

        /*
        int fd = open("/dev/null", O_WRONLY);
        dup2(fd, 2); close(fd);
        */

        execvp("ssh", args);
        _exit(1);
    }

    close(tossh[0]); tossh[0] = -1;
    close(fromssh[1]); fromssh[1] = -1;
    acs->from_ssh = fromssh[0]; fromssh[0] = -1;
    acs->to_ssh = tossh[1]; tossh[1] = -1;
    fcntl(acs->from_ssh, F_SETFL, fcntl(acs->from_ssh, F_GETFL) | O_NONBLOCK);
    fcntl(acs->to_ssh, F_SETFL, fcntl(acs->to_ssh, F_GETFL) | O_NONBLOCK);

    if ((acs->vfd = eventfd(0, EFD_CLOEXEC)) < 0) {
        err("eventfd create failed: %s", os_ErrorMsg());
        goto fail;
    }

    if ((acs->tfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC)) < 0) {
        err("timerfd_create failed: %s", os_ErrorMsg());
        goto fail;
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
        if (timerfd_settime(acs->tfd, 0, &spec, NULL) < 0) {
            err("timerfd_settime failed: %s", os_ErrorMsg());
            return -1;
        }
    }

    if ((acs->efd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        err("epoll_create failed: %s", os_ErrorMsg());
        goto fail;
    }

    {
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = acs->vfd };
        epoll_ctl(acs->efd, EPOLL_CTL_ADD, acs->vfd, &ev);
    }
    {
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = acs->from_ssh };
        epoll_ctl(acs->efd, EPOLL_CTL_ADD, acs->from_ssh, &ev);
    }
    {
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = acs->tfd };
        epoll_ctl(acs->efd, EPOLL_CTL_ADD, acs->tfd, &ev);
    }

    pthread_attr_t pa;
    pthread_attr_init(&pa);
    pthread_attr_setstacksize(&pa, 1024 * 1024);
    pthread_attr_setdetachstate(&pa, PTHREAD_CREATE_DETACHED);
    int e = pthread_create(&acs->tid, &pa, thread_func, acs);
    if (e) {
        err("pthread_create failed: %s", strerror(e));
        goto fail;
    }
    pthread_attr_destroy(&pa);

    return 0;

fail:
    if (tossh[0] >= 0) close(tossh[0]);
    if (tossh[1] >= 0) close(tossh[1]);
    if (fromssh[0] >= 0) close(fromssh[0]);
    if (fromssh[1] >= 0) close(fromssh[1]);
    return -1;
}

static void
close_func(struct AgentClient *ac)
{
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    pthread_mutex_lock(&acs->stop_m);
    acs->stop_request = 1;
    uint64_t value = 1;
    write(acs->vfd, &value, sizeof(value));
    while (!acs->is_stopped) {
        pthread_cond_wait(&acs->stop_c, &acs->stop_m);
    }
    pthread_mutex_unlock(&acs->stop_m);
}

static int
is_closed_func(struct AgentClient *ac)
{
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    return acs->is_stopped;
}

static void
add_wchunk_json(
        struct AgentClientSsh *acs,
        cJSON *json)
{
    char *str = cJSON_PrintUnformatted(json);
    int len = strlen(str);
    if (acs->verbose_mode) {
        info("to agent: %s", str);
    }
    str = realloc(str, len + 2);
    str[len++] = '\n';
    str[len++] = '\n';
    str[len] = 0;
    add_wchunk_move(acs, str, len);
}

static cJSON *
create_request(
        struct AgentClientSsh *acs,
        struct Future *f,
        long long *p_time_ms,
        const unsigned char *query)
{
    cJSON *jq = cJSON_CreateObject();
    int serial = ++acs->serial;
    future_init(f, serial);
    add_future(acs, f);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    if (p_time_ms) *p_time_ms = current_time_ms;

    cJSON_AddNumberToObject(jq, "t", (double) current_time_ms);
    cJSON_AddNumberToObject(jq, "s", (double) serial);
    cJSON_AddStringToObject(jq, "q", query);

    return jq;
}

static int
poll_queue_func(
        struct AgentClient *ac,
        unsigned char *pkt_name,
        size_t pkt_len,
        int random_mode)
{
    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "poll");
    if (random_mode > 0) {
        cJSON_AddTrueToObject(jq, "random_mode");
    }
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;

    future_wait(&f);

    // { "q" : "poll-result", "pkt-name" : N }
    if (f.value) {
        cJSON *jj = cJSON_GetObjectItem(f.value, "q");
        if (jj && jj->type == cJSON_String
            && !strcmp("poll-result", jj->valuestring)) {
            cJSON *jn = cJSON_GetObjectItem(f.value, "pkt-name");
            if (jn && jn->type == cJSON_String) {
                snprintf(pkt_name, pkt_len, "%s", jn->valuestring);
                result = 1;
            }
        }
        cJSON *jt = cJSON_GetObjectItem(f.value, "t");
        if (jt && jt->type == cJSON_Number) {
            long long dur_ms = jt->valuedouble;
            dur_ms -= time_ms;
            (void) dur_ms;
            //fprintf(stderr, "poll: %lld ms\n", dur_ms);
        }
    }

    future_fini(&f);
    return result;
}

static int
process_file_result(
        struct AgentClientSsh *acs,
        cJSON *j,
        char **p_pkt_ptr,
        size_t *p_pkt_len)
{
    cJSON *jok = cJSON_GetObjectItem(j, "ok");
    if (!jok || jok->type != cJSON_True) {
        return -1;
    }
    cJSON *jq = cJSON_GetObjectItem(j, "q");
    if (!jq || jq->type != cJSON_String || strcmp("file-result", jq->valuestring) != 0) {
        err("invalid json");
        return -1;
    }
    cJSON *jf = cJSON_GetObjectItem(j, "found");
    if (!jf || jf->type != cJSON_True) {
        return 0;
    }
    cJSON *jz = cJSON_GetObjectItem(j, "size");
    if (!jz || jz->type != cJSON_Number) {
        err("invalid json: no size");
        return -1;
    }
    int size = (int) jz->valuedouble;
    if (size < 0 || size > 1000000000) {
        err("invalid json: invalid size");
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
        err("invalid json: no encoding");
        return -1;
    }
    cJSON *jd = cJSON_GetObjectItem(j, "data");
    if (!jd || jd->type != cJSON_String) {
        err("invalid json: no data");
        return -1;
    }
    int len = strlen(jd->valuestring);
    char *ptr = malloc(len + 1);
    int b64err = 0;
    int n = base64u_decode(jd->valuestring, len, ptr, &b64err);
    if (n != size) {
        err("invalid json: size mismatch");
        free(ptr);
        return -1;
    }
    ptr[size] = 0;
    *p_pkt_ptr = ptr;
    *p_pkt_len = size;
    return 1;
}

static int
get_packet_func(
        struct AgentClient *ac,
        const unsigned char *pkt_name,
        char **p_pkt_ptr,
        size_t *p_pkt_len)
{
    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "get-packet");
    cJSON_AddStringToObject(jq, "pkt_name", pkt_name);
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;

    future_wait(&f);

    result = process_file_result(acs, f.value, p_pkt_ptr, p_pkt_len);
    future_fini(&f);
    return result;
}

static int
get_data_func(
        struct AgentClient *ac,
        const unsigned char *pkt_name,
        const unsigned char *suffix,
        char **p_pkt_ptr,
        size_t *p_pkt_len)
{
    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "get-data");
    cJSON_AddStringToObject(jq, "pkt_name", pkt_name);
    if (suffix) {
        cJSON_AddStringToObject(jq, "suffix", suffix);
    }
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;

    future_wait(&f);

    result = process_file_result(acs, f.value, p_pkt_ptr, p_pkt_len);
    future_fini(&f);
    return result;
}

static void
add_file_to_object(cJSON *j, const char *data, size_t size)
{
    cJSON_AddNumberToObject(j, "size", (double) size);
    if (!size) {
        return;
    }
    cJSON_AddTrueToObject(j, "b64");
    char *ptr = malloc(size * 2 + 16);
    int n = base64u_encode(data, size, ptr);
    ptr[n] = 0;
    cJSON_AddStringToObject(j, "data", ptr);
    free(ptr);
}

static int
put_reply_func(
        struct AgentClient *ac,
        const unsigned char *contest_server_name,
        int contest_id,
        const unsigned char *run_name,
        const unsigned char *pkt_ptr,
        size_t pkt_len)
{
    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "put-reply");
    cJSON_AddStringToObject(jq, "server", contest_server_name);
    cJSON_AddNumberToObject(jq, "contest", contest_id);
    cJSON_AddStringToObject(jq, "run_name", run_name);
    add_file_to_object(jq, pkt_ptr, pkt_len);
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;

    future_wait(&f);

    cJSON *jok = cJSON_GetObjectItem(f.value, "ok");
    if (!jok || jok->type != cJSON_True) {
        result = -1;
    }

    future_fini(&f);
    return result;
}

static int
put_output_func(
        struct AgentClient *ac,
        const unsigned char *contest_server_name,
        int contest_id,
        const unsigned char *run_name,
        const unsigned char *suffix,
        const unsigned char *pkt_ptr,
        size_t pkt_len)
{
    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "put-output");
    cJSON_AddStringToObject(jq, "server", contest_server_name);
    cJSON_AddNumberToObject(jq, "contest", contest_id);
    cJSON_AddStringToObject(jq, "run_name", run_name);
    if (suffix) {
        cJSON_AddStringToObject(jq, "suffix", suffix);
    }
    add_file_to_object(jq, pkt_ptr, pkt_len);
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;

    future_wait(&f);

    cJSON *jok = cJSON_GetObjectItem(f.value, "ok");
    if (!jok || jok->type != cJSON_True) {
        result = -1;
    }

    future_fini(&f);
    return result;
}


static int
put_output_2_func(
        struct AgentClient *ac,
        const unsigned char *contest_server_name,
        int contest_id,
        const unsigned char *run_name,
        const unsigned char *suffix,
        const unsigned char *path)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_NOFOLLOW, 0);
    if (fd < 0) {
        err("put_output_2: cannot open '%s': %s", path, os_ErrorMsg());
        return -1;
    }
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        err("put_output_2: fstat failed '%s': %s", path, os_ErrorMsg());
        close(fd);
        return -1;
    }
    if (!S_ISREG(stb.st_mode)) {
        err("put_output_2: not a regular file '%s'", path);
        close(fd);
        return -1;
    }
    if (stb.st_size < 0 || stb.st_size > 2000000000) {
        err("put_output_2: file too big '%s': %lld", path, (long long) stb.st_mode);
        close(fd);
        return -1;
    }
    size_t pkt_len = stb.st_size;
    char *pkt_ptr = NULL;
    if (pkt_len > 0) {
        pkt_ptr = mmap(NULL, pkt_len, PROT_READ, MAP_PRIVATE, fd, 0);
        if (pkt_ptr == MAP_FAILED) {
            err("put_output_2: mmap failed '%s': %s", path, os_ErrorMsg());
            close(fd);
            return -1;
        }
    }
    close(fd); fd = -1;

    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "put-output");
    cJSON_AddStringToObject(jq, "server", contest_server_name);
    cJSON_AddNumberToObject(jq, "contest", contest_id);
    cJSON_AddStringToObject(jq, "run_name", run_name);
    if (suffix) {
        cJSON_AddStringToObject(jq, "suffix", suffix);
    }
    add_file_to_object(jq, pkt_ptr, pkt_len);
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;
    if (pkt_ptr) {
        munmap(pkt_ptr, pkt_len);
    }

    future_wait(&f);

    cJSON *jok = cJSON_GetObjectItem(f.value, "ok");
    if (!jok || jok->type != cJSON_True) {
        result = -1;
    }

    future_fini(&f);
    return result;
}

static int
async_wait_init_func(
        struct AgentClient *ac,
        int notify_signal,
        int random_mode,
        unsigned char *pkt_name,
        size_t pkt_len,
        struct Future **p_future)
{
    int result = 0;
    struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future f;
    long long time_ms;
    cJSON *jq = create_request(acs, &f, &time_ms, "wait");
    cJSON_AddNumberToObject(jq, "channel", (double) ++acs->serial);
    if (random_mode > 0) {
        cJSON_AddTrueToObject(jq, "random_mode");
    }
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;

    future_wait(&f);

    // { "q" : "poll-result", "pkt-name" : N }
    if (f.value) {
        cJSON *jj = cJSON_GetObjectItem(f.value, "q");
        if (jj && jj->type == cJSON_String
            && !strcmp("poll-result", jj->valuestring)) {
            cJSON *jn = cJSON_GetObjectItem(f.value, "pkt-name");
            if (jn && jn->type == cJSON_String) {
                snprintf(pkt_name, pkt_len, "%s", jn->valuestring);
                result = 1;
            }
        }
        if (jj && jj->type == cJSON_String && !strcmp("channel-result", jj->valuestring)) {
            cJSON *jc = cJSON_GetObjectItem(f.value, "channel");
            if (jc && jc->type == cJSON_Number) {
                int channel = jc->valuedouble;
                struct Future *future = malloc(sizeof(*future));
                *p_future = future;
                future_init(future, channel);
                future->notify_signal = notify_signal;
                add_future(acs, future);
                result = 0;
            }
        }
    }

    future_fini(&f);
    return result;
}

static int
async_wait_complete_func(
        struct AgentClient *ac,
        struct Future **p_future,
        unsigned char *pkt_name,
        size_t pkt_len)
{
    __attribute__((unused)) struct AgentClientSsh *acs = (struct AgentClientSsh *) ac;
    struct Future *future = *p_future;
    if (!future) return 0;
    pthread_mutex_lock(&future->m);
    int ready = future->ready;
    pthread_mutex_unlock(&future->m);
    if (!ready) return 0;

    int result = -1;
    cJSON *j = future->value;
    cJSON *jq = cJSON_GetObjectItem(j, "q");
    if (!jq || jq->type != cJSON_String || strcmp("poll-result", jq->valuestring) != 0) {
        goto done;
    }
    cJSON *jn = cJSON_GetObjectItem(j, "pkt-name");
    if (!jn || jq->type != cJSON_String) {
        goto done;
    }

    snprintf(pkt_name, pkt_len, "%s", jn->valuestring);
    result = 1;

done:
    future_fini(future);
    free(future);
    *p_future = NULL;
    return result;
}

static void
internal_ping_callback(
    struct Future *f,
    void *u)
{
    struct AgentClientSsh *acs = (struct AgentClientSsh *) u;
    if (acs->ping_future) {
        long long roundtrip_ms = acs->current_time_ms - acs->ping_time_ms;
        info("agent: ping roundtrip: %lld ms", roundtrip_ms);
        acs->ping_future = NULL;
        acs->ping_time_ms = 0;
        future_fini(f);
        free(f);
    }
}

static struct Future *
internal_ping(struct AgentClientSsh *acs)
{
    struct Future *f;
    XCALLOC(f, 1);
    cJSON *jq = create_request(acs, f, &acs->ping_time_ms, "ping");
    f->callback = internal_ping_callback;
    f->user = acs;
    add_wchunk_json(acs, jq);
    cJSON_Delete(jq); jq = NULL;
    return f;
}

static const struct AgentClientOps ops_ssh =
{
    destroy_func,
    init_func,
    connect_func,
    close_func,
    is_closed_func,
    poll_queue_func,
    get_packet_func,
    get_data_func,
    put_reply_func,
    put_output_func,
    put_output_2_func,
    async_wait_init_func,
    async_wait_complete_func,
};

struct AgentClient *
agent_client_ssh_create(void)
{
    struct AgentClientSsh *acs;

    XCALLOC(acs, 1);
    acs->b.ops = &ops_ssh;

    acs->efd = -1;
    acs->pid = -1;
    acs->from_ssh = -1;
    acs->to_ssh = -1;
    acs->vfd = -1;
    acs->tfd = -1;

    pthread_mutex_init(&acs->rchunkm, NULL);
    pthread_cond_init(&acs->rchunkc, NULL);
    pthread_mutex_init(&acs->wchunkm, NULL);
    pthread_mutex_init(&acs->stop_m, NULL);
    pthread_cond_init(&acs->stop_c, NULL);
    pthread_mutex_init(&acs->futurem, NULL);

    return &acs->b;
}
