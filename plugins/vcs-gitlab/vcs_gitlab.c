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
#include "ejudge/common_plugin.h"
#include "ejudge/vcs_plugin.h"
#include "ejudge/userprob_plugin.h"
#include "ejudge/random.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <curl/curl.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

struct vcs_gitlab_data
{
    struct vcs_plugin_data b;
    struct userprob_plugin_data *userprob_plugin;

    vcs_set_command_handler_t set_command_handler_func;
    void *set_command_handler_data;

    unsigned char *work_dir;
};

extern struct vcs_plugin_iface plugin_vcs_gitlab;

static struct common_plugin_data *
init_func(void)
{
    struct vcs_gitlab_data *state = NULL;
    XCALLOC(state, 1);
    state->b.vt = &plugin_vcs_gitlab;
    return &state->b.b;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct vcs_gitlab_data *vgd = (struct vcs_gitlab_data *) data;

    (void) vgd;
    return 0;
}

static void
gitlab_webhook_handler(
        int uid,
        int argc,
        char **argv,
        void *self);

static int
open_func(
        struct vcs_plugin_data *data,
        const struct ejudge_cfg *config)
{
    struct vcs_gitlab_data *vgd = (struct vcs_gitlab_data *) data;

    vgd->userprob_plugin = userprob_plugin_get(config, NULL, 0);
    if (!vgd->userprob_plugin) {
        return -1;
    }

    vgd->set_command_handler_func(vgd->set_command_handler_data,
                                  "gitlab_webhook",
                                  gitlab_webhook_handler,
                                  data);

    return 0;
}

static void
set_set_command_handler_func(
        struct vcs_plugin_data *data,
        vcs_set_command_handler_t setter,
        void *setter_self)
{
    struct vcs_gitlab_data *vgd = (struct vcs_gitlab_data *) data;

    vgd->set_command_handler_func = setter;
    vgd->set_command_handler_data = setter_self;
}

static void
set_work_dir_func(
        struct vcs_plugin_data *data,
        const unsigned char *work_dir)
{
    struct vcs_gitlab_data *vgd = (struct vcs_gitlab_data *) data;

    vgd->work_dir = xstrdup(work_dir);
}

struct vcs_plugin_iface plugin_vcs_gitlab =
{
    {
        {
            sizeof (struct vcs_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "vcs",
            "gitlab",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    VCS_PLUGIN_IFACE_VERSION,
    open_func,
    set_set_command_handler_func,
    set_work_dir_func,
};

/*
  jobs_args[0] = "gitlab_webhook";
  jobs_args[1] = gitlab_event;
  jobs_args[2] = gitlab_event_uuid;
  jobs_args[3] = serial_id_buf;
  jobs_args[4] = prob->problem_dir;
  jobs_args[5] = post_pull_cmd;
  jobs_args[6] = user_session;
  jobs_args[7] = self_url;
  jobs_args[8] = gitlab_json;
  jobs_args[9] = NULL;
 */

static void
gitlab_webhook_handler(
        int uid,
        int argc,
        char **argv,
        void *self)
{
    struct vcs_gitlab_data *vgd = (struct vcs_gitlab_data *) self;
    int64_t serial_id = 0;
    struct userprob_entry *ue = NULL;
    unsigned char randdir[64];
    unsigned char work_dir[PATH_MAX];
    unsigned char id_path[PATH_MAX];
    unsigned char repo_dir[PATH_MAX];
    unsigned char git_dir[PATH_MAX];
    unsigned char git_info_path[PATH_MAX];
    tpTask git_task = NULL;
    unsigned char source_path[PATH_MAX];
    unsigned char orig_path[PATH_MAX];
    unsigned char post_pull_path[PATH_MAX];
    unsigned char tbz_path[PATH_MAX];
    unsigned char b64_path[PATH_MAX];
    unsigned char res_path[PATH_MAX];
    FILE *dst_f = NULL;
    FILE *src_f = NULL;
    CURL *curl = NULL;
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    unsigned long long session_id, client_key;
    char *resp_s = NULL;
    size_t resp_z = 0;
    FILE *resp_f = NULL;
    unsigned char ejsid_buf[64];
    struct curl_slist *list = NULL;

    work_dir[0] = 0;

    const unsigned char *problem_dir = argv[4];
    const unsigned char *post_pull_cmd = argv[5];
    const unsigned char *self_url = argv[7];

    if (argc != 9) {
        err("gitlab_webhook_handler: wrong number of arguments");
        goto done;
    }

    /*
    fprintf(stderr, "in gitlab_webhook\n");
    for (int i = 0; i < argc; ++i) {
        fprintf(stderr, "[%d]: '%s'\n", i, argv[i]);
    }
    */

    if (sscanf(argv[6], "%llx-%llx", &session_id, &client_key) != 2) {
        err("gitlab_webhook_handler: failed to parse user session");
        goto done;
    }

    {
        char *eptr = NULL;
        errno = 0;
        serial_id = strtoll(argv[3], &eptr, 10);
        if (*eptr || errno || eptr == argv[3] || serial_id <= 0) {
            err("gitlab_webhook_handler: invalid serial_id");
            goto done;
        }
    }
    ue = vgd->userprob_plugin->vt->fetch_by_serial_id(vgd->userprob_plugin, serial_id);
    if (!ue) {
        err("gitlab_webhook_handler: invalid serial_id");
        goto done;
    }

    random_init();
    snprintf(randdir, sizeof(randdir), "gitlab_%llu", random_u64());
    snprintf(work_dir, sizeof(work_dir), "%s/%s", vgd->work_dir, randdir);
    if (make_dir(work_dir, 0700) < 0) {
        err("gitlab_webhook_handler: failed to create directory '%s'", work_dir);
        goto done;
    }

    if (!ue->ssh_private_key || !*ue->ssh_private_key) {
        err("gitlab_webhook_handler: ssh private key is not set");
        goto done;
    }
    if (generic_write_file(ue->ssh_private_key, strlen(ue->ssh_private_key), 0,
                           work_dir, "ssh_id", NULL) < 0) {
        err("gitlab_webhook_handler: failed to save ssh private key");
        goto done;
    }
    snprintf(id_path, sizeof(id_path), "%s/%s", work_dir, "ssh_id");
    if (chmod(id_path, 0600) < 0) {
        err("gitlab_webhook_handler: failed to chmod: %s", os_ErrorMsg());
        goto done;
    }

    git_task = task_New();
    task_AddArg(git_task, "/usr/bin/git");
    task_AddArg(git_task, "clone");
    task_AddArg(git_task, ue->vcs_url);
    task_SetPathAsArg0(git_task);
    task_SetEnv(git_task, "GIT_SSH_COMMAND", "ssh -i ssh_id -o IdentitiesOnly=yes -o StrictHostKeychecking=no");
    task_SetWorkingDir(git_task, work_dir);
    if (task_Start(git_task) < 0) {
        err("gitlab_webhook_handler: failed to start git");
        goto done;
    }
    task_NewWait(git_task);
    if (task_IsAbnormal(git_task)) {
        err("gitlab_webhook_handler: git clone failed");
        goto done;
    }
    task_Delete(git_task); git_task = NULL;

    {
        char *p = strrchr(ue->vcs_url, '/');
        if (!p) {
            err("gitlab_webhook_handler: cannot extract directory name from %s", ue->vcs_url);
            goto done;
        }
        snprintf(repo_dir, sizeof(repo_dir), "%s", p + 1);
        if ((p = strrchr(repo_dir, '.'))) {
            *p = 0;
        }
    }

    snprintf(git_dir, sizeof(git_dir), "%s/%s", work_dir, repo_dir);
    snprintf(git_info_path, sizeof(git_info_path), "%s/INFO", work_dir);

    git_task = task_New();
    task_AddArg(git_task, "/usr/bin/git");
    task_SetPathAsArg0(git_task);
    task_AddArg(git_task, "log");
    task_AddArg(git_task, "-1");
    task_AddArg(git_task, "--stat");
    task_SetRedir(git_task, 1, TSR_FILE, git_info_path, TSK_REWRITE, 0600);
    task_SetWorkingDir(git_task, git_dir);
    if (task_Start(git_task) < 0) {
        err("gitlab_webhook_handler: failed to start git");
        goto done;
    }
    task_NewWait(git_task);
    if (task_IsAbnormal(git_task)) {
        err("gitlab_webhook_handler: git log failed");
        goto done;
    }
    task_Delete(git_task); git_task = NULL;

    snprintf(source_path, sizeof(source_path), "%s/%s", work_dir, "source");

    if (ue->vcs_subdir && *ue->vcs_subdir) {
        snprintf(orig_path, sizeof(orig_path), "%s/%s", git_dir, ue->vcs_subdir);
    } else {
        snprintf(orig_path, sizeof(orig_path), "%s/.git", git_dir);
        remove_directory_recursively(orig_path, 0);
        snprintf(orig_path, sizeof(orig_path), "%s", git_dir);
    }
    if (rename(orig_path, source_path) < 0) {
        err("gitlab_webhook_handler: rename failed: %s -> %s", orig_path, source_path);
        goto done;
    }

    if (post_pull_cmd && *post_pull_cmd) {
        if (os_IsAbsolutePath(post_pull_cmd)) {
            snprintf(post_pull_path, sizeof(post_pull_path), "%s", post_pull_cmd);
        } else {
            snprintf(post_pull_path, sizeof(post_pull_path), "%s/%s", problem_dir, post_pull_cmd);
        }
        fprintf(stderr, "starting post-pull %s\n", post_pull_path);
        git_task = task_New();
        task_AddArg(git_task, post_pull_path);
        task_SetPathAsArg0(git_task);
        task_AddArg(git_task, problem_dir);
        task_AddArg(git_task, ue->lang_name);
        task_SetWorkingDir(git_task, source_path);
        if (task_Start(git_task) < 0) {
            err("gitlab_webhook_handler: post_pull_cmd failed to start: %s", post_pull_path);
            goto done;
        }
        task_NewWait(git_task);
        if (task_IsAbnormal(git_task)) {
            err("gitlab_webhook_handler: post_pull_cmd failed");
            goto done;
        }
        task_Delete(git_task); git_task = NULL;
    }

    git_task = task_New();
    task_AddArg(git_task, "/usr/bin/tar");
    task_SetPathAsArg0(git_task);
    task_AddArg(git_task, "cfj");
    task_AddArg(git_task, "source.tbz");
    task_AddArg(git_task, "source");
    task_SetWorkingDir(git_task, work_dir);
    if (task_Start(git_task) < 0) {
        err("gitlab_webhook_handler: failed to start tar");
        goto done;
    }
    task_NewWait(git_task);
    if (task_IsAbnormal(git_task)) {
        err("gitlab_webhook_handler: tar failed");
        goto done;
    }
    task_Delete(git_task); git_task = NULL;

    snprintf(tbz_path, sizeof(tbz_path), "%s/%s", work_dir, "source.tbz");
    snprintf(b64_path, sizeof(b64_path), "%s/%s", work_dir, "source.b64");

    git_task = task_New();
    task_AddArg(git_task, "/usr/bin/base64");
    task_SetPathAsArg0(git_task);
    task_SetWorkingDir(git_task, work_dir);
    task_SetRedir(git_task, 0, TSR_FILE, tbz_path, TSK_READ, 0);
    task_SetRedir(git_task, 1, TSR_FILE, b64_path, TSK_REWRITE, 0600);
    if (task_Start(git_task) < 0) {
        err("gitlab_webhook_handler: failed to start base64");
        goto done;
    }
    task_NewWait(git_task);
    if (task_IsAbnormal(git_task)) {
        err("gitlab_webhook_handler: base64 failed");
        goto done;
    }
    task_Delete(git_task); git_task = NULL;

    snprintf(res_path, sizeof(res_path), "%s/%s", work_dir, "source.res");
    dst_f = fopen(res_path, "w");
    if (!dst_f) {
        err("gitlab_webhook_handler: cannot open '%s' for write", res_path);
        goto done;
    }
    src_f = fopen(git_info_path, "r");
    if (src_f) {
        int c;
        while ((c = getc_unlocked(src_f)) != EOF) {
            putc_unlocked(c, dst_f);
        }
        fclose(src_f); src_f = NULL;
    }
    fprintf(dst_f, "\n-----BEGIN CONTENT-----\n");
    src_f = fopen(b64_path, "r");
    if (src_f) {
        int c;
        while ((c = getc_unlocked(src_f)) != EOF) {
            putc_unlocked(c, dst_f);
        }
        fclose(src_f); src_f = NULL;
    }
    putc_unlocked('\n', dst_f);
    fclose(dst_f); dst_f = NULL;

    curl = curl_easy_init();
    if (!curl) {
        err("gitlab_webhook_handler: cannot initialize curl");
        goto done;
    }
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    mime = curl_mime_init(curl);

    part = curl_mime_addpart(mime);
    curl_mime_data(part, "1", CURL_ZERO_TERMINATED);
    curl_mime_name(part, "json");
    part = curl_mime_addpart(mime);
    curl_mime_data(part, "submit-run", CURL_ZERO_TERMINATED);
    curl_mime_name(part, "action");
    part = curl_mime_addpart(mime);
    char prob_id_buf[64];
    snprintf(prob_id_buf, sizeof(prob_id_buf), "%d", ue->prob_id);
    curl_mime_data(part, prob_id_buf, CURL_ZERO_TERMINATED);
    curl_mime_name(part, "prob_id");
    if (ue->lang_name && *ue->lang_name) {
        part = curl_mime_addpart(mime);
        curl_mime_data(part, ue->lang_name, CURL_ZERO_TERMINATED);
        curl_mime_name(part, "lang_id");
    }
    char sid_buf[64];
    snprintf(sid_buf, sizeof(sid_buf), "%016llx", session_id);
    part = curl_mime_addpart(mime);
    curl_mime_data(part, sid_buf, CURL_ZERO_TERMINATED);
    curl_mime_name(part, "SID");

    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, res_path);
    curl_mime_type(part, "text/plain");
    curl_mime_name(part, "file");

    snprintf(ejsid_buf, sizeof(ejsid_buf), "EJSID=%016llx", client_key);

    resp_f = open_memstream(&resp_s, &resp_z);
    curl_easy_setopt(curl, CURLOPT_COOKIE, ejsid_buf);
    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_URL, self_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    CURLcode res = curl_easy_perform(curl);
    fclose(resp_f);
    if (res != CURLE_OK) {
        err("curl request failed");
    }

    fprintf(stderr, "response: <%s>\n", resp_s);

    info("pull complete");

done:;
    task_Delete(git_task);
    if (work_dir[0]) {
        remove_directory_recursively(work_dir, 0);
    }
    userprob_entry_free(ue);
    if (mime) {
        curl_mime_free(mime);
    }
    if (curl) {
        curl_easy_cleanup(curl);
    }
    if (list) {
        curl_slist_free_all(list);
    }
}
