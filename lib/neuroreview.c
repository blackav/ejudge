/* -*- mode: c -*- */

/* Copyright (C) 2007-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/neuroreview.h"
#include "ejudge/new-server.h"
#include "ejudge/errlog.h"
#include "ejudge/cJSON.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/clarlog.h"
#include "ejudge/serve_state.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>
#include <pthread.h>


#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)


struct neuroreview_reviews_list {
    struct neuroreview_review_state state;
    struct neuroreview_reviews_list *next, *prev;
};

struct neuroreview_reviews_list *neuroreview_reviews = NULL;

static atomic_bool neuroreview_exit = false;
static pthread_t neuroreview_pull_pthread;
pthread_mutex_t neuroreview_pull_pthread_mutex = PTHREAD_MUTEX_INITIALIZER;


struct _curl_memory {
    char *response;
    size_t size;
};

static size_t _curl_cb(char *data, size_t size, size_t nmemb, void *clientp)
{
    size_t realsize = nmemb;
    struct _curl_memory *mem = (struct _curl_memory *)clientp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr) {
        err("Neuroreview: Cannot reallocate curl buffer");
        return 0;  /* out of memory */
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

void neuroreview_pull() {
    const unsigned char *text = NULL;
    size_t text_len, subj_len, text3_len;
    unsigned char *text2 = 0, *text3 = 0;
    unsigned char subj2[1024];
    struct timeval precise_time;
    int clar_id = 0;
    struct _curl_memory chunk = { 0 };
    CURL *curl = NULL;
    ej_uuid_t uuid = {};
    cJSON *result_json = NULL;
    CURLcode result;
    cJSON *result_array_item = NULL;

    if (!neuroreview_reviews) {
        return;
    }

    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080/get_reviews");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        result = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (result != CURLE_OK) {
            err("Neuroreview: Curl error: %s", curl_easy_strerror(result));
            goto cleanup;
        }
    } else {
        err("Neuroreview: can not init curl");
        goto cleanup;
    }

    result_json = cJSON_Parse(chunk.response);
    if (!result_json) {
        err("Neuroreview: can not parse /get_reviews response json");
        goto cleanup;
    }

    if ((result_json->type & 0xFF) != cJSON_Array) {
        err("Neuroreview: /get_reviews response is not an array");
        goto cleanup;
    }

    cJSON_ArrayForEach(result_array_item, result_json) {
        if ((result_array_item->type & 0xFF) != cJSON_Object) {
            err("Neuroreview: /get_reviews response is not an array of objects");
            goto cleanup;
        }

        cJSON *uuid_json = cJSON_GetObjectItem(result_array_item, "uuid");
        if (!uuid_json || ((uuid_json->type & 0xFF) != cJSON_String) || !uuid_json->valuestring) {
            err("Neuroreview: /get_reviews response does not containt 'uuid' field or it is not string");
            goto cleanup;
        }

        cJSON *msg_id_json = cJSON_GetObjectItem(result_array_item, "msg_id");
        if (!msg_id_json || ((msg_id_json->type & 0xFF) != cJSON_String) || !msg_id_json->valuestring) {
            err("Neuroreview: /get_reviews response does not containt 'msg_id' field or it is not string");
            goto cleanup;
        }

        cJSON *text_json = cJSON_GetObjectItem(result_array_item, "response");
        if (!text_json || ((text_json->type & 0xFF) != cJSON_String) || !text_json->valuestring) {
            err("Neuroreview: /get_reviews response does not containt 'response' field or it is not string");
            goto cleanup;
        }

        if (ej_uuid_parse(uuid_json->valuestring, &uuid) < 0) {
            err("Neuroreview: cannot parse uuid '%s'", uuid_json->valuestring);
            goto cleanup;
        }

        pthread_mutex_lock(&neuroreview_pull_pthread_mutex);

        struct neuroreview_reviews_list *node = neuroreview_reviews;
        while (node && memcmp(&(node->state.uuid), &uuid, sizeof(uuid))) {
            node = node->next;
        }

        pthread_mutex_unlock(&neuroreview_pull_pthread_mutex);

        if (!node) {
            err("Neuroreview: can not find review with such uuid '%s'", uuid_json->valuestring);
            continue;
        }

        text = text_json->valuestring;
        if (!text) text = "";
        text_len = strlen(text);
        if (text_len > 56 * 1024) {
            err("Neuroreview: clar text is too long");
            goto cleanup;
        }
        text2 = alloca(text_len + 1);
        memcpy(text2, text, text_len + 1);
        while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
        if (!text_len) {
            err("Neuroreview: clar text is empty");
            goto cleanup;
        }
    
        snprintf(subj2, sizeof(subj2), "%d %s", node->state.run_id, _("is commented"));
        subj_len = strlen(subj2);
    
        text3 = alloca(subj_len + text_len + 32);
        text3_len = sprintf(text3, "Subject: %s\n\n%s\n", subj2, text2);
    
        ej_uuid_t clar_uuid = {};
        gettimeofday(&precise_time, 0);
        if ((clar_id = clar_add_record(node->state.cs->clarlog_state,
            precise_time.tv_sec,
            precise_time.tv_usec * 1000,
            text3_len,
            &node->state.ip,
            node->state.ssl_flag,
            0, node->state.run_user_id, 0, node->state.request_user_id,
            0, node->state.locale_id,
            0 /* in_reply_to */,
            NULL /* in_reply_uuid */,
            node->state.run_id + 1,
            &node->state.run_uuid,
            0 /* appeal_flag */,
            0, /* old_status */
            0, /* new_status */
            utf8_mode, NULL, subj2, &clar_uuid)) < 0) {
            err("Neuroreview: failed to create clar");
            goto cleanup;
            }
    
        if (clar_add_text(node->state.cs->clarlog_state, clar_id, &clar_uuid, text3, text3_len) < 0) {
            err("Neuroreview: failed to add text to clar");
            goto cleanup;
        }

        char curl_buffer[100];
        sprintf(curl_buffer, "{\"msg_id\":\"%s\"}", msg_id_json->valuestring);

        curl = curl_easy_init();

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080/ack_reviews");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, curl_buffer);
            result = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            if (result != CURLE_OK) {
                err("Neuroreview: Curl error: %s", curl_easy_strerror(result));
                goto cleanup;
            }
        } else {
            err("Neuroreview: can not init curl");
            goto cleanup;
        }

        pthread_mutex_lock(&neuroreview_pull_pthread_mutex);

        if (node->prev) {
            node->prev->next = node->next;
        } else {
            neuroreview_reviews = node->next;
        }
        if (node->next) {
            node->next->prev = node->prev;
        }

        pthread_mutex_unlock(&neuroreview_pull_pthread_mutex);

        free(node);
    }

cleanup:
    free(chunk.response);
    cJSON_Delete(result_json);
}

void* neuroreview_pull_thread() {
    while (!neuroreview_exit) {
        sleep(5);
        neuroreview_pull();
    }
    return NULL;
}

void neuroreview_init_manager() {
    info("Neuroreview: init manager");

    if (pthread_create(&neuroreview_pull_pthread, NULL, neuroreview_pull_thread, NULL) != 0) {
        err("Neuroreview: failed to create pthread");
        exit(1);
    }
}

void neuroreview_stop_manager() {
    neuroreview_exit = true;
    pthread_join(neuroreview_pull_pthread, NULL);
    pthread_mutex_destroy(&neuroreview_pull_pthread_mutex);
}

int neuroreview_send_review(struct neuroreview_review_state state, const char *prob_statement, const char *run_text) {
    int retval = 0;
    struct neuroreview_reviews_list *node = NULL;
    char uuid_buf[40];
    cJSON *request = NULL;
    char *request_string = NULL;

    ej_uuid_generate(&state.uuid);
    ej_uuid_unparse_r(uuid_buf, sizeof(uuid_buf), &state.uuid, NULL);

    request = cJSON_CreateObject();
    if (!request)
        FAIL(1);
    cJSON *request_contest_id = cJSON_CreateNumber(state.cs->contest_id);
    if (!request_contest_id)
        FAIL(1);
    cJSON *request_uuid = cJSON_CreateString(uuid_buf);
    if (!request_uuid)
        FAIL(1);
    cJSON *request_problem_statement = cJSON_CreateString(prob_statement);
    if (!request_problem_statement)
        FAIL(1);
    cJSON *request_run_text = cJSON_CreateString(run_text);
    if (!request_run_text)
        FAIL(1);
    
    cJSON_AddItemToObject(request, "contest_id", request_contest_id);
    cJSON_AddItemToObject(request, "uuid", request_uuid);
    cJSON_AddItemToObject(request, "problem_statement", request_problem_statement);
    cJSON_AddItemToObject(request, "run_text", request_run_text);


    request_string = cJSON_Print(request);
    if (!request_string)
        FAIL(1);

    CURLcode result;
    CURL *curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080/send_review");

        struct curl_slist *http_headers = NULL;
        http_headers = curl_slist_append(http_headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_string);
        result = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (result != CURLE_OK) {
            FAIL(1);
        }
    }

    node = malloc(sizeof(struct neuroreview_reviews_list));
    if (!node) {
        FAIL(1);
    }
    memcpy(&node->state, &state, sizeof(struct neuroreview_review_state));

    pthread_mutex_lock(&neuroreview_pull_pthread_mutex);

    node->next = neuroreview_reviews;
    node->prev = NULL;
    if (neuroreview_reviews) {
        neuroreview_reviews->prev = node;
    }
    neuroreview_reviews = node;

    pthread_mutex_unlock(&neuroreview_pull_pthread_mutex);

cleanup:
    free(request_string);
    cJSON_Delete(request);

    return retval;
}
