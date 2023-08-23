/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/polygon_packet.h"
#include "ejudge/expat_iface.h"
#include "ejudge/xml_utils.h"
#include "ejudge/problem_config.h"
#include "ejudge/list_ops.h"
#include "ejudge/misctext.h"
#include "ejudge/html_parse.h"
#include "ejudge/sha512utils.h"
#include "ejudge/cJSON.h"
#include "ejudge/fileutl.h"

#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <printf.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <grp.h>
#include <fcntl.h>

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#endif

#if defined CONF_HAS_LIBZIP
#include <zip.h>
#endif

#define DEFAULT_POLYGON_URL "https://polygon.codeforces.com"
#define DEFAULT_ARCH        "$linux"
#define DEFAULT_SLEEP_INTERVAL 10
#define DEFAULT_PROBLEM_XML_NAME "problem.xml"
#define DEFAULT_TESTSET     "tests"
#define DEFAULT_RETRY_COUNT 10

enum UpdateState
{
    STATE_NOT_STARTED,
    STATE_NOT_FOUND,
    STATE_ALREADY_EXISTS,
    STATE_FAILED,
    STATE_INFO_LOADED,
    STATE_RUNNING,
    STATE_DOWNLOADED,
    STATE_UPDATED,
    STATE_ACTUAL,
    STATE_UNCOMMITTED,
    STATE_TIMEOUT,
    STATE_NOT_AVAILABLE,
    STATE_PERMISSION_DENIED,

    STATE_LAST,
};

struct ProblemInfo
{
    int key_id;
    unsigned char *key_name;
    int ejudge_id;
    unsigned char *ejudge_short_name;
    int state;
    int problem_id;
    unsigned char *problem_name;
    unsigned char *author;
    int latest_rev;
    int package_rev;
    time_t mtime;
    int has_start;
    int continue_id;
    int discard_id;
    unsigned char *edit_session;

    // extracted from problem.xml
    int time_limit_ms;
    int test_count;
    ssize_t memory_limit;
    unsigned char *long_name_ru;
    unsigned char *long_name_en;
    unsigned char *input_file;
    unsigned char *output_file;
    unsigned char *input_path_pattern;
    unsigned char *answer_path_pattern;
    unsigned char *test_pat;
    unsigned char *corr_pat;
    unsigned char *standard_checker;
    unsigned char *checker_env;
    unsigned char *check_cmd;
    unsigned char *test_checker_cmd;
    unsigned char *solution_cmd;
    unsigned char *interactor_cmd;
    unsigned char *html_statement_path;
};

struct RevisionInfo
{
    int package_id;
    int revision;
    time_t creation_time;
    unsigned char *state;
    unsigned char *comment;
    unsigned char *standard_url;
    unsigned char *windows_url;
    unsigned char *linux_url;
};

struct PolygonState
{
    unsigned char *ccid; // may be NULL for older versions of Polygon
    unsigned char *ccid_amp; // "&ccid=CCID" or ""
    unsigned char *ccid_q;   // "?ccid=CCID" or "?"

    // problem table column indices
    int id_column_num;
    int name_column_num;
    int owner_column_num;
    int rev_column_num;
    int modif_column_num;
    int edit_column_num;
};

struct ProblemSet
{
    int count;
    struct ProblemInfo *infos;
};

enum
{
    TG__BARRIER = 1,
    TG__DEFAULT,

    TG_LAST_TAG,
};

enum
{
    AT__BARRIER = 1,
    AT__DEFAULT,

    AT_LAST_TAG,
};

static char const * const elem_map[] =
{
    0,
    0,
    "_default",

    0
};

static char const * const attr_map[] =
{
    0,
    0,
    "_default",

    0
};

static struct xml_parse_spec generic_xml_parse_spec =
{
    .elem_map = elem_map,
    .attr_map = attr_map,
    .elem_sizes = NULL,
    .attr_sizes = NULL,
    .default_elem = TG__DEFAULT,
    .default_attr = AT__DEFAULT,
    .elem_alloc = NULL,
    .attr_alloc = NULL,
    .elem_free = NULL,
    .attr_free = NULL,
    .verbatim_flags = NULL,
};

static const unsigned char *progname;

static void
fatal(const char *format, ...)
    __attribute__((format(printf, 1, 2), noreturn));
static void
fatal(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s\n", progname, buf);
    exit(2);
}

static int sigint_caught;
static void sigint_handler(int signo)
{
    sigint_caught = 1;
}

static void
report_version(void)
{
    printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    exit(0);
}

struct RandomSource;
struct RandomSourceOperations
{
    void (*destroy)(struct RandomSource *);
    void (*b32_bytes)(struct RandomSource *, unsigned char *buf, size_t count);
};

struct RandomSource
{
    const struct RandomSourceOperations *ops;
};

struct RandomSourceURandom
{
    struct RandomSource b;
    int fd;
};

static void
random_source_urandom_destroy(struct RandomSource *b)
{
    struct RandomSourceURandom *rand = (struct RandomSourceURandom *) b;
    if (rand->fd >= 0) close(rand->fd);
    memset(rand, 0, sizeof(*rand));
    rand->fd = -1;
    xfree(rand);
}

static void
random_source_urandom_b32_bytes(struct RandomSource *b, unsigned char *buf, size_t count)
{
    struct RandomSourceURandom *rand = (struct RandomSourceURandom *) b;
    unsigned value = 0;
    int available = 0;

    for (; count > 0; --count) {
        if (available < 5) {
            if (read(rand->fd, &value, sizeof(value)) != sizeof(value)) {
                fatal("read error from /dev/urandom: %s", strerror(errno));
            }
            available = 32;
        }
        unsigned t = value & 0x1f;
        value >>= 5;
        available -= 5;
        if (t <= 9) {
            *buf++ = '0' + t;
        } else {
            *buf++ = 'a' - 10 + t;
        }
    }
    *buf = 0;
}

struct RandomSource *
random_source_urandom(void)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        fatal("cannot open /dev/urandom: %s", strerror(errno));
    }

    struct RandomSourceURandom *rand;
    XCALLOC(rand, 1);
    rand->fd = fd;

    static const struct RandomSourceOperations ops =
    {
        random_source_urandom_destroy,
        random_source_urandom_b32_bytes,
    };
    rand->b.ops = &ops;

    return &rand->b;
}


struct DownloadData;
struct DownloadInterface
{
    struct DownloadData *(*create)(FILE *log_f, const struct DownloadInterface *iface, struct polygon_packet *);
    struct DownloadData *(*cleanup)(struct DownloadData *data);
    unsigned char *(*get_page_text)(struct DownloadData *data);
    ssize_t (*get_page_size)(struct DownloadData *data);
    int (*login_page)(struct DownloadData *data);
    int (*login_action)(struct DownloadData *data, struct PolygonState *ps);
    int (*problems_page)(struct DownloadData *data, struct PolygonState *ps, int page);
    int (*problem_info_page)(struct DownloadData *data, struct PolygonState *ps, struct ProblemInfo *info);
    int (*package_page)(struct DownloadData *data, struct PolygonState *ps, const unsigned char *edit_session);
    int (*create_full_package)(struct DownloadData *data, struct PolygonState *ps, const unsigned char *edit_session);
    int (*download_zip)(struct DownloadData *data, struct PolygonState *ps, const unsigned char *zip_url, const unsigned char *edit_session);
    int (*contests_page)(struct DownloadData *data, struct PolygonState *ps);
    int (*contest_page)(struct DownloadData *data, struct PolygonState *ps, int contest_id);
    int (*problems_multi_page)(FILE *log_f, struct DownloadData *data, struct PolygonState *ps);
    int (*contest_api)(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        const unsigned char *contest_id);
    int (*problems_api)(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret);
    int (*problem_info_api)(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        int problem_id);
    int (*problem_packages_api)(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        int problem_id);
    int (*problem_package_api)(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        int problem_id,
        int package_id,
        const unsigned char *type);
};

static int
ends_with(const unsigned char *str, const unsigned char *suffix);

#if CONF_HAS_LIBCURL - 0 == 1
struct DownloadData
{
    size_t size;
    FILE *log_f;
    const struct DownloadInterface *iface;
    struct polygon_packet *pkt;
    CURL *curl;

    char *page_text;
    size_t page_size;
    char *effective_url;
    char *clean_url;
};

static struct DownloadData *
curl_iface_create_func(FILE *log_f, const struct DownloadInterface *iface, struct polygon_packet *pkt)
{
    struct DownloadData *data = NULL;
    XCALLOC(data, 1);
    data->size = sizeof(*data);
    data->log_f = log_f;
    data->iface = iface;
    data->pkt = pkt;
    if (!(data->curl = curl_easy_init())) {
        fprintf(log_f, "curl_easy_init() failed\n");
        xfree(data);
        return NULL;
    }

    return data;
}
static struct DownloadData *
curl_iface_cleanup_func(struct DownloadData *data)
{
    if (data) {
        if (data->curl) {
            curl_easy_cleanup(data->curl);
        }
        xfree(data->page_text);
        xfree(data);
    }
    return NULL;
}

static unsigned char *
curl_iface_get_page_text(struct DownloadData *data)
{
    return data->page_text;
}

static ssize_t
curl_iface_get_page_size(struct DownloadData *data)
{
    return data->page_size;
}

static CURLcode
curl_iface_get_func(struct DownloadData *data, const unsigned char *url)
{
    FILE *file = NULL;
    CURLcode res = 0;

    xfree(data->page_text); data->page_text = NULL; data->page_size = 0;

    fprintf(data->log_f, "GET: %s\n", url);

    //curl_easy_setopt(data->curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate, br");
    //curl_easy_setopt(data->curl, CURLOPT_AUTOREFERER, 1);
    curl_easy_setopt(data->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(data->curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(data->curl, CURLOPT_USERAGENT, data->pkt->user_agent);
    curl_easy_setopt(data->curl, CURLOPT_URL, url);
    file = open_memstream(&data->page_text, &data->page_size);
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, file);
    res = curl_easy_perform(data->curl);
    fclose(file); file = NULL;
    if (res != CURLE_OK) {
        fprintf(data->log_f, "Request failed: %s\n", curl_easy_strerror(res));
        return res;
    }
    curl_easy_getinfo(data->curl, CURLINFO_EFFECTIVE_URL, &data->effective_url);
    xfree(data->clean_url); data->clean_url = NULL;
    if (data->effective_url) {
        data->clean_url = xstrdup(data->effective_url);
        char *p = strchr(data->clean_url, '?');
        if (p) *p = 0;
    }
    if (data->effective_url && strcmp(url, data->effective_url)) {
        fprintf(data->log_f, "Redirect: %s\n", data->effective_url);
    }

    return res;
}

static int
curl_iface_login_page_func(struct DownloadData *data)
{
    unsigned char url_buf[1024];

    snprintf(url_buf, sizeof(url_buf), "%s/login", data->pkt->polygon_url);
    return curl_iface_get_func(data, url_buf);
}

static int
curl_iface_login_action_func(struct DownloadData *data, struct PolygonState *ps)
{
    unsigned char url_buf[1024];
    unsigned char param_buf[1024];
    FILE *file = NULL;
    int retval = 0;
    CURLcode res = 0;
    char *login_esc = NULL;
    char *password_esc = NULL;
    char *effective_url = NULL;

    xfree(data->page_text); data->page_text = NULL; data->page_size = 0;

    snprintf(url_buf, sizeof(url_buf), "%s/login", data->pkt->polygon_url);
    fprintf(data->log_f, "POST: %s\n", url_buf);

    if (!data->pkt->login || !data->pkt->login[0]) {
        fprintf(data->log_f, "'login' is empty\n");
        retval = 1;
        goto cleanup;
    }
    login_esc = curl_easy_escape(data->curl, data->pkt->login, 0);
    if (!data->pkt->password || !data->pkt->password[0]) {
        fprintf(data->log_f, "'password' is empty\n");
        retval = 1;
        goto cleanup;
    }
    password_esc = curl_easy_escape(data->curl, data->pkt->password, 0);
    snprintf(param_buf, sizeof(param_buf), "submitted=true&login=%s&password=%s&submit=Login&fp=%s", login_esc, password_esc, ps->ccid_amp);

    //curl_easy_setopt(data->curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate, br");
    //curl_easy_setopt(data->curl, CURLOPT_AUTOREFERER, 1);
    curl_easy_setopt(data->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(data->curl, CURLOPT_USERAGENT, data->pkt->user_agent);
    curl_easy_setopt(data->curl, CURLOPT_URL, url_buf);
    file = open_memstream(&data->page_text, &data->page_size);
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(data->curl, CURLOPT_POSTFIELDS, (char*) param_buf);
    curl_easy_setopt(data->curl, CURLOPT_POST, 1);
    res = curl_easy_perform(data->curl);
    fclose(file); file = NULL;
    curl_easy_getinfo(data->curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    curl_easy_setopt(data->curl, CURLOPT_POST, 0);
    if (res != CURLE_OK) {
        fprintf(data->log_f, "polygon login action failed: %s\n", curl_easy_strerror(res));
        retval = 1;
        goto cleanup;
    }
    xfree(data->clean_url); data->clean_url = NULL;
    if (effective_url) {
        data->clean_url = xstrdup(effective_url);
        char *p = strchr(data->clean_url, '?');
        if (p) *p = 0;
    }
    if (!data->clean_url || (!ends_with(data->clean_url, "/problems") && !strstr(data->clean_url, "/problems/"))) {
        fprintf(data->log_f, "polygon login action failed: invalid login or password?\n");
        retval = 1;
        goto cleanup;
    }

    fprintf(data->log_f, "Redirect: %s\n", effective_url);

cleanup:
    xfree(login_esc);
    xfree(password_esc);
    if (file) fclose(file);
    return retval;
}

static int
curl_iface_problems_page_func(struct DownloadData *data, struct PolygonState *ps, int page)
{
    unsigned char url_buf[1024];
    unsigned char page_buf[64];

    page_buf[0] = 0;
    if (page > 0) {
        snprintf(page_buf, sizeof(page_buf), "&page=%d", page);
    }
    snprintf(url_buf, sizeof(url_buf), "%s/problems%s%s", data->pkt->polygon_url, ps->ccid_q, page_buf);
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    if (!data->clean_url || !ends_with(data->clean_url, "/problems")) {
        fprintf(data->log_f, "failed to retrieve problems page: redirected to %s\n", data->effective_url);
        return 1;
    }

    return 0;
}

static int
count_problem_pages(const unsigned char *text)
{
    const unsigned char *cur;
    int pos = 0;
    struct HtmlElement *elem = NULL;
    struct HtmlElement *elem2 = NULL;
    struct HtmlAttribute *attr;
    int max_page_num = -1;

    while ((cur = strstr(text + pos, "<div "))) {
        pos = (int)(cur - text);
        elem = html_element_parse_start(text, pos, &pos);
        if (elem && (attr = html_element_find_attribute(elem, "class")) && attr->value && !strcasecmp(attr->value, "pagination")) {
            if (!(cur = strstr(text + pos, "</div>"))) goto fail;
            int endpos = (int)(cur - text);

            while ((cur = strstr(text + pos, "<a "))) {
                pos = (int)(cur - text);
                if (pos > endpos) break;

                elem2 = html_element_parse_start(text, pos, &pos);
                if (elem2 && (attr = html_element_find_attribute(elem2, "href")) && attr->value) {
                    const unsigned char *p = strstr(attr->value, "?page=");
                    if (p) {
                        int n, x;
                        if (sscanf(p + 6, "%d%n", &x, &n) == 1 && (p[n + 6] == '&' || p[n + 6] == 0)) {
                            if (x >= 1 && x < 100000 && x > max_page_num) {
                                max_page_num = x;
                            }
                        }
                    }
                }
                elem2 = html_element_free(elem2);
            }

            pos = endpos;
        }
        elem = html_element_free(elem);
    }
    return max_page_num;

fail:
    elem = html_element_free(elem);
    elem2 = html_element_free(elem2);
    return 0;
}

static int
curl_iface_problems_multi_page_func(FILE *log_f, struct DownloadData *data, struct PolygonState *ps)
{
    int retval = 0;
    unsigned char *merged_pages = NULL;

    if ((retval = curl_iface_problems_page_func(data, ps, 0))) {
        goto done;
    }

    int page_count = count_problem_pages(data->iface->get_page_text(data));
    if (page_count <= 1) return 0;

    fprintf(log_f, "Problems listing has %d pages\n", page_count);

    // just concatenate pages
    merged_pages = data->page_text; data->page_text = NULL;
    for (int page = 2; page <= page_count; ++page) {
        if ((retval = curl_iface_problems_page_func(data, ps, page))) {
            goto done;
        }
        merged_pages = xstrmerge1(merged_pages, data->page_text);
    }

    xfree(data->page_text);
    data->page_text = merged_pages;
    merged_pages = NULL;

done:
    xfree(merged_pages);
    return retval;
}

static int
curl_iface_problem_info_page_func(struct DownloadData *data, struct PolygonState *ps, struct ProblemInfo *info)
{
    unsigned char url_buf[1024];

    if (info->has_start) {
        snprintf(url_buf, sizeof(url_buf), "%s/edit-start?problemId=%d%s",
                 data->pkt->polygon_url, info->problem_id, ps->ccid_amp);
    } else if (info->continue_id) {
        snprintf(url_buf, sizeof(url_buf), "%s/edit-continue?workingCopyId=%d%s",
                 data->pkt->polygon_url, info->continue_id, ps->ccid_amp);
    } else {
        abort();
    }
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    if (!data->clean_url || !strstr(data->clean_url, "/generalInfo")) {
        fprintf(data->log_f, "failed to retrieve problems page: redirected to %s\n", data->effective_url);
        return 1;
    }

    xfree(info->edit_session); info->edit_session = NULL;
    unsigned char *p = strstr(data->effective_url, "session=");
    if (p) {
        p += 8;
        unsigned char *q = p;
        while (isxdigit(*q)) ++q;
        if (q > p) {
            unsigned char *s = (typeof(s)) xmalloc((q - p + 1) * sizeof(s[0]));
            memcpy(s, p, q - p);
            s[q - p] = 0;
            info->edit_session = s;
        }
    }

    return 0;
}

static int
curl_iface_package_page_func(struct DownloadData *data, struct PolygonState *ps, const unsigned char *edit_session)
{
    unsigned char url_buf[1024];

    snprintf(url_buf, sizeof(url_buf), "%s/package?session=%s%s", data->pkt->polygon_url, edit_session, ps->ccid_amp);
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    if (!data->clean_url || !strstr(data->clean_url, "/package")) {
        fprintf(data->log_f, "failed to retrieve problems page: redirected to %s\n", data->effective_url);
        return 1;
    }
    return 0;
}

static int
curl_iface_create_full_package_func(struct DownloadData *data, struct PolygonState *ps, const unsigned char *edit_session)
{
    unsigned char url_buf[1024];

    snprintf(url_buf, sizeof(url_buf), "%s/package?action=create&createFull=true&session=%s%s", data->pkt->polygon_url, edit_session,
             ps->ccid_amp);
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    // FIXME: check redirect URL
    return 0;
}

static int
curl_iface_download_zip_func(struct DownloadData *data, struct PolygonState *ps, const unsigned char *zip_url, const unsigned char *edit_session)
{
    unsigned char url_buf[1024];
    int sep_char = '?';

    if (strchr(zip_url, '?')) sep_char = '&';
    snprintf(url_buf, sizeof(url_buf), "%s/%s%csession=%s", data->pkt->polygon_url, zip_url, sep_char, edit_session);
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    return 0;
}

static int
curl_iface_contests_page_func(struct DownloadData *data, struct PolygonState *ps)
{
    unsigned char url_buf[1024];

    snprintf(url_buf, sizeof(url_buf), "%s/contests%s", data->pkt->polygon_url, ps->ccid_q);
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    if (!data->clean_url || !ends_with(data->clean_url, "/contests")) {
        fprintf(data->log_f, "failed to retrieve contests page: redirected to %s\n", data->effective_url);
        return 1;
    }

    return 0;
}

static int
curl_iface_contest_page_func(struct DownloadData *data, struct PolygonState *ps, int contest_id)
{
    unsigned char url_buf[1024];

    snprintf(url_buf, sizeof(url_buf), "%s/contest?dummy=1&contestId=%d%s", data->pkt->polygon_url, contest_id, ps->ccid_amp);
    if (curl_iface_get_func(data, url_buf) != CURLE_OK) return 1;
    if (!data->clean_url || !ends_with(data->clean_url, "/contest")) {
        fprintf(data->log_f, "failed to retrieve contests page: redirected to %s\n", data->effective_url);
        return 1;
    }

    return 0;
}

static int
curl_iface_contest_api_func(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        const unsigned char *contest_id)
{
    int retval = 0;
    char *sigbuf_s = NULL;
    size_t sigbuf_z = 0;
    FILE *sigbuf_f = NULL;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;

    if (!(sigbuf_f = open_memstream(&sigbuf_s, &sigbuf_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }

    time_t current = time(NULL);

    unsigned char rand6[8];
    rand->ops->b32_bytes(rand, rand6, 6);
    fprintf(sigbuf_f, "%s/contest.problems?apiKey=%s&contestId=%s&time=%lld#%s",
            rand6, key, contest_id, (long long) current, secret);
    fclose(sigbuf_f); sigbuf_f = NULL;

    unsigned char req_hash[256];
    sha512b16buf(req_hash, sizeof(req_hash), sigbuf_s, sigbuf_z);

    if (!(url_f = open_memstream(&url_s, &url_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }
    fprintf(url_f, "%s/api/contest.problems?apiKey=%s&contestId=%s&time=%lld&apiSig=%s%s",
            data->pkt->polygon_url, key, contest_id, (long long) current, rand6, req_hash);
    fclose(url_f); url_f = NULL;

    if (curl_iface_get_func(data, url_s) != CURLE_OK) {
        retval = 1;
        goto done;
    }

done: ;
    if (url_f) fclose(url_f);
    if (url_s) free(url_s);
    if (sigbuf_f) fclose(sigbuf_f);
    if (sigbuf_s) free(sigbuf_s);
    return retval;
}

static int
curl_iface_problems_api_func(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret)
{
    int retval = 0;
    char *sigbuf_s = NULL;
    size_t sigbuf_z = 0;
    FILE *sigbuf_f = NULL;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;

    if (!(sigbuf_f = open_memstream(&sigbuf_s, &sigbuf_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }

    time_t current = time(NULL);

    unsigned char rand6[8];
    rand->ops->b32_bytes(rand, rand6, 6);
    fprintf(sigbuf_f, "%s/problems.list?apiKey=%s&time=%lld#%s",
            rand6, key, (long long) current, secret);
    fclose(sigbuf_f); sigbuf_f = NULL;

    unsigned char req_hash[256];
    sha512b16buf(req_hash, sizeof(req_hash), sigbuf_s, sigbuf_z);

    if (!(url_f = open_memstream(&url_s, &url_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }
    fprintf(url_f, "%s/api/problems.list?apiKey=%s&time=%lld&apiSig=%s%s",
            data->pkt->polygon_url, key, (long long) current, rand6, req_hash);
    fclose(url_f); url_f = NULL;

    if (curl_iface_get_func(data, url_s) != CURLE_OK) {
        retval = 1;
        goto done;
    }

done: ;
    if (url_f) fclose(url_f);
    if (url_s) free(url_s);
    if (sigbuf_f) fclose(sigbuf_f);
    if (sigbuf_s) free(sigbuf_s);
    return retval;
}

static int
curl_iface_problem_info_api_func(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        int problem_id)
{
    int retval = 0;
    char *sigbuf_s = NULL;
    size_t sigbuf_z = 0;
    FILE *sigbuf_f = NULL;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;

    if (!(sigbuf_f = open_memstream(&sigbuf_s, &sigbuf_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }

    time_t current = time(NULL);

    unsigned char rand6[8];
    rand->ops->b32_bytes(rand, rand6, 6);
    fprintf(sigbuf_f, "%s/problem.info?apiKey=%s&problemId=%d&time=%lld#%s",
            rand6, key, problem_id, (long long) current, secret);
    fclose(sigbuf_f); sigbuf_f = NULL;

    unsigned char req_hash[256];
    sha512b16buf(req_hash, sizeof(req_hash), sigbuf_s, sigbuf_z);

    if (!(url_f = open_memstream(&url_s, &url_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }
    fprintf(url_f, "%s/api/problem.info?apiKey=%s&problemId=%d&time=%lld&apiSig=%s%s",
            data->pkt->polygon_url, key, problem_id, (long long) current, rand6, req_hash);
    fclose(url_f); url_f = NULL;

    if (curl_iface_get_func(data, url_s) != CURLE_OK) {
        retval = 1;
        goto done;
    }

done: ;
    if (url_f) fclose(url_f);
    if (url_s) free(url_s);
    if (sigbuf_f) fclose(sigbuf_f);
    if (sigbuf_s) free(sigbuf_s);
    return retval;
}

static int
curl_iface_problem_packages_api_func(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        int problem_id)
{
    int retval = 0;
    char *sigbuf_s = NULL;
    size_t sigbuf_z = 0;
    FILE *sigbuf_f = NULL;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;

    if (!(sigbuf_f = open_memstream(&sigbuf_s, &sigbuf_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }

    time_t current = time(NULL);

    unsigned char rand6[8];
    rand->ops->b32_bytes(rand, rand6, 6);
    fprintf(sigbuf_f, "%s/problem.packages?apiKey=%s&problemId=%d&time=%lld#%s",
            rand6, key, problem_id, (long long) current, secret);
    fclose(sigbuf_f); sigbuf_f = NULL;

    unsigned char req_hash[256];
    sha512b16buf(req_hash, sizeof(req_hash), sigbuf_s, sigbuf_z);

    if (!(url_f = open_memstream(&url_s, &url_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }
    fprintf(url_f, "%s/api/problem.packages?apiKey=%s&problemId=%d&time=%lld&apiSig=%s%s",
            data->pkt->polygon_url, key, problem_id, (long long) current, rand6, req_hash);
    fclose(url_f); url_f = NULL;

    if (curl_iface_get_func(data, url_s) != CURLE_OK) {
        retval = 1;
        goto done;
    }

done: ;
    if (url_f) fclose(url_f);
    if (url_s) free(url_s);
    if (sigbuf_f) fclose(sigbuf_f);
    if (sigbuf_s) free(sigbuf_s);
    return retval;
}

static int
curl_iface_problem_package_api_func(
        struct DownloadData *data,
        struct PolygonState *ps,
        struct RandomSource *rand,
        const unsigned char *key,
        const unsigned char *secret,
        int problem_id,
        int package_id,
        const unsigned char *type)
{
    int retval = 0;
    char *sigbuf_s = NULL;
    size_t sigbuf_z = 0;
    FILE *sigbuf_f = NULL;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;

    if (type && !strcmp(type, "$linux")) {
        type = "Linux";
    }

    if (!(sigbuf_f = open_memstream(&sigbuf_s, &sigbuf_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }

    time_t current = time(NULL);

    unsigned char rand6[8];
    rand->ops->b32_bytes(rand, rand6, 6);
    fprintf(sigbuf_f, "%s/problem.package?apiKey=%s&packageId=%d&problemId=%d&time=%lld&type=%s#%s",
            rand6, key, package_id, problem_id, (long long) current, type, secret);
    fclose(sigbuf_f); sigbuf_f = NULL;

    unsigned char req_hash[256];
    sha512b16buf(req_hash, sizeof(req_hash), sigbuf_s, sigbuf_z);

    if (!(url_f = open_memstream(&url_s, &url_z))) {
        fprintf(data->log_f, "open_memstream failed\n");
        retval = 1;
        goto done;
    }
    fprintf(url_f, "%s/api/problem.package?apiKey=%s&packageId=%d&problemId=%d&time=%lld&type=%s&apiSig=%s%s",
            data->pkt->polygon_url, key, package_id, problem_id, (long long) current, type, rand6, req_hash);
    fclose(url_f); url_f = NULL;

    if (curl_iface_get_func(data, url_s) != CURLE_OK) {
        retval = 1;
        goto done;
    }

done: ;
    if (url_f) fclose(url_f);
    if (url_s) free(url_s);
    if (sigbuf_f) fclose(sigbuf_f);
    if (sigbuf_s) free(sigbuf_s);
    return retval;
}

static const struct DownloadInterface curl_download_interface =
{
    curl_iface_create_func,
    curl_iface_cleanup_func,
    curl_iface_get_page_text,
    curl_iface_get_page_size,
    curl_iface_login_page_func,
    curl_iface_login_action_func,
    curl_iface_problems_page_func,
    curl_iface_problem_info_page_func,
    curl_iface_package_page_func,
    curl_iface_create_full_package_func,
    curl_iface_download_zip_func,
    curl_iface_contests_page_func,
    curl_iface_contest_page_func,
    curl_iface_problems_multi_page_func,
    curl_iface_contest_api_func,
    curl_iface_problems_api_func,
    curl_iface_problem_info_api_func,
    curl_iface_problem_packages_api_func,
    curl_iface_problem_package_api_func,
};

static const struct DownloadInterface *
get_curl_download_interface(FILE *log_f, const struct polygon_packet *pkt)
{
    return &curl_download_interface;
}
#else
/* no curl library was available during compilation */
struct DownloadData
{
    size_t size;
    FILE *log_f;
    const struct DownloadInterface *iface;
    struct polygon_packet *pkt;

    char *page_text;
    size_t page_size;
    char *effective_url;
    char *clean_url;
};
static const struct DownloadInterface *
get_curl_download_interface(FILE *log_f, const struct polygon_packet *pkt)
    __attribute__((unused));
static const struct DownloadInterface *
get_curl_download_interface(FILE *log_f, const struct polygon_packet *pkt)
{
    fprintf(log_f, "libcurl library was missing during the compilation\n");
    return NULL;
}
#endif

static int
ends_with(const unsigned char *str, const unsigned char *suffix)
{
    if (!str) str = "";
    if (!suffix) suffix = "";

    int slen = strlen(str);
    int flen = strlen(suffix);
    return slen >= flen && !strcmp(str + slen - flen, suffix);
}

struct ZipData;
struct ZipInterface
{
    struct ZipData *(*open)(FILE *log_f, const unsigned char *path);
    struct ZipData *(*close)(struct ZipData *zdata);
    int (*read_file)(
        struct ZipData *zdata,
        const unsigned char *name,
        unsigned char **p_data,
        ssize_t *p_size);
};

#if CONF_HAS_LIBZIP - 0 == 1
struct ZipData
{
    FILE *log_f;
    struct zip *zf;
};

struct ZipData *
zip_open_func(FILE *log_f, const unsigned char *path)
{
    int zip_err = 0;
    struct zip *zzz = NULL;
    char errbuf[1024];
    struct ZipData *zdata = NULL;

    if (!(zzz = zip_open(path, 0, &zip_err))) {
        zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
        fprintf(log_f, "%s: failed to open ZIP '%s': %s\n", __FUNCTION__, path, errbuf);
    } else {
        XCALLOC(zdata, 1);
        zdata->log_f = log_f;
        zdata->zf = zzz;
    }
    return zdata;
}

struct ZipData *
zip_close_func(struct ZipData *zdata)
{
    if (zdata) {
        if (zdata->zf) {
            if (zip_close(zdata->zf) < 0) {
                fprintf(zdata->log_f, "%s: close failed: %s\n", __FUNCTION__, zip_strerror(zdata->zf));
            }
        }
        zdata->zf = NULL;
        zdata->log_f = NULL;
        xfree(zdata);
    }
    return NULL;
}

static int
zip_read_file_func(
        struct ZipData *zdata,
        const unsigned char *name,
        unsigned char **p_data,
        ssize_t *p_size)
{
    int file_ind = 0;
    struct zip_stat zs;
    unsigned char *data = NULL, *ptr;
    struct zip_file *zf = NULL;
    ssize_t rz, remz;

    if ((file_ind = zip_name_locate(zdata->zf, name, 0)) < 0) {
        fprintf(zdata->log_f, "%s: file '%s' does not exist\n", __FUNCTION__, name);
        return 0;
    }

    zip_stat_init(&zs);
    if (zip_stat_index(zdata->zf, file_ind, 0, &zs) < 0) {
        fprintf(zdata->log_f, "%s: file '%s' stat failed\n", __FUNCTION__, name);
        goto fail;
    }

    if ((ssize_t) zs.size <= 0) {
        *p_size = 0;
        *p_data = xmalloc(1);
        **p_data = 0;
        return 1;
    }

    *p_size = zs.size;
    data = xmalloc(zs.size + 1);
    if (!(zf = zip_fopen_index(zdata->zf, file_ind, 0))) {
        fprintf(zdata->log_f, "%s: failed to open entry '%s': %s\n", __FUNCTION__, name, zip_strerror(zdata->zf));
        goto fail;
    }

    ptr = data; remz = zs.size;
    while (remz > 0) {
        if ((rz = zip_fread(zf, ptr, remz)) < 0) {
            fprintf(zdata->log_f, "%s: read error: %s\n", __FUNCTION__, zip_file_strerror(zf));
            goto fail;
        }
        if (!rz) {
            fprintf(zdata->log_f, "%s: read returned 0\n", __FUNCTION__);
            goto fail;
        }
        ptr += rz;
        remz -= rz;
    }

    zip_fclose(zf); zf = NULL;
    data[zs.size] = 0;
    *p_data = data;
    return 1;

fail:
    if (zf) zip_fclose(zf);
    xfree(data);
    return -1;
}

static const struct ZipInterface zip_interface =
{
    zip_open_func,
    zip_close_func,
    zip_read_file_func,
};

static const struct ZipInterface *
get_zip_interface(FILE *log_f, const struct polygon_packet *pkt)
{
    return &zip_interface;
}
#else
static const struct ZipInterface *
get_zip_interface(FILE *log_f, const struct polygon_packet *pkt)
    __attribute__((unused));
static const struct ZipInterface *
get_zip_interface(FILE *log_f, const struct polygon_packet *pkt)
{
    fprintf(log_f, "libzip library was missing during the compilation\n");
    return NULL;
}
#endif

struct PolygonState *
polygon_state_create(void)
{
    struct PolygonState *ps = NULL;
    XCALLOC(ps, 1);
    return ps;
}

struct PolygonState *
polygon_state_free(struct PolygonState *ps)
{
    if (!ps) return NULL;
    xfree(ps->ccid);
    xfree(ps->ccid_amp);
    xfree(ps->ccid_q);
    xfree(ps);
    return NULL;
}

const unsigned char * update_statuses[] =
{
    [STATE_NOT_STARTED] = "NOT_STARTED",
    [STATE_NOT_FOUND] = "NOT_FOUND",
    [STATE_ALREADY_EXISTS] = "ALREADY_EXISTS",
    [STATE_FAILED] = "FAILED",
    [STATE_INFO_LOADED] = "INFO_LOADED",
    [STATE_RUNNING] = "RUNNING",
    [STATE_DOWNLOADED] = "DOWNLOADED",
    [STATE_UPDATED] = "UPDATED",
    [STATE_ACTUAL] = "ACTUAL",
    [STATE_UNCOMMITTED] = "UNCOMMITTED",
    [STATE_TIMEOUT] = "TIMEOUT",
    [STATE_NOT_AVAILABLE] = "NOT_AVAILABLE",
    [STATE_PERMISSION_DENIED] = "PERMISSION_DENIED",

    [STATE_LAST] = NULL,
};

struct TagA
{
    unsigned char *url;
    unsigned char *text;
};
static void
free_taga(struct TagA *tags, int count)
{
    if (!tags || count <= 0) return;
    for (int i = 0; i < count; ++i) {
        xfree(tags[i].url);
        xfree(tags[i].text);
    }
    xfree(tags);
}

static void
free_problem_infos(struct ProblemSet *probset)
{
    if (!probset->infos || probset->count <= 0) return;
    for (int i = 0; i < probset->count; ++i) {
        struct ProblemInfo *pi = &probset->infos[i];
        xfree(pi->key_name);
        xfree(pi->ejudge_short_name);
        xfree(pi->problem_name);
        xfree(pi->author);
        xfree(pi->edit_session);
        xfree(pi->long_name_en);
        xfree(pi->long_name_ru);
        xfree(pi->input_file);
        xfree(pi->output_file);
        xfree(pi->input_path_pattern);
        xfree(pi->answer_path_pattern);
        xfree(pi->test_pat);
        xfree(pi->corr_pat);
        xfree(pi->standard_checker);
        xfree(pi->checker_env);
        xfree(pi->check_cmd);
        xfree(pi->test_checker_cmd);
        xfree(pi->solution_cmd);
        xfree(pi->interactor_cmd);
        xfree(pi->html_statement_path);
    }
    xfree(probset->infos);
    probset->count = 0;
    probset->infos = 0;
}

static void
free_revision_info(struct RevisionInfo *info)
{
    if (info) {
        xfree(info->state);
        xfree(info->comment);
        xfree(info->standard_url);
        xfree(info->windows_url);
        xfree(info->linux_url);
    }
    memset(info, 0, sizeof(*info));
}

static int
check_directory(
        FILE *log_f,
        const unsigned char *dir_mode,
        const unsigned char *dir_group,
        const unsigned char *name,
        const unsigned char *path)
{
    struct stat stb;

    if (!path || !*path) {
        fprintf(log_f, "'%s': undefined\n", name);
        return 1;
    }

    if (stat(path, &stb) < 0) {
        if (os_MakeDirPath2(path, dir_mode, dir_group) < 0) {
            fprintf(log_f, "'%s': failed to create '%s'\n", name, path);
            return 1;
        }
    }
    if (stat(path, &stb) < 0) {
        fprintf(log_f, "'%s': path '%s' still does not exist\n", name, path);
        return 1;
    }

    if (!S_ISDIR(stb.st_mode)) {
        fprintf(log_f, "'%s': path '%s' is not a directory\n", name, path);
        return 1;
    }
    if (access(path, R_OK | W_OK | X_OK) < 0) {
        fprintf(log_f, "'%s': path '%s' has insufficient permissions\n", name, path);
        return 1;
    }
    return 0;
}

static int
check_directories(FILE *log_f, const struct polygon_packet *pkt)
{
    int retval = 0;

    if ((retval = check_directory(log_f, pkt->dir_mode, pkt->dir_group, "download_dir", pkt->download_dir)))
        return retval;
    if ((retval = check_directory(log_f, pkt->dir_mode, pkt->dir_group, "problem_dir", pkt->problem_dir)))
        return retval;

    return retval;
}

static void
extract_a(const unsigned char *s, struct TagA **p_tags, int *p_count)
{
    unsigned char *ubuf = NULL;
    unsigned char *tbuf = NULL, *pt;
    unsigned char *vbuf = NULL, *pv;
    int slen, term;
    int count = 0;
    int size = 0;
    struct TagA *tags = NULL;

    if (!s || !*s) return;
    slen = strlen(s);
    ubuf = (typeof(ubuf)) xmalloc((slen + 1) * sizeof(ubuf[0]));
    tbuf = (typeof(tbuf)) xmalloc((slen + 1) * sizeof(tbuf[0]));
    vbuf = (typeof(vbuf)) xmalloc((slen + 1) * sizeof(vbuf[0]));

    while (*s) {
        if (*s == '<') {
            ++s;
            while (isspace(*s)) ++s;
            pv = vbuf;
            while (isalnum(*s) || *s == '_' || *s == '-')
                *pv++ = tolower(*s++);
            *pv = 0;
            if (strcmp(vbuf, "a") != 0) {
                continue;
            }
            while (isspace(*s)) ++s;
            while (*s && *s != '>') {
                pt = tbuf;
                while (isalnum(*s) || *s == '_' || *s == '-')
                    *pt++ = tolower(*s++);
                *pt = 0;
                while (isspace(*s)) ++s;
                if (*s != '=') continue;
                ++s;
                while (isspace(*s)) ++s;
                if (*s == '\'' || *s == '\"') {
                    term = *s;
                    ++s;
                    pv = vbuf;
                    while (*s && *s != term) {
                        *pv++ = *s++;
                    }
                    *pv = 0;
                    if (*s) {
                        ++s;
                        if (!strcmp(tbuf, "href")) {
                            strcpy(ubuf, vbuf);
                        }
                    }
                } else {
                    continue;
                }
                while (isspace(*s)) ++s;
            }
            if (!*s) continue;
            if (*s != '>') continue;
            ++s;
            pt = tbuf;
            while (*s) {
                if (*s == '<' && s[1] == '/' && (s[2] == 'a' || s[2] == 'A') && s[3] == '>') {
                    s += 4;
                    break;
                }
                *pt++ = *s++;
            }
            *pt = 0;

            if (count == size) {
                if (!(size *= 2)) size = 16;
                tags = (typeof(tags)) realloc(tags, size * sizeof(tags[0]));
            }
            tags[count].url = strdup(ubuf);
            tags[count].text = strdup(tbuf);
            ++count;
        } else {
            ++s;
        }
    }

    xfree(ubuf);
    xfree(tbuf);
    xfree(vbuf);
    *p_count = count;
    *p_tags = tags;
}

static int
extract_td_content(const unsigned char *s, unsigned char *out, const unsigned char **out_s)
{
    int outpos = 0;
    *out = 0;
    if (*s != '<') return -1;
    ++s;
    while (isspace(*s)) ++s;
    if (tolower(s[0]) != 't' || tolower(s[1]) != 'd') return -1;
    s += 2;
    if (!isspace(*s) && *s != '>') return -1;
    while (*s && *s != '>') ++s;
    if (*s != '>') return -1;
    ++s;
    while (isspace(*s)) ++s;
    while (1) {
        if (!*s) return -1;
        if (!strncmp(s, "</td>", 5)) {
            s += 5;
            break;
        }
        if (*s == '<') {
            ++s;
            while (*s && *s != '>') ++s;
            if (*s == '>') ++s;
            if (!outpos) {
                while (isspace(*s)) ++s;
            }
            continue;
        }
        out[outpos++] = *s++;
    }
    while (outpos > 0 && isspace(out[outpos - 1])) --outpos;
    out[outpos] = 0;
    *out_s = s;
    return 1;
}

static int
extract_raw_td_content(const unsigned char *s, unsigned char *out, const unsigned char **out_s)
{
    unsigned char *p = strstr(s, "</td>");
    if (!p) {
        *out = 0;
        return -1;
    }
    memcpy(out, s + 4, p - s - 4);
    out[p - s - 4] = 0;
    s = p + 5;
    return 1;
}

static time_t
parse_time(FILE *log_f, const unsigned char *param_name, const unsigned char *buf);

static int
process_login_page(
        FILE *log_f,
        struct PolygonState *ps,
        struct DownloadData *ddata)
{
    int pos = 0;
    const unsigned char *text = ddata->iface->get_page_text(ddata);
    const unsigned char *cur;
    struct HtmlElement *elem = NULL;
    struct HtmlAttribute *attr;

    while ((cur = strstr(text + pos, "<input"))) {
        pos = (int)(cur - text);
        elem = html_element_parse_start(text, pos, &pos);
        if (elem) {
            if ((attr = html_element_find_attribute(elem, "type")) && attr->value && !strcasecmp(attr->value, "hidden")
                && (attr = html_element_find_attribute(elem, "name")) && attr->value && !strcasecmp(attr->value, "ccid")
                && (attr = html_element_find_attribute(elem, "value")) && attr->value) {
                ps->ccid = xstrdup(attr->value);
                elem = html_element_free(elem);
                break;
            }
            elem = html_element_free(elem);
        }
    }

    if (ps->ccid) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "&ccid=%s", ps->ccid);
        ps->ccid_amp = xstrdup(buf);
        snprintf(buf, sizeof(buf), "?ccid=%s", ps->ccid);
        ps->ccid_q = xstrdup(buf);
    } else {
        ps->ccid_amp = xstrdup("");
        ps->ccid_q = xstrdup("?");
    }

    return 0;
}

static void
process_problem_row(
        FILE *log_f,
        const unsigned char *text,
        struct ProblemSet *probset)
{
    unsigned char *buf = NULL;
    struct TagA *a_tags = NULL;
    int a_count = 0;
    if (!text) text = "";
    int row_len = strlen(text);
    int id = -1, n = -1;

    buf = (typeof(buf)) malloc((row_len + 1) * sizeof(buf[0]));
    buf[0] = 0; n = -1;
    if (sscanf(text, "<tr problemId=\"%d\" problemName=\"%[^\"]\"%n", &id, buf, &n) != 2 || n < 0) {
        fprintf(log_f, "failed to parse problemId: %.60s...\n", text);
        goto cleanup;
    }
    if (!isspace(text[n]) && text[n] != '>') {
        fprintf(log_f, "failed to parse problemId: %.60s...\n", text);
        goto cleanup;
    }
    if (!buf[0]) {
        fprintf(log_f, "problemName is empty: %.60s...\n", text);
        goto cleanup;
    }

    // find by id or name
    int num;
    for (num = 0; num < probset->count; ++num) {
        if (probset->infos[num].key_id > 0 && probset->infos[num].key_id == id) {
            break;
        } else if (probset->infos[num].key_name && !strcmp(probset->infos[num].key_name, buf)) {
            break;
        }
    }
    if (num >= probset->count) goto cleanup;

    struct ProblemInfo *pi = &probset->infos[num];
    if (pi->state == STATE_UPDATED || pi->state == STATE_ACTUAL) goto cleanup;

    pi->state = STATE_FAILED;
    pi->problem_id = id;
    pi->problem_name = strdup(buf);

    const unsigned char *s = text;
    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 1 (favorite), but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (!(s = strstr(s + 4, "<td"))) {
        fprintf(log_f, "expected column 2 (problemId), but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (extract_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 2 (problemId): %.60s...\n", s);
        goto cleanup;
    }
    n = -1; id = -1;
    if (sscanf(buf, "%d%n", &id, &n) != 1 || n < 0 || id <= 0 || buf[n]) {
        fprintf(log_f, "failed to parse problemId in column 2: %.60s...\n", buf);
        goto cleanup;
    }
    if (id != pi->problem_id) {
        fprintf(log_f, "problemId mismatch: <tr>: %d, <td>: %d\n", pi->problem_id, id);
        goto cleanup;
    }
    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 3 (problemName), but got nothing in row %s\n", text);
        goto cleanup;
    }
    s += 4;
    /*
    if (extract_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 3 (problemName): %.60s...\n", s);
        goto cleanup;
    }
    if (strcmp(pi->problem_name, buf) != 0) {
        fprintf(log_f, "problemName mismatch: <tr>: %s, <td>: %s\n", pi->problem_name, buf);
        goto cleanup;
    }
    */
    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 4 (author), but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (extract_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 4 (author): %.60s...\n", s);
        goto cleanup;
    }
    pi->author = strdup(buf);

    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 5, but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (extract_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 7: %.60s...\n", s);
        goto cleanup;
    }

    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 6 (revision), but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (extract_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 5 (revision): %.60s...\n", s);
        goto cleanup;
    }
    int lr = -1, pr = -1;
    n = -1;
    // Well, ignore garbage after revision number
    if (sscanf(buf, "%d / %d", &lr, &pr) != 2) {
        if (sscanf(buf, "%d", &lr) != 1) {
            fprintf(log_f, "failed to parse revision column: %s\n", buf);
            goto cleanup;
        } else {
            pr = lr;
        }
    }
    if (lr <= 0) {
        fprintf(log_f, "invalid latest revision %d\n", lr);
        goto cleanup;
    }
    if (pr <= 0) {
        fprintf(log_f, "invalid package revision %d\n", pr);
        goto cleanup;
    }
    if (pr > lr) {
        fprintf(log_f, "package revision %d > latest revision %d\n", pr, lr);
        goto cleanup;
    }
    pi->latest_rev = lr;
    pi->package_rev = pr;
    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 7 (modification time), but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (extract_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 6 (modification time): %.60s...\n", s);
        goto cleanup;
    }

    time_t lt = parse_time(log_f, "modification time", buf);
    if (lt < 0) goto cleanup;

    pi->mtime = lt;

    if (!(s = strstr(s, "<td"))) {
        fprintf(log_f, "expected column 8 (links), but got nothing in row %s\n", text);
        goto cleanup;
    }
    if (extract_raw_td_content(s, buf, &s) < 0) {
        fprintf(log_f, "failed to extract the content of column 8 (links): %.60s...\n", s);
        goto cleanup;
    }

    extract_a(buf, &a_tags, &a_count);
    if (a_count > 0) {
        for (int i = 0; i < a_count; ++i) {
            static const char id_param_string[] = "workingCopyId=";
            if (!strcmp(a_tags[i].text, "Continue")) {
                unsigned char *p = strstr(a_tags[i].url, id_param_string);
                if (p) {
                    sscanf(p + sizeof(id_param_string) - 1, "%d", &pi->continue_id);
                }
            } else if (strstr(a_tags[i].text, "Continue ")) {
                unsigned char *p = strstr(a_tags[i].url, id_param_string);
                if (p) {
                    sscanf(p + sizeof(id_param_string) - 1, "%d", &pi->continue_id);
                }
            } else if (!strcmp(a_tags[i].text, "Discard")) {
                unsigned char *p = strstr(a_tags[i].url, id_param_string);
                if (p) {
                    sscanf(p + sizeof(id_param_string) - 1, "%d", &pi->discard_id);
                }
            } else if (!strcmp(a_tags[i].text, "Start")) {
                pi->has_start = 1;
            }
        }
    }

    pi->state = STATE_INFO_LOADED;

cleanup:
    free_taga(a_tags, a_count);
    xfree(buf);
}

static const unsigned char *
skip_to_tag_end(const unsigned char *s)
{
    // make something complicated
    while (*s && *s != '>') {
        ++s;
    }
    return s;
}

static int
find_column(int count, unsigned char **titles, const unsigned char *str)
{
    if (count <= 0) return 0;
    for (int i = 0; i < count; ++i) {
        if (!strcmp(titles[i], str)) {
            return i + 1;
        }
    }
    return 0;
}

static int
process_problems_table_header(
        FILE *log_f,
        struct PolygonState *ps,
        const unsigned char *text)
{
    unsigned char **titles = NULL;
    int title_a = 0;
    int title_u = 0;

    // extract table header
    const unsigned char *thead_beg = strstr(text, "<thead>");
    if (!thead_beg) {
        fprintf(log_f, "no <thead> tag in problems page\n");
        return -1;
    }
    const unsigned char *thead_end = strstr(text, "</thead>");
    if (!thead_end) {
        fprintf(log_f, "no </thead> tag in problems page\n");
        return -1;
    }
    if (thead_end < thead_beg) {
        fprintf(log_f, "invalid location of <thead> and </thead> tags\n");
        return -1;
    }

    unsigned char *thbuf = xmalloc(thead_end - thead_beg + 9); // + </thead> + \0
    memcpy(thbuf, thead_beg, thead_end - thead_beg + 8);
    thbuf[thead_end - thead_beg + 8] = 0;

    const unsigned char *s = thbuf + 7;
    while ((s = strstr(s, "<th"))) {
        s = skip_to_tag_end(s + 3);
        if (!*s) {
            fprintf(log_f, "unexpected end of th tag\n");
            break;
        }
        ++s;
        const unsigned char *q = strstr(s, "</th>");
        if (!q) {
            fprintf(log_f, "no matching </th> tag\n");
            break;
        }
        while (s < q && isspace(*s)) {
            ++s;
        }
        int len = q - s;
        unsigned char *title = xmalloc(len + 1);
        memcpy(title, s, len);
        while (len > 0 && isspace(title[len - 1]))
            --len;
        title[len] = 0;
        s = q + 5;
        if (title_u == title_a) {
            if (!(title_a *= 2)) title_a = 16;
            titles = xrealloc(titles, sizeof(titles[0]) * title_a);
        }
        titles[title_u++] = title; title = NULL;
    }

    fprintf(log_f, "Problem table columns:\n");
    for (int i = 0; i < title_u; ++i) {
        fprintf(log_f, "    %s\n", titles[i]);
    }

    ps->id_column_num = find_column(title_u, titles, "#");
    ps->name_column_num = find_column(title_u, titles, "Name");
    ps->owner_column_num = find_column(title_u, titles, "Owner");
    ps->rev_column_num = find_column(title_u, titles, "Rev.");
    ps->modif_column_num = find_column(title_u, titles, "Modif.");
    ps->edit_column_num = find_column(title_u, titles, "Edit session");

    fprintf(log_f, "Problem table columns:\n");
    fprintf(log_f, "    Id:    %d\n", ps->id_column_num);
    fprintf(log_f, "    Name:  %d\n", ps->name_column_num);
    fprintf(log_f, "    Owner: %d\n", ps->owner_column_num);
    fprintf(log_f, "    Rev:   %d\n", ps->rev_column_num);
    fprintf(log_f, "    Modif: %d\n", ps->modif_column_num);
    fprintf(log_f, "    Edit:  %d\n", ps->edit_column_num);

    for (int i = 0; i < title_u; ++i) {
        xfree(titles[i]);
    }
    xfree(titles);
    xfree(thbuf);
    return 0;
}

static void
process_problems_page(
        FILE *log_f,
        struct PolygonState *ps,
        const unsigned char *text,
        struct ProblemSet *probset)
{
    const unsigned char *s, *q;
    int row_len;
    unsigned char *row = NULL;

    if (!text) text = "";

    if (process_problems_table_header(log_f, ps, text) < 0) {
        return;
    }

    s = text;

    while ((s = strstr(s, "<tr problemId=\""))) {
        if (!(q = strstr(s, "</tr>"))) {
            fprintf(log_f, "problems page: failed to find matching </tr>\n");
            break;
        }

        row_len = q - s + 5;
        row = (typeof(row)) xmalloc((row_len + 1) * sizeof(row[0]));
        memcpy(row, s, row_len);
        row[row_len] = 0;

        process_problem_row(log_f, row, probset);

        xfree(row); row = NULL;
        s = q + 5;
    }

    for (int i = 0; i < probset->count; ++i) {
        if (probset->infos[i].state == STATE_NOT_STARTED)
            probset->infos[i].state = STATE_NOT_FOUND;
    }
}

static int
process_contests_page(
        FILE *log_f,
        struct PolygonState *ps,
        struct DownloadData *ddata,
        const unsigned char *polygon_contest_id,
        int *p_id)
{
    const unsigned char *text = ddata->iface->get_page_text(ddata);
    const unsigned char *cur;
    int pos = 0;
    struct HtmlElement *elem = NULL;
    struct HtmlAttribute *attr;
    int id = 0;

    while ((cur = strstr(text + pos, "<tr"))) {
        pos = (int)(cur - text);
        elem = html_element_parse_start(text, pos, &pos);
        if (elem) {
            const unsigned char *contest_id = NULL;
            const unsigned char *contest_name = NULL;

            if ((attr = html_element_find_attribute(elem, "contestid")) && attr->value) {
                contest_id = attr->value;
            }
            if ((attr = html_element_find_attribute(elem, "contestname")) && attr->value) {
                contest_name = attr->value;
            }

            if (contest_id && contest_name && (!strcmp(contest_id, polygon_contest_id) || !strcmp(contest_name, polygon_contest_id))) {
                if (sscanf(contest_id, "%d", &id) == 0 || id <= 0) {
                    fprintf(log_f, "invalid contest id '%s'\n", contest_id);
                }
            }

            elem = html_element_free(elem);
        }
    }

    if (p_id) *p_id = id;

    return 0;
}

static int
process_contest_page(
        FILE *log_f,
        struct PolygonState *ps,
        struct DownloadData *ddata,
        struct ProblemSet *probset)
{
    const unsigned char *text = ddata->iface->get_page_text(ddata);
    const unsigned char *cur;
    int pos = 0;
    struct HtmlElement *elem = NULL;
    struct HtmlAttribute *attr;
    int count = 0;

    while ((cur = strstr(text + pos, "<tr"))) {
        pos = (int)(cur - text);
        elem = html_element_parse_start(text, pos, &pos);
        if (elem) {
            if ((attr = html_element_find_attribute(elem, "problemid")) && attr->value) {
                ++count;
            }
            elem = html_element_free(elem);
        }
    }

    if (count <= 0) return 0;

    probset->count = count;
    XCALLOC(probset->infos, probset->count);

    pos = 0;
    count = 0;
    while ((cur = strstr(text + pos, "<tr"))) {
        pos = (int)(cur - text);
        elem = html_element_parse_start(text, pos, &pos);
        if (elem) {
            if ((attr = html_element_find_attribute(elem, "problemid")) && attr->value) {
                int id = 0;
                sscanf(attr->value, "%d", &id);
                if (id > 0) {
                    probset->infos[count++].key_id = id;
                }
            }
            elem = html_element_free(elem);
        }
    }
    probset->count = count;

    return 0;
}

static time_t
parse_time(FILE *log_f, const unsigned char *param_name, const unsigned char *buf)
{
    int year, month, mday, hour, min, sec, n;

    year = month = mday = hour = min = sec = n = -1;
    if (sscanf(buf, "%d-%d-%d %d:%d:%d%n", &year, &month, &mday, &hour, &min, &sec, &n) == 6 && !buf[n]) {
    } else {
        year = month = mday = n = -1;
        hour = min = sec = 0;
        if (sscanf(buf, "%d-%d-%d%n", &year, &month, &mday, &n) == 3 && !buf[n]) {
        } else {
            fprintf(log_f, "failed to parse %s: %s\n", param_name, buf);
            return -1;
        }
    }
    if (year < 1980 || year > 2030) {
        fprintf(log_f, "invalid year in %s: %d\n", param_name, year);
        return -1;
    }
    if (month <= 0 || month > 12) {
        fprintf(log_f, "invalid month in %s: %d\n", param_name, month);
        return -1;
    }
    if (mday <= 0 || mday > 31) {
        fprintf(log_f, "invalid day in %s: %d\n", param_name, mday);
        return -1;
    }
    if (hour < 0 || hour >= 24) {
        fprintf(log_f, "invalid hour in %s: %d\n", param_name, hour);
        return -1;
    }
    if (min < 0 || min >= 60) {
        fprintf(log_f, "invalid min in %s: %d\n", param_name, min);
        return -1;
    }
    if (sec < 0 || sec > 60) {
        fprintf(log_f, "invalid sec in %s: %d\n", param_name, sec);
        return -1;
    }

    struct tm ltm;
    memset(&ltm, 0, sizeof(ltm));
    ltm.tm_isdst = -1;
    ltm.tm_year = year - 1900;
    ltm.tm_mon = month - 1;
    ltm.tm_mday = mday;
    ltm.tm_hour = hour;
    ltm.tm_min = min;
    ltm.tm_sec = sec;
    time_t lt = mktime(&ltm);
    if (lt < 0) {
        fprintf(log_f, "invalid %s: %s\n", param_name, buf);
        return -1;
    }
    return lt;
}

static int
find_revision(FILE *log_f, const unsigned char *text, int revision, struct RevisionInfo *ri)
{
    unsigned char *tr = NULL;
    unsigned char *buf = NULL;
    int a_count = 0;
    struct TagA *a_tags = NULL;
    int retval = -1;

    if (!text) text = "";
    const unsigned char *p = strstr(text, "<table class=\"grid tablesorter\">");
    if (!p) return 0;
    p = strstr(p, "<tbody>");
    if (!p) return 0;
    const unsigned char *endp = strstr(p, "</tbody>");

    while (1) {
        free(tr); tr = NULL;
        free(buf); buf = NULL;

        p = strstr(p, "<tr>");
        if (!p || p >= endp) break;
        p += 4;
        const unsigned char *s = p;
        const unsigned char *q = strstr(p, "</tr>");
        if (!q) {
            fprintf(log_f, "find_revision: no matching </tr>\n");
            goto cleanup;
        }
        int trl = q - p;
        tr = (typeof(tr)) xmalloc((trl + 1) * sizeof(tr[0]));
        memcpy(tr, p, trl);
        tr[trl] = 0;
        p = q + 5;
        buf = (typeof(tr)) xmalloc((trl + 1) * sizeof(buf[0]));

        if (!(s = strstr(s, "<td"))) {
            fprintf(log_f, "expected column 1 (packageId), but nothing found\n");
            goto cleanup;
        }
        if (extract_td_content(s, buf, &s) < 0) {
            fprintf(log_f, "failed to extract the content of column 1 (packageId): %.60s...\n", s);
            goto cleanup;
        }
        errno = 0;
        char *eptr = NULL;
        int val = strtol(buf, &eptr, 10);
        if (errno || *eptr || val <= 0) {
            fprintf(log_f, "invalid value in column 1 (packageId): %s\n", buf);
            goto cleanup;
        }
        ri->package_id = val;

        if (!(s = strstr(s, "<td"))) {
            fprintf(log_f, "expected column 2 (revision), but nothing found\n");
            goto cleanup;
        }
        if (extract_td_content(s, buf, &s) < 0) {
            fprintf(log_f, "failed to extract the content of column 2 (revision): %.60s...\n", s);
            goto cleanup;
        }
        errno = 0;
        eptr = NULL;
        val = strtol(buf, &eptr, 10);
        if (errno || *eptr || val < 0) {
            fprintf(log_f, "invalid value in column 2 (revision): %s\n", buf);
            goto cleanup;
        }
        if (val != revision) continue;
        ri->revision = val;

        if (!(s = strstr(s, "<td"))) {
            fprintf(log_f, "expected column 3 (creation time), but nothing found\n");
            goto cleanup;
        }
        if (extract_td_content(s, buf, &s) < 0) {
            fprintf(log_f, "failed to extract the content of column 3 (creation time): %.60s...\n", s);
            goto cleanup;
        }

        time_t lt = parse_time(log_f, "creation time", buf);
        if (lt < 0) goto cleanup;
        ri->creation_time = lt;

        if (!(s = strstr(s, "<td"))) {
            fprintf(log_f, "expected column 4 (state), but nothing found\n");
            goto cleanup;
        }
        if (extract_td_content(s, buf, &s) < 0) {
            fprintf(log_f, "failed to extract the content of column 4 (state): %.60s...\n", s);
            goto cleanup;
        }
        ri->state = strdup(buf);

        if (!(s = strstr(s, "<td"))) {
            fprintf(log_f, "expected column 5 (comment), but nothing found\n");
            goto cleanup;
        }
        if (extract_td_content(s, buf, &s) < 0) {
            fprintf(log_f, "failed to extract the content of column 5 (comment): %.60s...\n", s);
            goto cleanup;
        }
        ri->comment = strdup(buf);

        if (!(s = strstr(s, "<td "))) {
            fprintf(log_f, "expected column 6 (download), but got nothing\n");
            goto cleanup;
        }
        if (extract_raw_td_content(s, buf, &s) < 0) {
            fprintf(log_f, "failed to extract the content of column 6 (download): %.60s...\n", s);
            goto cleanup;
        }
        extract_a(buf, &a_tags, &a_count);
        if (a_tags) {
            for (int i = 0; i < a_count; ++i) {
                if (!strcmp(a_tags[i].text, "Standard")) {
                    ri->standard_url = strdup(a_tags[i].url);
                } else if (!strcmp(a_tags[i].text, "Windows")) {
                    ri->windows_url = strdup(a_tags[i].url);
                } else if (!strcmp(a_tags[i].text, "Linux")) {
                    ri->linux_url = strdup(a_tags[i].url);
                }
            }
        }
        retval = 1;
        goto cleanup;
    }

    retval = 0;

cleanup:
    free(tr);
    free(buf);
    free_taga(a_tags, a_count);
    return retval;
}

static int
parse_mode(const unsigned char *mode_str)
{
  char *eptr = NULL;
  int val = 0;

  errno = 0;
  val = strtol(mode_str, &eptr, 8);
  if (errno || val <= 0 || val > 07777) return -1;
  return val;
}

static int
parse_group(const unsigned char *group_str)
{
  struct group *grp = getgrnam(group_str);
  if (!grp || grp->gr_gid <= 0) return -1;
  return grp->gr_gid;
}

static int
is_file_unchanged(const unsigned char *path, const unsigned char *bytes, ssize_t size)
{
    struct stat stb;
    unsigned char *b = NULL, *s;
    ssize_t z = 0, r = 0;
    int fd = -1;

    if (stat(path, &stb) < 0) {
        goto fail;
    }
    if (stb.st_size != size) {
        //fprintf(stderr, "size mismatch: %s, %d, %d\n", path, (int) stb.st_size, size);
        goto fail;
    }
    b = xmalloc((size + 1) * sizeof(b[0]));
    if ((fd = open(path, O_RDONLY, 0)) < 0) {
        goto fail;
    }
    z = size; s = b;
    while (z && (r = read(fd, s, z)) > 0) {
        z -= r; s += r;
    }
    if (r <= 0) goto fail;
    if (read(fd, s, 1) != 0) goto fail;
    *s = 0;
    close(fd); fd = -1;
    if (memcmp(b, bytes, size) != 0) goto fail;
    xfree(b);
    return 1;

fail:
    if (fd >= 0) close(fd);
    xfree(b);
    return 0;
}

static int
save_file(
        FILE *log_f,
        const unsigned char *path,
        const unsigned char *bytes,
        ssize_t size,
        const unsigned char *file_mode,
        const unsigned char *file_group,
        int *p_changed)
{
    __attribute__((unused)) int _;

    if (is_file_unchanged(path, bytes, size)) {
        if (p_changed) *p_changed = 0;
        return 0;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(log_f, "failed to open '%s' for writing: %s\n", path, strerror(errno));
        return 1;
    }
    for (ssize_t i = 0; i < size; ++i) {
        if (putc_unlocked(bytes[i], f) == EOF) {
            fprintf(log_f, "write error to '%s': %s\n", path, strerror(errno));
            fclose(f);
            return 1;
        }
    }
    if (fflush(f) < 0) {
        fprintf(log_f, "write error to '%s': %s\n", path, strerror(errno));
        fclose(f);
        return 1;
    }
    fclose(f); f = NULL;

    int mode = 0;
    if (file_mode && *file_mode) {
        mode = parse_mode(file_mode);
        if (mode < 0) {
            fprintf(log_f, "invalid file mode '%s'\n", file_mode);
            mode = 0;
        }
    }
    int group = 0;
    if (file_group && *file_group) {
        group = parse_group(file_group);
        if (group < 0) {
            fprintf(log_f, "invalid group '%s'\n", file_group);
            group = 0;
        }
    }
    if (mode > 0) _ = chmod(path, mode);
    if (group > 0) _ = chown(path, -1, group);
    if (p_changed) *p_changed = 1;
    return 0;
}

static ssize_t
parse_memory_limit(FILE *log_f, const unsigned char *str)
{
    if (!str) return -1;
    char *eptr = NULL;
    errno = 0;
    long long value = strtoll(str, &eptr, 10);
    if (errno || *eptr) return -1;
    if (value < 0) return -1;
    if (value >= 2LL * 1024LL * 1024LL * 1024LL) return -1;
    return (ssize_t) value;
}

static int
check_format(const unsigned char *format)
{
  int printf_arg_types[10];
  memset(printf_arg_types, 0, sizeof(printf_arg_types));
  int printf_arg_count = parse_printf_format(format, 10, printf_arg_types);
  if (printf_arg_count != 1) return 1;
  if ((printf_arg_types[0] & ~PA_FLAG_MASK) != PA_INT) return 1;
  return 0;
}

static int
copy_from_zip(
        FILE *log_f,
        const struct polygon_packet *pkt,
        const struct ZipInterface *zif,
        struct ZipData *zid,
        const unsigned char *arch_path,
        const unsigned char *zip_path,
        const unsigned char *path)
{
    unsigned char *data = NULL;
    ssize_t size = 0;
    int is_changed = 0;
    int r = zif->read_file(zid, zip_path, &data, &size);
    if (!r) {
        fprintf(log_f, "file '%s' does not exist in archive '%s'\n", zip_path, arch_path);
        return 1;
    }
    if (r < 0) {
        fprintf(log_f, "failed to read '%s' from archive '%s'\n", zip_path, arch_path);
        return 1;
    }
    if (save_file(log_f, path, data, size, pkt->file_mode, pkt->file_group, &is_changed)) {
        xfree(data);
        return 1;
    }
    if (is_changed) fprintf(log_f, "%s saved ok\n", path);
    xfree(data);
    return 0;
}

static const unsigned char *
get_attr_by_name(struct xml_tree *t, const unsigned char *name)
{
    for (struct xml_attr *a = t->first; a; a = a->next) {
        if (!strcmp(a->name[0], name))
            return a->text;
    }
    return NULL;
}

static struct xml_tree *
get_elem_by_name(struct xml_tree *t, const unsigned char *name)
{
    for (struct xml_tree *t1 = t->first_down; t1; t1 = t1->right) {
        if (!strcmp(t1->name[0], name))
            return t1;
    }
    return NULL;
}

static struct xml_tree *
get_next_elem_by_name(struct xml_tree *t, const unsigned char *name)
{
    if (t) {
        for (struct xml_tree *t1 = t->right; t1; t1 = t1->right) {
            if (!strcmp(t1->name[0], name))
                return t1;
        }
    }
    return NULL;
}

static void
process_polygon_zip(
        FILE *log_f,
        const struct polygon_packet *pkt,
        const struct ZipInterface *zif,
        const unsigned char *zip_path,
        struct ProblemInfo *pi,
        int fill_info_mode)
{
    struct ZipData *zid = NULL;
    unsigned char *data = NULL;
    ssize_t size = 0;
    struct xml_tree *tree = NULL;
    struct xml_attr *a;
    struct problem_config_section *prob_cfg = NULL;
    char *cfg_text = NULL;
    size_t cfg_size = 0;
    FILE *cfg_file = NULL;
    unsigned char *problem_url = NULL;

    if (!(zid = zif->open(log_f, zip_path))) {
        fprintf(log_f, "Failed to open zip file '%s'\n", zip_path);
        goto zip_error;
    }

    if (zif->read_file(zid, pkt->problem_xml_name, &data, &size) <= 0) {
        goto zip_error;
    }

    if (pkt->verbose > 0) {
        fprintf(log_f, "Problem XML:\n");
        fprintf(log_f, "%s\n", data);
    }

    tree = xml_build_tree_str(log_f, data, &generic_xml_parse_spec);
    if (!tree) {
        fprintf(log_f, "parsing of '%s' failed\n", pkt->problem_xml_name);
        goto zip_error;
    }
    xfree(data); data = NULL; size = 0;
    if (strcmp(tree->name[0], "problem")) {
        fprintf(log_f, "%s: root element must be <problem>\n", pkt->problem_xml_name);
        goto zip_error;
    }
    for (a = tree->first; a; a = a->next) {
        if (!strcmp(a->name[0], "short-name")) {
            if (fill_info_mode > 0) {
                pi->problem_name = xstrdup(a->text);
            }
        } else if (!strcmp(a->name[0], "name")) {
            if (strcmp(pi->problem_name, a->text)) {
                fprintf(log_f, "problem name mismatch: db == '%s', xml attr == '%s'\n", pi->problem_name, a->text);
                goto zip_error;
            }
        } else if (!strcmp(a->name[0], "revision")) {
            int revision = -1;
            if (xml_parse_int(log_f, pkt->problem_xml_name, a->line, a->column, a->text, &revision)) {
                fprintf(log_f, "failed to parse revision attribute\n");
                goto zip_error;
            }
            if (fill_info_mode > 0) {
                pi->package_rev = revision;
            } else if (pi->package_rev != revision && pkt->fetch_latest_available <= 0) {
                fprintf(log_f, "package revision mismatch: db == %d, xml attr == %d\n", pi->package_rev, revision);
                goto zip_error;
            }
        } else if (!strcmp(a->name[0], "url")) {
            const char *p = a->text;
            if (!strncasecmp(p, "http://", 7)) {
                p += 7;
            } else if (!strncasecmp(p, "https://", 8)) {
                p += 8;
            }
            const char *q = strchr(p, '/');
            if (q) {
                problem_url = xstrdup(q + 1);
            }
        }
    }

    for (struct xml_tree *t1 = tree->first_down; t1; t1 = t1->right) {
        if (!strcmp(t1->name[0], "names")) {
            for (struct xml_tree *t2 = t1->first_down; t2; t2 = t2->right) {
                if (!strcmp(t2->name[0], "name")) {
                    const unsigned char *language = NULL;
                    const unsigned char *value = NULL;
                    for (a = t2->first; a; a = a->next) {
                        if (!strcmp(a->name[0], "language")) {
                            language = a->text;
                        } else if (!strcmp(a->name[0], "value")) {
                            value = a->text;
                        }
                    }
                    if(language && value) {
                        if (!strcmp(language, "russian")) {
                            pi->long_name_ru = xstrdup(value);
                        } else if (!strcmp(language, "english")) {
                            pi->long_name_en = xstrdup(value);
                        }
                    }
                }
            }
        } else if (!strcmp(t1->name[0], "judging")) {
            const unsigned char *input_file = NULL;
            const unsigned char *output_file = NULL;
            for (a = t1->first; a; a = a->next) {
                if (!strcmp(a->name[0], "input-file") && a->text[0]) {
                    input_file = a->text;
                } else if (!strcmp(a->name[0], "output-file") && a->text[0]) {
                    output_file = a->text;
                }
            }
            if (input_file) pi->input_file = xstrdup(input_file);
            if (output_file) pi->output_file = xstrdup(output_file);
            for (struct xml_tree *t2 = t1->first_down; t2; t2 = t2->right) {
                if (!strcmp(t2->name[0], "testset")) {
                    const unsigned char *testset_name = NULL;
                    for (a = t2->first; a; a = a->next) {
                        if (!strcmp(a->name[0], "name")) {
                            testset_name = a->text;
                        }
                    }
                    if (!testset_name) {
                        fprintf(log_f, "anonymous testset is ignored\n");
                        continue;
                    }
                    if (strcmp(testset_name, pkt->testset)) {
                        fprintf(log_f, "testset '%s' is ignored\n", testset_name);
                        continue;
                    }

                    for (struct xml_tree *t3 = t2->first_down; t3; t3 = t3->right) {
                        if (!strcmp(t3->name[0], "time-limit")) {
                            int time_limit = -1;
                            if (xml_parse_int(log_f, pkt->problem_xml_name, t3->line, t3->column, t3->text, &time_limit)) {
                                fprintf(log_f, "failed to parse <time-limit> element '%s'\n", t3->text);
                                goto zip_error;
                            }
                            if (time_limit < 0 || time_limit >= 2000000000) {
                                fprintf(log_f, "invalid value of <time-limit> element %d\n", time_limit);
                                goto zip_error;
                            }
                            pi->time_limit_ms = time_limit;
                        } else if (!strcmp(t3->name[0], "memory-limit")) {
                            ssize_t ml = parse_memory_limit(log_f, t3->text);
                            if (ml < 0) {
                                fprintf(log_f, "invalid value of <memory-limit> element '%s'\n", t3->text);
                                goto zip_error;
                            }
                            pi->memory_limit = ml;
                        } else if (!strcmp(t3->name[0], "test-count")) {
                            int test_count = -1;
                            if (xml_parse_int(log_f, pkt->problem_xml_name, t3->line, t3->column, t3->text, &test_count)) {
                                fprintf(log_f, "failed to parse <test-count> element '%s'\n", t3->text);
                                goto zip_error;
                            }
                            if (test_count <= 0 || test_count >= 2000000000) {
                                fprintf(log_f, "invalid value of <test-count> element %d\n", test_count);
                                goto zip_error;
                            }
                            pi->test_count = test_count;
                        } else if (!strcmp(t3->name[0], "input-path-pattern")) {
                            pi->input_path_pattern = xstrdup(t3->text);
                        } else if (!strcmp(t3->name[0], "answer-path-pattern")) {
                            pi->answer_path_pattern = xstrdup(t3->text);
                        }
                    }
                }
            }
        } else if (!strcmp(t1->name[0], "files")) {
        } else if (!strcmp(t1->name[0], "assets")) {
        } else if (!strcmp(t1->name[0], "statements")) {
            for (struct xml_tree *t2 = t1->first_down; t2; t2 = t2->right) {
                if (!strcmp(t2->name[0], "statement")) {
                    const unsigned char *cur_charset = NULL;
                    const unsigned char *cur_language = NULL;
                    int cur_mathjax = 0;
                    const unsigned char *cur_path = NULL;
                    const unsigned char *cur_type = NULL;
                    for (a = t2->first; a; a = a->next) {
                        if (!strcmp(a->name[0], "charset")) {
                            cur_charset = a->text;
                        } else if (!strcmp(a->name[0], "language")) {
                            cur_language = a->text;
                        } else if (!strcmp(a->name[0], "mathjax")) {
                            xml_attr_bool(a, &cur_mathjax);
                        } else if (!strcmp(a->name[0], "path")) {
                            cur_path = a->text;
                        } else if (!strcmp(a->name[0], "type")) {
                            cur_type = a->text;
                        }
                    }
                    if (!strcasecmp(cur_type, "text/html")
                        && !strcasecmp(cur_language, "russian")
                        && !strcasecmp(cur_charset, "utf-8")) {
                        pi->html_statement_path = xstrdup(cur_path);
                    }
                }
            }
        }
    }

    if (pi->test_count <= 0) {
        fprintf(log_f, "test-count value is not specified\n");
        goto zip_error;
    }
    if (!pi->input_path_pattern) {
        fprintf(log_f, "input-path-pattern is not specified\n");
        goto zip_error;
    }
    if (!pi->answer_path_pattern) {
        fprintf(log_f, "output-path-pattern is not specified\n");
        goto zip_error;
    }
    if (check_format(pi->input_path_pattern)) {
        fprintf(log_f, "input-path-pattern value '%s' is invalid\n", pi->input_path_pattern);
        goto zip_error;
    }
    if (check_format(pi->answer_path_pattern)) {
        fprintf(log_f, "answer-path-pattern value '%s' is invalid\n", pi->answer_path_pattern);
        goto zip_error;
    }

    const unsigned char *s;
    if (!(s = strrchr(pi->input_path_pattern, '/'))) {
        s = pi->input_path_pattern;
    } else {
        ++s;
    }
    pi->test_pat = xstrdup(s);
    if (!(s = strrchr(pi->answer_path_pattern, '/'))) {
        s = pi->answer_path_pattern;
    } else {
        ++s;
    }
    pi->corr_pat = xstrdup(s);

    fprintf(log_f, "problem %d (%s):\n", pi->problem_id, pi->problem_name);
    fprintf(log_f, "    long_name_en: %s\n", pi->long_name_en);
    fprintf(log_f, "    long_name_ru: %s\n", pi->long_name_ru);
    fprintf(log_f, "    input_file: %s\n", pi->input_file);
    fprintf(log_f, "    output_file: %s\n", pi->output_file);
    fprintf(log_f, "    time_limit_ms: %d\n", pi->time_limit_ms);
    fprintf(log_f, "    test_count: %d\n", pi->test_count);
    fprintf(log_f, "    input_pattern: %s\n", pi->input_path_pattern);
    fprintf(log_f, "    answer_pattern: %s\n", pi->answer_path_pattern);
    fprintf(log_f, "    memory_limit: %lld\n", (long long) pi->memory_limit);
    fprintf(log_f, "    test_pat: %s\n", pi->test_pat);
    fprintf(log_f, "    corr_pat: %s\n", pi->corr_pat);

    unsigned char problem_path[PATH_MAX];
    snprintf(problem_path, sizeof(problem_path), "%s/%s", pkt->problem_dir, pi->problem_name);
    if (pkt->create_mode > 0) {
        struct stat stb;
        if (stat(problem_path, &stb) > 0) {
            fprintf(log_f, "file or directory '%s' aready exists\n", problem_path);
            pi->state = STATE_ALREADY_EXISTS;
            goto cleanup;
        }
    }
    if (os_MakeDirPath2(problem_path, pkt->dir_mode, pkt->dir_group) < 0) {
        fprintf(log_f, "failed to create directory '%s'\n", problem_path);
        goto zip_error;
    }
    unsigned char tests_path[PATH_MAX];
    snprintf(tests_path, sizeof(tests_path), "%s/tests", problem_path);
    if (os_MakeDirPath2(tests_path, pkt->dir_mode, pkt->dir_group) < 0) {
        fprintf(log_f, "failed to create directory '%s'\n", tests_path);
        goto zip_error;
    }
    unsigned char solutions_path[PATH_MAX];
    if (pkt->ignore_solutions) {
        snprintf(solutions_path, sizeof(solutions_path), "%s/solutions1", problem_path);
    } else {
        snprintf(solutions_path, sizeof(solutions_path), "%s/solutions", problem_path);
    }
    if (os_MakeDirPath2(solutions_path, pkt->dir_mode, pkt->dir_group) < 0) {
        fprintf(log_f, "failed to create directory '%s'\n", solutions_path);
        goto zip_error;
    }

    for (int num = 1; num <= pi->test_count; ++num) {
        unsigned char path1[PATH_MAX];
        snprintf(path1, sizeof(path1), pi->input_path_pattern, num);
        unsigned char path2[PATH_MAX];
        snprintf(path2, sizeof(path2), pi->test_pat, num);
        unsigned char path3[PATH_MAX];
        snprintf(path3, sizeof(path3), "%s/%s", tests_path, path2);
        if (copy_from_zip(log_f, pkt, zif, zid, zip_path, path1, path3)) goto zip_error;

        snprintf(path1, sizeof(path1), pi->answer_path_pattern, num);
        snprintf(path2, sizeof(path2), pi->corr_pat, num);
        snprintf(path3, sizeof(path3), "%s/%s", tests_path, path2);
        if (copy_from_zip(log_f, pkt, zif, zid, zip_path, path1, path3)) goto zip_error;
    }

    // remote the remaining files, which match the test file pattern
    int removed_flag = 1;
    for (int num = pi->test_count + 1; removed_flag; ++num) {
        removed_flag = 0;
        unsigned char path2[PATH_MAX];
        snprintf(path2, sizeof(path2), pi->test_pat, num);
        unsigned char path3[PATH_MAX];
        snprintf(path3, sizeof(path3), "%s/%s", tests_path, path2);
        if (access(path3, F_OK) >= 0) {
            unlink(path3);
            removed_flag = 1;
        }
        snprintf(path2, sizeof(path2), pi->corr_pat, num);
        snprintf(path3, sizeof(path3), "%s/%s", tests_path, path2);
        if (access(path3, F_OK) >= 0) {
            unlink(path3);
            removed_flag = 1;
        }
    }

    for (struct xml_tree *t1 = tree->first_down; t1; t1 = t1->right) {
        if (!strcmp(t1->name[0], "files")) {
            for (struct xml_tree *t2 = t1->first_down; t2; t2 = t2->right) {
                if (!strcmp(t2->name[0], "resources")) {
                    for (struct xml_tree *t3 = t2->first_down; t3; t3 = t3->right) {
                        if (!strcmp(t3->name[0], "file")) {
                            const unsigned char *path = NULL;
                            const unsigned char *type = NULL;
                            for (a = t3->first; a; a = a->next) {
                                if (!strcmp(a->name[0], "path")) {
                                    path = a->text;
                                } else if (!strcmp(a->name[0], "type")) {
                                    type = a->text;
                                }
                            }
                            (void) type;
                            if (path) {
                                if (!strcmp(path, "files/problem.tex")) {
                                    // ignore it
                                } else {
                                    // copy to the root dir
                                    if (!(s = strrchr(path, '/'))) {
                                        s = path;
                                    } else {
                                        ++s;
                                    }
                                    unsigned char dst_path[PATH_MAX];
                                    snprintf(dst_path, sizeof(dst_path), "%s/%s", problem_path, s);
                                    if (copy_from_zip(log_f, pkt, zif, zid, zip_path, path, dst_path)) goto zip_error;
                                }
                            }
                        }
                    }
                }
            }
        } else if (!strcmp(t1->name[0], "assets")) {
            for (struct xml_tree *t2 = t1->first_down; t2; t2 = t2->right) {
                if (!strcmp(t2->name[0], "checker")) {
                    const unsigned char *name = NULL;
                    const unsigned char *src_path = NULL;
                    for (a = t2->first; a; a = a->next) {
                        if (!strcmp(a->name[0], "name")) {
                            name = a->text;
                        }
                    }
                    for (struct xml_tree *t3 = t2->first_down; t3; t3 = t3->right) {
                        if (!strcmp(t3->name[0], "source")) {
                            for (a = t3->first; a; a = a->next) {
                                if (!strcmp(a->name[0], "path")) {
                                    src_path = a->text;
                                }
                            }
                        }
                    }
                    if (name && !strcmp(name, "std::hcmp.cpp")) {
                        pi->standard_checker = xstrdup("cmp_huge_int");
                    } else if (name && !strcmp(name, "std::rcmp9.cpp")) {
                        pi->standard_checker = xstrdup("cmp_double_seq");
                        pi->checker_env = xstrdup("EPS=1e-9");
                    } else if (name && !strcmp(name, "std::rcmp4.cpp")) {
                        pi->standard_checker = xstrdup("cmp_double_seq");
                        pi->checker_env = xstrdup("EPS=1e-4");
                    } else if (name && !strcmp(name, "std::rcmp6.cpp")) {
                        pi->standard_checker = xstrdup("cmp_double_seq");
                        pi->checker_env = xstrdup("EPS=1e-6");
                    } else if (name && !strcmp(name, "std::yesno.cpp")) {
                        pi->standard_checker = xstrdup("cmp_yesno");
                        pi->checker_env = xstrdup("CASE_INSENSITIVE=1");
                    } else if (name && !strcmp(name, "std::lcmp.cpp")) {
                        pi->standard_checker = xstrdup("cmp_file_nospace");
                    } else if (name && !strcmp(name, "std::fcmp.cpp")) {
                        pi->standard_checker = xstrdup("cmp_file");
                    } else if (name && !strcmp(name, "std::ncmp.cpp")) {
                        pi->standard_checker = xstrdup("cmp_long_long_seq");
                    } else {
                        // std::wcmp.cpp checker is not supported as a standard checker
                        if (!src_path) {
                            fprintf(log_f, "source path is undefined for the checker\n");
                            goto zip_error;
                        }
                        if (!(s = strrchr(src_path, '/'))) {
                            s = src_path;
                        } else {
                            ++s;
                        }
                        unsigned char dst_path[PATH_MAX];
                        snprintf(dst_path, sizeof(dst_path), "%s/%s", problem_path, s);
                        if (copy_from_zip(log_f, pkt, zif, zid, zip_path, src_path, dst_path)) goto zip_error;
                        pi->check_cmd = xstrdup(s);
                        unsigned char *q;
                        if ((q = strrchr(pi->check_cmd, '.'))) {
                            *q = 0;
                        }
                    }
                } else if (!strcmp(t2->name[0], "interactor")) {

                    const unsigned char *src_path = NULL;
                    for (struct xml_tree *t3 = t2->first_down; t3; t3 = t3->right) {
                        if (!strcmp(t3->name[0], "source")) {
                            for (a = t3->first; a; a = a->next) {
                                if (!strcmp(a->name[0], "path")) {
                                    src_path = a->text;
                                }
                            }
                        }
                    }
                    if (!src_path) {
                        fprintf(log_f, "source path is undefined for the checker\n");
                        goto zip_error;
                    }

                    if (!(s = strrchr(src_path, '/'))) {
                        s = src_path;
                    } else {
                        ++s;
                    }
                    unsigned char dst_path[PATH_MAX];
                    snprintf(dst_path, sizeof(dst_path), "%s/%s", problem_path, s);
                    if (copy_from_zip(log_f, pkt, zif, zid, zip_path, src_path, dst_path)) goto zip_error;
                    pi->interactor_cmd = xstrdup(s);
                    unsigned char *q;
                    if ((q = strrchr(pi->interactor_cmd, '.'))) {
                        *q = 0;
                    }
                } else if (!strcmp(t2->name[0], "validator")) {
                    struct xml_tree *t3 = get_elem_by_name(t2, "source");
                    if (t3) {
                        const unsigned char *src_path = get_attr_by_name(t3, "path");
                        if (src_path) {
                            if (!(s = strrchr(src_path, '/'))) {
                                s = src_path;
                            } else {
                                ++s;
                            }
                            unsigned char dst_path[PATH_MAX];
                            snprintf(dst_path, sizeof(dst_path), "%s/%s", problem_path, s);
                            if (copy_from_zip(log_f, pkt, zif, zid, zip_path, src_path, dst_path)) goto zip_error;
                            pi->test_checker_cmd = xstrdup(s);
                            unsigned char *q;
                            if ((q = strrchr(pi->test_checker_cmd, '.'))) {
                                *q = 0;
                            }
                        }
                    }
                } else if (!strcmp(t2->name[0], "solutions")) {
                    struct xml_tree *t3 = get_elem_by_name(t2, "solution");
                    while (t3) {
                        const unsigned char *sol_tag = get_attr_by_name(t3, "tag");
                        struct xml_tree *t4 = get_elem_by_name(t3, "source");
                        if (t4) {
                            const unsigned char *src_path = get_attr_by_name(t4, "path");
                            if (src_path) {
                                if (!(s = strrchr(src_path, '/'))) {
                                    s = src_path;
                                } else {
                                    ++s;
                                }
                                unsigned char dst_path[PATH_MAX];
                                snprintf(dst_path, sizeof(dst_path), "%s/%s", solutions_path, s);
                                if (copy_from_zip(log_f, pkt, zif, zid, zip_path, src_path, dst_path)) goto zip_error;
                                if (sol_tag && !strcmp(sol_tag, "main")) {
                                    snprintf(dst_path, sizeof(dst_path), "%s/%s", problem_path, s);
                                    if (copy_from_zip(log_f, pkt, zif, zid, zip_path, src_path, dst_path)) goto zip_error;
                                    pi->solution_cmd = xstrdup(s);
                                    unsigned char *q;
                                    if ((q = strrchr(pi->solution_cmd, '.'))) {
                                        *q = 0;
                                    }
                                }
                            }
                        }
                        t3 = get_next_elem_by_name(t3, "solution");
                    }
                }
            }
        }
    }
    if (pi->html_statement_path && pkt->enable_iframe_statement > 0) {
        unsigned char attachments_path[PATH_MAX];
        snprintf(attachments_path, sizeof(attachments_path),
                 "%s/attachments", problem_path);
        if (os_MakeDirPath2(attachments_path, pkt->dir_mode, pkt->dir_group) < 0) {
            fprintf(log_f, "failed to create directory '%s'\n", attachments_path);
            goto zip_error;
        }
        unsigned char statement_path[PATH_MAX];
        snprintf(statement_path, sizeof(statement_path),
                 "%s/statement.html", attachments_path);
        if (copy_from_zip(log_f, pkt, zif, zid, zip_path, pi->html_statement_path, statement_path)) goto zip_error;

        unsigned char html_statement_dir[PATH_MAX];
        unsigned char css_src_path[PATH_MAX];
        unsigned char css_dst_path[PATH_MAX];
        const unsigned char *p = strrchr(pi->html_statement_path, '/');
        if (p) {
            snprintf(html_statement_dir, sizeof(html_statement_dir),
                     "%.*s", (int) (p - pi->html_statement_path),
                     pi->html_statement_path);
            snprintf(css_src_path, sizeof(css_src_path),
                     "%s/problem-statement.css", html_statement_dir);
            snprintf(css_dst_path, sizeof(css_dst_path),
                     "%s/problem-statement.css", attachments_path);
            if (copy_from_zip(log_f, pkt, zif, zid, zip_path, css_src_path, css_dst_path)) goto zip_error;
        }

        unsigned char statement_xml_path[PATH_MAX];
        snprintf(statement_xml_path, sizeof(statement_xml_path),
                 "%s/statement.xml", problem_path);
        FILE *f = fopen(statement_xml_path, "w");
        if (f) {
            fputs("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
                  "<problem><statement language=\"ru_RU\"><description><div id=\"polygon_iframe\"><iframe src=\"${getfile}=statement.html\" title=\"statement\" style=\"border:none;\" width=\"80%\" height=\"700px\" > </iframe></div></description></statement></problem>\n", f);
            fclose(f);
        }
    }

    fprintf(log_f, "    standard_checker: %s\n", pi->standard_checker);
    fprintf(log_f, "    checker_env: %s\n", pi->checker_env);
    fprintf(log_f, "    check_cmd: %s\n", pi->check_cmd);
    fprintf(log_f, "    test_checker_cmd: %s\n", pi->test_checker_cmd);
    if (pkt->ignore_main_solution <= 0) {
        fprintf(log_f, "    solution_cmd: %s\n", pi->solution_cmd);
    }
    fprintf(log_f, "    interactor_cmd: %s\n", pi->interactor_cmd);
    fprintf(log_f, "    html_statement: %s\n", pi->html_statement_path);

    unsigned char buf[1024];

    prob_cfg = problem_config_section_alloc();
    if (pi->ejudge_id > 0) {
        prob_cfg->id = pi->ejudge_id;
    }
    if (pi->ejudge_short_name) {
        prob_cfg->short_name = xstrdup(pi->ejudge_short_name);
    }
    prob_cfg->internal_name = xstrdup(pi->problem_name);
    if (pi->problem_id > 0) {
        snprintf(buf, sizeof(buf), "polygon:%d", pi->problem_id);
        prob_cfg->extid = xstrdup(buf);
    } else if (problem_url && problem_url[0]) {
        snprintf(buf, sizeof(buf), "polygon:%s", problem_url);
        prob_cfg->extid = xstrdup(buf);
    }
    snprintf(buf, sizeof(buf), "%d", pi->package_rev);
    prob_cfg->revision = xstrdup(buf);
    if (pi->time_limit_ms > 0 && pi->time_limit_ms % 1000 == 0) {
        prob_cfg->time_limit = pi->time_limit_ms / 1000;
    } else if (pi->time_limit_ms > 0) {
        prob_cfg->time_limit_millis = pi->time_limit_ms;
    }
    if (pi->long_name_ru && pi->long_name_en) {
        if (pkt->language_priority
            && !strcasecmp(pkt->language_priority, "en,ru")) {
            prob_cfg->long_name = xstrdup(pi->long_name_en);
        } else {
            prob_cfg->long_name = xstrdup(pi->long_name_ru);
            prob_cfg->long_name_en = xstrdup(pi->long_name_en);
        }
    } else if (pi->long_name_ru) {
        prob_cfg->long_name = xstrdup(pi->long_name_ru);
    } else if (pi->long_name_en) {
        prob_cfg->long_name = xstrdup(pi->long_name_en);
    }
    if (!pi->input_file) {
        prob_cfg->use_stdin = 1;
    } else {
        prob_cfg->use_stdin = 0;
        prob_cfg->input_file = xstrdup(pi->input_file);
    }
    if (!pi->output_file) {
        prob_cfg->use_stdout = 1;
    } else {
        prob_cfg->use_stdout = 0;
        prob_cfg->output_file = xstrdup(pi->output_file);
    }
    if (pi->memory_limit > 0) {
        prob_cfg->max_vm_size = pi->memory_limit;
        if (pkt->enable_max_stack_size > 0) {
            prob_cfg->max_stack_size = pi->memory_limit;
        }
    }
    if (pi->test_pat) {
        prob_cfg->test_pat = xstrdup(pi->test_pat);
    }
    if (pi->corr_pat) {
        prob_cfg->use_corr = 1;
        prob_cfg->corr_pat = xstrdup(pi->corr_pat);
    }
    if (pi->standard_checker) {
        prob_cfg->standard_checker = xstrdup(pi->standard_checker);
    }
    if (pi->check_cmd) {
        prob_cfg->check_cmd = xstrdup(pi->check_cmd);
    }
    if (pi->checker_env) {
        XCALLOC(prob_cfg->checker_env, 2);
        prob_cfg->checker_env[0] = xstrdup(pi->checker_env);
    }
    if (pi->test_checker_cmd) {
        prob_cfg->test_checker_cmd = xstrdup(pi->test_checker_cmd);
    }
    if (pi->interactor_cmd) {
        prob_cfg->interactor_cmd = xstrdup(pi->interactor_cmd);
    }
    if (pi->solution_cmd && pkt->ignore_main_solution <= 0) {
        prob_cfg->solution_cmd = xstrdup(pi->solution_cmd);
    }
    prob_cfg->enable_testlib_mode = 1;
    if (pkt->binary_input > 0) {
        prob_cfg->binary_input = 1;
    }
    if (pi->html_statement_path && pi->html_statement_path[0] && pkt->enable_iframe_statement > 0) {
        prob_cfg->iframe_statement = xstrdup("statement.html");
        prob_cfg->enable_iframe_statement = 1;
        prob_cfg->xml_file = xstrdup("statement.xml");
    }

    cfg_file = open_memstream(&cfg_text, &cfg_size);
    problem_config_section_unparse_cfg(cfg_file, prob_cfg);
    fclose(cfg_file); cfg_file = NULL;
    unsigned char cfg_path[PATH_MAX];
    snprintf(cfg_path, sizeof(cfg_path), "%s/problem.cfg", problem_path);
    if (save_file(log_f, cfg_path, cfg_text, cfg_size, pkt->file_mode, pkt->file_group, NULL)) goto zip_error;
    pi->state = STATE_UPDATED;

    if (pkt->verbose) {
        fprintf(log_f, "config file: \n");
        fprintf(log_f, "%s\n", cfg_text);
    }

cleanup:
    zid = zif->close(zid);
    xfree(data);
    if (cfg_file) fclose(cfg_file);
    xfree(cfg_text);
    xml_tree_free(tree, &generic_xml_parse_spec);
    problem_config_section_free((struct generic_section_config *) prob_cfg);
    free(problem_url);
    return;

zip_error:
    pi->state = STATE_FAILED;
    unlink(zip_path);
    goto cleanup;
}

static int
has_uncommitted_changes(const unsigned char *text)
{
    const unsigned char *cur = text;
    int pos = 0;
    struct HtmlElement *elem = NULL;
    int result = 0;

    while ((cur = strstr(text + pos, "<a"))) {
        pos = (int)(cur - text);
        elem = html_element_parse_start(text, pos, &pos);
        if (elem) {
            struct HtmlAttribute *attr = html_element_find_attribute(elem, "href");
            if (attr && attr->value && !strncmp(attr->value, "/changes/", 9)) {
                result = 1;
            }
        }
        elem = html_element_free(elem);
    }
    return result;
}

static int
check_problem_status(
        FILE *log_f,
        const struct polygon_packet *pkt,
        const struct DownloadInterface *dif,
        struct DownloadData *ddata,
        struct PolygonState *ps,
        const struct ZipInterface *zif,
        struct ProblemInfo *pi)
{
    unsigned char zip_path[PATH_MAX];
    struct stat stb;
    struct RevisionInfo rinfo;
    const unsigned char *availability_comment = "latest ";

    memset(&rinfo, 0, sizeof(rinfo));
    if (pi->state != STATE_INFO_LOADED) goto cleanup;

    if (pi->latest_rev == pi->package_rev) {
        snprintf(zip_path, sizeof(zip_path), "%s/%s-%d%s.zip", pkt->download_dir,
                 pi->problem_name, pi->package_rev, pkt->arch);
        if (stat(zip_path, &stb) >= 0) {
            if (!S_ISREG(stb.st_mode)) {
                fprintf(log_f, "file %s is not a regular file\n", zip_path);
                pi->state = STATE_FAILED;
                goto cleanup;
            }
            if (access(zip_path, R_OK) < 0) {
                fprintf(log_f, "file %s is not readable\n", zip_path);
                pi->state = STATE_FAILED;
                goto cleanup;
            }
            if (pkt->create_mode > 0) {
                pi->state = STATE_ALREADY_EXISTS;
                goto cleanup;
            }
            pi->state = STATE_ACTUAL;
            goto cleanup;
            //goto file_downloaded;
        }
    }

    if (dif->problem_info_page(ddata, ps, pi)) {
        fprintf(log_f, "failed to access problemInfo page\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (!pi->edit_session) {
        fprintf(log_f, "failed to extract edit session from problemInfo URL\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (dif->package_page(ddata, ps, pi->edit_session)) {
        fprintf(log_f, "failed to access packages page\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (has_uncommitted_changes(dif->get_page_text(ddata))) {
        fprintf(log_f, "problem has uncommitted changes\n");
        pi->state = STATE_UNCOMMITTED;
        goto cleanup;
    }
    int r = find_revision(log_f, dif->get_page_text(ddata), pi->latest_rev, &rinfo);
    if (r < 0) {
        fprintf(log_f, "packages page parse error\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (!r) {
        if (pkt->fetch_latest_available > 0) {
            int current_rev = pi->latest_rev;
            while (1) {
                if((r = find_revision(log_f, dif->get_page_text(ddata), current_rev, &rinfo)) < 0) {
                    fprintf(log_f, "packages page parse error\n");
                    pi->state = STATE_FAILED;
                    goto cleanup;
                }
                if (r > 0) {
                    pi->latest_rev = current_rev;
                    availability_comment = "latest AVAILABLE ";
                    break;
                }
                --current_rev;
                if (current_rev <= 0) {
                    fprintf(log_f, "no available revision found\n");
                    pi->state = STATE_FAILED;
                    goto cleanup;
                }
            }
        } else {
            if (dif->create_full_package(ddata, ps, pi->edit_session)) {
                fprintf(log_f, "failed to start full package creation\n");
                pi->state = STATE_FAILED;
                goto cleanup;
            }
            pi->state = STATE_RUNNING;
            goto cleanup;
        }
    }

    fprintf(log_f, "problem %d (%s) %srevision info:\n", pi->problem_id, pi->problem_name,
            availability_comment);
    fprintf(log_f, "    package_id:    %d\n"
            "    revision:      %d\n"
            "    creation time: %ld\n"
            "    state:         %s\n"
            "    comment:       %s\n"
            "    standard_url:  %s\n"
            "    windows_url:   %s\n"
            "    linux_url:     %s\n",
            rinfo.package_id, rinfo.revision, (long) rinfo.creation_time, rinfo.state, rinfo.comment,
            rinfo.standard_url, rinfo.windows_url, rinfo.linux_url);

    if (!rinfo.state) {
        fprintf(log_f, "failed to parse package state\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (!strcasecmp(rinfo.state, "RUNNING")) {
        pi->state = STATE_RUNNING;
        goto cleanup;
    }
    if (!strcasecmp(rinfo.state, "FAILED")) {
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (strcasecmp(rinfo.state, "READY")) {
        if (pkt->fetch_latest_available > 0 && pi->latest_rev > 0) {
            --pi->latest_rev;
            return check_problem_status(log_f, pkt, dif, ddata, ps, zif, pi);
        }
        fprintf(log_f, "unknown state '%s', restarting package creation\n", rinfo.state);
        if (dif->create_full_package(ddata, ps, pi->edit_session)) {
            fprintf(log_f, "failed to start full package creation\n");
            pi->state = STATE_FAILED;
            goto cleanup;
        }
        pi->state = STATE_RUNNING;
        goto cleanup;
    }
    if (!rinfo.linux_url) {
        if (pkt->fetch_latest_available > 0 && pi->latest_rev > 0) {
            --pi->latest_rev;
            return check_problem_status(log_f, pkt, dif, ddata, ps, zif, pi);
        }
        fprintf(log_f, "Linux download link is missing, restarting package creation\n");
        if (dif->create_full_package(ddata, ps, pi->edit_session)) {
            fprintf(log_f, "failed to start full package creation\n");
            pi->state = STATE_FAILED;
            goto cleanup;
        }
        pi->state = STATE_RUNNING;
        goto cleanup;
    }

    if (dif->download_zip(ddata, ps, rinfo.linux_url, pi->edit_session)) {
        fprintf(log_f, "download failed\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }

    fprintf(log_f, "Archive size: %ld\n", (long) dif->get_page_size(ddata));

    snprintf(zip_path, sizeof(zip_path), "%s/%s-%d%s.zip", pkt->download_dir,
             pi->problem_name, pi->package_rev, pkt->arch);

    if (save_file(log_f, zip_path, dif->get_page_text(ddata), dif->get_page_size(ddata),
                  pkt->file_mode, pkt->file_group, NULL)) {
        pi->state = STATE_FAILED;
        goto cleanup;
    }

    //file_downloaded:

    pi->state = STATE_DOWNLOADED;
    process_polygon_zip(log_f, pkt, zif, zip_path, pi, 0);

cleanup:
    free_revision_info(&rinfo);
    return pi->state == STATE_RUNNING;
}

static int
check_problem_statuses(
        FILE *log_f,
        const struct polygon_packet *pkt,
        const struct DownloadInterface *dif,
        struct DownloadData *ddata,
        struct PolygonState *ps,
        const struct ZipInterface *zif,
        struct ProblemSet *probset)
{
    int running_count = 0;
    for (int num = 0; num < probset->count; ++num) {
        running_count += check_problem_status(log_f, pkt, dif, ddata, ps, zif, &probset->infos[num]);
    }
    return running_count;
}

static int
process_contest_json(
        FILE *log_f,
        struct PolygonState *ps,
        struct DownloadData *ddata,
        struct ProblemSet *probset)
{
    int retval = 0;
    cJSON *root = NULL;
    const unsigned char *text = ddata->iface->get_page_text(ddata);
    size_t size = ddata->iface->get_page_size(ddata);

    fprintf(log_f, "=== %zu ===\n%s\n===\n", size, text);

    root = cJSON_Parse(text);
    if (!root) {
        fprintf(log_f, "JSON parse failed\n");
        retval = 1;
        goto done;
    }
    if (root->type != cJSON_Object) {
        fprintf(log_f, "invalid contests json, root document expected\n");
        retval = 1;
        goto done;
    }
    cJSON *jstatus = cJSON_GetObjectItem(root, "status");
    if (!jstatus || jstatus->type != cJSON_String || strcmp(jstatus->valuestring, "OK")) {
        fprintf(log_f, "invalid json: invalid or missing 'status'\n");
        retval = 1;
        goto done;
    }
    cJSON *jresult = cJSON_GetObjectItem(root, "result");
    if (!jresult || jresult->type != cJSON_Object) {
        fprintf(log_f, "invalid json: invalid or missing 'result'\n");
        retval = 1;
        goto done;
    }

    int count = 0;
    for (cJSON *jitem = jresult->child; jitem; jitem = jitem->next, ++count) {
        if (jitem->type != cJSON_Object) {
            fprintf(log_f, "invalid json: object expected for problem\n");
            retval = 1;
            goto done;
        }
    }

    if (count <= 0) goto done;

    probset->count = count;
    XCALLOC(probset->infos, probset->count);

    int pos = 0;
    for (cJSON *jitem = jresult->child; jitem; jitem = jitem->next, ++pos) {
        cJSON *jid = cJSON_GetObjectItem(jitem, "id");
        if (!jid || jid->type != cJSON_Number || jid->valueint <= 0) {
            fprintf(log_f, "invalid json: integer id expected for problem\n");
            retval = 1;
            goto done;
        }
        probset->infos[pos].key_id = jid->valueint;
    }

done:
    if (root) cJSON_Delete(root);
    return retval;
}

static int
process_problems_json(
        FILE *log_f,
        const struct polygon_packet *pkt,
        struct PolygonState *ps,
        struct DownloadData *ddata,
        struct ProblemSet *probset)
{
    int retval = 0;
    cJSON *root = NULL;
    const unsigned char *text = ddata->iface->get_page_text(ddata);

    root = cJSON_Parse(text);
    if (!root) {
        fprintf(log_f, "JSON parse failed\n");
        retval = 1;
        goto done;
    }
    if (root->type != cJSON_Object) {
        fprintf(log_f, "invalid contests json, root document expected\n");
        retval = 1;
        goto done;
    }

    if (pkt->verbose) {
        char *s = cJSON_Print(root);
        fprintf(log_f, "=== problems.json ===\n%s\n===\n", s);
        free(s);
    }

    cJSON *jstatus = cJSON_GetObjectItem(root, "status");
    if (!jstatus || jstatus->type != cJSON_String || strcmp(jstatus->valuestring, "OK")) {
        fprintf(log_f, "invalid json: invalid or missing 'status'\n");
        retval = 1;
        goto done;
    }
    cJSON *jresult = cJSON_GetObjectItem(root, "result");
    if (!jresult || jresult->type != cJSON_Array) {
        fprintf(log_f, "invalid json: invalid or missing 'result'\n");
        retval = 1;
        goto done;
    }
    for (cJSON *jitem = jresult->child; jitem; jitem = jitem->next) {
        if (jitem->type != cJSON_Object) {
            fprintf(log_f, "invalid json: object expected for problem\n");
            retval = 1;
            goto done;
        }
        cJSON *jid = cJSON_GetObjectItem(jitem, "id");
        if (!jid || jid->type != cJSON_Number || jid->valueint <= 0) {
            fprintf(log_f, "invalid json: integer id expected for problem\n");
            retval = 1;
            goto done;
        }
        cJSON *jname = cJSON_GetObjectItem(jitem, "name");
        if (!jname || jname->type != cJSON_String) {
            fprintf(log_f, "invalid json: string name expected for problem\n");
            retval = 1;
            goto done;
        }
        struct ProblemInfo *pi = NULL;
        for (int i = 0; i < probset->count; ++i) {
            if (probset->infos[i].key_id > 0 && probset->infos[i].key_id == jid->valueint) {
                pi = &probset->infos[i];
                break;
            }
            if (probset->infos[i].key_name && jname && !strcmp(probset->infos[i].key_name, jname->valuestring)) {
                pi = &probset->infos[i];
                break;
            }
        }
        if (!pi) continue;

        cJSON *jaccessType = cJSON_GetObjectItem(jitem, "accessType");
        if (!jaccessType || jaccessType->type != cJSON_String) {
            fprintf(log_f, "invalid json: accessType must be string\n");
            retval = 1;
            goto done;
        }
        if (strcasecmp(jaccessType->valuestring, "WRITE") != 0
	    && strcasecmp(jaccessType->valuestring, "OWNER") != 0) {
            if (pi->key_id > 0) {
                fprintf(log_f, "WRITE access is required for problem %d\n",
                        pi->key_id);
            } else if (pi->key_name) {
                fprintf(log_f, "WRITE access is required for problem '%s'\n",
                        pi->key_name);
            }
            pi->state = STATE_PERMISSION_DENIED;
            continue;
        }

        pi->problem_id = jid->valueint;
        pi->problem_name = xstrdup(jname->valuestring);

        cJSON *jrevision = cJSON_GetObjectItem(jitem, "revision");
        if (jrevision) {
            if (jrevision->type != cJSON_Number) {
                fprintf(log_f, "invalid json: integer id expected for revision\n");
                retval = 1;
                goto done;
            }
            pi->latest_rev = jrevision->valueint;
        }

        cJSON *jlatest_package = cJSON_GetObjectItem(jitem, "latestPackage");
        if (jlatest_package) {
            if (jlatest_package->type != cJSON_Number) {
                fprintf(log_f, "invalid json: integer id expected for latestPackage\n");
                retval = 1;
                goto done;
            }
            pi->package_rev = jlatest_package->valueint;
        }
        pi->state = STATE_INFO_LOADED;
    }

    for (int i = 0; i < probset->count; ++i) {
        struct ProblemInfo *pi = &probset->infos[i];
        if (!pi->state) {
            pi->state = STATE_NOT_FOUND;
            if (pi->key_id > 0) {
                fprintf(log_f, "problem with id == %d not found\n", pi->key_id);
            } else if (pi->key_name) {
                fprintf(log_f, "problem with name == '%s' not found\n", pi->key_name);
            } else {
                fprintf(log_f, "problem not found\n");
            }
        }
    }

done:
    if (root) cJSON_Delete(root);
    return retval;
}

static int
process_problem_info_json(
        FILE *log_f,
        const struct polygon_packet *pkt,
        struct PolygonState *ps,
        struct DownloadData *ddata,
        struct ProblemInfo *pi)
{
    int retval = 1;
    cJSON *root = NULL;
    const unsigned char *text = ddata->iface->get_page_text(ddata);

    root = cJSON_Parse(text);
    if (!root) {
        fprintf(log_f, "JSON parse failed\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    if (root->type != cJSON_Object) {
        fprintf(log_f, "invalid contests json, root document expected\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }

    if (pkt->verbose) {
        char *s = cJSON_Print(root);
        fprintf(log_f, "=== problem_info.json ===\n%s\n===\n", s);
        free(s);
    }

    retval = 0;

done:;
    if (root) cJSON_Delete(root);
    return retval;
}

static int
process_problem_packages_json(
        FILE *log_f,
        const struct polygon_packet *pkt,
        struct PolygonState *ps,
        struct DownloadData *ddata,
        struct ProblemInfo *pi,
        int revision,
        struct RevisionInfo *rinfo)
{
    int retval = 0;
    cJSON *root = NULL;
    const unsigned char *text = ddata->iface->get_page_text(ddata);

    root = cJSON_Parse(text);
    if (!root) {
        fprintf(log_f, "JSON parse failed\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    if (root->type != cJSON_Object) {
        fprintf(log_f, "invalid contests json, root document expected\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    if (pkt->verbose) {
        char *s = cJSON_Print(root);
        fprintf(log_f, "=== problem_packages.json ===\n%s\n===\n", s);
        free(s);
    }

    cJSON *jstatus = cJSON_GetObjectItem(root, "status");
    if (!jstatus || jstatus->type != cJSON_String || strcmp(jstatus->valuestring, "OK")) {
        fprintf(log_f, "invalid json: invalid or missing 'status'\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    cJSON *jresult = cJSON_GetObjectItem(root, "result");
    if (!jresult || jresult->type != cJSON_Array) {
        fprintf(log_f, "invalid json: invalid or missing 'result'\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }

    cJSON *found_jitem = NULL;
    for (cJSON *jitem = jresult->child; jitem; jitem = jitem->next) {
        if (jitem->type != cJSON_Object) {
            fprintf(log_f, "invalid json: object expected for revision\n");
            retval = 1;
            pi->state = STATE_FAILED;
            goto done;
        }
        cJSON *jrevision = cJSON_GetObjectItem(jitem, "revision");
        if (!jrevision || jrevision->type != cJSON_Number) {
            fprintf(log_f, "invalid json: revision must be number\n");
            retval = 1;
            pi->state = STATE_FAILED;
            goto done;
        }
        if (jrevision->valueint == revision) {
            found_jitem = jitem;
            break;
        }
    }
    if (!found_jitem) {
        fprintf(log_f, "revision %d not found\n", revision);
        retval = 1;
        pi->state = STATE_NOT_AVAILABLE;
        goto done;
    }

    rinfo->revision = revision;

    cJSON *jid = cJSON_GetObjectItem(found_jitem, "id");
    if (!jid || jid->type != cJSON_Number) {
        fprintf(log_f, "invalid json: number expected for package id\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    rinfo->package_id = jid->valueint;

    cJSON *jcreation_time = cJSON_GetObjectItem(found_jitem, "creationTimeSeconds");
    if (!jcreation_time || jcreation_time->type != cJSON_Number) {
        fprintf(log_f, "invalid json: number expected for creationTimeSeconds\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    rinfo->creation_time = (time_t) jcreation_time->valuedouble;

    cJSON *jstate = cJSON_GetObjectItem(found_jitem, "state");
    if (!jstate || jstate->type != cJSON_String) {
        fprintf(log_f, "invalid json: string expected for state\n");
        retval = 1;
        pi->state = STATE_FAILED;
        goto done;
    }
    if (strcmp(jstate->valuestring, "READY")) {
        fprintf(log_f, "package in state: %s, not READY\n", jstate->valuestring);
        retval = 1;
        pi->state = STATE_NOT_AVAILABLE;
        goto done;
    }
    rinfo->state = xstrdup(jstate->valuestring);

    cJSON *jcomment = cJSON_GetObjectItem(found_jitem, "comment");
    if (jcomment) {
        if (jcomment->type != cJSON_String) {
            fprintf(log_f, "invalid json: string expected for comment\n");
            retval = 1;
            pi->state = STATE_FAILED;
            goto done;
        }
        rinfo->comment = xstrdup(jcomment->valuestring);
    }

done:
    if (root) cJSON_Delete(root);
    return retval;
}

static int
check_problem_status_api(
        FILE *log_f,
        const struct polygon_packet *pkt,
        struct RandomSource *rand,
        const struct DownloadInterface *dif,
        struct DownloadData *ddata,
        struct PolygonState *ps,
        const struct ZipInterface *zif,
        struct ProblemInfo *pi)
{
    unsigned char zip_path[PATH_MAX];
    struct RevisionInfo rinfo;
    memset(&rinfo, 0, sizeof(rinfo));

    if (pi->state != STATE_INFO_LOADED) goto cleanup;

    // in the API mode automatic regeneration of the latest package is not supported
    if (pi->package_rev <= 0) {
        pi->state = STATE_NOT_AVAILABLE;
        goto cleanup;
    }

    int package_rev = pi->package_rev;
    if (package_rev > 0) {
        struct stat stb;
        if (snprintf(zip_path, sizeof(zip_path), "%s/%s-%d%s.zip", pkt->download_dir,
                     pi->problem_name, package_rev, pkt->arch) >= sizeof(zip_path)) {
            fprintf(log_f, "path '%s' is too long\n", zip_path);
            pi->state = STATE_FAILED;
            goto cleanup;
        }
        if (stat(zip_path, &stb) >= 0) {
            if (!S_ISREG(stb.st_mode)) {
                fprintf(log_f, "file %s is not a regular file\n", zip_path);
                pi->state = STATE_FAILED;
                goto cleanup;
            }
            if (access(zip_path, R_OK) < 0) {
                fprintf(log_f, "file %s is not readable\n", zip_path);
                pi->state = STATE_FAILED;
                goto cleanup;
            }
            if (pkt->create_mode > 0) {
                pi->state = STATE_ALREADY_EXISTS;
                goto cleanup;
            }
            pi->state = STATE_ACTUAL;
            goto cleanup;
        }
    }

    if (dif->problem_info_api(ddata, ps, rand, pkt->key, pkt->secret, pi->problem_id)) {
        fprintf(log_f, "failed to access problem.info API\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (process_problem_info_json(log_f, pkt, ps, ddata, pi)) {
        pi->state = STATE_FAILED;
        goto cleanup;
    }

    if (dif->problem_packages_api(ddata, ps, rand, pkt->key, pkt->secret, pi->problem_id)) {
        fprintf(log_f, "failed to access problem.packages API\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }
    if (process_problem_packages_json(log_f, pkt, ps, ddata, pi, package_rev, &rinfo)) {
        goto cleanup;
    }

    fprintf(log_f, "problem %d (%s) revision info:\n", pi->problem_id, pi->problem_name);
    fprintf(log_f, "    package_id:    %d\n"
            "    revision:      %d\n"
            "    creation time: %lld\n"
            "    state:         %s\n"
            "    comment:       %s\n",
            rinfo.package_id, rinfo.revision, (long long) rinfo.creation_time, rinfo.state, rinfo.comment);

    if (dif->problem_package_api(ddata, ps, rand, pkt->key, pkt->secret, pi->problem_id, rinfo.package_id, pkt->arch)) {
        fprintf(log_f, "failed to access problem.package API\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }

    const unsigned char *zip_data = dif->get_page_text(ddata);
    size_t zip_size = dif->get_page_size(ddata);

    if (zip_size <= 2 || zip_data[0] != 'P' || zip_data[1] != 'K') {
        fprintf(log_f, "not a ZIP file\n");
        pi->state = STATE_FAILED;
        goto cleanup;
    }

    fprintf(log_f, "Archive size: %lld\n", (long long) zip_size);

    snprintf(zip_path, sizeof(zip_path), "%s/%s-%d%s.zip", pkt->download_dir, pi->problem_name, package_rev, pkt->arch);

    if (save_file(log_f, zip_path, zip_data, zip_size, pkt->file_mode, pkt->file_group, NULL)) {
        pi->state = STATE_FAILED;
        goto cleanup;
    }

    //file_downloaded:

    pi->state = STATE_DOWNLOADED;
    process_polygon_zip(log_f, pkt, zif, zip_path, pi, 0);

cleanup:
    free_revision_info(&rinfo);
    return pi->state == STATE_RUNNING;
}

static int
check_problem_statuses_api(
        FILE *log_f,
        const struct polygon_packet *pkt,
        struct RandomSource *rand,
        const struct DownloadInterface *dif,
        struct DownloadData *ddata,
        struct PolygonState *ps,
        const struct ZipInterface *zif,
        struct ProblemSet *probset)
{
    int running_count = 0;
    for (int num = 0; num < probset->count; ++num) {
        running_count += check_problem_status_api(log_f, pkt, rand, dif, ddata, ps, zif, &probset->infos[num]);
    }
    return running_count;
}

static int
do_work_api(
        FILE *log_f,
        struct polygon_packet *pkt,
        struct RandomSource *rand,
        struct ProblemSet *probset)
{
    const struct DownloadInterface *dif = NULL;
    struct DownloadData *ddata = NULL;
    const struct ZipInterface *zif = NULL;
    struct PolygonState *ps = NULL;
    int retval = 0;

    if ((retval = check_directories(log_f, pkt))) goto done;

#if CONF_HAS_LIBCURL - 0 == 0
    fprintf(log_f, "libcurl library was missing during the complation, functionality is not available\n");
    retval = 1;
    goto done;
#else
    dif = get_curl_download_interface(log_f, pkt);
#endif
    if (!dif) {
        fprintf(log_f, "download interface is not available\n");
        retval = 1;
        goto done;
    }
    if (!(ddata = dif->create(log_f, dif, pkt))) {
        fprintf(log_f, "failed to initialize download interface\n");
        retval = 1;
        goto done;
    }

#if CONF_HAS_LIBZIP - 0 == 0
    fprintf(log_f, "libzip library was missing during the complation, functionality is not available\n");
    retval = 1;
    goto done;
#else
    zif = get_zip_interface(log_f, pkt);
#endif
    if (!zif) {
        fprintf(log_f, "zip interface is not available\n");
        retval = 1;
        goto done;
    }

    if (!(ps = polygon_state_create())) {
        fprintf(log_f, "failed to create PolygonState object\n");
        retval = 1;
        goto done;
    }

    if (pkt->polygon_contest_id && *pkt->polygon_contest_id) {
        if (dif->contest_api(ddata, ps, rand, pkt->key, pkt->secret, pkt->polygon_contest_id)) {
            retval = 1;
            goto done;
        }
        if (process_contest_json(log_f, ps, ddata, probset)) {
            retval = 1;
            goto done;
        }
    }

    if (probset->count <= 0) {
        fprintf(log_f, "no problems to update\n");
        goto done;
    }

    if (dif->problems_api(ddata, ps, rand, pkt->key, pkt->secret)) {
        retval = 1;
        goto done;
    }
    if (process_problems_json(log_f, pkt, ps, ddata, probset)) {
        retval = 1;
        goto done;
    }

    check_problem_statuses_api(log_f, pkt, rand, dif, ddata, ps, zif, probset);

done:
    ps = polygon_state_free(ps);
    if (ddata) {
        if (dif) ddata = dif->cleanup(ddata);
    }
    return retval;
}

static int
do_work(
        FILE *log_f,
        struct polygon_packet *pkt,
        struct ProblemSet *probset)
{
    const struct DownloadInterface *dif = NULL;
    const struct ZipInterface *zif = NULL;
    struct DownloadData *ddata = NULL;
    int retval = 0;
    struct PolygonState *ps = NULL;
    int retry_count = 0;

    if ((retval = check_directories(log_f, pkt))) goto done;

#if CONF_HAS_LIBCURL - 0 == 0
    fprintf(log_f, "libcurl library was missing during the complation, functionality is not available\n");
    retval = 1;
    goto done;
#else
    dif = get_curl_download_interface(log_f, pkt);
#endif
    if (!dif) {
        fprintf(log_f, "download interface is not available\n");
        retval = 1;
        goto done;
    }
    if (!(ddata = dif->create(log_f, dif, pkt))) {
        fprintf(log_f, "failed to initialize download interface\n");
        retval = 1;
        goto done;
    }

#if CONF_HAS_LIBZIP - 0 == 0
    fprintf(log_f, "libzip library was missing during the complation, functionality is not available\n");
    retval = 1;
    goto done;
#else
    zif = get_zip_interface(log_f, pkt);
#endif
    if (!zif) {
        fprintf(log_f, "zip interface is not available\n");
        retval = 1;
        goto done;
    }

    if (!(ps = polygon_state_create())) {
        fprintf(log_f, "failed to create PolygonState object\n");
        retval = 1;
        goto done;
    }

    if ((retval = dif->login_page(ddata)))
        goto done;

    if (!ends_with(ddata->clean_url, "/login")) {
        // fix polygon url
        xfree(ddata->pkt->polygon_url);
        ddata->pkt->polygon_url = xstrdup(ddata->clean_url);
        if ((retval = dif->login_page(ddata)))
            goto done;
    }

    if ((retval = process_login_page(log_f, ps, ddata)))
        goto done;

    if ((retval = dif->login_action(ddata, ps)))
        goto done;

    if (pkt->polygon_contest_id && *pkt->polygon_contest_id) {
        int id = 0;
        if ((retval = dif->contests_page(ddata, ps)))
            goto done;

        if ((retval = process_contests_page(log_f, ps, ddata, pkt->polygon_contest_id, &id)))
            goto done;

        if ((retval = dif->contest_page(ddata, ps, id)))
            goto done;

        if ((retval = process_contest_page(log_f, ps, ddata, probset)))
            goto done;
    }

    if ((retval = dif->problems_multi_page(log_f, ddata, ps)))
        goto done;

    if (probset->count <= 0) {
        fprintf(log_f, "no problems to update\n");
        goto done;
    }

    while (1) {
        if (sigint_caught) {
            fprintf(log_f, "exiting due to signal caught\n");
            break;
        }

        process_problems_page(log_f, ps, dif->get_page_text(ddata), probset);

        if (!check_problem_statuses(log_f, pkt, dif, ddata, ps, zif, probset)) {
            // no problems in RUNNING state
            break;
        }

        if (retry_count > pkt->retry_count) {
            fprintf(log_f, "number of retries exceeded the limit %d\n",
                    pkt->retry_count);
            for (int i = 0; i < probset->count; ++i) {
                if (probset->infos[i].state == STATE_RUNNING) {
                    probset->infos[i].state = STATE_TIMEOUT;
                }
            }
            break;
        }

        fprintf(log_f, "sleeping for %d seconds\n", pkt->sleep_interval);
        ++retry_count;
        sleep(pkt->sleep_interval);
        if (sigint_caught) {
            fprintf(log_f, "exiting due to signal caught\n");
            break;
        }

        if ((retval = dif->problems_multi_page(log_f, ddata, ps)))
            goto done;
    }

done:;
    if (ddata) {
        if (dif) ddata = dif->cleanup(ddata);
    }
    ps = polygon_state_free(ps);
    return retval;
}

static int
do_work_file(
        FILE *log_f,
        struct polygon_packet *pkt,
        struct ProblemSet *probset)
{
    const struct ZipInterface *zif = NULL;
    int retval = 1;

#if CONF_HAS_LIBZIP - 0 == 0
    fprintf(log_f, "libzip library was missing during the complation, functionality is not available\n");
    retval = 1;
    goto done;
#else
    zif = get_zip_interface(log_f, pkt);
#endif

    if (!zif) {
        fprintf(log_f, "zip interface is not available\n");
        retval = 1;
        goto done;
    }

    probset->count = 1;
    XCALLOC(probset->infos, probset->count);

    if (pkt->ejudge_short_name && pkt->ejudge_short_name[0] && pkt->ejudge_short_name[0][0]) {
        probset->infos[0].ejudge_short_name = xstrdup(pkt->ejudge_short_name[0]);
    }

    process_polygon_zip(log_f, pkt, zif, pkt->package_file, &probset->infos[0], 1);

    // copy zip file to download directory
    if (pkt->download_dir && pkt->download_dir[0]) {
        unsigned char target_name[PATH_MAX];
        snprintf(target_name, sizeof(target_name),
                 "%s-%d", probset->infos[0].problem_name,
                 probset->infos[0].package_rev);
        generic_copy_file(0, NULL, pkt->package_file, NULL,
                          0, pkt->download_dir, target_name, ".zip");
    }

    retval = 0;

done:;
    return retval;
}

int
main(int argc, char **argv)
{
    int cur_arg = 1;
    int retval = 0;
    struct RandomSource *rand = NULL;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    progname = os_GetLastname(argv[0]);

    while (cur_arg < argc) {
        if (!strcmp(argv[cur_arg], "--version")) {
            report_version();
        } else if (!strcmp(argv[cur_arg], "--")) {
            ++cur_arg;
            break;
        } else if (argv[cur_arg][0] == '-') {
            fatal("invalid option '%s'", argv[cur_arg]);
        } else {
            break;
        }
    }

    if (cur_arg >= argc) {
        fatal("packet path is expected");
    }
    if (cur_arg < argc - 1) {
        fatal("too many arguments");
    }

    FILE *f = fopen(argv[cur_arg], "r");
    if (!f) {
        fatal("cannot open packet file '%s'", argv[cur_arg]);
    }

    struct polygon_packet *pkt = polygon_packet_parse(argv[cur_arg], f);
    f = NULL;
    if (!pkt) {
        fatal("failed to parse packet file '%s'", argv[cur_arg]);
    }

    if (!pkt->polygon_url) {
        pkt->polygon_url = xstrdup(DEFAULT_POLYGON_URL);
    }
    if (!pkt->arch) {
        pkt->arch = xstrdup(DEFAULT_ARCH);
    }
    if (pkt->sleep_interval <= 0) {
        pkt->sleep_interval = DEFAULT_SLEEP_INTERVAL;
    }
    if (!pkt->problem_xml_name) {
        pkt->problem_xml_name = xstrdup(DEFAULT_PROBLEM_XML_NAME);
    }
    if (!pkt->testset) {
        pkt->testset = xstrdup(DEFAULT_TESTSET);
    }
    if (!pkt->user_agent) {
        unsigned char ua_buf[1024];
        snprintf(ua_buf, sizeof(ua_buf), "%s: ejudge version %s compiled %s",
                 progname, compile_version, compile_date);
        pkt->user_agent = xstrdup(ua_buf);
    }
    if (pkt->working_dir) {
        if (chdir(pkt->working_dir) < 0)
            fatal("cannot change directory to '%s': %s", pkt->working_dir, strerror(errno));
    }
    if (pkt->pid_file) {
        FILE *f = fopen(pkt->pid_file, "w");
        if (!f) fatal("'pid_file' path '%s' cannot be opened for write", pkt->pid_file);
        fprintf(f, "%d\n", getpid());
        fflush(f);
        if (ferror(f)) fatal("'pid_file' path '%s' write error", pkt->pid_file);
        fclose(f); f = NULL;
    }
    if (pkt->retry_count <= 0) {
        pkt->retry_count = DEFAULT_RETRY_COUNT;
    }

    rand = random_source_urandom();

    struct ProblemSet problem_set;
    memset(&problem_set, 0, sizeof(problem_set));

    if (pkt->id) {
        for (; pkt->id[problem_set.count]; ++problem_set.count) {}
        if (problem_set.count > 0) {
            XCALLOC(problem_set.infos, problem_set.count);
        }
        int ej_id_len = sarray_len(pkt->ejudge_id);
        int ej_name_len = sarray_len(pkt->ejudge_short_name);
        for (int i = 0; pkt->id[i]; ++i) {
            problem_set.infos[i].key_id = -1;
            unsigned char *id_str = pkt->id[i];
            if (!strncmp(id_str, "polygon:", 8)) {
                id_str += 8;
            }
            char *eptr = NULL;
            errno = 0;
            int val = strtol(id_str, &eptr, 10);
            if (!errno && !*eptr && val > 0) {
                problem_set.infos[i].key_id = val;
            } else {
                problem_set.infos[i].key_name = xstrdup(id_str);
            }
            if (i < ej_id_len) {
                eptr = NULL;
                errno = 0;
                val = strtol(pkt->ejudge_id[i], &eptr, 10);
                if (!errno && !*eptr && val > 0) {
                    problem_set.infos[i].ejudge_id = val;
                }
            }
            if (i < ej_name_len) {
                problem_set.infos[i].ejudge_short_name = xstrdup(pkt->ejudge_short_name[i]);
            }
        }
    }

    FILE *log_f = NULL;
    if (pkt->log_file) {
        log_f = fopen(pkt->log_file, "w");
        if (!log_f) {
            fatal("failed to open log file '%s'", pkt->log_file);
        }
        setvbuf(log_f, NULL, _IONBF, 0);
    } else {
        log_f = stderr;
    }
    if (pkt->package_file) {
        retval = do_work_file(log_f, pkt, &problem_set);
    } else if (pkt->secret && *pkt->secret) {
        retval = do_work_api(log_f, pkt, rand, &problem_set);
    } else {
        retval = do_work(log_f, pkt, &problem_set);
    }

    FILE *st_f = NULL;
    if (pkt->status_file) {
        st_f = fopen(pkt->status_file, "w");
        if (!st_f) {
            fprintf(log_f, "failed to open status file '%s'", pkt->status_file);
            st_f = stdout;
        }
    } else {
        st_f = stdout;
    }
    fprintf(st_f, "%d\n", retval);
    fprintf(st_f, "%d\n", problem_set.count);
    for (int i = 0; i < problem_set.count; ++i) {
        if (problem_set.infos[i].key_id > 0) {
            fprintf(st_f, "%d;", problem_set.infos[i].key_id);
        } else if (problem_set.infos[i].key_name) {
            fprintf(st_f, "%s;", problem_set.infos[i].key_name);
        } else {
            fprintf(st_f, ";");
        }
        fprintf(st_f, "%s;", update_statuses[problem_set.infos[i].state]);
        fprintf(st_f, "%d;", problem_set.infos[i].problem_id);
        if (problem_set.infos[i].problem_name) {
            fprintf(st_f, "%s;", problem_set.infos[i].problem_name);
        } else {
            fprintf(st_f, ";");
        }
        fprintf(st_f, "\n");
    }
    if (pkt->status_file) {
        fclose(st_f);
    }
    st_f = NULL;
    if (pkt->log_file) {
        fclose(log_f);
    }
    log_f = NULL;

    free_problem_infos(&problem_set);

    if (pkt->pid_file) {
        unlink(pkt->pid_file);
    }

    polygon_packet_free((struct generic_section_config *) pkt);
    pkt = NULL;
    if (rand) {
        rand->ops->destroy(rand);
        rand = NULL;
    }

    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
