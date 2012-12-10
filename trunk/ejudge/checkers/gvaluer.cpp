/* $Id$ */
/* Copyright (C) 2012 Alexander Chernov <cher@ejudge.ru> */

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

#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <climits>
#include <unistd.h>
#include <cctype>

using namespace std;

enum
{
  RUN_OK               = 0,
  RUN_COMPILE_ERR      = 1,
  RUN_RUN_TIME_ERR     = 2,
  RUN_TIME_LIMIT_ERR   = 3,
  RUN_PRESENTATION_ERR = 4,
  RUN_WRONG_ANSWER_ERR = 5,
  RUN_CHECK_FAILED     = 6,
  RUN_PARTIAL          = 7,
  RUN_ACCEPTED         = 8,
  RUN_IGNORED          = 9,
  RUN_DISQUALIFIED     = 10,
  RUN_PENDING          = 11,
  RUN_MEM_LIMIT_ERR    = 12,
  RUN_SECURITY_ERR     = 13,
  RUN_STYLE_ERR        = 14,
  RUN_WALL_TIME_LIMIT_ERR = 15,
  RUN_PENDING_REVIEW   = 16,
  RUN_REJECTED         = 17,
  RUN_SKIPPED          = 18
};

static void
die(const char *, ...)
    __attribute__((noreturn, format(printf, 1, 2)));
static void
die(const char *format, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "fatal: %s\n", buf);
    exit(RUN_CHECK_FAILED);
}

static bool marked_flag;
static bool user_score_flag;
static bool interactive_flag;

class ConfigParser
{
private:
    FILE *in_f = NULL;
    string path;
    int line;
    int pos;

    int in_c;
    int c_line;
    int c_pos;

    string token;
    int t_line;
    int t_pos;

public:
    ConfigParser()
    {
    }

    ~ConfigParser()
    {
        if (!in_f) fclose(in_f);
        in_f = NULL;
    }

    void next_char()
    {
        c_line = line;
        c_pos = pos;
        in_c = fgetc(in_f);
        if (in_c == '\n') {
            pos = 0;
            ++line;
        } else if (in_c == '\t') {
            pos = (pos + 8) & ~7;
        } else if (in_c >= ' ') {
            ++pos;
        }
    }

    void next_token()
    {
        if (in_c == EOF) {
            token = "";
        }
        while (1) {
            while (isspace(in_c)) next_char();
            if (in_c != '#') break;
            while (in_c != EOF && in_c != '\n') next_char();
            if (in_c == '\n') next_char();
        }
        if (isalnum(in_c)) {
            token = "";
            t_line = c_line;
            t_pos = c_pos;
            while (isalnum(in_c)) {
                token += char(in_c);
                next_char();
            }
            return;
        }
        /*
        if (in_c == '\"') {
        }
        */
        if (in_c == ';') {
            t_line = c_line;
            t_pos = c_pos;
            token = ";";
            return;
        }
        if (in_c == '{') {
            t_line = c_line;
            t_pos = c_pos;
            token = "{";
            return;
        }
        if (in_c == '}') {
            t_line = c_line;
            t_pos = c_pos;
            token = "}";
            return;
        }
        die("%s: %d: %d: invalid character", path.c_str(), c_line, c_pos);
    }

    void parse_groups()
    {
        while (token == "group") {
            next_token();
        }
    }

    void parse(const string &configpath)
    {
        path = configpath;
        line = 1;
        pos = 0;
        in_f = fopen(configpath.c_str(), "r");
        if (!in_f) die("cannot open config file '%s'", configpath.c_str());
        next_char();
        next_token();
        parse_groups();
        if (token != "") {
            die("%s: %d: %d: parse error", path.c_str(), t_line, t_pos);
        }
    }
};

int
main(int argc, char *argv[])
{
    if (argc != 3) die("invalid number of arguments");

    string self(argv[0]);
    string selfdir;
    size_t pos = self.find_last_of('/');
    if (pos == string::npos) {
        char buf[PATH_MAX];
        if (!getcwd(buf, sizeof(buf))) die("getcwd() failed");
        selfdir = buf;
    } else if (pos == 0) {
        die("won't work in the root directory");
    } else if (self[0] == '/') {
        selfdir = self.substr(0, pos);
    } else {
        char buf[PATH_MAX];
        if (!getcwd(buf, sizeof(buf))) die("getcwd() failed");
        selfdir = buf;
        if (selfdir != "/") selfdir += '/';
        selfdir += self.substr(0, pos);
    }

    if (!getenv("EJUDGE")) die("EJUDGE environment variable must be set");
    if (getenv("EJUDGE_USER_SCORE")) user_score_flag = true;
    if (getenv("EJUDGE_MARKED")) marked_flag = true;
    if (getenv("EJUDGE_INTERACTIVE")) interactive_flag = true;

    string configpath = selfdir + "/valuer.cfg";
    ConfigParser parser;
    parser.parse(configpath);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
