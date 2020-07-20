/* Copyright (C) 2012-2017 Alexander Chernov <cher@ejudge.ru> */

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
#include <vector>
#include <algorithm>
#include <set>

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
  RUN_SKIPPED          = 18,
  RUN_SYNC_ERR         = 19,
  RUN_SUMMONED         = 23,
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
static bool rejudge_flag;
static int locale_id = 0;

static int parse_status(const string &str)
{
    if (str.length() != 2) return -1;
    char c1 = toupper(str[0]);
    char c2 = toupper(str[1]);
    if (c1 == 'A') {
        if (c2 == 'C') return RUN_ACCEPTED;
    } else if (c1 == 'C') {
        if (c2 == 'E') return RUN_COMPILE_ERR;
        if (c2 == 'F') return RUN_CHECK_FAILED;
    } else if (c1 == 'D') {
        if (c2 == 'Q') return RUN_DISQUALIFIED;
    } else if (c1 == 'I') {
        if (c2 == 'G') return RUN_IGNORED;
    } else if (c1 == 'M') {
        if (c2 == 'L') return RUN_MEM_LIMIT_ERR;
    } else if (c1 == 'O') {
        if (c2 == 'K') return RUN_OK;
    } else if (c1 == 'P') {
        if (c2 == 'D') return RUN_PENDING;
        if (c2 == 'E') return RUN_PRESENTATION_ERR;
        if (c2 == 'R') return RUN_PENDING_REVIEW;
        if (c2 == 'T') return RUN_PARTIAL;
    } else if (c1 == 'S') {
        if (c2 == 'E') return RUN_SECURITY_ERR;
        if (c2 == 'K') return RUN_SKIPPED;
        if (c2 == 'M') return RUN_SUMMONED;
        if (c2 == 'V') return RUN_STYLE_ERR;
        if (c2 == 'Y') return RUN_SYNC_ERR;
    } else if (c1 == 'R') {
        if (c2 == 'J') return RUN_REJECTED;
        if (c2 == 'T') return RUN_RUN_TIME_ERR;
    } else if (c1 == 'T') {
        if (c2 == 'L') return RUN_TIME_LIMIT_ERR;
    } else if (c1 == 'W') {
        if (c2 == 'A') return RUN_WRONG_ANSWER_ERR;
        if (c2 == 'T') return RUN_WALL_TIME_LIMIT_ERR;
    }

    return -1;
}

class ConfigParser;
class Group
{
    string group_id;
    int first = 0;
    int last = 0;
    vector<string> requires;
    vector<string> sets_marked_if_passed;
    bool offline = false;
    bool sets_marked = false;
    bool skip = false;
    bool skip_if_not_rejudge = false;
    bool stat_to_judges = false;
    bool stat_to_users = false;
    bool test_all = false;
    int score = 0;
    int test_score = -1;
    int pass_if_count = -1;
    int user_status = -1;

    int passed_count = 0;
    int total_score = 0;
    string comment;

    vector<set<int> > zero_sets;
    set<int> passed_set;

public:
    Group() {}

    void set_group_id(const string &group_id_) { group_id = group_id_; }
    const string &get_group_id() const { return group_id; }

    void set_range(int first, int last)
    {
        this->first = first; 
        this->last = last;
    }
    int get_first() const { return first; }
    int get_last() const { return last; }

    void add_requires(const string &s) { requires.push_back(s); }
    const vector<string> &get_requires() const { return requires; }

    void add_sets_marked_if_passed(const string &s) { sets_marked_if_passed.push_back(s); }
    const vector<string> &get_sets_marked_if_passed() const { return sets_marked_if_passed; }

    void set_offline(bool offline) { this->offline = offline; }
    bool get_offline() const { return offline; }

    void set_sets_marked(bool sets_marked) { this->sets_marked = sets_marked; }
    bool get_sets_marked() const { return sets_marked; }

    void set_skip(bool skip) { this->skip = skip; }
    bool get_skip() const { return skip; }

    void set_skip_if_not_rejudge(bool skip) { this->skip_if_not_rejudge = skip; }
    bool get_skip_if_not_rejudge() const { return skip_if_not_rejudge; }

    void set_stat_to_judges(bool stat) { this->stat_to_judges = stat; }
    bool get_stat_to_judges() const { return stat_to_judges; }

    void set_stat_to_users(bool stat) { this->stat_to_users = stat; }
    bool get_stat_to_users() const { return stat_to_users; }

    void set_score(int score) { this->score = score; }
    int get_score() const { return score; }

    void set_pass_if_count(int count) { this->pass_if_count = count; }
    int get_pass_if_count() const { return pass_if_count; }

    void set_test_all(bool value) { test_all = value; }
    bool get_test_all() const { return test_all; }

    void inc_passed_count() { ++passed_count; }
    int get_passed_count() const { return passed_count; }
    bool is_passed() const
    {
        if (pass_if_count > 0) return passed_count >= pass_if_count;
        return passed_count == (last - first + 1);
    }

    void add_passed_test(int test_num)
    {
        passed_set.insert(test_num);
    }

    bool is_zero_set() const
    {
        for (int i = 0; i < int(zero_sets.size()); ++i) {
            if (passed_set == zero_sets[i])
                return true;
        }
        return false;
    }

    void set_comment(const string &comment_) { comment = comment_; }
    const string &get_comment() const { return comment; }
    bool has_comment() const { return comment.length() > 0; }

    void set_test_score(int ts) { test_score = ts; }
    int get_test_score() const { return test_score; }

    void set_user_status(int user_status) { this->user_status = user_status; }
    int get_user_status() const { return user_status; }

    void add_zero_set(set<int> &&zs)
    {
        zero_sets.emplace_back(zs);
    }

    bool meet_requirements(const ConfigParser &cfg, const Group *& grp) const;

    void add_total_score()
    {
        if (test_score > 0) total_score += test_score;
    }
    void set_total_score(int total_score)
    {
        this->total_score = total_score;
    }
    int get_total_score() const { return total_score; }

    int calc_score() const
    {
        if (test_score < 0 && passed_count == (last - first + 1)) {
            return score;
        } else if (test_score >= 0) {
            return total_score;
        }
        return 0;
    }
};

class Global
{
    int stat_to_judges = -1;
    int stat_to_users = -1;

public:
    void set_stat_to_judges(int value)
    {
        if (value < 0) {
            value = -1;
        } else if (value > 0) {
            value = 1;
        }
        stat_to_judges = value;
    }
    int get_stat_to_judges() const { return stat_to_judges; }

    void set_stat_to_users(int value)
    {
        if (value < 0) {
            value = -1;
        } else if (value > 0) {
            value = 1;
        }
        stat_to_users = value;
    }
    int get_stat_to_users() const { return stat_to_users; }
};

class ConfigParser
{
public:
    const int T_EOF = 256;
    const int T_IDENT = 257;

private:
    FILE *in_f = NULL;
    string path;
    int line;
    int pos;

    int in_c;
    int c_line;
    int c_pos;

    string token;
    int t_type;
    int t_line;
    int t_pos;

    Global global;
    vector<Group> groups;

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
        while (1) {
            while (isspace(in_c)) next_char();
            if (in_c != '#') break;
            while (in_c != EOF && in_c != '\n') next_char();
            if (in_c == '\n') next_char();
        }
        if (in_c == EOF) {
            t_type = T_EOF;
            token = "";
            return;
        }
        if (isalnum(in_c) || in_c == '_') {
            token = "";
            t_type = T_IDENT;
            t_line = c_line;
            t_pos = c_pos;
            while (isalnum(in_c) || in_c == '_') {
                token += char(in_c);
                next_char();
            }
            return;
        }
        /*
        if (in_c == '\"') {
        }
        */
        if (in_c == ';' || in_c == '{' || in_c == '}' || in_c == '-' || in_c == ',') {
            t_line = c_line;
            t_pos = c_pos;
            token = ";";
            t_type = in_c;
            next_char();
            return;
        }
        scan_error("invalid character");
    }

    void scan_error(const string &msg) const;
    void parse_error(const string &msg) const;

    int read_int_opt(int default_value)
    {
        int value = default_value;
        if (t_type == T_IDENT) {
            try {
                value = stoi(token);
            } catch (...) {
                parse_error("NUM expected");
            }
            next_token();
        }
        return value;
    }

    void parse_group()
    {
        Group g;
        bool has_stat_to_judges = false;
        bool has_stat_to_users = false;

        if (token != "group") parse_error("'group' expected");
        next_token();
        if (t_type != T_IDENT) parse_error("IDENT expected");
        if (find_group(token) != NULL)
            parse_error(string("group ") + token + " already defined");
        g.set_group_id(token);
        next_token();
        if (t_type != '{') parse_error("'{' expected");
        next_token();
        while (1) {
            if (token == "tests") {
                next_token();
                int first = -1, last = -1;
                try {
                    first = stoi(token);
                } catch (...) {
                    parse_error("NUM expected");
                }
                if (first <= 0) parse_error("invalid test number");
                next_token();
                if (t_type == '-') {
                    next_token();
                    try {
                        last = stoi(token);
                    } catch (...) {
                        parse_error("NUM expected");
                    }
                    if (last <= 0) parse_error("invalid test number");
                    if (last < first) parse_error("invalid range");
                    next_token();
                } else {
                    last = first;
                }
                g.set_range(first, last);
                if (t_type != ';') parse_error("';' expected");
                next_token();
            } else if (token == "requires") {
                next_token();
                if (t_type != T_IDENT) parse_error("IDENT expected");
                g.add_requires(token);
                next_token();
                while (t_type == ',') {
                    next_token();
                    if (t_type != T_IDENT) parse_error("IDENT expected");
                    g.add_requires(token);
                    next_token();
                }
                if (t_type != ';') parse_error("';' expected");
                next_token();
            } else if (token == "sets_marked_if_passed") {
                next_token();
                if (t_type != T_IDENT) parse_error("IDENT expected");
                g.add_sets_marked_if_passed(token);
                next_token();
                while (t_type == ',') {
                    next_token();
                    if (t_type != T_IDENT) parse_error("IDENT expected");
                    g.add_sets_marked_if_passed(token);
                    next_token();
                }
                if (t_type != ';') parse_error("';' expected");
                next_token();
            } else if (token == "0_if") {
                set<int> zs;
                try {
                    next_token();
                    int tn = stoi(token);
                    if (tn < g.get_first() || tn > g.get_last()) parse_error("invalid test number");
                    zs.insert(tn);
                    next_token();
                    while (t_type == ',') {
                        next_token();
                        tn = stoi(token);
                        if (tn < g.get_first() || tn > g.get_last()) parse_error("invalid test number");
                        zs.insert(tn);
                        next_token();
                    }
                } catch (...) {
                    parse_error("NUM expected");
                }
                if (t_type != ';') parse_error("';' expected");
                g.add_zero_set(move(zs));
                next_token();
            } else if (token == "offline") {
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_offline(true);
            } else if (token == "sets_marked") {
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_sets_marked(true);
            } else if (token == "skip") {
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_skip(true);
            } else if (token == "skip_if_not_rejudge") {
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_skip_if_not_rejudge(true);
            } else if (token == "stat_to_judges") {
                next_token();
                int value = read_int_opt(1);
                if (t_type != ';') parse_error("';' expected");
                next_token();
                if (value >= 0) {
                    g.set_stat_to_judges(bool(value));
                    has_stat_to_judges = true;
                }
            } else if (token == "stat_to_users") {
                next_token();
                int value = read_int_opt(1);
                if (t_type != ';') parse_error("';' expected");
                next_token();
                if (value >= 0) {
                    g.set_stat_to_users(bool(value));
                    has_stat_to_users = true;
                }
            } else if (token == "test_all") {
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_test_all(true);
            } else if (token == "score") {
                next_token();
                if (t_type != T_IDENT) parse_error("NUM expected");
                int score = -1;
                try {
                    score = stoi(token);
                } catch (...) {
                    parse_error("NUM expected");
                }
                if (score < 0) parse_error("invalid score");
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_score(score);
            } else if (token == "test_score") {
                next_token();
                if (t_type != T_IDENT) parse_error("NUM expected");
                int test_score = -1;
                try {
                    test_score = stoi(token);
                } catch (...) {
                    parse_error("NUM expected");
                }
                if (test_score < 0) parse_error("invalid test_score");
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_test_score(test_score);
            } else if (token == "pass_if_count") {
                next_token();
                if (t_type != T_IDENT) parse_error("NUM expected");
                int count = -1;
                try {
                    count = stoi(token);
                } catch (...) {
                    parse_error("NUM expected");
                }
                if (count <= 0) parse_error("invalid pass_if_count");
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_pass_if_count(count);
            } else if (token == "user_status") {
                next_token();
                if (t_type != T_IDENT) parse_error("status expected");
                int user_status = parse_status(token);
                if (user_status < 0) parse_error("invalid user_status");
                next_token();
                if (t_type != ';') parse_error("';' expected");
                next_token();
                g.set_user_status(user_status);
            } else {
                break;
            }
        }
        if (t_type != '}') parse_error("'}' expected");
        next_token();
        if (!has_stat_to_judges && global.get_stat_to_judges() >= 0) {
            g.set_stat_to_judges(bool(global.get_stat_to_judges()));
        }
        if (!has_stat_to_users && global.get_stat_to_users() >= 0) {
            g.set_stat_to_users(bool(global.get_stat_to_users()));
        }
        groups.push_back(g);
    }

    void parse_groups()
    {
        while (token == "group") {
            parse_group();
        }
        if (groups.size() <= 0) parse_error("no groups defined");
        sort(groups.begin(), groups.end(), [](const Group &g1, const Group &g2) -> bool { return g1.get_first() < g2.get_first(); });
        for (int i = 1; i < int(groups.size()); ++i) {
            if (groups[i].get_first() <= groups[i - 1].get_last()) {
                parse_error(string("groups ") + groups[i - 1].get_group_id() + " and " + groups[i].get_group_id() + " overlap");
            }
            if (groups[i].get_first() != groups[i - 1].get_last() + 1) {
                parse_error(string("hole between groups ") + groups[i - 1].get_group_id() + " and " + groups[i].get_group_id());
            }
        }
        for (int i = 0; i < int(groups.size()); ++i) {
            const vector<string> &r = groups[i].get_requires();
            for (int j = 0; j < int(r.size()); ++j) {
                int k;
                for (k = 0; k < i; ++k) {
                    if (groups[k].get_group_id() == r[j])
                        break;
                }
                if (k >= i) {
                    parse_error(string("no group ") + r[j] + " before group " + groups[i].get_group_id());
                }
            }
        }
        for (int i = 0; i < int(groups.size()); ++i) {
            const vector<string> &r = groups[i].get_sets_marked_if_passed();
            for (int j = 0; j < int(r.size()); ++j) {
                int k;
                for (k = 0; k <= i; ++k) {
                    if (groups[k].get_group_id() == r[j])
                        break;
                }
                if (k > i) {
                    parse_error(string("no group ") + r[j] + " before group " + groups[i].get_group_id());
                }
            }
        }
        int i;
        for (i = 0; i < int(groups.size()); ++i) {
            if (groups[i].get_offline())
                break;
        }
        if (i < int(groups.size())) {
            for (; i < int(groups.size()); ++i) {
                if (!groups[i].get_offline()) {
                    parse_error("all offline groups must follow all online groups");
                }
            }
        }
    }

    void parse_opt_global()
    {
        if (token != "global") return;
        next_token();
        if (t_type != '{') parse_error("'{' expected");
        next_token();

        while (1) {
            if (token == "stat_to_judges") {
                next_token();
                int value = read_int_opt(1);
                if (t_type != ';') parse_error("';' expected");
                next_token();
                global.set_stat_to_judges(value);
            } else if (token == "stat_to_users") {
                next_token();
                int value = read_int_opt(1);
                if (t_type != ';') parse_error("';' expected");
                next_token();
                global.set_stat_to_users(value);
            } else {
                break;
            }
        }

        if (t_type != '}') parse_error("'}' expected");
        next_token();
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
        parse_opt_global();
        parse_groups();
        if (token != "") {
            parse_error("EOF expected");
        }
    }

    const Group *find_group(const string &id) const
    {
        for (auto i = groups.begin(); i != groups.end(); ++i) {
            if (i->get_group_id() == id)
                return &(*i);
        }
        return NULL;
    }

    Group *find_group(int test_num)
    {
        for (auto i = groups.begin(); i != groups.end(); ++i) {
            if (i->get_first() <= test_num && test_num <= i->get_last())
                return &(*i);
        }
        return NULL;
    }

    const vector<Group> &get_groups() const { return groups; }
};

void
ConfigParser::parse_error(const string &msg) const
{
    fprintf(stderr, "%s: %d: %d: parse error: %s\n", path.c_str(), t_line, t_pos, msg.c_str());
    exit(RUN_CHECK_FAILED);
}

void
ConfigParser::scan_error(const string &msg) const
{
    fprintf(stderr, "%s: %d: %d: scan error: %s\n", path.c_str(), c_line, c_pos, msg.c_str());
    exit(RUN_CHECK_FAILED);
}

bool
Group::meet_requirements(const ConfigParser &cfg, const Group *&grp) const
{
    if (requires.size() <= 0) {
        grp = NULL;
        return true;
    }
    int i;
    const Group *gg = NULL;
    for (i = 0; i < int(requires.size()); ++i) {
        gg = cfg.find_group(requires[i]);
        if (gg == NULL) die("group %s not found", requires[i].c_str());
        if (!gg->is_passed()) break;
    }
    if (i >= int(requires.size())) {
        grp = NULL;
        return true;
    }
    grp = gg;
    return false;
}

int
main(int argc, char *argv[])
{
    if (argc < 3 || argc > 4) die("invalid number of arguments");

    string self(argv[0]);
    string selfdir;
    int valuer_marked = 0;
    if (argc == 3) {
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
    } else {
        selfdir = argv[3];
    }

    if (!getenv("EJUDGE")) die("EJUDGE environment variable must be set");
    if (getenv("EJUDGE_USER_SCORE")) user_score_flag = true;
    if (getenv("EJUDGE_MARKED")) marked_flag = true;
    if (getenv("EJUDGE_INTERACTIVE")) interactive_flag = true;
    if (getenv("EJUDGE_REJUDGE")) rejudge_flag = true;
    {
        char *ls = getenv("EJUDGE_LOCALE");
        if (ls) {
            try {
                locale_id = stoi(ls);
            } catch (...) {
            }
            if (locale_id < 0) locale_id = 0;
        }
    }

    string configpath = selfdir + "/valuer.cfg";
    ConfigParser parser;
    parser.parse(configpath);

    if (!interactive_flag) die("non-interactive mode not yet supported");
    int total_count = -2;
    if (scanf("%d", &total_count) != 1) die("expected the count of tests");
    if (total_count != -1) die("count value must be -1");

    int test_num = 1, t_status, t_score, t_time;
    while (scanf("%d%d%d", &t_status, &t_score, &t_time) == 3) {
        Group *g = parser.find_group(test_num);
        if (g == NULL) die("unexpected test number %d", test_num);
        if (t_status == RUN_OK) {
            // just go to the next test...
            g->inc_passed_count();
            g->add_total_score();
            g->add_passed_test(test_num);
            ++test_num;
        } else if (g->get_test_score() >= 0) {
            // by-test score, just go on
            if (test_num == g->get_last()) {
                if (g->is_zero_set()) {
                    char buf[1024];
                    if (locale_id == 1) {
                        snprintf(buf, sizeof(buf), "Группа тестов %s (%d-%d) оценена в 0 баллов, "
                                 "так как были пройдены только специальные тесты.\n",
                                 g->get_group_id().c_str(), g->get_first(), g->get_last());
                    } else {
                        snprintf(buf, sizeof(buf), "Test group %s (%d-%d) is scored 0 points "
                                 "because only specific tests were passed.\n",
                                 g->get_group_id().c_str(), g->get_first(), g->get_last());
                    }
                    g->set_total_score(0);
                    g->set_comment(string(buf));
                }
            }
            ++test_num;
        } else if (g->get_test_all()) {
            // test everything even if fail
            ++test_num;
        } else {
            if (test_num < g->get_last() && !g->get_offline()) {
                char buf[1024];
                if (locale_id == 1) {
                    snprintf(buf, sizeof(buf), "Тестирование на тестах %d-%d не выполнялось, "
                             "так как тест %d не пройден, и оценка за группу тестов %s - 0 баллов.\n",
                             test_num + 1, g->get_last(), test_num, g->get_group_id().c_str());
                } else {
                    snprintf(buf, sizeof(buf), "Testing on tests %d-%d has not been performed, "
                             "as test %d has not passed, and test group '%s' score is 0.\n",
                             test_num + 1, g->get_last(), test_num, g->get_group_id().c_str());
                }
                g->set_comment(string(buf));
            }
            test_num = g->get_last() + 1;
        }
        if (test_num <= g->get_last()) {
            printf("%d\n", -1);
            fflush(stdout);
            continue;
        }
        const Group *gg = NULL;
        while ((g = parser.find_group(test_num)) && !g->meet_requirements(parser, gg)) {
            if (!g->get_offline()) {
                char buf[1024];
                if (locale_id == 1) {
                    snprintf(buf, sizeof(buf), "Тестирование на тестах %d-%d не выполнялось, "
                             "так как не пройдена одна из требуемых групп %s.\n",
                             g->get_first(), g->get_last(), gg->get_group_id().c_str());
                } else {
                    snprintf(buf, sizeof(buf), "Testing on tests %d-%d has not been performed, "
                             "as one of the required groups '%s' has not passed.\n",
                             g->get_first(), g->get_last(), gg->get_group_id().c_str());
                }
                g->set_comment(string(buf));
            } else if (g->get_offline() && !gg->get_offline()) {
                char buf[1024];
                if (locale_id == 1) {
                    snprintf(buf, sizeof(buf), "Тестирование на тестах %d-%d не будет выполняться после окончания тура, "
                             "так как не пройдена одна из требуемых групп %s.\n",
                             g->get_first(), g->get_last(), gg->get_group_id().c_str());
                } else {
                    snprintf(buf, sizeof(buf), "Testing on tests %d-%d will not be performed after the tour finish, "
                             "as one of the required groups '%s' has not passed.\n",
                             g->get_first(), g->get_last(), gg->get_group_id().c_str());
                }
                g->set_comment(string(buf));
            }
            test_num = g->get_last() + 1;
        }
        while ((g = parser.find_group(test_num))
               && (g->get_skip() || (g->get_skip_if_not_rejudge() && !rejudge_flag))) {
            test_num = g->get_last() + 1;
        }
        printf("%d\n", -test_num);
        fflush(stdout);
    }

    FILE *fcmt = fopen(argv[1], "w");
    if (!fcmt) die("cannot open file '%s' for writing", argv[1]);

    FILE *fjcmt = fopen(argv[2], "w");
    if (!fjcmt) die("cannot open file '%s' for writing", argv[2]);

    int score = 0, user_status = RUN_OK, user_score = 0, user_tests_passed = 0;
    for (const Group &g : parser.get_groups()) {
        if (g.has_comment()) {
            fprintf(fcmt, "%s", g.get_comment().c_str());
        }
        if (g.get_sets_marked() && g.is_passed()) {
            valuer_marked = 1;
        }
        const vector<string> &smv = g.get_sets_marked_if_passed();
        if (smv.size() > 0) {
            bool failed = false;
            for (const string &gn : smv) {
                const Group *pg2 = parser.find_group(gn);
                if (!pg2 || !pg2->is_passed()) {
                    failed = true;
                }
            }
            if (!failed) valuer_marked = 1;
        }
        int group_score = g.calc_score();
        if (g.get_stat_to_judges()) {
            if (locale_id == 1) {
                fprintf(fjcmt, "Группа тестов %s: тесты %d-%d: балл %d\n",
                        g.get_group_id().c_str(), g.get_first(), g.get_last(), group_score);
            } else {
                fprintf(fjcmt, "Test group '%s': tests %d-%d: score %d\n",
                        g.get_group_id().c_str(), g.get_first(), g.get_last(), group_score);
            }

        }
        if (g.get_stat_to_users() && !g.get_offline()) {
            if (locale_id == 1) {
                fprintf(fcmt, "Группа тестов %s: тесты %d-%d: балл %d\n",
                        g.get_group_id().c_str(), g.get_first(), g.get_last(), group_score);
            } else {
                fprintf(fcmt, "Test group '%s': tests %d-%d: score %d\n",
                        g.get_group_id().c_str(), g.get_first(), g.get_last(), group_score);
            }

        }
        if (g.get_offline()) {
            score += group_score;
        } else {
            user_tests_passed += g.get_passed_count();
            score += group_score;
            user_score += group_score;
            if (!g.is_passed()) {
                user_status = RUN_PARTIAL;
            } else if (g.get_user_status() >= 0) {
                user_status = g.get_user_status();
            }
        }
    }

    printf("%d", score);
    if (marked_flag) {
        printf(" %d", valuer_marked);
    }
    if (user_score_flag) {
        printf(" %d %d %d", user_status, user_score, user_tests_passed);
    }
    printf("\n");
    fflush(stdout);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
