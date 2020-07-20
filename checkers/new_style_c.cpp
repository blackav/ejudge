#include <string>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <map>

#define INDENT 4
#define MAX_LINE_LENGTH 120

using namespace std;

static const char *program_name = nullptr;

#include "c_cpp_token.h"

class Range
{
    int low = 0, high = 0; // [low; high)

public:
    Range() = default;
    Range(int low, int high) : low(low), high(high) {}

    explicit operator bool() const { return low < high; }

    int get_low() const { return low; }
    int get_high() const { return high; }
};

class Position
{
    string file;
    int line = 0;
    int column = 0;

public:
    Position(const string &file, int line, int column = 0)
        : file(file), line(line), column(column)
    {
    }
    Position(const Position &other) = default;
    Position(Position &&other) = default;
    Position &operator=(const Position &other) = default;
    Position &operator=(Position &&other) = default;

    Position(const Position &other, int length)
        : file(other.file), line(other.line), column(other.column + length - 1)
    {
    }

    const string &get_file() const { return file; }
    int get_line() const { return line; }
    int get_column() const { return column; }

    string to_string() const
    {
        string buf(file);
        char b[64];
        snprintf(b, sizeof(b), ":%d:%d", line, column);
        buf += b;
        return buf;
    }
};

class TokenInfo
{
    Token token = Token::NO_TOKEN;
    Position begpos;
    Position endpos;
    int length = 0;
    string text;

public:
    TokenInfo(Token token, const string &file, int lineno, int column, int length)
        : token(token), begpos(file, lineno, column), endpos(begpos, length), length(length)
    {
    }
    TokenInfo(Token token, const string &file, int lineno, int column, const string &text)
        : token(token), begpos(file, lineno, column), endpos(begpos, int(text.size())), length(int(text.size())), text(text)
    {
    }
    TokenInfo(const TokenInfo &other) = default;
    TokenInfo(TokenInfo &&other) = default;

    TokenInfo &operator =(const TokenInfo &other) = default;
    TokenInfo &operator =(TokenInfo &&other) = default;

    Token get_token() const { return token; }
    int get_int_token() const { return int(token); }

    const Position &get_begpos() const { return begpos; }
    const Position &get_endpos() const { return endpos; }
    const string &get_text() const { return text; }
};

class Line
{
    string file;
    string text;
    vector<TokenInfo> tokens;
    int lineno = 0;
    int column = 0;

public:
    Line() = default;
    Line(const char *name, int lineno, const string &text)
        : file(name), text(text), lineno(lineno)
    {
    }

    const string &get_file() const { return file; }
    int get_lineno() const { return lineno; }
    string &get_text() { return text; }
    const string &get_ctext() const { return text; }
    int get_column() const { return column; }
    const vector<TokenInfo> &get_tokens() const { return tokens; }

    void set_lineno(int lineno) { this->lineno = lineno; }
    void set_file(const string &file) { this->file = file; }
    void set_file(string && file) { this->file = file; }
    void set_column(int column) { this->column = column; }
    void set_tokens(vector<TokenInfo> &&tokens) { this->tokens = tokens; }

    void append_nows_tokens(vector<TokenInfo> &toks)
    {
        for (const auto &t : tokens) {
            if (t.get_int_token() > ' ') {
                toks.push_back(t);
            }
        }
    }
};

class SourceFile
{
    vector<Line> lines;
    int error_count = 0;
    vector<TokenInfo> tokens; // tokens (no whitespace)

    class CharIterator
    {
        typedef char value_type;
        typedef ptrdiff_t difference_type;
        typedef char* pointer;
        typedef char& reference;
        typedef std::bidirectional_iterator_tag iterator_category;

        SourceFile *sf = nullptr;
        int line = 0;
        int column = 0;

    public:
        CharIterator(SourceFile *sf) : sf(sf)
        {
            if (sf->lines.empty()) {
                sf = nullptr;
            }
        }
        CharIterator() {}
        CharIterator &operator++()
        {
            if (sf) {
                ++column;
                if (column >= int(sf->lines[line].get_text().size())) {
                    column = 0;
                    ++line;
                    if (line >= int(sf->lines.size())) {
                        line = 0;
                        sf = nullptr;
                    }
                }
            }
            return *this;
        }
        CharIterator operator++(int)
        {
            CharIterator tmp = *this;
            ++(*this);
            return tmp;
        }
        bool operator ==(const CharIterator &it) const
        {
            if (!sf && !it.sf) return true;
            if (!sf || !it.sf) return false;
            return line == it.line && column == it.column;
        }
        bool operator !=(const CharIterator &it) const
        {
            return !operator==(it);
        }
        char &operator *()
        {
            return sf->lines[line].get_text()[column];
        }
    };
public:
    void append_line(const char *name, int lineno, const string &text)
    {
        lines.emplace_back(Line(name, lineno, text));
    }

    bool read_file(const char *name, FILE *fin)
    {
        int c;
        string buf;
        int line = 1;

        while ((c = getc_unlocked(fin)) != EOF) {
            buf += char(c);
            if (c == '\n') {
                append_line(name, line, buf);
                ++line;
                buf.erase();
            }
        }
        if (buf.size() > 0) {
            append_line(name, line, buf);
            ++line;
            buf.erase();
        }
        return true;
    }

    CharIterator begin()
    {
        return CharIterator(this);
    }

    CharIterator end()
    {
        return CharIterator();
    }

    vector<char*> get_char_vector()
    {
        vector<char*> res;

        if (lines.empty()) return res;

        for (char &c : *this) {
            res.push_back(&c);
        }
        return res;
    }

    int get_error_count() const { return error_count; }
    
    bool handle_comments_1()
    {
        bool retval = true;
        vector<char*> vpc = get_char_vector();

        if (lines.empty()) return true;
        const string&name = lines[0].get_file();

        int i = 0;
        while (i < int(vpc.size())) {
            if (*vpc[i] == '\"') {
                // check that no string spans over lines
                ++i;
                while (1) {
                    if (i >= int(vpc.size())) {
                        fprintf(stderr, "%s: unclosed string at end of file\n", name.c_str());
                        return false;
                    }
                    if (*vpc[i] == '\n') {
                        fprintf(stderr, "%s: string spans over several lines\n", name.c_str());
                        return false;
                    }
                    if (*vpc[i] == '\"') {
                        ++i;
                        break;
                    }
                    if (*vpc[i] == '\\') {
                        ++i;
                        if (i >= int(vpc.size())) {
                            fprintf(stderr, "%s: string contails \\ at end of input\n", name.c_str());
                            return false;
                        }
                        ++i;
                    } else {
                        ++i;
                    }
                }
            } else if (*vpc[i] == '\'') {
                // check that no literal spans over lines
                ++i;
                while (1) {
                    if (i >= int(vpc.size())) {
                        fprintf(stderr, "%s: unclosed char literal at end of file\n", name.c_str());
                        return false;
                    }
                    if (*vpc[i] == '\n') {
                        fprintf(stderr, "%s: char literal spans over several lines\n", name.c_str());
                        return false;
                    }
                    if (*vpc[i] == '\'') {
                        ++i;
                        break;
                    }
                    if (*vpc[i] == '\\') {
                        ++i;
                        if (i >= int(vpc.size())) {
                            fprintf(stderr, "%s: char literal contails \\ at end of input\n", name.c_str());
                            return false;
                        }
                        ++i;
                    } else {
                        ++i;
                    }
                }
            } else if (*vpc[i] == '/') {
                if (i + 1 < int(vpc.size()) && *vpc[i + 1] == '/') {
                    // line comment
                    *vpc[i] = ' ';
                    *vpc[i + 1] = ' ';
                    i += 2;
                    while (i < int(vpc.size()) && *vpc[i] != '\n') {
                        *vpc[i] = ' ';
                        ++i;
                    }
                    if (i < int(vpc.size())) *vpc[i] = ' ';
                } else if (i + 1 < int(vpc.size()) && *vpc[i + 1] == '*') {
                    // block comment
                    *vpc[i] = ' ';
                    *vpc[i + 1] = ' ';
                    i += 2;
                    while (1) {
                        if (i >= int(vpc.size())) {
                            fprintf(stderr, "%s: unclosed block comment at end of file\n", name.c_str());
                            return false;
                        }
                        if (*vpc[i] == '*' && i + 1 < int(vpc.size()) && *vpc[i + 1] == '/') {
                            *vpc[i] = ' ';
                            *vpc[i + 1] = ' ';
                            i += 2;
                            break;
                        }
                        *vpc[i] = ' ';
                        ++i;
                    }
                } else {
                    ++i;
                }
            } else {
                ++i;
            }
        }
        return retval;
    }

    void trim()
    {
        for (int i = 0; i < int(lines.size()); ++i) {
            string &line = lines[i].get_text();
            int j = int(line.size());
            while (j > 0 && isspace(line[j - 1])) --j;
            line.resize(j);
        }
    }

    void invalid_line_directive(int i)
    {
        fprintf(stderr, "%s:%d: invalid #line directive\n", lines[i].get_file().c_str(), lines[i].get_lineno());
        ++error_count;
    }
    void handle_line_directive(int i)
    {
        string &line = lines[i].get_text();
        string lbuf;
        string sbuf;

        int j = 0;
        while (j < int(line.size()) && isspace(line[j])) ++j;
        if (j >= int(line.size()) || line[j] != '#') {
            invalid_line_directive(i);
            return;
        }
        ++j;
        while (j < int(line.size()) && isspace(line[j])) ++j;
        if (j + 3 >= int(line.size()) || line[j] != 'l' || line[j + 1] != 'i' || line[j + 2] != 'n' || line[j + 3] != 'e') {
            invalid_line_directive(i);
            return;
        }
        j += 4;
        if (j >= int(line.size()) || !isspace(line[j])) {
            invalid_line_directive(i);
            return;
        }
        while (j < int(line.size()) && isspace(line[j])) ++j;
        if (j >= int(line.size()) || !isdigit(line[j])) {
            invalid_line_directive(i);
            return;
        }
        while (j < int(line.size()) && isdigit(line[j])) {
            lbuf.push_back(line[j++]);
        }
        long newlineno = 0;
        errno = 0;
        newlineno = strtol(lbuf.c_str(), NULL, 10);
        if (errno || newlineno < 0) {
            invalid_line_directive(i);
            return;
        }
        if (j >= int(line.size())) {
            ++i;
            for (; i < int(lines.size()); ++i) {
                lines[i].set_lineno(++newlineno);
            }
            line.clear();
            return;
        }
        if(!isspace(line[j])) {
            invalid_line_directive(i);
            return;
        }
        while (j < int(line.size()) && isspace(line[j])) ++j;
        if (j >= int(line.size()) || line[j] != '\"') {
            invalid_line_directive(i);
            return;
        }
        ++j;
        while (j < int(line.size()) && line[j] != '\"') {
            sbuf.push_back(line[j++]);
        }
        if (j >= int(line.size())) {
            invalid_line_directive(i);
            return;
        }
        ++j;
        if (j < int(line.size())) {
            invalid_line_directive(i);
            return;
        }

        ++i;
        for (; i < int(lines.size()); ++i) {
            lines[i].set_file(sbuf);
            lines[i].set_lineno(newlineno++);
        }
        line.clear();
        return;
    }

    void handle_cpp_1()
    {
        for (int i = 0; i < int(lines.size());) {
            string &line = lines[i].get_text();
            int j = 0;
            while (j < int(line.size()) && isspace(line[j])) ++j;
            if (j < int(line.size()) && line[j] == '#') {
                int k = j + 1;
                while (k < int(line.size()) && isspace(line[k])) ++k;
                if (k + 3 < int(line.size()) && line[k] == 'l' && line[k + 1] == 'i' && line[k + 2] == 'n' && line[k + 3] == 'e') {
                    // #line directive
                    if (line[line.size() - 1] == '\\') {
                        fprintf(stderr, "%s:%d: #line must be signle-line\n",
                                lines[i].get_file().c_str(), lines[i].get_lineno());
                        ++error_count;
                        return;
                    }
                    handle_line_directive(i);
                    ++i;
                } else {
                    if (j != 0) {
                        fprintf(stderr, "%s:%d: preprocessor directive must start at column 0\n",
                                lines[i].get_file().c_str(), lines[i].get_lineno());
                        ++error_count;
                    }
                    int n = i;
                    while (1) {
                        if (n >= int(lines.size())) {
                            fprintf(stderr, "%s:%d: preprocessor continuation at end of file\n",
                                    lines[i].get_file().c_str(), lines[i].get_lineno());
                            ++error_count;
                            return;
                        }
                        string &s = lines[n].get_text();
                        if (s.empty() || s[s.size() - 1] != '\\') break;
                        ++n;
                    }
                    // preprocessor directive at range [i, n]
                    // replace it all with spaces
                    for (; i <= n; ++i) {
                        lines[i].get_text().resize(0);
                    }
                }
            } else {
                ++i;
            }
        }
    }

    void handle_characters()
    {
        for (int i = 0; i < int(lines.size()); ++i) {
            string &line = lines[i].get_text();
            for (int j = 0; j < int(line.size()); ++j) {
                unsigned char c = line[j];
                if (c == '\t') {
                    fprintf(stderr, "%s:%d: TAB is not allowed. Please use spaces to indent the code.\n",
                            lines[i].get_file().c_str(), lines[i].get_lineno());
                    ++error_count;
                    line[j] = ' ';
                } else if (c == '\x7f') {
                    fprintf(stderr, "%s:%d: invalid control character \\x7f\n",
                            lines[i].get_file().c_str(), lines[i].get_lineno());
                    ++error_count;
                    line[j] = ' ';
                } else if (c >= 128) {
                    fprintf(stderr, "%s:%d: characters with codes >= \\x80 are not allowed\n",
                            lines[i].get_file().c_str(), lines[i].get_lineno());
                    ++error_count;
                    line[j] = ' ';
                } else if (c < ' ') {
                    fprintf(stderr, "%s:%d: invalid control character \\x%02x\n",
                            lines[i].get_file().c_str(), lines[i].get_lineno(), c);
                    ++error_count;
                    line[j] = ' ';
                }
            }
        }
    }

    void remove_empty_lines()
    {
        int i = 0, j = 0;
        while (j < int(lines.size())) {
            if (lines[j].get_text().empty()) {
                ++j;
            } else if (i != j) {
                lines[i] = lines[j];
                ++i;
                ++j;
            } else {
                ++i;
                ++j;
            }
        }
        if (i != j) {
            lines.resize(i);
        }
    }

    void remove_first_spaces()
    {
        for (int i = 0; i < int(lines.size()); ++i) {
            string &line = lines[i].get_text();
            int j = 0;
            if (line.size() > MAX_LINE_LENGTH) {
                fprintf(stderr, "%s:%d: line length exceeds %d (actually %d)\n",
                        lines[i].get_file().c_str(), lines[i].get_lineno(), MAX_LINE_LENGTH, int(line.size()));
                ++error_count;
            }
            while (j < int(line.size()) && isspace(line[j])) ++j;
            if (j >= int(line.size())) {
                line.clear();
            } else if (j > 0) {
                if (j % INDENT != 0) {
                    fprintf(stderr, "%s:%d: invalid indentation %d spaces. Indentation must be multiplier of %d.\n",
                            lines[i].get_file().c_str(), lines[i].get_lineno(), j, INDENT);
                    ++error_count;
                }
                line.erase(0, j);
                lines[i].set_column(j);
            }
        }
    }

    Token get_c_keyword(const string &id)
    {
        static const map<string, Token> c_keywords
        {
#include "c_keywords.cpp"
        };
        auto it = c_keywords.find(id);
        if (it == c_keywords.end()) return Token::NO_TOKEN;
        return it->second;
    }

    const char *get_token_string(Token t)
    {
#include "token_strings.cpp"
        auto it = token_strings.find(t);
        if (it == token_strings.end()) return "?";
        return it->second;
    }

    void tokenize_line(const Line &line, vector<TokenInfo> &tokens)
    {
        const unsigned char *p = (const unsigned char*) line.get_ctext().c_str();
        const string &file = line.get_file();
        int lineno = line.get_lineno();
        int column = line.get_column();
        while (*p) {
            if (*p <= ' ') {
                tokens.emplace_back(TokenInfo(Token::SPACE, file, lineno, column, 1));
                ++column;
                ++p;
            } else if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || *p == '_' || *p == '$') {
                const unsigned char *q = p + 1;
                while ((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') || *q == '_' || *q == '$' || (*q >= '0' && *q <= '9')) ++q;
                string id((char*) p, q - p);
                Token k = get_c_keyword(id);
                if (k != Token::NO_TOKEN) {
                    tokens.emplace_back(TokenInfo(k, file, lineno, column, int(id.size())));
                } else {
                    tokens.emplace_back(TokenInfo(Token::IDENT, file, lineno, column, id));
                }
                column += id.size();
                p = q;
            } else if (*p == '\"') {
                const unsigned char *orig_p = p;
                ++p;
                while (*p) {
                    if (*p == '\\' && p[1]) {
                        p += 2;
                    } else if (*p == '\"') {
                        ++p;
                        break;
                    } else {
                        ++p;
                    }
                }
                tokens.emplace_back(TokenInfo(Token::STRING, file, lineno, column, p - orig_p));
                column += (p - orig_p);
            } else if (*p == '\'') {
                // FIXME: check for 'abcd'
                const unsigned char *orig_p = p;
                ++p;
                while (*p) {
                    if (*p == '\\' && p[1]) {
                        p += 2;
                    } else if (*p == '\'') {
                        ++p;
                        break;
                    } else {
                        ++p;
                    }
                }
                tokens.emplace_back(TokenInfo(Token::CHAR_LITERAL, file, lineno, column, p - orig_p));
                column += (p - orig_p);
            } else if (*p == '0') {
                const unsigned char *orig_p = p;
                Token tok = Token::NO_TOKEN;
                ++p;
                if (*p == 'x' || *p == 'X') {
                    ++p;
                    while (isxdigit(*p)) ++p;
                    if (*p == 'p' || *p == 'P') {
                        ++p;
                        if (*p == '+' || *p == '-') ++p;
                        while (*p >= '0' && *p <= '9') ++p;
                        tok = Token::FP_LITERAL;
                    } else if (*p == '.') {
                        ++p;
                        while (isxdigit(*p)) ++p;
                        if (*p == 'p' || *p == 'P') {
                            ++p;
                            if (*p == '+' || *p == '-') ++p;
                            while (*p >= '0' && *p <= '9') ++p;
                        }
                        tok = Token::FP_LITERAL;
                    } else if (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') {
                        while (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') ++p;
                        tok = Token::INT_LITERAL;
                    } else {
                        tok = Token::INT_LITERAL;
                    }
                } else if (*p == 'b' || *p == 'B') {
                    ++p;
                    while (*p == '0' || *p == '1') ++p;
                    if (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') {
                        while (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') ++p;
                        tok = Token::INT_LITERAL;
                    } else {
                        tok = Token::INT_LITERAL;
                    }
                } else if (*p >= '0' && *p <= '9') {
                    // not entirely correct
                    while (*p >= '0' && *p <= '9') ++p;
                    if (*p == '.') {
                        ++p;
                        while (*p >= '0' && *p <= '9') ++p;
                        if (*p == 'e' || *p == 'E') {
                            ++p;
                            if (*p == '+' || *p == '-') ++p;
                            while (*p >= '0' && *p <= '9') ++p;
                        }
                        tok = Token::FP_LITERAL;
                    } else if (*p == 'e' || *p == 'E') {
                        ++p;
                        if (*p == '+' || *p == '-') ++p;
                        while (*p >= '0' && *p <= '9') ++p;
                        tok = Token::FP_LITERAL;
                    } else if (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') {
                        while (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') ++p;
                        tok = Token::INT_LITERAL;
                    } else {
                        tok = Token::INT_LITERAL;
                    }
                } else if (*p == '.') {
                    ++p;
                    while (*p >= '0' && *p <= '9') ++p;
                    if (*p == 'e' || *p == 'E') {
                        ++p;
                        if (*p == '+' || *p == '-') ++p;
                        while (*p >= '0' && *p <= '9') ++p;
                    }
                    tok = Token::FP_LITERAL;
                } else {
                    tok = Token::INT_LITERAL;
                }
                tokens.emplace_back(TokenInfo(tok, file, lineno, column, p - orig_p));
                column += (p - orig_p);
            } else if (*p >= '1' && *p <= '9') {
                const unsigned char *orig_p = p;
                Token tok = Token::NO_TOKEN;
                while (*p >= '0' && *p <= '9') ++p;
                if (*p == '.') {
                    ++p;
                    while (*p >= '0' && *p <= '9') ++p;
                    if (*p == 'e' || *p == 'E') {
                        ++p;
                        if (*p == '+' || *p == '-') ++p;
                        while (*p >= '0' && *p <= '9') ++p;
                    }
                    tok = Token::FP_LITERAL;
                } else if (*p == 'e' || *p == 'E') {
                    ++p;
                    if (*p == '+' || *p == '-') ++p;
                    while (*p >= '0' && *p <= '9') ++p;
                    tok = Token::FP_LITERAL;
                } else if (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') {
                    while (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L') ++p;
                    tok = Token::INT_LITERAL;
                } else {
                    tok = Token::INT_LITERAL;
                }
                tokens.emplace_back(TokenInfo(tok, file, lineno, column, p - orig_p));
                column += (p - orig_p);
            } else if (*p == '+') {
                // +, +=, ++
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::ADD_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else if (p[1] == '+') {
                    tokens.emplace_back(TokenInfo(Token::INCR, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token('+'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '-') {
                // -, ->, ->*, --, -=
                if (p[1] == '>') {
                    if (p[2] == '*') {
                        tokens.emplace_back(TokenInfo(Token::ARROWSTAR, file, lineno, column, 3));
                        column += 3;
                        p += 3;
                    } else {
                        tokens.emplace_back(TokenInfo(Token::ARROW, file, lineno, column, 2));
                        column += 2;
                        p += 2;
                    }
                } else if (p[1] == '-') {
                    tokens.emplace_back(TokenInfo(Token::DECR, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::SUB_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token('-'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '&') {
                if (p[1] == '&') {
                    tokens.emplace_back(TokenInfo(Token::AND, file, lineno, column, 2));
                    column += 2;
                    p += 2;                    
                } else if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::AND_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;                    
                } else {
                    tokens.emplace_back(TokenInfo(Token('&'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '|') {
                if (p[1] == '|') {
                    tokens.emplace_back(TokenInfo(Token::OR, file, lineno, column, 2));
                    column += 2;
                    p += 2;                    
                } else if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::OR_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;                    
                } else {
                    tokens.emplace_back(TokenInfo(Token('|'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '.') {
                if (p[1] == '.' && p[2] == '.') {
                    tokens.emplace_back(TokenInfo(Token::ELLIPSIS, file, lineno, column, 3));
                    column += 3;
                    p += 3;
                } else if (p[1] == '*') {
                    tokens.emplace_back(TokenInfo(Token::DOTSTAR, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token('.'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '/') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::DIV_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token('/'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '=') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::EQ, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token('='), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == ':') {
                if (p[1] == ':') {
                    tokens.emplace_back(TokenInfo(Token::SCOPE, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token(':'), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '^') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::XOR_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '*') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::MUL_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '%') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::MOD_ASSIGN, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '!') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::NOT_EQ, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else {
                    tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '>') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::GEQ, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else if (p[1] == '>') {
                    if (p[2] == '=') {
                        tokens.emplace_back(TokenInfo(Token::RSH_ASSIGN, file, lineno, column, 3));
                        column += 3;
                        p += 3;
                    } else {
                        tokens.emplace_back(TokenInfo(Token::RSHIFT, file, lineno, column, 2));
                        column += 2;
                        p += 2;
                    }
                } else {
                    tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '<') {
                if (p[1] == '=') {
                    tokens.emplace_back(TokenInfo(Token::LEQ, file, lineno, column, 2));
                    column += 2;
                    p += 2;
                } else if (p[1] == '<') {
                    if (p[2] == '=') {
                        tokens.emplace_back(TokenInfo(Token::LSH_ASSIGN, file, lineno, column, 3));
                        column += 3;
                        p += 3;
                    } else {
                        tokens.emplace_back(TokenInfo(Token::LSHIFT, file, lineno, column, 2));
                        column += 2;
                        p += 2;
                    }
                } else {
                    tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                    ++column;
                    ++p;
                }
            } else if (*p == '(' || *p == ')' || *p == ',' || *p == ';' || *p == '?'
                       || *p == '[' || *p == ']' || *p == '{' || *p == '}' || *p == '~') {
                tokens.emplace_back(TokenInfo(Token(*p), file, lineno, column, 1));
                ++column;
                ++p;
            } else {
                tokens.emplace_back(TokenInfo(Token('@'), file, lineno, column, 1));
                ++column;
                ++p;
            }
        }
    }

    void tokenize()
    {
        for (int i = 0; i < int(lines.size()); ++i) {
            vector<TokenInfo> tokens;
            tokenize_line(lines[i], tokens);
            lines[i].set_tokens(move(tokens));
        }
    }

    void append_nows_tokens(vector<TokenInfo> &toks)
    {
        for (int i = 0; i < int(lines.size()); ++i) {
            lines[i].append_nows_tokens(toks);
        }
    }

    void collect_tokens()
    {
        append_nows_tokens(tokens);
        tokens.emplace_back(TokenInfo(Token::EOF_TOKEN, "", 0, 0, 0));
    }

    void dump()
    {
        for (int i = 0; i < int(lines.size()); ++i) {
            /*
            printf("%s:%d:%d:%s\n", lines[i].get_file().c_str(), lines[i].get_lineno(),
                   lines[i].get_column(), lines[i].get_text().c_str());
            */
            printf("%s:%d:%d:", lines[i].get_file().c_str(), lines[i].get_lineno(), lines[i].get_column());
            const vector<TokenInfo> &tokens = lines[i].get_tokens();
            for (int j = 0; j < int(tokens.size()); ++j) {
                TokenInfo t = tokens[j];
                if (t.get_int_token() < 256) {
                    putchar(char(t.get_int_token()));
                } else {
                    printf("%s", get_token_string(t.get_token()));
                }
            }
            printf("\n");
        }
    }

    bool is_opening(int pos)
    {
        Token t = tokens[pos].get_token();
        return t == Token::LPAREN || t == Token::LBRACKET || t == Token::LBRACE;
    }

    bool is_good_type_name(const TokenInfo &id)
    {
        const string &str = id.get_text();
        if (!str.size()) {
            fprintf(stderr, "%s: invalid type name\n", id.get_begpos().to_string().c_str());
            ++error_count;
            return false;
        }
        if (!isupper(str[0])) {
            fprintf(stderr, "%s: type name or type tag must start from a capital letter\n",
                    id.get_begpos().to_string().c_str());
            ++error_count;
            return false;
        }
        for (int i = 0; i < int(str.size()); ++i) {
            if (str[i] == '_') {
                fprintf(stderr, "%s: type name must not contain '_'\n", id.get_begpos().to_string().c_str());
                ++error_count;
                return false;
            }
        }
        return true;
    }

    bool is_good_constant_name(const TokenInfo &id)
    {
        const string &str = id.get_text();
        if (!str.size()) {
            fprintf(stderr, "%s: invalid constant name\n", id.get_begpos().to_string().c_str());
            ++error_count;
            return false;
        }
        for (int i = 0; i < int(str.size()); ++i) {
            if (!isupper(str[i]) && !isdigit(str[i]) && str[i] != '_') {
                fprintf(stderr, "%s: constant name must contain only uppercase letters or digits\n",
                        id.get_begpos().to_string().c_str());
                ++error_count;
                return false;
            }
        }
        return true;
    }

    int skip_to_pairing_bracket(int pos)
    {
        vector<Token> st;
        for (; pos < int(tokens.size()); ++pos) {
            Token t = tokens[pos].get_token();
            switch (t) {
            case Token::EOF_TOKEN: return -1;
            case Token::LPAREN: // (
                st.push_back(Token::RPAREN);
                break;
            case Token::LBRACKET: // [
                st.push_back(Token::RBRACKET);
                break;
            case Token::LBRACE: // {
                st.push_back(Token::RBRACE);
                break;
            case Token::RPAREN:
            case Token::RBRACKET:
            case Token::RBRACE:
                if (!st.size()) return -1;
                if (st.back() != t) return -1;
                st.pop_back();
                if (!st.size()) return pos;
                break;
            default:
                break;
            }
        }
        return -1;
    }

    int top_level_recovery(int pos)
    {
        // skip to the nearest ';' or EOF
        while (pos < int(tokens.size())) {
            Token t = tokens[pos].get_token();
            if (t == Token::EOF_TOKEN) return pos;
            if (t == Token::LPAREN || t == Token::LBRACKET || t == Token::LBRACE) {
                pos = skip_to_pairing_bracket(pos);
                if (pos < 0) return tokens.size() - 1; // no recovery possible, just go to the last token
            }
            ++pos;
        }
        return pos;
    }

    Range is_enum_definition(int pos)
    {
        Token t;
        int orig_pos = pos;
        bool is_typedef = false;
        while ((t = tokens[pos].get_token()) != Token::LPAREN
               && t != Token::SEMICOLON
               && t != Token::LBRACE
               && t != Token::EOF_TOKEN
               && t != Token::LBRACKET
               && t != Token::LESS
               && t != Token::ENUM) {
            if (t == Token::TYPEDEF) is_typedef = true;
            ++pos;
        }
        if (t != Token::ENUM) return Range();
        ++pos;
        if (tokens[pos].get_token() == Token::CLASS) ++pos;
        if (tokens[pos].get_token() == Token::IDENT) ++pos;
        if (tokens[pos].get_token() != Token::LBRACE) return Range();
        if ((pos = skip_to_pairing_bracket(pos)) < 0) return Range();
        ++pos;
        if (is_typedef && tokens[pos].get_token() == Token::IDENT) ++pos;
        if (tokens[pos].get_token() != Token::SEMICOLON) {
            fprintf(stderr, "%s: do not mix type and variable declaration (see 4.1 of coding style rules)\n",
                    tokens[orig_pos].get_begpos().to_string().c_str());
            ++error_count;
            return Range();
        }
        return Range(orig_pos, pos + 1);
    }

    Range is_struct_definition(int pos)
    {
        Token t;
        int orig_pos = pos;
        bool is_typedef = false;
        while ((t = tokens[pos].get_token()) != Token::LPAREN
               && t != Token::SEMICOLON
               && t != Token::LBRACE
               && t != Token::EOF_TOKEN
               && t != Token::LBRACKET
               && t != Token::LESS
               && t != Token::CLASS
               && t != Token::STRUCT
               && t != Token::UNION) {
            if (t == Token::TYPEDEF) is_typedef = true;
            ++pos;
        }
        if (t != Token::CLASS && t!= Token::STRUCT && t != Token::UNION) return Range();
        ++pos;
        if (tokens[pos].get_token() == Token::IDENT) ++pos;
        if (tokens[pos].get_token() != Token::LBRACE) return Range();
        if ((pos = skip_to_pairing_bracket(pos)) < 0) return Range();
        ++pos;
        if (is_typedef && tokens[pos].get_token() == Token::IDENT) ++pos;
        if (tokens[pos].get_token() != Token::SEMICOLON) {
            fprintf(stderr, "%s: do not mix type and variable declaration (see 4.1 of coding style rules)\n",
                    tokens[orig_pos].get_begpos().to_string().c_str());
            ++error_count;
            return Range();
        }
        return Range(orig_pos, pos + 1);
    }

    void check_same_file(Range range)
    {
        const Position &p1 = tokens[range.get_low()].get_begpos();
        for (int i = range.get_low(); i < range.get_high(); ++i) {
            const auto &pp = tokens[i].get_begpos();
            if (pp.get_file() != p1.get_file()) {
                fprintf(stderr, "%s: definition/declaration must not span over file boundary\n",
                        p1.to_string().c_str());
                ++error_count;
                return;
            }
        }
    }

    void check_same_line(Range range)
    {
        const Position &p1 = tokens[range.get_low()].get_begpos();
        for (int i = range.get_low(); i < range.get_high(); ++i) {
            const auto &pp = tokens[i].get_begpos();
            if (pp.get_line() != p1.get_line()) {
                fprintf(stderr, "%s: this token must be on the same line, as token %s\n",
                        pp.to_string().c_str(), p1.to_string().c_str());
                ++error_count;
                return;
            }
        }
    }

    void check_no_space(int pos)
    {
        const auto &pprev = tokens[pos - 1].get_endpos();
        const auto &pcur = tokens[pos].get_begpos();
        if (pprev.get_line() != pcur.get_line()) {
            fprintf(stderr, "%s: this token must be on the same line as previous\n", pcur.to_string().c_str());
            ++error_count;
        } else if (pprev.get_column() + 1 != pcur.get_column()) {
            fprintf(stderr, "%s: no space required between tokens\n", pprev.to_string().c_str());
            ++error_count;
        }
    }

    void check_one_space(int pos)
    {
        const auto &pprev = tokens[pos - 1].get_endpos();
        const auto &pcur = tokens[pos].get_begpos();
        if (pprev.get_line() != pcur.get_line()) {
            fprintf(stderr, "%s: this token must be on the same line as previous\n", pcur.to_string().c_str());
            ++error_count;
        } else if (pprev.get_column() + 2 != pcur.get_column()) {
            fprintf(stderr, "%s: exactly one space required\n", pprev.to_string().c_str());
            ++error_count;
        }
    }

    void handle_enum(Range range, int indent)
    {
        const Position &p1 = tokens[range.get_low()].get_begpos();
        //const Position &p2 = tokens[range.get_high() - 1].get_endpos();

        check_same_file(range);

        bool is_typedef = false;
        int pos = range.get_low();
        if (p1.get_column() != indent) {
            fprintf(stderr, "%s: invalid indentation: %d expected, but %d actual\n",
                    p1.to_string().c_str(), indent, p1.get_column());
            ++error_count;
        }
        while (1) {
            if (pos >= range.get_high()) abort();
            if (pos > range.get_low()) {
                check_one_space(pos);
            }
            if (tokens[pos].get_token() == Token::ENUM) break;
            if (tokens[pos].get_token() == Token::TYPEDEF) is_typedef = true;
            ++pos;
        }
        (void) is_typedef;

        ++pos;
        if (tokens[pos].get_token() == Token::IDENT) {
            check_one_space(pos);
            is_good_type_name(tokens[pos]);
            ++pos;
        }
        if (tokens[pos].get_token() != Token::LBRACE) abort();
        if (tokens[pos].get_begpos().get_line() == tokens[pos - 1].get_begpos().get_line()) {
            // single line enum: enum TAG { NAME1 = VAL1, NAME2 = VAL2 };
            check_same_line(range);
            check_one_space(pos);
            ++pos;
            while (1) {
                if (tokens[pos].get_token() == Token::RBRACE) {
                    check_no_space(pos);
                    ++pos;
                    break;
                }
                if (tokens[pos].get_token() != Token::IDENT) {
                    fprintf(stderr, "IDENT expected\n");
                    return;
                }
                is_good_constant_name(tokens[pos]);
                check_one_space(pos);
                ++pos;
                if (tokens[pos].get_token() == Token::RBRACE) {
                    check_one_space(pos);
                    ++pos;
                    break;
                }
                if (tokens[pos].get_token() == Token::COMMA) {
                    check_no_space(pos);
                    ++pos;
                    if (tokens[pos].get_token() == Token::RBRACE) {
                        check_one_space(pos);
                        ++pos;
                        break;
                    }
                } else if (tokens[pos].get_token() == Token::EQUAL) {
                    check_one_space(pos);
                    ++pos;
                    check_one_space(pos);
                    // scan to ',' or '}' or EOF
                    int pos1 = pos;
                    while (1) {
                        if (is_opening(pos1)) {
                            pos1 = skip_to_pairing_bracket(pos1);
                            if (pos1 < 0) return;
                            ++pos1;
                        } else if (tokens[pos1].get_token() == Token::RBRACE || tokens[pos1].get_token() == Token::COMMA) {
                            break;
                        } else {
                            ++pos1;
                        }
                    }
                    // [pos; pos1) is expression, check it
                    pos = pos1;
                    if (tokens[pos].get_token() == Token::RBRACE) {
                        check_one_space(pos);
                        ++pos;
                        break;
                    }
                    if (tokens[pos].get_token() == Token::COMMA) {
                        check_no_space(pos);
                        ++pos;
                        if (tokens[pos].get_token() == Token::RBRACE) {
                            check_one_space(pos);
                            ++pos;
                            break;
                        }
                    }
                } else {
                    fprintf(stderr, "!\n");
                    return;
                }
            }
            if (tokens[pos].get_token() == Token::IDENT) {
                check_one_space(pos);
                is_good_type_name(tokens[pos]);
                ++pos;
            }
            check_no_space(pos);
            //if (tokens[pos].get_token() != Token::SEMICOLON) abort();
        } else {
            // enum TAG
            // {
            //     C = V,
            // };

            // { must be on the next line with initial column
            const Position &lbp = tokens[pos].get_begpos();
            if (lbp.get_line() != p1.get_line() + 1 || lbp.get_column() != indent) {
                fprintf(stderr, "%s: invalid location of '{' in multi-line enum\n", lbp.to_string().c_str());
                ++error_count;
            }
            ++pos;
            int cur_line = lbp.get_line();
            while (1) {
                ++cur_line;
                if (tokens[pos].get_token() == Token::RBRACE) {
                    break;
                }
                if (tokens[pos].get_token() != Token::IDENT) {
                    fprintf(stderr, "IDENT expected\n");
                    return;
                }
                is_good_constant_name(tokens[pos]);
                const Position &cbp = tokens[pos].get_begpos();
                if (cbp.get_line() != cur_line || cbp.get_column() != indent + INDENT) {
                    fprintf(stderr, "%s: invalid location of enumeration constant in multi-line enum\n", cbp.to_string().c_str());
                    ++error_count;
                }
                ++pos;
                if (tokens[pos].get_token() == Token::RBRACE) {
                    continue;
                }
                if (tokens[pos].get_token() == Token::COMMA) {
                    check_no_space(pos);
                    ++pos;
                    continue;
                }
                if (tokens[pos].get_token() != Token::EQUAL) return;
                check_one_space(pos);
                ++pos;
                check_one_space(pos);
                // scan to ',' or '}' or EOF
                int pos1 = pos;
                while (1) {
                    if (is_opening(pos1)) {
                        pos1 = skip_to_pairing_bracket(pos1);
                        if (pos1 < 0) return;
                        ++pos1;
                    } else if (tokens[pos1].get_token() == Token::RBRACE || tokens[pos1].get_token() == Token::COMMA) {
                        break;
                    } else {
                        ++pos1;
                    }
                }
                // [pos; pos1) is expression, check it
                check_same_line(Range(pos - 1, pos1));
                pos = pos1;
                if (tokens[pos].get_token() == Token::COMMA) {
                    check_no_space(pos);
                    ++pos;
                }
            }
            const Position &rbp = tokens[pos].get_begpos();
            if (rbp.get_line() != cur_line || rbp.get_column() != indent) {
                fprintf(stderr, "%s: invalid location of '}' in multi-line enum\n", lbp.to_string().c_str());
                ++error_count;
            }
            ++pos;
            if (tokens[pos].get_token() == Token::IDENT) {
                check_one_space(pos);
                is_good_type_name(tokens[pos]);
                ++pos;
            }
            check_no_space(pos);
        }
    }

    void handle_struct(Range range, int indent)
    {
        const Position &p1 = tokens[range.get_low()].get_begpos();
        check_same_file(range);

        bool is_typedef = false;
        int pos = range.get_low();
        if (p1.get_column() != indent) {
            fprintf(stderr, "%s: invalid indentation: %d expected, but %d actual\n",
                    p1.to_string().c_str(), indent, p1.get_column());
            ++error_count;
        }

        while (1) {
            if (pos >= range.get_high()) abort();
            if (pos > range.get_low()) {
                check_one_space(pos);
            }
            if (tokens[pos].get_token() == Token::STRUCT || tokens[pos].get_token() == Token::UNION || tokens[pos].get_token() == Token::CLASS) break;
            if (tokens[pos].get_token() == Token::TYPEDEF) is_typedef = true;
            ++pos;
        }
        (void) is_typedef;

        ++pos;
        if (tokens[pos].get_token() == Token::IDENT) {
            check_one_space(pos);
            is_good_type_name(tokens[pos]);
            ++pos;
        }
        if (tokens[pos].get_token() != Token::LBRACE) abort();
            // { must be on the next line with initial column
        const Position &lbp = tokens[pos].get_begpos();
        if (lbp.get_line() != p1.get_line() + 1 || lbp.get_column() != indent) {
            fprintf(stderr, "%s: invalid location of '{' in struct/union/class\n", lbp.to_string().c_str());
            ++error_count;
        }

        //++pos;
        // seek for the pairing }
        // handle struct def
        pos = skip_to_pairing_bracket(pos);
        if (pos < 0) return;
        const Position &rbp = tokens[pos].get_begpos();
        if (rbp.get_column() != indent) {
            fprintf(stderr, "%s: invalid location of '}' in struct/class/enum\n", lbp.to_string().c_str());
            ++error_count;
        }
        ++pos;
        if (tokens[pos].get_token() == Token::IDENT) {
            check_one_space(pos);
            is_good_type_name(tokens[pos]);
            ++pos;
        }
        check_no_space(pos);
    }

    void parse()
    {
        Range r;
        int cur = 0;
        while (cur < int(tokens.size())) {
            if (tokens[cur].get_token() == Token::EOF_TOKEN) break;
            if ((r = is_enum_definition(cur))) {
                handle_enum(r, 0);
                cur = r.get_high();
            } else if ((r = is_struct_definition(cur))) {
                handle_struct(r, 0);
                cur = r.get_high();
            } else {
                cur = top_level_recovery(cur);
            }
        }
    }
};

namespace std {
template<> struct iterator_traits<SourceFile::CharIterator>
{
    typedef ptrdiff_t difference_type;
    typedef char      value_type;
    typedef char&     reference;
    typedef char*     pointer;
    typedef bidirectional_iterator_tag iterator_category;
};
}

int handle_stream(const char *name, FILE *fin)
{
    SourceFile sf;

    if (!sf.read_file(name, fin)) return 2;

    //for (auto c : sf) {
    //    putchar(c);
    //}

    //vector<char*> vpc = sf.get_char_vector();
    //for (auto pc : vpc) {
    //    putchar(*pc);
    //}

    if (!sf.handle_comments_1()) return 1;
    sf.trim();
    sf.handle_cpp_1();
    sf.handle_characters();
    if (sf.get_error_count() > 0) return 1;

    sf.trim();
    sf.remove_empty_lines();
    sf.remove_first_spaces();
    sf.tokenize();
    sf.collect_tokens();

    sf.parse();

    //sf.dump();

    if (sf.get_error_count() > 0) return 1;

    return 0;
}

int handle_stdin()
{
    return handle_stream("<stdin>", stdin);
}

int handle_file(const char *file)
{
    if (!file || !strcmp(file, "-")) {
        return handle_stdin();
    }
    FILE *fin = fopen(file, "r");
    if (!fin) {
        fprintf(stderr, "%s: failed to open input file '%s': %s\n", program_name, file, strerror(errno));
        return 2;
    }
    int retval = handle_stream(file, fin);
    fclose(fin);
    return retval;
}

int main(int argc, char **argv)
{
    program_name = argv[0];
    int argi = 1;
    int retval = 0;

    // here handle command line args

    if (argi == argc) {
        int val = handle_stdin();
        if (val > retval) retval = val;
    } else {
        for (; argi < argc; ++argi) {
            int val = handle_file(argv[argi]);
            if (val > retval) retval = val;
        }
    }

    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 *  compile-command: "g++ -Wall -Werror -std=gnu++14 -g new_style_c.cpp -o new_style_c"
 * End:
 */
