/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2026 Alexander Chernov <cher@ejudge.ru> */

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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/random.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/wait.h>

static const char *program_name;

#define DIE(format, ...) do { fprintf(stderr, "%s:%s:%d:fatal:" format, program_name, __FILE__, __LINE__, ##__VA_ARGS__); exit(1); } while(0)

static int
count_system_users(const char *system_user_prefix)
{
    __attribute__((unused)) int _;
    int i = 0;
    char *login = NULL;
    while (1) {
        free(login); login = NULL;
        if (i == 0) {
            login = strdup(system_user_prefix);
        } else {
            _ = asprintf(&login, "%s%d", system_user_prefix, i);
        }
        struct passwd *pwd = getpwnam(login);
        if (!pwd) break;
        ++i;
    }
    free(login);
    return i;
}

static char const base64_encode_table[]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";

static int
base64_encode(unsigned char const *in, size_t size, char *out)
{
  unsigned int   ebuf;
  int            nw = size / 3;
  int            l = size - nw * 3;
  int            i;
  unsigned char const    *p = in;
  unsigned char          *s = (unsigned char *) out;

  for (i = 0; i < nw; i++) {
    ebuf  = *(unsigned const char*) p++ << 16;
    ebuf |= *(unsigned const char*) p++ << 8;
    ebuf |= *(unsigned const char*) p++;
    ebuf += (ebuf & ~0x3FFFF);
    ebuf += (ebuf & ~0x3FFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64_encode_table[ebuf >> 24];
    *s++ = base64_encode_table[(ebuf >> 16) & 0xFF];
    *s++ = base64_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64_encode_table[ebuf & 0xFF];
  }
  if (l == 2) {
    /* make a 18-bit group */
    ebuf  = *(unsigned const char*) p++ << 10;
    ebuf |= *(unsigned const char*) p++ << 2;
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64_encode_table[(ebuf >> 16) & 0xFF];
    *s++ = base64_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64_encode_table[ebuf & 0xFF];
  } else if (l == 1) {
    /* make a 12-bit group */
    ebuf = *(unsigned const char*) p++ << 4;
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64_encode_table[ebuf & 0xFF];
  }
  return (char *) s - out;
}

static char *
get_random_password()
{
    enum { RANDOM_SIZE = 15 };
    unsigned char rb[RANDOM_SIZE];
    char out[RANDOM_SIZE * 2 + 1];
    if (getrandom(rb, sizeof(rb), 0) < 0) {
        DIE("getrandom failed: %s", strerror(errno));
    }
    int res = base64_encode(rb, sizeof(rb), out);
    out[res] = 0;
    return strdup(out);
}

static int
run_psql(
        const char *host,
        const char *port,
        const char *user,
        const char *password,
        const char *database,
        int ignore_stdout,
        int html_output_flag,
        int tuples_only_flag,
        ...)
{
    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed: %s\n", program_name,
                strerror(errno));
        return -1;
    }
    if (!pid) {
        const char *args[64];
        int i = 0;

        if (password) {
            setenv("PGPASSWORD", password, 1);
        }
        args[i++] = "psql";
        args[i++] = "-h";
        args[i++] = host;
        args[i++] = "-p";
        args[i++] = port;
        args[i++] = "-U";
        args[i++] = user;
        if (database) {
            args[i++] = "-d";
            args[i++] = database;
        }
        args[i++] = "-X";
        args[i++] = "-w";
        if (html_output_flag > 0) {
            args[i++] = "--html";
        } else {
            args[i++] = "--csv";
        }
        if (tuples_only_flag > 0) {
            args[i++] = "-t";
        }
        args[i++] = "-q";

        va_list lst;
        va_start(lst, tuples_only_flag);
        const char *ptr = NULL;
        while ((ptr = va_arg(lst, const char *))) {
            args[i++] = ptr;
        }
        va_end(lst);
        args[i] = NULL;

        if (ignore_stdout) {
            int fd = open("/dev/null", O_WRONLY | O_CLOEXEC, 0);
            if (fd < 0) {
                _exit(1);
            }
            dup2(fd, 1);
        }

        execvp(args[0], (char**) args);
        fprintf(stderr, "%s: exec failed: %s\n", program_name,
                strerror(errno));
        _exit(1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "%s: psql terminated with signal %d\n",
                program_name, WTERMSIG(status));
        return 256 + WTERMSIG(status);
    }
    if (!WIFEXITED(status)) {
        abort();
    }
    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: psql exited with status %d\n",
                program_name, WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }
    return 0;
}

static int
create_user(
        const char *host,
        const char *port,
        const char *root_user,
        const char *root_password,
        const char *new_user,
        const char *new_password)
{
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "CREATE USER %s WITH PASSWORD '%s';", new_user, new_password);
    fclose(cmd_f); cmd_f = NULL;
    int r = run_psql(host, port, root_user, root_password, NULL,
                     1 /* ignore_stdout */,
                     0 /* html_output_flag */,
                     0 /* tuples_only_flag */,
                     "-c", cmd_s, NULL);
    free(cmd_s); cmd_s = NULL;

    return r;
}

static void
create_all_users(
        const char *host,
        const char *port,
        const char *root_user,
        const char *root_password,
        const char *user_prefix,
        char **user_passwords,
        int user_count)
{
    __attribute__((unused)) int _;
    char *new_user = NULL;
    for (int i = 0; i < user_count; ++i) {
        free(new_user); new_user = NULL;
        if (i == 0) {
            new_user = strdup(user_prefix);
        } else {
            _ = asprintf(&new_user, "%s%d", user_prefix, i);
        }
        int r = create_user(host, port, root_user, root_password, new_user, user_passwords[i]);
        if (r != 0) {
            DIE("user creation failed on user %s", new_user);
        }
    }
    free(new_user);
}

int
main(int argc, char *argv[])
{
    int argi = 1;
    const char *host = "127.0.0.1";
    const char *port = "15432";
    const char *base_prefix = "testdb";
    const char *root_user = "postgres";
    const char *root_password = NULL;
    const char *user_prefix = "ejexec";
    const char *system_user_prefix = "ejexec";

    {
        const char *p = strrchr(argv[0], '/');
        if (p) {
            program_name = p + 1;
        } else {
            program_name = argv[0];
        }
    }

    while (argi < argc) {
        if (!strcmp(argv[argi], "--host")) {
            if (argi + 1 == argc) DIE("argument required for --host");
            host = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--port")) {
            if (argi + 1 == argc) DIE("argument required for --port");
            port = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--base-prefix")) {
            if (argi + 1 == argc) DIE("argument required for --base-prefix");
            base_prefix = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--root-user")) {
            if (argi + 1 == argc) DIE("argument required for --root-user");
            root_user = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--user-prefix")) {
            if (argi + 1 == argc) DIE("argument required for --user-prefix");
            user_prefix = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--system-user-prefix")) {
            if (argi + 1 == argc) DIE("argument required for --system-user-prefix");
            system_user_prefix = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--root-password")) {
            if (argi + 1 == argc) DIE("argument required for --root-password");
            root_password = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        } else if (argv[argi][0] == '-') {
            DIE("invalid option %s", argv[argi]);
        } else {
            break;
        }
    }
    if (argi < argc) {
        DIE("invalid command line");
    }
    if (!root_password || !*root_password) {
        DIE("root password is undefined");
    }

    int required_users = count_system_users(system_user_prefix);
    if (required_users <= 0) {
        DIE("no system users found");
    }

    char **user_passwords = calloc(required_users, sizeof(user_passwords[0]));
    for (int i = 0; i < required_users; ++i) {
        user_passwords[i] = get_random_password();
    }

    create_all_users(host, port, root_user, root_password, user_prefix, user_passwords, required_users);

    printf("PGHOST=%s\n", host);
    printf("PGPORT=%s\n", port);
    printf("PG_BASE_PREFIX=%s\n", base_prefix);
    printf("PG_ROOT_USER=%s\n", root_user);
    printf("PG_ROOT_PASSWORD=%s\n", root_password);
    printf("PG_USER_PREFIX=%s\n", user_prefix);
    printf("PG_PASSWORDS=");
    for (int i = 0; i < required_users; ++i) {
        if (i > 0) putchar(':');
        printf("%s", user_passwords[i]);
    }
    printf("\n");
}
