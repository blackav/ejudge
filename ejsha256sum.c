#include "./include/ejudge/sha256.h"
#include "./include/ejudge/sha256utils.h"
#include <stdio.h>
#include <string.h>

struct sha256hash
{
    uint8_t hash[SHA256_BLOCK_SIZE];
};

struct sha256string
{
    char str[80];
};

static void
process_stream(FILE *in, struct sha256hash *result)
{
    SHA256_CTX cntx;
    uint8_t buf[1024];

    sha256_init(&cntx);
    while (1) {
        size_t rsz = fread(buf, 1, sizeof(buf), in);
        if (!rsz) break;
        sha256_update(&cntx, buf, rsz);
    }
    sha256_final(&cntx, result->hash);
}

static void
sha256_to_string(const struct sha256hash *in, struct sha256string *result)
{
    char *p = result->str;
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        sprintf(p, "%02x", in->hash[i]);
        p += 2;
    }
    *p = 0;
}

static void
process_stdin(void)
{
    struct sha256hash hash;
    struct sha256string str;
    process_stream(stdin, &hash);
    sha256_to_string(&hash, &str);
    printf("%s  %s\n", str.str, "-");
}

static void
process_stdin_b64(void)
{
    char result[64];
    sha256b64file(result, sizeof(result), stdin);
    printf("%s  %s\n", result, "-");
}

static void
process_file(const char *path)
{
    struct sha256hash hash;
    struct sha256string str;
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open file '%s'\n", path);
        return;
    }
    process_stream(f, &hash);
    sha256_to_string(&hash, &str);
    printf("%s  %s\n", str.str, path);
    fclose(f);
}

int
main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "-b")) {
        process_stdin_b64();
    } else if (argc == 1) {
        process_stdin();
    } else {
        for (int i = 1; i < argc; ++i) {
            process_file(argv[i]);
        }
    }
}
