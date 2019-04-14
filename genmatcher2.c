#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static char *
fix_for_c_enum_str(char *s)
{
    for (int i = 0; s[i]; ++i) {
    }
    return s;
}

static int
sort_func(const void *p1, const void *p2)
{
    return strcmp(*(const char**) p1, *(const char **) p2);
}

int main(int argc, char *argv[])
{
    char *str = NULL;
    size_t strz = 0;
    ssize_t ret;

    char **strs = NULL;
    size_t strsu = 0, strsa = 0;
    char **sorted_strs = NULL;

    char *enum_prefix = NULL;
    char *function_name = NULL;

    if (argc > 0) {
        enum_prefix = argv[1];
    }
    if (argc > 1) {
        function_name = argv[2];
    }
    if (!enum_prefix) enum_prefix = "Tag_";
    if (!function_name) function_name = "match";

    while ((ret = getline(&str, &strz, stdin)) > 0) {
        while (ret > 0 && isspace((unsigned char) str[ret - 1])) --ret;
        str[ret] = 0;
        if (ret <= 0) {
            str = NULL;
            strz = 0;
            continue;
        }
        if (strlen(str) != ret) abort();

        if (strsu == strsa) {
            if (!(strsa *= 2)) strsa = 16;
            strs = realloc(strs, strsa * sizeof(strs[0]));
        }
        strs[strsu++] = str;

        str = NULL;
        strz = 0;
    }

    if (strsu <= 0) {
        exit(0);
    }

    sorted_strs = calloc(strsu, sizeof(sorted_strs[0]));
    memcpy(sorted_strs, strs, strsu * sizeof(sorted_strs[0]));
    qsort(sorted_strs, strsu, sizeof(strs[0]), sort_func);

    // generate enum
    printf("enum\n"
           "{\n");
    for (int i = 0; i < strsu; ++i) {
        char *fixstr = strdup(strs[i]);
        printf("    %s%s", enum_prefix, fix_for_c_enum_str(fixstr));
        free(fixstr);
        if (!i) {
            printf(" = 1");
        }
        if (i != strsu - 1) {
            printf(",");
        }
        printf("\n");
    }
    printf("};\n");
    printf("int\n"
           "%s(const char *s)\n"
           "{\n", function_name);
    printf("    return 0;\n"
           "}\n\n");
}
