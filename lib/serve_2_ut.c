#include <stdlib.h>
#include <check.h>

#include "ejudge/serve_state.h"
#include "ejudge/prepare.h"

char **
filter_lang_environ(
        serve_state_t state,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        const struct section_tester_data *tester,
        char **environ);

START_TEST(test_filter_env)
{
    struct serve_state state = {0};
    struct section_problem_data prob = {0};
    struct section_language_data lang = {
        .short_name = "gcc-32",
    };
    struct section_tester_data tester = {0};
    char *environ[] = {
        "gcc-32=a=1",
        "gcc=b=2",
        "*=c=3",
        NULL
    };
    char **newenv = filter_lang_environ(&state, &prob, &lang, &tester, environ);
    ck_assert_str_eq(newenv[0], "a=1");
    ck_assert_str_eq(newenv[1], "c=3");
    ck_assert(newenv[2] == NULL);
}
END_TEST

Suite * serve_2_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Serve_2");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_filter_env);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = serve_2_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
