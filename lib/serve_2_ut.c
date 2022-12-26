#include <stdlib.h>
#include <check.h>

START_TEST(test_filter_env)
{
    ck_assert(0);
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
