/* -*- mode: c -*- */
/* $Id$ */

#ifndef NEED_CORR
#error You must define NEED_CORR macro
#endif /* NEED_CORR */
#ifndef NEED_INFO
#error You must define NEED_INFO macro
#endif /* NEED_INFO */
#ifndef NEED_TGZ
#define NEED_TGZ 0
#endif /* NEED_TGZ */

#include "checker_internal.h"

#if NEED_INFO == 1
#include "testinfo.h"
int (*testinfo_parse_func)(const unsigned char*,testinfo_t*) = testinfo_parse;
const unsigned char *(*testinfo_strerror_func)(int) = testinfo_strerror;
extern testinfo_t test_info;
#else
struct testinfo_struct;
int (*testinfo_parse_func)(const unsigned char*,struct testinfo_struct*) = 0;
const unsigned char *(*testinfo_strerror_func)(int) = 0;
#endif /* NEED_INFO */

extern int checker_main(int, char **);
int
main(int argc, char **argv)
{
  checker_do_init(argc, argv, NEED_CORR, NEED_INFO, NEED_TGZ);
  return checker_main(argc, argv);
}


