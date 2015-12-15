// This is an auto-generated file, do not edit

#ifndef __DATES_CONFIG_META_H__
#define __DATES_CONFIG_META_H__

#include <stdlib.h>

enum
{
  META_DATES_GLOBAL_DATA_deadline = 1,
  META_DATES_GLOBAL_DATA_start_date,
  META_DATES_GLOBAL_DATA_date_penalty,
  META_DATES_GLOBAL_DATA_group_start_date,
  META_DATES_GLOBAL_DATA_group_deadline,
  META_DATES_GLOBAL_DATA_personal_deadline,

  META_DATES_GLOBAL_DATA_LAST_FIELD,
};

struct dates_global_data;

int meta_dates_global_data_get_type(int tag);
size_t meta_dates_global_data_get_size(int tag);
const char *meta_dates_global_data_get_name(int tag);
const void *meta_dates_global_data_get_ptr(const struct dates_global_data *ptr, int tag);
void *meta_dates_global_data_get_ptr_nc(struct dates_global_data *ptr, int tag);
int meta_dates_global_data_lookup_field(const char *name);

struct meta_methods;
extern const struct meta_methods meta_dates_global_data_methods;


enum
{
  META_DATES_PROBLEM_DATA_abstract = 1,
  META_DATES_PROBLEM_DATA_super,
  META_DATES_PROBLEM_DATA_short_name,
  META_DATES_PROBLEM_DATA_use_dates_of,
  META_DATES_PROBLEM_DATA_deadline,
  META_DATES_PROBLEM_DATA_start_date,
  META_DATES_PROBLEM_DATA_date_penalty,
  META_DATES_PROBLEM_DATA_group_start_date,
  META_DATES_PROBLEM_DATA_group_deadline,
  META_DATES_PROBLEM_DATA_personal_deadline,
  META_DATES_PROBLEM_DATA_extid,

  META_DATES_PROBLEM_DATA_LAST_FIELD,
};

struct dates_problem_data;

int meta_dates_problem_data_get_type(int tag);
size_t meta_dates_problem_data_get_size(int tag);
const char *meta_dates_problem_data_get_name(int tag);
const void *meta_dates_problem_data_get_ptr(const struct dates_problem_data *ptr, int tag);
void *meta_dates_problem_data_get_ptr_nc(struct dates_problem_data *ptr, int tag);
int meta_dates_problem_data_lookup_field(const char *name);

struct meta_methods;
extern const struct meta_methods meta_dates_problem_data_methods;

#endif
