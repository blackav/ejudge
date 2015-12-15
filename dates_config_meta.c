// This is an auto-generated file, do not edit

#include "ejudge/meta/dates_config_meta.h"
#include "ejudge/dates_config.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_dates_global_data_data[] =
{
  [META_DATES_GLOBAL_DATA_deadline] = { META_DATES_GLOBAL_DATA_deadline, 't', XSIZE(struct dates_global_data, deadline), "deadline", XOFFSET(struct dates_global_data, deadline) },
  [META_DATES_GLOBAL_DATA_start_date] = { META_DATES_GLOBAL_DATA_start_date, 't', XSIZE(struct dates_global_data, start_date), "start_date", XOFFSET(struct dates_global_data, start_date) },
  [META_DATES_GLOBAL_DATA_date_penalty] = { META_DATES_GLOBAL_DATA_date_penalty, 'x', XSIZE(struct dates_global_data, date_penalty), "date_penalty", XOFFSET(struct dates_global_data, date_penalty) },
  [META_DATES_GLOBAL_DATA_group_start_date] = { META_DATES_GLOBAL_DATA_group_start_date, 'x', XSIZE(struct dates_global_data, group_start_date), "group_start_date", XOFFSET(struct dates_global_data, group_start_date) },
  [META_DATES_GLOBAL_DATA_group_deadline] = { META_DATES_GLOBAL_DATA_group_deadline, 'x', XSIZE(struct dates_global_data, group_deadline), "group_deadline", XOFFSET(struct dates_global_data, group_deadline) },
  [META_DATES_GLOBAL_DATA_personal_deadline] = { META_DATES_GLOBAL_DATA_personal_deadline, 'x', XSIZE(struct dates_global_data, personal_deadline), "personal_deadline", XOFFSET(struct dates_global_data, personal_deadline) },
};

int meta_dates_global_data_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_GLOBAL_DATA_LAST_FIELD);
  return meta_info_dates_global_data_data[tag].type;
}

size_t meta_dates_global_data_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_GLOBAL_DATA_LAST_FIELD);
  return meta_info_dates_global_data_data[tag].size;
}

const char *meta_dates_global_data_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_GLOBAL_DATA_LAST_FIELD);
  return meta_info_dates_global_data_data[tag].name;
}

const void *meta_dates_global_data_get_ptr(const struct dates_global_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_GLOBAL_DATA_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_dates_global_data_data[tag].offset);
}

void *meta_dates_global_data_get_ptr_nc(struct dates_global_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_GLOBAL_DATA_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_dates_global_data_data[tag].offset);
}

int meta_dates_global_data_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_dates_global_data_data, META_DATES_GLOBAL_DATA_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_dates_global_data_methods =
{
  META_DATES_GLOBAL_DATA_LAST_FIELD,
  sizeof(struct dates_global_data),
  meta_dates_global_data_get_type,
  meta_dates_global_data_get_size,
  meta_dates_global_data_get_name,
  (const void *(*)(const void *ptr, int tag))meta_dates_global_data_get_ptr,
  (void *(*)(void *ptr, int tag))meta_dates_global_data_get_ptr_nc,
  meta_dates_global_data_lookup_field,
};

static struct meta_info_item meta_info_dates_problem_data_data[] =
{
  [META_DATES_PROBLEM_DATA_abstract] = { META_DATES_PROBLEM_DATA_abstract, 'B', XSIZE(struct dates_problem_data, abstract), "abstract", XOFFSET(struct dates_problem_data, abstract) },
  [META_DATES_PROBLEM_DATA_super] = { META_DATES_PROBLEM_DATA_super, 's', XSIZE(struct dates_problem_data, super), "super", XOFFSET(struct dates_problem_data, super) },
  [META_DATES_PROBLEM_DATA_short_name] = { META_DATES_PROBLEM_DATA_short_name, 's', XSIZE(struct dates_problem_data, short_name), "short_name", XOFFSET(struct dates_problem_data, short_name) },
  [META_DATES_PROBLEM_DATA_use_dates_of] = { META_DATES_PROBLEM_DATA_use_dates_of, 's', XSIZE(struct dates_problem_data, use_dates_of), "use_dates_of", XOFFSET(struct dates_problem_data, use_dates_of) },
  [META_DATES_PROBLEM_DATA_deadline] = { META_DATES_PROBLEM_DATA_deadline, 't', XSIZE(struct dates_problem_data, deadline), "deadline", XOFFSET(struct dates_problem_data, deadline) },
  [META_DATES_PROBLEM_DATA_start_date] = { META_DATES_PROBLEM_DATA_start_date, 't', XSIZE(struct dates_problem_data, start_date), "start_date", XOFFSET(struct dates_problem_data, start_date) },
  [META_DATES_PROBLEM_DATA_date_penalty] = { META_DATES_PROBLEM_DATA_date_penalty, 'x', XSIZE(struct dates_problem_data, date_penalty), "date_penalty", XOFFSET(struct dates_problem_data, date_penalty) },
  [META_DATES_PROBLEM_DATA_group_start_date] = { META_DATES_PROBLEM_DATA_group_start_date, 'x', XSIZE(struct dates_problem_data, group_start_date), "group_start_date", XOFFSET(struct dates_problem_data, group_start_date) },
  [META_DATES_PROBLEM_DATA_group_deadline] = { META_DATES_PROBLEM_DATA_group_deadline, 'x', XSIZE(struct dates_problem_data, group_deadline), "group_deadline", XOFFSET(struct dates_problem_data, group_deadline) },
  [META_DATES_PROBLEM_DATA_personal_deadline] = { META_DATES_PROBLEM_DATA_personal_deadline, 'x', XSIZE(struct dates_problem_data, personal_deadline), "personal_deadline", XOFFSET(struct dates_problem_data, personal_deadline) },
  [META_DATES_PROBLEM_DATA_extid] = { META_DATES_PROBLEM_DATA_extid, 's', XSIZE(struct dates_problem_data, extid), "extid", XOFFSET(struct dates_problem_data, extid) },
};

int meta_dates_problem_data_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_PROBLEM_DATA_LAST_FIELD);
  return meta_info_dates_problem_data_data[tag].type;
}

size_t meta_dates_problem_data_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_PROBLEM_DATA_LAST_FIELD);
  return meta_info_dates_problem_data_data[tag].size;
}

const char *meta_dates_problem_data_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_PROBLEM_DATA_LAST_FIELD);
  return meta_info_dates_problem_data_data[tag].name;
}

const void *meta_dates_problem_data_get_ptr(const struct dates_problem_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_PROBLEM_DATA_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_dates_problem_data_data[tag].offset);
}

void *meta_dates_problem_data_get_ptr_nc(struct dates_problem_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_DATES_PROBLEM_DATA_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_dates_problem_data_data[tag].offset);
}

int meta_dates_problem_data_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_dates_problem_data_data, META_DATES_PROBLEM_DATA_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_dates_problem_data_methods =
{
  META_DATES_PROBLEM_DATA_LAST_FIELD,
  sizeof(struct dates_problem_data),
  meta_dates_problem_data_get_type,
  meta_dates_problem_data_get_size,
  meta_dates_problem_data_get_name,
  (const void *(*)(const void *ptr, int tag))meta_dates_problem_data_get_ptr,
  (void *(*)(void *ptr, int tag))meta_dates_problem_data_get_ptr_nc,
  meta_dates_problem_data_lookup_field,
};

