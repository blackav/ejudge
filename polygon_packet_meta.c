// This is an auto-generated file, do not edit
// Generated 2013/10/02 11:57:41

#include "polygon_packet_meta.h"
#include "polygon_packet.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_polygon_packet_data[] =
{
  [META_POLYGON_PACKET_sleep_interval] = { META_POLYGON_PACKET_sleep_interval, 'i', XSIZE(struct polygon_packet, sleep_interval), "sleep_interval", XOFFSET(struct polygon_packet, sleep_interval) },
  [META_POLYGON_PACKET_enable_max_stack_size] = { META_POLYGON_PACKET_enable_max_stack_size, 'B', XSIZE(struct polygon_packet, enable_max_stack_size), "enable_max_stack_size", XOFFSET(struct polygon_packet, enable_max_stack_size) },
  [META_POLYGON_PACKET_create_mode] = { META_POLYGON_PACKET_create_mode, 'B', XSIZE(struct polygon_packet, create_mode), "create_mode", XOFFSET(struct polygon_packet, create_mode) },
  [META_POLYGON_PACKET_retry_count] = { META_POLYGON_PACKET_retry_count, 'i', XSIZE(struct polygon_packet, retry_count), "retry_count", XOFFSET(struct polygon_packet, retry_count) },
  [META_POLYGON_PACKET_polygon_url] = { META_POLYGON_PACKET_polygon_url, 's', XSIZE(struct polygon_packet, polygon_url), "polygon_url", XOFFSET(struct polygon_packet, polygon_url) },
  [META_POLYGON_PACKET_login] = { META_POLYGON_PACKET_login, 's', XSIZE(struct polygon_packet, login), "login", XOFFSET(struct polygon_packet, login) },
  [META_POLYGON_PACKET_password] = { META_POLYGON_PACKET_password, 's', XSIZE(struct polygon_packet, password), "password", XOFFSET(struct polygon_packet, password) },
  [META_POLYGON_PACKET_user_agent] = { META_POLYGON_PACKET_user_agent, 's', XSIZE(struct polygon_packet, user_agent), "user_agent", XOFFSET(struct polygon_packet, user_agent) },
  [META_POLYGON_PACKET_log_file] = { META_POLYGON_PACKET_log_file, 's', XSIZE(struct polygon_packet, log_file), "log_file", XOFFSET(struct polygon_packet, log_file) },
  [META_POLYGON_PACKET_status_file] = { META_POLYGON_PACKET_status_file, 's', XSIZE(struct polygon_packet, status_file), "status_file", XOFFSET(struct polygon_packet, status_file) },
  [META_POLYGON_PACKET_pid_file] = { META_POLYGON_PACKET_pid_file, 's', XSIZE(struct polygon_packet, pid_file), "pid_file", XOFFSET(struct polygon_packet, pid_file) },
  [META_POLYGON_PACKET_download_dir] = { META_POLYGON_PACKET_download_dir, 's', XSIZE(struct polygon_packet, download_dir), "download_dir", XOFFSET(struct polygon_packet, download_dir) },
  [META_POLYGON_PACKET_problem_dir] = { META_POLYGON_PACKET_problem_dir, 's', XSIZE(struct polygon_packet, problem_dir), "problem_dir", XOFFSET(struct polygon_packet, problem_dir) },
  [META_POLYGON_PACKET_dir_mode] = { META_POLYGON_PACKET_dir_mode, 's', XSIZE(struct polygon_packet, dir_mode), "dir_mode", XOFFSET(struct polygon_packet, dir_mode) },
  [META_POLYGON_PACKET_dir_group] = { META_POLYGON_PACKET_dir_group, 's', XSIZE(struct polygon_packet, dir_group), "dir_group", XOFFSET(struct polygon_packet, dir_group) },
  [META_POLYGON_PACKET_file_mode] = { META_POLYGON_PACKET_file_mode, 's', XSIZE(struct polygon_packet, file_mode), "file_mode", XOFFSET(struct polygon_packet, file_mode) },
  [META_POLYGON_PACKET_file_group] = { META_POLYGON_PACKET_file_group, 's', XSIZE(struct polygon_packet, file_group), "file_group", XOFFSET(struct polygon_packet, file_group) },
  [META_POLYGON_PACKET_arch] = { META_POLYGON_PACKET_arch, 's', XSIZE(struct polygon_packet, arch), "arch", XOFFSET(struct polygon_packet, arch) },
  [META_POLYGON_PACKET_working_dir] = { META_POLYGON_PACKET_working_dir, 's', XSIZE(struct polygon_packet, working_dir), "working_dir", XOFFSET(struct polygon_packet, working_dir) },
  [META_POLYGON_PACKET_problem_xml_name] = { META_POLYGON_PACKET_problem_xml_name, 's', XSIZE(struct polygon_packet, problem_xml_name), "problem_xml_name", XOFFSET(struct polygon_packet, problem_xml_name) },
  [META_POLYGON_PACKET_testset] = { META_POLYGON_PACKET_testset, 's', XSIZE(struct polygon_packet, testset), "testset", XOFFSET(struct polygon_packet, testset) },
  [META_POLYGON_PACKET_language_priority] = { META_POLYGON_PACKET_language_priority, 's', XSIZE(struct polygon_packet, language_priority), "language_priority", XOFFSET(struct polygon_packet, language_priority) },
  [META_POLYGON_PACKET_polygon_contest_id] = { META_POLYGON_PACKET_polygon_contest_id, 's', XSIZE(struct polygon_packet, polygon_contest_id), "polygon_contest_id", XOFFSET(struct polygon_packet, polygon_contest_id) },
  [META_POLYGON_PACKET_id] = { META_POLYGON_PACKET_id, 'x', XSIZE(struct polygon_packet, id), "id", XOFFSET(struct polygon_packet, id) },
  [META_POLYGON_PACKET_ejudge_id] = { META_POLYGON_PACKET_ejudge_id, 'x', XSIZE(struct polygon_packet, ejudge_id), "ejudge_id", XOFFSET(struct polygon_packet, ejudge_id) },
  [META_POLYGON_PACKET_ejudge_short_name] = { META_POLYGON_PACKET_ejudge_short_name, 'x', XSIZE(struct polygon_packet, ejudge_short_name), "ejudge_short_name", XOFFSET(struct polygon_packet, ejudge_short_name) },
};

int meta_polygon_packet_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_POLYGON_PACKET_LAST_FIELD);
  return meta_info_polygon_packet_data[tag].type;
}

size_t meta_polygon_packet_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_POLYGON_PACKET_LAST_FIELD);
  return meta_info_polygon_packet_data[tag].size;
}

const char *meta_polygon_packet_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_POLYGON_PACKET_LAST_FIELD);
  return meta_info_polygon_packet_data[tag].name;
}

const void *meta_polygon_packet_get_ptr(const struct polygon_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_POLYGON_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_polygon_packet_data[tag].offset);
}

void *meta_polygon_packet_get_ptr_nc(struct polygon_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_POLYGON_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_polygon_packet_data[tag].offset);
}

int meta_polygon_packet_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_polygon_packet_data, META_POLYGON_PACKET_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_polygon_packet_methods =
{
  META_POLYGON_PACKET_LAST_FIELD,
  sizeof(struct polygon_packet),
  meta_polygon_packet_get_type,
  meta_polygon_packet_get_size,
  meta_polygon_packet_get_name,
  (const void *(*)(const void *ptr, int tag))meta_polygon_packet_get_ptr,
  (void *(*)(void *ptr, int tag))meta_polygon_packet_get_ptr_nc,
  meta_polygon_packet_lookup_field,
};

