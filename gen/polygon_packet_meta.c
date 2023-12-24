// This is an auto-generated file, do not edit

#include "ejudge/meta/polygon_packet_meta.h"
#include "ejudge/polygon_packet.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_polygon_packet_data[] =
{
  [META_POLYGON_PACKET_sleep_interval] = { META_POLYGON_PACKET_sleep_interval, 'i', XSIZE(struct polygon_packet, sleep_interval), "sleep_interval", XOFFSET(struct polygon_packet, sleep_interval) },
  [META_POLYGON_PACKET_enable_max_stack_size] = { META_POLYGON_PACKET_enable_max_stack_size, 'B', XSIZE(struct polygon_packet, enable_max_stack_size), "enable_max_stack_size", XOFFSET(struct polygon_packet, enable_max_stack_size) },
  [META_POLYGON_PACKET_create_mode] = { META_POLYGON_PACKET_create_mode, 'B', XSIZE(struct polygon_packet, create_mode), "create_mode", XOFFSET(struct polygon_packet, create_mode) },
  [META_POLYGON_PACKET_ignore_solutions] = { META_POLYGON_PACKET_ignore_solutions, 'B', XSIZE(struct polygon_packet, ignore_solutions), "ignore_solutions", XOFFSET(struct polygon_packet, ignore_solutions) },
  [META_POLYGON_PACKET_retry_count] = { META_POLYGON_PACKET_retry_count, 'i', XSIZE(struct polygon_packet, retry_count), "retry_count", XOFFSET(struct polygon_packet, retry_count) },
  [META_POLYGON_PACKET_fetch_latest_available] = { META_POLYGON_PACKET_fetch_latest_available, 'B', XSIZE(struct polygon_packet, fetch_latest_available), "fetch_latest_available", XOFFSET(struct polygon_packet, fetch_latest_available) },
  [META_POLYGON_PACKET_binary_input] = { META_POLYGON_PACKET_binary_input, 'B', XSIZE(struct polygon_packet, binary_input), "binary_input", XOFFSET(struct polygon_packet, binary_input) },
  [META_POLYGON_PACKET_enable_iframe_statement] = { META_POLYGON_PACKET_enable_iframe_statement, 'B', XSIZE(struct polygon_packet, enable_iframe_statement), "enable_iframe_statement", XOFFSET(struct polygon_packet, enable_iframe_statement) },
  [META_POLYGON_PACKET_enable_api] = { META_POLYGON_PACKET_enable_api, 'B', XSIZE(struct polygon_packet, enable_api), "enable_api", XOFFSET(struct polygon_packet, enable_api) },
  [META_POLYGON_PACKET_verbose] = { META_POLYGON_PACKET_verbose, 'B', XSIZE(struct polygon_packet, verbose), "verbose", XOFFSET(struct polygon_packet, verbose) },
  [META_POLYGON_PACKET_ignore_main_solution] = { META_POLYGON_PACKET_ignore_main_solution, 'B', XSIZE(struct polygon_packet, ignore_main_solution), "ignore_main_solution", XOFFSET(struct polygon_packet, ignore_main_solution) },
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
  [META_POLYGON_PACKET_key] = { META_POLYGON_PACKET_key, 's', XSIZE(struct polygon_packet, key), "key", XOFFSET(struct polygon_packet, key) },
  [META_POLYGON_PACKET_secret] = { META_POLYGON_PACKET_secret, 's', XSIZE(struct polygon_packet, secret), "secret", XOFFSET(struct polygon_packet, secret) },
  [META_POLYGON_PACKET_package_file] = { META_POLYGON_PACKET_package_file, 's', XSIZE(struct polygon_packet, package_file), "package_file", XOFFSET(struct polygon_packet, package_file) },
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

void meta_polygon_packet_copy(struct polygon_packet *dst, const struct polygon_packet *src)
{
  // hidden g
  dst->sleep_interval = src->sleep_interval;
  dst->enable_max_stack_size = src->enable_max_stack_size;
  dst->create_mode = src->create_mode;
  dst->ignore_solutions = src->ignore_solutions;
  dst->retry_count = src->retry_count;
  dst->fetch_latest_available = src->fetch_latest_available;
  dst->binary_input = src->binary_input;
  dst->enable_iframe_statement = src->enable_iframe_statement;
  dst->enable_api = src->enable_api;
  dst->verbose = src->verbose;
  dst->ignore_main_solution = src->ignore_main_solution;
  if (src->polygon_url) {
    dst->polygon_url = strdup(src->polygon_url);
  }
  if (src->login) {
    dst->login = strdup(src->login);
  }
  if (src->password) {
    dst->password = strdup(src->password);
  }
  if (src->user_agent) {
    dst->user_agent = strdup(src->user_agent);
  }
  if (src->log_file) {
    dst->log_file = strdup(src->log_file);
  }
  if (src->status_file) {
    dst->status_file = strdup(src->status_file);
  }
  if (src->pid_file) {
    dst->pid_file = strdup(src->pid_file);
  }
  if (src->download_dir) {
    dst->download_dir = strdup(src->download_dir);
  }
  if (src->problem_dir) {
    dst->problem_dir = strdup(src->problem_dir);
  }
  if (src->dir_mode) {
    dst->dir_mode = strdup(src->dir_mode);
  }
  if (src->dir_group) {
    dst->dir_group = strdup(src->dir_group);
  }
  if (src->file_mode) {
    dst->file_mode = strdup(src->file_mode);
  }
  if (src->file_group) {
    dst->file_group = strdup(src->file_group);
  }
  if (src->arch) {
    dst->arch = strdup(src->arch);
  }
  if (src->working_dir) {
    dst->working_dir = strdup(src->working_dir);
  }
  if (src->problem_xml_name) {
    dst->problem_xml_name = strdup(src->problem_xml_name);
  }
  if (src->testset) {
    dst->testset = strdup(src->testset);
  }
  if (src->language_priority) {
    dst->language_priority = strdup(src->language_priority);
  }
  if (src->polygon_contest_id) {
    dst->polygon_contest_id = strdup(src->polygon_contest_id);
  }
  if (src->key) {
    dst->key = strdup(src->key);
  }
  if (src->secret) {
    dst->secret = strdup(src->secret);
  }
  if (src->package_file) {
    dst->package_file = strdup(src->package_file);
  }
  dst->id = (typeof(dst->id)) sarray_copy((char**) src->id);
  dst->ejudge_id = (typeof(dst->ejudge_id)) sarray_copy((char**) src->ejudge_id);
  dst->ejudge_short_name = (typeof(dst->ejudge_short_name)) sarray_copy((char**) src->ejudge_short_name);
}

void meta_polygon_packet_free(struct polygon_packet *ptr)
{
  // hidden g
  free(ptr->polygon_url);
  free(ptr->login);
  free(ptr->password);
  free(ptr->user_agent);
  free(ptr->log_file);
  free(ptr->status_file);
  free(ptr->pid_file);
  free(ptr->download_dir);
  free(ptr->problem_dir);
  free(ptr->dir_mode);
  free(ptr->dir_group);
  free(ptr->file_mode);
  free(ptr->file_group);
  free(ptr->arch);
  free(ptr->working_dir);
  free(ptr->problem_xml_name);
  free(ptr->testset);
  free(ptr->language_priority);
  free(ptr->polygon_contest_id);
  free(ptr->key);
  free(ptr->secret);
  free(ptr->package_file);
  sarray_free((char**) ptr->id);
  sarray_free((char**) ptr->ejudge_id);
  sarray_free((char**) ptr->ejudge_short_name);
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
  (void (*)(void *, const void *))meta_polygon_packet_copy,
  (void (*)(void *))meta_polygon_packet_free,
};

