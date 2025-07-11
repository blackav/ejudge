// This is an auto-generated file, do not edit

#include "ejudge/meta/ej_import_packet_meta.h"
#include "ejudge/ej_import_packet.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_ej_import_packet_data[] =
{
  [META_EJ_IMPORT_PACKET_contest_id] = { META_EJ_IMPORT_PACKET_contest_id, 'i', XSIZE(struct ej_import_packet, contest_id), "contest_id", XOFFSET(struct ej_import_packet, contest_id) },
  [META_EJ_IMPORT_PACKET_user_id] = { META_EJ_IMPORT_PACKET_user_id, 'i', XSIZE(struct ej_import_packet, user_id), "user_id", XOFFSET(struct ej_import_packet, user_id) },
  [META_EJ_IMPORT_PACKET_require_master_solution] = { META_EJ_IMPORT_PACKET_require_master_solution, 'B', XSIZE(struct ej_import_packet, require_master_solution), "require_master_solution", XOFFSET(struct ej_import_packet, require_master_solution) },
  [META_EJ_IMPORT_PACKET_require_test_checker] = { META_EJ_IMPORT_PACKET_require_test_checker, 'B', XSIZE(struct ej_import_packet, require_test_checker), "require_test_checker", XOFFSET(struct ej_import_packet, require_test_checker) },
  [META_EJ_IMPORT_PACKET_archive_file] = { META_EJ_IMPORT_PACKET_archive_file, 's', XSIZE(struct ej_import_packet, archive_file), "archive_file", XOFFSET(struct ej_import_packet, archive_file) },
  [META_EJ_IMPORT_PACKET_content_type] = { META_EJ_IMPORT_PACKET_content_type, 's', XSIZE(struct ej_import_packet, content_type), "content_type", XOFFSET(struct ej_import_packet, content_type) },
  [META_EJ_IMPORT_PACKET_log_file] = { META_EJ_IMPORT_PACKET_log_file, 's', XSIZE(struct ej_import_packet, log_file), "log_file", XOFFSET(struct ej_import_packet, log_file) },
  [META_EJ_IMPORT_PACKET_status_file] = { META_EJ_IMPORT_PACKET_status_file, 's', XSIZE(struct ej_import_packet, status_file), "status_file", XOFFSET(struct ej_import_packet, status_file) },
  [META_EJ_IMPORT_PACKET_pid_file] = { META_EJ_IMPORT_PACKET_pid_file, 's', XSIZE(struct ej_import_packet, pid_file), "pid_file", XOFFSET(struct ej_import_packet, pid_file) },
  [META_EJ_IMPORT_PACKET_working_dir] = { META_EJ_IMPORT_PACKET_working_dir, 's', XSIZE(struct ej_import_packet, working_dir), "working_dir", XOFFSET(struct ej_import_packet, working_dir) },
  [META_EJ_IMPORT_PACKET_remote_addr] = { META_EJ_IMPORT_PACKET_remote_addr, 's', XSIZE(struct ej_import_packet, remote_addr), "remote_addr", XOFFSET(struct ej_import_packet, remote_addr) },
  [META_EJ_IMPORT_PACKET_user_login] = { META_EJ_IMPORT_PACKET_user_login, 's', XSIZE(struct ej_import_packet, user_login), "user_login", XOFFSET(struct ej_import_packet, user_login) },
  [META_EJ_IMPORT_PACKET_user_name] = { META_EJ_IMPORT_PACKET_user_name, 's', XSIZE(struct ej_import_packet, user_name), "user_name", XOFFSET(struct ej_import_packet, user_name) },
  [META_EJ_IMPORT_PACKET_required_solutions] = { META_EJ_IMPORT_PACKET_required_solutions, 'x', XSIZE(struct ej_import_packet, required_solutions), "required_solutions", XOFFSET(struct ej_import_packet, required_solutions) },
};

int meta_ej_import_packet_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_EJ_IMPORT_PACKET_LAST_FIELD);
  return meta_info_ej_import_packet_data[tag].type;
}

size_t meta_ej_import_packet_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_EJ_IMPORT_PACKET_LAST_FIELD);
  return meta_info_ej_import_packet_data[tag].size;
}

const char *meta_ej_import_packet_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_EJ_IMPORT_PACKET_LAST_FIELD);
  return meta_info_ej_import_packet_data[tag].name;
}

const void *meta_ej_import_packet_get_ptr(const struct ej_import_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_EJ_IMPORT_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ej_import_packet_data[tag].offset);
}

void *meta_ej_import_packet_get_ptr_nc(struct ej_import_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_EJ_IMPORT_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ej_import_packet_data[tag].offset);
}

int meta_ej_import_packet_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_ej_import_packet_data, META_EJ_IMPORT_PACKET_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

void meta_ej_import_packet_copy(struct ej_import_packet *dst, const struct ej_import_packet *src)
{
  // hidden g
  dst->contest_id = src->contest_id;
  dst->user_id = src->user_id;
  dst->require_master_solution = src->require_master_solution;
  dst->require_test_checker = src->require_test_checker;
  if (src->archive_file) {
    dst->archive_file = strdup(src->archive_file);
  }
  if (src->content_type) {
    dst->content_type = strdup(src->content_type);
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
  if (src->working_dir) {
    dst->working_dir = strdup(src->working_dir);
  }
  if (src->remote_addr) {
    dst->remote_addr = strdup(src->remote_addr);
  }
  if (src->user_login) {
    dst->user_login = strdup(src->user_login);
  }
  if (src->user_name) {
    dst->user_name = strdup(src->user_name);
  }
  dst->required_solutions = (typeof(dst->required_solutions)) sarray_copy((char**) src->required_solutions);
}

void meta_ej_import_packet_free(struct ej_import_packet *ptr)
{
  // hidden g
  free(ptr->archive_file);
  free(ptr->content_type);
  free(ptr->log_file);
  free(ptr->status_file);
  free(ptr->pid_file);
  free(ptr->working_dir);
  free(ptr->remote_addr);
  free(ptr->user_login);
  free(ptr->user_name);
  sarray_free((char**) ptr->required_solutions);
}

const struct meta_methods meta_ej_import_packet_methods =
{
  META_EJ_IMPORT_PACKET_LAST_FIELD,
  sizeof(struct ej_import_packet),
  meta_ej_import_packet_get_type,
  meta_ej_import_packet_get_size,
  meta_ej_import_packet_get_name,
  (const void *(*)(const void *ptr, int tag))meta_ej_import_packet_get_ptr,
  (void *(*)(void *ptr, int tag))meta_ej_import_packet_get_ptr_nc,
  meta_ej_import_packet_lookup_field,
  (void (*)(void *, const void *))meta_ej_import_packet_copy,
  (void (*)(void *))meta_ej_import_packet_free,
  meta_info_ej_import_packet_data,
};

