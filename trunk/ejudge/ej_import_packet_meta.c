// This is an auto-generated file, do not edit
// Generated 2013/10/17 00:54:49

#include "ej_import_packet_meta.h"
#include "ej_import_packet.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
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
};

