// This is an auto-generated file, do not edit
// Generated 2013/10/17 00:54:49

#ifndef __EJ_IMPORT_PACKET_META_H__
#define __EJ_IMPORT_PACKET_META_H__

#include <stdlib.h>

enum
{
  META_EJ_IMPORT_PACKET_contest_id = 1,
  META_EJ_IMPORT_PACKET_user_id,
  META_EJ_IMPORT_PACKET_require_master_solution,
  META_EJ_IMPORT_PACKET_require_test_checker,
  META_EJ_IMPORT_PACKET_archive_file,
  META_EJ_IMPORT_PACKET_content_type,
  META_EJ_IMPORT_PACKET_log_file,
  META_EJ_IMPORT_PACKET_status_file,
  META_EJ_IMPORT_PACKET_pid_file,
  META_EJ_IMPORT_PACKET_working_dir,
  META_EJ_IMPORT_PACKET_remote_addr,
  META_EJ_IMPORT_PACKET_user_login,
  META_EJ_IMPORT_PACKET_user_name,
  META_EJ_IMPORT_PACKET_required_solutions,

  META_EJ_IMPORT_PACKET_LAST_FIELD,
};

struct ej_import_packet;

int meta_ej_import_packet_get_type(int tag);
size_t meta_ej_import_packet_get_size(int tag);
const char *meta_ej_import_packet_get_name(int tag);
const void *meta_ej_import_packet_get_ptr(const struct ej_import_packet *ptr, int tag);
void *meta_ej_import_packet_get_ptr_nc(struct ej_import_packet *ptr, int tag);
int meta_ej_import_packet_lookup_field(const char *name);

struct meta_methods;
extern const struct meta_methods meta_ej_import_packet_methods;

#endif
