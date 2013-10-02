// This is an auto-generated file, do not edit
// Generated 2013/10/02 11:57:41

#ifndef __POLYGON_PACKET_META_H__
#define __POLYGON_PACKET_META_H__

#include <stdlib.h>

enum
{
  META_POLYGON_PACKET_sleep_interval = 1,
  META_POLYGON_PACKET_enable_max_stack_size,
  META_POLYGON_PACKET_create_mode,
  META_POLYGON_PACKET_retry_count,
  META_POLYGON_PACKET_polygon_url,
  META_POLYGON_PACKET_login,
  META_POLYGON_PACKET_password,
  META_POLYGON_PACKET_user_agent,
  META_POLYGON_PACKET_log_file,
  META_POLYGON_PACKET_status_file,
  META_POLYGON_PACKET_pid_file,
  META_POLYGON_PACKET_download_dir,
  META_POLYGON_PACKET_problem_dir,
  META_POLYGON_PACKET_dir_mode,
  META_POLYGON_PACKET_dir_group,
  META_POLYGON_PACKET_file_mode,
  META_POLYGON_PACKET_file_group,
  META_POLYGON_PACKET_arch,
  META_POLYGON_PACKET_working_dir,
  META_POLYGON_PACKET_problem_xml_name,
  META_POLYGON_PACKET_testset,
  META_POLYGON_PACKET_language_priority,
  META_POLYGON_PACKET_polygon_contest_id,
  META_POLYGON_PACKET_id,
  META_POLYGON_PACKET_ejudge_id,
  META_POLYGON_PACKET_ejudge_short_name,

  META_POLYGON_PACKET_LAST_FIELD,
};

struct polygon_packet;

int meta_polygon_packet_get_type(int tag);
size_t meta_polygon_packet_get_size(int tag);
const char *meta_polygon_packet_get_name(int tag);
const void *meta_polygon_packet_get_ptr(const struct polygon_packet *ptr, int tag);
void *meta_polygon_packet_get_ptr_nc(struct polygon_packet *ptr, int tag);
int meta_polygon_packet_lookup_field(const char *name);

struct meta_methods;
extern const struct meta_methods meta_polygon_packet_methods;

#endif
