// This is an auto-generated file, do not edit

#ifndef __COMPILE_PACKET_META_H__
#define __COMPILE_PACKET_META_H__

#include <stdlib.h>

enum
{
  META_COMPILE_REQUEST_PACKET_judge_id = 1,
  META_COMPILE_REQUEST_PACKET_contest_id,
  META_COMPILE_REQUEST_PACKET_run_id,
  META_COMPILE_REQUEST_PACKET_lang_id,
  META_COMPILE_REQUEST_PACKET_locale_id,
  META_COMPILE_REQUEST_PACKET_output_only,
  META_COMPILE_REQUEST_PACKET_style_check_only,
  META_COMPILE_REQUEST_PACKET_ts1,
  META_COMPILE_REQUEST_PACKET_ts1_us,
  META_COMPILE_REQUEST_PACKET_use_uuid,
  META_COMPILE_REQUEST_PACKET_multi_header,
  META_COMPILE_REQUEST_PACKET_lang_header,
  META_COMPILE_REQUEST_PACKET_uuid,
  META_COMPILE_REQUEST_PACKET_max_vm_size,
  META_COMPILE_REQUEST_PACKET_max_stack_size,
  META_COMPILE_REQUEST_PACKET_max_file_size,
  META_COMPILE_REQUEST_PACKET_style_checker,
  META_COMPILE_REQUEST_PACKET_src_sfx,
  META_COMPILE_REQUEST_PACKET_lang_short_name,
  META_COMPILE_REQUEST_PACKET_header_pat,
  META_COMPILE_REQUEST_PACKET_footer_pat,
  META_COMPILE_REQUEST_PACKET_header_dir,
  META_COMPILE_REQUEST_PACKET_compiler_env_pat,
  META_COMPILE_REQUEST_PACKET_run_block_len,
  META_COMPILE_REQUEST_PACKET_run_block,
  META_COMPILE_REQUEST_PACKET_env_num,
  META_COMPILE_REQUEST_PACKET_sc_env_num,
  META_COMPILE_REQUEST_PACKET_env_vars,
  META_COMPILE_REQUEST_PACKET_sc_env_vars,

  META_COMPILE_REQUEST_PACKET_LAST_FIELD,
};

struct compile_request_packet;

int meta_compile_request_packet_get_type(int tag);
size_t meta_compile_request_packet_get_size(int tag);
const char *meta_compile_request_packet_get_name(int tag);
const void *meta_compile_request_packet_get_ptr(const struct compile_request_packet *ptr, int tag);
void *meta_compile_request_packet_get_ptr_nc(struct compile_request_packet *ptr, int tag);
int meta_compile_request_packet_lookup_field(const char *name);

struct meta_methods;
extern const struct meta_methods meta_compile_request_packet_methods;

#endif
