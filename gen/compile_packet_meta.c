// This is an auto-generated file, do not edit

#include "ejudge/meta/compile_packet_meta.h"
#include "ejudge/compile_packet.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_compile_request_packet_data[] =
{
  [META_COMPILE_REQUEST_PACKET_judge_id] = { META_COMPILE_REQUEST_PACKET_judge_id, 'i', XSIZE(struct compile_request_packet, judge_id), "judge_id", XOFFSET(struct compile_request_packet, judge_id) },
  [META_COMPILE_REQUEST_PACKET_contest_id] = { META_COMPILE_REQUEST_PACKET_contest_id, 'i', XSIZE(struct compile_request_packet, contest_id), "contest_id", XOFFSET(struct compile_request_packet, contest_id) },
  [META_COMPILE_REQUEST_PACKET_run_id] = { META_COMPILE_REQUEST_PACKET_run_id, 'i', XSIZE(struct compile_request_packet, run_id), "run_id", XOFFSET(struct compile_request_packet, run_id) },
  [META_COMPILE_REQUEST_PACKET_lang_id] = { META_COMPILE_REQUEST_PACKET_lang_id, 'i', XSIZE(struct compile_request_packet, lang_id), "lang_id", XOFFSET(struct compile_request_packet, lang_id) },
  [META_COMPILE_REQUEST_PACKET_locale_id] = { META_COMPILE_REQUEST_PACKET_locale_id, 'i', XSIZE(struct compile_request_packet, locale_id), "locale_id", XOFFSET(struct compile_request_packet, locale_id) },
  [META_COMPILE_REQUEST_PACKET_output_only] = { META_COMPILE_REQUEST_PACKET_output_only, 'i', XSIZE(struct compile_request_packet, output_only), "output_only", XOFFSET(struct compile_request_packet, output_only) },
  [META_COMPILE_REQUEST_PACKET_style_check_only] = { META_COMPILE_REQUEST_PACKET_style_check_only, 'i', XSIZE(struct compile_request_packet, style_check_only), "style_check_only", XOFFSET(struct compile_request_packet, style_check_only) },
  [META_COMPILE_REQUEST_PACKET_ts1] = { META_COMPILE_REQUEST_PACKET_ts1, 'i', XSIZE(struct compile_request_packet, ts1), "ts1", XOFFSET(struct compile_request_packet, ts1) },
  [META_COMPILE_REQUEST_PACKET_ts1_us] = { META_COMPILE_REQUEST_PACKET_ts1_us, 'i', XSIZE(struct compile_request_packet, ts1_us), "ts1_us", XOFFSET(struct compile_request_packet, ts1_us) },
  [META_COMPILE_REQUEST_PACKET_use_uuid] = { META_COMPILE_REQUEST_PACKET_use_uuid, 'i', XSIZE(struct compile_request_packet, use_uuid), "use_uuid", XOFFSET(struct compile_request_packet, use_uuid) },
  [META_COMPILE_REQUEST_PACKET_multi_header] = { META_COMPILE_REQUEST_PACKET_multi_header, 'i', XSIZE(struct compile_request_packet, multi_header), "multi_header", XOFFSET(struct compile_request_packet, multi_header) },
  [META_COMPILE_REQUEST_PACKET_lang_header] = { META_COMPILE_REQUEST_PACKET_lang_header, 'i', XSIZE(struct compile_request_packet, lang_header), "lang_header", XOFFSET(struct compile_request_packet, lang_header) },
  [META_COMPILE_REQUEST_PACKET_user_id] = { META_COMPILE_REQUEST_PACKET_user_id, 'i', XSIZE(struct compile_request_packet, user_id), "user_id", XOFFSET(struct compile_request_packet, user_id) },
  [META_COMPILE_REQUEST_PACKET_use_container] = { META_COMPILE_REQUEST_PACKET_use_container, 'i', XSIZE(struct compile_request_packet, use_container), "use_container", XOFFSET(struct compile_request_packet, use_container) },
  [META_COMPILE_REQUEST_PACKET_vcs_mode] = { META_COMPILE_REQUEST_PACKET_vcs_mode, 'i', XSIZE(struct compile_request_packet, vcs_mode), "vcs_mode", XOFFSET(struct compile_request_packet, vcs_mode) },
  [META_COMPILE_REQUEST_PACKET_not_ok_is_cf] = { META_COMPILE_REQUEST_PACKET_not_ok_is_cf, 'i', XSIZE(struct compile_request_packet, not_ok_is_cf), "not_ok_is_cf", XOFFSET(struct compile_request_packet, not_ok_is_cf) },
  [META_COMPILE_REQUEST_PACKET_preserve_numbers] = { META_COMPILE_REQUEST_PACKET_preserve_numbers, 'i', XSIZE(struct compile_request_packet, preserve_numbers), "preserve_numbers", XOFFSET(struct compile_request_packet, preserve_numbers) },
  [META_COMPILE_REQUEST_PACKET_enable_remote_cache] = { META_COMPILE_REQUEST_PACKET_enable_remote_cache, 'i', XSIZE(struct compile_request_packet, enable_remote_cache), "enable_remote_cache", XOFFSET(struct compile_request_packet, enable_remote_cache) },
  [META_COMPILE_REQUEST_PACKET_enable_exe_properties] = { META_COMPILE_REQUEST_PACKET_enable_exe_properties, 'i', XSIZE(struct compile_request_packet, enable_exe_properties), "enable_exe_properties", XOFFSET(struct compile_request_packet, enable_exe_properties) },
  [META_COMPILE_REQUEST_PACKET_submit_id] = { META_COMPILE_REQUEST_PACKET_submit_id, '?', XSIZE(struct compile_request_packet, submit_id), "submit_id", XOFFSET(struct compile_request_packet, submit_id) },
  [META_COMPILE_REQUEST_PACKET_uuid] = { META_COMPILE_REQUEST_PACKET_uuid, '?', XSIZE(struct compile_request_packet, uuid), "uuid", XOFFSET(struct compile_request_packet, uuid) },
  [META_COMPILE_REQUEST_PACKET_judge_uuid] = { META_COMPILE_REQUEST_PACKET_judge_uuid, '?', XSIZE(struct compile_request_packet, judge_uuid), "judge_uuid", XOFFSET(struct compile_request_packet, judge_uuid) },
  [META_COMPILE_REQUEST_PACKET_max_vm_size] = { META_COMPILE_REQUEST_PACKET_max_vm_size, 'E', XSIZE(struct compile_request_packet, max_vm_size), "max_vm_size", XOFFSET(struct compile_request_packet, max_vm_size) },
  [META_COMPILE_REQUEST_PACKET_max_stack_size] = { META_COMPILE_REQUEST_PACKET_max_stack_size, 'E', XSIZE(struct compile_request_packet, max_stack_size), "max_stack_size", XOFFSET(struct compile_request_packet, max_stack_size) },
  [META_COMPILE_REQUEST_PACKET_max_file_size] = { META_COMPILE_REQUEST_PACKET_max_file_size, 'E', XSIZE(struct compile_request_packet, max_file_size), "max_file_size", XOFFSET(struct compile_request_packet, max_file_size) },
  [META_COMPILE_REQUEST_PACKET_max_rss_size] = { META_COMPILE_REQUEST_PACKET_max_rss_size, 'E', XSIZE(struct compile_request_packet, max_rss_size), "max_rss_size", XOFFSET(struct compile_request_packet, max_rss_size) },
  [META_COMPILE_REQUEST_PACKET_style_checker] = { META_COMPILE_REQUEST_PACKET_style_checker, 's', XSIZE(struct compile_request_packet, style_checker), "style_checker", XOFFSET(struct compile_request_packet, style_checker) },
  [META_COMPILE_REQUEST_PACKET_src_sfx] = { META_COMPILE_REQUEST_PACKET_src_sfx, 's', XSIZE(struct compile_request_packet, src_sfx), "src_sfx", XOFFSET(struct compile_request_packet, src_sfx) },
  [META_COMPILE_REQUEST_PACKET_lang_short_name] = { META_COMPILE_REQUEST_PACKET_lang_short_name, 's', XSIZE(struct compile_request_packet, lang_short_name), "lang_short_name", XOFFSET(struct compile_request_packet, lang_short_name) },
  [META_COMPILE_REQUEST_PACKET_header_pat] = { META_COMPILE_REQUEST_PACKET_header_pat, 's', XSIZE(struct compile_request_packet, header_pat), "header_pat", XOFFSET(struct compile_request_packet, header_pat) },
  [META_COMPILE_REQUEST_PACKET_footer_pat] = { META_COMPILE_REQUEST_PACKET_footer_pat, 's', XSIZE(struct compile_request_packet, footer_pat), "footer_pat", XOFFSET(struct compile_request_packet, footer_pat) },
  [META_COMPILE_REQUEST_PACKET_header_dir] = { META_COMPILE_REQUEST_PACKET_header_dir, 's', XSIZE(struct compile_request_packet, header_dir), "header_dir", XOFFSET(struct compile_request_packet, header_dir) },
  [META_COMPILE_REQUEST_PACKET_compiler_env_pat] = { META_COMPILE_REQUEST_PACKET_compiler_env_pat, 's', XSIZE(struct compile_request_packet, compiler_env_pat), "compiler_env_pat", XOFFSET(struct compile_request_packet, compiler_env_pat) },
  [META_COMPILE_REQUEST_PACKET_user_login] = { META_COMPILE_REQUEST_PACKET_user_login, 's', XSIZE(struct compile_request_packet, user_login), "user_login", XOFFSET(struct compile_request_packet, user_login) },
  [META_COMPILE_REQUEST_PACKET_exam_cypher] = { META_COMPILE_REQUEST_PACKET_exam_cypher, 's', XSIZE(struct compile_request_packet, exam_cypher), "exam_cypher", XOFFSET(struct compile_request_packet, exam_cypher) },
  [META_COMPILE_REQUEST_PACKET_contest_server_id] = { META_COMPILE_REQUEST_PACKET_contest_server_id, 's', XSIZE(struct compile_request_packet, contest_server_id), "contest_server_id", XOFFSET(struct compile_request_packet, contest_server_id) },
  [META_COMPILE_REQUEST_PACKET_container_options] = { META_COMPILE_REQUEST_PACKET_container_options, 's', XSIZE(struct compile_request_packet, container_options), "container_options", XOFFSET(struct compile_request_packet, container_options) },
  [META_COMPILE_REQUEST_PACKET_vcs_compile_cmd] = { META_COMPILE_REQUEST_PACKET_vcs_compile_cmd, 's', XSIZE(struct compile_request_packet, vcs_compile_cmd), "vcs_compile_cmd", XOFFSET(struct compile_request_packet, vcs_compile_cmd) },
  [META_COMPILE_REQUEST_PACKET_compile_cmd] = { META_COMPILE_REQUEST_PACKET_compile_cmd, 's', XSIZE(struct compile_request_packet, compile_cmd), "compile_cmd", XOFFSET(struct compile_request_packet, compile_cmd) },
  [META_COMPILE_REQUEST_PACKET_extra_src_dir] = { META_COMPILE_REQUEST_PACKET_extra_src_dir, 's', XSIZE(struct compile_request_packet, extra_src_dir), "extra_src_dir", XOFFSET(struct compile_request_packet, extra_src_dir) },
  [META_COMPILE_REQUEST_PACKET_run_block_len] = { META_COMPILE_REQUEST_PACKET_run_block_len, 'i', XSIZE(struct compile_request_packet, run_block_len), "run_block_len", XOFFSET(struct compile_request_packet, run_block_len) },
  [META_COMPILE_REQUEST_PACKET_run_block] = { META_COMPILE_REQUEST_PACKET_run_block, '?', XSIZE(struct compile_request_packet, run_block), "run_block", XOFFSET(struct compile_request_packet, run_block) },
  [META_COMPILE_REQUEST_PACKET_env_num] = { META_COMPILE_REQUEST_PACKET_env_num, 'i', XSIZE(struct compile_request_packet, env_num), "env_num", XOFFSET(struct compile_request_packet, env_num) },
  [META_COMPILE_REQUEST_PACKET_sc_env_num] = { META_COMPILE_REQUEST_PACKET_sc_env_num, 'i', XSIZE(struct compile_request_packet, sc_env_num), "sc_env_num", XOFFSET(struct compile_request_packet, sc_env_num) },
  [META_COMPILE_REQUEST_PACKET_env_vars] = { META_COMPILE_REQUEST_PACKET_env_vars, 'x', XSIZE(struct compile_request_packet, env_vars), "env_vars", XOFFSET(struct compile_request_packet, env_vars) },
  [META_COMPILE_REQUEST_PACKET_sc_env_vars] = { META_COMPILE_REQUEST_PACKET_sc_env_vars, 'x', XSIZE(struct compile_request_packet, sc_env_vars), "sc_env_vars", XOFFSET(struct compile_request_packet, sc_env_vars) },
};

int meta_compile_request_packet_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_COMPILE_REQUEST_PACKET_LAST_FIELD);
  return meta_info_compile_request_packet_data[tag].type;
}

size_t meta_compile_request_packet_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_COMPILE_REQUEST_PACKET_LAST_FIELD);
  return meta_info_compile_request_packet_data[tag].size;
}

const char *meta_compile_request_packet_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_COMPILE_REQUEST_PACKET_LAST_FIELD);
  return meta_info_compile_request_packet_data[tag].name;
}

const void *meta_compile_request_packet_get_ptr(const struct compile_request_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_COMPILE_REQUEST_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_compile_request_packet_data[tag].offset);
}

void *meta_compile_request_packet_get_ptr_nc(struct compile_request_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_COMPILE_REQUEST_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_compile_request_packet_data[tag].offset);
}

int meta_compile_request_packet_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_compile_request_packet_data, META_COMPILE_REQUEST_PACKET_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

void meta_compile_request_packet_copy(struct compile_request_packet *dst, const struct compile_request_packet *src)
{
  dst->judge_id = src->judge_id;
  dst->contest_id = src->contest_id;
  dst->run_id = src->run_id;
  dst->lang_id = src->lang_id;
  dst->locale_id = src->locale_id;
  dst->output_only = src->output_only;
  dst->style_check_only = src->style_check_only;
  dst->ts1 = src->ts1;
  dst->ts1_us = src->ts1_us;
  dst->use_uuid = src->use_uuid;
  dst->multi_header = src->multi_header;
  dst->lang_header = src->lang_header;
  dst->user_id = src->user_id;
  dst->use_container = src->use_container;
  dst->vcs_mode = src->vcs_mode;
  dst->not_ok_is_cf = src->not_ok_is_cf;
  dst->preserve_numbers = src->preserve_numbers;
  dst->enable_remote_cache = src->enable_remote_cache;
  dst->enable_exe_properties = src->enable_exe_properties;
  // submit_id
  // uuid
  // judge_uuid
  dst->max_vm_size = src->max_vm_size;
  dst->max_stack_size = src->max_stack_size;
  dst->max_file_size = src->max_file_size;
  dst->max_rss_size = src->max_rss_size;
  if (src->style_checker) {
    dst->style_checker = strdup(src->style_checker);
  }
  if (src->src_sfx) {
    dst->src_sfx = strdup(src->src_sfx);
  }
  if (src->lang_short_name) {
    dst->lang_short_name = strdup(src->lang_short_name);
  }
  if (src->header_pat) {
    dst->header_pat = strdup(src->header_pat);
  }
  if (src->footer_pat) {
    dst->footer_pat = strdup(src->footer_pat);
  }
  if (src->header_dir) {
    dst->header_dir = strdup(src->header_dir);
  }
  if (src->compiler_env_pat) {
    dst->compiler_env_pat = strdup(src->compiler_env_pat);
  }
  if (src->user_login) {
    dst->user_login = strdup(src->user_login);
  }
  if (src->exam_cypher) {
    dst->exam_cypher = strdup(src->exam_cypher);
  }
  if (src->contest_server_id) {
    dst->contest_server_id = strdup(src->contest_server_id);
  }
  if (src->container_options) {
    dst->container_options = strdup(src->container_options);
  }
  if (src->vcs_compile_cmd) {
    dst->vcs_compile_cmd = strdup(src->vcs_compile_cmd);
  }
  if (src->compile_cmd) {
    dst->compile_cmd = strdup(src->compile_cmd);
  }
  if (src->extra_src_dir) {
    dst->extra_src_dir = strdup(src->extra_src_dir);
  }
  dst->run_block_len = src->run_block_len;
  // run_block
  dst->env_num = src->env_num;
  dst->sc_env_num = src->sc_env_num;
  dst->env_vars = (typeof(dst->env_vars)) sarray_copy((char**) src->env_vars);
  dst->sc_env_vars = (typeof(dst->sc_env_vars)) sarray_copy((char**) src->sc_env_vars);
}

void meta_compile_request_packet_free(struct compile_request_packet *ptr)
{
  // submit_id
  // uuid
  // judge_uuid
  free(ptr->style_checker);
  free(ptr->src_sfx);
  free(ptr->lang_short_name);
  free(ptr->header_pat);
  free(ptr->footer_pat);
  free(ptr->header_dir);
  free(ptr->compiler_env_pat);
  free(ptr->user_login);
  free(ptr->exam_cypher);
  free(ptr->contest_server_id);
  free(ptr->container_options);
  free(ptr->vcs_compile_cmd);
  free(ptr->compile_cmd);
  free(ptr->extra_src_dir);
  // run_block
  sarray_free((char**) ptr->env_vars);
  sarray_free((char**) ptr->sc_env_vars);
}

const struct meta_methods meta_compile_request_packet_methods =
{
  META_COMPILE_REQUEST_PACKET_LAST_FIELD,
  sizeof(struct compile_request_packet),
  meta_compile_request_packet_get_type,
  meta_compile_request_packet_get_size,
  meta_compile_request_packet_get_name,
  (const void *(*)(const void *ptr, int tag))meta_compile_request_packet_get_ptr,
  (void *(*)(void *ptr, int tag))meta_compile_request_packet_get_ptr_nc,
  meta_compile_request_packet_lookup_field,
  (void (*)(void *, const void *))meta_compile_request_packet_copy,
  (void (*)(void *))meta_compile_request_packet_free,
};

