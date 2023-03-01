/* This is auto-generated file */
enum
{
    Tag_tests = 1,
    Tag_test,
    Tag_args,
    Tag_input,
    Tag_output,
    Tag_correct,
    Tag_stderr,
    Tag_checker,
    Tag_comment,
    Tag_valuer_comment,
    Tag_valuer_judge_comment,
    Tag_valuer_errors,
    Tag_host,
    Tag_cpu_model,
    Tag_cpu_mhz,
    Tag_errors,
    Tag_ttrows,
    Tag_ttrow,
    Tag_ttcells,
    Tag_ttcell,
    Tag_compiler_output,
    Tag_uuid,
    Tag_program_stats_str,
    Tag_interactor_stats_str,
    Tag_checker_stats_str,
    Tag_run_id,
    Tag_judge_id,
    Tag_status,
    Tag_scoring,
    Tag_archive_available,
    Tag_correct_available,
    Tag_info_available,
    Tag_run_tests,
    Tag_variant,
    Tag_accepting_mode,
    Tag_failed_test,
    Tag_tests_passed,
    Tag_score,
    Tag_max_score,
    Tag_num,
    Tag_exit_code,
    Tag_term_signal,
    Tag_time,
    Tag_real_time,
    Tag_nominal_score,
    Tag_team_comment,
    Tag_checker_comment,
    Tag_output_available,
    Tag_stderr_available,
    Tag_checker_output_available,
    Tag_args_too_long,
    Tag_input_digest,
    Tag_correct_digest,
    Tag_info_digest,
    Tag_time_limit_ms,
    Tag_real_time_limit_ms,
    Tag_exit_comment,
    Tag_max_memory_used,
    Tag_real_time_available,
    Tag_max_memory_used_available,
    Tag_marked_flag,
    Tag_tests_mode,
    Tag_tt_row_count,
    Tag_tt_column_count,
    Tag_name,
    Tag_must_fail,
    Tag_row,
    Tag_column,
    Tag_visibility,
    Tag_user_status,
    Tag_user_tests_passed,
    Tag_user_score,
    Tag_user_max_score,
    Tag_user_run_tests,
    Tag_compile_error,
    Tag_contest_id,
    Tag_size,
    Tag_too_big,
    Tag_original_size,
    Tag_base64,
    Tag_has_user,
    Tag_user_nominal_score,
    Tag_checker_token,
    Tag_data,
    Tag_bzip2,
    Tag_max_rss_available,
    Tag_separate_user_score,
    Tag_max_rss,
    Tag_submit_id,
    Tag_judge_uuid,
    Tag_test_checker,
    Tag_verdict_bits
};
static __attribute__((unused)) const char * const tag_table[] =
{
    0,
    "tests",
    "test",
    "args",
    "input",
    "output",
    "correct",
    "stderr",
    "checker",
    "comment",
    "valuer_comment",
    "valuer_judge_comment",
    "valuer_errors",
    "host",
    "cpu_model",
    "cpu_mhz",
    "errors",
    "ttrows",
    "ttrow",
    "ttcells",
    "ttcell",
    "compiler_output",
    "uuid",
    "program_stats_str",
    "interactor_stats_str",
    "checker_stats_str",
    "run_id",
    "judge_id",
    "status",
    "scoring",
    "archive_available",
    "correct_available",
    "info_available",
    "run_tests",
    "variant",
    "accepting_mode",
    "failed_test",
    "tests_passed",
    "score",
    "max_score",
    "num",
    "exit_code",
    "term_signal",
    "time",
    "real_time",
    "nominal_score",
    "team_comment",
    "checker_comment",
    "output_available",
    "stderr_available",
    "checker_output_available",
    "args_too_long",
    "input_digest",
    "correct_digest",
    "info_digest",
    "time_limit_ms",
    "real_time_limit_ms",
    "exit_comment",
    "max_memory_used",
    "real_time_available",
    "max_memory_used_available",
    "marked_flag",
    "tests_mode",
    "tt_row_count",
    "tt_column_count",
    "name",
    "must_fail",
    "row",
    "column",
    "visibility",
    "user_status",
    "user_tests_passed",
    "user_score",
    "user_max_score",
    "user_run_tests",
    "compile_error",
    "contest_id",
    "size",
    "too_big",
    "original_size",
    "base64",
    "has_user",
    "user_nominal_score",
    "checker_token",
    "data",
    "bzip2",
    "max_rss_available",
    "separate_user_score",
    "max_rss",
    "submit_id",
    "judge_uuid",
    "test_checker",
    "verdict_bits",
};
static __attribute__((unused)) int
match(const char *s)
{
    if (s[0] == 'a') {
        if (s[1] == 'c' && s[2] == 'c' && s[3] == 'e' && s[4] == 'p' && s[5] == 't' && s[6] == 'i' && s[7] == 'n' && s[8] == 'g' && s[9] == '_' && s[10] == 'm' && s[11] == 'o' && s[12] == 'd' && s[13] == 'e' && !s[14]) {
            return Tag_accepting_mode;
        } else if (s[1] == 'r') {
            if (s[2] == 'c' && s[3] == 'h' && s[4] == 'i' && s[5] == 'v' && s[6] == 'e' && s[7] == '_' && s[8] == 'a' && s[9] == 'v' && s[10] == 'a' && s[11] == 'i' && s[12] == 'l' && s[13] == 'a' && s[14] == 'b' && s[15] == 'l' && s[16] == 'e' && !s[17]) {
                return Tag_archive_available;
            } else if (s[2] == 'g'&& s[3] == 's') {
                if (!s[4]) {
                    return Tag_args;
                } else if (s[4] == '_' && s[5] == 't' && s[6] == 'o' && s[7] == 'o' && s[8] == '_' && s[9] == 'l' && s[10] == 'o' && s[11] == 'n' && s[12] == 'g' && !s[13]) {
                    return Tag_args_too_long;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else if (s[0] == 'b') {
        if (s[1] == 'a' && s[2] == 's' && s[3] == 'e' && s[4] == '6' && s[5] == '4' && !s[6]) {
            return Tag_base64;
        } else if (s[1] == 'z' && s[2] == 'i' && s[3] == 'p' && s[4] == '2' && !s[5]) {
            return Tag_bzip2;
        } else {
            return 0;
        }
    } else if (s[0] == 'c') {
        if (s[1] == 'h'&& s[2] == 'e'&& s[3] == 'c'&& s[4] == 'k'&& s[5] == 'e'&& s[6] == 'r') {
            if (!s[7]) {
                return Tag_checker;
            } else if (s[7] == '_') {
                if (s[8] == 'c' && s[9] == 'o' && s[10] == 'm' && s[11] == 'm' && s[12] == 'e' && s[13] == 'n' && s[14] == 't' && !s[15]) {
                    return Tag_checker_comment;
                } else if (s[8] == 'o' && s[9] == 'u' && s[10] == 't' && s[11] == 'p' && s[12] == 'u' && s[13] == 't' && s[14] == '_' && s[15] == 'a' && s[16] == 'v' && s[17] == 'a' && s[18] == 'i' && s[19] == 'l' && s[20] == 'a' && s[21] == 'b' && s[22] == 'l' && s[23] == 'e' && !s[24]) {
                    return Tag_checker_output_available;
                } else if (s[8] == 's' && s[9] == 't' && s[10] == 'a' && s[11] == 't' && s[12] == 's' && s[13] == '_' && s[14] == 's' && s[15] == 't' && s[16] == 'r' && !s[17]) {
                    return Tag_checker_stats_str;
                } else if (s[8] == 't' && s[9] == 'o' && s[10] == 'k' && s[11] == 'e' && s[12] == 'n' && !s[13]) {
                    return Tag_checker_token;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (s[1] == 'o') {
            if (s[2] == 'l' && s[3] == 'u' && s[4] == 'm' && s[5] == 'n' && !s[6]) {
                return Tag_column;
            } else if (s[2] == 'm') {
                if (s[3] == 'm' && s[4] == 'e' && s[5] == 'n' && s[6] == 't' && !s[7]) {
                    return Tag_comment;
                } else if (s[3] == 'p'&& s[4] == 'i'&& s[5] == 'l'&& s[6] == 'e') {
                    if (s[7] == '_' && s[8] == 'e' && s[9] == 'r' && s[10] == 'r' && s[11] == 'o' && s[12] == 'r' && !s[13]) {
                        return Tag_compile_error;
                    } else if (s[7] == 'r' && s[8] == '_' && s[9] == 'o' && s[10] == 'u' && s[11] == 't' && s[12] == 'p' && s[13] == 'u' && s[14] == 't' && !s[15]) {
                        return Tag_compiler_output;
                    } else {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else if (s[2] == 'n' && s[3] == 't' && s[4] == 'e' && s[5] == 's' && s[6] == 't' && s[7] == '_' && s[8] == 'i' && s[9] == 'd' && !s[10]) {
                return Tag_contest_id;
            } else if (s[2] == 'r'&& s[3] == 'r'&& s[4] == 'e'&& s[5] == 'c'&& s[6] == 't') {
                if (!s[7]) {
                    return Tag_correct;
                } else if (s[7] == '_') {
                    if (s[8] == 'a' && s[9] == 'v' && s[10] == 'a' && s[11] == 'i' && s[12] == 'l' && s[13] == 'a' && s[14] == 'b' && s[15] == 'l' && s[16] == 'e' && !s[17]) {
                        return Tag_correct_available;
                    } else if (s[8] == 'd' && s[9] == 'i' && s[10] == 'g' && s[11] == 'e' && s[12] == 's' && s[13] == 't' && !s[14]) {
                        return Tag_correct_digest;
                    } else {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (s[1] == 'p'&& s[2] == 'u'&& s[3] == '_'&& s[4] == 'm') {
            if (s[5] == 'h' && s[6] == 'z' && !s[7]) {
                return Tag_cpu_mhz;
            } else if (s[5] == 'o' && s[6] == 'd' && s[7] == 'e' && s[8] == 'l' && !s[9]) {
                return Tag_cpu_model;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else if (s[0] == 'd' && s[1] == 'a' && s[2] == 't' && s[3] == 'a' && !s[4]) {
        return Tag_data;
    } else if (s[0] == 'e') {
        if (s[1] == 'r' && s[2] == 'r' && s[3] == 'o' && s[4] == 'r' && s[5] == 's' && !s[6]) {
            return Tag_errors;
        } else if (s[1] == 'x'&& s[2] == 'i'&& s[3] == 't'&& s[4] == '_'&& s[5] == 'c'&& s[6] == 'o') {
            if (s[7] == 'd' && s[8] == 'e' && !s[9]) {
                return Tag_exit_code;
            } else if (s[7] == 'm' && s[8] == 'm' && s[9] == 'e' && s[10] == 'n' && s[11] == 't' && !s[12]) {
                return Tag_exit_comment;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else if (s[0] == 'f' && s[1] == 'a' && s[2] == 'i' && s[3] == 'l' && s[4] == 'e' && s[5] == 'd' && s[6] == '_' && s[7] == 't' && s[8] == 'e' && s[9] == 's' && s[10] == 't' && !s[11]) {
        return Tag_failed_test;
    } else if (s[0] == 'h') {
        if (s[1] == 'a' && s[2] == 's' && s[3] == '_' && s[4] == 'u' && s[5] == 's' && s[6] == 'e' && s[7] == 'r' && !s[8]) {
            return Tag_has_user;
        } else if (s[1] == 'o' && s[2] == 's' && s[3] == 't' && !s[4]) {
            return Tag_host;
        } else {
            return 0;
        }
    } else if (s[0] == 'i'&& s[1] == 'n') {
        if (s[2] == 'f'&& s[3] == 'o'&& s[4] == '_') {
            if (s[5] == 'a' && s[6] == 'v' && s[7] == 'a' && s[8] == 'i' && s[9] == 'l' && s[10] == 'a' && s[11] == 'b' && s[12] == 'l' && s[13] == 'e' && !s[14]) {
                return Tag_info_available;
            } else if (s[5] == 'd' && s[6] == 'i' && s[7] == 'g' && s[8] == 'e' && s[9] == 's' && s[10] == 't' && !s[11]) {
                return Tag_info_digest;
            } else {
                return 0;
            }
        } else if (s[2] == 'p'&& s[3] == 'u'&& s[4] == 't') {
            if (!s[5]) {
                return Tag_input;
            } else if (s[5] == '_' && s[6] == 'd' && s[7] == 'i' && s[8] == 'g' && s[9] == 'e' && s[10] == 's' && s[11] == 't' && !s[12]) {
                return Tag_input_digest;
            } else {
                return 0;
            }
        } else if (s[2] == 't' && s[3] == 'e' && s[4] == 'r' && s[5] == 'a' && s[6] == 'c' && s[7] == 't' && s[8] == 'o' && s[9] == 'r' && s[10] == '_' && s[11] == 's' && s[12] == 't' && s[13] == 'a' && s[14] == 't' && s[15] == 's' && s[16] == '_' && s[17] == 's' && s[18] == 't' && s[19] == 'r' && !s[20]) {
            return Tag_interactor_stats_str;
        } else {
            return 0;
        }
    } else if (s[0] == 'j'&& s[1] == 'u'&& s[2] == 'd'&& s[3] == 'g'&& s[4] == 'e'&& s[5] == '_') {
        if (s[6] == 'i' && s[7] == 'd' && !s[8]) {
            return Tag_judge_id;
        } else if (s[6] == 'u' && s[7] == 'u' && s[8] == 'i' && s[9] == 'd' && !s[10]) {
            return Tag_judge_uuid;
        } else {
            return 0;
        }
    } else if (s[0] == 'm') {
        if (s[1] == 'a') {
            if (s[2] == 'r' && s[3] == 'k' && s[4] == 'e' && s[5] == 'd' && s[6] == '_' && s[7] == 'f' && s[8] == 'l' && s[9] == 'a' && s[10] == 'g' && !s[11]) {
                return Tag_marked_flag;
            } else if (s[2] == 'x'&& s[3] == '_') {
                if (s[4] == 'm'&& s[5] == 'e'&& s[6] == 'm'&& s[7] == 'o'&& s[8] == 'r'&& s[9] == 'y'&& s[10] == '_'&& s[11] == 'u'&& s[12] == 's'&& s[13] == 'e'&& s[14] == 'd') {
                    if (!s[15]) {
                        return Tag_max_memory_used;
                    } else if (s[15] == '_' && s[16] == 'a' && s[17] == 'v' && s[18] == 'a' && s[19] == 'i' && s[20] == 'l' && s[21] == 'a' && s[22] == 'b' && s[23] == 'l' && s[24] == 'e' && !s[25]) {
                        return Tag_max_memory_used_available;
                    } else {
                        return 0;
                    }
                } else if (s[4] == 'r'&& s[5] == 's'&& s[6] == 's') {
                    if (!s[7]) {
                        return Tag_max_rss;
                    } else if (s[7] == '_' && s[8] == 'a' && s[9] == 'v' && s[10] == 'a' && s[11] == 'i' && s[12] == 'l' && s[13] == 'a' && s[14] == 'b' && s[15] == 'l' && s[16] == 'e' && !s[17]) {
                        return Tag_max_rss_available;
                    } else {
                        return 0;
                    }
                } else if (s[4] == 's' && s[5] == 'c' && s[6] == 'o' && s[7] == 'r' && s[8] == 'e' && !s[9]) {
                    return Tag_max_score;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (s[1] == 'u' && s[2] == 's' && s[3] == 't' && s[4] == '_' && s[5] == 'f' && s[6] == 'a' && s[7] == 'i' && s[8] == 'l' && !s[9]) {
            return Tag_must_fail;
        } else {
            return 0;
        }
    } else if (s[0] == 'n') {
        if (s[1] == 'a' && s[2] == 'm' && s[3] == 'e' && !s[4]) {
            return Tag_name;
        } else if (s[1] == 'o' && s[2] == 'm' && s[3] == 'i' && s[4] == 'n' && s[5] == 'a' && s[6] == 'l' && s[7] == '_' && s[8] == 's' && s[9] == 'c' && s[10] == 'o' && s[11] == 'r' && s[12] == 'e' && !s[13]) {
            return Tag_nominal_score;
        } else if (s[1] == 'u' && s[2] == 'm' && !s[3]) {
            return Tag_num;
        } else {
            return 0;
        }
    } else if (s[0] == 'o') {
        if (s[1] == 'r' && s[2] == 'i' && s[3] == 'g' && s[4] == 'i' && s[5] == 'n' && s[6] == 'a' && s[7] == 'l' && s[8] == '_' && s[9] == 's' && s[10] == 'i' && s[11] == 'z' && s[12] == 'e' && !s[13]) {
            return Tag_original_size;
        } else if (s[1] == 'u'&& s[2] == 't'&& s[3] == 'p'&& s[4] == 'u'&& s[5] == 't') {
            if (!s[6]) {
                return Tag_output;
            } else if (s[6] == '_' && s[7] == 'a' && s[8] == 'v' && s[9] == 'a' && s[10] == 'i' && s[11] == 'l' && s[12] == 'a' && s[13] == 'b' && s[14] == 'l' && s[15] == 'e' && !s[16]) {
                return Tag_output_available;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else if (s[0] == 'p' && s[1] == 'r' && s[2] == 'o' && s[3] == 'g' && s[4] == 'r' && s[5] == 'a' && s[6] == 'm' && s[7] == '_' && s[8] == 's' && s[9] == 't' && s[10] == 'a' && s[11] == 't' && s[12] == 's' && s[13] == '_' && s[14] == 's' && s[15] == 't' && s[16] == 'r' && !s[17]) {
        return Tag_program_stats_str;
    } else if (s[0] == 'r') {
        if (s[1] == 'e'&& s[2] == 'a'&& s[3] == 'l'&& s[4] == '_'&& s[5] == 't'&& s[6] == 'i'&& s[7] == 'm'&& s[8] == 'e') {
            if (!s[9]) {
                return Tag_real_time;
            } else if (s[9] == '_') {
                if (s[10] == 'a' && s[11] == 'v' && s[12] == 'a' && s[13] == 'i' && s[14] == 'l' && s[15] == 'a' && s[16] == 'b' && s[17] == 'l' && s[18] == 'e' && !s[19]) {
                    return Tag_real_time_available;
                } else if (s[10] == 'l' && s[11] == 'i' && s[12] == 'm' && s[13] == 'i' && s[14] == 't' && s[15] == '_' && s[16] == 'm' && s[17] == 's' && !s[18]) {
                    return Tag_real_time_limit_ms;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (s[1] == 'o' && s[2] == 'w' && !s[3]) {
            return Tag_row;
        } else if (s[1] == 'u'&& s[2] == 'n'&& s[3] == '_') {
            if (s[4] == 'i' && s[5] == 'd' && !s[6]) {
                return Tag_run_id;
            } else if (s[4] == 't' && s[5] == 'e' && s[6] == 's' && s[7] == 't' && s[8] == 's' && !s[9]) {
                return Tag_run_tests;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else if (s[0] == 's') {
        if (s[1] == 'c'&& s[2] == 'o'&& s[3] == 'r') {
            if (s[4] == 'e' && !s[5]) {
                return Tag_score;
            } else if (s[4] == 'i' && s[5] == 'n' && s[6] == 'g' && !s[7]) {
                return Tag_scoring;
            } else {
                return 0;
            }
        } else if (s[1] == 'e' && s[2] == 'p' && s[3] == 'a' && s[4] == 'r' && s[5] == 'a' && s[6] == 't' && s[7] == 'e' && s[8] == '_' && s[9] == 'u' && s[10] == 's' && s[11] == 'e' && s[12] == 'r' && s[13] == '_' && s[14] == 's' && s[15] == 'c' && s[16] == 'o' && s[17] == 'r' && s[18] == 'e' && !s[19]) {
            return Tag_separate_user_score;
        } else if (s[1] == 'i' && s[2] == 'z' && s[3] == 'e' && !s[4]) {
            return Tag_size;
        } else if (s[1] == 't') {
            if (s[2] == 'a' && s[3] == 't' && s[4] == 'u' && s[5] == 's' && !s[6]) {
                return Tag_status;
            } else if (s[2] == 'd'&& s[3] == 'e'&& s[4] == 'r'&& s[5] == 'r') {
                if (!s[6]) {
                    return Tag_stderr;
                } else if (s[6] == '_' && s[7] == 'a' && s[8] == 'v' && s[9] == 'a' && s[10] == 'i' && s[11] == 'l' && s[12] == 'a' && s[13] == 'b' && s[14] == 'l' && s[15] == 'e' && !s[16]) {
                    return Tag_stderr_available;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (s[1] == 'u' && s[2] == 'b' && s[3] == 'm' && s[4] == 'i' && s[5] == 't' && s[6] == '_' && s[7] == 'i' && s[8] == 'd' && !s[9]) {
            return Tag_submit_id;
        } else {
            return 0;
        }
    } else if (s[0] == 't') {
        if (s[1] == 'e') {
            if (s[2] == 'a' && s[3] == 'm' && s[4] == '_' && s[5] == 'c' && s[6] == 'o' && s[7] == 'm' && s[8] == 'm' && s[9] == 'e' && s[10] == 'n' && s[11] == 't' && !s[12]) {
                return Tag_team_comment;
            } else if (s[2] == 'r' && s[3] == 'm' && s[4] == '_' && s[5] == 's' && s[6] == 'i' && s[7] == 'g' && s[8] == 'n' && s[9] == 'a' && s[10] == 'l' && !s[11]) {
                return Tag_term_signal;
            } else if (s[2] == 's'&& s[3] == 't') {
                if (!s[4]) {
                    return Tag_test;
                } else if (s[4] == '_' && s[5] == 'c' && s[6] == 'h' && s[7] == 'e' && s[8] == 'c' && s[9] == 'k' && s[10] == 'e' && s[11] == 'r' && !s[12]) {
                    return Tag_test_checker;
                } else if (s[4] == 's') {
                    if (!s[5]) {
                        return Tag_tests;
                    } else if (s[5] == '_') {
                        if (s[6] == 'm' && s[7] == 'o' && s[8] == 'd' && s[9] == 'e' && !s[10]) {
                            return Tag_tests_mode;
                        } else if (s[6] == 'p' && s[7] == 'a' && s[8] == 's' && s[9] == 's' && s[10] == 'e' && s[11] == 'd' && !s[12]) {
                            return Tag_tests_passed;
                        } else {
                            return 0;
                        }
                    } else {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if (s[1] == 'i'&& s[2] == 'm'&& s[3] == 'e') {
            if (!s[4]) {
                return Tag_time;
            } else if (s[4] == '_' && s[5] == 'l' && s[6] == 'i' && s[7] == 'm' && s[8] == 'i' && s[9] == 't' && s[10] == '_' && s[11] == 'm' && s[12] == 's' && !s[13]) {
                return Tag_time_limit_ms;
            } else {
                return 0;
            }
        } else if (s[1] == 'o' && s[2] == 'o' && s[3] == '_' && s[4] == 'b' && s[5] == 'i' && s[6] == 'g' && !s[7]) {
            return Tag_too_big;
        } else if (s[1] == 't') {
            if (s[2] == '_') {
                if (s[3] == 'c' && s[4] == 'o' && s[5] == 'l' && s[6] == 'u' && s[7] == 'm' && s[8] == 'n' && s[9] == '_' && s[10] == 'c' && s[11] == 'o' && s[12] == 'u' && s[13] == 'n' && s[14] == 't' && !s[15]) {
                    return Tag_tt_column_count;
                } else if (s[3] == 'r' && s[4] == 'o' && s[5] == 'w' && s[6] == '_' && s[7] == 'c' && s[8] == 'o' && s[9] == 'u' && s[10] == 'n' && s[11] == 't' && !s[12]) {
                    return Tag_tt_row_count;
                } else {
                    return 0;
                }
            } else if (s[2] == 'c'&& s[3] == 'e'&& s[4] == 'l'&& s[5] == 'l') {
                if (!s[6]) {
                    return Tag_ttcell;
                } else if (s[6] == 's' && !s[7]) {
                    return Tag_ttcells;
                } else {
                    return 0;
                }
            } else if (s[2] == 'r'&& s[3] == 'o'&& s[4] == 'w') {
                if (!s[5]) {
                    return Tag_ttrow;
                } else if (s[5] == 's' && !s[6]) {
                    return Tag_ttrows;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else if (s[0] == 'u') {
        if (s[1] == 's'&& s[2] == 'e'&& s[3] == 'r'&& s[4] == '_') {
            if (s[5] == 'm' && s[6] == 'a' && s[7] == 'x' && s[8] == '_' && s[9] == 's' && s[10] == 'c' && s[11] == 'o' && s[12] == 'r' && s[13] == 'e' && !s[14]) {
                return Tag_user_max_score;
            } else if (s[5] == 'n' && s[6] == 'o' && s[7] == 'm' && s[8] == 'i' && s[9] == 'n' && s[10] == 'a' && s[11] == 'l' && s[12] == '_' && s[13] == 's' && s[14] == 'c' && s[15] == 'o' && s[16] == 'r' && s[17] == 'e' && !s[18]) {
                return Tag_user_nominal_score;
            } else if (s[5] == 'r' && s[6] == 'u' && s[7] == 'n' && s[8] == '_' && s[9] == 't' && s[10] == 'e' && s[11] == 's' && s[12] == 't' && s[13] == 's' && !s[14]) {
                return Tag_user_run_tests;
            } else if (s[5] == 's') {
                if (s[6] == 'c' && s[7] == 'o' && s[8] == 'r' && s[9] == 'e' && !s[10]) {
                    return Tag_user_score;
                } else if (s[6] == 't' && s[7] == 'a' && s[8] == 't' && s[9] == 'u' && s[10] == 's' && !s[11]) {
                    return Tag_user_status;
                } else {
                    return 0;
                }
            } else if (s[5] == 't' && s[6] == 'e' && s[7] == 's' && s[8] == 't' && s[9] == 's' && s[10] == '_' && s[11] == 'p' && s[12] == 'a' && s[13] == 's' && s[14] == 's' && s[15] == 'e' && s[16] == 'd' && !s[17]) {
                return Tag_user_tests_passed;
            } else {
                return 0;
            }
        } else if (s[1] == 'u' && s[2] == 'i' && s[3] == 'd' && !s[4]) {
            return Tag_uuid;
        } else {
            return 0;
        }
    } else if (s[0] == 'v') {
        if (s[1] == 'a') {
            if (s[2] == 'l'&& s[3] == 'u'&& s[4] == 'e'&& s[5] == 'r'&& s[6] == '_') {
                if (s[7] == 'c' && s[8] == 'o' && s[9] == 'm' && s[10] == 'm' && s[11] == 'e' && s[12] == 'n' && s[13] == 't' && !s[14]) {
                    return Tag_valuer_comment;
                } else if (s[7] == 'e' && s[8] == 'r' && s[9] == 'r' && s[10] == 'o' && s[11] == 'r' && s[12] == 's' && !s[13]) {
                    return Tag_valuer_errors;
                } else if (s[7] == 'j' && s[8] == 'u' && s[9] == 'd' && s[10] == 'g' && s[11] == 'e' && s[12] == '_' && s[13] == 'c' && s[14] == 'o' && s[15] == 'm' && s[16] == 'm' && s[17] == 'e' && s[18] == 'n' && s[19] == 't' && !s[20]) {
                    return Tag_valuer_judge_comment;
                } else {
                    return 0;
                }
            } else if (s[2] == 'r' && s[3] == 'i' && s[4] == 'a' && s[5] == 'n' && s[6] == 't' && !s[7]) {
                return Tag_variant;
            } else {
                return 0;
            }
        } else if (s[1] == 'e' && s[2] == 'r' && s[3] == 'd' && s[4] == 'i' && s[5] == 'c' && s[6] == 't' && s[7] == '_' && s[8] == 'b' && s[9] == 'i' && s[10] == 't' && s[11] == 's' && !s[12]) {
            return Tag_verdict_bits;
        } else if (s[1] == 'i' && s[2] == 's' && s[3] == 'i' && s[4] == 'b' && s[5] == 'i' && s[6] == 'l' && s[7] == 'i' && s[8] == 't' && s[9] == 'y' && !s[10]) {
            return Tag_visibility;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
    return 0;
}

