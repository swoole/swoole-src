/*
+----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
 */

#include "php_swoole_stdext.h"

#define MAX_ARGC 8

/**
 * This module aims to enhance the PHP standard library without modifying the php-src core code.
 * It seeks to introduce strongly-typed arrays and enable the use of built-in methods directly on arrays and strings,
 * instead of relying on array_* or str_* functions.
 */

static struct {
    zval func;
    zval this_;
    uint8_t op1_type;
} call_info;

static zend_function *fn_swoole_call_array_method = nullptr;
static zend_function *fn_swoole_call_string_method = nullptr;

static zend_function *get_function(const zend_array *function_table, const char *name, size_t name_len) {
    return static_cast<zend_function *>(zend_hash_str_find_ptr(function_table, name, name_len));
}

static void call_func_switch_arg_1_and_2(zend_function *fn, zend_execute_data *execute_data, zval *retval) {
    zval argv[MAX_ARGC];
    const zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = MIN(ZEND_CALL_NUM_ARGS(execute_data), MAX_ARGC);
    argv[0] = arg_ptr[1];
    argv[1] = arg_ptr[0];
    for (int i = 2; i < arg_count; i++) {
        argv[i] = arg_ptr[i];
    }
    zend_call_known_function(fn, nullptr, nullptr, retval, arg_count, argv, nullptr);
}

static std::unordered_map<std::string, std::string> array_methods = {
    {"all", "array_all"},
    {"any", "array_any"},
    {"changeKeyCase", "array_change_key_case"},
    {"chunk", "array_chunk"},
    {"column", "array_column"},
    {"countValues", "array_count_values"},
    {"diff", "array_diff"},
    {"diffAssoc", "array_diff_assoc"},
    {"diffKey", "array_diff_key"},
    {"filter", "array_filter"},
    {"find", "array_find"},
    {"flip", "array_flip"},
    {"intersect", "array_intersect"},
    {"intersectAssoc", "array_intersect_assoc"},
    {"isList", "array_is_list"},
    {"keyExists", "swoole_array_key_exists"},
    {"keyFirst", "array_key_first"},
    {"keyLast", "array_key_last"},
    {"keys", "array_keys"},
    {"map", "swoole_array_map"},
    {"pad", "array_pad"},
    {"product", "array_product"},
    {"rand", "array_rand"},
    {"reduce", "array_reduce"},
    {"replace", "array_replace"},
    {"reverse", "array_reverse"},
    {"search", "swoole_array_search"},
    {"slice", "array_slice"},
    {"sum", "array_sum"},
    {"unique", "array_unique"},
    {"values", "array_values"},
    {"count", "count"},
    {"contains", "swoole_array_contains"},
    {"join", "swoole_array_join"},
};

static std::unordered_map<std::string, std::string> string_methods = {
    {"length", "strlen"},
    {"toLower", "strtolower"},
    {"toUpper", "strtoupper"},
    {"addCSlashes", "addcslashes"},
    {"addSlashes", "addslashes"},
    {"bin2hex", "bin2hex"},
    {"hex2bin", "hex2bin"},
    {"chunkSplit", "chunk_split"},
    {"countChars", "count_chars"},
    {"crypt", "crypt"},
    {"htmlEntityDecode", "html_entity_decode"},
    {"htmlEntityEncode", "htmlentities"},
    {"htmlSpecialCharsEncode", "htmlspecialchars"},
    {"htmlSpecialCharsDecode", "htmlspecialchars_decode"},
    {"lowerCaseFirst", "lcfirst"},
    {"trim", "trim"},
    {"ltrim", "ltrim"},
    {"rtrim", "rtrim"},
    {"nl2br", "nl2br"},
    {"parseUrlQuery", "parse_str"},
    {"soundex", "soundex"},
    {"contains", "str_contains"},
    {"increment", "str_increment"},
    {"caseReplace", "str_ireplace"},
    {"pad", "str_pad"},
    {"repeat", "str_repeat"},
    {"replace", "str_replace"},
    {"shuffle", "str_shuffle"},
    {"split", "swoole_str_split"},
    {"startsWith", "str_starts_with"},
    {"endsWith", "str_ends_with"},
    {"wordCount", "str_word_count"},
    {"caseCmp", "strcasecmp"},
    {"cmp", "strcmp"},
    {"find", "strstr"},
    {"caseFind", "stristr"},
    {"stripTags", "strip_tags"},
    {"stripCSlashes", "stripcslashes"},
    {"stripSlashes", "stripslashes"},
    {"caseIndexOf", "stripos"},
    {"upperCaseFirst", "ucfirst"},
    {"upperCaseWords", "ucwords"},
    {"indexOf", "strpos"},
    {"substr", "substr"},
    {"md5", "md5"},
    {"sha1", "sha1"},
    {"crc32", "crc32"},
};

static void call_method(const std::unordered_map<std::string, std::string> &method_map,
                        zend_execute_data *execute_data,
                        zval *retval) {
    const auto name = std::string(Z_STRVAL(call_info.func), Z_STRLEN(call_info.func));
    const auto iter = method_map.find(name);
    if (iter == method_map.end()) {
    _not_found:
        zend_throw_error(
            nullptr, "The method `%s` is undefined on %s", name.c_str(), zend_zval_type_name(&call_info.this_));
        return;
    }
    const auto real_fn = iter->second;
    const auto fn = get_function(EG(function_table), real_fn.c_str(), real_fn.length());
    if (!fn) {
        goto _not_found;
    }
    zval argv[MAX_ARGC];
    const zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = MIN(ZEND_CALL_NUM_ARGS(execute_data), MAX_ARGC);
    argv[0] = call_info.this_;
    for (int i = 0; i < arg_count; i++) {
        argv[i + 1] = arg_ptr[i];
    }
    zend_call_known_function(fn, nullptr, nullptr, retval, arg_count + 1, argv, nullptr);
    if (call_info.op1_type == IS_VAR) {
        zval_ptr_dtor(&call_info.this_);
    }
}

static void init_func_run_time_cache_i(zend_op_array *op_array) {
    ZEND_ASSERT(RUN_TIME_CACHE(op_array) == nullptr);
    const auto run_time_cache = static_cast<void **>(zend_arena_alloc(&CG(arena), op_array->cache_size));
    memset(run_time_cache, 0, op_array->cache_size);
    ZEND_MAP_PTR_SET(op_array->run_time_cache, run_time_cache);
}

static int method_call_handler(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    zval *object;
    if (opline->op1_type == IS_CONST) {
        object = RT_CONSTANT(opline, opline->op1);
    } else if (UNEXPECTED(opline->op1_type == IS_UNUSED)) {
        return ZEND_USER_OPCODE_DISPATCH;
    } else {
        object = EX_VAR(opline->op1.var);
    }

    if (Z_TYPE_P(object) == IS_ARRAY || Z_TYPE_P(object) == IS_STRING) {
        call_info.func = *RT_CONSTANT(opline, opline->op2);
        call_info.this_ = *object;
        call_info.op1_type = opline->op1_type;
        zend_function *fbc = Z_TYPE_P(object) == IS_ARRAY ? fn_swoole_call_array_method : fn_swoole_call_string_method;
        zend_execute_data *call =
            zend_vm_stack_push_call_frame(ZEND_CALL_NESTED_FUNCTION, fbc, opline->extended_value, nullptr);
        if (EXPECTED(fbc->type == ZEND_USER_FUNCTION) && UNEXPECTED(!RUN_TIME_CACHE(&fbc->op_array))) {
            init_func_run_time_cache_i(&fbc->op_array);
        }
        call->prev_execute_data = EX(call);
        EX(call) = call;
        EX(opline)++;

        // printf("method=%s, opline->op1_type=%d\n", Z_STRVAL(_x_func), opline->op1_type);

        return ZEND_USER_OPCODE_CONTINUE;
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

void php_swoole_stdext_minit(int module_number) {
    zend_set_user_opcode_handler(ZEND_INIT_METHOD_CALL, method_call_handler);
    fn_swoole_call_array_method = get_function(CG(function_table), ZEND_STRL("swoole_call_array_method"));
    fn_swoole_call_string_method = get_function(CG(function_table), ZEND_STRL("swoole_call_string_method"));
}

PHP_FUNCTION(swoole_array_search) {
    static zend_function *fn_array_search = nullptr;
    if (!fn_array_search) {
        fn_array_search = get_function(CG(function_table), ZEND_STRL("array_search"));
    }
    call_func_switch_arg_1_and_2(fn_array_search, execute_data, return_value);
}

PHP_FUNCTION(swoole_array_contains) {
    static zend_function *fn_in_array = nullptr;
    if (!fn_in_array) {
        fn_in_array = get_function(CG(function_table), ZEND_STRL("in_array"));
    }
    return call_func_switch_arg_1_and_2(fn_in_array, execute_data, return_value);
}

PHP_FUNCTION(swoole_array_join) {
    static zend_function *fn_implode = nullptr;
    if (!fn_implode) {
        fn_implode = get_function(CG(function_table), ZEND_STRL("implode"));
    }
    call_func_switch_arg_1_and_2(fn_implode, execute_data, return_value);
}

PHP_FUNCTION(swoole_str_split) {
    static zend_function *fn_explode = nullptr;
    if (!fn_explode) {
        fn_explode = get_function(CG(function_table), ZEND_STRL("explode"));
    }
    call_func_switch_arg_1_and_2(fn_explode, execute_data, return_value);
}

PHP_FUNCTION(swoole_array_key_exists) {
    static zend_function *fn_array_key_exists = nullptr;
    if (!fn_array_key_exists) {
        fn_array_key_exists = get_function(CG(function_table), ZEND_STRL("array_key_exists"));
    }
    call_func_switch_arg_1_and_2(fn_array_key_exists, execute_data, return_value);
}

PHP_FUNCTION(swoole_array_map) {
    static zend_function *fn_array_map = nullptr;
    if (!fn_array_map) {
        fn_array_map = get_function(CG(function_table), ZEND_STRL("array_map"));
    }
    call_func_switch_arg_1_and_2(fn_array_map, execute_data, return_value);
}

PHP_FUNCTION(swoole_call_array_method) {
    call_method(array_methods, execute_data, return_value);
}

PHP_FUNCTION(swoole_call_string_method) {
    call_method(string_methods, execute_data, return_value);
}
