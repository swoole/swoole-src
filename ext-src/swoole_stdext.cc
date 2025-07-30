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
#include "php_variables.h"
#include "thirdparty/php/zend/zend_opcode_execute.h"

#define MAX_ARGC 16
#define HASH_FLAG_TYPED_ARRAY (1 << 30)

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

struct ArrayTypeInfo {
    bool strict;
    uint8_t type_of_value;
    uint8_t type_of_key;
    uint8_t element_type_of_key;
    uint8_t element_type_of_value;
    uint16_t element_offset_of_value_type_str;
    uint16_t element_len_of_value_type_str;
    zend_class_entry *value_ce;
    uint16_t len_of_value_type_str;
    char value_type_str[0];
};

static zend_function *fn_swoole_call_array_method = nullptr;
static zend_function *fn_swoole_call_string_method = nullptr;

static int opcode_handler_array_assign(zend_execute_data *execute_data);
static int opcode_handler_array_unset(zend_execute_data *execute_data);
static int opcode_handler_method_call(zend_execute_data *execute_data);
static ArrayTypeInfo *get_type_info(zend_array *array);

static zend_function *get_function(const zend_array *function_table, const char *name, size_t name_len) {
    return static_cast<zend_function *>(zend_hash_str_find_ptr(function_table, name, name_len));
}

static void call_function(zend_function *fn, int argc, zval *argv, zval *retval) {
    zend_call_known_function(fn, nullptr, nullptr, retval, argc, argv, nullptr);
    if (call_info.op1_type == IS_VAR) {
        zval_ptr_dtor(&call_info.this_);
    }
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
    // pass by ref
    {"sort", "sort"},
    {"pop", "array_pop"},
    {"push", "array_push"},
    {"shift", "array_shift"},
    {"unshift", "array_unshift"},
    {"shift", "array_splice"},
    {"walk", "array_walk"},
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
    {"parseStr", "swoole_parse_str"},
    {"parseUrl", "parse_url"},
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
    {"substrCompare", "substr_compare"},
    {"substrCount", "substr_count"},
    {"substrReplace", "substr_replace"},
    {"md5", "md5"},
    {"sha1", "sha1"},
    {"hash", "swoole_hash"},
    {"crc32", "crc32"},
    {"wordWrap", "wordwrap"},
    {"base64Decode", "base64_decode"},
    {"base64Encode", "base64_encode"},
    {"urlDecode", "urldecode"},
    {"urlEncode", "urlencode"},
};

static void call_func_switch_arg_1_and_2(zend_function *fn, zend_execute_data *execute_data, zval *retval) {
    zval argv[MAX_ARGC];
    const zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = MIN(ZEND_CALL_NUM_ARGS(execute_data), MAX_ARGC);
    argv[0] = arg_ptr[1];
    argv[1] = arg_ptr[0];
    for (int i = 2; i < arg_count; i++) {
        argv[i] = arg_ptr[i];
    }
    call_function(fn, arg_count, argv, retval);
}

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
    call_function(fn, arg_count + 1, argv, retval);
}

static void init_func_run_time_cache_i(zend_op_array *op_array) {
    ZEND_ASSERT(RUN_TIME_CACHE(op_array) == nullptr);
    const auto run_time_cache = static_cast<void **>(zend_arena_alloc(&CG(arena), op_array->cache_size));
    memset(run_time_cache, 0, op_array->cache_size);
    ZEND_MAP_PTR_SET(op_array->run_time_cache, run_time_cache);
}

static int opcode_handler_method_call(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    zval *object;
    if (opline->op1_type == IS_CONST) {
        object = RT_CONSTANT(opline, opline->op1);
    } else if (UNEXPECTED(opline->op1_type == IS_UNUSED)) {
        return ZEND_USER_OPCODE_DISPATCH;
    } else {
        object = EX_VAR(opline->op1.var);
    }

    auto type = Z_TYPE_P(object);
    if (type == IS_REFERENCE) {
        type = Z_TYPE_P(Z_REFVAL_P(object));
    }

    if (type == IS_ARRAY || type == IS_STRING) {
        call_info.func = *RT_CONSTANT(opline, opline->op2);
        call_info.this_ = *object;
        call_info.op1_type = opline->op1_type;
        zend_function *fbc = type == IS_ARRAY ? fn_swoole_call_array_method : fn_swoole_call_string_method;
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
    zend_set_user_opcode_handler(ZEND_INIT_METHOD_CALL, opcode_handler_method_call);
    zend_set_user_opcode_handler(ZEND_ASSIGN_DIM, opcode_handler_array_assign);
    zend_set_user_opcode_handler(ZEND_UNSET_DIM, opcode_handler_array_unset);
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
    zval_add_ref(return_value);
}

PHP_FUNCTION(swoole_hash) {
    static zend_function *fn_hash = nullptr;
    if (!fn_hash) {
        fn_hash = get_function(CG(function_table), ZEND_STRL("hash"));
    }
    call_func_switch_arg_1_and_2(fn_hash, execute_data, return_value);
    zval_add_ref(return_value);
}

PHP_FUNCTION(swoole_parse_str) {
    char *arg;
    size_t arglen;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(arg, arglen)
    ZEND_PARSE_PARAMETERS_END();

    array_init(return_value);
    auto res = estrndup(arg, arglen);
    sapi_module.treat_data(PARSE_STRING, res, return_value);
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

ZEND_API HashTable *ZEND_FASTCALL sw_zend_new_array(const uint32_t nSize, const uint32_t nTypeStr) {
    const auto ht = static_cast<zend_array *>(emalloc(sizeof(HashTable) + sizeof(ArrayTypeInfo) + nTypeStr + 1));
    _zend_hash_init(ht, nSize, ZVAL_PTR_DTOR, false);
    HT_FLAGS(ht) |= HASH_FLAG_TYPED_ARRAY;
    return ht;
}

static ArrayTypeInfo *get_type_info(zend_array *array) {
    return reinterpret_cast<ArrayTypeInfo *>(reinterpret_cast<char *>(array) + sizeof(HashTable));
}

static zend_string *get_array_type_def(const ArrayTypeInfo *info) {
    zend_string *result = zend_string_alloc(info->len_of_value_type_str + 16, false);
    char *p = result->val;
    *p = '<';
    if (info->type_of_key == IS_STRING) {
        p++;
        strcpy(p, "string,");
        p += 7;
    } else if (info->type_of_key == IS_LONG) {
        p++;
        strcpy(p, "int,");
        p += 4;
    }

    memcpy(p, info->value_type_str, info->len_of_value_type_str);
    p += info->len_of_value_type_str;
    *p = '>';
    p++;
    *p = '\0';
    result->len = p - result->val;

    return result;
}

static bool type_check(zend_array *ht, zval *value) {
    auto type_info = get_type_info(ht);
    if (type_info->type_of_value == IS_TRUE && (Z_TYPE_P(value) == IS_TRUE || Z_TYPE_P(value) == IS_FALSE)) {
        return true;
    }
    if (Z_TYPE_P(value) != type_info->type_of_value) {
        zend_type_error("Array value type mismatch, expected `%s`, got `%s`",
                        zend_get_type_by_const(type_info->type_of_value),
                        zend_get_type_by_const(Z_TYPE_P(value)));
        return false;
    }
    if (type_info->type_of_value == IS_OBJECT && !instanceof_function(Z_OBJCE_P(value), type_info->value_ce)) {
        zend_type_error("Array value type mismatch, expected `%s`, got `%s`",
                        type_info->value_ce->name->val,
                        Z_OBJCE_P(value)->name->val);
        return false;
    }
    if (type_info->type_of_value == IS_ARRAY) {
        const auto element_array_type_info = get_type_info(Z_ARRVAL_P(value));
        const auto element_ht = Z_ARRVAL_P(value);
        if (!(HT_FLAGS(element_ht) & HASH_FLAG_TYPED_ARRAY)) {
            zend_type_error("Array value type mismatch, expected `%.*s`, got `array`",
                            type_info->len_of_value_type_str,
                            type_info->value_type_str);
            return false;
        }
        if (element_array_type_info->type_of_key != type_info->element_type_of_key ||
            element_array_type_info->type_of_value != type_info->element_type_of_value ||
            memcmp(element_array_type_info->value_type_str,
                   type_info->value_type_str + type_info->element_offset_of_value_type_str,
                   MIN(element_array_type_info->len_of_value_type_str, type_info->element_len_of_value_type_str)) !=
                0) {
            auto element_type_str = get_array_type_def(element_array_type_info);
            zend_type_error("Array value type mismatch, expected `%.*s`, got `%.*s`",
                            type_info->len_of_value_type_str,
                            type_info->value_type_str,
                            (int) ZSTR_LEN(element_type_str),
                            ZSTR_VAL(element_type_str));
            zend_string_release(element_type_str);
            return false;
        }
    }
    return true;
}

static int opcode_handler_array_assign(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    auto array = EX_VAR(opline->op1.var);
    if (Z_TYPE_P(array) != IS_ARRAY && Z_TYPE_P(array) != IS_REFERENCE) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    if (Z_TYPE_P(array) == IS_REFERENCE) {
        array = Z_REFVAL_P(array);
    }
    zend_array *ht = Z_ARRVAL_P(array);
    if (!(HT_FLAGS(ht) & HASH_FLAG_TYPED_ARRAY)) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    auto value = get_op_data_zval_ptr_r((opline + 1)->op1_type, (opline + 1)->op1);
    if (!type_check(ht, value)) {
        FREE_OP((opline + 1)->op1_type, (opline + 1)->op1.var);
        return ZEND_USER_OPCODE_CONTINUE;
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int opcode_handler_array_unset(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    auto array = EX_VAR(opline->op1.var);
    if (Z_TYPE_P(array) != IS_ARRAY && Z_TYPE_P(array) != IS_REFERENCE) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    if (Z_TYPE_P(array) == IS_REFERENCE) {
        array = Z_REFVAL_P(array);
    }
    zend_array *ht = Z_ARRVAL_P(array);
    if (!(HT_FLAGS(ht) & HASH_FLAG_TYPED_ARRAY)) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    auto type_info = get_type_info(ht);
    if (type_info->type_of_key == 0) {
        zend_throw_error(nullptr, "The typed array list do not support random deletion of elements");
        FREE_OP((opline + 1)->op1_type, (opline + 1)->op1.var);
        return ZEND_USER_OPCODE_CONTINUE;
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static void remove_all_spaces(char **val, size_t *len) {
    if (!*val || *len == 0) {
        return;
    }

    char *src = *val;
    char *dst = *val;
    size_t new_len = 0;

    for (size_t i = 0; i < *len; i++) {
        if (!isspace((unsigned char) *src)) {
            *dst = *src;
            dst++;
            new_len++;
        }
        src++;
    }

    *len = new_len;
}

static int8_t get_type(const char *val, size_t len) {
    if (SW_STRCASEEQ(val, len, "int")) {
        return IS_LONG;
    } else if (SW_STRCASEEQ(val, len, "float")) {
        return IS_DOUBLE;
    } else if (SW_STRCASEEQ(val, len, "string")) {
        return IS_STRING;
    } else if (SW_STRCASEEQ(val, len, "bool")) {
        return IS_TRUE;  // IS_TRUE or IS_FALSE
    } else if (val[0] == '<' && val[len - 1] == '>') {
        return IS_ARRAY;
    } else if (SW_STRCASEEQ(val, len, "resource")) {
        return IS_RESOURCE;
    } else if (SW_STRCASEEQ(val, len, "null")) {
        return IS_NULL;
    } else {
        return IS_OBJECT;
    }
}

static bool parse_array_type(const char *type_str,
                             size_t len_of_type_str,
                             uint8_t *type_of_key,
                             uint8_t *type_of_value,
                             uint16_t *offset_of_value_type_str,
                             uint16_t *len_of_value_type_str) {
    auto pos = strchr(type_str, ',');
    if (pos == nullptr) {
        *type_of_key = 0;
        *offset_of_value_type_str = 1;
    } else {
        *type_of_key = get_type(type_str + 1, pos - type_str - 1);
        if (*type_of_key != IS_STRING && *type_of_key != IS_LONG) {
            zend_throw_error(nullptr, "The key type of array must be string or int, but got %s", pos + 1);
            return false;
        }
        *offset_of_value_type_str = pos - type_str + 1;
    }
    *len_of_value_type_str = len_of_type_str - *offset_of_value_type_str - 1;
    *type_of_value = get_type(type_str + *offset_of_value_type_str, *len_of_value_type_str);
    return true;
}

PHP_FUNCTION(swoole_typed_array) {
    zend_string *type_def;
    zval *init_values = nullptr;
    bool strict = true;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_STR(type_def)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(init_values)
    Z_PARAM_BOOL(strict)
    ZEND_PARSE_PARAMETERS_END();

    zend::String tmp_type_def(zend_string_tolower(type_def), false);
    char *type_str = tmp_type_def.val();
    size_t len_of_type_str = tmp_type_def.len();
    remove_all_spaces(&type_str, &len_of_type_str);
    type_str[len_of_type_str] = '\0';

    uint8_t type_of_value, type_of_key = 0;
    uint16_t len_of_value_type_str = 0, offset_of_value_type_str = 0;

    if (!parse_array_type(type_str,
                          len_of_type_str,
                          &type_of_key,
                          &type_of_value,
                          &offset_of_value_type_str,
                          &len_of_value_type_str)) {
        return;
    }

    zend_class_entry *value_ce = nullptr;
    if (type_of_value == IS_OBJECT) {
        zend::String type_str_of_value(type_str + offset_of_value_type_str, len_of_value_type_str);
        value_ce = zend_lookup_class(type_str_of_value.get());
        if (!value_ce) {
            zend_throw_error(nullptr, "Class '%s' not found", type_str_of_value.val());
            return;
        }
    }

    auto array = sw_zend_new_array(0, len_of_type_str);
    ZVAL_ARR(return_value, array);
    auto info = get_type_info(array);
    info->strict = strict;
    info->type_of_value = type_of_value;
    info->type_of_key = type_of_key;
    info->value_ce = value_ce;
    info->len_of_value_type_str = len_of_value_type_str;
    memcpy(info->value_type_str, type_str + offset_of_value_type_str, len_of_value_type_str);
    info->value_type_str[len_of_value_type_str] = '\0';

    if (info->type_of_value == IS_ARRAY) {
        if (!parse_array_type(info->value_type_str,
                              len_of_value_type_str,
                              &info->element_type_of_key,
                              &info->element_type_of_value,
                              &info->element_offset_of_value_type_str,
                              &info->element_len_of_value_type_str)) {
            zval_ptr_dtor(return_value);
            RETURN_NULL();
        }
    }


}
