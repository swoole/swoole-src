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
#include "php_swoole_private.h"

#ifdef SW_STDEXT
#include "php_swoole_stdext.h"
#include "php_swoole_cxx.h"
#include "php_variables.h"

SW_EXTERN_C_BEGIN
#include "ext/pcre/php_pcre.h"
#include "ext/json/php_json.h"
#include "thirdparty/php/zend/zend_execute.c"
SW_EXTERN_C_END

enum HashFlag {
    HASH_FLAG_TYPED_ARRAY = (1 << 12),
};

/**
 * This module aims to enhance the PHP standard library without modifying the php-src core code.
 * It seeks to introduce strongly-typed arrays and enable the use of built-in methods directly on arrays and strings,
 * instead of relying on array_* or str_* functions.
 */

struct CallInfo {
    zval func;
    zval this_;
    uint8_t op1_type;
};

struct ArrayTypeValue {
    uint8_t type_of_value;
    uint8_t type_of_key;
    uint16_t offset_of_value_type_str;
    uint16_t len_of_value_type_str;

    bool parse(const char *type_str, size_t len_of_type_str);
};

struct ArrayTypeInfo {
    ArrayTypeValue self;
    ArrayTypeValue element;
    zend_class_entry *value_ce;
    uint16_t len_of_type_str;
    char type_str[0];

    bool parse(zend_string *type_def);
    bool equals(const ArrayTypeInfo *other) const {
        return self.type_of_key == other->self.type_of_key && self.type_of_value == other->self.type_of_value &&
               len_of_type_str == other->len_of_type_str && memcmp(type_str, other->type_str, len_of_type_str) == 0;
    }
    bool element_type_equals(const ArrayTypeInfo *element_array_type_info) const {
        return element_array_type_info->get_type_of_key() == element.type_of_key &&
               element_array_type_info->get_type_of_value() == element.type_of_value &&
               element_array_type_info->len_of_type_str == get_len_of_value_type_str() &&
               memcmp(element_array_type_info->type_str, get_value_type_str(), get_len_of_value_type_str()) == 0;
    }
    const char *get_value_type_str() const {
        return type_str + self.offset_of_value_type_str;
    }
    uint16_t get_len_of_type_str() const {
        return len_of_type_str;
    }
    uint16_t get_len_of_value_type_str() const {
        return self.len_of_value_type_str;
    }
    uint8_t get_type_of_key() const {
        return self.type_of_key;
    }
    uint8_t get_type_of_value() const {
        return self.type_of_value;
    }
    bool is_list() const {
        return self.type_of_key == 0;
    }
    bool value_is_bool() const {
        return self.type_of_value == IS_TRUE || self.type_of_value == IS_FALSE;
    }
    bool value_is_object() const {
        return self.type_of_value == IS_OBJECT;
    }
    bool value_is_array() const {
        return self.type_of_value == IS_ARRAY;
    }
    bool value_is_string() const {
        return self.type_of_value == IS_STRING;
    }
    bool value_is_numeric() const {
        return self.type_of_value == IS_LONG || self.type_of_value == IS_DOUBLE;
    }
    bool instance_of(const zval *value) const {
        return instanceof_function(Z_OBJCE_P(value), value_ce);
    }
    bool check(const zend_array *ht, const zval *key, const zval *value) const;
    ArrayTypeInfo *dup() const {
        const auto copy = static_cast<ArrayTypeInfo *>(emalloc(sizeof(ArrayTypeInfo) + get_len_of_type_str() + 1));
        memcpy(copy, this, sizeof(ArrayTypeInfo) + get_len_of_type_str() + 1);
        return copy;
    }
};

static zend_function *fn_swoole_call_array_method = nullptr;
static zend_function *fn_swoole_call_string_method = nullptr;
static zend_function *fn_swoole_call_stream_method = nullptr;
static zend_function *fn_array_push = nullptr;
static zend_function *fn_array_unshift = nullptr;
static zend_function *fn_array_splice = nullptr;
static zif_handler ori_handler_array_push;
static zif_handler ori_handler_array_unshift;
static zif_handler ori_handler_array_splice;

static int opcode_handler_array_assign(zend_execute_data *execute_data);
static int opcode_handler_array_assign_op(zend_execute_data *execute_data);
static int opcode_handler_array_unset(zend_execute_data *execute_data);
static int opcode_handler_foreach_begin(zend_execute_data *execute_data);
static int opcode_handler_method_call(zend_execute_data *execute_data);
static ArrayTypeInfo *get_type_info(zend_array *array);

static PHP_FUNCTION(swoole_array_push);
static PHP_FUNCTION(swoole_array_unshift);
static PHP_FUNCTION(swoole_array_splice);

static bool is_typed_array(const zval *zval) {
    return HT_FLAGS(Z_ARRVAL_P(zval)) & HASH_FLAG_TYPED_ARRAY;
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
    {"merge", "array_merge"},
    {"contains", "swoole_array_contains"},
    {"join", "swoole_array_join"},
    {"isTyped", "swoole_array_is_typed"},
    {"isEmpty", "swoole_array_is_empty"},
    // pass by ref
    {"sort", "sort"},
    {"pop", "array_pop"},
    {"push", "array_push"},
    {"shift", "array_shift"},
    {"unshift", "array_unshift"},
    {"splice", "array_splice"},
    {"walk", "array_walk"},
    {"replaceStr", "swoole_array_replace_str"},
    {"iReplaceStr", "swoole_array_ireplace_str"},
    // serialize
    {"serialize", "serialize"},
    {"marshal", "serialize"},
    {"jsonEncode", "json_encode"},
};

/**
 * i=ignore case, l=left, r=right
 */
static std::unordered_map<std::string, std::string> string_methods = {
    {"length", "strlen"},
    {"isEmpty", "swoole_str_is_empty"},
    {"lower", "strtolower"},
    {"upper", "strtoupper"},
    {"lowerFirst", "lcfirst"},
    {"upperFirst", "ucfirst"},
    {"upperWords", "ucwords"},
    {"addCSlashes", "addcslashes"},
    {"addSlashes", "addslashes"},
    {"chunkSplit", "chunk_split"},
    {"countChars", "count_chars"},
    {"htmlEntityDecode", "html_entity_decode"},
    {"htmlEntityEncode", "htmlentities"},
    {"htmlSpecialCharsEncode", "htmlspecialchars"},
    {"htmlSpecialCharsDecode", "htmlspecialchars_decode"},
    {"trim", "trim"},
    {"lTrim", "ltrim"},
    {"rTrim", "rtrim"},
    {"parseStr", "swoole_parse_str"},
    {"parseUrl", "parse_url"},
    {"contains", "str_contains"},
    {"incr", "str_increment"},
    {"decr", "str_decrement"},
    {"pad", "str_pad"},
    {"repeat", "str_repeat"},
    {"replace", "swoole_str_replace"},
    {"iReplace", "swoole_str_ireplace"},
    {"shuffle", "str_shuffle"},
    {"split", "swoole_str_split"},  // explode
    {"startsWith", "str_starts_with"},
    {"endsWith", "str_ends_with"},
    {"wordCount", "str_word_count"},
    {"iCompare", "strcasecmp"},
    {"compare", "strcmp"},
    {"find", "strstr"},
    {"iFind", "stristr"},
    {"stripTags", "strip_tags"},
    {"stripCSlashes", "stripcslashes"},
    {"stripSlashes", "stripslashes"},
    {"iIndexOf", "stripos"},
    {"indexOf", "strpos"},
    {"lastIndexOf", "strrpos"},
    {"iLastIndexOf", "strripos"},
    {"lastCharIndexOf", "strrchr"},
    {"substr", "substr"},
    {"substrCompare", "substr_compare"},
    {"substrCount", "substr_count"},
    {"substrReplace", "substr_replace"},
    {"reverse", "strrev"},
    {"md5", "md5"},
    {"sha1", "sha1"},
    {"crc32", "crc32"},
    {"hash", "swoole_hash"},
    {"hashCode", "swoole_hashcode"},
    {"base64Decode", "base64_decode"},
    {"base64Encode", "base64_encode"},
    {"urlDecode", "urldecode"},
    {"urlEncode", "urlencode"},
    {"rawUrlEncode", "rawurlencode"},
    {"rawUrlDecode", "rawurldecode"},
    {"match", "swoole_str_match"},
    {"matchAll", "swoole_str_match_all"},
    {"isNumeric", "is_numeric"},
    // mbstring
    {"mbUpperFirst", "mb_ucfirst"},
    {"mbLowerFirst", "mb_lcfirst"},
    {"mbTrim", "mb_trim"},
    {"mbSubstrCount", "mb_substr_count"},
    {"mbSubstr", "mb_substr"},
    {"mbUpper", "mb_strtoupper"},
    {"mbLower", "mb_strtolower"},
    {"mbFind", "mb_strstr"},
    {"mbIndexOf", "mb_strpos"},
    {"mbLastIndexOf", "mb_strrpos"},
    {"mbILastIndexOf", "mb_strripos"},
    {"mbLastCharIndexOf", "mb_strrchr"},
    {"mbILastCharIndex", "mb_strrichr"},
    {"mbLength", "mb_strlen"},
    {"mbIFind", "mb_stristr"},
    {"mbIIndexOf", "mb_stripos"},
    {"mbCut", "mb_strcut"},
    {"mbRTrim", "mb_rtrim"},
    {"mbLTrim", "mb_ltrim"},
    {"mbDetectEncoding", "mb_detect_encoding"},
    {"mbConvertEncoding", "mb_convert_encoding"},
    {"mbConvertCase", "mb_convert_case"},
    // serialize
    {"unserialize", "unserialize"},
    {"unmarshal", "unserialize"},
    {"jsonDecode", "swoole_str_json_decode"},
    {"jsonDecodeToObject", "swoole_str_json_decode_to_object"},
};

static std::unordered_map<std::string, std::string> stream_methods = {
    {"write", "fwrite"},
    {"read", "fread"},
    {"close", "fclose"},
    {"dataSync", "fdatasync"},
    {"sync", "fsync"},
    {"truncate", "ftruncate"},
    {"stat", "fstat"},
    {"seek", "fseek"},
    {"tell", "ftell"},
    {"lock", "flock"},
    {"eof", "feof"},
    {"getChar", "fgetc"},
    {"getLine", "fgets"},
};

static void move_first_element(const zval src[], zval dst[], int size, int position) {
    zval first = src[0];
    for (int i = 0; i < position; i++) {
        dst[i] = src[i + 1];
    }
    dst[position] = first;
    for (int i = position + 1; i < size; i++) {
        dst[i] = src[i];
    }
}

static void call_func_move_first_arg(zend_function *fn, zend_execute_data *execute_data, zval *retval, int position) {
    const zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = ZEND_CALL_NUM_ARGS(execute_data);
    const auto argv = static_cast<zval *>(ecalloc(arg_count, sizeof(zval)));
    move_first_element(arg_ptr, argv, arg_count, position);
    zend_call_known_function(fn, nullptr, nullptr, retval, arg_count, argv, nullptr);
    efree(argv);
}

static void call_method(const std::unordered_map<std::string, std::string> &method_map,
                        zend_execute_data *execute_data,
                        zval *retval) {
    const auto call_info = reinterpret_cast<CallInfo *>(execute_data->run_time_cache);
    const auto name = std::string(Z_STRVAL(call_info->func), Z_STRLEN(call_info->func));
    const auto iter = method_map.find(name);

    ON_SCOPE_EXIT {
        efree(call_info);
        execute_data->run_time_cache = nullptr;
    };

    if (iter == method_map.end()) {
        zend_throw_error(
            nullptr, "The method `%s` is undefined on %s", name.c_str(), zend_zval_type_name(&call_info->this_));
        return;
    }
    const auto real_fn = iter->second;
    const auto fn = zend::get_function(real_fn.c_str(), real_fn.length());
    if (!fn) {
        zend_throw_error(nullptr, "The function `%s` is undefined", real_fn.c_str());
        return;
    }

    const zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = ZEND_CALL_NUM_ARGS(execute_data);
    const auto argv = static_cast<zval *>(ecalloc(arg_count + 1, sizeof(zval)));

    argv[0] = call_info->this_;
    for (int i = 0; i < arg_count; i++) {
        argv[i + 1] = arg_ptr[i];
    }

    zend_call_known_function(fn, nullptr, nullptr, retval, arg_count + 1, argv, nullptr);
    if (call_info->op1_type == IS_VAR) {
        zval_ptr_dtor(&call_info->this_);
    }
    efree(argv);
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

    if (type == IS_ARRAY || type == IS_STRING || type == IS_RESOURCE) {
        auto call_info = static_cast<CallInfo *>(emalloc(sizeof(CallInfo)));
        call_info->func = *RT_CONSTANT(opline, opline->op2);
        call_info->this_ = *object;
        call_info->op1_type = opline->op1_type;

        zend_function *fbc = nullptr;
        switch (type) {
        case IS_ARRAY:
            fbc = fn_swoole_call_array_method;
            break;
        case IS_STRING:
            fbc = fn_swoole_call_string_method;
            break;
        default:
            fbc = fn_swoole_call_stream_method;
        }

        zend_execute_data *call =
            zend_vm_stack_push_call_frame(ZEND_CALL_NESTED_FUNCTION, fbc, opline->extended_value, object);

        call->run_time_cache = reinterpret_cast<void **>(call_info);
        call->prev_execute_data = EX(call);
        EX(call) = call;
        EX(opline)++;

        return ZEND_USER_OPCODE_CONTINUE;
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

void php_swoole_stdext_minit(int module_number) {
    zend_set_user_opcode_handler(ZEND_INIT_METHOD_CALL, opcode_handler_method_call);
    zend_set_user_opcode_handler(ZEND_ASSIGN_DIM, opcode_handler_array_assign);
    zend_set_user_opcode_handler(ZEND_ASSIGN_DIM_OP, opcode_handler_array_assign_op);
    zend_set_user_opcode_handler(ZEND_UNSET_DIM, opcode_handler_array_unset);
    zend_set_user_opcode_handler(ZEND_FE_RESET_RW, opcode_handler_foreach_begin);

    fn_swoole_call_array_method = zend::get_function(CG(function_table), ZEND_STRL("swoole_call_array_method"));
    fn_swoole_call_string_method = zend::get_function(CG(function_table), ZEND_STRL("swoole_call_string_method"));
    fn_swoole_call_stream_method = zend::get_function(CG(function_table), ZEND_STRL("swoole_call_stream_method"));

    fn_array_push = zend::get_function(CG(function_table), ZEND_STRL("array_push"));
    fn_array_unshift = zend::get_function(CG(function_table), ZEND_STRL("array_unshift"));
    fn_array_splice = zend::get_function(CG(function_table), ZEND_STRL("array_splice"));

    ori_handler_array_push = fn_array_push->internal_function.handler;
    fn_array_push->internal_function.handler = ZEND_FN(swoole_array_push);
    ori_handler_array_unshift = fn_array_unshift->internal_function.handler;
    fn_array_unshift->internal_function.handler = ZEND_FN(swoole_array_unshift);
    ori_handler_array_splice = fn_array_splice->internal_function.handler;
    fn_array_splice->internal_function.handler = ZEND_FN(swoole_array_splice);
}

#define SW_CREATE_PHP_FUNCTION_WRAPPER(php_func_name, swoole_func_name, position)                                      \
    PHP_FUNCTION(swoole_func_name) {                                                                                   \
        static zend_function *fn_##swoole_func_name = nullptr;                                                         \
        if (!fn_##swoole_func_name) {                                                                                  \
            fn_##swoole_func_name = zend::get_function(CG(function_table), ZEND_STRL(#php_func_name));                 \
        }                                                                                                              \
        call_func_move_first_arg(fn_##swoole_func_name, execute_data, return_value, position);                         \
    }

// array
SW_CREATE_PHP_FUNCTION_WRAPPER(array_search, swoole_array_search, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(in_array, swoole_array_contains, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(implode, swoole_array_join, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(array_key_exists, swoole_array_key_exists, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(array_map, swoole_array_map, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(str_replace, swoole_array_replace_str, 2);
SW_CREATE_PHP_FUNCTION_WRAPPER(str_ireplace, swoole_array_ireplace_str, 2);

// string
SW_CREATE_PHP_FUNCTION_WRAPPER(explode, swoole_str_split, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(hash, swoole_hash, 1);
SW_CREATE_PHP_FUNCTION_WRAPPER(str_replace, swoole_str_replace, 2);
SW_CREATE_PHP_FUNCTION_WRAPPER(str_ireplace, swoole_str_ireplace, 2);

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

PHP_FUNCTION(swoole_str_is_empty) {
    zend_string *str;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();
    RETURN_BOOL(str->len == 0);
}

PHP_FUNCTION(swoole_array_is_empty) {
    zval *array;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(array)
    ZEND_PARSE_PARAMETERS_END();
    RETURN_BOOL(zend_array_count(Z_ARRVAL_P(array)) == 0);
}

PHP_FUNCTION(swoole_call_array_method) {
    call_method(array_methods, execute_data, return_value);
}

PHP_FUNCTION(swoole_call_string_method) {
    call_method(string_methods, execute_data, return_value);
}

PHP_FUNCTION(swoole_call_stream_method) {
    call_method(stream_methods, execute_data, return_value);
}

static HashTable *make_typed_array(const uint32_t nSize, const uint32_t nTypeStr) {
    const auto ht = static_cast<zend_array *>(emalloc(sizeof(HashTable) + sizeof(ArrayTypeInfo) + nTypeStr + 1));
    _zend_hash_init(ht, nSize, ZVAL_PTR_DTOR, false);
    HT_FLAGS(ht) |= HASH_FLAG_TYPED_ARRAY;
    return ht;
}

void copy_array_type_info(zval *container, zend_array *src) {
    auto src_type_info = get_type_info(src);
    zend_array *ht = Z_ARRVAL_P(container);
    auto extra_size = sizeof(ArrayTypeInfo) + src_type_info->get_len_of_type_str() + 1;
    const auto tmp = static_cast<zend_array *>(emalloc(sizeof(HashTable) + extra_size));
    memcpy(tmp, ht, sizeof(HashTable));
    memcpy(reinterpret_cast<char *>(tmp) + sizeof(HashTable), src_type_info, extra_size);
    HT_FLAGS(tmp) |= HASH_FLAG_TYPED_ARRAY;
    Z_ARRVAL_P(container) = tmp;
    efree(ht);
}

static ArrayTypeInfo *get_type_info(zend_array *array) {
    return reinterpret_cast<ArrayTypeInfo *>(reinterpret_cast<char *>(array) + sizeof(HashTable));
}

static zend_string *get_array_type_def(const ArrayTypeInfo *info) {
    zend_string *result = zend_string_alloc(info->get_len_of_value_type_str() + 16, false);
    char *p = result->val;
    *p = '<';
    if (info->get_type_of_key() == IS_STRING) {
        p++;
        strcpy(p, "string,");
        p += 7;
    } else if (info->get_type_of_key() == IS_LONG) {
        p++;
        strcpy(p, "int,");
        p += 4;
    }

    memcpy(p, info->get_value_type_str(), info->get_len_of_value_type_str());
    p += info->get_len_of_value_type_str();
    *p = '>';
    p++;
    *p = '\0';
    result->len = p - result->val;

    return result;
}

bool ArrayTypeInfo::check(const zend_array *ht, const zval *key, const zval *value) const {
    if (get_type_of_key() > 0) {
        if (Z_TYPE_P(key) != get_type_of_key()) {
            zend_type_error("Array key type mismatch, expected `%s`, got `%s`",
                            zend_get_type_by_const(get_type_of_key()),
                            zend_get_type_by_const(Z_TYPE_P(key)));
            return false;
        }
    } else {
        if (Z_TYPE_P(key) == IS_LONG) {
            if (Z_LVAL_P(key) > zend_hash_num_elements(ht)) {
                zend_throw_error(
                    nullptr, "Incorrect array key `%ld`, out of the permitted range", (long) Z_LVAL_P(key));
                return false;
            }
        } else if (!(Z_TYPE_P(key) == IS_UNDEF || Z_TYPE_P(key) == IS_NULL)) {
            zend_throw_error(nullptr, "Incorrect array key, must be undef or int");
            return false;
        }
    }
    ZVAL_DEREF(value);
    if (value_is_bool() && ZVAL_IS_BOOL(value)) {
        return true;
    }
    if (Z_TYPE_P(value) != get_type_of_value()) {
        zend_type_error("Array value type mismatch, expected `%s`, got `%s`",
                        zend_get_type_by_const(get_type_of_value()),
                        zend_get_type_by_const(Z_TYPE_P(value)));
        return false;
    }
    if (value_is_object() && !instance_of(value)) {
        zend_type_error(
            "Array value type mismatch, expected `%s`, got `%s`", value_ce->name->val, Z_OBJCE_P(value)->name->val);
        return false;
    }
    if (value_is_array()) {
        const auto element_array_type_info = get_type_info(Z_ARRVAL_P(value));
        const auto element_ht = Z_ARRVAL_P(value);
        if (!(HT_FLAGS(element_ht) & HASH_FLAG_TYPED_ARRAY)) {
            zend_type_error("Array value type mismatch, expected `%.*s`, got `array`",
                            get_len_of_value_type_str(),
                            get_value_type_str());
            return false;
        }
        if (!element_type_equals(element_array_type_info)) {
            const auto element_type_str = get_array_type_def(element_array_type_info);
            zend_type_error("Array value type mismatch, expected `%.*s`, got `%.*s`",
                            get_len_of_value_type_str(),
                            get_value_type_str(),
                            (int) ZSTR_LEN(element_type_str),
                            ZSTR_VAL(element_type_str));
            zend_string_release(element_type_str);
            return false;
        }
    }
    return true;
}

static zval *get_array_on_opline(const zend_op *opline EXECUTE_DATA_DC) {
    auto array = _get_zval_ptr_ptr_var(opline->op1.var EXECUTE_DATA_CC);
    if (ZVAL_IS_REF(array)) {
        array = Z_REFVAL_P(array);
    }
    if (!ZVAL_IS_ARRAY(array)) {
        return nullptr;
    }
    return array;
}

#ifdef DEBUG
static void debug_val(const char *tag, int op_type, zval *value) {
    printf("[%s] refcount=%d, op1_type=%d, type=%s, refcounted=%d\n",
           tag,
           Z_REFCOUNTED_P(value) ? Z_REFCOUNT_P(value) : 0,
           op_type,
           zend_get_type_by_const(Z_TYPE_P(value)),
           Z_REFCOUNTED_P(value));
}
#else
#define debug_val(tag, op_type, value)
#endif

// In a release version, this function suddenly changes from static to ZEND_API.
// We don't know which version it is. In principle, the ZEND_API should not be changed in the release version,
// but PHP still does so, which is against the R&D specification. We have to copy the code of this function once.
#define zend_cannot_add_element sw_zend_cannot_add_element
static zend_never_inline ZEND_COLD void ZEND_FASTCALL sw_zend_cannot_add_element(void) {
    zend_throw_error(NULL, "Cannot add element to the array as the next element is already occupied");
}

static void array_add_or_update(const zend_op *opline, zval *container, const zval *key, zval *value EXECUTE_DATA_DC) {
    zval *var_ptr;
    HashTable *source = Z_ARRVAL_P(container);
    SEPARATE_ARRAY(container);
    if (source != Z_ARRVAL_P(container)) {
        copy_array_type_info(container, source);
    }
    HashTable *ht = Z_ARRVAL_P(container);
    const zend_op *op_data = opline + 1;

    if (ZVAL_IS_NULL(key)) {
        var_ptr = zend_hash_next_index_insert(ht, value);
        if (UNEXPECTED(!var_ptr)) {
            zend_cannot_add_element();
            goto assign_dim_op_ret_null;
        }
    } else {
        zval *variable_ptr;
        if (opline->op2_type == IS_CONST) {
            variable_ptr = zend_fetch_dimension_address_inner_W_CONST(Z_ARRVAL_P(container), key EXECUTE_DATA_CC);
        } else {
            variable_ptr = zend_fetch_dimension_address_inner_W(Z_ARRVAL_P(container), key EXECUTE_DATA_CC);
        }
        if (UNEXPECTED(variable_ptr == nullptr)) {
            goto assign_dim_op_ret_null;
        }
        debug_val("1", op_data->op1_type, value);
        var_ptr = zend_assign_to_variable(variable_ptr, value, op_data->op1_type, EX_USES_STRICT_TYPES());
        debug_val("2", op_data->op1_type, value);
        if (UNEXPECTED(!var_ptr)) {
        assign_dim_op_ret_null:
            FREE_OP(op_data->op1_type, op_data->op1.var);
            if (UNEXPECTED(RETURN_VALUE_USED(opline))) {
                ZVAL_NULL(EX_VAR(opline->result.var));
            }
            return;
        }
    }
    debug_val("3", op_data->op1_type, value);
    if (UNEXPECTED(RETURN_VALUE_USED(opline))) {
        ZVAL_COPY(EX_VAR(opline->result.var), var_ptr);
    }
    if (op_data->op1_type == IS_VAR) {
        Z_TRY_ADDREF_P(value);
    }
    FREE_OP(op_data->op1_type, op_data->op1.var);
    debug_val("4", op_data->op1_type, value);
}

static void array_op(const zend_op *opline, zval *container, const zval *key, zval *value EXECUTE_DATA_DC) {
    HashTable *source = Z_ARRVAL_P(container);
    SEPARATE_ARRAY(container);
    if (source != Z_ARRVAL_P(container)) {
        copy_array_type_info(container, source);
    }
    const auto type_info = get_type_info(Z_ARRVAL_P(container));

    zval *variable_ptr;
    if ((opline + 1)->op1_type == IS_CONST) {
        variable_ptr = zend_fetch_dimension_address_inner_RW_CONST(Z_ARRVAL_P(container), key EXECUTE_DATA_CC);
    } else {
        variable_ptr = zend_fetch_dimension_address_inner_RW(Z_ARRVAL_P(container), key EXECUTE_DATA_CC);
    }
    if (UNEXPECTED(variable_ptr == nullptr)) {
    assign_dim_op_ret_null:
        FREE_OP((opline + 1)->op1_type, (opline + 1)->op1.var);
        if (UNEXPECTED(RETURN_VALUE_USED(opline))) {
            ZVAL_NULL(EX_VAR(opline->result.var));
        }
        return;
    }
    do {
        if (UNEXPECTED(Z_ISREF_P(variable_ptr))) {
            zend_reference *ref = Z_REF_P(variable_ptr);
            variable_ptr = Z_REFVAL_P(variable_ptr);
            if (UNEXPECTED(ZEND_REF_HAS_TYPE_SOURCES(ref))) {
                zend_binary_assign_op_typed_ref(ref, value OPLINE_CC EXECUTE_DATA_CC);
                break;
            }
        }
        const auto opcode = opline->extended_value;
        if (opcode == ZEND_CONCAT) {
            if (!type_info->value_is_string()) {
                zend_type_error("Only string support concat operation");
                goto assign_dim_op_ret_null;
            }
        } else {
            if (!type_info->value_is_numeric()) {
                zend_type_error("Only int or float support arithmetic operation");
                goto assign_dim_op_ret_null;
            }
        }
        zend_binary_op(variable_ptr, variable_ptr, value OPLINE_CC);
    } while (false);

    if (UNEXPECTED(RETURN_VALUE_USED(opline))) {
        ZVAL_COPY(EX_VAR(opline->result.var), variable_ptr);
    }
    FREE_OP((opline + 1)->op1_type, (opline + 1)->op1.var);
}

typedef std::function<void(const zend_op *, zval *, const zval *, zval *EXECUTE_DATA_DC)> ArrayFn;

static int opcode_handler_array(zend_execute_data *execute_data, const ArrayFn &fn) {
    const zend_op *opline = EX(opline);
    const zend_op *op_data = opline + 1;
    zval *array = get_array_on_opline(opline EXECUTE_DATA_CC);
    if (UNEXPECTED(!array)) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    zend_array *ht = Z_ARRVAL_P(array);
    if (!(HT_FLAGS(ht) & HASH_FLAG_TYPED_ARRAY)) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    const auto value = get_op_data_zval_ptr_r(op_data->op1_type, op_data->op1);
    zval *key;
    if (opline->op2_type == IS_CONST) {
        key = RT_CONSTANT(opline, opline->op2);
    } else if (UNEXPECTED(opline->op2_type == IS_UNUSED)) {
        key = &EG(uninitialized_zval);
    } else {
        key = EX_VAR(opline->op2.var);
    }
    const auto type_info = get_type_info(ht);
    if (!type_info->check(ht, key, value)) {
        FREE_OP(op_data->op1_type, op_data->op1.var);
        return ZEND_USER_OPCODE_CONTINUE;
    }
    fn(opline, array, key, value EXECUTE_DATA_CC);
    EX(opline) += 2;
    return ZEND_USER_OPCODE_CONTINUE;
}

static int opcode_handler_array_assign(zend_execute_data *execute_data) {
    return opcode_handler_array(execute_data, array_add_or_update);
}

static int opcode_handler_array_assign_op(zend_execute_data *execute_data) {
    return opcode_handler_array(execute_data, array_op);
}

static int opcode_handler_foreach_begin(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    zval *array;
    if (opline->op1_type == IS_VAR || opline->op1_type == IS_CV) {
        array = _get_zval_ptr_ptr_var(opline->op1.var EXECUTE_DATA_CC);
    } else if (opline->op1_type == IS_CONST) {
        array = RT_CONSTANT(opline, opline->op1);
    } else {
        array = _get_zval_ptr_tmp(opline->op1.var EXECUTE_DATA_CC);
    }
    ZVAL_DEREF(array);
    if (UNEXPECTED(!array || !ZVAL_IS_ARRAY(array))) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    const zend_array *ht = Z_ARRVAL_P(array);
    if (HT_FLAGS(ht) & HASH_FLAG_TYPED_ARRAY) {
        zend_throw_error(nullptr, "The type array do not support using references for element value during iteration");
        ZVAL_UNDEF(EX_VAR(opline->result.var));
        Z_FE_ITER_P(EX_VAR(opline->result.var)) = static_cast<uint32_t>(-1);

        return ZEND_USER_OPCODE_CONTINUE;
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int opcode_handler_array_unset(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    const zval *array = get_array_on_opline(opline EXECUTE_DATA_CC);
    if (!array) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    zend_array *ht = Z_ARRVAL_P(array);
    if (!(HT_FLAGS(ht) & HASH_FLAG_TYPED_ARRAY)) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    const auto type_info = get_type_info(ht);
    if (type_info->is_list()) {
        zend_throw_error(nullptr, "The typed array list do not support random deletion of elements");
        return ZEND_USER_OPCODE_CONTINUE;
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static void remove_all_spaces(char **val, uint16_t *len) {
    if (!*val || *len == 0) {
        return;
    }

    const char *src = *val;
    char *dst = *val;
    size_t new_len = 0;

    for (size_t i = 0; i < *len; i++) {
        if (!isspace((uchar) *src)) {
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

bool ArrayTypeValue::parse(const char *type_str, const size_t len_of_type_str) {
    auto pos = strchr(type_str, ',');
    if (pos == nullptr) {
        type_of_key = 0;
        offset_of_value_type_str = 1;
    } else {
        type_of_key = get_type(type_str + 1, pos - type_str - 1);
        if (type_of_key != IS_STRING && type_of_key != IS_LONG) {
            zend_throw_error(nullptr, "The key type of array must be string or int, but got %s", pos + 1);
            return false;
        }
        offset_of_value_type_str = pos - type_str + 1;
    }
    len_of_value_type_str = len_of_type_str - offset_of_value_type_str - 1;
    type_of_value = get_type(type_str + offset_of_value_type_str, len_of_value_type_str);
    return true;
}

bool ArrayTypeInfo::parse(zend_string *type_def) {
    if (type_def->len >= 65535) {
        zend_throw_error(nullptr, "The type definition string is too long (must be less than 65535 characters)");
        return false;
    }
    zend_string *lc_type_def = zend_string_tolower(type_def);
    memcpy(type_str, lc_type_def->val, lc_type_def->len + 1);
    len_of_type_str = lc_type_def->len;
    zend_string_release(lc_type_def);

    char *tmp_type_str = type_str;
    remove_all_spaces(&tmp_type_str, &len_of_type_str);
    tmp_type_str[len_of_type_str] = '\0';
    if (tmp_type_str != type_str) {
        memmove(type_str, tmp_type_str, len_of_type_str + 1);
    }

    if (type_str[0] != '<' || type_str[len_of_type_str - 1] != '>') {
        zend_throw_error(nullptr, "The type definition of typed array must start with '<' and end with '>'");
        return false;
    }
    if (!self.parse(type_str, len_of_type_str)) {
        return false;
    }

    if (self.type_of_value == IS_OBJECT) {
        zend::String type_str_of_value(type_str + self.offset_of_value_type_str, self.len_of_value_type_str);
        value_ce = zend_lookup_class(type_str_of_value.get());
        if (!value_ce) {
            zend_throw_error(nullptr, "Class '%s' not found", type_str_of_value.val());
            return false;
        }
    }

    return true;
}

PHP_FUNCTION(swoole_typed_array) {
    zend_string *type_def;
    zval *init_values = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STR(type_def)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(init_values)
    ZEND_PARSE_PARAMETERS_END();

    auto tmp_info = static_cast<ArrayTypeInfo *>(emalloc(sizeof(ArrayTypeInfo) + ZSTR_LEN(type_def) + 1));
    if (!tmp_info->parse(type_def)) {
        efree(tmp_info);
        RETURN_NULL();
    }

    if (init_values && is_typed_array(init_values)) {
        auto type_info = get_type_info(Z_ARRVAL_P(init_values));
        if (tmp_info->equals(type_info)) {
            ZVAL_COPY(return_value, init_values);
        } else {
            zend_throw_error(nullptr, "The type definition of the typed array does not match the initial values");
        }
        efree(tmp_info);
        return;
    }

    auto n = init_values ? zend_array_count(Z_ARRVAL_P(init_values)) : 0;
    auto array = make_typed_array(n, tmp_info->len_of_type_str);
    ZVAL_ARR(return_value, array);
    auto info = get_type_info(array);
    memcpy(info, tmp_info, sizeof(ArrayTypeInfo) + tmp_info->len_of_type_str + 1);
    efree(tmp_info);

    if (info->self.type_of_value == IS_ARRAY) {
        if (!info->element.parse(info->get_value_type_str(), info->get_len_of_value_type_str())) {
            zval_ptr_dtor(return_value);
            RETURN_NULL();
        }
    }

    if (init_values) {
        zend_string *str_key;
        zend_ulong num_key;
        zval *zv;
        zval zk;
        HashTable *ht = Z_ARRVAL_P(init_values);

        ZEND_HASH_FOREACH_KEY_VAL(ht, num_key, str_key, zv) {
            if (str_key) {
                ZVAL_STR(&zk, str_key);
            } else {
                ZVAL_LONG(&zk, num_key);
            }
            if (!info->check(array, &zk, zv)) {
                zval_ptr_dtor(return_value);
                RETURN_NULL();
            }
            Z_TRY_ADDREF_P(zv);
            if (str_key) {
                zend_hash_add(array, str_key, zv);
            } else {
                zend_hash_index_add(array, num_key, zv);
            }
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_FUNCTION(swoole_array_is_typed) {
    zend_string *type_def = nullptr;
    zval *array;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ARRAY(array)
    Z_PARAM_OPTIONAL
    Z_PARAM_STR(type_def)
    ZEND_PARSE_PARAMETERS_END();

    HashTable *ht = Z_ARRVAL_P(array);
    if (!(HT_FLAGS(ht) & HASH_FLAG_TYPED_ARRAY)) {
        RETURN_FALSE;
    }
    if (!type_def) {
        RETURN_TRUE;
    }

    const auto tmp_info = static_cast<ArrayTypeInfo *>(emalloc(sizeof(ArrayTypeInfo) + ZSTR_LEN(type_def) + 1));
    if (!tmp_info->parse(type_def)) {
        efree(tmp_info);
        RETURN_FALSE;
    }

    const auto info = get_type_info(ht);
    RETVAL_BOOL(info->equals(tmp_info));
    efree(tmp_info);
}

static PHP_FUNCTION(swoole_array_push) {
    zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = ZEND_CALL_NUM_ARGS(execute_data);
    zval *array = &arg_ptr[0];
    ZVAL_DEREF(array);

    if (Z_TYPE_P(array) == IS_ARRAY && is_typed_array(array)) {
        auto source = Z_ARRVAL_P(array);
        auto type_info = get_type_info(source);
        for (int i = 1; i < arg_count; i++) {
            if (!type_info->check(source, &EG(uninitialized_zval), &arg_ptr[i])) {
                return;
            }
        }
    }
    ori_handler_array_push(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_FUNCTION(swoole_array_unshift) {
    zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = ZEND_CALL_NUM_ARGS(execute_data);
    zval *array = &arg_ptr[0];
    ZVAL_DEREF(array);

    if (Z_TYPE_P(array) == IS_ARRAY && is_typed_array(array)) {
        auto source = Z_ARRVAL_P(array);
        auto type_info = get_type_info(source);
        for (int i = 1; i < arg_count; i++) {
            if (!type_info->check(source, &EG(uninitialized_zval), &arg_ptr[i])) {
                return;
            }
        }
        ori_handler_array_unshift(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        HT_FLAGS(source) |= HASH_FLAG_TYPED_ARRAY;
    } else {
        ori_handler_array_unshift(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    }
}

static PHP_FUNCTION(swoole_array_splice) {
    const zval *arg_ptr = ZEND_CALL_ARG(execute_data, 1);
    const int arg_count = ZEND_CALL_NUM_ARGS(execute_data);
    const zval *array = &arg_ptr[0];
    ZVAL_DEREF(array);
    if (Z_TYPE_P(array) == IS_ARRAY && is_typed_array(array)) {
        if (arg_count > 3) {
            auto type_info = get_type_info(Z_ARRVAL_P(array));
            auto values = &arg_ptr[3];
            ZVAL_DEREF(values);
            if (Z_TYPE_P(values) == IS_ARRAY) {
                zval *zv;
                HashTable *ht = Z_ARRVAL_P(values);
                ZEND_HASH_FOREACH_VAL(ht, zv) {
                    if (!type_info->check(Z_ARRVAL_P(array), &EG(uninitialized_zval), zv)) {
                        return;
                    }
                }
                ZEND_HASH_FOREACH_END();
            } else {
                if (!type_info->check(Z_ARRVAL_P(array), &EG(uninitialized_zval), values)) {
                    return;
                }
            }
        }
        const auto source = Z_ARRVAL_P(array);
        ori_handler_array_splice(execute_data, return_value);
        HT_FLAGS(source) |= HASH_FLAG_TYPED_ARRAY;
    } else {
        ori_handler_array_splice(execute_data, return_value);
    }
}

static void php_do_pcre_match(INTERNAL_FUNCTION_PARAMETERS, int global) /* {{{ */
{
    /* parameters */
    zend_string *regex;         /* Regular expression */
    zend_string *subject;       /* String to match against */
    pcre_cache_entry *pce;      /* Compiled regular expression */
    zend_long flags = 0;        /* Match control flags */
    zend_long start_offset = 0; /* Where the new search starts */

    ZEND_PARSE_PARAMETERS_START(2, 4)
    Z_PARAM_STR(subject)
    Z_PARAM_STR(regex)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(flags)
    Z_PARAM_LONG(start_offset)
    ZEND_PARSE_PARAMETERS_END();

    /* Compile regex or get it from cache. */
    if ((pce = pcre_get_compiled_regex_cache(regex)) == nullptr) {
        RETURN_FALSE;
    }

    zval count = {};
    php_pcre_pce_incref(pce);
#if PHP_VERSION_ID >= 80400
    php_pcre_match_impl(pce, subject, &count, return_value, global == 1, flags, start_offset);
#else
    php_pcre_match_impl(pce, subject, &count, return_value, global, ZEND_NUM_ARGS() >= 3, flags, start_offset);
#endif
    php_pcre_pce_decref(pce);
}
/* }}} */

PHP_FUNCTION(swoole_str_match) {
    php_do_pcre_match(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(swoole_str_match_all) {
    php_do_pcre_match(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void php_do_json_decode(INTERNAL_FUNCTION_PARAMETERS, bool assoc) /* {{{ */
{
    char *str;
    size_t str_len;
    zend_long depth = PHP_JSON_PARSER_DEFAULT_DEPTH;
    zend_long options = 0;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_STRING(str, str_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(depth)
    Z_PARAM_LONG(options)
    ZEND_PARSE_PARAMETERS_END();

    if (assoc) {
        options |= PHP_JSON_OBJECT_AS_ARRAY;
    } else {
        options &= ~PHP_JSON_OBJECT_AS_ARRAY;
    }

    zend::json_decode(return_value, str, str_len, options, depth);
}
/* }}} */

PHP_FUNCTION(swoole_str_json_decode) {
    php_do_json_decode(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

PHP_FUNCTION(swoole_str_json_decode_to_object) {
    php_do_json_decode(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}
#endif
