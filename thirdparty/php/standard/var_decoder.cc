#include "php_swoole.h"

BEGIN_EXTERN_C()
#include "ext/standard/php_var.h"
#include "ext/json/php_json.h"
extern PHP_JSON_API zend_class_entry *php_json_exception_ce;
END_EXTERN_C()

namespace zend {
void unserialize(zval *return_value, const char *buf, size_t buf_len, HashTable *options) {
    php_unserialize_with_options(return_value, buf, buf_len, options, "swoole_ext_unserialize");
}

static const char *php_json_get_error_msg(php_json_error_code error_code) /* {{{ */
{
    switch (error_code) {
    case PHP_JSON_ERROR_NONE:
        return "No error";
    case PHP_JSON_ERROR_DEPTH:
        return "Maximum stack depth exceeded";
    case PHP_JSON_ERROR_STATE_MISMATCH:
        return "State mismatch (invalid or malformed JSON)";
    case PHP_JSON_ERROR_CTRL_CHAR:
        return "Control character error, possibly incorrectly encoded";
    case PHP_JSON_ERROR_SYNTAX:
        return "Syntax error";
    case PHP_JSON_ERROR_UTF8:
        return "Malformed UTF-8 characters, possibly incorrectly encoded";
    case PHP_JSON_ERROR_RECURSION:
        return "Recursion detected";
    case PHP_JSON_ERROR_INF_OR_NAN:
        return "Inf and NaN cannot be JSON encoded";
    case PHP_JSON_ERROR_UNSUPPORTED_TYPE:
        return "Type is not supported";
    case PHP_JSON_ERROR_INVALID_PROPERTY_NAME:
        return "The decoded property name is invalid";
    case PHP_JSON_ERROR_UTF16:
        return "Single unpaired UTF-16 surrogate in unicode escape";
    default:
        return "Unknown error";
    }
}

void json_decode(zval *return_value, const char *str, size_t str_len, zend_long options, zend_long depth) {
    if (!(options & PHP_JSON_THROW_ON_ERROR)) {
        JSON_G(error_code) = PHP_JSON_ERROR_NONE;
    }

    if (!str_len) {
        if (!(options & PHP_JSON_THROW_ON_ERROR)) {
            JSON_G(error_code) = PHP_JSON_ERROR_SYNTAX;
        } else {
            zend_throw_exception(
                php_json_exception_ce, php_json_get_error_msg(PHP_JSON_ERROR_SYNTAX), PHP_JSON_ERROR_SYNTAX);
        }
        RETURN_NULL();
    }

    if (depth <= 0) {
        php_error_docref(NULL, E_WARNING, "Depth must be greater than zero");
        RETURN_NULL();
    }

    if (depth > INT_MAX) {
        php_error_docref(NULL, E_WARNING, "Depth must be lower than %d", INT_MAX);
        RETURN_NULL();
    }
    php_json_decode_ex(return_value, (char *) str, str_len, options, depth);
}
}  // namespace zend
