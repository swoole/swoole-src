#include "php_swoole.h"

BEGIN_EXTERN_C()
#include "ext/standard/php_var.h"
#ifdef SW_USE_JSON
#include "ext/json/php_json.h"
extern PHP_JSON_API zend_class_entry *php_json_exception_ce;
#endif
END_EXTERN_C()

namespace zend {
void unserialize(zval *return_value, const char *buf, size_t buf_len, HashTable *options) {
#if PHP_VERSION_ID >= 80000
    php_unserialize_with_options(return_value, buf, buf_len, options, "swoole_ext_unserialize");
#else
    HashTable *class_hash = NULL, *prev_class_hash;
    const unsigned char *p = (const unsigned char *) buf;
    php_unserialize_data_t var_hash;
    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    zval *retval;

    prev_class_hash = php_var_unserialize_get_allowed_classes(var_hash);
#if PHP_VERSION_ID >= 70400
    zend_long prev_max_depth = php_var_unserialize_get_max_depth(var_hash);
    zend_long prev_cur_depth = php_var_unserialize_get_cur_depth(var_hash);
#endif
    if (options != NULL) {
        zval *classes;
#if PHP_VERSION_ID >= 70400
        classes = zend_hash_str_find_deref(options, "allowed_classes", sizeof("allowed_classes") - 1);
#else
        classes = zend_hash_str_find(options, "allowed_classes", sizeof("allowed_classes") - 1);
#endif
        if (classes && Z_TYPE_P(classes) != IS_ARRAY && Z_TYPE_P(classes) != IS_TRUE && Z_TYPE_P(classes) != IS_FALSE) {
            php_error_docref(NULL, E_WARNING, "allowed_classes option should be array or boolean");
            RETVAL_FALSE;
            goto cleanup;
        }

        if (classes && (Z_TYPE_P(classes) == IS_ARRAY || !zend_is_true(classes))) {
            ALLOC_HASHTABLE(class_hash);
            zend_hash_init(class_hash,
                           (Z_TYPE_P(classes) == IS_ARRAY) ? zend_hash_num_elements(Z_ARRVAL_P(classes)) : 0,
                           NULL,
                           NULL,
                           0);
        }
        if (class_hash && Z_TYPE_P(classes) == IS_ARRAY) {
            zval *entry;
            zend_string *lcname;

            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(classes), entry) {
                convert_to_string_ex(entry);
                lcname = zend_string_tolower(Z_STR_P(entry));
                zend_hash_add_empty_element(class_hash, lcname);
#if PHP_VERSION_ID >= 70400
                zend_string_release_ex(lcname, 0);
#else
                zend_string_release(lcname);
#endif
            }
            ZEND_HASH_FOREACH_END();

            /* Exception during string conversion. */
            if (EG(exception)) {
                goto cleanup;
            }
        }
        php_var_unserialize_set_allowed_classes(var_hash, class_hash);

#if PHP_VERSION_ID >= 70400
        zval *max_depth = zend_hash_str_find_deref(options, "max_depth", sizeof("max_depth") - 1);
        if (max_depth) {
            if (Z_TYPE_P(max_depth) != IS_LONG) {
                php_error_docref(NULL, E_WARNING, "max_depth should be int");
                RETVAL_FALSE;
                goto cleanup;
            }
            if (Z_LVAL_P(max_depth) < 0) {
                php_error_docref(NULL, E_WARNING, "max_depth cannot be negative");
                RETVAL_FALSE;
                goto cleanup;
            }

            php_var_unserialize_set_max_depth(var_hash, Z_LVAL_P(max_depth));
            /* If the max_depth for a nested unserialize() call has been overridden,
             * start counting from zero again (for the nested call only). */
            php_var_unserialize_set_cur_depth(var_hash, 0);
        }
#endif
    }

#if PHP_VERSION_ID >= 70400
    if (BG(unserialize).level > 1) {
        retval = var_tmp_var(&var_hash);
    } else {
        retval = return_value;
    }
#else
    retval = var_tmp_var(&var_hash);
#endif

    if (!php_var_unserialize(retval, &p, p + buf_len, &var_hash)) {
        if (!EG(exception)) {
            php_error_docref(NULL,
                             E_NOTICE,
                             "Error at offset " ZEND_LONG_FMT " of %zd bytes",
                             (zend_long)((char *) p - buf),
                             buf_len);
        }
        if (BG(unserialize).level <= 1) {
            zval_ptr_dtor(return_value);
        }
        RETVAL_FALSE;
    }
#if PHP_VERSION_ID >= 70400
    else if (BG(unserialize).level > 1) {
        ZVAL_COPY(return_value, retval);
    } else if (Z_REFCOUNTED_P(return_value)) {
        zend_refcounted *ref = Z_COUNTED_P(return_value);
        gc_check_possible_root(ref);
    }
#else
    else {
        ZVAL_COPY(return_value, retval);
    }
#endif

cleanup:
    if (class_hash) {
        zend_hash_destroy(class_hash);
        FREE_HASHTABLE(class_hash);
    }

    /* Reset to previous options in case this is a nested call */
    php_var_unserialize_set_allowed_classes(var_hash, prev_class_hash);
#if PHP_VERSION_ID >= 70400
    php_var_unserialize_set_max_depth(var_hash, prev_max_depth);
    php_var_unserialize_set_cur_depth(var_hash, prev_cur_depth);
#endif
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);

    /* Per calling convention we must not return a reference here, so unwrap. We're doing this at
     * the very end, because __wakeup() calls performed during UNSERIALIZE_DESTROY might affect
     * the value we unwrap here. This is compatible with behavior in PHP <=7.0. */
    if (Z_ISREF_P(return_value)) {
        zend_unwrap_reference(return_value);
    }
#endif
}

#ifdef SW_USE_JSON
#if PHP_VERSION_ID >= 70300
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
#endif

void json_decode(zval *return_value, const char *str, size_t str_len, zend_long options, zend_long depth) {
#if PHP_VERSION_ID >= 70300
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
#else
    JSON_G(error_code) = PHP_JSON_ERROR_NONE;

    if (!str_len) {
        JSON_G(error_code) = PHP_JSON_ERROR_SYNTAX;
        RETURN_NULL();
    }
#endif

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
#endif
}  // namespace zend
