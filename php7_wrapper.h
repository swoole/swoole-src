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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef EXT_SWOOLE_PHP7_WRAPPER_H_
#define EXT_SWOOLE_PHP7_WRAPPER_H_

#include "ext/standard/php_http.h"

static sw_inline zend_bool Z_BVAL_P(zval *v)
{
    return Z_TYPE_P(v) == IS_TRUE;
}

static sw_inline zend_bool ZVAL_IS_ARRAY(zval *v)
{
    return Z_TYPE_P(v) == IS_ARRAY;
}

//----------------------------------Array API------------------------------------

static sw_inline int add_assoc_ulong_safe(zval *arg, const char *key, zend_ulong value)
{
    if (likely(value <= ZEND_LONG_MAX))
    {
        return add_assoc_long(arg, key, value);
    }
    else
    {
        char buf[MAX_LENGTH_OF_LONG + 1] = {0};
        sprintf((char *) buf, ZEND_ULONG_FMT, value);
        return add_assoc_string(arg, key, buf);
    }
}

#define SW_HASHTABLE_FOREACH_START(ht, _val) ZEND_HASH_FOREACH_VAL(ht, _val);  {
#define SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, _val) zend_string *_foreach_key;\
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, _foreach_key, _val);\
    if (!_foreach_key) {k = NULL; klen = 0; ktype = 0;}\
    else {k = _foreach_key->val, klen=_foreach_key->len; ktype = 1;} {

#define SW_HASHTABLE_FOREACH_END()                 } ZEND_HASH_FOREACH_END();

static inline char* sw_php_format_date(char *format, size_t format_len, time_t ts, int localtime)
{
    zend_string *time = php_format_date(format, format_len, ts, localtime);
    char *return_str = estrndup(time->val, time->len);
    zend_string_release(time);
    return return_str;
}

static sw_inline char* sw_php_url_encode(char *value, size_t value_len, int* exten)
{
    zend_string *str = php_url_encode(value, value_len);
    *exten = str->len;
    char *return_str = estrndup(str->val, str->len);
    zend_string_release(str);
    return return_str;
}

#define SW_PHP_MAX_PARAMS_NUM     20

static sw_inline int sw_call_user_function_ex(HashTable *function_table, zval* object_p, zval *function_name, zval **retval_ptr_ptr, uint32_t param_count, zval *params, int no_separation, HashTable* ymbol_table)
{
    static zval _retval;
    *retval_ptr_ptr = &_retval;
    return call_user_function_ex(function_table, object_p, function_name, &_retval, param_count, param_count ? params : NULL, no_separation, ymbol_table);
}

static sw_inline int sw_call_user_function_anyway(zval *object_p, zval *function_name, zval **retval_ptr_ptr, uint32_t param_count, zval params[], int no_separation)
{
    static zval _retval;
    *retval_ptr_ptr = &_retval;
    zend_object* exception = EG(exception);
    if (exception)
    {
        EG(exception) = NULL;
    }
    int ret = call_user_function_ex(NULL, object_p, function_name, &_retval, param_count, param_count ? params : NULL, no_separation, NULL);
    if (exception)
    {
        EG(exception) = exception;
    }
    return ret;
}

static sw_inline int sw_call_user_function_fast_ex(zval *function_name, zend_fcall_info_cache *fci_cache, zval **retval_ptr_ptr, uint32_t param_count, zval *params)
{
    static zval _retval;
    *retval_ptr_ptr = &_retval;

    zend_fcall_info fci;
    fci.size = sizeof(fci);
#if PHP_MAJOR_VERSION == 7 && PHP_MINOR_VERSION == 0
    fci.function_table = EG(function_table);
    fci.symbol_table = NULL;
#endif
    fci.object = NULL;
    if (!fci_cache || !fci_cache->function_handler)
    {
        ZVAL_COPY_VALUE(&fci.function_name, function_name);
    }
    else
    {
        ZVAL_UNDEF(&fci.function_name);
    }
    fci.retval = *retval_ptr_ptr;
    fci.param_count = param_count;
    fci.params = params;
    fci.no_separation = 0;

    return zend_call_function(&fci, fci_cache);
}

#define SW_MAKE_STD_ZVAL(p)             zval _stack_zval_##p; p = &(_stack_zval_##p); bzero(p, sizeof(zval))
#define SW_ALLOC_INIT_ZVAL(p)           do{p = (zval *)emalloc(sizeof(zval)); bzero(p, sizeof(zval));}while(0)
#define SW_SEPARATE_ZVAL(p)             zval _##p;\
    memcpy(&_##p, p, sizeof(_##p));\
    p = &_##p

#define SW_ZEND_FETCH_RESOURCE_NO_RETURN(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type)        \
        (rsrc = (rsrc_type) zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type))
#define SW_ZEND_REGISTER_RESOURCE(return_value, result, le_result)  ZVAL_RES(return_value,zend_register_resource(result, le_result))

#define sw_zend_register_internal_class_ex(entry,parent_ptr,str)    zend_register_internal_class_ex(entry,parent_ptr)

#define sw_zend_call_method_with_0_params(obj, ptr, what, method, retval) \
    zval __retval;\
    zend_call_method_with_0_params(*obj, ptr, what, method, &__retval);\
    if (ZVAL_IS_NULL(&__retval)) *(retval) = NULL;\
    else *(retval) = &__retval;

#define sw_zend_call_method_with_1_params(obj, ptr, what, method, retval, v1)           \
    zval __retval;\
    zend_call_method_with_1_params(*obj, ptr, what, method, &__retval, v1);\
    if (ZVAL_IS_NULL(&__retval)) *(retval) = NULL;\
    else *(retval) = &__retval;

#define sw_zend_call_method_with_2_params(obj, ptr, what, method, retval, v1, v2)    \
    zval __retval;\
    zend_call_method_with_2_params(*obj, ptr, what, method, &__retval, v1, v2);\
    if (ZVAL_IS_NULL(&__retval)) *(retval) = NULL;\
    else *(retval) = &__retval;

// do not use sw_copy_to_stack(return_value, foo);
#define sw_copy_to_stack(a, b)                {zval *__tmp = (zval *) a;\
    a = &b;\
    memcpy(a, __tmp, sizeof(zval));}

static sw_inline zval* sw_zval_dup(zval *val)
{
    zval *dup;
    SW_ALLOC_INIT_ZVAL(dup);
    memcpy(dup, val, sizeof(zval));
    return dup;
}

static sw_inline void sw_zval_free(zval *val)
{
    zval_ptr_dtor(val);
    efree(val);
}

static sw_inline zval* sw_zend_read_property(zend_class_entry *class_ptr, zval *obj, const char *s, int len, int silent)
{
    zval rv;
    return zend_read_property(class_ptr, obj, s, len, silent, &rv);
}

static sw_inline zval* sw_zend_read_property_not_null(zend_class_entry *class_ptr, zval *obj, const char *s, int len, int silent)
{
    zval rv;
    zval *property = zend_read_property(class_ptr, obj, s, len, silent, &rv);
    return ZVAL_IS_NULL(property) ? NULL : property;
}

static sw_inline zval* sw_zend_read_property_array(zend_class_entry *class_ptr, zval *obj, const char *s, int len, int silent)
{
    zval rv, *property = zend_read_property(class_ptr, obj, s, len, silent, &rv);
    if (Z_TYPE_P(property) != IS_ARRAY)
    {
        zval temp_array;
        array_init(&temp_array);
        zend_update_property(class_ptr, obj, s, len, &temp_array);
        zval_ptr_dtor(&temp_array);
        // NOTICE: if user unset the property, zend_read_property will return uninitialized_zval instead of NULL pointer
        if (unlikely(property == &EG(uninitialized_zval)))
        {
            property = zend_read_property(class_ptr, obj, s, len, silent, &rv);
        }
    }

    return property;
}

static sw_inline int sw_zend_is_callable(zval *cb, int a, char **name)
{
    zend_string *key = NULL;
    int ret = zend_is_callable(cb, a, &key);
    char *tmp = estrndup(key->val, key->len);
    zend_string_release(key);
    *name = tmp;
    return ret;
}

static sw_inline int sw_zend_is_callable_ex(zval *zcallable, zval *zobject, uint check_flags, char **callable_name, int *callable_name_len, zend_fcall_info_cache *fci_cache, char **error)
{
    zend_string *key = NULL;
    int ret = zend_is_callable_ex(zcallable, NULL, check_flags, &key, fci_cache, error);
    char *tmp = estrndup(key->val, key->len);
    zend_string_release(key);
    *callable_name = tmp;
    return ret;
}

static inline int sw_zend_register_class_alias(const char *name, zend_class_entry *ce)
{
    int name_len = strlen(name);
    zend_string *_name;
    if (name[0] == '\\')
    {
        _name = zend_string_init(name, name_len, 1);
        zend_str_tolower_copy(ZSTR_VAL(_name), name + 1, name_len - 1);
    }
    else
    {
        _name = zend_string_init(name, strlen(name), 1);
        zend_str_tolower_copy(ZSTR_VAL(_name), name, name_len);
    }

    zend_string *_interned_name = zend_new_interned_string(_name);

#if PHP_VERSION_ID >= 70300
    return zend_register_class_alias_ex(_interned_name->val, _interned_name->len, ce, 1);
#else
    return zend_register_class_alias_ex(_interned_name->val, _interned_name->len, ce);
#endif
}

static sw_inline char* sw_http_build_query(zval *zdata, size_t *length, smart_str *formstr)
{
    if (php_url_encode_hash_ex(HASH_OF(zdata), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE)
    {
        if (formstr->s)
        {
            smart_str_free(formstr);
        }
        return NULL;
    }
    if (!formstr->s)
    {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->s->len;
    return formstr->s->val;
}

static sw_inline void sw_get_debug_print_backtrace(swString *buffer, zend_long options, zend_long limit)
{
    zval _fcn, *fcn = &_fcn, args[2], *retval = NULL;
    php_output_start_user(NULL, 0, PHP_OUTPUT_HANDLER_STDFLAGS);
    ZVAL_STRING(fcn, "debug_print_backtrace");
    ZVAL_LONG(&args[0], options);
    ZVAL_LONG(&args[1], limit);
    sw_call_user_function_ex(EG(function_table), NULL, fcn, &retval, 2, args, 0, NULL);
    zval_ptr_dtor(fcn);
    php_output_get_contents(retval);
    php_output_discard();
    swString_clear(buffer);
    swString_append_ptr(buffer, ZEND_STRL("Stack trace:\n"));
    swString_append_ptr(buffer, Z_STRVAL_P(retval), Z_STRLEN_P(retval)-1); // trim \n
    zval_ptr_dtor(retval);
}

#define SW_PREVENT_USER_DESTRUCT if(unlikely(!(GC_FLAGS(Z_OBJ_P(getThis())) & IS_OBJ_DESTRUCTOR_CALLED))){RETURN_NULL()}

#endif /* EXT_SWOOLE_PHP7_WRAPPER_H_ */
