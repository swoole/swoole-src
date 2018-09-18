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

#define sw_php_var_serialize                php_var_serialize
typedef size_t zend_size_t;
#define ZEND_SET_SYMBOL(ht,str,arr)         zval_add_ref(arr); zend_hash_str_update(ht, str, sizeof(str)-1, arr);

static sw_inline zend_bool Z_BVAL_P(zval *v)
{
    return Z_TYPE_P(v) == IS_TRUE;
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
        char buf[MAX_LENGTH_OF_LONG + 1];
        memset((char *) buf, 0, MAX_LENGTH_OF_LONG + 1);
        sprintf((char *) buf, ZEND_ULONG_FMT, value);
        return add_assoc_string(arg, key, buf);
    }
}

#define sw_add_assoc_stringl(__arg, __key, __str, __length, __duplicate)   add_assoc_stringl_ex(__arg, __key, strlen(__key), __str, __length)
static sw_inline int sw_add_assoc_stringl_ex(zval *arg, const char *key, size_t key_len, char *str, size_t length, int __duplicate)
{
    return add_assoc_stringl_ex(arg, key, key_len - 1, str, length);
}

#define sw_add_next_index_stringl(arr, str, len, dup)    add_next_index_stringl(arr, str, len)

static sw_inline int sw_add_assoc_long_ex(zval *arg, const char *key, size_t key_len, long value)
{
    return add_assoc_long_ex(arg, key, key_len - 1, value);
}

static sw_inline int sw_add_assoc_double_ex(zval *arg, const char *key, size_t key_len, double value)
{
    return add_assoc_double_ex(arg, key, key_len - 1, value);
}

#define SW_Z_ARRVAL_P(z)                          Z_ARRVAL_P(z)->ht

#define SW_HASHTABLE_FOREACH_START(ht, _val) ZEND_HASH_FOREACH_VAL(ht, _val);  {
#define SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, _val) zend_string *_foreach_key;\
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, _foreach_key, _val);\
    if (!_foreach_key) {k = NULL; klen = 0; ktype = 0;}\
    else {k = _foreach_key->val, klen=_foreach_key->len; ktype = 1;} {

#define SW_HASHTABLE_FOREACH_END()                 } ZEND_HASH_FOREACH_END();

#define Z_ARRVAL_PP(s)                             Z_ARRVAL_P(*s)
#define SW_Z_TYPE_P                                Z_TYPE_P
#define SW_Z_TYPE_PP(s)                            SW_Z_TYPE_P(*s)
#define Z_STRVAL_PP(s)                             Z_STRVAL_P(*s)
#define Z_STRLEN_PP(s)                             Z_STRLEN_P(*s)
#define Z_LVAL_PP(v)                               Z_LVAL_P(*v)

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

#define sw_zval_add_ref(p)   Z_TRY_ADDREF_P(*p)
#define sw_zval_ptr_dtor(p)  zval_ptr_dtor(*p)

#define SW_PHP_MAX_PARAMS_NUM     20

static sw_inline int sw_call_user_function_ex(HashTable *function_table, zval** object_pp, zval *function_name, zval **retval_ptr_ptr, uint32_t param_count, zval ***params, int no_separation, HashTable* ymbol_table)
{
    zval real_params[SW_PHP_MAX_PARAMS_NUM];
    uint32_t i = 0;
    for (; i < param_count; i++)
    {
        real_params[i] = **params[i];
    }
    zval phpng_retval;
    *retval_ptr_ptr = &phpng_retval;
    zval *object_p = (object_pp == NULL) ? NULL : *object_pp;
    return call_user_function_ex(function_table, object_p, function_name, &phpng_retval, param_count, real_params, no_separation, NULL);
}


static sw_inline int sw_call_user_function_fast(zval *function_name, zend_fcall_info_cache *fci_cache, zval **retval_ptr_ptr, uint32_t param_count, zval ***params)
{
    zval real_params[SW_PHP_MAX_PARAMS_NUM];
    uint32_t i = 0;
    for (; i < param_count; i++)
    {
        real_params[i] = **params[i];
    }

    zval phpng_retval;
    *retval_ptr_ptr = &phpng_retval;

    zend_fcall_info fci;
    fci.size = sizeof(fci);
#if PHP_MAJOR_VERSION == 7 && PHP_MINOR_VERSION == 0
    fci.function_table = EG(function_table);
    fci.symbol_table = NULL;
#endif
    fci.object = NULL;
    ZVAL_COPY_VALUE(&fci.function_name, function_name);
    fci.retval = &phpng_retval;
    fci.param_count = param_count;
    fci.params = real_params;
    fci.no_separation = 0;

    return zend_call_function(&fci, fci_cache);
}

#define sw_php_var_unserialize(rval, p, max, var_hash)  php_var_unserialize(*rval, p, max, var_hash)
#define SW_MAKE_STD_ZVAL(p)             zval _stack_zval_##p; p = &(_stack_zval_##p)
#define SW_ALLOC_INIT_ZVAL(p)           do{p = (zval *)emalloc(sizeof(zval)); bzero(p, sizeof(zval));}while(0)
#define SW_SEPARATE_ZVAL(p)             zval _##p;\
    memcpy(&_##p, p, sizeof(_##p));\
    p = &_##p
#define SW_RETURN_STRINGL(s, l, dup)    do{RETVAL_STRINGL(s, l); if (dup == 0) efree(s);}while(0);return
#define SW_RETVAL_STRINGL(s, l, dup)    do{RETVAL_STRINGL(s, l); if (dup == 0) efree(s);}while(0)
#define SW_RETVAL_STRING(s, dup)        do{RETVAL_STRING(s); if (dup == 0) efree(s);}while(0)

#define SW_ZEND_FETCH_RESOURCE_NO_RETURN(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type)        \
        (rsrc = (rsrc_type) zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type))
#define SW_ZEND_REGISTER_RESOURCE(return_value, result, le_result)  ZVAL_RES(return_value,zend_register_resource(result, le_result))

#define SW_RETURN_STRING(val, duplicate)     RETURN_STRING(val)
#define sw_add_assoc_string(array, key, value, duplicate)   add_assoc_string(array, key, value)
#define sw_zend_hash_copy(target,source,pCopyConstructor,tmp,size) zend_hash_copy(target,source,pCopyConstructor)
#define sw_php_array_merge                                          php_array_merge
#define sw_zend_register_internal_class_ex(entry,parent_ptr,str)    zend_register_internal_class_ex(entry,parent_ptr)
#define sw_zend_get_executed_filename()                             zend_get_executed_filename()

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

#define SW_ZVAL_STRINGL(z, s, l, dup)         ZVAL_STRINGL(z, s, l)
#define SW_ZVAL_STRING(z,s,dup)               ZVAL_STRING(z,s)
#define sw_smart_str                          smart_string
#define zend_get_class_entry                  Z_OBJCE_P
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
    sw_zval_ptr_dtor(&val);
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
    zend_uchar ztype = Z_TYPE_P(property);
    if (ztype != IS_ARRAY)
    {
        zval temp_array;
        array_init(&temp_array);
        zend_update_property(class_ptr, obj, s, len, &temp_array TSRMLS_CC);
        zval_ptr_dtor(&temp_array);
        // NOTICE: if user unset the property, this pointer will be changed
        // some objects such as `swoole_http2_request` always be writable
        if (ztype == IS_UNDEF)
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

static inline int sw_zend_is_callable_ex(zval *callable, zval *object, uint check_flags, char **callable_name, int *callable_name_len, zend_fcall_info_cache *fcc, char **error TSRMLS_DC)
{
    zend_string *key = NULL;
    int ret = zend_is_callable_ex(callable, NULL, check_flags, &key, fcc, error);
    char *tmp = estrndup(key->val, key->len);
    zend_string_release(key);
    *callable_name = tmp;
    return ret;
}

static inline int sw_zend_hash_del(HashTable *ht, char *k, int len)
{
    return zend_hash_str_del(ht, k, len - 1);
}

static inline int sw_zend_hash_add(HashTable *ht, char *k, int len, void *pData, int datasize, void **pDest)
{
    zval **real_p = (zval **)pData;
    return zend_hash_str_add(ht, k, len - 1, *real_p) ? SUCCESS : FAILURE;
}

static inline int sw_zend_hash_index_update(HashTable *ht, int key, void *pData, int datasize, void **pDest)
{
    zval **real_p = (zval **)pData;
    return zend_hash_index_update(ht, key, *real_p) ? SUCCESS : FAILURE;
}

static inline int sw_zend_hash_update(HashTable *ht, char *k, int len, zval *val, int size, void *ptr)
{
    return zend_hash_str_update(ht, (const char*)k, len -1, val) ? SUCCESS : FAILURE;
}

static inline int sw_zend_hash_find(HashTable *ht, const char *k, int len, void **v)
{
    zval *value = zend_hash_str_find(ht, k, len - 1);
    if (value == NULL)
    {
        return FAILURE;
    }
    else
    {
        *v = (void *) value;
        return SUCCESS;
    }
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

static sw_inline char* sw_http_build_query(zval *data, zend_size_t *length, smart_str *formstr TSRMLS_DC)
{
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE)
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

#define sw_get_object_handle(object)    Z_OBJ_HANDLE(*object)

#define SW_PREVENT_USER_DESTRUCT if(unlikely(!(GC_FLAGS(Z_OBJ_P(getThis())) & IS_OBJ_DESTRUCTOR_CALLED))){RETURN_NULL()}

#endif /* EXT_SWOOLE_PHP7_WRAPPER_H_ */
