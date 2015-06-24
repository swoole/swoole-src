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

#if PHP_MAJOR_VERSION < 7
typedef zend_rsrc_list_entry zend_resource;
#define SW_RETURN_STRING                      RETURN_STRING
#define SW_Z_ARRVAL_P                         Z_ARRVAL_P
#define sw_add_assoc_string                   add_assoc_string
inline int sw_zend_hash_find(HashTable *ht, char *k, int len, void **v);
#define sw_zend_hash_del                      zend_hash_del
#define sw_zend_hash_update                   zend_hash_update
#define sw_zend_hash_index_find               zend_hash_index_find
#define SW_ZVAL_STRINGL                       ZVAL_STRINGL
#define SW_ZEND_FETCH_RESOURCE_NO_RETURN      ZEND_FETCH_RESOURCE_NO_RETURN
#define SW_ZEND_FETCH_RESOURCE                ZEND_FETCH_RESOURCE
#define SW_ZEND_REGISTER_RESOURCE             ZEND_REGISTER_RESOURCE
#define SW_MAKE_STD_ZVAL(p)                   MAKE_STD_ZVAL(p)
#define SW_ZVAL_STRING                        ZVAL_STRING
#define SW_ALLOC_INIT_ZVAL(p)                 ALLOC_INIT_ZVAL(p)
#define SW_RETVAL_STRINGL                     RETVAL_STRINGL
#define sw_smart_str                          smart_str
#define sw_php_var_unserialize                php_var_unserialize
#define sw_zend_is_callable                   zend_is_callable
#define sw_zend_hash_add                      zend_hash_add
#define sw_zend_hash_index_update             zend_hash_index_update
#define sw_call_user_function_ex              call_user_function_ex
#define sw_add_assoc_stringl_ex               add_assoc_stringl_ex
#define sw_add_assoc_stringl                  add_assoc_stringl
#define sw_zval_ptr_dtor                      zval_ptr_dtor
#define sw_zend_hash_copy                     zend_hash_copy
#define sw_zval_add_ref                       zval_add_ref
#define sw_zend_hash_exists                   zend_hash_exists
#define sw_strndup(v,l)                       strndup(Z_STRVAL_P(v),l)
#define sw_php_format_date                    php_format_date
#define sw_php_url_encode                     php_url_encode
#define SW_RETURN_STRINGL                     RETURN_STRINGL
#define sw_zend_register_internal_class_ex    zend_register_internal_class_ex
#define sw_zend_call_method_with_2_params     zend_call_method_with_2_params
typedef int zend_size_t;

#define SWOOLE_GET_SERVER(zobject, serv) zval *zserv;\
    if (sw_zend_hash_find(Z_OBJPROP_P(zobject), ZEND_STRS("_server"), (void **) &zserv) == FAILURE){ \
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have swoole server");\
    RETURN_FALSE;}\
    ZEND_FETCH_RESOURCE(serv, swServer *, &zserv, -1, SW_RES_SERVER_NAME, le_swoole_server);

#define SWOOLE_GET_WORKER(zobject, process) zval *zprocess;\
    if (sw_zend_hash_find(Z_OBJPROP_P(zobject), ZEND_STRS("_process"), (void **) &zprocess) == FAILURE){ \
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Not have process");\
    RETURN_FALSE;}\
    ZEND_FETCH_RESOURCE(process, swWorker *, &zprocess, -1, SW_RES_PROCESS_NAME, le_swoole_process);

#define SW_HASHTABLE_FOREACH_START(ht, entry)\
                zval **tmp = NULL;\
                for (zend_hash_internal_pointer_reset(ht);\
                     zend_hash_has_more_elements(ht) == SUCCESS; \
                     zend_hash_move_forward(ht)) {\
                     if (zend_hash_get_current_data(ht, (void**)&tmp) == FAILURE) {\
            continue;\
                       }\
                       entry = *tmp;

#if defined(HASH_KEY_NON_EXISTANT) && !defined(HASH_KEY_NON_EXISTENT)
#define HASH_KEY_NON_EXISTENT HASH_KEY_NON_EXISTANT
#endif

#define SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, entry)\
    zval **tmp = NULL;\
    for (zend_hash_internal_pointer_reset(ht); \
            (ktype = zend_hash_get_current_key_ex(ht, &k, &klen, &idx, 0, NULL)) != HASH_KEY_NON_EXISTENT; \
            zend_hash_move_forward(ht)\
        ) { \
    if (zend_hash_get_current_data(ht, (void**)&tmp) == FAILURE) {\
        continue;\
    }\
    entry = *tmp;\
    klen --;

#define SW_HASHTABLE_FOREACH_END() }
#define sw_zend_read_property                  zend_read_property
#define sw_zend_hash_get_current_key(a,b,c,d)  zend_hash_get_current_key_ex(a,b,c,d,0,NULL)
#define sw_php_var_serialize(a,b,c)       php_var_serialize(a,&b,c)
#define IS_TRUE    1
inline int SW_Z_TYPE_P(zval *z);
#define SW_Z_TYPE_PP(z)        SW_Z_TYPE_P(*z)
#else
#define sw_php_var_serialize                php_var_serialize
typedef size_t zend_size_t;
#define SW_RETVAL_STRINGL(s, l,dup)         RETVAL_STRINGL(s,l)
#define ZEND_SET_SYMBOL(ht,str,arr) zend_hash_str_update(ht, str, sizeof(str)-1, arr);
inline int Z_BVAL_P(zval *v);
#define sw_add_assoc_stringl(__arg, __key, __str, __length, __duplicate) sw_add_assoc_stringl_ex(__arg, __key, strlen(__key)+1, __str, __length, __duplicate)
inline int sw_add_assoc_stringl_ex(zval *arg, const char *key, size_t key_len, char *str, size_t length,int duplicate);
#define SW_Z_ARRVAL_P(z)                          Z_ARRVAL_P(z)->ht

#define SW_HASHTABLE_FOREACH_START(ht, _val) ZEND_HASH_FOREACH_VAL(ht, _val);  {
#define SW_HASHTABLE_FOREACH_START2(ht, k, klen, ktype, _val) zend_string *_foreach_key;\
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, _foreach_key, _val); k = _foreach_key->val, klen=_foreach_key->len; {

#define SW_HASHTABLE_FOREACH_END()                 } ZEND_HASH_FOREACH_END();

#define Z_ARRVAL_PP(s)                             Z_ARRVAL_P(*s)
#define SW_Z_TYPE_P                                Z_TYPE_P
#define SW_Z_TYPE_PP(s)                            SW_Z_TYPE_P(*s)
#define Z_STRVAL_PP(s)                             Z_STRVAL_P(*s)
#define Z_STRLEN_PP(s)                             Z_STRLEN_P(*s)
#define Z_LVAL_PP(v)                               Z_LVAL_P(*v)
#define sw_strndup(s,l)                            \
        ({zend_string *str = zend_string_copy(Z_STR_P(s));\
        str->val;})
inline char * sw_php_format_date(char *format, size_t format_len, time_t ts, int localtime);

inline char * sw_php_url_encode(char *value, size_t value_len, int* exten);

#define sw_zval_add_ref(p)   Z_TRY_ADDREF_P(*p)
#define sw_zval_ptr_dtor(p)  zval_ptr_dtor(*p)
#define sw_call_user_function_ex(function_table, object_pp, function_name, retval_ptr_ptr, param_count, params, no_separation, ymbol_table)\
    ({zval  real_params[param_count];\
    int i=0;\
    for(;i<param_count;i++){\
       real_params[i] = **params[i];\
    }\
    zval phpng_retval;\
    *retval_ptr_ptr = &phpng_retval;\
    call_user_function_ex(function_table,NULL,function_name,&phpng_retval,param_count,real_params,no_separation,NULL);})

#define sw_php_var_unserialize(rval, p, max, var_hash)\
php_var_unserialize(*rval, p, max, var_hash)

#define SW_MAKE_STD_ZVAL(p)    zval _stack_zval_##p; p = &(_stack_zval_##p)

#define SW_RETURN_STRINGL(z,l,t)                      \
               zval key;\
                ZVAL_STRING(&key, z);\
                RETURN_STR(Z_STR(key))

#define SW_ALLOC_INIT_ZVAL(p)        SW_MAKE_STD_ZVAL(p)
#define SW_ZEND_FETCH_RESOURCE_NO_RETURN(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type)        \
        (rsrc = (rsrc_type) zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type))
#define SW_ZEND_REGISTER_RESOURCE(return_value, result, le_result)  ZVAL_RES(return_value,zend_register_resource(result, le_result))

#define SW_RETURN_STRING(val, duplicate)     RETURN_STRING(val)
#define sw_add_assoc_string(array, key, value, duplicate)   add_assoc_string(array, key, value)
#define sw_zend_hash_copy(target,source,pCopyConstructor,tmp,size) zend_hash_copy(target,source,pCopyConstructor)
#define sw_zend_register_internal_class_ex(entry,parent_ptr,str)    zend_register_internal_class_ex(entry,parent_ptr)
#define sw_zend_call_method_with_2_params(obj,ptr,what,char,return,name,cb)     zend_call_method_with_2_params(*obj,ptr,what,char,*return,name,cb)
#define SW_ZVAL_STRINGL(z, s, l, dup)         ZVAL_STRINGL(z, s, l)
#define SW_ZVAL_STRING(z,s,dup)               ZVAL_STRING(z,s)
#define sw_smart_str                          smart_string

inline zval* sw_zend_read_property(zend_class_entry *class_ptr,zval *obj,char *s, int len,int what);
inline int sw_zend_is_callable(zval *cv, int a, char **name);
inline int sw_zend_hash_del(HashTable *ht, char *k, int len);
inline int sw_zend_hash_add(HashTable *ht, char *k, int len,void *pData,int datasize,void **pDest);
inline int sw_zend_hash_index_update(HashTable *ht, int key,void *pData,int datasize,void **pDest);
inline int sw_zend_hash_update(HashTable *ht, char *k, int len ,void * val,int size,void *ptr);
inline int sw_zend_hash_get_current_key( HashTable *ht, char **key, uint32_t *idx, ulong *num);
inline int sw_zend_hash_find(HashTable *ht, char *k, int len, void **v);
inline int sw_zend_hash_exists(HashTable *ht, char *k, int len);
#endif

#endif /* EXT_SWOOLE_PHP7_WRAPPER_H_ */
