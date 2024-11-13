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

#include "php_swoole_cxx.h"

#ifdef SW_THREAD
#include "php_swoole_thread.h"

SW_EXTERN_C_BEGIN
#include "stubs/php_swoole_thread_map_arginfo.h"
SW_EXTERN_C_END

zend_class_entry *swoole_thread_map_ce;
static zend_object_handlers swoole_thread_map_handlers;

struct ThreadMapObject {
    ZendArray *map;
    zend_object std;
};

static sw_inline ThreadMapObject *map_fetch_object(zend_object *obj) {
    return (ThreadMapObject *) ((char *) obj - swoole_thread_map_handlers.offset);
}

static void map_free_object(zend_object *object) {
    ThreadMapObject *mo = map_fetch_object(object);
    if (mo->map) {
        mo->map->del_ref();
        mo->map = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *map_create_object(zend_class_entry *ce) {
    ThreadMapObject *mo = (ThreadMapObject *) zend_object_alloc(sizeof(ThreadMapObject), ce);
    zend_object_std_init(&mo->std, ce);
    object_properties_init(&mo->std, ce);
    mo->std.handlers = &swoole_thread_map_handlers;
    return &mo->std;
}

static ThreadMapObject *map_fetch_object_check(zval *zobject) {
    ThreadMapObject *map = map_fetch_object(Z_OBJ_P(zobject));
    if (!map->map) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return map;
}

ThreadResource *php_swoole_thread_map_cast(zval *zobject) {
    return map_fetch_object(Z_OBJ_P(zobject))->map;
}

void php_swoole_thread_map_create(zval *return_value, ThreadResource *resource) {
    auto obj = map_create_object(swoole_thread_map_ce);
    auto mo = (ThreadMapObject *) map_fetch_object(obj);
    mo->map = static_cast<ZendArray *>(resource);
    ZVAL_OBJ(return_value, obj);
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_map, __construct);
static PHP_METHOD(swoole_thread_map, offsetGet);
static PHP_METHOD(swoole_thread_map, offsetExists);
static PHP_METHOD(swoole_thread_map, offsetSet);
static PHP_METHOD(swoole_thread_map, offsetUnset);
static PHP_METHOD(swoole_thread_map, find);
static PHP_METHOD(swoole_thread_map, count);
static PHP_METHOD(swoole_thread_map, keys);
static PHP_METHOD(swoole_thread_map, values);
static PHP_METHOD(swoole_thread_map, incr);
static PHP_METHOD(swoole_thread_map, decr);
static PHP_METHOD(swoole_thread_map, add);
static PHP_METHOD(swoole_thread_map, update);
static PHP_METHOD(swoole_thread_map, clean);
static PHP_METHOD(swoole_thread_map, toArray);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_map_methods[] = {
    PHP_ME(swoole_thread_map, __construct,     arginfo_class_Swoole_Thread_Map___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetGet,       arginfo_class_Swoole_Thread_Map_offsetGet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetExists,    arginfo_class_Swoole_Thread_Map_offsetExists,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetSet,       arginfo_class_Swoole_Thread_Map_offsetSet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetUnset,     arginfo_class_Swoole_Thread_Map_offsetUnset,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, find,            arginfo_class_Swoole_Thread_Map_find,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, count,           arginfo_class_Swoole_Thread_Map_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, incr,            arginfo_class_Swoole_Thread_Map_incr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, decr,            arginfo_class_Swoole_Thread_Map_decr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, add,             arginfo_class_Swoole_Thread_Map_add,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, update,          arginfo_class_Swoole_Thread_Map_update,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, clean,           arginfo_class_Swoole_Thread_Map_clean,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, keys,            arginfo_class_Swoole_Thread_Map_keys,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, values,          arginfo_class_Swoole_Thread_Map_values,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, toArray,         arginfo_class_Swoole_Thread_Map_toArray,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_map_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_map, "Swoole\\Thread\\Map", nullptr, swoole_thread_map_methods);
    swoole_thread_map_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_map, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_map, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_map, map_create_object, map_free_object, ThreadMapObject, std);

    zend_class_implements(swoole_thread_map_ce, 2, zend_ce_arrayaccess, zend_ce_countable);
}

static PHP_METHOD(swoole_thread_map, __construct) {
    zend_array *array = nullptr;
    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY_HT_OR_NULL(array)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (mo->map != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        return;
    }

    if (array) {
        mo->map = ZendArray::from(array);
    } else {
        mo->map = new ZendArray();
    }
}

static int handle_array_key(zval *key, zend_ulong *idx) {
    switch (Z_TYPE_P(key)) {
    case IS_STRING:
        return _zend_handle_numeric_str(Z_STRVAL_P(key), Z_STRLEN_P(key), idx) ? IS_LONG : IS_STRING;
    case IS_LONG:
        *idx = Z_LVAL_P(key);
        return IS_LONG;
    case IS_NULL:
        return IS_NULL;
    case IS_DOUBLE:
        *idx = zend_dval_to_lval_safe(Z_DVAL_P(key));
        return IS_LONG;
    case IS_FALSE:
        *idx = 0;
        return IS_LONG;
    case IS_TRUE:
        *idx = 1;
        return IS_LONG;
    case IS_RESOURCE:
        zend_use_resource_as_offset(key);
        *idx = Z_RES_HANDLE_P(key);
        return IS_LONG;
    default:
        zend_argument_type_error(1, "Illegal offset type");
        return IS_UNDEF;
    }
}

#define ZEND_ARRAY_CALL_METHOD(array, method, zkey, ...)                                                               \
    zend_ulong idx;                                                                                                    \
    int type_of_key = handle_array_key(zkey, &idx);                                                                    \
    if (type_of_key == IS_LONG) {                                                                                      \
        array->intkey_##method(idx, ##__VA_ARGS__);                                                                    \
    } else if (type_of_key == IS_STRING) {                                                                             \
        array->strkey_##method(zkey, ##__VA_ARGS__);                                                                   \
    } else if (type_of_key == IS_NULL) {                                                                               \
        zval empty_str;                                                                                                \
        ZVAL_EMPTY_STRING(&empty_str);                                                                                 \
        array->strkey_##method(&empty_str, ##__VA_ARGS__);                                                             \
    } else {                                                                                                           \
        zend_type_error("Illegal offset type");                                                                        \
    }

static PHP_METHOD(swoole_thread_map, offsetGet) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetGet, zkey, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetExists) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetExists, zkey, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetSet) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetSet, zkey, zvalue);
}

static PHP_METHOD(swoole_thread_map, incr) {
    INIT_ARRAY_INCR_PARAMS
    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, incr, zkey, zvalue, return_value);
}

static PHP_METHOD(swoole_thread_map, decr) {
    INIT_ARRAY_INCR_PARAMS
    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, decr, zkey, zvalue, return_value);
}

static PHP_METHOD(swoole_thread_map, add) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, add, zkey, zvalue, return_value);
}

static PHP_METHOD(swoole_thread_map, update) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, update, zkey, zvalue, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetUnset) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetUnset, zkey);
}

static PHP_METHOD(swoole_thread_map, find) {
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = map_fetch_object_check(ZEND_THIS);
    mo->map->find(zvalue, return_value);
}

static PHP_METHOD(swoole_thread_map, count) {
    auto mo = map_fetch_object_check(ZEND_THIS);
    mo->map->count(return_value);
}

static PHP_METHOD(swoole_thread_map, keys) {
    auto mo = map_fetch_object_check(ZEND_THIS);
    mo->map->keys(return_value);
}

static PHP_METHOD(swoole_thread_map, values) {
    auto mo = map_fetch_object_check(ZEND_THIS);
    mo->map->values(return_value);
}

static PHP_METHOD(swoole_thread_map, toArray) {
    auto mo = map_fetch_object_check(ZEND_THIS);
    mo->map->to_array(return_value);
}

static PHP_METHOD(swoole_thread_map, clean) {
    auto mo = map_fetch_object_check(ZEND_THIS);
    mo->map->clean();
}

#endif
