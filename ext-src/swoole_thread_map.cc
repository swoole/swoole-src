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

static sw_inline ThreadMapObject *thread_map_fetch_object(zend_object *obj) {
    return (ThreadMapObject *) ((char *) obj - swoole_thread_map_handlers.offset);
}

static sw_inline zend_long thread_map_get_resource_id(zend_object *obj) {
    zval rv, *property = zend_read_property(swoole_thread_map_ce, obj, ZEND_STRL("id"), 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static sw_inline zend_long thread_map_get_resource_id(zval *zobject) {
    return thread_map_get_resource_id(Z_OBJ_P(zobject));
}

static void thread_map_free_object(zend_object *object) {
    zend_long resource_id = thread_map_get_resource_id(object);
    ThreadMapObject *mo = thread_map_fetch_object(object);
    if (mo->map && php_swoole_thread_resource_free(resource_id, mo->map)) {
        delete mo->map;
        mo->map = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *thread_map_create_object(zend_class_entry *ce) {
    ThreadMapObject *mo = (ThreadMapObject *) zend_object_alloc(sizeof(ThreadMapObject), ce);
    zend_object_std_init(&mo->std, ce);
    object_properties_init(&mo->std, ce);
    mo->std.handlers = &swoole_thread_map_handlers;
    return &mo->std;
}

ThreadMapObject *thread_map_fetch_object_check(zval *zobject) {
    ThreadMapObject *map = thread_map_fetch_object(Z_OBJ_P(zobject));
    if (!map->map) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return map;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_map, __construct);
static PHP_METHOD(swoole_thread_map, offsetGet);
static PHP_METHOD(swoole_thread_map, offsetExists);
static PHP_METHOD(swoole_thread_map, offsetSet);
static PHP_METHOD(swoole_thread_map, offsetUnset);
static PHP_METHOD(swoole_thread_map, count);
static PHP_METHOD(swoole_thread_map, keys);
static PHP_METHOD(swoole_thread_map, clean);
static PHP_METHOD(swoole_thread_map, __wakeup);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_map_methods[] = {
    PHP_ME(swoole_thread_map, __construct,     arginfo_class_Swoole_Thread_Map___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetGet,       arginfo_class_Swoole_Thread_Map_offsetGet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetExists,    arginfo_class_Swoole_Thread_Map_offsetExists,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetSet,       arginfo_class_Swoole_Thread_Map_offsetSet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, offsetUnset,     arginfo_class_Swoole_Thread_Map_offsetUnset,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, count,           arginfo_class_Swoole_Thread_Map_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, clean,           arginfo_class_Swoole_Thread_Map_clean,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, keys,            arginfo_class_Swoole_Thread_Map_keys,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_map, __wakeup,        arginfo_class_Swoole_Thread_Map___wakeup,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_map_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_map, "Swoole\\Thread\\Map", nullptr, swoole_thread_map_methods);
    SW_SET_CLASS_CLONEABLE(swoole_thread_map, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_map, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_map, thread_map_create_object, thread_map_free_object, ThreadMapObject, std);

    zend_class_implements(swoole_thread_map_ce, 2, zend_ce_arrayaccess, zend_ce_countable);
    zend_declare_property_long(swoole_thread_map_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
}


static PHP_METHOD(swoole_thread_map, __construct) {
    auto mo = thread_map_fetch_object(Z_OBJ_P(ZEND_THIS));
    mo->map = new ZendArray();
    auto resource_id = php_swoole_thread_resource_insert(mo->map);
    zend_update_property_long(swoole_thread_map_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
}

#define ZEND_ARRAY_CALL_METHOD(array, method, zkey, ...)                                                               \
    if (ZVAL_IS_LONG(zkey)) {                                                                                          \
        array->intkey_##method(zkey, ##__VA_ARGS__);                                                                   \
    } else {                                                                                                           \
        array->strkey_##method(zkey, ##__VA_ARGS__);                                                                   \
    }

static PHP_METHOD(swoole_thread_map, offsetGet) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetGet, zkey, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetExists) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetExists, zkey, return_value);
}

static PHP_METHOD(swoole_thread_map, offsetSet) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetSet, zkey, zvalue);
}

static PHP_METHOD(swoole_thread_map, offsetUnset) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    ZEND_ARRAY_CALL_METHOD(mo->map, offsetUnset, zkey);
}

static PHP_METHOD(swoole_thread_map, count) {
    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->map->count(return_value);
}

static PHP_METHOD(swoole_thread_map, keys) {
    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->map->keys(return_value);
}

static PHP_METHOD(swoole_thread_map, clean) {
    auto mo = thread_map_fetch_object_check(ZEND_THIS);
    mo->map->clean();
}

static PHP_METHOD(swoole_thread_map, __wakeup) {
    auto mo = thread_map_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = thread_map_get_resource_id(ZEND_THIS);
    mo->map = static_cast<ZendArray *>(php_swoole_thread_resource_fetch(resource_id));
    if (!mo->map) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
    }
}

#endif
