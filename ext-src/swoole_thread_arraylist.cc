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
#include "stubs/php_swoole_thread_arraylist_arginfo.h"
SW_EXTERN_C_END

zend_class_entry *swoole_thread_arraylist_ce;
static zend_object_handlers swoole_thread_arraylist_handlers;

struct ThreadArrayListObject {
    ZendArray *list;
    zend_object std;
};

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_arraylist, __construct);
static PHP_METHOD(swoole_thread_arraylist, offsetGet);
static PHP_METHOD(swoole_thread_arraylist, offsetExists);
static PHP_METHOD(swoole_thread_arraylist, offsetSet);
static PHP_METHOD(swoole_thread_arraylist, offsetUnset);
static PHP_METHOD(swoole_thread_arraylist, count);
static PHP_METHOD(swoole_thread_arraylist, incr);
static PHP_METHOD(swoole_thread_arraylist, decr);
static PHP_METHOD(swoole_thread_arraylist, clean);
static PHP_METHOD(swoole_thread_arraylist, __wakeup);
SW_EXTERN_C_END

static sw_inline ThreadArrayListObject *thread_arraylist_fetch_object(zend_object *obj) {
    return (ThreadArrayListObject *) ((char *) obj - swoole_thread_arraylist_handlers.offset);
}

static sw_inline zend_long thread_arraylist_get_resource_id(zend_object *obj) {
    zval rv, *property = zend_read_property(swoole_thread_arraylist_ce, obj, ZEND_STRL("id"), 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static sw_inline zend_long thread_arraylist_get_resource_id(zval *zobject) {
    return thread_arraylist_get_resource_id(Z_OBJ_P(zobject));
}

static void thread_arraylist_free_object(zend_object *object) {
    zend_long resource_id = thread_arraylist_get_resource_id(object);
    ThreadArrayListObject *ao = thread_arraylist_fetch_object(object);
    if (ao->list && php_swoole_thread_resource_free(resource_id, ao->list)) {
        delete ao->list;
        ao->list = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *thread_arraylist_create_object(zend_class_entry *ce) {
    ThreadArrayListObject *ao = (ThreadArrayListObject *) zend_object_alloc(sizeof(ThreadArrayListObject), ce);
    zend_object_std_init(&ao->std, ce);
    object_properties_init(&ao->std, ce);
    ao->std.handlers = &swoole_thread_arraylist_handlers;
    return &ao->std;
}

ThreadArrayListObject *thread_arraylist_fetch_object_check(zval *zobject) {
    ThreadArrayListObject *ao = thread_arraylist_fetch_object(Z_OBJ_P(zobject));
    if (!ao->list) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return ao;
}

// clang-format off
static const zend_function_entry swoole_thread_arraylist_methods[] = {
    PHP_ME(swoole_thread_arraylist, __construct,  arginfo_class_Swoole_Thread_ArrayList___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetGet,    arginfo_class_Swoole_Thread_ArrayList_offsetGet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetExists, arginfo_class_Swoole_Thread_ArrayList_offsetExists,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetSet,    arginfo_class_Swoole_Thread_ArrayList_offsetSet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetUnset,  arginfo_class_Swoole_Thread_ArrayList_offsetUnset,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, incr,         arginfo_class_Swoole_Thread_ArrayList_incr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, decr,         arginfo_class_Swoole_Thread_ArrayList_decr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, clean,        arginfo_class_Swoole_Thread_ArrayList_clean,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, count,        arginfo_class_Swoole_Thread_ArrayList_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, __wakeup,     arginfo_class_Swoole_Thread_ArrayList___wakeup,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_arraylist_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_arraylist, "Swoole\\Thread\\ArrayList", nullptr, swoole_thread_arraylist_methods);
    SW_SET_CLASS_CLONEABLE(swoole_thread_arraylist, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_arraylist, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_arraylist,
                               thread_arraylist_create_object,
                               thread_arraylist_free_object,
                               ThreadArrayListObject,
                               std);

    zend_class_implements(swoole_thread_arraylist_ce, 2, zend_ce_arrayaccess, zend_ce_countable);
    zend_declare_property_long(swoole_thread_arraylist_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);
}

static PHP_METHOD(swoole_thread_arraylist, __construct) {
    ZEND_PARSE_PARAMETERS_NONE();

    auto ao = thread_arraylist_fetch_object(Z_OBJ_P(ZEND_THIS));
    ao->list = new ZendArray();
    auto resource_id = php_swoole_thread_resource_insert(ao->list);
    zend_update_property_long(swoole_thread_arraylist_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
}

static PHP_METHOD(swoole_thread_arraylist, offsetGet) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_offsetGet(zkey, return_value)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, offsetExists) {
    zval *zkey;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zkey)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ao->list->index_offsetExists(zkey, return_value);
}

static PHP_METHOD(swoole_thread_arraylist, offsetSet) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_offsetSet(zkey, zvalue)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, incr) {
    INIT_ARRAY_INCR_PARAMS
    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_incr(zkey, zvalue, return_value)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, decr) {
    INIT_ARRAY_INCR_PARAMS
    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_decr(zkey, zvalue, return_value)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, offsetUnset) {
    zend_throw_exception(swoole_exception_ce, "unsupported", -3);
}

static PHP_METHOD(swoole_thread_arraylist, count) {
    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ao->list->count(return_value);
}

static PHP_METHOD(swoole_thread_arraylist, clean) {
    auto ao = thread_arraylist_fetch_object_check(ZEND_THIS);
    ao->list->clean();
}

static PHP_METHOD(swoole_thread_arraylist, __wakeup) {
    auto mo = thread_arraylist_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = thread_arraylist_get_resource_id(ZEND_THIS);
    mo->list = static_cast<ZendArray *>(php_swoole_thread_resource_fetch(resource_id));
    if (!mo->list) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
    }
}
#endif
