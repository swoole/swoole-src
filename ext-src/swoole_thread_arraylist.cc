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
static PHP_METHOD(swoole_thread_arraylist, find);
static PHP_METHOD(swoole_thread_arraylist, count);
static PHP_METHOD(swoole_thread_arraylist, incr);
static PHP_METHOD(swoole_thread_arraylist, decr);
static PHP_METHOD(swoole_thread_arraylist, clean);
static PHP_METHOD(swoole_thread_arraylist, toArray);
SW_EXTERN_C_END

static sw_inline ThreadArrayListObject *arraylist_fetch_object(zend_object *obj) {
    return (ThreadArrayListObject *) ((char *) obj - swoole_thread_arraylist_handlers.offset);
}

static void arraylist_free_object(zend_object *object) {
    ThreadArrayListObject *ao = arraylist_fetch_object(object);
    if (ao->list) {
        ao->list->del_ref();
        ao->list = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *arraylist_create_object(zend_class_entry *ce) {
    ThreadArrayListObject *ao = (ThreadArrayListObject *) zend_object_alloc(sizeof(ThreadArrayListObject), ce);
    zend_object_std_init(&ao->std, ce);
    object_properties_init(&ao->std, ce);
    ao->std.handlers = &swoole_thread_arraylist_handlers;
    return &ao->std;
}

static ThreadArrayListObject *arraylist_fetch_object_check(zval *zobject) {
    ThreadArrayListObject *ao = arraylist_fetch_object(Z_OBJ_P(zobject));
    if (!ao->list) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return ao;
}

ThreadResource *php_swoole_thread_arraylist_cast(zval *zobject) {
    return arraylist_fetch_object_check(zobject)->list;
}

void php_swoole_thread_arraylist_create(zval *return_value, ThreadResource *resource) {
    auto obj = arraylist_create_object(swoole_thread_arraylist_ce);
    auto ao = (ThreadArrayListObject *) arraylist_fetch_object(obj);
    ao->list = static_cast<ZendArray *>(resource);
    ZVAL_OBJ(return_value, obj);
}

// clang-format off
static const zend_function_entry swoole_thread_arraylist_methods[] = {
    PHP_ME(swoole_thread_arraylist, __construct,  arginfo_class_Swoole_Thread_ArrayList___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetGet,    arginfo_class_Swoole_Thread_ArrayList_offsetGet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetExists, arginfo_class_Swoole_Thread_ArrayList_offsetExists,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetSet,    arginfo_class_Swoole_Thread_ArrayList_offsetSet,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, offsetUnset,  arginfo_class_Swoole_Thread_ArrayList_offsetUnset,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, find,         arginfo_class_Swoole_Thread_ArrayList_find,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, incr,         arginfo_class_Swoole_Thread_ArrayList_incr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, decr,         arginfo_class_Swoole_Thread_ArrayList_decr,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, clean,        arginfo_class_Swoole_Thread_ArrayList_clean,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, count,        arginfo_class_Swoole_Thread_ArrayList_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_arraylist, toArray,      arginfo_class_Swoole_Thread_ArrayList_toArray,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_arraylist_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_arraylist, "Swoole\\Thread\\ArrayList", nullptr, swoole_thread_arraylist_methods);
    swoole_thread_arraylist_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_arraylist, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_arraylist, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_arraylist, arraylist_create_object, arraylist_free_object, ThreadArrayListObject, std);

    zend_class_implements(swoole_thread_arraylist_ce, 2, zend_ce_arrayaccess, zend_ce_countable);
    zend_declare_property_long(swoole_thread_arraylist_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);
}

static PHP_METHOD(swoole_thread_arraylist, __construct) {
    zend_array *array = nullptr;
    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY_HT_OR_NULL(array)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = arraylist_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (ao->list != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        return;
    }

    if (array) {
        if (!zend_array_is_list(array)) {
            zend_throw_error(NULL, "the parameter $array must be an array of type list");
            return;
        }
        ao->list = ZendArray::from(array);
    } else {
        ao->list = new ZendArray();
    }
}

static PHP_METHOD(swoole_thread_arraylist, offsetGet) {
    zend_long index;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(index)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_offsetGet(index, return_value)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, offsetExists) {
    zend_long index;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(index)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    ao->list->index_offsetExists(index, return_value);
}

static PHP_METHOD(swoole_thread_arraylist, offsetSet) {
    zval *zkey;
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zkey)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    zend_long index = ZVAL_IS_NULL(zkey) ? -1 : zval_get_long(zkey);
    if (!ao->list->index_offsetSet(index, zvalue)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, incr) {
    INIT_ARRAY_INCR_PARAMS
    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_incr(zkey, zvalue, return_value)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, decr) {
    INIT_ARRAY_INCR_PARAMS
    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    if (!ao->list->index_decr(zkey, zvalue, return_value)) {
        zend_throw_exception(swoole_exception_ce, "out of range", -1);
    }
}

static PHP_METHOD(swoole_thread_arraylist, offsetUnset) {
    zend_long index;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(index)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    ao->list->index_offsetUnset(index);
}

static PHP_METHOD(swoole_thread_arraylist, find) {
    zval *zvalue;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zvalue)
    ZEND_PARSE_PARAMETERS_END();

    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    ao->list->find(zvalue, return_value);
}

static PHP_METHOD(swoole_thread_arraylist, count) {
    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    ao->list->count(return_value);
}

static PHP_METHOD(swoole_thread_arraylist, clean) {
    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    ao->list->clean();
}

static PHP_METHOD(swoole_thread_arraylist, toArray) {
    auto ao = arraylist_fetch_object_check(ZEND_THIS);
    ao->list->to_array(return_value);
}
#endif
