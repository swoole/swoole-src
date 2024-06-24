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
#include "php_swoole_thread.h"
#include "swoole_memory.h"
#include "swoole_lock.h"

#ifdef SW_THREAD

BEGIN_EXTERN_C()
#include "stubs/php_swoole_thread_barrier_arginfo.h"
END_EXTERN_C()

using swoole::Barrier;

static zend_class_entry *swoole_thread_barrier_ce;
static zend_object_handlers swoole_thread_barrier_handlers;

struct BarrierResource : public ThreadResource {
    Barrier barrier_;
    BarrierResource(int count) : ThreadResource() {
        barrier_.init(false, count);
    }
    void wait() {
        barrier_.wait();
    }
    ~BarrierResource() {
        barrier_.destroy();
    }
};

struct BarrierObject {
    BarrierResource *barrier;
    zend_object std;
};

static sw_inline BarrierObject *php_swoole_thread_barrier_fetch_object(zend_object *obj) {
    return (BarrierObject *) ((char *) obj - swoole_thread_barrier_handlers.offset);
}

static BarrierResource *php_swoole_thread_barrier_get_ptr(zval *zobject) {
    return php_swoole_thread_barrier_fetch_object(Z_OBJ_P(zobject))->barrier;
}

static BarrierResource *php_swoole_thread_barrier_get_and_check_ptr(zval *zobject) {
    BarrierResource *barrier = php_swoole_thread_barrier_get_ptr(zobject);
    if (!barrier) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return barrier;
}

static void php_swoole_thread_barrier_free_object(zend_object *object) {
    BarrierObject *bo = php_swoole_thread_barrier_fetch_object(object);
    zend_long resource_id = zend::object_get_long(object, ZEND_STRL("id"));
    if (bo->barrier && php_swoole_thread_resource_free(resource_id, bo->barrier)) {
        delete bo->barrier;
        bo->barrier = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_thread_barrier_create_object(zend_class_entry *ce) {
    BarrierObject *bo = (BarrierObject *) zend_object_alloc(sizeof(BarrierObject), ce);
    zend_object_std_init(&bo->std, ce);
    object_properties_init(&bo->std, ce);
    bo->std.handlers = &swoole_thread_barrier_handlers;
    return &bo->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_barrier, __construct);
static PHP_METHOD(swoole_thread_barrier, wait);
static PHP_METHOD(swoole_thread_barrier, __wakeup);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_barrier_methods[] =
{
    PHP_ME(swoole_thread_barrier, __construct,  arginfo_class_Swoole_Thread_Barrier___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_barrier, wait,         arginfo_class_Swoole_Thread_Barrier_wait,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_barrier, __wakeup,     arginfo_class_Swoole_Thread_Barrier___wakeup,     ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_barrier_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_barrier, "Swoole\\Thread\\Barrier", nullptr, swoole_thread_barrier_methods);
    zend_declare_property_long(swoole_thread_barrier_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
    SW_SET_CLASS_CLONEABLE(swoole_thread_barrier, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_barrier, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_barrier,
                               php_swoole_thread_barrier_create_object,
                               php_swoole_thread_barrier_free_object,
                               BarrierObject,
                               std);
}

static PHP_METHOD(swoole_thread_barrier, __construct) {
    auto bo = php_swoole_thread_barrier_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (bo->barrier != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    zend_long count;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(count)
    ZEND_PARSE_PARAMETERS_END();

    if (count < 2) {
        zend_throw_exception(
            swoole_exception_ce, "The parameter $count must be greater than 1", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    bo->barrier = new BarrierResource(count);
    auto resource_id = php_swoole_thread_resource_insert(bo->barrier);
    zend_update_property_long(swoole_thread_barrier_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_thread_barrier, wait) {
    BarrierResource *barrier = php_swoole_thread_barrier_get_and_check_ptr(ZEND_THIS);
    if (barrier) {
        barrier->wait();
    }
}

static PHP_METHOD(swoole_thread_barrier, __wakeup) {
    auto bo = php_swoole_thread_barrier_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = zend::object_get_long(ZEND_THIS, ZEND_STRL("id"));
    bo->barrier = static_cast<BarrierResource *>(php_swoole_thread_resource_fetch(resource_id));
    if (!bo->barrier) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
        return;
    }
}
#endif
