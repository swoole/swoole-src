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

zend_class_entry *swoole_thread_barrier_ce;
static zend_object_handlers swoole_thread_barrier_handlers;

struct BarrierResource : public ThreadResource {
    Barrier barrier_;
    BarrierResource(int count) : ThreadResource() {
        barrier_.init(false, count);
    }
    void wait() {
        barrier_.wait();
    }
    ~BarrierResource() override {
        barrier_.destroy();
    }
};

struct BarrierObject {
    BarrierResource *barrier;
    zend_object std;
};

static sw_inline BarrierObject *barrier_fetch_object(zend_object *obj) {
    return (BarrierObject *) ((char *) obj - swoole_thread_barrier_handlers.offset);
}

static BarrierResource *barrier_get_ptr(zval *zobject) {
    return barrier_fetch_object(Z_OBJ_P(zobject))->barrier;
}

static BarrierResource *barrier_get_and_check_ptr(zval *zobject) {
    BarrierResource *barrier = barrier_get_ptr(zobject);
    if (UNEXPECTED(!barrier)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return barrier;
}

static void barrier_free_object(zend_object *object) {
    BarrierObject *bo = barrier_fetch_object(object);
    if (bo->barrier) {
        bo->barrier->del_ref();
        bo->barrier = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *barrier_create_object(zend_class_entry *ce) {
    BarrierObject *bo = (BarrierObject *) zend_object_alloc(sizeof(BarrierObject), ce);
    zend_object_std_init(&bo->std, ce);
    object_properties_init(&bo->std, ce);
    bo->std.handlers = &swoole_thread_barrier_handlers;
    return &bo->std;
}

ThreadResource *php_swoole_thread_barrier_cast(zval *zobject) {
    return barrier_fetch_object(Z_OBJ_P(zobject))->barrier;
}

void php_swoole_thread_barrier_create(zval *return_value, ThreadResource *resource) {
    auto obj = barrier_create_object(swoole_thread_barrier_ce);
    auto bo = (BarrierObject *) barrier_fetch_object(obj);
    bo->barrier = static_cast<BarrierResource *>(resource);
    ZVAL_OBJ(return_value, obj);
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_barrier, __construct);
static PHP_METHOD(swoole_thread_barrier, wait);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_barrier_methods[] =
{
    PHP_ME(swoole_thread_barrier, __construct,  arginfo_class_Swoole_Thread_Barrier___construct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_barrier, wait,         arginfo_class_Swoole_Thread_Barrier_wait,         ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_barrier_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_barrier, "Swoole\\Thread\\Barrier", nullptr, swoole_thread_barrier_methods);
    swoole_thread_barrier_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_barrier, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_barrier, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_thread_barrier,
                               barrier_create_object,
                               barrier_free_object,
                               BarrierObject,
                               std);
}

static PHP_METHOD(swoole_thread_barrier, __construct) {
    auto bo = barrier_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (bo->barrier != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        return;
    }

    zend_long count;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(count)
    ZEND_PARSE_PARAMETERS_END();

    if (count < 2) {
        zend_throw_exception(
            swoole_exception_ce, "The parameter $count must be greater than 1", SW_ERROR_INVALID_PARAMS);
        return;
    }

    bo->barrier = new BarrierResource(count);
}

static PHP_METHOD(swoole_thread_barrier, wait) {
    BarrierResource *barrier = barrier_get_and_check_ptr(ZEND_THIS);
    if (barrier) {
        barrier->wait();
    }
}

#endif
