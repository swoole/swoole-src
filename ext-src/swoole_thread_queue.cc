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
#include "stubs/php_swoole_thread_queue_arginfo.h"

#include <queue>
#include <condition_variable>

zend_class_entry *swoole_thread_queue_ce;
static zend_object_handlers swoole_thread_queue_handlers;

struct Queue : ThreadResource {
    std::queue<ArrayItem *> queue;
    std::mutex lock_;
    std::condition_variable cv_;

    enum {
        NOTIFY_NONE = 0,
        NOTIFY_ONE = 1,
        NOTIFY_ALL = 2,
    };

    Queue() : ThreadResource(), queue() {}

    ~Queue() override {
        clean();
    }

    void push(zval *zvalue) {
        auto item = new ArrayItem(zvalue);
        lock_.lock();
        queue.push(item);
        lock_.unlock();
    }

    void pop(zval *return_value) {
        ArrayItem *item = nullptr;
        lock_.lock();
        if (!queue.empty()) {
            item = queue.front();
            queue.pop();
        }
        lock_.unlock();
        if (item) {
            item->fetch(return_value);
            delete item;
        }
    }

    void push_notify(zval *zvalue, bool notify_all) {
        auto item = new ArrayItem(zvalue);
        std::unique_lock<std::mutex> _lock(lock_);
        queue.push(item);
        if (notify_all) {
            cv_.notify_all();
        } else {
            cv_.notify_one();
        }
    }

    void pop_wait(zval *return_value, double timeout) {
        ArrayItem *item = nullptr;
        std::unique_lock<std::mutex> _lock(lock_);
        SW_LOOP {
            if (!queue.empty()) {
                item = queue.front();
                queue.pop();
                break;
            } else {
                if (timeout > 0) {
                    if (cv_.wait_for(_lock, std::chrono::duration<double>(timeout)) == std::cv_status::timeout) {
                        break;
                    }
                } else {
                    cv_.wait(_lock);
                }
                // All threads have been awakened,
                // but the data has already been acquired by other thread, returning NULL.
                if (queue.empty()) {
                    RETVAL_NULL();
                    swoole_set_last_error(SW_ERROR_NO_PAYLOAD);
                    break;
                }
            }
        }
        _lock.unlock();
        if (item) {
            item->fetch(return_value);
            delete item;
        }
    }

    void count(zval *return_value) {
        lock_.lock();
        RETVAL_LONG(queue.size());
        lock_.unlock();
    }

    void clean() {
        lock_.lock();
        while (!queue.empty()) {
            ArrayItem *item = queue.front();
            delete item;
            queue.pop();
        }
        lock_.unlock();
    }
};

struct ThreadQueueObject {
    Queue *queue;
    zend_object std;
};

static sw_inline ThreadQueueObject *queue_fetch_object(zend_object *obj) {
    return (ThreadQueueObject *) ((char *) obj - swoole_thread_queue_handlers.offset);
}

static void queue_free_object(zend_object *object) {
    ThreadQueueObject *qo = queue_fetch_object(object);
    if (qo->queue) {
        qo->queue->del_ref();
        qo->queue = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *queue_create_object(zend_class_entry *ce) {
    ThreadQueueObject *qo = (ThreadQueueObject *) zend_object_alloc(sizeof(ThreadQueueObject), ce);
    zend_object_std_init(&qo->std, ce);
    object_properties_init(&qo->std, ce);
    qo->std.handlers = &swoole_thread_queue_handlers;
    return &qo->std;
}

ThreadQueueObject *queue_fetch_object_check(zval *zobject) {
    ThreadQueueObject *qo = queue_fetch_object(Z_OBJ_P(zobject));
    if (!qo->queue) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return qo;
}

ThreadResource *php_swoole_thread_queue_cast(zval *zobject) {
    return queue_fetch_object(Z_OBJ_P(zobject))->queue;
}

void php_swoole_thread_queue_create(zval *return_value, ThreadResource *resource) {
    auto obj = queue_create_object(swoole_thread_queue_ce);
    auto qo = (ThreadQueueObject *) queue_fetch_object(obj);
    qo->queue = static_cast<Queue *>(resource);
    ZVAL_OBJ(return_value, obj);
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_queue, __construct);
static PHP_METHOD(swoole_thread_queue, push);
static PHP_METHOD(swoole_thread_queue, pop);
static PHP_METHOD(swoole_thread_queue, count);
static PHP_METHOD(swoole_thread_queue, clean);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_queue_methods[] = {
    PHP_ME(swoole_thread_queue, __construct,  arginfo_class_Swoole_Thread_Queue___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, push,         arginfo_class_Swoole_Thread_Queue_push,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, pop,          arginfo_class_Swoole_Thread_Queue_pop,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, clean,        arginfo_class_Swoole_Thread_Queue_clean,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, count,        arginfo_class_Swoole_Thread_Queue_count,         ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_queue_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_queue, "Swoole\\Thread\\Queue", nullptr, swoole_thread_queue_methods);
    swoole_thread_queue_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NOT_SERIALIZABLE;
    SW_SET_CLASS_CLONEABLE(swoole_thread_queue, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_queue, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_queue, queue_create_object, queue_free_object, ThreadQueueObject, std);

    zend_class_implements(swoole_thread_queue_ce, 1, zend_ce_countable);

    zend_declare_class_constant_long(swoole_thread_queue_ce, ZEND_STRL("NOTIFY_ONE"), Queue::NOTIFY_ONE);
    zend_declare_class_constant_long(swoole_thread_queue_ce, ZEND_STRL("NOTIFY_ALL"), Queue::NOTIFY_ALL);
}

static PHP_METHOD(swoole_thread_queue, __construct) {
    auto qo = queue_fetch_object(Z_OBJ_P(ZEND_THIS));
    if (qo->queue != nullptr) {
        zend_throw_error(NULL, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        return;
    }
    qo->queue = new Queue();
}

static PHP_METHOD(swoole_thread_queue, push) {
    zval *zvalue;
    zend_long notify_which = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(zvalue)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(notify_which)
    ZEND_PARSE_PARAMETERS_END();

    auto qo = queue_fetch_object_check(ZEND_THIS);
    if (notify_which > 0) {
        qo->queue->push_notify(zvalue, notify_which == Queue::NOTIFY_ALL);
    } else {
        qo->queue->push(zvalue);
    }
}

static PHP_METHOD(swoole_thread_queue, pop) {
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END();

    auto qo = queue_fetch_object_check(ZEND_THIS);
    if (timeout == 0) {
        qo->queue->pop(return_value);
    } else {
        qo->queue->pop_wait(return_value, timeout);
    }
}

static PHP_METHOD(swoole_thread_queue, count) {
    auto qo = queue_fetch_object_check(ZEND_THIS);
    qo->queue->count(return_value);
}

static PHP_METHOD(swoole_thread_queue, clean) {
    auto qo = queue_fetch_object_check(ZEND_THIS);
    qo->queue->clean();
}

#endif
