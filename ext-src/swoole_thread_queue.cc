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

    ~Queue() {
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

static sw_inline ThreadQueueObject *thread_queue_fetch_object(zend_object *obj) {
    return (ThreadQueueObject *) ((char *) obj - swoole_thread_queue_handlers.offset);
}

static sw_inline zend_long thread_queue_get_resource_id(zend_object *obj) {
    zval rv, *property = zend_read_property(swoole_thread_queue_ce, obj, ZEND_STRL("id"), 1, &rv);
    return property ? zval_get_long(property) : 0;
}

static sw_inline zend_long thread_queue_get_resource_id(zval *zobject) {
    return thread_queue_get_resource_id(Z_OBJ_P(zobject));
}

static void thread_queue_free_object(zend_object *object) {
    zend_long resource_id = thread_queue_get_resource_id(object);
    ThreadQueueObject *qo = thread_queue_fetch_object(object);
    if (qo->queue && php_swoole_thread_resource_free(resource_id, qo->queue)) {
        delete qo->queue;
        qo->queue = nullptr;
    }
    zend_object_std_dtor(object);
}

static zend_object *thread_queue_create_object(zend_class_entry *ce) {
    ThreadQueueObject *qo = (ThreadQueueObject *) zend_object_alloc(sizeof(ThreadQueueObject), ce);
    zend_object_std_init(&qo->std, ce);
    object_properties_init(&qo->std, ce);
    qo->std.handlers = &swoole_thread_queue_handlers;
    return &qo->std;
}

ThreadQueueObject *thread_queue_fetch_object_check(zval *zobject) {
    ThreadQueueObject *qo = thread_queue_fetch_object(Z_OBJ_P(zobject));
    if (!qo->queue) {
        php_swoole_fatal_error(E_ERROR, "must call constructor first");
    }
    return qo;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_thread_queue, __construct);
static PHP_METHOD(swoole_thread_queue, push);
static PHP_METHOD(swoole_thread_queue, pop);
static PHP_METHOD(swoole_thread_queue, count);
static PHP_METHOD(swoole_thread_queue, clean);
static PHP_METHOD(swoole_thread_queue, __wakeup);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_thread_queue_methods[] = {
    PHP_ME(swoole_thread_queue, __construct,  arginfo_class_Swoole_Thread_Queue___construct,   ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, push,         arginfo_class_Swoole_Thread_Queue_push,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, pop,          arginfo_class_Swoole_Thread_Queue_pop,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, clean,        arginfo_class_Swoole_Thread_Queue_clean,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, count,        arginfo_class_Swoole_Thread_Queue_count,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_thread_queue, __wakeup,     arginfo_class_Swoole_Thread_Queue___wakeup,      ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_thread_queue_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_thread_queue, "Swoole\\Thread\\Queue", nullptr, swoole_thread_queue_methods);
    SW_SET_CLASS_CLONEABLE(swoole_thread_queue, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_thread_queue, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_thread_queue, thread_queue_create_object, thread_queue_free_object, ThreadQueueObject, std);

    zend_class_implements(swoole_thread_queue_ce, 1, zend_ce_countable);
    zend_declare_property_long(swoole_thread_queue_ce, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC | ZEND_ACC_READONLY);

    zend_declare_class_constant_long(swoole_thread_queue_ce, ZEND_STRL("NOTIFY_ONE"), Queue::NOTIFY_ONE);
    zend_declare_class_constant_long(swoole_thread_queue_ce, ZEND_STRL("NOTIFY_ALL"), Queue::NOTIFY_ALL);
}

static PHP_METHOD(swoole_thread_queue, __construct) {
    auto qo = thread_queue_fetch_object(Z_OBJ_P(ZEND_THIS));
    qo->queue = new Queue();
    auto resource_id = php_swoole_thread_resource_insert(qo->queue);
    zend_update_property_long(swoole_thread_queue_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), resource_id);
}

static PHP_METHOD(swoole_thread_queue, push) {
    zval *zvalue;
    zend_long notify_which = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(zvalue)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(notify_which)
    ZEND_PARSE_PARAMETERS_END();

    auto qo = thread_queue_fetch_object_check(ZEND_THIS);
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

    auto qo = thread_queue_fetch_object_check(ZEND_THIS);
    if (timeout == 0) {
        qo->queue->pop(return_value);
    } else {
        qo->queue->pop_wait(return_value, timeout);
    }
}

static PHP_METHOD(swoole_thread_queue, count) {
    auto qo = thread_queue_fetch_object_check(ZEND_THIS);
    qo->queue->count(return_value);
}

static PHP_METHOD(swoole_thread_queue, clean) {
    auto qo = thread_queue_fetch_object_check(ZEND_THIS);
    qo->queue->clean();
}

static PHP_METHOD(swoole_thread_queue, __wakeup) {
    auto qo = thread_queue_fetch_object(Z_OBJ_P(ZEND_THIS));
    zend_long resource_id = thread_queue_get_resource_id(ZEND_THIS);
    qo->queue = static_cast<Queue *>(php_swoole_thread_resource_fetch(resource_id));
    if (!qo->queue) {
        zend_throw_exception(swoole_exception_ce, EMSG_NO_RESOURCE, ECODE_NO_RESOURCE);
    }
}

#endif
