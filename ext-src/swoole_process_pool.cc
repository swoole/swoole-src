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
#include "php_swoole_process.h"

#include "swoole_server.h"
#include "swoole_signal.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_process_pool_arginfo.h"
END_EXTERN_C()

using namespace swoole;

static zend_class_entry *swoole_process_pool_ce;
static zend_object_handlers swoole_process_pool_handlers;
static ProcessPool *current_pool = nullptr;
static Worker *current_worker = nullptr;

struct ProcessPoolObject {
    ProcessPool *pool;
    zend::Callable *onStart;
    zend::Callable *onShutdown;
    zend::Callable *onWorkerStart;
    zend::Callable *onWorkerStop;
    zend::Callable *onWorkerExit;
    zend::Callable *onMessage;
    zend_bool enable_coroutine;
    zend_bool enable_message_bus;
    zend_object std;
};

static void process_pool_signal_handler(int sig);

static sw_inline ProcessPoolObject *process_pool_fetch_object(zend_object *obj) {
    return (ProcessPoolObject *) ((char *) obj - swoole_process_pool_handlers.offset);
}

static sw_inline ProcessPoolObject *process_pool_fetch_object(zval *zobject) {
    return process_pool_fetch_object(Z_OBJ_P(zobject));
}

static sw_inline ProcessPool *process_pool_get_pool(zval *zobject) {
    return process_pool_fetch_object(Z_OBJ_P(zobject))->pool;
}

static sw_inline ProcessPool *process_pool_get_and_check_pool(zval *zobject) {
    ProcessPool *pool = process_pool_get_pool(zobject);
    if (UNEXPECTED(!pool)) {
        swoole_fatal_error(SW_ERROR_WRONG_OPERATION, "must call constructor first");
    }
    return pool;
}

static void process_pool_free_object(zend_object *object) {
    ProcessPoolObject *pp = process_pool_fetch_object(object);

    ProcessPool *pool = pp->pool;
    if (pool) {
        efree(pool->ptr);
        pool->destroy();
        efree(pool);
    }

    if (pp->onWorkerStart) {
        sw_callable_free(pp->onWorkerStart);
    }
    if (pp->onMessage) {
        sw_callable_free(pp->onMessage);
    }
    if (pp->onWorkerStop) {
        sw_callable_free(pp->onWorkerStop);
    }
    if (pp->onStart) {
        sw_callable_free(pp->onStart);
    }
    if (pp->onWorkerExit) {
        sw_callable_free(pp->onWorkerExit);
    }
    if (pp->onShutdown) {
        sw_callable_free(pp->onShutdown);
    }

    zend_object_std_dtor(object);
}

static zend_object *process_pool_create_object(zend_class_entry *ce) {
    ProcessPoolObject *pp = (ProcessPoolObject *) zend_object_alloc(sizeof(ProcessPoolObject), ce);
    zend_object_std_init(&pp->std, ce);
    object_properties_init(&pp->std, ce);
    pp->std.handlers = &swoole_process_pool_handlers;
    return &pp->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_process_pool, __construct);
static PHP_METHOD(swoole_process_pool, __destruct);
static PHP_METHOD(swoole_process_pool, set);
static PHP_METHOD(swoole_process_pool, on);
static PHP_METHOD(swoole_process_pool, listen);
static PHP_METHOD(swoole_process_pool, write);
static PHP_METHOD(swoole_process_pool, sendMessage);
static PHP_METHOD(swoole_process_pool, detach);
static PHP_METHOD(swoole_process_pool, getProcess);
static PHP_METHOD(swoole_process_pool, start);
static PHP_METHOD(swoole_process_pool, stop);
static PHP_METHOD(swoole_process_pool, shutdown);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_process_pool_methods[] =
{
    PHP_ME(swoole_process_pool, __construct, arginfo_class_Swoole_Process_Pool___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, __destruct,  arginfo_class_Swoole_Process_Pool___destruct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, set,         arginfo_class_Swoole_Process_Pool_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, on,          arginfo_class_Swoole_Process_Pool_on,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, getProcess,  arginfo_class_Swoole_Process_Pool_getProcess,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, listen,      arginfo_class_Swoole_Process_Pool_listen,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, write,       arginfo_class_Swoole_Process_Pool_write,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, sendMessage, arginfo_class_Swoole_Process_Pool_sendMessage, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, detach,      arginfo_class_Swoole_Process_Pool_detach,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, start,       arginfo_class_Swoole_Process_Pool_start,       ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, stop,        arginfo_class_Swoole_Process_Pool_stop,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, shutdown,    arginfo_class_Swoole_Process_Pool_shutdown,    ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_process_pool_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_process_pool, "Swoole\\Process\\Pool", nullptr, swoole_process_pool_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_process_pool);
    SW_SET_CLASS_CLONEABLE(swoole_process_pool, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process_pool, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(
        swoole_process_pool, process_pool_create_object, process_pool_free_object, ProcessPoolObject, std);

    zend_declare_property_long(swoole_process_pool_ce, ZEND_STRL("master_pid"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_process_pool_ce, ZEND_STRL("workerPid"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_process_pool_ce, ZEND_STRL("workerId"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_pool_ce, ZEND_STRL("workers"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_process_pool_ce, ZEND_STRL("workerRunning"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_process_pool_ce, ZEND_STRL("running"), -1, ZEND_ACC_PUBLIC);
}

static void process_pool_onWorkerStart(ProcessPool *pool, Worker *worker) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolObject *pp = process_pool_fetch_object(zobject);
    php_swoole_process_clean();

    current_pool = pool;
    current_worker = worker;

    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("running"), true);
    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("workerRunning"), true);
    zend_update_property_long(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("workerPid"), getpid());
    zend_update_property_long(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("workerId"), worker->id);

    if (pp->onWorkerStart) {
        zval args[2];
        args[0] = *zobject;
        ZVAL_LONG(&args[1], worker->id);
        if (UNEXPECTED(!zend::function::call(pp->onWorkerStart->ptr(), 2, args, nullptr, pp->enable_coroutine))) {
            php_swoole_error(E_WARNING, "%s->onWorkerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
        }
    }

    if (!swoole_signal_isset(SIGTERM) && (pp->onMessage || pp->enable_coroutine)) {
        swoole_signal_set(SIGTERM, process_pool_signal_handler);
    }
}

static void process_pool_onMessage(ProcessPool *pool, RecvData *msg) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolObject *pp = process_pool_fetch_object(zobject);
    zval args[2];

    args[0] = *zobject;
    const char *data = msg->data;
    uint32_t length = msg->info.len;
    if (length == 0) {
        ZVAL_EMPTY_STRING(&args[1]);
    } else {
        if (msg->info.flags & SW_EVENT_DATA_OBJ_PTR) {
            zend::assign_zend_string_by_val(&args[1], (char *) data, length);
            pool->message_bus->move_packet();
        } else {
            ZVAL_STRINGL(&args[1], data, length);
        }
    }
    auto *worker = sw_worker();
    worker->set_status_to_busy();
    if (UNEXPECTED(!zend::function::call(pp->onMessage->ptr(), 2, args, nullptr, pp->enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    worker->add_request_count();
    worker->set_status_to_idle();
    zval_ptr_dtor(&args[1]);
}

static void process_pool_onWorkerStop(ProcessPool *pool, Worker *worker) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolObject *pp = process_pool_fetch_object(zobject);
    zval args[2];

    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("running"), false);
    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("workerRunning"), false);

    if (pp->onWorkerStop == nullptr) {
        return;
    }

    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker->id);

    if (UNEXPECTED(!zend::function::call(pp->onWorkerStop->ptr(), 2, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onWorkerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
}

static void process_pool_onWorkerExit(ProcessPool *pool, Worker *worker) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolObject *pp = process_pool_fetch_object(zobject);
    zval args[2];

    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("running"), false);
    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("workerRunning"), false);

    if (pp->onWorkerExit == nullptr) {
        return;
    }

    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker->id);

    if (UNEXPECTED(!zend::function::call(pp->onWorkerExit->ptr(), 2, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onWorkerExit handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
}

static void process_pool_onStart(ProcessPool *pool) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolObject *pp = process_pool_fetch_object(zobject);
    zval args[1];

    zend_update_property_long(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("master_pid"), getpid());
    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("running"), true);

    if (pp->onStart == nullptr) {
        return;
    }

    args[0] = *zobject;
    if (UNEXPECTED(!zend::function::call(pp->onStart->ptr(), 1, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onStart handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
}

static void process_pool_onShutdown(ProcessPool *pool) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolObject *pp = process_pool_fetch_object(zobject);
    zval args[1];

    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("running"), false);
    zend_update_property_bool(swoole_process_pool_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("workerRunning"), false);

    if (pp->onShutdown == nullptr) {
        return;
    }

    args[0] = *zobject;

    if (UNEXPECTED(!zend::function::call(pp->onShutdown->ptr(), 1, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onShutdown handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
}

static void process_pool_signal_handler(int sig) {
    if (!current_pool) {
        return;
    }
    switch (sig) {
    case SIGTERM:
        current_pool->running = false;
        if (current_worker) {
            current_pool->stop(current_worker);
        }
        break;
    case SIGUSR1:
    case SIGUSR2:
        current_pool->reload();
        current_pool->reload_init = false;
        break;
    case SIGIO:
        current_pool->read_message = true;
        break;
    default:
        break;
    }
}

static PHP_METHOD(swoole_process_pool, __construct) {
    zval *zobject = ZEND_THIS;
    zend_long worker_num;
    zend_long ipc_type = SW_IPC_NONE;
    zend_long msgq_key = 0;
    zend_bool enable_coroutine = 0;

    // only cli env
    if (!SWOOLE_G(cli)) {
        zend_throw_error(NULL, "%s can only be used in PHP CLI mode", SW_Z_OBJCE_NAME_VAL_P(zobject));
        RETURN_FALSE;
    }

    if (sw_server()) {
        zend_throw_error(NULL, "%s cannot use in server process", SW_Z_OBJCE_NAME_VAL_P(zobject));
        RETURN_FALSE;
    }

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l|llb", &worker_num, &ipc_type, &msgq_key, &enable_coroutine) ==
        FAILURE) {
        RETURN_FALSE;
    }

    if (worker_num <= 0) {
        zend_throw_exception_ex(swoole_exception_ce, errno, "the parameter $worker_num must be greater than 0");
        RETURN_FALSE;
    }

    if (enable_coroutine && ipc_type > 0 && ipc_type != SW_IPC_UNIXSOCK) {
        ipc_type = SW_IPC_UNIXSOCK;
        zend_throw_error(NULL, "the parameter $ipc_type must be SWOOLE_IPC_UNIXSOCK when enable coroutine");
        RETURN_FALSE;
    }

    ProcessPool *pool = (ProcessPool *) emalloc(sizeof(*pool));
    *pool = {};
    if (pool->create(worker_num, (key_t) msgq_key, (swIPCMode) ipc_type) < 0) {
        zend_throw_exception_ex(swoole_exception_ce, errno, "failed to create process pool");
        efree(pool);
        RETURN_FALSE;
    }

    pool->ptr = sw_zval_dup(zobject);
    pool->async = enable_coroutine;

    ProcessPoolObject *pp = process_pool_fetch_object(ZEND_THIS);

    pp->enable_coroutine = enable_coroutine;
    pp->pool = pool;
}

static PHP_METHOD(swoole_process_pool, set) {
    zval *zset = nullptr;
    HashTable *vht = nullptr;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    ProcessPoolObject *pp = process_pool_fetch_object(ZEND_THIS);
    ProcessPool *pool = process_pool_get_and_check_pool(ZEND_THIS);

    php_swoole_set_global_option(vht);
    php_swoole_set_coroutine_option(vht);
    php_swoole_set_aio_option(vht);

    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp)) {
        pool->async = pp->enable_coroutine = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "enable_message_bus", ztmp)) {
        pp->enable_message_bus = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "max_package_size", ztmp)) {
        pool->set_max_packet_size(php_swoole_parse_to_size(ztmp));
    }
}

static PHP_METHOD(swoole_process_pool, on) {
    char *name;
    size_t l_name;
    zval *zfn;

    ProcessPool *pool = process_pool_get_and_check_pool(ZEND_THIS);

    if (pool->started) {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to register event callback function");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(name, l_name)
    Z_PARAM_ZVAL(zfn);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ProcessPoolObject *pp = process_pool_fetch_object(ZEND_THIS);

    if (SW_STRCASEEQ(name, l_name, "WorkerStart")) {
        if (pp->onWorkerStart) {
            sw_callable_free(pp->onWorkerStart);
        }
        pp->onWorkerStart = sw_callable_create(zfn);
    } else if (SW_STRCASEEQ(name, l_name, "Message")) {
        if (pool->ipc_mode == SW_IPC_NONE) {
            zend_throw_exception(
                swoole_exception_ce, "cannot set `onMessage` event with ipc_type=0", SW_ERROR_INVALID_PARAMS);
            RETURN_FALSE;
        }
        if (pp->onMessage) {
            sw_callable_free(pp->onMessage);
        }
        pp->onMessage = sw_callable_create(zfn);
    } else if (SW_STRCASEEQ(name, l_name, "WorkerStop")) {
        if (pp->onWorkerStop) {
            sw_callable_free(pp->onWorkerStop);
        }
        pp->onWorkerStop = sw_callable_create(zfn);
    } else if (SW_STRCASEEQ(name, l_name, "WorkerExit")) {
        if (pp->onWorkerExit) {
            sw_callable_free(pp->onWorkerExit);
        }
        pp->onWorkerExit = sw_callable_create(zfn);
    } else if (SW_STRCASEEQ(name, l_name, "Start")) {
        if (pp->onStart) {
            sw_callable_free(pp->onStart);
        }
        pp->onStart = sw_callable_create(zfn);
    } else if (SW_STRCASEEQ(name, l_name, "Shutdown")) {
        if (pp->onShutdown) {
            sw_callable_free(pp->onShutdown);
        }
        pp->onShutdown = sw_callable_create(zfn);
    } else {
        php_swoole_error(E_WARNING, "unknown event type[%s]", name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process_pool, listen) {
    char *host;
    size_t l_host;
    zend_long port = 0;
    zend_long backlog = 2048;

    ProcessPool *pool = process_pool_get_and_check_pool(ZEND_THIS);

    if (pool->started) {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to listen");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &host, &l_host, &port, &backlog) == FAILURE) {
        RETURN_FALSE;
    }

    if (pool->ipc_mode != SW_IPC_SOCKET) {
        php_swoole_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
        RETURN_FALSE;
    }

    int ret;
    // unix socket
    if (SW_STR_ISTARTS_WITH(host, l_host, "unix:/")) {
        ret = pool->listen(host + 5, backlog);
    } else {
        ret = pool->listen(host, port, backlog);
    }
    pool->stream_info_->socket->set_fd_option(0, 1);

    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_process_pool, write) {
    char *data;
    size_t length;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(data, length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ProcessPool *pool = process_pool_get_and_check_pool(ZEND_THIS);
    if (pool->ipc_mode != SW_IPC_SOCKET) {
        php_swoole_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
        RETURN_FALSE;
    }
    if (length == 0) {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(pool->response(data, length));
}

static PHP_METHOD(swoole_process_pool, sendMessage) {
    ProcessPool *pool = process_pool_get_and_check_pool(ZEND_THIS);
    if (!pool->started) {
        php_swoole_fatal_error(E_WARNING, "process pool is not started.");
        RETURN_FALSE;
    }
    if (pool->ipc_mode != SW_IPC_UNIXSOCK) {
        php_swoole_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
        RETURN_FALSE;
    }

    char *message;
    size_t l_message;
    zend_long worker_id;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(message, l_message)
    Z_PARAM_LONG(worker_id)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Worker *worker = pool->get_worker(worker_id);
    if (pool->message_bus) {
        SendData _task{};
        _task.info.reactor_id = current_worker ? current_worker->pid : -1;
        _task.info.len = l_message;
        _task.data = message;
        RETURN_BOOL(pool->message_bus->write(worker->pipe_master, &_task));
    } else {
        RETURN_BOOL(worker->pipe_master->send_async(message, l_message));
    }
}

static PHP_METHOD(swoole_process_pool, start) {
    ProcessPool *pool = process_pool_get_and_check_pool(ZEND_THIS);
    if (pool->started) {
        php_swoole_fatal_error(E_WARNING, "process pool is started");
        RETURN_FALSE;
    }

    ProcessPoolObject *pp = process_pool_fetch_object(ZEND_THIS);
    std::unordered_map<int, swSignalHandler> ori_handlers;

    // The reactor must be cleaned up before registering signal
    swoole_event_free();
    ori_handlers[SIGTERM] = swoole_signal_set(SIGTERM, process_pool_signal_handler);
    ori_handlers[SIGUSR1] = swoole_signal_set(SIGUSR1, process_pool_signal_handler);
    ori_handlers[SIGUSR2] = swoole_signal_set(SIGUSR2, process_pool_signal_handler);
    ori_handlers[SIGIO] = swoole_signal_set(SIGIO, process_pool_signal_handler);

    if (pp->enable_message_bus) {
        if (pool->create_message_bus() != SW_OK) {
            RETURN_FALSE;
        }
        pool->message_bus->set_allocator(sw_zend_string_allocator());
        pool->set_protocol(SW_PROTOCOL_MESSAGE);
    } else {
        pool->set_protocol(SW_PROTOCOL_STREAM);
    }

    if (pp->onWorkerStart == nullptr && pp->onMessage == nullptr) {
        if (pool->async) {
            php_swoole_fatal_error(E_ERROR, "require 'onWorkerStart' callback");
            RETURN_FALSE;
        } else if (pool->ipc_mode != SW_IPC_NONE && pp->onMessage == nullptr) {
            php_swoole_fatal_error(E_ERROR, "require 'onMessage' callback");
            RETURN_FALSE;
        }
    }

    if (pp->onWorkerExit && !pp->enable_coroutine) {
        zend_throw_exception(
            swoole_exception_ce, "cannot set `onWorkerExit` without enable_coroutine", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    if (pp->onMessage) {
        pool->onMessage = process_pool_onMessage;
    } else {
        pool->main_loop = nullptr;
    }

    current_pool = pool;

    pool->onStart = process_pool_onStart;
    pool->onShutdown = process_pool_onShutdown;
    pool->onWorkerStart = process_pool_onWorkerStart;
    pool->onWorkerStop = process_pool_onWorkerStop;

    if (pp->enable_coroutine && pp->onWorkerExit) {
        pool->onWorkerExit = process_pool_onWorkerExit;
    }

    if (pool->start() < 0) {
        RETURN_FALSE;
    }

    pool->wait();
    pool->shutdown();

    current_pool = nullptr;

    for (auto iter = ori_handlers.begin(); iter != ori_handlers.end(); iter++) {
        swoole_signal_set(iter->first, iter->second);
    }
}

static PHP_METHOD(swoole_process_pool, detach) {
    if (current_pool == nullptr) {
        RETURN_FALSE;
    }
    RETURN_BOOL(current_pool->detach());
}

static PHP_METHOD(swoole_process_pool, getProcess) {
    long worker_id = -1;

    if (current_pool == nullptr) {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &worker_id) == FAILURE) {
        RETURN_FALSE;
    }

    if (worker_id >= current_pool->worker_num) {
        php_swoole_error(E_WARNING, "invalid worker_id[%ld]", worker_id);
        RETURN_FALSE;
    } else if (worker_id < 0) {
        worker_id = swoole_get_process_id();
    }

    zval *zworkers =
        sw_zend_read_and_convert_property_array(swoole_process_pool_ce, ZEND_THIS, ZEND_STRL("workers"), 0);
    zval *zprocess = zend_hash_index_find(Z_ARRVAL_P(zworkers), worker_id);
    zval zobject;

    if (zprocess == nullptr || ZVAL_IS_NULL(zprocess)) {
        zprocess = &zobject;
        /**
         * Separation from shared memory
         */
        Worker *worker = (Worker *) emalloc(sizeof(Worker));
        *worker = current_pool->workers[worker_id];

        object_init_ex(zprocess, swoole_process_ce);
        zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(zprocess), ZEND_STRL("id"), swoole_get_process_id());
        zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(zprocess), ZEND_STRL("pid"), worker->pid);
        if (current_pool->ipc_mode == SW_IPC_UNIXSOCK) {
            // current process
            if (worker->id == swoole_get_process_id()) {
                worker->pipe_current = worker->pipe_worker;
            } else {
                worker->pipe_current = worker->pipe_master;
            }
            /**
             * Forbidden to close pipe in the php layer
             */
            worker->pipe_object = nullptr;
            zend_update_property_long(
                swoole_process_ce, SW_Z8_OBJ_P(zprocess), ZEND_STRL("pipe"), worker->pipe_current->fd);
        }
        /**
         * The message bus is enabled and forbid to read/write/close the pipeline in the php layer
         */
        if (current_pool->message_bus) {
            worker->pipe_current = nullptr;
            worker->pipe_object = nullptr;
        }
        /**
         * The onMessage callback is not set, use getProcess()->push()/pop() to operate msgqueue
         */
        if (current_pool->ipc_mode == SW_IPC_MSGQUEUE && current_pool->onMessage == nullptr) {
            worker->queue = current_pool->queue;
            worker->msgqueue_mode = SW_MSGQUEUE_BALANCE;
        }
        php_swoole_process_set_worker(zprocess, worker);
        zend::Process *proc = new zend::Process(zend::PIPE_TYPE_STREAM, current_pool->async);
        worker->ptr2 = proc;
        (void) add_index_zval(zworkers, worker_id, zprocess);
    } else {
        auto _worker = php_swoole_process_get_worker(zprocess);
        if (_worker->pid != current_pool->workers[worker_id].pid) {
            _worker->pid = current_pool->workers[worker_id].pid;
            zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(zprocess), ZEND_STRL("pid"), _worker->pid);
        }
    }

    RETURN_ZVAL(zprocess, 1, 0);
}

static PHP_METHOD(swoole_process_pool, stop) {
    if (current_pool) {
        current_pool->running = false;
        if (current_worker) {
            current_pool->stop(current_worker);
        }
    }
}

static PHP_METHOD(swoole_process_pool, shutdown) {
    long pid = zend::object_get_long(ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_MASTER_PID));
    if (pid > 0) {
        RETURN_BOOL(swoole_kill(pid, SIGTERM) == 0);
    } else {
        zend_throw_exception(swoole_exception_ce, "invalid master pid", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process_pool, __destruct) {}
