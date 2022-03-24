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

using namespace swoole;

struct ProcessPoolProperty {
    zend_fcall_info_cache *onStart;
    zend_fcall_info_cache *onWorkerStart;
    zend_fcall_info_cache *onWorkerStop;
    zend_fcall_info_cache *onMessage;
    bool enable_coroutine;
};

static zend_class_entry *swoole_process_pool_ce;
static zend_object_handlers swoole_process_pool_handlers;
static ProcessPool *current_pool;

struct ProcessPoolObject {
    ProcessPool *pool;
    ProcessPoolProperty *pp;
    zend_object std;
};

static void pool_signal_handler(int sig);

static sw_inline ProcessPoolObject *php_swoole_process_pool_fetch_object(zend_object *obj) {
    return (ProcessPoolObject *) ((char *) obj - swoole_process_pool_handlers.offset);
}

static sw_inline ProcessPool *php_swoole_process_pool_get_pool(zval *zobject) {
    return php_swoole_process_pool_fetch_object(Z_OBJ_P(zobject))->pool;
}

static sw_inline ProcessPool *php_swoole_process_pool_get_and_check_pool(zval *zobject) {
    ProcessPool *pool = php_swoole_process_pool_get_pool(zobject);
    if (!pool) {
        php_swoole_fatal_error(E_ERROR, "you must call Process\\Pool constructor first");
    }
    return pool;
}

static sw_inline void php_swoole_process_pool_set_pool(zval *zobject, ProcessPool *pool) {
    php_swoole_process_pool_fetch_object(Z_OBJ_P(zobject))->pool = pool;
}

static sw_inline ProcessPoolProperty *php_swoole_process_pool_get_pp(zval *zobject) {
    return php_swoole_process_pool_fetch_object(Z_OBJ_P(zobject))->pp;
}

static sw_inline ProcessPoolProperty *php_swoole_process_pool_get_and_check_pp(zval *zobject) {
    ProcessPoolProperty *pp = php_swoole_process_pool_get_pp(zobject);
    if (!pp) {
        php_swoole_fatal_error(E_ERROR, "you must call Process\\Pool constructor first");
    }
    return pp;
}

static sw_inline void php_swoole_process_pool_set_pp(zval *zobject, ProcessPoolProperty *pp) {
    php_swoole_process_pool_fetch_object(Z_OBJ_P(zobject))->pp = pp;
}

static void php_swoole_process_pool_free_object(zend_object *object) {
    ProcessPoolObject *process_pool = php_swoole_process_pool_fetch_object(object);

    ProcessPool *pool = process_pool->pool;
    if (pool) {
        efree(pool->ptr);
        pool->destroy();
        efree(pool);
    }

    ProcessPoolProperty *pp = process_pool->pp;
    if (pp) {
        if (pp->onWorkerStart) {
            sw_zend_fci_cache_discard(pp->onWorkerStart);
            efree(pp->onWorkerStart);
        }
        if (pp->onMessage) {
            sw_zend_fci_cache_discard(pp->onMessage);
            efree(pp->onMessage);
        }
        if (pp->onWorkerStop) {
            sw_zend_fci_cache_discard(pp->onWorkerStop);
            efree(pp->onWorkerStop);
        }
        if (pp->onStart) {
            sw_zend_fci_cache_discard(pp->onStart);
            efree(pp->onStart);
        }
        efree(pp);
    }

    zend_object_std_dtor(object);
}

static zend_object *php_swoole_process_pool_create_object(zend_class_entry *ce) {
    ProcessPoolObject *process_pool = (ProcessPoolObject *) zend_object_alloc(sizeof(ProcessPoolObject), ce);
    zend_object_std_init(&process_pool->std, ce);
    object_properties_init(&process_pool->std, ce);
    process_pool->std.handlers = &swoole_process_pool_handlers;
    return &process_pool->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_process_pool, __construct);
static PHP_METHOD(swoole_process_pool, __destruct);
static PHP_METHOD(swoole_process_pool, set);
static PHP_METHOD(swoole_process_pool, on);
static PHP_METHOD(swoole_process_pool, listen);
static PHP_METHOD(swoole_process_pool, write);
static PHP_METHOD(swoole_process_pool, detach);
static PHP_METHOD(swoole_process_pool, getProcess);
static PHP_METHOD(swoole_process_pool, start);
static PHP_METHOD(swoole_process_pool, stop);
static PHP_METHOD(swoole_process_pool, shutdown);
SW_EXTERN_C_END

// clang-format off

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, worker_num)
    ZEND_ARG_INFO(0, ipc_type)
    ZEND_ARG_INFO(0, msgqueue_key)
    ZEND_ARG_INFO(0, enable_coroutine)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_getProcess, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_listen, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, backlog)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_write, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_process_pool_methods[] =
{
    PHP_ME(swoole_process_pool, __construct, arginfo_swoole_process_pool_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, __destruct, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, set, arginfo_swoole_process_pool_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, on, arginfo_swoole_process_pool_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, getProcess, arginfo_swoole_process_pool_getProcess, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, listen, arginfo_swoole_process_pool_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, write, arginfo_swoole_process_pool_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, detach, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, start, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, stop, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, shutdown, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_process_pool_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(
        swoole_process_pool, "Swoole\\Process\\Pool", "swoole_process_pool", nullptr, swoole_process_pool_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_process_pool);
    SW_SET_CLASS_CLONEABLE(swoole_process_pool, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process_pool, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_process_pool,
                               php_swoole_process_pool_create_object,
                               php_swoole_process_pool_free_object,
                               ProcessPoolObject,
                               std);

    zend_declare_property_long(swoole_process_pool_ce, ZEND_STRL("master_pid"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_pool_ce, ZEND_STRL("workers"), ZEND_ACC_PUBLIC);
}

static void pool_onWorkerStart(ProcessPool *pool, int worker_id) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(zobject);

    php_swoole_process_clean();
    SwooleG.process_id = worker_id;
    current_pool = pool;
    // main function
    if (!pp->onWorkerStart) {
        return;
    }
    // eventloop create
    if (pp->enable_coroutine && php_swoole_reactor_init() < 0) {
        return;
    }
    if (!pp->enable_coroutine && pp->onMessage) {
        swoole_signal_set(SIGTERM, pool_signal_handler);
    }
    zval args[2];
    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);
    if (UNEXPECTED(!zend::function::call(pp->onWorkerStart, 2, args, nullptr, pp->enable_coroutine))) {
        php_swoole_error(E_WARNING, "%s->onWorkerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    // eventloop start
    if (pp->enable_coroutine) {
        php_swoole_event_wait();
    }
}

static void pool_onMessage(ProcessPool *pool, const char *data, uint32_t length) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(zobject);
    zval args[2];

    args[0] = *zobject;
    ZVAL_STRINGL(&args[1], data, length);

    if (UNEXPECTED(!zend::function::call(pp->onMessage, 2, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }

    zval_ptr_dtor(&args[1]);
}

static void pool_onWorkerStop(ProcessPool *pool, int worker_id) {
    zval *zobject = (zval *) pool->ptr;
    ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(zobject);
    zval args[2];

    if (pp->onWorkerStop == nullptr) {
        return;
    }

    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);

    if (UNEXPECTED(!zend::function::call(pp->onWorkerStop, 2, args, nullptr, false))) {
        php_swoole_error(E_WARNING, "%s->onWorkerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
}

static void pool_signal_handler(int sig) {
    if (!current_pool) {
        return;
    }
    switch (sig) {
    case SIGTERM:
        current_pool->running = false;
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
        php_swoole_fatal_error(E_ERROR, "%s can only be used in PHP CLI mode", SW_Z_OBJCE_NAME_VAL_P(zobject));
        RETURN_FALSE;
    }

    if (sw_server()) {
        php_swoole_fatal_error(E_ERROR, "%s cannot use in server process", SW_Z_OBJCE_NAME_VAL_P(zobject));
        RETURN_FALSE;
    }

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l|llb", &worker_num, &ipc_type, &msgq_key, &enable_coroutine) ==
        FAILURE) {
        RETURN_FALSE;
    }

    if (worker_num <= 0) {
        zend_throw_exception_ex(swoole_exception_ce, errno, "invalid worker_num");
        RETURN_FALSE;
    }

    if (enable_coroutine && ipc_type > 0 && ipc_type != SW_IPC_UNIXSOCK) {
        ipc_type = SW_IPC_UNIXSOCK;
        php_swoole_fatal_error(E_NOTICE,
                               "%s object's ipc_type will be reset to SWOOLE_IPC_UNIXSOCK after enable coroutine",
                               SW_Z_OBJCE_NAME_VAL_P(zobject));
    }

    ProcessPool *pool = (ProcessPool *) emalloc(sizeof(*pool));
    *pool = {};
    if (pool->create(worker_num, (key_t) msgq_key, (swIPCMode) ipc_type) < 0) {
        zend_throw_exception_ex(swoole_exception_ce, errno, "failed to create process pool");
        efree(pool);
        RETURN_FALSE;
    }

    pool->ptr = sw_zval_dup(zobject);

    if (enable_coroutine) {
        pool->main_loop = nullptr;
    } else {
        if (ipc_type > 0) {
            pool->set_protocol(0, SW_INPUT_BUFFER_SIZE);
        }
    }

    ProcessPoolProperty *pp = (ProcessPoolProperty *) ecalloc(1, sizeof(ProcessPoolProperty));
    pp->enable_coroutine = enable_coroutine;
    php_swoole_process_pool_set_pp(zobject, pp);
    php_swoole_process_pool_set_pool(zobject, pool);
}

static PHP_METHOD(swoole_process_pool, set) {
    zval *zset = nullptr;
    HashTable *vht = nullptr;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(ZEND_THIS);

    php_swoole_set_global_option(vht);
    php_swoole_set_coroutine_option(vht);
    php_swoole_set_aio_option(vht);

    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp)) {
        pp->enable_coroutine = zval_is_true(ztmp);
    }

    ProcessPool *pool = php_swoole_process_pool_get_and_check_pool(ZEND_THIS);
    if (pp->enable_coroutine) {
        pool->main_loop = nullptr;
    }
}

static PHP_METHOD(swoole_process_pool, on) {
    char *name;
    size_t l_name;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    ProcessPool *pool = php_swoole_process_pool_get_and_check_pool(ZEND_THIS);

    if (pool->started) {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to register event callback function");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(name, l_name)
    Z_PARAM_FUNC(fci, fci_cache);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(ZEND_THIS);

    if (SW_STRCASEEQ(name, l_name, "WorkerStart")) {
        if (pp->onWorkerStart) {
            sw_zend_fci_cache_discard(pp->onWorkerStart);
            efree(pp->onWorkerStart);
        } else {
            pp->onWorkerStart = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onWorkerStart = fci_cache;
        sw_zend_fci_cache_persist(pp->onWorkerStart);
        RETURN_TRUE;
    } else if (SW_STRCASEEQ(name, l_name, "Message")) {
        if (pp->enable_coroutine) {
            php_swoole_fatal_error(E_NOTICE, "cannot set onMessage event with enable_coroutine");
            RETURN_FALSE;
        }
        if (pool->ipc_mode == SW_IPC_NONE) {
            php_swoole_fatal_error(E_WARNING, "cannot set onMessage event with ipc_type=0");
            RETURN_FALSE;
        }
        if (pp->onMessage) {
            sw_zend_fci_cache_discard(pp->onMessage);
            efree(pp->onMessage);
        } else {
            pp->onMessage = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onMessage = fci_cache;
        sw_zend_fci_cache_persist(pp->onMessage);
        RETURN_TRUE;
    } else if (SW_STRCASEEQ(name, l_name, "WorkerStop")) {
        if (pp->onWorkerStop) {
            sw_zend_fci_cache_discard(pp->onWorkerStop);
            efree(pp->onWorkerStop);
        } else {
            pp->onWorkerStop = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onWorkerStop = fci_cache;
        sw_zend_fci_cache_persist(pp->onWorkerStop);
        RETURN_TRUE;
    } else if (SW_STRCASEEQ(name, l_name, "Start")) {
        if (pp->onStart) {
            sw_zend_fci_cache_discard(pp->onStart);
            efree(pp->onStart);
        } else {
            pp->onStart = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onStart = fci_cache;
        sw_zend_fci_cache_persist(pp->onStart);
        RETURN_TRUE;
    } else {
        php_swoole_error(E_WARNING, "unknown event type[%s]", name);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process_pool, listen) {
    char *host;
    size_t l_host;
    zend_long port = 0;
    zend_long backlog = 2048;

    ProcessPool *pool = php_swoole_process_pool_get_and_check_pool(ZEND_THIS);

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
    if (SW_STRCASECT(host, l_host, "unix:/")) {
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

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &data, &length) == FAILURE) {
        RETURN_FALSE;
    }

    ProcessPool *pool = php_swoole_process_pool_get_and_check_pool(ZEND_THIS);
    if (pool->ipc_mode != SW_IPC_SOCKET) {
        php_swoole_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
        RETURN_FALSE;
    }
    if (length == 0) {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(pool->response(data, length));
}

static PHP_METHOD(swoole_process_pool, start) {
    ProcessPool *pool = php_swoole_process_pool_get_and_check_pool(ZEND_THIS);
    if (pool->started) {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to execute swoole_process_pool->start");
        RETURN_FALSE;
    }

    swoole_event_free();

    ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(ZEND_THIS);

    SwooleG.use_signalfd = 0;

    std::unordered_map<int, swSignalHandler> ori_handlers;

    ori_handlers[SIGTERM] = swoole_signal_set(SIGTERM, pool_signal_handler);
    ori_handlers[SIGUSR1] = swoole_signal_set(SIGUSR1, pool_signal_handler);
    ori_handlers[SIGUSR2] = swoole_signal_set(SIGUSR2, pool_signal_handler);
    ori_handlers[SIGIO] = swoole_signal_set(SIGIO, pool_signal_handler);

    if (pool->ipc_mode == SW_IPC_NONE || pp->enable_coroutine) {
        if (pp->onWorkerStart == nullptr) {
            php_swoole_fatal_error(E_ERROR, "require onWorkerStart callback");
            RETURN_FALSE;
        }
    } else {
        if (pp->onMessage == nullptr) {
            php_swoole_fatal_error(E_ERROR, "require onMessage callback");
            RETURN_FALSE;
        }
        pool->onMessage = pool_onMessage;
    }

    pool->onWorkerStart = pool_onWorkerStart;
    pool->onWorkerStop = pool_onWorkerStop;

    zend_update_property_long(swoole_process_pool_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("master_pid"), getpid());

    if (pool->start() < 0) {
        RETURN_FALSE;
    }

    current_pool = pool;

    if (pp->onStart) {
        zval args[1];
        args[0] = *ZEND_THIS;
        if (UNEXPECTED(!zend::function::call(pp->onStart, 1, args, nullptr, 0))) {
            php_swoole_error(E_WARNING, "%s->onStart handler error", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        }
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
        worker_id = SwooleG.process_id;
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
        zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(zprocess), ZEND_STRL("id"), SwooleG.process_id);
        zend_update_property_long(swoole_process_ce, SW_Z8_OBJ_P(zprocess), ZEND_STRL("pid"), worker->pid);
        if (current_pool->ipc_mode == SW_IPC_UNIXSOCK) {
            // current process
            if (worker->id == SwooleG.process_id) {
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
        php_swoole_process_set_worker(zprocess, worker);
        ProcessPoolProperty *pp = php_swoole_process_pool_get_and_check_pp(ZEND_THIS);
        zend::Process *proc = new zend::Process(zend::PIPE_TYPE_STREAM, pp->enable_coroutine);
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
    }
}

static PHP_METHOD(swoole_process_pool, shutdown) {
    zval *retval =
        sw_zend_read_property_ex(swoole_process_pool_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_MASTER_PID), 0);
    long pid = zval_get_long(retval);
    RETURN_BOOL(swoole_kill(pid, SIGTERM) == 0);
}

static PHP_METHOD(swoole_process_pool, __destruct) {}
