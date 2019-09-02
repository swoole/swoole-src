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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"

using namespace swoole;

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

static PHP_METHOD(swoole_process_pool, __construct);
static PHP_METHOD(swoole_process_pool, __destruct);
static PHP_METHOD(swoole_process_pool, set);
static PHP_METHOD(swoole_process_pool, on);
static PHP_METHOD(swoole_process_pool, listen);
static PHP_METHOD(swoole_process_pool, write);
static PHP_METHOD(swoole_process_pool, getProcess);
static PHP_METHOD(swoole_process_pool, start);
static PHP_METHOD(swoole_process_pool, shutdown);

static const zend_function_entry swoole_process_pool_methods[] =
{
    PHP_ME(swoole_process_pool, __construct, arginfo_swoole_process_pool_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, __destruct, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, set, arginfo_swoole_process_pool_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, on, arginfo_swoole_process_pool_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, getProcess, arginfo_swoole_process_pool_getProcess, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, listen, arginfo_swoole_process_pool_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, write, arginfo_swoole_process_pool_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, start, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, shutdown, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

typedef struct
{
    zend_fcall_info_cache *onStart;
    zend_fcall_info_cache *onWorkerStart;
    zend_fcall_info_cache *onWorkerStop;
    zend_fcall_info_cache *onMessage;
    bool enable_coroutine;
} process_pool_property;

static zend_class_entry *swoole_process_pool_ce;
static zend_object_handlers swoole_process_pool_handlers;
static swProcessPool *current_pool;

void php_swoole_process_pool_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_process_pool, "Swoole\\Process\\Pool", "swoole_process_pool", NULL, swoole_process_pool_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_process_pool, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_process_pool, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process_pool, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_process_pool);

    zend_declare_property_long(swoole_process_pool_ce, ZEND_STRL("master_pid"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_pool_ce, ZEND_STRL("workers"), ZEND_ACC_PUBLIC);
}

static void pool_onWorkerStart(swProcessPool *pool, int worker_id)
{
    zval *zobject = (zval *) pool->ptr;

    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);
    if (pp->onWorkerStart == NULL)
    {
        return;
    }

    php_swoole_process_clean();
    SwooleWG.id = worker_id;
    current_pool = pool;

    zval args[2];
    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);

    //eventloop create
    if (pp->enable_coroutine && php_swoole_reactor_init() < 0)
    {
        return;
    }
    //main function
    if (UNEXPECTED(!zend::function::call(pp->onWorkerStart, 2, args, NULL, pp->enable_coroutine)))
    {
        php_swoole_error(E_WARNING, "%s->onWorkerStart handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    //eventloop start
    if (pp->enable_coroutine)
    {
        php_swoole_event_wait();
    }
}

static void pool_onMessage(swProcessPool *pool, char *data, uint32_t length)
{
    zval *zobject = (zval *) pool->ptr;
    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);
    zval args[2];

    args[0] = *zobject;
    ZVAL_STRINGL(&args[1], data, length);

    if (UNEXPECTED(!zend::function::call(pp->onMessage, 2, args, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onMessage handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }

    zval_ptr_dtor(&args[1]);
}

static void pool_onWorkerStop(swProcessPool *pool, int worker_id)
{
    zval *zobject = (zval *) pool->ptr;
    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);
    zval args[2];

    if (pp->onWorkerStop == NULL)
    {
        return;
    }

    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);

    if (UNEXPECTED(!zend::function::call(pp->onWorkerStop, 2, args, NULL, false)))
    {
        php_swoole_error(E_WARNING, "%s->onWorkerStop handler error", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
}

static void pool_signal_handler(int sig)
{
    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
    case SIGUSR1:
    case SIGUSR2:
        current_pool->reloading = 1;
        current_pool->reload_init = 0;
        break;
    default:
        break;
    }
}

static PHP_METHOD(swoole_process_pool, __construct)
{
    zval *zobject = ZEND_THIS;
    zend_long worker_num;
    zend_long ipc_type = SW_IPC_NONE;
    zend_long msgq_key = 0;
    zend_bool enable_coroutine = 0;

    //only cli env
    if (!SWOOLE_G(cli))
    {
        php_swoole_fatal_error(E_ERROR, "%s can only be used in PHP CLI mode", SW_Z_OBJCE_NAME_VAL_P(zobject));
        RETURN_FALSE;
    }

    if (SwooleG.serv)
    {
        php_swoole_fatal_error(E_ERROR, "%s cannot use in server process", SW_Z_OBJCE_NAME_VAL_P(zobject));
        RETURN_FALSE;
    }

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l|llb", &worker_num, &ipc_type, &msgq_key, &enable_coroutine) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_num <= 0)
    {
        zend_throw_exception_ex(swoole_exception_ce, errno, "invalid worker_num");
        RETURN_FALSE;
    }

    if (enable_coroutine && ipc_type > 0 && ipc_type != SW_IPC_UNIXSOCK)
    {
        ipc_type = SW_IPC_UNIXSOCK;
        php_swoole_fatal_error(
            E_NOTICE, "%s object's ipc_type will be reset to SWOOLE_IPC_UNIXSOCK after enable coroutine",
            SW_Z_OBJCE_NAME_VAL_P(zobject)
        );
    }

    swProcessPool *pool = (swProcessPool *) emalloc(sizeof(swProcessPool));
    if (swProcessPool_create(pool, worker_num, (key_t) msgq_key, ipc_type) < 0)
    {
        zend_throw_exception_ex(swoole_exception_ce, errno, "failed to create process pool");
        efree(pool);
        RETURN_FALSE;
    }

    pool->ptr = sw_zval_dup(zobject);

    if (enable_coroutine)
    {
        pool->main_loop = nullptr;
    }
    else
    {
        if (ipc_type > 0)
        {
            if (swProcessPool_set_protocol(pool, 0, SW_BUFFER_INPUT_SIZE) < 0)
            {
                zend_throw_exception_ex(swoole_exception_ce, errno, "failed to create process pool");
                RETURN_FALSE;
            }
        }
    }

    process_pool_property *pp = (process_pool_property *) ecalloc(1, sizeof(process_pool_property));
    pp->enable_coroutine = enable_coroutine;
    swoole_set_property(zobject, 0, pp);
    swoole_set_object(zobject, pool);
}

static PHP_METHOD(swoole_process_pool, set)
{
    zval *zset = NULL;
    HashTable *vht = NULL;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(ZEND_THIS, 0);

    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp))
    {
        pp->enable_coroutine = zval_is_true(ztmp);
    }
}

static PHP_METHOD(swoole_process_pool, on)
{
    char *name;
    size_t l_name;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    swProcessPool *pool = (swProcessPool *) swoole_get_object(ZEND_THIS);

    if (pool->started > 0)
    {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to register event callback function");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_STRING(name, l_name)
        Z_PARAM_FUNC(fci, fci_cache);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(ZEND_THIS, 0);

    if (strncasecmp("WorkerStart", name, l_name) == 0)
    {
        if (pp->onWorkerStart)
        {
            sw_zend_fci_cache_discard(pp->onWorkerStart);
            efree(pp->onWorkerStart);
        }
        else
        {
            pp->onWorkerStart = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onWorkerStart = fci_cache;
        sw_zend_fci_cache_persist(pp->onWorkerStart);
        RETURN_TRUE;
    }
    else if (strncasecmp("Message", name, l_name) == 0)
    {
        if (pp->enable_coroutine)
        {
            php_swoole_fatal_error(E_NOTICE, "cannot set onMessage event with enable_coroutine");
            RETURN_FALSE;
        }
        if (pool->ipc_mode == SW_IPC_NONE)
        {
            php_swoole_fatal_error(E_WARNING, "cannot set onMessage event with ipc_type=0");
            RETURN_FALSE;
        }
        if (pp->onMessage)
        {
            sw_zend_fci_cache_discard(pp->onMessage);
            efree(pp->onMessage);
        }
        else
        {
            pp->onMessage = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onMessage = fci_cache;
        sw_zend_fci_cache_persist(pp->onMessage);
        RETURN_TRUE;
    }
    else if (strncasecmp("WorkerStop", name, l_name) == 0)
    {
        if (pp->onWorkerStop)
        {
            sw_zend_fci_cache_discard(pp->onWorkerStop);
            efree(pp->onWorkerStop);
        }
        else
        {
            pp->onWorkerStop = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onWorkerStop = fci_cache;
        sw_zend_fci_cache_persist(pp->onWorkerStop);
        RETURN_TRUE;
    }
    else if (strncasecmp("Start", name, l_name) == 0)
    {
        if (pp->onStart)
        {
            sw_zend_fci_cache_discard(pp->onStart);
            efree(pp->onStart);
        }
        else
        {
            pp->onStart = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onStart = fci_cache;
        sw_zend_fci_cache_persist(pp->onStart);
        RETURN_TRUE;
    }
    else
    {
        php_swoole_error(E_WARNING, "unknown event type[%s]", name);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process_pool, listen)
{
    char *host;
    size_t l_host;
    zend_long port = 0;
    zend_long backlog = 2048;

    swProcessPool *pool = (swProcessPool *) swoole_get_object(ZEND_THIS);

    if (pool->started > 0)
    {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to listen");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &host, &l_host, &port, &backlog) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        php_swoole_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
        RETURN_FALSE;
    }

    SwooleG.reuse_port = 0;
    int ret;
    //unix socket
    if (strncasecmp("unix:/", host, 6) == 0)
    {
        ret = swProcessPool_create_unix_socket(pool, host + 5, backlog);
    }
    else
    {
        ret = swProcessPool_create_tcp_socket(pool, host, port, backlog);
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_process_pool, write)
{
    char *data;
    size_t length;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &data, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    swProcessPool *pool = (swProcessPool *) swoole_get_object(ZEND_THIS);
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        php_swoole_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(swProcessPool_response(pool, data, length));
}

static PHP_METHOD(swoole_process_pool, start)
{
    swProcessPool *pool = (swProcessPool *) swoole_get_object(ZEND_THIS);
    if (pool->started)
    {
        php_swoole_fatal_error(E_WARNING, "process pool is started. unable to execute swoole_process_pool->start");
        RETURN_FALSE;
    }

    if (SwooleTG.reactor)
    {
        swoole_event_free();
    }

    process_pool_property *pp = (process_pool_property *) swoole_get_property(ZEND_THIS, 0);

    SwooleG.use_signalfd = 0;

    swSignal_add(SIGTERM, pool_signal_handler);
    swSignal_add(SIGUSR1, pool_signal_handler);
    swSignal_add(SIGUSR2, pool_signal_handler);

    if (pool->ipc_mode == SW_IPC_NONE || pp->enable_coroutine)
    {
        if (pp->onWorkerStart == NULL)
        {
            php_swoole_fatal_error(E_ERROR, "require onWorkerStart callback");
            RETURN_FALSE;
        }
    }
    else
    {
        if (pp->onMessage == NULL)
        {
            php_swoole_fatal_error(E_ERROR, "require onMessage callback");
            RETURN_FALSE;
        }
        pool->onMessage = pool_onMessage;
    }

    pool->onWorkerStart = pool_onWorkerStart;
    pool->onWorkerStop = pool_onWorkerStop;

    zend_update_property_long(swoole_process_pool_ce, ZEND_THIS, ZEND_STRL("master_pid"), getpid());

    if (swProcessPool_start(pool) < 0)
    {
        RETURN_FALSE;
    }

    current_pool = pool;

    if (pp->onStart)
    {
        zval args[1];
        args[0] = *ZEND_THIS;
        if (UNEXPECTED(!zend::function::call(pp->onStart, 1, args, NULL, 0)))
        {
            php_swoole_error(E_WARNING, "%s->onStart handler error", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        }
    }

    swProcessPool_wait(pool);
    swProcessPool_shutdown(pool);
}

static PHP_METHOD(swoole_process_pool, getProcess)
{
    long worker_id = -1;

    if (current_pool == NULL)
    {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &worker_id) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_id >= current_pool->worker_num)
    {
        php_swoole_error(E_WARNING, "invalid worker_id[%ld]", worker_id);
        RETURN_FALSE;
    }
    else if (worker_id < 0)
    {
        worker_id = SwooleWG.id;
    }

    zval *zworkers = sw_zend_read_and_convert_property_array(swoole_process_pool_ce, ZEND_THIS, ZEND_STRL("workers"), 0);
    zval *zprocess = zend_hash_index_find(Z_ARRVAL_P(zworkers), worker_id);
    zval zobject;

    if (zprocess == nullptr || ZVAL_IS_NULL(zprocess))
    {
        zprocess = &zobject;
        /**
         * Separation from shared memory
         */
        swWorker *worker = (swWorker *) emalloc(sizeof(swWorker));
        *worker = current_pool->workers[worker_id];

        object_init_ex(zprocess, swoole_process_ce);
        zend_update_property_long(swoole_process_ce, zprocess, ZEND_STRL("id"), SwooleWG.id);
        zend_update_property_long(swoole_process_ce, zprocess, ZEND_STRL("pid"), worker->pid);
        if (current_pool->ipc_mode == SW_IPC_UNIXSOCK)
        {
            //current process
            if (worker->id == SwooleWG.id)
            {
                worker->pipe = worker->pipe_worker;
            }
            else
            {
                worker->pipe = worker->pipe_master;
            }
            /**
             * Forbidden to close pipe in the php layer
             */
            worker->pipe_object = nullptr;
            zend_update_property_long(swoole_process_ce, zprocess, ZEND_STRL("pipe"), worker->pipe);
        }
        swoole_set_object(zprocess, worker);
        (void) add_index_zval(zworkers, worker_id, zprocess);
    }

    RETURN_ZVAL(zprocess, 1, 0);
}

static PHP_METHOD(swoole_process_pool, shutdown)
{
    zval *retval = sw_zend_read_property(swoole_process_pool_ce, ZEND_THIS, ZEND_STRL("master_pid"), 0);
    long pid = zval_get_long(retval);
    RETURN_BOOL(swoole_kill(pid, SIGTERM) == 0);
}

static PHP_METHOD(swoole_process_pool, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    swProcessPool *pool = (swProcessPool *) swoole_get_object(ZEND_THIS);
    efree(pool->ptr);
    efree(pool);
    swoole_set_object(ZEND_THIS, NULL);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(ZEND_THIS, 0);
    if (pp->onWorkerStart)
    {
        sw_zend_fci_cache_discard(pp->onWorkerStart);
        efree(pp->onWorkerStart);
    }
    if (pp->onMessage)
    {
        sw_zend_fci_cache_discard(pp->onMessage);
        efree(pp->onMessage);
    }
    if (pp->onWorkerStop)
    {
        sw_zend_fci_cache_discard(pp->onWorkerStop);
        efree(pp->onWorkerStop);
    }
    if (pp->onStart)
    {
        sw_zend_fci_cache_discard(pp->onStart);
        efree(pp->onStart);
    }
    efree(pp);
    swoole_set_property(ZEND_THIS, 0, NULL);
}
