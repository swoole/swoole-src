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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
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
    PHP_ME(swoole_process_pool, on, arginfo_swoole_process_pool_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, getProcess, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, listen, arginfo_swoole_process_pool_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, write, arginfo_swoole_process_pool_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, start, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, shutdown, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

typedef struct
{
    zend_fcall_info_cache *onWorkerStart;
    zend_fcall_info_cache *onWorkerStop;
    zend_fcall_info_cache *onMessage;
    bool enable_coroutine;
} process_pool_property;

static zend_class_entry *swoole_process_pool_ce;
static zend_object_handlers swoole_process_pool_handlers;
static swProcessPool *current_pool;

void swoole_process_pool_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_process_pool, "Swoole\\Process\\Pool", "swoole_process_pool", NULL, swoole_process_pool_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_process_pool, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_process_pool, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process_pool, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_process_pool);

    zend_declare_property_long(swoole_process_pool_ce, ZEND_STRL("master_pid"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_process_pool_ce, ZEND_STRL("workers"), ZEND_ACC_PUBLIC);
}

static void pool_onWorkerStart(swProcessPool *pool, int worker_id)
{
    zval *zobject = (zval *) pool->ptr;
    zval _retval, *retval = &_retval;

    zval args[2];
    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);
    if (pp->onWorkerStart == NULL)
    {
        return;
    }

    php_swoole_process_clean();
    SwooleWG.id = worker_id;
    current_pool = pool;

    if (pp->enable_coroutine)
    {
        if (PHPCoroutine::create(pp->onWorkerStart, 2, args) < 0)
        {
            swoole_php_error(E_WARNING, "create process coroutine error");
        }
    }
    else
    {
        if (sw_call_user_function_fast_ex(NULL, pp->onWorkerStart, retval, 2, args) == FAILURE)
        {
            swoole_php_fatal_error(E_WARNING, "onWorkerStart handler error");
        }
        zval_ptr_dtor(retval);
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (SwooleG.main_reactor)
    {
        php_swoole_event_wait();
        SwooleG.running = 0;
    }
}

static void pool_onMessage(swProcessPool *pool, char *data, uint32_t length)
{
    zval *zobject = (zval *) pool->ptr;
    zval _retval, *retval = &_retval;
    zval args[2];
    args[0] = *zobject;
    ZVAL_STRINGL(&args[1], data, length);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);

    if (sw_call_user_function_fast_ex( NULL, pp->onMessage, retval, 2, args) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onMessage handler error");
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(&args[1]);
    zval_ptr_dtor(retval);
}

static void pool_onWorkerStop(swProcessPool *pool, int worker_id)
{
    zval *zobject = (zval *) pool->ptr;
    zval _retval, *retval = &_retval;

    zval args[2];
    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);
    if (pp->onWorkerStop == NULL)
    {
        return;
    }
    if (sw_call_user_function_fast_ex(NULL, pp->onWorkerStop, retval, 2, args) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStop handler error");
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(retval);
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
    zend_long worker_num;
    zend_long ipc_type = SW_IPC_NONE;
    zend_long msgq_key = 0;
    zend_bool enable_coroutine = 0;

    //only cli env
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "Swoole\\Process\\Pool only can be used in PHP CLI mode");
        RETURN_FALSE;
    }

    if (SwooleG.serv)
    {
        swoole_php_fatal_error(E_ERROR, "Swoole\\Process\\Pool cannot use in server process");
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
        swoole_php_fatal_error(E_NOTICE, "Swoole\\Process\\Pool can only use unixsocket when enable coroutine");
    }

    swProcessPool *pool = (swProcessPool *) emalloc(sizeof(swProcessPool));
    if (swProcessPool_create(pool, worker_num, 0, (key_t) msgq_key, ipc_type) < 0)
    {
        zend_throw_exception_ex(swoole_exception_ce, errno, "failed to create process pool");
        RETURN_FALSE;
    }

    pool->ptr = sw_zval_dup(getThis());

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

    process_pool_property *pp = (process_pool_property *) emalloc(sizeof(process_pool_property));
    bzero(pp, sizeof(process_pool_property));
    pp->enable_coroutine = enable_coroutine;
    swoole_set_property(getThis(), 0, pp);
    swoole_set_object(getThis(), pool);
}

static PHP_METHOD(swoole_process_pool, on)
{
    char *name;
    size_t l_name;

    zend_fcall_info fci;
    zend_fcall_info_cache fci_cache;

    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());

    if (pool->started > 0)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to register event callback function");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_STRING(name, l_name)
        Z_PARAM_FUNC(fci, fci_cache);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(getThis(), 0);

    if (strncasecmp("WorkerStart", name, l_name) == 0)
    {
        if (pp->onWorkerStart)
        {
            sw_fci_cache_discard(pp->onWorkerStart);
        }
        else
        {
            pp->onWorkerStart = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onWorkerStart = fci_cache;
        sw_fci_cache_persist(pp->onWorkerStart);
        RETURN_TRUE;
    }
    else if (strncasecmp("Message", name, l_name) == 0)
    {
        if (pp->enable_coroutine)
        {
            swoole_php_fatal_error(E_NOTICE, "cannot set onMessage event with enable_coroutine");
            RETURN_FALSE;
        }
        if (pool->ipc_mode == SW_IPC_NONE)
        {
            swoole_php_fatal_error(E_WARNING, "cannot set onMessage event with ipc_type=0");
            RETURN_FALSE;
        }
        if (pp->onMessage)
        {
            sw_fci_cache_discard(pp->onMessage);
        }
        else
        {
            pp->onMessage = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onMessage = fci_cache;
        sw_fci_cache_persist(pp->onMessage);
        RETURN_TRUE;
    }
    else if (strncasecmp("WorkerStop", name, l_name) == 0)
    {
        if (pp->onWorkerStop)
        {
            sw_fci_cache_discard(pp->onWorkerStop);
        }
        else
        {
            pp->onWorkerStop = (zend_fcall_info_cache*) emalloc(sizeof(zend_fcall_info_cache));
        }
        *pp->onWorkerStop = fci_cache;
        sw_fci_cache_persist(pp->onWorkerStop);
        RETURN_TRUE;
    }
    else
    {
        swoole_php_error(E_WARNING, "unknown event type[%s]", name);
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process_pool, listen)
{
    char *host;
    size_t l_host;
    zend_long port = 0;
    zend_long backlog = 2048;

    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());

    if (pool->started > 0)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to listen");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &host, &l_host, &port, &backlog) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swoole_php_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
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

    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());
    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swoole_php_fatal_error(E_WARNING, "unsupported ipc type[%d]", pool->ipc_mode);
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
    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());
    if (pool->started)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to execute swoole_process_pool->start");
        RETURN_FALSE;
    }

    process_pool_property *pp = (process_pool_property *) swoole_get_property(getThis(), 0);

    SwooleG.use_signalfd = 0;

    swSignal_add(SIGTERM, pool_signal_handler);
    swSignal_add(SIGUSR1, pool_signal_handler);
    swSignal_add(SIGUSR2, pool_signal_handler);

    if (pool->ipc_mode == SW_IPC_NONE || pp->enable_coroutine)
    {
        if (pp->onWorkerStart == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "require onWorkerStart callback");
            RETURN_FALSE;
        }
    }
    else
    {
        if (pp->onMessage == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "require onMessage callback");
            RETURN_FALSE;
        }
        pool->onMessage = pool_onMessage;
    }

    pool->onWorkerStart = pool_onWorkerStart;
    pool->onWorkerStop = pool_onWorkerStop;

    zend_update_property_long(swoole_process_pool_ce, getThis(), ZEND_STRL("master_pid"), getpid());

    if (swProcessPool_start(pool) < 0)
    {
        RETURN_FALSE;
    }

    current_pool = pool;

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
        swoole_php_error(E_WARNING, "invalid worker_id[%ld]", worker_id);
        RETURN_FALSE;
    }
    else if (worker_id < 0)
    {
        worker_id = SwooleWG.id;
    }

    zval *zworkers = sw_zend_read_and_convert_property_array(swoole_process_pool_ce, getThis(), ZEND_STRL("workers"), 0);
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
    zval *retval = sw_zend_read_property(swoole_process_pool_ce, getThis(), ZEND_STRL("master_pid"), 0);
    long pid = zval_get_long(retval);
    RETURN_BOOL(swKill(pid, SIGTERM) == 0);
}

static PHP_METHOD(swoole_process_pool, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());
    efree(pool->ptr);
    efree(pool);
    swoole_set_object(getThis(), NULL);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(getThis(), 0);
    if (pp->onWorkerStart)
    {
        sw_fci_cache_discard(pp->onWorkerStart);
        efree(pp->onWorkerStart);
    }
    if (pp->onMessage)
    {
        sw_fci_cache_discard(pp->onMessage);
        efree(pp->onMessage);
    }
    if (pp->onWorkerStop)
    {
        sw_fci_cache_discard(pp->onWorkerStop);
        efree(pp->onWorkerStop);
    }
    efree(pp);
    swoole_set_property(getThis(), 0, NULL);
}
