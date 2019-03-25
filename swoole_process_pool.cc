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

#include "php_swoole.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pool_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, worker_num)
    ZEND_ARG_INFO(0, ipc_type)
    ZEND_ARG_INFO(0, msgqueue_key)
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
    zval *onWorkerStart;
    zval *onWorkerStop;
    zval *onMessage;
    zval _onWorkerStart;
    zval _onWorkerStop;
    zval _onMessage;
} process_pool_property;

static zend_class_entry swoole_process_pool_ce;
static zend_class_entry *swoole_process_pool_ce_ptr;
static zend_object_handlers swoole_process_pool_handlers;
static swProcessPool *current_pool;
static zval *current_process = NULL;

void swoole_process_pool_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_process_pool, "Swoole\\Process\\Pool", "swoole_process_pool", NULL, swoole_process_pool_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_process_pool, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_process_pool, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_process_pool, zend_class_unset_property_deny);

    zend_declare_property_long(swoole_process_pool_ce_ptr, ZEND_STRL("master_pid"), -1, ZEND_ACC_PUBLIC);
}

static void php_swoole_process_pool_onWorkerStart(swProcessPool *pool, int worker_id)
{
    zval *zobject = (zval *) pool->ptr;
    zval *retval = NULL;

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

    if (sw_call_user_function_ex(EG(function_table), NULL, pp->onWorkerStart, &retval, 2, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStart handler error.");
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    if (SwooleG.main_reactor)
    {
        php_swoole_event_wait();
        SwooleG.running = 0;
    }
}

static void php_swoole_process_pool_onMessage(swProcessPool *pool, char *data, uint32_t length)
{
    zval *zobject = (zval *) pool->ptr;
    zval *retval = NULL;

    zval args[2];
    args[0] = *zobject;
    ZVAL_STRINGL(&args[1], data, length);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);

    if (sw_call_user_function_ex(EG(function_table), NULL, pp->onMessage, &retval, 2, args, 0, NULL)  == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onMessage handler error.");
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    zval_ptr_dtor(&args[1]);
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_process_pool_onWorkerStop(swProcessPool *pool, int worker_id)
{
    zval *zobject = (zval *) pool->ptr;
    zval *retval = NULL;

    zval args[2];
    args[0] = *zobject;
    ZVAL_LONG(&args[1], worker_id);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(zobject, 0);
    if (pp->onWorkerStop == NULL)
    {
        return;
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, pp->onWorkerStop, &retval, 2, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStop handler error.");
    }
    if (UNEXPECTED(EG(exception)))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void php_swoole_process_pool_signal_handler(int sig)
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

    //only cli env
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process_pool only can be used in PHP CLI mode.");
        RETURN_FALSE;
    }

    if (SwooleG.serv)
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process_pool cannot use in server process.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l|ll", &worker_num, &ipc_type, &msgq_key) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_num <= 0)
    {
        zend_throw_exception_ex(swoole_exception_ce_ptr, errno, "invalid worker_num");
        RETURN_FALSE;
    }

    swProcessPool *pool = (swProcessPool *) emalloc(sizeof(swProcessPool));
    if (swProcessPool_create(pool, worker_num, 0, (key_t) msgq_key, ipc_type) < 0)
    {
        zend_throw_exception_ex(swoole_exception_ce_ptr, errno, "failed to create process pool");
        RETURN_FALSE;
    }

    if (ipc_type > 0)
    {
        if (swProcessPool_set_protocol(pool, 0, SW_BUFFER_INPUT_SIZE) < 0)
        {
            zend_throw_exception_ex(swoole_exception_ce_ptr, errno, "failed to create process pool");
            RETURN_FALSE;
        }
    }

    pool->ptr = sw_zval_dup(getThis());

    process_pool_property *pp = (process_pool_property *) emalloc(sizeof(process_pool_property));
    bzero(pp, sizeof(process_pool_property));
    swoole_set_property(getThis(), 0, pp);
    swoole_set_object(getThis(), pool);
}

static PHP_METHOD(swoole_process_pool, on)
{
    char *name;
    size_t l_name;
    zval *callback;

    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());

    if (pool->started > 0)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to register event callback function.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &name, &l_name, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (!php_swoole_is_callable(callback))
    {
        RETURN_FALSE;
    }

    process_pool_property *pp = (process_pool_property *) swoole_get_property(getThis(), 0);

    if (strncasecmp("WorkerStart", name, l_name) == 0)
    {
        if (pp->onWorkerStart)
        {
            zval_ptr_dtor(pp->onWorkerStart);
        }
        pp->onWorkerStart = callback;
        Z_TRY_ADDREF_P(callback);
        sw_copy_to_stack(pp->onWorkerStart, pp->_onWorkerStart);
        RETURN_TRUE;
    }
    else if (strncasecmp("Message", name, l_name) == 0)
    {
        if (pool->ipc_mode == SW_IPC_NONE)
        {
            swoole_php_fatal_error(E_WARNING, "cannot set onMessage event with ipc_type=0.");
            RETURN_TRUE;
        }
        if (pp->onMessage)
        {
            zval_ptr_dtor(pp->onMessage);
        }
        pp->onMessage = callback;
        Z_TRY_ADDREF_P(callback);
        sw_copy_to_stack(pp->onMessage, pp->_onMessage);
        RETURN_TRUE;
    }
    else if (strncasecmp("WorkerStop", name, l_name) == 0)
    {
        if (pp->onWorkerStop)
        {
            zval_ptr_dtor(pp->onWorkerStop);
        }
        pp->onWorkerStop = callback;
        Z_TRY_ADDREF_P(callback);
        sw_copy_to_stack(pp->onWorkerStop, pp->_onWorkerStop);
        RETURN_TRUE;
    }
    else
    {
        swoole_php_error(E_WARNING, "unknown event type[%s]", name);
        RETURN_TRUE;
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
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to listen.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &host, &l_host, &port, &backlog) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (pool->ipc_mode != SW_IPC_SOCKET)
    {
        swoole_php_fatal_error(E_WARNING, "unsupported ipc type[%d].", pool->ipc_mode);
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
        swoole_php_fatal_error(E_WARNING, "unsupported ipc type[%d].", pool->ipc_mode);
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
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to execute swoole_process_pool->start.");
        RETURN_FALSE;
    }

    process_pool_property *pp = (process_pool_property *) swoole_get_property(getThis(), 0);

    SwooleG.use_signalfd = 0;

    swSignal_add(SIGTERM, php_swoole_process_pool_signal_handler);
    swSignal_add(SIGUSR1, php_swoole_process_pool_signal_handler);
    swSignal_add(SIGUSR2, php_swoole_process_pool_signal_handler);

    if (pool->ipc_mode > SW_IPC_NONE)
    {
        if (pp->onMessage == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "require onMessage callback");
            RETURN_FALSE;
        }
        pool->onMessage = php_swoole_process_pool_onMessage;
    }
    else
    {
        if (pp->onWorkerStart == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "require onWorkerStart callback");
            RETURN_FALSE;
        }
    }

    pool->onWorkerStart = php_swoole_process_pool_onWorkerStart;
    pool->onWorkerStop = php_swoole_process_pool_onWorkerStop;

    zend_update_property_long(swoole_process_pool_ce_ptr, getThis(), ZEND_STRL("master_pid"), getpid());

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
    static zval object;

    if (current_pool == NULL)
    {
        RETURN_FALSE;
    }

    if (current_process == NULL)
    {
        swWorker *worker = &current_pool->workers[SwooleWG.id];
        object_init_ex(&object, swoole_process_ce_ptr);
        zend_update_property_long(swoole_process_ce_ptr, &object, ZEND_STRL("id"), SwooleWG.id);
        zend_update_property_long(swoole_process_ce_ptr, &object, ZEND_STRL("pid"), getpid());
        swoole_set_object(&object, worker);
        current_process = &object;
    }
    else
    {
        Z_TRY_ADDREF_P(&object);
    }

    RETURN_ZVAL(current_process, 1, 0);
}

static PHP_METHOD(swoole_process_pool, shutdown)
{
    zval rv;
    zval *retval = zend_read_property(swoole_process_pool_ce_ptr, getThis(), ZEND_STRL("master_pid"), 1, &rv);
    long pid = zval_get_long(retval);
    if (pid > 0)
    {
        RETURN_BOOL(kill(pid, SIGTERM) == 0);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process_pool, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swProcessPool *pool = (swProcessPool *) swoole_get_object(getThis());
    efree(pool->ptr);
    efree(pool);
    swoole_set_object(getThis(), NULL);

    process_pool_property *pp = (process_pool_property *) swoole_get_property(getThis(), 0);
    if (pp->onWorkerStart)
    {
        zval_ptr_dtor(pp->onWorkerStart);
    }
    if (pp->onMessage)
    {
        zval_ptr_dtor(pp->onMessage);
    }
    if (pp->onWorkerStop)
    {
        zval_ptr_dtor(pp->onWorkerStop);
    }
    efree(pp);
    swoole_set_property(getThis(), 0, NULL);
}
