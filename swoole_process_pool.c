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
    ZEND_ARG_INFO(0, callback)
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
static PHP_METHOD(swoole_process_pool, start);

static const zend_function_entry swoole_process_pool_methods[] =
{
    PHP_ME(swoole_process_pool, __construct, arginfo_swoole_process_pool_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_process_pool, __destruct, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_process_pool, on, arginfo_swoole_process_pool_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, listen, arginfo_swoole_process_pool_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, write, arginfo_swoole_process_pool_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process_pool, start, arginfo_swoole_process_pool_void, ZEND_ACC_PUBLIC)
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
static zend_class_entry *swoole_process_pool_class_entry_ptr;

void swoole_process_pool_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_process_pool_ce, "swoole_process_pool", "Swoole\\Process\\Pool", swoole_process_pool_methods);
    swoole_process_pool_class_entry_ptr = zend_register_internal_class(&swoole_process_pool_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_process_pool, "Swoole\\Process\\Pool");
}

static void php_swoole_process_pool_onWorkerStart(swProcessPool *pool, int worker_id)
{
    SWOOLE_GET_TSRMLS;

    zval *zobject = (zval *) pool->ptr;
    zval *zworker_id;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    zval **args[2];
    args[0] = &zobject;
    args[1] = &zworker_id;

    process_pool_property *pp = swoole_get_property(zobject, 0);
    if (pp->onWorkerStart == NULL)
    {
        return;
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, pp->onWorkerStart, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStart handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_process_pool_onMessage(swProcessPool *pool, char *data, uint32_t length)
{
    SWOOLE_GET_TSRMLS;

    zval *zobject = (zval *) pool->ptr;
    zval *zdata;
    zval *retval;

    SW_MAKE_STD_ZVAL(zdata);
    SW_ZVAL_STRINGL(zdata, data, length, 1);

    zval **args[2];
    args[0] = &zobject;
    args[1] = &zdata;

    process_pool_property *pp = swoole_get_property(zobject, 0);

    if (sw_call_user_function_ex(EG(function_table), NULL, pp->onMessage, &retval, 2, args, 0, NULL TSRMLS_CC)  == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStart handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    sw_zval_ptr_dtor(&zdata);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_process_pool_onWorkerStop(swProcessPool *pool, int worker_id)
{
    SWOOLE_GET_TSRMLS;

    zval *zobject = (zval *) pool->ptr;
    zval *zworker_id;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    zval **args[2];
    args[0] = &zobject;
    args[1] = &zworker_id;

    process_pool_property *pp = swoole_get_property(zobject, 0);
    if (pp->onWorkerStop == NULL)
    {
        return;
    }
    if (sw_call_user_function_ex(EG(function_table), NULL, pp->onWorkerStop, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onWorkerStop handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_process_pool_signal_hanlder(int sig)
{
    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
    case SIGUSR1:
    case SIGUSR2:
        SwooleGS->event_workers.reloading = 1;
        SwooleGS->event_workers.reload_init = 0;
        break;
    default:
        break;
    }
}

static PHP_METHOD(swoole_process_pool, __construct)
{
    long worker_num;
    long ipc_type = SW_IPC_NONE;
    long msgq_key = 0;

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

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|ll", &worker_num, &ipc_type, &msgq_key) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (worker_num <= 0)
    {
        zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "invalid worker_num");
        RETURN_FALSE;
    }

    swProcessPool *pool = emalloc(sizeof(swProcessPool));
    if (swProcessPool_create(pool, worker_num, 0, (key_t) msgq_key, ipc_type) < 0)
    {
        zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "failed to create process pool");
        RETURN_FALSE;
    }

    if (ipc_type > 0)
    {
        if (swProcessPool_set_protocol(pool, 0, SW_BUFFER_INPUT_SIZE) < 0)
        {
            zend_throw_exception_ex(swoole_exception_class_entry_ptr, errno TSRMLS_CC, "failed to create process pool");
            RETURN_FALSE;
        }
    }

    pool->ptr = sw_zval_dup(getThis());

    process_pool_property *pp = emalloc(sizeof(process_pool_property));
    bzero(pp, sizeof(process_pool_property));
    swoole_set_property(getThis(), 0, pp);
    swoole_set_object(getThis(), pool);
}

static PHP_METHOD(swoole_process_pool, on)
{
    char *name;
    zend_size_t l_name;
    zval *callback;

    swProcessPool *pool = swoole_get_object(getThis());

    if (pool->started > 0)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to register event callback function.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &l_name, &callback) == FAILURE)
    {
        return;
    }

    if (!php_swoole_is_callable(callback))
    {
        RETURN_FALSE;
    }

    process_pool_property *pp = swoole_get_property(getThis(), 0);

    if (strncasecmp("WorkerStart", name, l_name) == 0)
    {
        if (pp->onWorkerStart)
        {
            sw_zval_ptr_dtor(&pp->onWorkerStart);
        }
        pp->onWorkerStart = callback;
        sw_zval_add_ref(&callback);
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
            sw_zval_ptr_dtor(&pp->onMessage);
        }
        pp->onMessage = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(pp->onMessage, pp->_onMessage);
        RETURN_TRUE;
    }
    else if (strncasecmp("WorkerStop", name, l_name) == 0)
    {
        if (pp->onWorkerStop)
        {
            sw_zval_ptr_dtor(&pp->onWorkerStop);
        }
        pp->onWorkerStop = callback;
        sw_zval_add_ref(&callback);
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
    zend_size_t l_host;
    long port;
    long backlog = 2048;

    swProcessPool *pool = swoole_get_object(getThis());

    if (pool->started > 0)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to listen.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &host, &l_host, &port, &backlog) == FAILURE)
    {
        return;
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
    zend_size_t length;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &length) == FAILURE)
    {
        return;
    }

    swProcessPool *pool = swoole_get_object(getThis());
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
    swProcessPool *pool = swoole_get_object(getThis());
    if (pool->started)
    {
        swoole_php_fatal_error(E_WARNING, "process pool is started. unable to execute swoole_process_pool->start.");
        RETURN_FALSE;
    }

    process_pool_property *pp = swoole_get_property(getThis(), 0);

    SwooleG.use_signalfd = 0;

    swSignal_add(SIGTERM, php_swoole_process_pool_signal_hanlder);

    if (pool->ipc_mode > SW_IPC_NONE)
    {
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

    if (swProcessPool_start(pool) < 0)
    {
        RETURN_FALSE;
    }
    swProcessPool_wait(pool);
    swProcessPool_shutdown(pool);
}

static PHP_METHOD(swoole_process_pool, __destruct)
{
    swProcessPool *pool = swoole_get_object(getThis());
    sw_zval_free(pool->ptr);
    efree(pool);

    process_pool_property *pp = swoole_get_property(getThis(), 0);
    if (pp->onWorkerStart)
    {
        sw_zval_ptr_dtor(&pp->onWorkerStart);
    }
    if (pp->onMessage)
    {
        sw_zval_ptr_dtor(&pp->onMessage);
    }
    if (pp->onWorkerStop)
    {
        sw_zval_ptr_dtor(&pp->onWorkerStop);
    }
    efree(pp);
}
