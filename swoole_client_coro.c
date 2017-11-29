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
#include "socks5.h"

#ifdef SW_COROUTINE

#include "swoole_coroutine.h"
#include "ext/standard/basic_functions.h"
#include <setjmp.h>

enum client_property
{
    client_coro_property_context = 0,
    client_coro_property_coroutine = 1,
    client_coro_property_socket = 2,
};

typedef enum
{
    SW_CLIENT_CORO_STATUS_CLOSED,
    SW_CLIENT_CORO_STATUS_READY,
    SW_CLIENT_CORO_STATUS_WAIT,
    SW_CLIENT_CORO_STATUS_DONE
} swoole_client_coro_io_status;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _object;
#endif
    swoole_client_coro_io_status iowait;
    swTimer_node *timer;
    swString *result;
    int cid;
} swoole_client_coro_property;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_client_coro, __construct);
static PHP_METHOD(swoole_client_coro, __destruct);
static PHP_METHOD(swoole_client_coro, set);
static PHP_METHOD(swoole_client_coro, connect);
static PHP_METHOD(swoole_client_coro, recv);
static PHP_METHOD(swoole_client_coro, send);
static PHP_METHOD(swoole_client_coro, sendfile);
static PHP_METHOD(swoole_client_coro, sendto);
#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL);
static PHP_METHOD(swoole_client_coro, getPeerCert);
static PHP_METHOD(swoole_client_coro, verifyPeerCert);
#endif
#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client_coro, getSocket);
#endif
static PHP_METHOD(swoole_client_coro, isConnected);
static PHP_METHOD(swoole_client_coro, getsockname);
static PHP_METHOD(swoole_client_coro, getpeername);
static PHP_METHOD(swoole_client_coro, close);

static void client_onConnect(swClient *cli);
static void client_onReceive(swClient *cli, char *data, uint32_t length);
static void client_onClose(swClient *cli);
static void client_onError(swClient *cli);
static void client_coro_onTimeout(swTimer *timer, swTimer_node *tnode);

static const zend_function_entry swoole_client_coro_methods[] =
{
    PHP_ME(swoole_client_coro, __construct, arginfo_swoole_client_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client_coro, __destruct, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client_coro, set, arginfo_swoole_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, connect, arginfo_swoole_client_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recv, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, send, arginfo_swoole_client_coro_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendfile, arginfo_swoole_client_coro_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendto, arginfo_swoole_client_coro_sendto, ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client_coro, enableSSL, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getPeerCert, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, verifyPeerCert, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client_coro, isConnected, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getsockname, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getpeername, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, close, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_client_coro, getSocket, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

zend_class_entry swoole_client_coro_ce;
zend_class_entry *swoole_client_coro_class_entry_ptr;

static void client_execute_callback(zval *zobject, enum php_swoole_client_callback_type type)
{
    zval *retval = NULL;
    zval *result = NULL;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    swoole_client_coro_property *ccp = swoole_get_property(zobject, 1);
    if (type == SW_CLIENT_CB_onConnect 
#ifdef SW_USE_OPENSSL
            || type == SW_CLIENT_CB_onSSLReady
#endif
       )
    {
        zval *type = sw_zend_read_property(swoole_client_coro_class_entry_ptr, zobject, ZEND_STRL("type"), 1 TSRMLS_CC);
        int client_type = php_swoole_socktype(Z_LVAL_P(type));
        if (client_type == SW_SOCK_UNIX_DGRAM || client_type == SW_SOCK_UDP || client_type == SW_SOCK_UDP6)
        {
            return;
        }
        ccp->iowait = SW_CLIENT_CORO_STATUS_READY;
        SW_MAKE_STD_ZVAL(result);
        ZVAL_BOOL(result, 1);
        php_context *sw_current_context = swoole_get_property(zobject, 0);
        int ret = coro_resume(sw_current_context, result, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        sw_zval_ptr_dtor(&result);
        return;
    }

    if (type == SW_CLIENT_CB_onError || (type == SW_CLIENT_CB_onClose && ccp->iowait > SW_CLIENT_CORO_STATUS_READY))
    {
        SW_MAKE_STD_ZVAL(result);
        ZVAL_BOOL(result, 0);
        php_context *sw_current_context = swoole_get_property(zobject, 0);
        int ret = coro_resume(sw_current_context, result, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        sw_zval_ptr_dtor(&result);
        return;
    }
}

void swoole_client_coro_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_client_coro_ce, "swoole_client_coro", "Swoole\\Coroutine\\Client", swoole_client_coro_methods);
    swoole_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_client_coro_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_client_coro, "Swoole\\Client");

    zend_declare_property_long(swoole_client_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_coro_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_OOB"), MSG_OOB TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_PEEK"), MSG_PEEK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL TSRMLS_CC);
}

static void client_coro_onTimeout(swTimer *timer, swTimer_node *tnode)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    php_context *ctx = (php_context *) tnode->data;
    zval *zdata = NULL;
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    zval *zobject = (zval *)ctx->coro_params;
#else
    zval _zobject = ctx->coro_params;
    zval *zobject = & _zobject;
#endif
    zend_update_property_long(swoole_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);

    swoole_client_coro_property *ccp = swoole_get_property(zobject, 1);
    if (ccp)
    {
        ccp->timer = NULL;
        ccp->iowait = SW_CLIENT_CORO_STATUS_READY;
    }

    swClient *cli = swoole_get_object(zobject);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "client is not connected to server.");
        return;
    }

    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, 0);
    int ret = coro_resume(ctx, zdata, &retval);
    if (ret == CORO_END && retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
}

static void client_onReceive(swClient *cli, char *data, uint32_t length)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;

    swoole_client_coro_property *ccp = swoole_get_property(zobject, 1);
    if (ccp->timer)
    {
        swTimer_del(&SwooleG.timer, ccp->timer);
        ccp->timer = NULL;
    }

    if (ccp->iowait == SW_CLIENT_CORO_STATUS_WAIT)
    {
        ccp->iowait = SW_CLIENT_CORO_STATUS_READY;

        zval *retval = NULL;
        zval *zdata;
        SW_MAKE_STD_ZVAL(zdata);
        SW_ZVAL_STRINGL(zdata, data, length, 1);
        php_context *sw_current_context = swoole_get_property(zobject, 0);
        int ret = coro_resume(sw_current_context, zdata, &retval);
        if (ret == CORO_END && retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        sw_zval_ptr_dtor(&zdata);
    }
    else
    {
        if (ccp->result)
        {
            if (swString_append_ptr(ccp->result, data, length) == SW_ERR)
            {
                swWarn("failed to append package.");
            }
            if (swString_length(ccp->result) >= cli->buffer_input_size)
            {
                swClient_sleep(cli);
            }
        }
        else
        {
            ccp->result = swString_dup(data, length);
            if (ccp->result)
            {
                ccp->iowait = SW_CLIENT_CORO_STATUS_DONE;
            }
            if (cli->open_eof_check || cli->open_length_check || length >= cli->buffer_input_size)
            {
                swClient_sleep(cli);
            }
        }
    }
}

static void client_onConnect(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;
#ifdef SW_USE_OPENSSL
    if (cli->ssl_wait_handshake)
    {
        client_execute_callback(zobject, SW_CLIENT_CB_onSSLReady);
    }
    else
#endif
    {
        client_execute_callback(zobject, SW_CLIENT_CB_onConnect);
    }
}

static void client_onClose(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;
    if (cli->released)
    {
        return;
    }
    php_swoole_client_free(zobject, cli TSRMLS_CC);
    client_execute_callback(zobject, SW_CLIENT_CB_onClose);
#if PHP_MAJOR_VERSION < 7
    sw_zval_ptr_dtor(&zobject);
#endif
}

static void client_onError(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;
    zend_update_property_long(swoole_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
    if (!cli->released)
    {
        php_swoole_client_free(zobject, cli TSRMLS_CC);
    }
    client_execute_callback(zobject, SW_CLIENT_CB_onError);
}

swClient* php_swoole_client_coro_new(zval *object, char *host, int host_len, int port)
{
    zval *ztype;
    int async = 0;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    ztype = sw_zend_read_property(swoole_client_coro_class_entry_ptr, object, SW_STRL("type")-1, 0 TSRMLS_CC);

    if (ztype == NULL || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "get swoole_client_coro->type failed.");
        return NULL;
    }

    long type = Z_LVAL_P(ztype);

    //new flag, swoole-1.6.12+
    if (type & SW_FLAG_ASYNC)
    {
        async = 1;
    }

    swClient *cli;
    cli = (swClient*) emalloc(sizeof(swClient));

    if (swClient_create(cli, php_swoole_socktype(type), async) < 0)
    {
        swoole_php_fatal_error(E_WARNING, "swClient_create() failed. Error: %s [%d]", strerror(errno), errno);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, object, ZEND_STRL("errCode"), errno TSRMLS_CC);
        return NULL;
    }

    zend_update_property_long(swoole_client_coro_class_entry_ptr, object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL)
    {
        cli->open_ssl = 1;
    }
#endif

    return cli;
}

static PHP_METHOD(swoole_client_coro, __construct)
{
	coro_check(TSRMLS_C);

    long async = 1;
    long type = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &type) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "require socket type param.");
        RETURN_FALSE;
    }

    if (async == 1)
    {
        type |= SW_FLAG_ASYNC;
    }

    //不支持长连
    int client_type = php_swoole_socktype(type);
    if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_STREAM)
    {
        swoole_php_fatal_error(E_ERROR, "Unknown client type '%d'.", client_type);
    }

    zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), type TSRMLS_CC);
    //init
    swoole_set_object(getThis(), NULL);

    swoole_client_coro_property *client_coro_property = emalloc(sizeof(swoole_client_coro_property));
    bzero(client_coro_property, sizeof(swoole_client_coro_property));
    client_coro_property->iowait = SW_CLIENT_CORO_STATUS_CLOSED;
    swoole_set_property(getThis(), client_coro_property_coroutine, client_coro_property);

    php_context *sw_current_context = emalloc(sizeof(php_context));
    sw_current_context->onTimeout = NULL;
#if PHP_MAJOR_VERSION < 7
    sw_current_context->coro_params = getThis();
#else
    sw_current_context->coro_params = *getThis();
#endif
    sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
    swoole_set_property(getThis(), client_coro_property_context, sw_current_context);
#ifdef SWOOLE_SOCKETS_SUPPORT
    swoole_set_property(getThis(), client_coro_property_socket, NULL);
#endif

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, __destruct)
{
    swClient *cli = swoole_get_object(getThis());
    //no keep connection
    if (cli)
    {
        zval *zobject = getThis();
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, swoole_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    php_context *sw_current_context = swoole_get_property(getThis(), 0);
    if (sw_current_context)
    {
        efree(sw_current_context);
        swoole_set_property(getThis(), 0, NULL);
    }
    swoole_client_coro_property *ccp = swoole_get_property(getThis(), 1);
    if (ccp)
    {
        if (ccp->result)
        {
            swString_free(ccp->result);
        }
        if (ccp->timer)
        {
            swTimer_del(&SwooleG.timer, ccp->timer);
        }
        efree(ccp);
        swoole_set_property(getThis(), 1, NULL);
    }
}

static PHP_METHOD(swoole_client_coro, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, connect)
{
    long port = 0, sock_flag = 0;
    char *host = NULL;
    zend_size_t host_len;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ld", &host, &host_len, &port, &timeout) == FAILURE)
    {
        return;
    }

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "The host is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (cli)
    {
        swoole_php_fatal_error(E_WARNING, "The client is already connected server.");
        RETURN_FALSE;
    }

    cli = php_swoole_client_coro_new(getThis(), host, host_len, port);
    if (cli == NULL)
    {
        RETURN_FALSE;
    }

    swoole_set_object(getThis(), cli);

    if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6)
    {
        if (port <= 0 || port > SW_CLIENT_MAX_PORT)
        {
            swoole_php_fatal_error(E_WARNING, "The port is invalid.");
            RETURN_FALSE;
        }
        if (cli->async == 1)
        {
            //for tcp: nonblock
            //for udp: have udp connect
            sock_flag = 1;
        }
    }

    if (cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_client_coro is already connected.");
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        php_swoole_client_check_setting(cli, zset TSRMLS_CC);
    }

    if (swSocket_is_stream(cli->type))
    {
        cli->onConnect = client_onConnect;
        cli->onClose = client_onClose;
        cli->onError = client_onError;
        cli->onReceive = client_onReceive;

        cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    }
    else
    {
        cli->onConnect = client_onConnect;
        cli->onReceive = client_onReceive;
        cli->reactor_fdtype = PHP_SWOOLE_FD_DGRAM_CLIENT;
    }

    zval *zobject = getThis();
    cli->object = zobject;
#if PHP_MAJOR_VERSION >= 7
    swoole_client_coro_property *ccp = swoole_get_property(getThis(), 1);
    sw_copy_to_stack(cli->object, ccp->_object);
#endif

    cli->timeout = timeout;
    //nonblock async
    if (cli->connect(cli, host, port, timeout, sock_flag) < 0)
    {
        swoole_php_sys_error(E_WARNING, "connect to server[%s:%d] failed.", host, (int )port);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errno TSRMLS_CC);
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UNIX_DGRAM || cli->type == SW_SOCK_UDP6 || cli->type == SW_SOCK_UDP)
    {
        RETURN_TRUE;
    }

    php_context *sw_current_context = swoole_get_property(getThis(), 0);
    coro_save(sw_current_context);
    coro_yield();
}

static PHP_METHOD(swoole_client_coro, send)
{
    char *data;
    zend_size_t data_len;
    long flags = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &data, &data_len, &flags) == FAILURE)
    {
        return;
    }

    if (data_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "client is not connected to server.");
        RETURN_FALSE;
    }

    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        RETURN_FALSE;
    }

    //clear errno
    SwooleG.error = 0;
    int ret = cli->send(cli, data, data_len, flags);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", cli->socket->fd, data_len);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(ret);
    }
}

static PHP_METHOD(swoole_client_coro, sendto)
{
    char* ip;
    zend_size_t ip_len;
    long port;
    char *data;
    zend_size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls", &ip, &ip_len, &port, &data, &len) == FAILURE)
    {
        return;
    }

    if (len <= 0)
    {
        swoole_php_error(E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        cli = php_swoole_client_new(getThis(), ip, ip_len, port);
        if (cli == NULL)
        {
            RETURN_FALSE;
        }
        cli->socket->active = 1;
        swoole_set_object(getThis(), cli);
    }

    int ret;
    if (cli->type == SW_SOCK_UDP)
    {
        ret = swSocket_udp_sendto(cli->socket->fd, ip, port, data, len);
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        ret = swSocket_udp_sendto6(cli->socket->fd, ip, port, data, len);
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "only support SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6.");
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client_coro, sendfile)
{
    char *file;
    zend_size_t file_len;
    long offset = 0;
    long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &file, &file_len, &offset) == FAILURE)
    {
        return;
    }
    if (file_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "file is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }

    if (!(cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6 || cli->type == SW_SOCK_UNIX_STREAM))
    {
        swoole_php_error(E_WARNING, "dgram socket cannot use sendfile.");
        RETURN_FALSE;
    }
    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "Server is not connected.");
        RETURN_FALSE;
    }
    //clear errno
    SwooleG.error = 0;
    int ret = cli->sendfile(cli, file, offset, length);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_fatal_error(E_WARNING, "sendfile() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }
    else
    {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client_coro, recv)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "client is not connected to server.");
        RETURN_FALSE;
    }

    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        RETURN_FALSE;
    }

    if (cli->sleep)
    {
        swClient_wakeup(cli);
    }

    swoole_client_coro_property *ccp = swoole_get_property(getThis(), 1);
    if (ccp->iowait == SW_CLIENT_CORO_STATUS_DONE)
    {
        ccp->iowait = SW_CLIENT_CORO_STATUS_READY;
        zval *result;
        SW_MAKE_STD_ZVAL(result);
        SW_ZVAL_STRINGL(result, ccp->result->str, ccp->result->length, 1);
        swString_free(ccp->result);
        ccp->result = NULL;
        RETURN_ZVAL(result, 0, 1);
    }
    else if (ccp->iowait == SW_CLIENT_CORO_STATUS_WAIT && ccp->cid != COROG.current_coro->cid)
    {
        swoole_php_fatal_error(E_WARNING, "client has been bound to another coro");
        RETURN_FALSE;
    }


    php_context *context = swoole_get_property(getThis(), 0);
    if (cli->timeout > 0)
    {
        php_swoole_check_timer((int) (cli->timeout * 1000));
        ccp->timer = SwooleG.timer.add(&SwooleG.timer, (int) (cli->timeout * 1000), 0, context, client_coro_onTimeout);
    }
    ccp->iowait = SW_CLIENT_CORO_STATUS_WAIT;
    coro_save(context);
    ccp->cid = COROG.current_coro->cid;
    coro_yield();
}

static PHP_METHOD(swoole_client_coro, isConnected)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->socket->active);
}

static PHP_METHOD(swoole_client_coro, getsockname)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    if (!cli->socket->active)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UNIX_STREAM || cli->type == SW_SOCK_UNIX_DGRAM)
    {
        swoole_php_fatal_error(E_WARNING, "getsockname() only support AF_INET family socket.");
        RETURN_FALSE;
    }

    cli->socket->info.len = sizeof(cli->socket->info.addr);
    if (getsockname(cli->socket->fd, (struct sockaddr*) &cli->socket->info.addr, &cli->socket->info.len) < 0)
    {
        swoole_php_sys_error(E_WARNING, "getsockname() failed.");
        RETURN_FALSE;
    }

    array_init(return_value);
    if (cli->type == SW_SOCK_UDP6 || cli->type == SW_SOCK_TCP6)
    {
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v6.sin6_port));
        char tmp[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &cli->socket->info.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)))
        {
            sw_add_assoc_string(return_value, "host", tmp, 1);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "inet_ntop() failed.");
        }
    }
    else
    {
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v4.sin_port));
        sw_add_assoc_string(return_value, "host", inet_ntoa(cli->socket->info.addr.inet_v4.sin_addr), 1);
    }
}

static PHP_METHOD(swoole_client_coro, getpeername)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }

    if (!cli->socket->active)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UDP)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->remote_addr.addr.inet_v4.sin_port));
        sw_add_assoc_string(return_value, "host", inet_ntoa(cli->remote_addr.addr.inet_v4.sin_addr), 1);
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->remote_addr.addr.inet_v6.sin6_port));
        char tmp[INET6_ADDRSTRLEN];

        if (inet_ntop(AF_INET6, &cli->remote_addr.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)))
        {
            sw_add_assoc_string(return_value, "host", tmp, 1);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "inet_ntop() failed.");
        }
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "only support SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6.");
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client_coro, close)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }
    if (cli->socket->active == 0)
    {
        cli->socket->removed = 1;
    }
    if (cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "client socket is closed.");
        RETURN_FALSE;
    }
    //Connection error, or short tcp connection.
    swoole_client_coro_property *ccp = swoole_get_property(getThis(), 1);
    ccp->iowait = SW_CLIENT_CORO_STATUS_CLOSED;
    cli->released = 1;
    php_swoole_client_free(getThis(), cli TSRMLS_CC);

    RETURN_TRUE;
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    if (cli->type != SW_SOCK_TCP && cli->type != SW_SOCK_TCP6)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use enableSSL.");
        RETURN_FALSE;
    }
    if (cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL has been enabled.");
        RETURN_FALSE;
    }
    if (swClient_enable_ssl_encrypt(cli) < 0)
    {
        RETURN_FALSE;
    }
    cli->open_ssl = 1;
    cli->ssl_wait_handshake = 1;
    cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;

    SwooleG.main_reactor->set(SwooleG.main_reactor, cli->socket->fd, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE);

    php_context *sw_current_context = swoole_get_property(getThis(), 0);
    coro_save(sw_current_context);
    coro_yield();
}

static PHP_METHOD(swoole_client_coro, getPeerCert)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    if (!cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL no ready.");
        RETURN_FALSE;
    }
    char buf[8192];
    int n = swSSL_get_client_certificate(cli->socket->ssl, buf, sizeof(buf));
    if (n < 0)
    {
        RETURN_FALSE;
    }
    SW_RETURN_STRINGL(buf, n, 1);
}

static PHP_METHOD(swoole_client_coro, verifyPeerCert)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }
    if (!cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL no ready.");
        RETURN_FALSE;
    }
    zend_bool allow_self_signed = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &allow_self_signed) == FAILURE)
    {
        return;
    }
    SW_CHECK_RETURN(swSSL_verify(cli->socket, allow_self_signed));
}
#endif


#ifdef SWOOLE_SOCKETS_SUPPORT

static sw_inline swClient* client_get_ptr(zval *zobject TSRMLS_DC)
{
    swClient *cli = swoole_get_object(zobject);
    if (cli && cli->socket && cli->socket->active == 1)
    {
        return cli;
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "client is not connected to server.");
        return NULL;
    }
}

static PHP_METHOD(swoole_client_coro, getSocket)
{
    zval *zsocket = swoole_get_property(getThis(), client_coro_property_socket);
    if (zsocket)
    {
        RETURN_ZVAL(zsocket, 1, NULL);
    }
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (cli->keep)
    {
        swoole_php_fatal_error(E_WARNING, "the 'getSocket' method can't be used on persistent connection.");
        RETURN_FALSE;
    }
    php_socket *socket_object = swoole_convert_to_socket(cli->socket->fd);
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void * ) socket_object, php_sockets_le_socket());
    zsocket = sw_zval_dup(return_value);
    sw_zval_add_ref(&zsocket);
    swoole_set_property(getThis(), client_coro_property_socket, zsocket);
}
#endif

#endif
