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
 | Author: Fang  <coooold@live.com>                                     |
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 | Author: Yuanyi   Zhi  <syyuanyizhi@163.com>                          |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_http_client.h"
#include "swoole_coroutine.h"
#include <setjmp.h>

static swString *http_client_buffer;

static void http_client_coro_onReceive(swClient *cli, char *data, uint32_t length);
static void http_client_coro_onConnect(swClient *cli);
static void http_client_coro_onClose(swClient *cli);
static void http_client_coro_onError(swClient *cli);
static int http_client_coro_onMessage(swConnection *conn, char *data, uint32_t length);

static int http_client_coro_send_http_request(zval *zobject TSRMLS_DC);
static int http_client_coro_execute(zval *zobject, char *uri, zend_size_t uri_len TSRMLS_DC);

static void http_client_coro_onTimeout(swTimer *timer, swTimer_node *tnode);

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_client_parser_on_header_field,
    http_client_parser_on_header_value,
    http_client_parser_on_headers_complete,
    http_client_parser_on_body,
    http_client_parser_on_message_complete
};

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setMethod, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setHeaders, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, headers, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setCookies, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cookies, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setData, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setDefer, 0, 0, 1)
    ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_addFile, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_execute, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_get, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_upgrade, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_post, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

zend_class_entry swoole_http_client_coro_ce;
zend_class_entry *swoole_http_client_coro_class_entry_ptr;

static PHP_METHOD(swoole_http_client_coro, __construct);
static PHP_METHOD(swoole_http_client_coro, __destruct);
static PHP_METHOD(swoole_http_client_coro, set);
static PHP_METHOD(swoole_http_client_coro, setMethod);
static PHP_METHOD(swoole_http_client_coro, setHeaders);
static PHP_METHOD(swoole_http_client_coro, setCookies);
static PHP_METHOD(swoole_http_client_coro, setData);
static PHP_METHOD(swoole_http_client_coro, addFile);
static PHP_METHOD(swoole_http_client_coro, execute);
static PHP_METHOD(swoole_http_client_coro, isConnected);
static PHP_METHOD(swoole_http_client_coro, close);
static PHP_METHOD(swoole_http_client_coro, get);
static PHP_METHOD(swoole_http_client_coro, upgrade);
static PHP_METHOD(swoole_http_client_coro, post);
static PHP_METHOD(swoole_http_client_coro, push);
static PHP_METHOD(swoole_http_client_coro, setDefer);
static PHP_METHOD(swoole_http_client_coro, getDefer);
static PHP_METHOD(swoole_http_client_coro, recv);

static const zend_function_entry swoole_http_client_coro_methods[] =
{
    PHP_ME(swoole_http_client_coro, __construct, arginfo_swoole_http_client_coro_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http_client_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http_client_coro, set, arginfo_swoole_http_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setMethod, arginfo_swoole_http_client_coro_setMethod, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setHeaders, arginfo_swoole_http_client_coro_setHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setCookies, arginfo_swoole_http_client_coro_setCookies, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setData, arginfo_swoole_http_client_coro_setData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, execute, arginfo_swoole_http_client_coro_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, get, arginfo_swoole_http_client_coro_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, post, arginfo_swoole_http_client_coro_post, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, upgrade, arginfo_swoole_http_client_coro_upgrade, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, addFile, arginfo_swoole_http_client_coro_addFile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, isConnected, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setDefer, arginfo_swoole_http_client_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, recv, arginfo_swoole_http_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, push, arginfo_swoole_http_client_coro_push, ZEND_ACC_PUBLIC)
    PHP_FALIAS(__sleep, swoole_unsupport_serialize, NULL)
    PHP_FALIAS(__wakeup, swoole_unsupport_serialize, NULL)

    PHP_FE_END
};

static int http_client_coro_execute(zval *zobject, char *uri, zend_size_t uri_len TSRMLS_DC)
{
    if (uri_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "path is empty.");
        return SW_ERR;
    }

    http_client *http = swoole_get_object(zobject);

    //http is not null when keeping alive
    if (http)
    {
        //http not ready
        if (http->state != HTTP_CLIENT_STATE_READY)
        {
            //swWarn("fd=%d, state=%d, active=%d, keep_alive=%d", http->cli->socket->fd, http->state, http->cli->socket->active, http->keep_alive);
            swoole_php_fatal_error(E_WARNING, "Operation now in progress phase %d.", http->state);
            return SW_ERR;
        }
        else if (!http->cli->socket->active)
        {
            swoole_php_fatal_error(E_WARNING, "connection#%d is closed.", http->cli->socket->fd);
            return SW_ERR;
        }
    }
    else
    {
        php_swoole_check_reactor();
        http = http_client_create(zobject TSRMLS_CC);
    }

    if (http == NULL)
    {
        return SW_ERR;
    }

    if (http->body == NULL)
    {
        http->body = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
        if (http->body == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            return SW_ERR;
        }
    }
    else
    {
        swString_clear(http->body);
    }

    if (http->uri)
    {
        efree(http->uri);
    }

    http->uri = estrdup(uri);
    http->uri_len = uri_len;
    //if connection exists
    if (http->cli)
    {
        http_client_coro_send_http_request(zobject TSRMLS_CC);
        return SW_OK;
    }

    swClient *cli = php_swoole_client_new(zobject, http->host, http->host_len, http->port);
    if (cli == NULL)
    {
        return SW_ERR;
    }
    http->cli = cli;

    zval *ztmp;
    HashTable *vht;
    zval *zset = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        vht = Z_ARRVAL_P(zset);
        /**
         * timeout
         */
        if (php_swoole_array_get_value(vht, "timeout", ztmp))
        {
            convert_to_double(ztmp);
            http->timeout = (double) Z_DVAL_P(ztmp);
        }
        /**
         * keep_alive
         */
        if (php_swoole_array_get_value(vht, "keep_alive", ztmp))
        {
            convert_to_boolean(ztmp);
            http->keep_alive = (int) Z_LVAL_P(ztmp);
        }
        //client settings
        php_swoole_client_check_setting(http->cli, zset TSRMLS_CC);

        if (http->cli->http_proxy)
        {
            zval *send_header = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestHeaders"), 1 TSRMLS_CC);
            if (send_header == NULL || Z_TYPE_P(send_header) != IS_ARRAY)
            {
                swoole_php_fatal_error (E_WARNING, "http proxy must set Host");
                return SW_ERR;
            }
            zval *value;
            if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value) == FAILURE)
            {
                swoole_php_fatal_error (E_WARNING, "http proxy must set Host");
                return SW_ERR;
            }
        }
    }

    if (cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client is already connected.");
        return SW_ERR;
    }

    cli->object = zobject;
	
#if PHP_MAJOR_VERSION >= 7
    http_client_property *hcc = swoole_get_property(zobject, 0);
    sw_copy_to_stack(cli->object, hcc->_object);
#endif

    cli->open_eof_check = 0;
    cli->open_length_check = 0;
    cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    cli->onReceive = http_client_coro_onReceive;
    cli->onConnect = http_client_coro_onConnect;
    cli->onClose = http_client_coro_onClose;
    cli->onError = http_client_coro_onError;

    swTraceLog(SW_TRACE_HTTP_CLIENT, "connect to server, object handle=%d, fd=%d", sw_get_object_handle(zobject), cli->socket->fd);

    return cli->connect(cli, http->host, http->port, http->timeout, 0);
}

static void http_client_coro_onTimeout(swTimer *timer, swTimer_node *tnode)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *zdata;
    zval *retval = NULL;

    php_context *ctx = tnode->data;

    SW_MAKE_STD_ZVAL(zdata);
    //return false
    ZVAL_BOOL(zdata, 0);

#if PHP_MAJOR_VERSION < 7
    zval *zobject = (zval *)ctx->coro_params;
#else
    zval _zobject = ctx->coro_params;
    zval *zobject = &_zobject;
#endif

    swTraceLog(SW_TRACE_HTTP_CLIENT, "recv timeout, object handle=%d.", sw_get_object_handle(zobject));

    http_client *http = swoole_get_object(zobject);
    http->timer = NULL;

    if (http->cli && http->cli->socket && !http->cli->socket->closed)
    {
        http->cli->released = 1;
        http->cli->close(http->cli);
        http_client_free(zobject TSRMLS_CC);
    }

    //define time out RETURN ERROR  110
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), ETIMEDOUT TSRMLS_CC);
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("statusCode"), -2 TSRMLS_CC);

    http_client_property *hcc = swoole_get_property(zobject, 0);
    if (hcc->defer && hcc->defer_status != HTTP_CLIENT_STATE_DEFER_WAIT)
    {
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_DONE;
        hcc->defer_result = 0;
        goto free_zdata;
    }

    hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
    hcc->cid = 0;
    int ret = coro_resume(ctx, zdata, &retval);
    if (ret > 0)
    {
        goto free_zdata;
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

void swoole_http_client_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http_client_coro_ce, "Swoole\\Coroutine\\Http\\Client", swoole_http_client_coro_methods);
    swoole_http_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_http_client_coro_ce TSRMLS_CC);

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Http\\Client", swoole_http_client_coro_class_entry_ptr);
    }

    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http_client_coro_class_entry_ptr, SW_STRL("reuse")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("reuseCount")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("statusCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("host")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, SW_STRL("port")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("requestMethod")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("requestHeaders")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("requestBody")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("uploadFiles")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("cookies")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, SW_STRL("body")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(2048);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

/**
 * @zobject: swoole_http_client_coro object
 */
static void http_client_coro_onClose(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    zend_bool result = 0;

    zend_update_property_bool(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);

    swTraceLog(SW_TRACE_HTTP_CLIENT, "connection close, object handle=%d, state=%d", sw_get_object_handle(zobject), http->state);

    if (!http)
    {
        return;
    }

    if (http->state == HTTP_CLIENT_STATE_WAIT_CLOSE)
    {
        http_client_parser_on_message_complete(&http->parser);
        result = 1;
        goto _resume;
    }

    if (http->state != HTTP_CLIENT_STATE_BUSY)
    {
        return;
    }

    if (cli->released)
    {
        return;
    }

    _resume: http_client_free(zobject TSRMLS_CC);

    http_client_property *hcc = swoole_get_property(zobject, 0);

    if (hcc->defer && hcc->defer_status != HTTP_CLIENT_STATE_DEFER_WAIT)
    {
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_DONE;
        hcc->defer_result = 0;
        return;
    }

    hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
    zval *retval = NULL;
    zval *zdata = NULL;

    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, result);

    php_context *sw_current_context = swoole_get_property(zobject, 1);
    hcc->cid = 0;
    coro_resume(sw_current_context, zdata, &retval);

    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&zdata);
}

static int http_client_coro_onMessage(swConnection *conn, char *data, uint32_t length)
{
    swClient *cli = conn->object;
    zval *zobject = cli->object;
    zval *retval = NULL;
    zval *zframe;

    swString msg;
    msg.str = data;
    msg.length = length;

    http_client *http = swoole_get_object(zobject);
    if (http->timer)
    {
        swTimer_del(&SwooleG.timer, http->timer);
        http->timer = NULL;
    }

    http_client_property *hcc = swoole_get_property(zobject, 0);
    if (hcc->defer_status != HTTP_CLIENT_STATE_DEFER_WAIT)
    {
        SW_ALLOC_INIT_ZVAL(zframe);
        php_swoole_websocket_unpack(&msg, zframe TSRMLS_CC);
        swLinkedList_append(hcc->message_queue, zframe);
        /**
         * Too many queued messages
         */
        if (hcc->message_queue->num > SW_WEBSOCKET_QUEUE_SIZE)
        {
            swClient_sleep(cli);
        }
        return SW_OK;
    }

    php_context *sw_current_context = swoole_get_property(zobject, 1);
    hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
    hcc->cid = 0;

    SW_MAKE_STD_ZVAL(zframe);
    php_swoole_websocket_unpack(&msg, zframe TSRMLS_CC);

    int ret = coro_resume(sw_current_context, zframe, &retval);
    if (ret > 0)
    {
        goto free_zdata;
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata: sw_zval_ptr_dtor(&zframe);
    return SW_OK;
}

/**
 * @zobject: swoole_http_client object
 */
static void http_client_coro_onError(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    zval *zdata;
    zval *retval = NULL;

    SW_MAKE_STD_ZVAL(zdata);
    //return false
    ZVAL_BOOL(zdata, 0);

    zval *zobject = cli->object;
    php_context *sw_current_context = swoole_get_property(zobject, 1);
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("statusCode"), -1 TSRMLS_CC);

    swTraceLog(SW_TRACE_HTTP_CLIENT, "connect error, object handle=%d", sw_get_object_handle(zobject));

    http_client *http = swoole_get_object(zobject);
    http->timer = NULL;
    if (!cli->released)
    {
        http_client_free(zobject TSRMLS_CC);
    }

    http_client_property *hcc = swoole_get_property(zobject, 0);
    if (hcc->defer && hcc->defer_status != HTTP_CLIENT_STATE_DEFER_WAIT)
    {
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_DONE;
        hcc->defer_result = 0;
        goto free_zdata;
    }

    hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
    hcc->cid = 0;

    int ret = coro_resume(sw_current_context, zdata, &retval);
    if (ret > 0)
    {
        goto free_zdata;
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void http_client_coro_onReceive(swClient *cli, char *data, uint32_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    zval *retval = NULL;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client_coro.");
        return;
    }

    if (http->header_completed == 0)
    {
        swString *buffer = cli->buffer;
        buffer->length += length;

        //HTTP/1.1 200 OK
        if (buffer->length < 16)
        {
            return;
        }
        //No header
        if (swoole_strnpos(buffer->str + buffer->offset, buffer->length - buffer->offset, ZEND_STRL("\r\n\r\n")) < 0)
        {
            if (buffer->length == buffer->size)
            {
                swSysError("Wrong http response.");
                cli->close(cli);
                return;
            }
            buffer->offset = buffer->length - 4 <= 0 ? 0 : buffer->length - 4;
            return;
        }
        else
        {
            http->header_completed = 1;
            data = buffer->str;
            length = buffer->length;
            swString_clear(buffer);
        }
    }

    long parsed_n = php_http_parser_execute(&http->parser, &http_parser_settings, data, length);

    swDebug("parsed_n=%ld, data_length=%d.", parsed_n, length);

    http_client_property *hcc = swoole_get_property(zobject, 0);
    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);

    if (parsed_n < 0)
    {
        //return false
        ZVAL_BOOL(zdata, 0);
        if (http->timer)
        {
            swTimer_del(&SwooleG.timer, http->timer);
            http->timer = NULL;
        }
        if (hcc->defer && hcc->defer_status != HTTP_CLIENT_STATE_DEFER_WAIT)
        {
            //not recv yet  sava data
            hcc->defer_status = HTTP_CLIENT_STATE_DEFER_DONE;
            hcc->defer_result = 0;
            goto free_zdata;
            //wait for recv
        }
        goto begin_resume;
    }

    //not complete
    if (!http->completed)
    {
        return;
    }

//    if (!hcc->defer_chunk_status)
//    {
//        //not recv all wait for next
//        return;
//    }

    //timeout
    if (http->timer)
    {
        swTimer_del(&SwooleG.timer, http->timer);
        http->timer = NULL;
    }

    ZVAL_BOOL(zdata, 1); //return false
    if (hcc->defer && hcc->defer_status != HTTP_CLIENT_STATE_DEFER_WAIT)
    {
        //not recv yet  sava data
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_DONE;
        hcc->defer_result = 1;
        goto free_zdata;
    }

    /**
     * TODO: Sec-WebSocket-Accept check
     */
    if (http->upgrade)
    {
        cli->open_length_check = 1;
        cli->protocol.get_package_length = swWebSocket_get_package_length;
        cli->protocol.onPackage = http_client_coro_onMessage;
        cli->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t);
        http->state = HTTP_CLIENT_STATE_UPGRADE;
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
        /**
         * websocket message queue
         */
        hcc->message_queue = swLinkedList_new(16, NULL);

        if (http->upgrade)
        {
            //data frame
            if (length > parsed_n + 3)
            {
                cli->buffer->length = length - parsed_n - 1;
                memmove(cli->buffer->str, data + parsed_n + 1, cli->buffer->length);
                cli->socket->skip_recv = 1;
                swProtocol_recv_check_length(&cli->protocol, cli->socket, cli->buffer);
            }
            else
            {
                swString_clear(cli->buffer);
            }
        }
    }

    begin_resume:
    {
        //if should resume
        /*if next cr*/
        php_context *sw_current_context = swoole_get_property(zobject, 1);
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
        hcc->cid = 0;
        //hcc->defer_chunk_status = 0;
        http->completed = 0;
        http->state = HTTP_CLIENT_STATE_READY;

        int ret = coro_resume(sw_current_context, zdata, &retval);
        if (ret > 0)
        {
            goto free_zdata;
        }
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void http_client_coro_onConnect(swClient *cli)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client_coro.");
        return;
    }
    zend_update_property_bool(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("connected"), 1 TSRMLS_CC);
    http_client_coro_send_http_request(zobject TSRMLS_CC);
}

static int http_client_coro_send_http_request(zval *zobject TSRMLS_DC)
{
    int ret;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli || !http->cli->socket )
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }

    if (http->cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        return SW_ERR;
    }

    if (http->state != HTTP_CLIENT_STATE_READY)
    {
        swoole_php_error(E_WARNING, "http client is not ready.");
        return SW_ERR;
    }

    http->state = HTTP_CLIENT_STATE_BUSY;
    //clear errno
    SwooleG.error = 0;

    http_client_property *hcc = swoole_get_property(zobject, 0);

    zval *post_data = hcc->request_body;
    zval *send_header = hcc->request_header;
    zval *value = NULL;

    //POST
    if (post_data)
    {
        if (hcc->request_method == NULL)
        {
            hcc->request_method = "POST";
        }
    }
    //GET
    else
    {
        if (hcc->request_method == NULL)
        {
            hcc->request_method = "GET";
        }
    }

    http->method = swHttp_get_method(hcc->request_method, strlen(hcc->request_method) + 1);

    swString_clear(http_client_buffer);
    swString_append_ptr(http_client_buffer, hcc->request_method, strlen(hcc->request_method));
    hcc->request_method = NULL;
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));

#ifdef SW_USE_OPENSSL
    if (http->cli->http_proxy && !http->cli->open_ssl)
#else
    if (http->cli->http_proxy)
#endif
    {
        sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value); //checked before
        char *pre = "http://";
        int len = http->uri_len + Z_STRLEN_P(value) + strlen(pre) + 10;
        void *addr = emalloc(http->uri_len + Z_STRLEN_P(value) + strlen(pre) + 10);
        http->uri_len = snprintf(addr, len, "%s%s:%d%s", pre, Z_STRVAL_P(value), http->port, http->uri);
        efree(http->uri);
        http->uri = addr;
    }

    swString_append_ptr(http_client_buffer, http->uri, http->uri_len);
    swString_append_ptr(http_client_buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    char *key;
    uint32_t keylen;
    int keytype;

    if (send_header && Z_TYPE_P(send_header) == IS_ARRAY)
    {
        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Connection"), (void **) &value) == FAILURE)
        {
            if (http->keep_alive)
            {
                http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
            }
            else
            {
                http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
            }
        }

        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
        }

#ifdef SW_HAVE_ZLIB
        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Accept-Encoding"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
        }
#endif

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(send_header), key, keylen, keytype, value)
        if (HASH_KEY_IS_STRING != keytype)
        {
            continue;
        }
        convert_to_string(value);
        http_client_swString_append_headers(http_client_buffer, key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
        SW_HASHTABLE_FOREACH_END();
    }
    else
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        http->keep_alive = 1;
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
#ifdef SW_HAVE_ZLIB
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
#endif
    }

    if (hcc->cookies && Z_TYPE_P(hcc->cookies) == IS_ARRAY)
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("Cookie: "));
        int n_cookie = Z_ARRVAL_P(hcc->cookies)->nNumOfElements;
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->cookies), key, keylen, keytype, value)
            i ++;
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            if (Z_STRLEN_P(value) == 0)
            {
                continue;
            }
            swString_append_ptr(http_client_buffer, key, keylen);
            swString_append_ptr(http_client_buffer, "=", 1);

            int encoded_value_len;
            encoded_value = sw_php_url_encode(Z_STRVAL_P(value), Z_STRLEN_P(value), &encoded_value_len);
            if (encoded_value)
            {
                swString_append_ptr(http_client_buffer, encoded_value, encoded_value_len);
                efree(encoded_value);
            }
            if (i < n_cookie)
            {
                swString_append_ptr(http_client_buffer, "; ", 2);
            }
        SW_HASHTABLE_FOREACH_END();
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    //form-data
    if (hcc->request_upload_files)
    {
        char header_buf[2048];
        char boundary_str[39];
        int n;

        memcpy(boundary_str, SW_HTTP_CLIENT_BOUNDARY_PREKEY, sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1);
        swoole_random_string(boundary_str + sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1,
                sizeof(boundary_str) - sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY));

        n = snprintf(header_buf, sizeof(header_buf), "Content-Type: multipart/form-data; boundary=%*s\r\n",
                sizeof(boundary_str) - 1, boundary_str);

        swString_append_ptr(http_client_buffer, header_buf, n);

        int content_length = 0;

        //post data
        if (post_data && Z_TYPE_P(post_data) == IS_ARRAY)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(post_data), key, keylen, keytype, value)
                if (HASH_KEY_IS_STRING != keytype)
                {
                    continue;
                }
                convert_to_string(value);
                //strlen("%.*")*2 = 6
                //header + body + CRLF
                content_length += (sizeof(SW_HTTP_FORM_DATA_FORMAT_STRING) - 7) + (sizeof(boundary_str) - 1) + keylen
                        + Z_STRLEN_P(value) + 2;
            SW_HASHTABLE_FOREACH_END();
        }

        zval *zname;
        zval *ztype;
        zval *zsize = NULL;
        zval *zpath;
        zval *zfilename;
        zval *zoffset;

        if (hcc->request_upload_files)
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->request_upload_files), key, keylen, keytype, value)
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("name"), (void **) &zname) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("filename"), (void **) &zfilename) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("size"), (void **) &zsize) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("type"), (void **) &ztype) == FAILURE)
                {
                    continue;
                }
                //strlen("%.*")*4 = 12
                //header + body + CRLF
                content_length += (sizeof(SW_HTTP_FORM_DATA_FORMAT_FILE) - 13) + (sizeof(boundary_str) - 1)
                        + Z_STRLEN_P(zname) + Z_STRLEN_P(zfilename) + Z_STRLEN_P(ztype) + Z_LVAL_P(zsize) + 2;
            SW_HASHTABLE_FOREACH_END();
        }

        http_client_append_content_length(http_client_buffer, content_length + sizeof(boundary_str) - 1 + 6);

        //post data
        if (post_data && Z_TYPE_P(post_data) == IS_ARRAY)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(post_data), key, keylen, keytype, value)
                if (HASH_KEY_IS_STRING != keytype)
                {
                    continue;
                }
                convert_to_string(value);
                n = snprintf(header_buf, sizeof(header_buf), SW_HTTP_FORM_DATA_FORMAT_STRING, sizeof(boundary_str) - 1,
                        boundary_str, keylen, key);
                swString_append_ptr(http_client_buffer, header_buf, n);
                swString_append_ptr(http_client_buffer, Z_STRVAL_P(value), Z_STRLEN_P(value));
                swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
            SW_HASHTABLE_FOREACH_END();

            zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestBody") TSRMLS_CC);
            hcc->request_body = NULL;
        }

        if ((ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0)) < 0)
        {
            goto send_fail;
        }

        if (hcc->request_upload_files)
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->request_upload_files), key, keylen, keytype, value)
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("name"), (void **) &zname) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("filename"), (void **) &zfilename) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("path"), (void **) &zpath) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("type"), (void **) &ztype) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("offset"), (void **) &zoffset) == FAILURE)
                {
                    continue;
                }
                n = snprintf(header_buf, sizeof(header_buf), SW_HTTP_FORM_DATA_FORMAT_FILE, sizeof(boundary_str) - 1,
                        boundary_str, Z_STRLEN_P(zname), Z_STRVAL_P(zname), Z_STRLEN_P(zfilename),
                        Z_STRVAL_P(zfilename), Z_STRLEN_P(ztype), Z_STRVAL_P(ztype));

                if ((ret = http->cli->send(http->cli, header_buf, n, 0)) < 0)
                {
                    goto send_fail;
                }
                if ((ret = http->cli->sendfile(http->cli, Z_STRVAL_P(zpath), Z_LVAL_P(zoffset), Z_LVAL_P(zsize))) < 0)
                {
                    goto send_fail;
                }
                if ((ret = http->cli->send(http->cli, "\r\n", 2, 0)) < 0)
                {
                    goto send_fail;
                }
            SW_HASHTABLE_FOREACH_END();

            zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("uploadFiles") TSRMLS_CC);
            hcc->request_upload_files = NULL;
        }

        n = snprintf(header_buf, sizeof(header_buf), "--%*s--\r\n", sizeof(boundary_str) - 1, boundary_str);
        if ((ret = http->cli->send(http->cli, header_buf, n, 0)) < 0)
        {
            goto send_fail;
        }
        else
        {
            return SW_OK;
        }
    }
    //x-www-form-urlencoded or raw
    else if (post_data)
    {
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            zend_size_t len;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            smart_str formstr_s = { 0 };
            char *formstr = sw_http_build_query(post_data, &len, &formstr_s TSRMLS_CC);
            if (formstr == NULL)
            {
                swoole_php_error(E_WARNING, "http_build_query failed.");
                return SW_ERR;
            }
            http_client_append_content_length(http_client_buffer, len);
            swString_append_ptr(http_client_buffer, formstr, len);
            smart_str_free(&formstr_s);
        }
        else
        {
            http_client_append_content_length(http_client_buffer, Z_STRLEN_P(post_data));
            swString_append_ptr(http_client_buffer, Z_STRVAL_P(post_data), Z_STRLEN_P(post_data));
        }
        zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestBody") TSRMLS_CC);
        hcc->request_body = NULL;
    }
    else
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    swTrace("[%d]: %s\n", (int)http_client_buffer->length, http_client_buffer->str);

    if (http->timeout > 0)
    {
        php_context *context = swoole_get_property(zobject, 1);
        http->timer = SwooleG.timer.add(&SwooleG.timer, (int) (http->timeout * 1000), 0, context, http_client_coro_onTimeout);
        if (http->timer && hcc->defer)
        {
            context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
        }
    }

    if ((ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0)) < 0)
    {
       send_fail:
       SwooleG.error = errno;
       swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", http->cli->socket->fd, (int )http_client_buffer->length);
       zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
    }
    return ret;
}

static PHP_METHOD(swoole_http_client_coro, __construct)
{
    coro_check(TSRMLS_C);

    char *host;
    zend_size_t host_len;
    long port = 80;
    zend_bool ssl = SW_FALSE;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &host, &host_len, &port, &ssl) == FAILURE)
    {
        return;
    }

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_ERROR, "host is empty.");
        RETURN_FALSE;
    }

    zend_update_property_stringl(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len TSRMLS_CC);
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr,getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    //init
    swoole_set_object(getThis(), NULL);

    zval *headers;
    SW_MAKE_STD_ZVAL(headers);
    array_init(headers);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("headers"), headers TSRMLS_CC);
    sw_zval_ptr_dtor(&headers);

    http_client_property *hcc;
    hcc = (http_client_property*) emalloc(sizeof(http_client_property));
    bzero(hcc, sizeof(http_client_property));
    hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
   // hcc->defer_chunk_status = 0;
    swoole_set_property(getThis(), 0, hcc);

    int flags = SW_SOCK_TCP | SW_FLAG_ASYNC;
    if (ssl)
    {
#ifdef SW_USE_OPENSSL
        flags |= SW_SOCK_SSL;
#else
        swoole_php_fatal_error(E_ERROR, "require openssl library.");
#endif
    }

    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), flags TSRMLS_CC);

    php_context *context = emalloc(sizeof(php_context));
    swoole_set_property(getThis(), 1, context);

    context->onTimeout = NULL;
#if PHP_MAJOR_VERSION < 7
	context->coro_params = getThis();
#else
	context->coro_params = *getThis();
#endif
	context->state = SW_CORO_CONTEXT_RUNNING;

    swTraceLog(SW_TRACE_HTTP_CLIENT, "ctor, object handle=%d.", sw_get_object_handle(getThis()));
}

static PHP_METHOD(swoole_http_client_coro, __destruct)
{
    swTraceLog(SW_TRACE_HTTP_CLIENT, "dtor, object handle=%d.", sw_get_object_handle(getThis()));

    http_client *http = swoole_get_object(getThis());
    if (http)
    {
        zval *zobject = getThis();
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, swoole_http_client_coro_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc)
    {
        if (hcc->message_queue)
        {
            swLinkedList_free(hcc->message_queue);
        }
        efree(hcc);
        swoole_set_property(getThis(), 0, NULL);
    }

    php_context *context = swoole_get_property(getThis(), 1);
    if (context)
    {
        efree(context);
        swoole_set_property(getThis(), 1, NULL);
    }
}

static PHP_METHOD(swoole_http_client_coro, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    if (Z_TYPE_P(zset) != IS_ARRAY)
    {
        RETURN_FALSE;
    }
    zval *zsetting = php_swoole_read_init_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting") TSRMLS_CC);
    sw_php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders)
{
    zval *headers;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &headers) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), headers TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_header = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_header, hcc->_request_header);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setCookies)
{
    zval *cookies;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &cookies) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("cookies"), cookies TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->cookies = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("cookies"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->cookies, hcc->_cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, getDefer)
{
    http_client_property *hcc = swoole_get_property(getThis(), 0);

    RETURN_BOOL(hcc->defer);
}

static PHP_METHOD(swoole_http_client_coro, setDefer)
{
    zend_bool defer = 1;
    http_client_property *hcc = swoole_get_property(getThis(), 0);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &defer) == FAILURE)
    {
        return;
    }

    if (hcc->defer_status != HTTP_CLIENT_STATE_DEFER_INIT)
    {
        RETURN_BOOL(defer);
    }

    hcc->defer = defer;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, recv)
{
    http_client *http = swoole_get_object(getThis());
    if (!http)
    {
        RETURN_FALSE;
    }
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->cid != 0 && hcc->cid != COROG.current_coro->cid)
    {
        swoole_php_fatal_error(E_WARNING, "client has been bound to another coro");
    }

    double timeout = 0;

    //resume
    if (http->cli->sleep)
    {
        swClient_wakeup(http->cli);
    }
    //websocket
    if (http->upgrade)
    {
        if (hcc->message_queue->num > 0)
        {
            zval *msg = swLinkedList_shift(hcc->message_queue);
            if (msg)
            {
                RETVAL_ZVAL(msg, 0, 0);
                efree(msg);
                return;
            }
        }

        if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|d", &timeout) == FAILURE)
        {
            return;
        }

        goto _yield;
    }

    //no defer
    if (!hcc->defer)
    {
        swoole_php_fatal_error(E_WARNING, "you should not use recv without defer.");
        RETURN_FALSE;
    }

    switch (hcc->defer_status)
    {
    case HTTP_CLIENT_STATE_DEFER_DONE:
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_INIT;
        RETURN_BOOL(hcc->defer_result);
    case HTTP_CLIENT_STATE_DEFER_SEND:
        goto _yield;
    case HTTP_CLIENT_STATE_DEFER_INIT:
        //not ready
        swoole_php_fatal_error(E_WARNING, "you should post or get or execute before recv.");
        RETURN_FALSE;
    default:
        return;
    }

    _yield: hcc->defer_status = HTTP_CLIENT_STATE_DEFER_WAIT;
    php_context *context = swoole_get_property(getThis(), 1);

    if (timeout > 0)
    {
        php_swoole_check_timer((int) (timeout * 1000));
        http->timer = SwooleG.timer.add(&SwooleG.timer, (int) (timeout * 1000), 0, context, http_client_coro_onTimeout);
    }

    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_http_client_coro, setData)
{
    zval *data;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &data) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_body = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addFile)
{
    char *path;
    zend_size_t l_path;
    char *name;
    zend_size_t l_name;
    char *type = NULL;
    zend_size_t l_type;
    char *filename = NULL;
    zend_size_t l_filename;
    long offset = 0;
    long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|ssll", &path, &l_path, &name, &l_name, &type, &l_type,
            &filename, &l_filename, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (offset < 0)
    {
        offset = 0;
    }
    if (length < 0)
    {
        length = 0;
    }
    struct stat file_stat;
    if (stat(path, &file_stat) < 0)
    {
        swoole_php_sys_error(E_WARNING, "stat(%s) failed.", path);
        RETURN_FALSE;
    }
    if (file_stat.st_size == 0)
    {
        swoole_php_sys_error(E_WARNING, "cannot send empty file[%s].", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= offset)
    {
        swoole_php_error(E_WARNING, "parameter $offset[%ld] exceeds the file size.", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset)
    {
        swoole_php_sys_error(E_WARNING, "parameter $length[%ld] exceeds the file size.", length);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        length = file_stat.st_size - offset;
    }
    if (type == NULL)
    {
        type = swoole_get_mimetype(path);
        l_type = strlen(type);
    }
    if (filename == NULL)
    {
        char *dot = strrchr(path, '/');
        if (dot == NULL)
        {
            filename = path;
            l_filename = l_path;
        }
        else
        {
            filename = dot + 1;
            l_filename = strlen(filename);
        }
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    zval *files;
    if (!hcc->request_upload_files)
    {
        SW_MAKE_STD_ZVAL(files);
        array_init(files);
        zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), files TSRMLS_CC);
        sw_zval_ptr_dtor(&files);

        hcc->request_upload_files = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), 0 TSRMLS_CC);
        sw_copy_to_stack(hcc->request_upload_files, hcc->_request_upload_files);
    }

    zval *upload_file;
    SW_MAKE_STD_ZVAL(upload_file);
    array_init(upload_file);

    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("path"), path, l_path, 1);
    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("name"), name, l_name, 1);
    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("filename"), filename, l_filename, 1);
    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("type"), type, l_type, 1);
    add_assoc_long(upload_file, "size", length);
    add_assoc_long(upload_file, "offset", offset);

    add_next_index_zval(hcc->request_upload_files, upload_file);
    RETURN_TRUE;
}



static PHP_METHOD(swoole_http_client_coro, setMethod)
{
    zval *method;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &method) == FAILURE)
    {
        return;
    }
    convert_to_string(method);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestMethod"), method TSRMLS_CC);
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_method = Z_STRVAL_P(method);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, isConnected)
{
    http_client *http = swoole_get_object(getThis());
    if (!http || !http->cli)
    {
        RETURN_FALSE;
    }
    if (!http->cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(http->cli->socket->active);
}

static PHP_METHOD(swoole_http_client_coro, close)
{
    http_client *http = swoole_get_object(getThis());
    if (!http)
    {
        RETURN_FALSE;
    }

    swClient *cli = http->cli;
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }
    if (cli->socket->closed)
    {
        http_client_free(getThis() TSRMLS_CC);
        RETURN_FALSE;
    }

    int ret = SW_OK;
    cli->released = 1;
    ret = cli->close(cli);
    http_client_free(getThis() TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client_coro, execute)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->cid != 0 && hcc->cid != COROG.current_coro->cid)
    {
        swoole_php_fatal_error(E_WARNING, "client has been bound to another coro");
    }
    if (hcc->defer)
    {
        if (hcc->defer_status != HTTP_CLIENT_STATE_DEFER_INIT)
        {
            RETURN_FALSE;
        }
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_SEND;
    }
    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }

    php_context *context = swoole_get_property(getThis(), 1);
    if (hcc->defer)
    {
        RETURN_TRUE;
    }
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_http_client_coro, get)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->cid != 0 && hcc->cid != COROG.current_coro->cid)
    {
        swoole_php_fatal_error(E_WARNING, "client has been bound to another coro");
    }
    if (hcc->defer)
    {
        if (hcc->defer_status != HTTP_CLIENT_STATE_DEFER_INIT)
        {
            RETURN_FALSE;
        }
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_SEND;
    }
    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }

    php_context *context = swoole_get_property(getThis(), 1);
    if (hcc->defer)
    {
        RETURN_TRUE;
    }
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_http_client_coro, post)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *post_data;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &post_data) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(post_data) != IS_ARRAY && Z_TYPE_P(post_data) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "post data must be string or array.");
        RETURN_FALSE;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), post_data TSRMLS_CC);
    hcc->request_body = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_body, hcc->_request_body);
    if (hcc->cid != 0 && hcc->cid != COROG.current_coro->cid)
    {
        swoole_php_fatal_error(E_WARNING, "client has been bound to another coro");
    }

    if (hcc->defer)
    {
        if (hcc->defer_status != HTTP_CLIENT_STATE_DEFER_INIT)
        {
            RETURN_FALSE;
        }
        hcc->defer_status = HTTP_CLIENT_STATE_DEFER_SEND;
    }
    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }

    php_context *context = swoole_get_property(getThis(), 1);
    if (hcc->defer)
    {
        RETURN_TRUE;
    }
    hcc->cid = COROG.current_coro->cid;
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_http_client_coro, upgrade)
{
    int ret;
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->cid != 0 && hcc->cid != COROG.current_coro->cid)
    {
        swoole_php_fatal_error(E_WARNING, "client has been bound to another coro");
    }

    zval *headers = hcc->request_header;
    if (hcc->request_header == NULL)
    {
        headers = php_swoole_read_init_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders") TSRMLS_CC);
        hcc->request_header = headers;
        sw_copy_to_stack(hcc->request_header, hcc->_request_header);
    }

    char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
    http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);

    sw_add_assoc_string(headers, "Connection", "Upgrade", 1);
    sw_add_assoc_string(headers, "Upgrade", "websocket", 1);
    sw_add_assoc_string(headers, "Sec-WebSocket-Version", SW_WEBSOCKET_VERSION, 1);

#if PHP_MAJOR_VERSION < 7
    int encoded_value_len = 0;
    uchar *encoded_value = php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH, &encoded_value_len);
    add_assoc_stringl_ex(headers, ZEND_STRS("Sec-WebSocket-Key"), (char* )encoded_value, encoded_value_len, 0);
#else
    zend_string *str = php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH);
    add_assoc_str_ex(headers, ZEND_STRL("Sec-WebSocket-Key"), str);
#endif

    ret = http_client_coro_execute(getThis(), uri, uri_len TSRMLS_CC);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }

    php_context *context = swoole_get_property(getThis(), 1);
    if (hcc->defer)
    {
        RETURN_TRUE;
    }
    hcc->cid = COROG.current_coro->cid;
    coro_save(context);
    coro_yield();
}

static PHP_METHOD(swoole_http_client_coro, push)
{
    char *data;
    zend_size_t length;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &data, &length, &opcode, &fin) == FAILURE)
    {
        return;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swoole_php_fatal_error(E_WARNING, "opcode max 10");
        SwooleG.error = SW_ERROR_WEBSOCKET_BAD_OPCODE;
        RETURN_FALSE;
    }

    http_client *http = swoole_get_object(getThis());
    if (!(http && http->cli && http->cli->socket))
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        SwooleG.error = SW_ERROR_WEBSOCKET_UNCONNECTED;
        RETURN_FALSE;
    }

    if (!http->upgrade)
    {
        swoole_php_fatal_error(E_WARNING, "websocket handshake failed, cannot push data.");
        SwooleG.error = SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED;
        RETURN_FALSE;
    }

    swString_clear(http_client_buffer);
    swWebSocket_encode(http_client_buffer, data, length, opcode, (int) fin, http->websocket_mask);
    SW_CHECK_RETURN(http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0));
}

#endif
