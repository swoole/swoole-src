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
#include "swoole_http.h"

#include <ext/standard/url.h>
#include <ext/standard/sha1.h>
#include <ext/standard/php_var.h>
#include <ext/standard/php_string.h>
#include <ext/date/php_date.h>
#include <main/php_variables.h>

#include "websocket.h"
#include "Connection.h"
#include "base64.h"
#include "thirdparty/php_http_parser.h"

zend_class_entry swoole_websocket_server_ce;
zend_class_entry *swoole_websocket_server_class_entry_ptr;

zend_class_entry swoole_websocket_frame_ce;
zend_class_entry *swoole_websocket_frame_class_entry_ptr;

enum websocket_callback
{
    WEBSOCKET_CALLBACK_onOpen = 0,
    WEBSOCKET_CALLBACK_onMessage,
};

static int websocket_handshake(swoole_http_client *client);
static void sha1(const char *str, int _len, unsigned char *digest);
static zval* websocket_callbacks[2];

static PHP_METHOD(swoole_websocket_server, on);
static PHP_METHOD(swoole_websocket_server, push);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_push, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_websocket_server_methods[] =
{
    PHP_ME(swoole_websocket_server, on,         arginfo_swoole_websocket_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, push,       arginfo_swoole_websocket_server_push, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

int swoole_websocket_isset_onMessage(void)
{
    return (websocket_callbacks[WEBSOCKET_CALLBACK_onMessage] != NULL);
}

void swoole_websocket_onOpen(swoole_http_client *client)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    int fd = client->fd;

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn)
    {
        swWarn("connection[%d] is closed.", fd);
        return;
    }
    conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;

    swTrace("\n\n\n\nconn ws status:%d, fd=%d\n\n\n", conn->websocket_status, fd);

    if (websocket_callbacks[WEBSOCKET_CALLBACK_onOpen])
    {
        swTrace("\n\n\n\nhandshake success\n\n\n");

        zval **args[2];
        swServer *serv = SwooleG.serv;
        zval *zserv = (zval *) serv->ptr2;
        zval *zrequest_object = client->request.zrequest_object;
        zval *retval = NULL;

#ifdef __CYGWIN__
        //TODO: memory error on cygwin.
        sw_zval_add_ref(&zrequest_object);
#endif

        args[0] = &zserv;
        args[1] = &zrequest_object;

        if (sw_call_user_function_ex(EG(function_table), NULL, websocket_callbacks[WEBSOCKET_CALLBACK_onOpen], &retval, 2, args, 0,  NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onOpen handler error");
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
}

static void sha1(const char *str, int _len, unsigned char *digest)
{
    PHP_SHA1_CTX context;
    PHP_SHA1Init(&context);
    PHP_SHA1Update(&context, (unsigned char *) str, _len);
    PHP_SHA1Final(digest, &context);
}

static int websocket_handshake(swoole_http_client *client)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *header = client->request.zheader;
    HashTable *ht = Z_ARRVAL_P(header);
    zval *pData;

    if (sw_zend_hash_find(ht, ZEND_STRS("sec-websocket-key"), (void **) &pData) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "header no sec-websocket-key");
        return SW_ERR;
    }
    convert_to_string(pData);

    swString_clear(swoole_http_buffer);
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"));

    int n;
    char sec_websocket_accept[128];
    memcpy(sec_websocket_accept, Z_STRVAL_P(pData), Z_STRLEN_P(pData));
    memcpy(sec_websocket_accept + Z_STRLEN_P(pData), SW_WEBSOCKET_GUID, sizeof(SW_WEBSOCKET_GUID) - 1);

    char sha1_str[20];
    bzero(sha1_str, sizeof(sha1_str));
    sha1(sec_websocket_accept, Z_STRLEN_P(pData) + sizeof(SW_WEBSOCKET_GUID) - 1, (unsigned char *) sha1_str);

    char encoded_str[50];
    bzero(encoded_str, sizeof(encoded_str));
    n = swBase64_encode((unsigned char *) sha1_str, sizeof(sha1_str), encoded_str);

    char _buf[128];
    n = snprintf(_buf, sizeof(_buf), "Sec-WebSocket-Accept: %*s\r\n", n, encoded_str);

    swString_append_ptr(swoole_http_buffer, _buf, n);
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("Sec-WebSocket-Version: "SW_WEBSOCKET_VERSION"\r\n"));
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("Server: "SW_WEBSOCKET_SERVER_SOFTWARE"\r\n\r\n"));

    swTrace("websocket header len:%ld\n%s \n", swoole_http_buffer->length, swoole_http_buffer->str);

    return swServer_tcp_send(SwooleG.serv, client->fd, swoole_http_buffer->str, swoole_http_buffer->length);
}

int swoole_websocket_onMessage(swEventData *req)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    int fd = req->info.fd;
    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    zdata = php_swoole_get_recv_data(zdata, req TSRMLS_CC);

    char *buf = Z_STRVAL_P(zdata);
    long finish = buf[0] ? 1 : 0;
    long opcode = buf[1] ? 1 : 0;

    zval *zframe;
    SW_MAKE_STD_ZVAL(zframe);
    object_init_ex(zframe, swoole_websocket_frame_class_entry_ptr);

    zend_update_property_long(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("fd"), fd TSRMLS_CC);
    zend_update_property_long(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("finish"), finish TSRMLS_CC);
    zend_update_property_long(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("opcode"), opcode TSRMLS_CC);
    zend_update_property_stringl(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("data"), buf + 2, (Z_STRLEN_P(zdata) - 2) TSRMLS_CC);

    swServer *serv = SwooleG.serv;
    zval *zserv = (zval *) serv->ptr2;

    zval **args[2];
    args[0] = &zserv;
    args[1] = &zframe;

    zval *retval = NULL;

    if (sw_call_user_function_ex(EG(function_table), NULL, websocket_callbacks[WEBSOCKET_CALLBACK_onMessage], &retval, 2,
            args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onMessage handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&zdata);
    sw_zval_ptr_dtor(&zframe);

    return SW_OK;
}

int swoole_websocket_onHandshake(swoole_http_client *client)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    int fd = client->fd;
    int ret = websocket_handshake(client);
    if (ret == SW_ERR)
    {
        swTrace("websocket handshake error\n");
        SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
        return SW_ERR;
    }
    swoole_websocket_onOpen(client);
    if (!client->end)
    {
        swoole_http_request_free(client TSRMLS_CC);
    }
    return SW_OK;
}

void swoole_websocket_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_websocket_server_ce, "swoole_websocket_server", swoole_websocket_server_methods);
    swoole_websocket_server_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_websocket_server_ce, swoole_http_server_class_entry_ptr, "swoole_http_server" TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_websocket_frame_ce, "swoole_websocket_frame", NULL);
    swoole_websocket_frame_class_entry_ptr = zend_register_internal_class(&swoole_websocket_frame_ce TSRMLS_CC);

    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_TEXT", WEBSOCKET_OPCODE_TEXT_FRAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_BINARY", WEBSOCKET_OPCODE_BINARY_FRAME, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CONNECTION", WEBSOCKET_STATUS_CONNECTION, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_HANDSHAKE", WEBSOCKET_STATUS_HANDSHAKE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_FRAME", WEBSOCKET_STATUS_FRAME, CONST_CS | CONST_PERSISTENT);
}

static PHP_METHOD( swoole_websocket_server, on)
{
    zval *callback;
    zval *event_name;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &event_name, &callback) == FAILURE)
    {
        return;
    }

    swServer *serv = swoole_get_object(getThis());

    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

#if PHP_MAJOR_VERSION >= 7
    zval *callback_copy = emalloc(sizeof(zval));
    memcpy(callback_copy, callback, sizeof(zval));
    callback = callback_copy;
#endif

    serv->open_websocket_protocol = 1;

    if (strncasecmp("open", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        sw_zval_add_ref(&callback);
        websocket_callbacks[0] = callback;
    }
    else if (strncasecmp("message", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        sw_zval_add_ref(&callback);
        websocket_callbacks[1] = callback;
    }
    else
    {
        zval *obj = getThis();
        sw_zend_call_method_with_2_params(&obj, swoole_http_server_class_entry_ptr, NULL, "on", &return_value, event_name, callback);
    }
}

static PHP_METHOD(swoole_websocket_server, push)
{
    zval *zdata;
    long fd = 0;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|lb", &fd, &zdata, &opcode, &fin) == FAILURE)
    {
        return;
    }

    if (fd <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "fd[%d] is invalid.", (int )fd);
        RETURN_FALSE;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swoole_php_fatal_error(E_WARNING, "opcode max 10");
        RETURN_FALSE;
    }

    char *data;
    int length = php_swoole_get_send_data(zdata, &data TSRMLS_CC);

    if (length < 0)
    {
        RETURN_FALSE;
    }
    else if (length == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn || conn->websocket_status < WEBSOCKET_STATUS_HANDSHAKE)
    {
        swoole_php_fatal_error(E_WARNING, "connection[%d] is not a websocket client.", (int ) fd);
        RETURN_FALSE;
    }
    swString_clear(swoole_http_buffer);
    swWebSocket_encode(swoole_http_buffer, data, length, opcode, (int) fin, 0);
    SW_CHECK_RETURN(swServer_tcp_send(SwooleG.serv, fd, swoole_http_buffer->str, swoole_http_buffer->length));
}
