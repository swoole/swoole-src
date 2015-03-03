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

static zval* php_sw_websocket_server_callbacks[2];

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, ha_name)
    ZEND_ARG_INFO(0, cb)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_websocket_server_methods[] =
{
    PHP_ME(swoole_websocket_server, on,         arginfo_swoole_websocket_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, push,       NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

int php_swoole_websocket_isset_onMessage()
{
    int ret = 0;
    if (php_sw_websocket_server_callbacks[1] != NULL)
        ret = 1;
    return ret;
}

void php_swoole_websocket_onOpen(int fd)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn)
    {
        swWarn("connection[%d] is closed.", fd);
        return;
    }
    if (conn->websocket_status == WEBSOCKET_STATUS_CONNECTION)
    {
        conn->websocket_status = WEBSOCKET_STATUS_HANDSHAKE;
    }

    swTrace("\n\n\n\nconn ws status:%d, fd=%d\n\n\n", conn->websocket_status, fd);

    if (php_sw_websocket_server_callbacks[0] != NULL)
    {
        swTrace("\n\n\n\nhandshake success\n\n\n");

	zval **args[2];
	swServer *serv = SwooleG.serv;
	zval *zserv = (zval *)serv->ptr2;
	zval *zfd;
	MAKE_STD_ZVAL(zfd);
	ZVAL_LONG(zfd, fd);		
	args[0] = &zserv;
	args[1] = &zfd;
	zval *retval;

	if (call_user_function_ex(EG(function_table), NULL, php_sw_websocket_server_callbacks[0], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onMessage handler error");
        }
        swTrace("===== message callback end======");
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            zval_ptr_dtor(&retval);
        }
    }
}

int php_swoole_websocket_onMessage(swEventData *req TSRMLS_DC)
{
	int fd = req->info.fd;
	zval *zdata = php_swoole_get_data(req TSRMLS_CC);

	char *buf = Z_STRVAL_P(zdata);
	long fin = buf[0] ? 1 : 0;
	long opcode = buf[1] ? 1 : 0;

	buf += 2;

	swServer *serv = SwooleG.serv;
	zval *zserv = (zval *)serv->ptr2;
	zval *zd, *zfd, *zopcode, *zfin;

	MAKE_STD_ZVAL(zd);
	MAKE_STD_ZVAL(zfd);
	MAKE_STD_ZVAL(zopcode);
	MAKE_STD_ZVAL(zfin);

	SW_ZVAL_STRINGL(zd, buf, Z_STRLEN_P(zdata) - 2, 1);
	ZVAL_LONG(zfd, fd);
	ZVAL_LONG(zopcode, opcode);
	ZVAL_LONG(zfin, fin);

	zval **args[5];
	args[0] = &zserv;
	args[1] = &zfd;
	args[2] = &zd;
	args[3] = &zopcode;
	args[4] = &zfin;
	zval *retval;

	if (call_user_function_ex(EG(function_table), NULL, php_sw_websocket_server_callbacks[1], &retval, 5, args, 0, NULL
            TSRMLS_CC) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "onMessage handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        zval_ptr_dtor(&retval);
    }
    zval_ptr_dtor(&zdata);
    zval_ptr_dtor(&zfd);
    zval_ptr_dtor(&zd);
    zval_ptr_dtor(&zopcode);
    zval_ptr_dtor(&zfin);
    zval_ptr_dtor(&zserv);

    return SW_OK;
}

void swoole_websocket_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_websocket_server_ce, "swoole_websocket_server", swoole_websocket_server_methods);
    swoole_websocket_server_class_entry_ptr = zend_register_internal_class_ex(&swoole_websocket_server_ce, swoole_http_server_class_entry_ptr, "swoole_http_server" TSRMLS_CC);

    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_TEXT", WEBSOCKET_OPCODE_TEXT_FRAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_BINARY", WEBSOCKET_OPCODE_BINARY_FRAME, CONST_CS | CONST_PERSISTENT);
}

PHP_METHOD( swoole_websocket_server, on)
{
    zval *callback;
    zval *event_name;
    swServer *serv;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &event_name, &callback) == FAILURE)
    {
        return;
    }

    SWOOLE_GET_SERVER(getThis(), serv);

    char *func_name = NULL;
    if (!zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    serv->open_websocket_protocol = 1;

    if (strncasecmp("open", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_websocket_server_callbacks[0] = callback;
    }
    else if (strncasecmp("message", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zval_add_ref(&callback);
        php_sw_websocket_server_callbacks[1] = callback;
    }
    else
    {
        zend_call_method_with_2_params(&getThis(), swoole_http_server_class_entry_ptr, NULL, "on", &return_value, event_name, callback);
    }
}


PHP_METHOD(swoole_websocket_server, push)
{
    swString data;
    data.length = 0;
    long fd = 0;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls|lb", &fd, &data.str, &data.length, &opcode, &fin) == FAILURE)
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

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn || conn->websocket_status < WEBSOCKET_STATUS_HANDSHAKE)
    {
        swoole_php_fatal_error(E_WARNING, "connection[%d] is not a websocket client.", (int ) fd);
        RETURN_FALSE;
    }

    swTrace("need send:%s len:%zd\n", data.str, data.length);
    swString *response = swWebSocket_encode(&data, opcode, (int) fin);
    int ret = swServer_tcp_send(SwooleG.serv, fd, response->str, response->length);
    swTrace("need send:%s len:%zd\n", response->str, response->length);
    swString_free(response);
    SW_CHECK_RETURN(ret);
}

