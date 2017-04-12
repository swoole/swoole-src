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

typedef enum {SW_CLIENT_CORO_STATUS_CLOSED, SW_CLIENT_CORO_STATUS_READY, SW_CLIENT_CORO_STATUS_WAIT, SW_CLIENT_CORO_STATUS_DONE} swoole_client_coro_io_status;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _object;
#endif
    swoole_client_coro_io_status iowait;
    swLinkedList_node *timeout_node;
    swString *result;
} swoole_client_coro_property;

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
static PHP_METHOD(swoole_client_coro, isConnected);
static PHP_METHOD(swoole_client_coro, getsockname);
static PHP_METHOD(swoole_client_coro, getpeername);
static PHP_METHOD(swoole_client_coro, close);

void php_swoole_client_coro_free(zval *zobject, swClient *cli TSRMLS_DC);

static void client_onConnect(swClient *cli);
static void client_onReceive(swClient *cli, char *data, uint32_t length);
static int client_onPackage(swConnection *conn, char *data, uint32_t length);
static void client_onClose(swClient *cli);
static void client_onError(swClient *cli);

static const zend_function_entry swoole_client_coro_methods[] =
{
    PHP_ME(swoole_client_coro, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client_coro, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client_coro, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recv, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, send, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendfile, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendto, NULL, ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client_coro, enableSSL, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getPeerCert, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, verifyPeerCert, NULL, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client_coro, isConnected, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getsockname, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getpeername, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, close, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

zend_class_entry swoole_client_coro_ce;
zend_class_entry *swoole_client_coro_class_entry_ptr;

static sw_inline void client_execute_callback(zval *zobject, enum php_swoole_client_callback_type type)
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

    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_OOB"), MSG_OOB TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_PEEK"), MSG_PEEK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL TSRMLS_CC);
}

static void client_coro_onTimeout(php_context *ctx)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zdata = NULL;
    zval *retval = NULL;

#if PHP_MAJOR_VERSION < 7
    zval *zobject = (zval *)ctx->coro_params;
#else
    zval _zobject = ctx->coro_params;
    zval *zobject = & _zobject;
#endif
    zend_update_property_long(swoole_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), 110 TSRMLS_CC);

    swClient *cli = swoole_get_object(zobject);
    cli->timeout_id = 0;

    //timeout close connection
    //sw_zend_call_method_with_0_params(&zobject, swoole_client_coro_class_entry_ptr, NULL, "close", &retval);
    //if (retval)
    //{
    //    sw_zval_ptr_dtor(&retval);
    //}

    SW_MAKE_STD_ZVAL(zdata);
    ZVAL_BOOL(zdata, 0);
    int ret = coro_resume(ctx, zdata, &retval);
	if (ret == CORO_END && retval)
	{
		sw_zval_ptr_dtor(&retval);
	}
	sw_zval_ptr_dtor(&zdata);
}


static int client_onPackage(swConnection *conn, char *data, uint32_t length)
{
    client_onReceive(conn->object, data, length);
    return SW_OK;
}

static void client_onReceive(swClient *cli, char *data, uint32_t length)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;
    swoole_client_coro_property *ccp = swoole_get_property(zobject, 1);
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
        cli->timeout_id = 0;
    }
    else if (cli->timeout > 0 && ccp->iowait == SW_CLIENT_CORO_STATUS_WAIT && ccp->timeout_node != NULL)
    {
        efree(ccp->timeout_node->data);
        swLinkedList_remove_node(SwooleWG.delayed_coro_timeout_list, ccp->timeout_node);
        ccp->timeout_node = NULL;
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
                swWarn("append package fail.");
            }
        }
        else
        {
            ccp->result = swString_dup(data, length);
            ccp->iowait = SW_CLIENT_CORO_STATUS_DONE;
        }
    }
}

static void client_onConnect(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
		cli->timeout_id = 0;
    }
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
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
		cli->timeout_id = 0;
    }
    zval *zobject = cli->object;
    if (!cli->released)
    {
        php_swoole_client_coro_free(zobject, cli TSRMLS_CC);
    }
    client_execute_callback(zobject, SW_CLIENT_CB_onClose);
#if PHP_MAJOR_VERSION < 7
    sw_zval_ptr_dtor(&zobject);
#endif
}

static void client_onError(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
		cli->timeout_id = 0;
    }
    zval *zobject = cli->object;
    zend_update_property_long(swoole_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
    if (!cli->released)
    {
        php_swoole_client_coro_free(zobject, cli TSRMLS_CC);
    }
    client_execute_callback(zobject, SW_CLIENT_CB_onError);
}

void php_swoole_client_coro_check_setting(swClient *cli, zval *zset TSRMLS_DC)
{
    HashTable *vht;
    zval *v;
    int value = 1;

    char *bind_address = NULL;
    int bind_port = 0;

    vht = Z_ARRVAL_P(zset);

    //buffer: check eof
    if (php_swoole_array_get_value(vht, "open_eof_split", v) || php_swoole_array_get_value(vht, "open_eof_check", v))
    {
        convert_to_boolean(v);
        cli->open_eof_check = Z_BVAL_P(v);
        cli->protocol.split_by_eof = 1;
    }
    //package eof
    if (php_swoole_array_get_value(vht, "package_eof", v))
    {
        convert_to_string(v);
        cli->protocol.package_eof_len = Z_STRLEN_P(v);
        if (cli->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            return;
        }
        bzero(cli->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(cli->protocol.package_eof, Z_STRVAL_P(v), Z_STRLEN_P(v));
        cli->protocol.onPackage = client_onPackage;
    }
    //open length check
    if (php_swoole_array_get_value(vht, "open_length_check", v))
    {
        convert_to_boolean(v);
        cli->open_length_check = Z_BVAL_P(v);
        cli->protocol.get_package_length = swProtocol_get_package_length;
        cli->protocol.onPackage = client_onPackage;
    }
    //package length size
    if (php_swoole_array_get_value(vht, "package_length_type", v))
    {
        convert_to_string(v);
        cli->protocol.package_length_type = Z_STRVAL_P(v)[0];
        cli->protocol.package_length_size = swoole_type_size(cli->protocol.package_length_type);

        if (cli->protocol.package_length_size == 0)
        {
            swoole_php_fatal_error(E_ERROR, "Unknown package_length_type name '%c', see pack(). Link: http://php.net/pack", cli->protocol.package_length_type);
            return;
        }
    }
    //package length offset
    if (php_swoole_array_get_value(vht, "package_length_offset", v))
    {
        convert_to_long(v);
        cli->protocol.package_length_offset = (int) Z_LVAL_P(v);
    }
    //package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", v))
    {
        convert_to_long(v);
        cli->protocol.package_body_offset = (int) Z_LVAL_P(v);
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", v))
    {
        convert_to_long(v);
        cli->protocol.package_max_length = (int) Z_LVAL_P(v);
    }
    else
    {
        cli->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
    }
    /**
     * socket send/recv buffer size
     */
    if (php_swoole_array_get_value(vht, "socket_buffer_size", v))
    {
        convert_to_long(v);
        value = (int) Z_LVAL_P(v);
        swSocket_set_buffer_size(cli->socket->fd, value);
        cli->socket->buffer_size = cli->buffer_input_size = value;
    }
    /**
     * bind address
     */
    if (php_swoole_array_get_value(vht, "bind_address", v))
    {
        convert_to_string(v);
        bind_address = Z_STRVAL_P(v);
    }
    /**
     * bind port
     */
    if (php_swoole_array_get_value(vht, "bind_port", v))
    {
        convert_to_long(v);
        bind_port = (int) Z_LVAL_P(v);
    }
    if (bind_address)
    {
        swSocket_bind(cli->socket->fd, cli->type, bind_address, &bind_port);
    }
    /**
     * TCP_NODELAY
     */
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", v))
    {
        value = 1;
        if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0)
        {
            swSysError("setsockopt(%d, TCP_NODELAY) failed.", cli->socket->fd);
        }
    }
    /**
     * socks5 proxy
     */
    if (php_swoole_array_get_value(vht, "socks5_host", v))
    {
        convert_to_string(v);
        cli->socks5_proxy = emalloc(sizeof(swSocks5));
        bzero(cli->socks5_proxy, sizeof(swSocks5));
        cli->socks5_proxy->host = strdup(Z_STRVAL_P(v));
        cli->socks5_proxy->dns_tunnel = 1;

        if (php_swoole_array_get_value(vht, "socks5_port", v))
        {
            convert_to_long(v);
            cli->socks5_proxy->port = Z_LVAL_P(v);
        }
        else
        {
            swoole_php_fatal_error(E_ERROR, "socks5 proxy require server port option.");
            return;
        }
        if (php_swoole_array_get_value(vht, "socks5_username", v))
        {
            convert_to_string(v);
            cli->socks5_proxy->username = Z_STRVAL_P(v);
            cli->socks5_proxy->l_username = Z_STRLEN_P(v);
        }
        if (php_swoole_array_get_value(vht, "socks5_password", v))
        {
            convert_to_string(v);
            cli->socks5_proxy->password = Z_STRVAL_P(v);
            cli->socks5_proxy->l_password = Z_STRLEN_P(v);
        }
    }
#ifdef SW_USE_OPENSSL
    if (php_swoole_array_get_value(vht, "ssl_method", v))
    {
        convert_to_long(v);
        cli->ssl_method = (int) Z_LVAL_P(v);
        cli->open_ssl = 1;
    }
    if (php_swoole_array_get_value(vht, "ssl_compress", v))
    {
        convert_to_boolean(v);
        cli->ssl_disable_compress = !Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_cert_file", v))
    {
        convert_to_string(v);
        cli->ssl_cert_file = strdup(Z_STRVAL_P(v));
        if (access(cli->ssl_cert_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", cli->ssl_cert_file);
            return;
        }
        cli->open_ssl = 1;
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", v))
    {
        convert_to_string(v);
        cli->ssl_key_file = strdup(Z_STRVAL_P(v));
        if (access(cli->ssl_key_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", cli->ssl_key_file);
            return;
        }
    }
    if (cli->ssl_cert_file && !cli->ssl_key_file)
    {
        swoole_php_fatal_error(E_ERROR, "ssl require key file.");
        return;
    }
#endif
}

void php_swoole_client_coro_free(zval *zobject, swClient *cli TSRMLS_DC)
{
    //socks5 proxy config
    if (cli->socks5_proxy)
    {
        efree(cli->socks5_proxy);
    }
	cli->socket->active = 0;
	swClient_free(cli);
	efree(cli);
    //unset object
    swoole_set_object(zobject, NULL);
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
	swoole_set_property(getThis(), 1, client_coro_property);

	php_context *sw_current_context = emalloc(sizeof(php_context));
	sw_current_context->onTimeout = client_coro_onTimeout;
#if PHP_MAJOR_VERSION < 7
	sw_current_context->coro_params = getThis();
#else
	sw_current_context->coro_params = *getThis();
#endif
	sw_current_context->state = SW_CORO_CONTEXT_RUNNING;
	swoole_set_property(getThis(), 0, sw_current_context);

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
        php_swoole_client_coro_check_setting(cli, zset TSRMLS_CC);
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

#if PHP_MAJOR_VERSION < 7
    sw_zval_add_ref(&zobject);
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
	if (cli->timeout > 0)
	{
		php_swoole_add_timer_coro((int) (cli->timeout * 1000), cli->socket->fd, &cli->timeout_id, (void *) sw_current_context, NULL TSRMLS_CC);
	}

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
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
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
    //if (!cli)
    //{
    //    	zval *retval = NULL;
    //    	zval *remote_ip, *remote_port;
    //    	zend_bool r = 1;
    //    	SW_MAKE_STD_ZVAL(remote_ip);
    //    	SW_MAKE_STD_ZVAL(remote_port);
    //    	SW_ZVAL_STRINGL(remote_ip, ip, ip_len, 1);
    //    	ZVAL_LONG(remote_port, port);
    //    	//sw_zend_call_method_with_2_params(&getThis(), swoole_client_coro_class_entry_ptr, NULL, "connect", &retval, remote_ip, remote_port);
    //    	sw_zval_ptr_dtor(&remote_ip);
    //    	sw_zval_ptr_dtor(&remote_port);
    //    	if (retval)
    //    	{
    //    		r = Z_BVAL_P(retval);
    //    		sw_zval_ptr_dtor(&retval);
    //    	}

    //    	if (!r)
    //    	{
    //    		RETURN_FALSE;
    //    	}

    //    	cli = swoole_get_object(getThis());
    //}

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

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &file, &file_len, &offset) == FAILURE)
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
    int ret = cli->sendfile(cli, file, offset);
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
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client_coro.");
        RETURN_FALSE;
    }

    if (cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        RETURN_FALSE;
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
	php_context *sw_current_context = swoole_get_property(getThis(), 0);
	if (cli->timeout > 0)
	{
		php_swoole_add_timer_coro((int) (cli->timeout * 1000), cli->socket->fd, &cli->timeout_id, (void *) sw_current_context, &(ccp->timeout_node) TSRMLS_CC);
	}
	ccp->iowait = SW_CLIENT_CORO_STATUS_WAIT;
	coro_save(sw_current_context);

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
    if (cli->timeout_id > 0)
    {
        php_swoole_clear_timer_coro(cli->timeout_id TSRMLS_CC);
        cli->timeout_id = 0;
    }
    //Connection error, or short tcp connection.
	swoole_client_coro_property *ccp = swoole_get_property(getThis(), 1);
	ccp->iowait = SW_CLIENT_CORO_STATUS_CLOSED;
	cli->released = 1;
	php_swoole_client_coro_free(getThis(), cli TSRMLS_CC);

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

#endif
