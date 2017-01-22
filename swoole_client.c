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
#include "module.h"

#include "ext/standard/basic_functions.h"

typedef struct
{
    zval *onConnect;
    zval *onReceive;
    zval *onClose;
    zval *onError;
    zval *onBufferFull;
    zval *onBufferEmpty;
#ifdef SW_USE_OPENSSL
    zval *onSSLReady;
#endif

#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _onConnect;
    zval _onReceive;
    zval _onClose;
    zval _onError;
    zval _onBufferFull;
    zval _onBufferEmpty;
#ifdef SW_USE_OPENSSL
    zval _onSSLReady;
#endif
#endif

} client_callback;

enum client_property
{
    client_property_callback = 0,
    client_property_socket = 1,
};

static PHP_METHOD(swoole_client, __construct);
static PHP_METHOD(swoole_client, __destruct);
static PHP_METHOD(swoole_client, set);
static PHP_METHOD(swoole_client, connect);
static PHP_METHOD(swoole_client, recv);
static PHP_METHOD(swoole_client, send);
static PHP_METHOD(swoole_client, pipe);
static PHP_METHOD(swoole_client, sendfile);
static PHP_METHOD(swoole_client, sendto);
static PHP_METHOD(swoole_client, sleep);
static PHP_METHOD(swoole_client, wakeup);
#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client, enableSSL);
static PHP_METHOD(swoole_client, getPeerCert);
static PHP_METHOD(swoole_client, verifyPeerCert);
#endif
static PHP_METHOD(swoole_client, isConnected);
static PHP_METHOD(swoole_client, getsockname);
static PHP_METHOD(swoole_client, getpeername);
static PHP_METHOD(swoole_client, close);
static PHP_METHOD(swoole_client, on);

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client, getSocket);
#endif

static int client_select_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC);
static int client_select_wait(zval *sock_array, fd_set *fds TSRMLS_DC);

static void client_onConnect(swClient *cli);
static void client_onReceive(swClient *cli, char *data, uint32_t length);
static int client_onPackage(swConnection *conn, char *data, uint32_t length);
static void client_onClose(swClient *cli);
static void client_onError(swClient *cli);
static void client_onBufferFull(swClient *cli);
static void client_onBufferEmpty(swClient *cli);

static sw_inline void client_execute_callback(zval *zobject, enum php_swoole_client_callback_type type)
{
    SWOOLE_GET_TSRMLS;

    zval *callback = NULL;
    zval *retval = NULL;
    zval **args[1];

    client_callback *cb = swoole_get_property(zobject, 0);
    char *callback_name;

    switch(type)
    {
    case SW_CLIENT_CB_onConnect:
        callback = cb->onConnect;
        callback_name = "onConnect";
        break;
    case SW_CLIENT_CB_onError:
        callback = cb->onError;
        callback_name = "onError";
        break;
    case SW_CLIENT_CB_onClose:
        callback = cb->onClose;
        callback_name = "onClose";
        break;
    case SW_CLIENT_CB_onBufferFull:
        callback = cb->onBufferFull;
        callback_name = "onBufferFull";
        break;
    case SW_CLIENT_CB_onBufferEmpty:
        callback = cb->onBufferEmpty;
        callback_name = "onBufferEmpty";
        break;
#ifdef SW_USE_OPENSSL
    case SW_CLIENT_CB_onSSLReady:
        callback = cb->onSSLReady;
        callback_name = "onSSLReady";
        break;
#endif
    default:
        return;
    }

    if (callback == NULL || ZVAL_IS_NULL(callback))
    {
        swoole_php_fatal_error(E_WARNING, "object have not %s callback.", callback_name);
        return;
    }

    args[0] = &zobject;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "%s handler error.", callback_name);
        return;
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, async)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_connect, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, timeout)
    ZEND_ARG_INFO(0, sock_flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_pipe, 0, 0, 1)
    ZEND_ARG_INFO(0, dst_socket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_close, 0, 0, 0)
    ZEND_ARG_INFO(0, force)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

#ifdef SW_USE_OPENSSL
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_enableSSL, 0, 0, 0)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()
#endif

static const zend_function_entry swoole_client_methods[] =
{
    PHP_ME(swoole_client, __construct, arginfo_swoole_client_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client, __destruct, arginfo_swoole_client_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client, set, arginfo_swoole_client_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, connect, arginfo_swoole_client_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, recv, arginfo_swoole_client_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, send, arginfo_swoole_client_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, pipe, arginfo_swoole_client_pipe, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendfile, arginfo_swoole_client_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendto, arginfo_swoole_client_sendto, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sleep, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, wakeup, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_client, pause, sleep, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_client, resume, wakeup, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client, enableSSL, arginfo_swoole_client_enableSSL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getPeerCert, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, verifyPeerCert, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client, isConnected, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getsockname, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getpeername, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, close, arginfo_swoole_client_close, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, on, arginfo_swoole_client_on, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_client, getSocket, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

static swHashMap *php_sw_long_connections;

zend_class_entry swoole_client_ce;
zend_class_entry *swoole_client_class_entry_ptr;

void swoole_client_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_client_ce, "swoole_client", "Swoole\\Client", swoole_client_methods);
    swoole_client_class_entry_ptr = zend_register_internal_class(&swoole_client_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_client, "Swoole\\Client");

    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_client_class_entry_ptr, SW_STRL("reuse")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("reuseCount")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    php_sw_long_connections = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, NULL);

    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_OOB"), MSG_OOB TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_PEEK"), MSG_PEEK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL TSRMLS_CC);
}

static int client_onPackage(swConnection *conn, char *data, uint32_t length)
{
    client_onReceive(conn->object, data, length);
    return SW_OK;
}

static void client_onReceive(swClient *cli, char *data, uint32_t length)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    zval *zobject = cli->object;
    zval *zcallback = NULL;
    zval **args[2];
    zval *retval;

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);
    SW_ZVAL_STRINGL(zdata, data, length, 1);

    args[0] = &zobject;
    args[1] = &zdata;

    client_callback *cb = swoole_get_property(zobject, 0);
    zcallback = cb->onReceive;
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_WARNING, "swoole_client object have not receive callback.");
        goto free_zdata;
    }

    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onReactorCallback handler error");
        goto free_zdata;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    free_zdata:
    sw_zval_ptr_dtor(&zdata);
}

static void client_onConnect(swClient *cli)
{
    zval *zobject = cli->object;
#ifdef SW_USE_OPENSSL
    if (cli->ssl_wait_handshake)
    {
        client_execute_callback(zobject, SW_CLIENT_CB_onSSLReady);
    }
    else
#endif
    if (!cli->redirect)
    {
        client_execute_callback(zobject, SW_CLIENT_CB_onConnect);
    }
    else
    {
        SWOOLE_GET_TSRMLS;
        client_callback *cb = swoole_get_property(zobject, 0);
        if (!cb || !cb->onReceive)
        {
            swoole_php_fatal_error(E_ERROR, "no receive callback.");
        }
    }
}

static void client_onClose(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;
    if (!cli->released)
    {
        php_swoole_client_free(zobject, cli TSRMLS_CC);
    }
    client_execute_callback(zobject, SW_CLIENT_CB_onClose);
    sw_zval_ptr_dtor(&zobject);
}

static void client_onError(swClient *cli)
{
    SWOOLE_GET_TSRMLS;
    zval *zobject = cli->object;
    zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
    if (!cli->released)
    {
        php_swoole_client_free(zobject, cli TSRMLS_CC);
    }
    client_execute_callback(zobject, SW_CLIENT_CB_onError);
    sw_zval_ptr_dtor(&zobject);
}

static void client_onBufferFull(swClient *cli)
{
    zval *zobject = cli->object;
    client_execute_callback(zobject, SW_CLIENT_CB_onBufferFull);
}

static void client_onBufferEmpty(swClient *cli)
{
    zval *zobject = cli->object;
    client_execute_callback(zobject, SW_CLIENT_CB_onBufferEmpty);
}

void php_swoole_client_check_setting(swClient *cli, zval *zset TSRMLS_DC)
{
    HashTable *vht;
    zval *v;
    int value = 1;

    char *bind_address = NULL;
    int bind_port = 0;

    vht = Z_ARRVAL_P(zset);

    //buffer: eof check
    if (php_swoole_array_get_value(vht, "open_eof_check", v))
    {
        convert_to_boolean(v);
        cli->open_eof_check = Z_BVAL_P(v);
    }
    //buffer: split package with eof
    if (php_swoole_array_get_value(vht, "open_eof_split", v))
    {
        convert_to_boolean(v);
        cli->protocol.split_by_eof = Z_BVAL_P(v);
        if (cli->protocol.split_by_eof)
        {
            cli->open_eof_check = 1;
        }
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
    //length function
    if (php_swoole_array_get_value(vht, "package_length_func", v))
    {
        while(1)
        {
            if (Z_TYPE_P(v) == IS_STRING)
            {
                swProtocol_length_function func = swModule_get_global_function(Z_STRVAL_P(v), Z_STRLEN_P(v));
                if (func != NULL)
                {
                    cli->protocol.get_package_length = func;
                    break;
                }
            }

            char *func_name = NULL;
            if (!sw_zend_is_callable(v, 0, &func_name TSRMLS_CC))
            {
                swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
                efree(func_name);
                return;
            }
            efree(func_name);
            cli->protocol.get_package_length = php_swoole_length_func;
            sw_zval_add_ref(&v);
            cli->protocol.private_data = sw_zval_dup(v);
            break;
        }

        cli->protocol.package_length_size = 0;
        cli->protocol.package_length_type = '\0';
        cli->protocol.package_length_offset = SW_BUFFER_SIZE;
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
        if (value <= 0 || value > SW_MAX_INT)
        {
            value = SW_MAX_INT;
        }
        swSocket_set_buffer_size(cli->socket->fd, value);
        cli->socket->buffer_size = cli->buffer_input_size = value;
    }
    if (php_swoole_array_get_value(vht, "buffer_high_watermark", v))
    {
        convert_to_long(v);
        value = (int) Z_LVAL_P(v);
        cli->buffer_high_watermark = value;
    }
    if (php_swoole_array_get_value(vht, "buffer_low_watermark", v))
    {
        convert_to_long(v);
        value = (int) Z_LVAL_P(v);
        cli->buffer_low_watermark = value;
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
    if (cli->open_ssl)
    {
        if (php_swoole_array_get_value(vht, "ssl_method", v))
        {
            convert_to_long(v);
            cli->ssl_method = (int) Z_LVAL_P(v);
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
    }
#endif
}

void php_swoole_at_shutdown(char *function)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

#if PHP_MAJOR_VERSION >=7
    php_shutdown_function_entry shutdown_function_entry;
    shutdown_function_entry.arg_count = 1;
    shutdown_function_entry.arguments = (zval *) safe_emalloc(sizeof(zval), 1, 0);
    ZVAL_STRING(&shutdown_function_entry.arguments[0], "swoole_event_wait");

    if (!register_user_shutdown_function("swoole_event_wait", sizeof("swoole_event_wait")-1, &shutdown_function_entry TSRMLS_CC))
    {
        zval_ptr_dtor(&shutdown_function_entry.arguments[0]);
        efree(shutdown_function_entry.arguments);
        swoole_php_fatal_error(E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
    }
#else

    zval *callback;
    SW_MAKE_STD_ZVAL(callback);
    SW_ZVAL_STRING(callback, "swoole_event_wait", 1);

#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4

     php_shutdown_function_entry shutdown_function_entry;

    shutdown_function_entry.arg_count = 1;
    shutdown_function_entry.arguments = (zval **) safe_emalloc(sizeof(zval *), 1, 0);


    shutdown_function_entry.arguments[0] = callback;

    if (!register_user_shutdown_function("swoole_event_wait", sizeof("swoole_event_wait"), &shutdown_function_entry TSRMLS_CC))
    {
        efree(shutdown_function_entry.arguments);
        sw_zval_ptr_dtor(&callback);
        swoole_php_fatal_error(E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
    }
#else
    zval *register_shutdown_function;
    zval *retval = NULL;
    SW_MAKE_STD_ZVAL(register_shutdown_function);
    SW_ZVAL_STRING(register_shutdown_function, "register_shutdown_function", 1);
    zval **args[1] = {&callback};

    if (sw_call_user_function_ex(EG(function_table), NULL, register_shutdown_function, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "Unable to register shutdown function [swoole_event_wait]");
        return;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
#endif

#endif
}

void php_swoole_check_reactor()
{
    if (SwooleWG.reactor_init)
    {
        return;
    }

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "async-io must use in cli environment.");
        return;
    }

    if (swIsTaskWorker())
    {
        swoole_php_fatal_error(E_ERROR, "cannot use async-io in task process.");
        return;
    }

    if (SwooleG.main_reactor == NULL)
    {
        swTraceLog(SW_TRACE_PHP, "init reactor");

        SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
        if (SwooleG.main_reactor == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "malloc failed.");
            return;
        }
        if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "create reactor failed.");
            return;
        }
        //client, swoole_event_exit will set swoole_running = 0
        SwooleWG.in_client = 1;
        SwooleWG.reactor_wait_onexit = 1;
        SwooleWG.reactor_ready = 0;
        //only client side
        php_swoole_at_shutdown("swoole_event_wait");
    }

    php_swoole_event_init();

    SwooleWG.reactor_init = 1;
}

void php_swoole_client_free(zval *zobject, swClient *cli TSRMLS_DC)
{
    //socks5 proxy config
    if (cli->socks5_proxy)
    {
        efree(cli->socks5_proxy);
    }
    if (cli->protocol.private_data)
    {
        zval *zcallback = cli->protocol.private_data;
        sw_zval_free(zcallback);
    }
    //long tcp connection, delete from php_sw_long_connections
    if (cli->keep)
    {
        if (swHashMap_del(php_sw_long_connections, cli->server_str, cli->server_strlen))
        {
            swoole_php_fatal_error(E_WARNING, "delete from hashtable failed.");
        }
        efree(cli->server_str);
        swClient_free(cli);
        pefree(cli, 1);
    }
    else
    {
        efree(cli->server_str);
        swClient_free(cli);
        efree(cli);
    }
    //unset object
    swoole_set_object(zobject, NULL);
}

swClient* php_swoole_client_new(zval *object, char *host, int host_len, int port)
{
    zval *ztype;
    int async = 0;
    char conn_key[SW_LONG_CONNECTION_KEY_LEN];
    int conn_key_len = 0;
    uint64_t tmp_buf;
    int ret;

#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    ztype = sw_zend_read_property(swoole_client_class_entry_ptr, object, SW_STRL("type")-1, 0 TSRMLS_CC);

    if (ztype == NULL || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "get swoole_client->type failed.");
        return NULL;
    }

    long type = Z_LVAL_P(ztype);

    //new flag, swoole-1.6.12+
    if (type & SW_FLAG_ASYNC)
    {
        async = 1;
    }

    swClient *cli;
    bzero(conn_key, SW_LONG_CONNECTION_KEY_LEN);
    zval *connection_id = sw_zend_read_property(swoole_client_class_entry_ptr, object, ZEND_STRL("id"), 1 TSRMLS_CC);

    if (connection_id == NULL || ZVAL_IS_NULL(connection_id))
    {
        conn_key_len = snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN, "%s:%d", host, port) + 1;
    }
    else
    {
        conn_key_len = snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN, "%s", Z_STRVAL_P(connection_id)) + 1;
    }

    //keep the tcp connection
    if (type & SW_FLAG_KEEP)
    {
        swClient *find = swHashMap_find(php_sw_long_connections, conn_key, conn_key_len);
        if (find == NULL)
        {
            cli = (swClient*) pemalloc(sizeof(swClient), 1);
            if (swHashMap_add(php_sw_long_connections, conn_key, conn_key_len, cli) == FAILURE)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_client_create_socket add to hashtable failed.");
            }
            goto create_socket;
        }
        else
        {
            cli = find;
            //try recv, check connection status
            ret = recv(cli->socket->fd, &tmp_buf, sizeof(tmp_buf), MSG_DONTWAIT | MSG_PEEK);
            if (ret == 0 || (ret < 0 && swConnection_error(errno) == SW_CLOSE))
            {
                cli->close(cli);
                goto create_socket;
            }
            //clear history data
            if (ret > 0)
            {
                swSocket_clean(cli->socket->fd);
            }
            cli->reuse_count ++;
            zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("reuseCount"), cli->reuse_count TSRMLS_CC);
        }
    }
    else
    {
        cli = (swClient*) emalloc(sizeof(swClient));

        create_socket:
        if (swClient_create(cli, php_swoole_socktype(type), async) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "swClient_create() failed. Error: %s [%d]", strerror(errno), errno);
            zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("errCode"), errno TSRMLS_CC);
            return NULL;
        }

        //don't forget free it
        cli->server_str = estrdup(conn_key);
        cli->server_strlen = conn_key_len;
    }

    zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

    if (type & SW_FLAG_KEEP)
    {
        cli->keep = 1;
    }

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL)
    {
        cli->open_ssl = 1;
    }
#endif

    return cli;
}

static PHP_METHOD(swoole_client, __construct)
{
    long async = 0;
    long type = 0;
    char *id = NULL;
    zend_size_t len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|ls", &type, &async, &id, &len) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "require socket type param.");
        RETURN_FALSE;
    }

    if (async == 1)
    {
        type |= SW_FLAG_ASYNC;
    }

    if ((type & SW_FLAG_ASYNC))
    {
        if ((type & SW_FLAG_KEEP) && SWOOLE_G(cli))
        {
            swoole_php_fatal_error(E_ERROR, "The 'SWOOLE_KEEP' flag can only be used in the php-fpm or apache environment.");
        }
        php_swoole_check_reactor();
    }

    int client_type = php_swoole_socktype(type);
    if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_STREAM)
    {
        swoole_php_fatal_error(E_ERROR, "Unknown client type '%d'.", client_type);
    }

    zend_update_property_long(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), type TSRMLS_CC);
    if (id)
    {
        zend_update_property_stringl(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("id"), id, len TSRMLS_CC);
    }
    else
    {
        zend_update_property_null(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("id") TSRMLS_CC);
    }
    //init
    swoole_set_object(getThis(), NULL);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, __destruct)
{
    swClient *cli = swoole_get_object(getThis());
    //no keep connection
    if (cli)
    {
        zval *zobject = getThis();
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, swoole_client_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    //free memory
    client_callback *cb = swoole_get_property(getThis(), client_property_callback);
    if (cb)
    {
        efree(cb);
        swoole_set_property(getThis(), client_property_callback, NULL);
    }
#ifdef SWOOLE_SOCKETS_SUPPORT
    zval *zsocket = swoole_get_property(getThis(), client_property_socket);
    if (zsocket)
    {
        sw_zval_ptr_dtor(&zsocket);
#if PHP_MAJOR_VERSION >= 7
        efree(zsocket);
#endif
        swoole_set_property(getThis(), client_property_socket, NULL);
    }
#endif
}

static PHP_METHOD(swoole_client, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    php_swoole_array_separate(zset);
    zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, connect)
{
    long port = 0, sock_flag = 0;
    char *host = NULL;
    zend_size_t host_len;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ldl", &host, &host_len, &port, &timeout, &sock_flag) == FAILURE)
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

    cli = php_swoole_client_new(getThis(), host, host_len, port);
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

    if (cli->keep == 1 && cli->socket->active == 1)
    {
        zend_update_property_bool(swoole_client_class_entry_ptr, getThis(), SW_STRL("reuse")-1, 1 TSRMLS_CC);
        RETURN_TRUE;
    }
    else if (cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_client is already connected.");
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        php_swoole_client_check_setting(cli, zset TSRMLS_CC);
    }

    //nonblock async
    if (cli->async)
    {
        client_callback *cb = swoole_get_property(getThis(), 0);
        if (!cb)
        {
            swoole_php_fatal_error(E_ERROR, "no event callback function.");
            RETURN_FALSE;
        }

        if (swSocket_is_stream(cli->type))
        {
            if (!cb->onConnect)
            {
                swoole_php_fatal_error(E_ERROR, "no connect callback.");
                RETURN_FALSE;
            }
            if (!cb->onError)
            {
                swoole_php_fatal_error(E_ERROR, "no error callback.");
                RETURN_FALSE;
            }
            if (!cb->onClose)
            {
                swoole_php_fatal_error(E_ERROR, "no close callback.");
                RETURN_FALSE;
            }
            cli->onConnect = client_onConnect;
            cli->onClose = client_onClose;
            cli->onError = client_onError;
            cli->onReceive = client_onReceive;
            cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
            if (!cb->onBufferFull)
            {
                cli->onBufferFull = client_onBufferFull;
            }
            if (!cb->onBufferEmpty)
            {
                cli->onBufferEmpty = client_onBufferEmpty;
            }
        }
        else
        {
            if (!cb || !cb->onReceive)
            {
                swoole_php_fatal_error(E_ERROR, "no receive callback.");
                RETURN_FALSE;
            }
            if (cb->onConnect)
            {
                cli->onConnect = client_onConnect;
            }
            if (cb->onClose)
            {
                cli->onClose = client_onClose;
            }
            cli->onReceive = client_onReceive;
            cli->reactor_fdtype = PHP_SWOOLE_FD_DGRAM_CLIENT;
        }

        zval *zobject = getThis();
        cli->object = zobject;
        sw_copy_to_stack(cli->object, cb->_object);
        sw_zval_add_ref(&zobject);
    }

    //nonblock async
    if (cli->connect(cli, host, port, timeout, sock_flag) < 0)
    {
        swoole_php_sys_error(E_WARNING, "connect to server[%s:%d] failed.", host, (int )port);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errno TSRMLS_CC);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, send)
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

    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }

    //clear errno
    SwooleG.error = 0;
    int ret = cli->send(cli, data, data_len, flags);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", cli->socket->fd, data_len);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }
    else
    {
        RETURN_LONG(ret);
    }
}

static PHP_METHOD(swoole_client, sendto)
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

static PHP_METHOD(swoole_client, sendfile)
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

    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    //only stream socket can sendfile
    if (!(cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6 || cli->type == SW_SOCK_UNIX_STREAM))
    {
        swoole_php_error(E_WARNING, "dgram socket cannot use sendfile.");
        RETURN_FALSE;
    }
    //clear errno
    SwooleG.error = 0;
    int ret = cli->sendfile(cli, file, offset);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_fatal_error(E_WARNING, "sendfile() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }
    else
    {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client, recv)
{
    long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    long flags = 0;
    int ret;
    char *buf = NULL;
    char stack_buf[SW_BUFFER_SIZE_BIG];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &buf_len, &flags) == FAILURE)
    {
        return;
    }

    //waitall
    if (flags == 1)
    {
        flags = MSG_WAITALL;
    }

    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }

    swProtocol *protocol = &cli->protocol;

    if (cli->open_eof_check)
    {
        if (cli->buffer == NULL)
        {
            cli->buffer = swString_new(SW_BUFFER_SIZE_BIG);
        }

        swString *buffer = cli->buffer;
        int eof = -1;

        while (1)
        {
            buf = buffer->str + buffer->length;
            buf_len = buffer->size - buffer->length;

            if (buf_len > SW_BUFFER_SIZE_BIG)
            {
                buf_len = SW_BUFFER_SIZE_BIG;
            }

            ret = cli->recv(cli, buf, buf_len, 0);
            if (ret < 0)
            {
                swoole_php_error(E_WARNING, "recv() failed. Error: %s [%d]", strerror(errno), errno);
                buffer->length = 0;
                RETURN_FALSE;
            }
            else if (ret == 0)
            {
                buffer->length = 0;
                RETURN_EMPTY_STRING();
            }

            buffer->length += ret;

            if (buffer->length < protocol->package_eof_len)
            {
                continue;
            }

            eof = swoole_strnpos(buffer->str, buffer->length, protocol->package_eof, protocol->package_eof_len);
            if (eof >= 0)
            {
                eof += protocol->package_eof_len;
                SW_RETVAL_STRINGL(buffer->str, eof, 1);

                if (buffer->length > eof)
                {
                    buffer->length -= eof;
                    memcpy(stack_buf, buffer->str + eof, buffer->length);
                    memcpy(buffer->str, stack_buf, buffer->length);
                }
                else
                {
                    buffer->length = 0;
                }
                return;
            }
            else
            {
                if (buffer->length == protocol->package_max_length)
                {
                    swoole_php_error(E_WARNING, "no package eof");
                    buffer->length = 0;
                    RETURN_FALSE;
                }
                else if (buffer->length == buffer->size)
                {
                    if (buffer->size < protocol->package_max_length)
                    {
                        int new_size = buffer->size * 2;
                        if (new_size > protocol->package_max_length)
                        {
                            new_size = protocol->package_max_length;
                        }
                        if (swString_extend(buffer, new_size) < 0)
                        {
                            buffer->length = 0;
                            RETURN_FALSE;
                        }
                    }
                }
            }
        }
        buffer->length = 0;
        RETURN_FALSE;
    }
    else if (cli->open_length_check)
    {
        uint32_t header_len = protocol->package_length_offset + protocol->package_length_size;
        ret = cli->recv(cli, stack_buf, header_len, MSG_WAITALL);
        if (ret <= 0)
        {
            goto check_return;
        }

        buf_len = swProtocol_get_package_length(protocol, cli->socket, stack_buf, ret);

        //error package
        if (buf_len < 0)
        {
            RETURN_EMPTY_STRING();
        }
        //empty package
        else if (buf_len == header_len)
        {
            SW_RETURN_STRINGL(stack_buf, header_len, 1);
        }
        else if (buf_len > protocol->package_max_length)
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE, "Package is too big. package_length=%d", (int )buf_len);
            RETURN_EMPTY_STRING();
        }

        buf = emalloc(buf_len + 1);
        memcpy(buf, stack_buf, header_len);
        SwooleG.error = 0;
        ret = cli->recv(cli, buf + header_len, buf_len - header_len, MSG_WAITALL);
        if (ret > 0)
        {
            ret += header_len;
        }
    }
    else
    {
        if (!(flags & MSG_WAITALL) && buf_len > SW_PHP_CLIENT_BUFFER_SIZE)
        {
            buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
        }
        buf = emalloc(buf_len + 1);
        SwooleG.error = 0;
        ret = cli->recv(cli, buf, buf_len, flags);
    }

    check_return:

    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_error(E_WARNING, "recv() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        swoole_efree(buf);
        RETURN_FALSE;
    }
    else
    {
        if (ret == 0)
        {
            swoole_efree(buf);
            RETURN_EMPTY_STRING();
        }
        else
        {
            buf[ret] = 0;
            SW_RETVAL_STRINGL(buf, ret, 0);
        }
    }
}

static PHP_METHOD(swoole_client, isConnected)
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

static PHP_METHOD(swoole_client, getsockname)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
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

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client, getSocket)
{
    zval *zsocket = swoole_get_property(getThis(), client_property_socket);
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
        swoole_php_fatal_error(E_WARNING, "The getSocket method cannot be used for long connection.");
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
    swoole_set_property(getThis(), client_property_socket, zsocket);
}
#endif

static PHP_METHOD(swoole_client, getpeername)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
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

static PHP_METHOD(swoole_client, close)
{
    int ret = 1;
    zend_bool force = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &force) == FAILURE)
    {
        return;
    }

    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "client socket is closed.");
        RETURN_FALSE;
    }
    //Connection error, or short tcp connection.
    //No keep connection
    if (force || !cli->keep || swConnection_error(SwooleG.error) == SW_CLOSE)
    {
        cli->released = 1;
        ret = cli->close(cli);
        php_swoole_client_free(getThis(), cli TSRMLS_CC);
    }
    else
    {
        //unset object
        swoole_set_object(getThis(), NULL);
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client, on)
{
    char *cb_name;
    zend_size_t cb_name_len;
    zval *zcallback;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE)
    {
        return;
    }

    zval *ztype = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("type")-1, 0 TSRMLS_CC);
    if (ztype == NULL || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "get swoole_client->type failed.");
        return;
    }

    if (!(Z_LVAL_P(ztype) & SW_FLAG_ASYNC))
    {
        swoole_php_fatal_error(E_ERROR, "sync-client cannot set event callback.");
        return;
    }

    client_callback *cb = swoole_get_property(getThis(), client_property_callback);
    if (!cb)
    {
        cb = emalloc(sizeof(client_callback));
        bzero(cb, sizeof(client_callback));
        swoole_set_property(getThis(), client_property_callback, cb);
    }

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (!sw_zend_is_callable(zcallback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);
#endif

    if (strncasecmp("connect", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onConnect"), zcallback TSRMLS_CC);
        cb->onConnect = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onConnect"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onConnect, cb->_onConnect);
    }
    else if (strncasecmp("receive", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onReceive"), zcallback TSRMLS_CC);
        cb->onReceive = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onReceive"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onReceive, cb->_onReceive);
    }
    else if (strncasecmp("close", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onClose"), zcallback TSRMLS_CC);
        cb->onClose = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onClose"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onClose, cb->_onClose);
    }
    else if (strncasecmp("error", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onError"), zcallback TSRMLS_CC);
        cb->onError = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onError"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onError, cb->_onError);
    }
    else if (strncasecmp("bufferFull", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onBufferFull"), zcallback TSRMLS_CC);
        cb->onBufferFull = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onBufferFull"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onBufferFull, cb->_onBufferFull);
    }
    else if (strncasecmp("bufferEmpty", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onBufferEmpty"), zcallback TSRMLS_CC);
        cb->onBufferEmpty = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onBufferEmpty"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onBufferEmpty, cb->_onBufferEmpty);
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "Unknown event callback type name '%s'.", cb_name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, sleep)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    int ret;
    if (cli->socket->events & SW_EVENT_WRITE)
    {
        ret = SwooleG.main_reactor->set(SwooleG.main_reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_WRITE);
    }
    else
    {
        ret = SwooleG.main_reactor->del(SwooleG.main_reactor, cli->socket->fd);
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client, wakeup)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    int ret;
    if (cli->socket->events & SW_EVENT_WRITE)
    {
        ret = SwooleG.main_reactor->set(SwooleG.main_reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
    }
    else
    {
        ret = SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_READ);
    }
    SW_CHECK_RETURN(ret);
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client, enableSSL)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
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
    if (cli->async)
    {
        zval *zcallback;
        if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &zcallback) == FAILURE)
        {
            return;
        }
#ifdef PHP_SWOOLE_CHECK_CALLBACK
        char *func_name = NULL;
        if (!sw_zend_is_callable(zcallback, 0, &func_name TSRMLS_CC))
        {
            swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
            efree(func_name);
            return;
        }
        efree(func_name);
#endif

        client_callback *cb = swoole_get_property(getThis(), client_property_callback);
        if (!cb)
        {
            swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_client.");
            RETURN_FALSE;
        }
        zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("onSSLReady"), zcallback TSRMLS_CC);
        cb->onSSLReady = sw_zend_read_property(swoole_client_class_entry_ptr,  getThis(), ZEND_STRL("onSSLReady"), 0 TSRMLS_CC);
        sw_copy_to_stack(cb->onSSLReady, cb->_onSSLReady);
        cli->ssl_wait_handshake = 1;
        cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;

        SwooleG.main_reactor->set(SwooleG.main_reactor, cli->socket->fd, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE);
    }
    else
    {
        if (swClient_ssl_handshake(cli) < 0)
        {
            RETURN_FALSE;
        }
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, getPeerCert)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
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

static PHP_METHOD(swoole_client, verifyPeerCert)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
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

static PHP_METHOD(swoole_client, pipe)
{
    swClient *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    zval *write_socket;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &write_socket) == FAILURE)
    {
        return;
    }

    int fd;
    int flags = 0;

    //server session id
    if (SW_Z_TYPE_P(write_socket) == IS_LONG)
    {
        fd = Z_LVAL_P(write_socket);
        swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
        if (conn == NULL)
        {
            RETURN_FALSE;
        }
        flags = SW_CLIENT_PIPE_TCP_SESSION;
    }
    else
    {
        fd = swoole_convert_to_fd(write_socket TSRMLS_CC);
        if (fd < 0)
        {
            RETURN_FALSE;
        }
    }
    SW_CHECK_RETURN(cli->pipe(cli, fd, flags));
}

PHP_FUNCTION(swoole_client_select)
{
    zval *r_array, *w_array, *e_array;
    fd_set rfds, wfds, efds;

    int max_fd = 0;
    int    retval, sets = 0;
    double timeout = 0.5;
    struct timeval timeo;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a!a!a!|d", &r_array, &w_array, &e_array, &timeout) == FAILURE)
    {
        return;
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    if (r_array != NULL) sets += client_select_add(r_array, &rfds, &max_fd TSRMLS_CC);
    if (w_array != NULL) sets += client_select_add(w_array, &wfds, &max_fd TSRMLS_CC);
    if (e_array != NULL) sets += client_select_add(e_array, &efds, &max_fd TSRMLS_CC);

    if (!sets)
    {
        swoole_php_fatal_error(E_WARNING, "no resource arrays were passed to select");
        RETURN_FALSE;
    }

    if (max_fd >= FD_SETSIZE)
    {
        swoole_php_fatal_error(E_WARNING, "select max_fd > FD_SETSIZE[%d]", FD_SETSIZE);
        RETURN_FALSE;
    }
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);

    retval = select(max_fd + 1, &rfds, &wfds, &efds, &timeo);
    if (retval == -1)
    {
        swoole_php_fatal_error(E_WARNING, "unable to select. Error: %s [%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    if (r_array != NULL)
    {
        client_select_wait(r_array, &rfds TSRMLS_CC);
    }
    if (w_array != NULL)
    {
        client_select_wait(w_array, &wfds TSRMLS_CC);
    }
    if (e_array != NULL)
    {
        client_select_wait(e_array, &efds TSRMLS_CC);
    }
    RETURN_LONG(retval);
}

static int client_select_wait(zval *sock_array, fd_set *fds TSRMLS_DC)
{
    zval *element = NULL;
    int sock;

    ulong_t num = 0;
    if (SW_Z_TYPE_P(sock_array) != IS_ARRAY)
    {
        return 0;
    }

#if PHP_MAJOR_VERSION < 7
    HashTable *new_hash;
    char *key = NULL;
    zval **dest_element;
    uint32_t key_len;

    ALLOC_HASHTABLE(new_hash);
    zend_hash_init(new_hash, zend_hash_num_elements(Z_ARRVAL_P(sock_array)), NULL, ZVAL_PTR_DTOR, 0);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(sock_array), element)
        sock = swoole_convert_to_fd(element TSRMLS_CC);
        if (sock < 0)
        {
            continue;
        }
        if ((sock < FD_SETSIZE) && FD_ISSET(sock, fds))
        {
            switch (sw_zend_hash_get_current_key(Z_ARRVAL_P(sock_array), &key, &key_len, &num))
            {
            case HASH_KEY_IS_STRING:
                sw_zend_hash_add(new_hash, key, key_len, (void * ) &element, sizeof(zval *), (void ** )&dest_element);
                break;
            case HASH_KEY_IS_LONG:
                sw_zend_hash_index_update(new_hash, num, (void * ) &element, sizeof(zval *), (void ** )&dest_element);
                break;
            }
            if (dest_element)
            {
                sw_zval_add_ref(dest_element);
            }
        }
        num ++;
    SW_HASHTABLE_FOREACH_END();

    zend_hash_destroy(Z_ARRVAL_P(sock_array));
    efree(Z_ARRVAL_P(sock_array));

    zend_hash_internal_pointer_reset(new_hash);
    Z_ARRVAL_P(sock_array) = new_hash;
#else
    zval new_array;
    array_init(&new_array);
    zend_ulong num_key;
    zend_string *key;
    zval *dest_element;


    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(sock_array), num_key, key, element)
    {
        sock = swoole_convert_to_fd(element TSRMLS_CC);
        if (sock < 0)
        {
            continue;
        }
        if ((sock < FD_SETSIZE) && FD_ISSET(sock, fds))
        {
            if (key)
            {
                dest_element = zend_hash_add(Z_ARRVAL(new_array), key, element);
            }
            else
            {
                dest_element = zend_hash_index_update(Z_ARRVAL(new_array), num_key, element);
            }
            if (dest_element)
            {
                Z_ADDREF_P(dest_element);
            }
        }
        num++;
    } ZEND_HASH_FOREACH_END();

    zval_ptr_dtor(sock_array);
    ZVAL_COPY_VALUE(sock_array, &new_array);
#endif
    return num ? 1 : 0;
}

static int client_select_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC)
{
    zval *element = NULL;
    if (SW_Z_TYPE_P(sock_array) != IS_ARRAY)
    {
        return 0;
    }

    int sock;
    int num = 0;

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(sock_array), element)
        sock = swoole_convert_to_fd(element TSRMLS_CC);
        if (sock < 0)
        {
            continue;
        }
        if (sock < FD_SETSIZE)
        {
            FD_SET(sock, fds);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "socket[%d] > FD_SETSIZE[%d].", sock, FD_SETSIZE);
            continue;
        }
        if (sock > *max_fd)
        {
            *max_fd = sock;
        }
        num ++;
    SW_HASHTABLE_FOREACH_END();

    return num ? 1 : 0;
}
