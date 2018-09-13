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
#include "socket.h"
#include "socks5.h"
#include "mqtt.h"

#include "ext/standard/basic_functions.h"

enum client_property
{
    client_property_callback = 0,
    client_property_coroutine = 1,
    client_property_socket = 2,
};

using namespace swoole;

#ifdef FAST_ZPP
#undef FAST_ZPP
#endif

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_peek, 0, 0, 0)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, address)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_coro_recvfrom, 0, 0, 2)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(1, address)
    ZEND_ARG_INFO(1, port)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_client_coro, __construct);
static PHP_METHOD(swoole_client_coro, __destruct);
static PHP_METHOD(swoole_client_coro, set);
static PHP_METHOD(swoole_client_coro, connect);
static PHP_METHOD(swoole_client_coro, recv);
static PHP_METHOD(swoole_client_coro, peek);
static PHP_METHOD(swoole_client_coro, send);
static PHP_METHOD(swoole_client_coro, sendfile);
static PHP_METHOD(swoole_client_coro, sendto);
static PHP_METHOD(swoole_client_coro, recvfrom);
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

static void client_coro_check_ssl_setting(Socket *cli, zval *zset);
static Socket* client_coro_new(zval *object, int port = 0);
void php_swoole_client_coro_free(zval *zobject, Socket *cli);
void php_swoole_client_coro_check_setting(Socket *cli, zval *zset);

static const zend_function_entry swoole_client_coro_methods[] =
{
    PHP_ME(swoole_client_coro, __construct, arginfo_swoole_client_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client_coro, __destruct, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client_coro, set, arginfo_swoole_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, connect, arginfo_swoole_client_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recv, arginfo_swoole_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, peek, arginfo_swoole_client_coro_peek, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, send, arginfo_swoole_client_coro_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendfile, arginfo_swoole_client_coro_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, sendto, arginfo_swoole_client_coro_sendto, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, recvfrom, arginfo_swoole_client_coro_recvfrom, ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client_coro, enableSSL, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getPeerCert, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, verifyPeerCert, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client_coro, isConnected, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getsockname, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, getpeername, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, close, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_client_coro, getSocket, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

zend_class_entry swoole_client_coro_ce;
zend_class_entry *swoole_client_coro_class_entry_ptr;

void swoole_client_coro_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_client_coro_ce, "Swoole\\Coroutine\\Client", swoole_client_coro_methods);
    swoole_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_client_coro_ce TSRMLS_CC);
    swoole_client_coro_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_client_coro_class_entry_ptr->unserialize = zend_class_unserialize_deny;

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Client", swoole_client_coro_class_entry_ptr);
    }

    zend_declare_property_long(swoole_client_coro_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_coro_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_client_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_OOB"), MSG_OOB TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_PEEK"), MSG_PEEK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_coro_class_entry_ptr, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL TSRMLS_CC);
}

static sw_inline Socket* client_get_ptr(zval *zobject TSRMLS_DC)
{
    Socket *cli = (Socket *) swoole_get_object(zobject);
    if (cli && cli->socket && cli->socket->active == 1)
    {
        return cli;
    }
    else
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_client_coro_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        swoole_php_error(E_WARNING, "client is not connected to server.");
        return NULL;
    }
}

static Socket* client_coro_new(zval *object, int port)
{
    zval *ztype;

    ztype = sw_zend_read_property(Z_OBJCE_P(object), object, SW_STRL("type")-1, 0 TSRMLS_CC);

    if (ztype == NULL || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "failed to get swoole_client->type.");
        return NULL;
    }

    long type = Z_LVAL_P(ztype);
    if ((type == SW_SOCK_TCP || type == SW_SOCK_TCP6) && (port <= 0 || port > SW_CLIENT_MAX_PORT))
    {
        swoole_php_fatal_error(E_WARNING, "The port is invalid.");
        return NULL;
    }

    Socket *cli = new Socket((enum swSocket_type) type);
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "new Client() failed. Error: %s [%d]", strerror(errno), errno);
        zend_update_property_long(Z_OBJCE_P(object), object, ZEND_STRL("errCode"), errno TSRMLS_CC);
        return NULL;
    }

    zend_update_property_long(Z_OBJCE_P(object), object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL)
    {
        cli->open_ssl = true;
    }
#endif

    return cli;
}

void php_swoole_client_coro_free(zval *zobject, Socket *cli TSRMLS_DC)
{
    if (cli->timer)
    {
        swTimer_del(&SwooleG.timer, cli->timer);
        cli->timer = NULL;
    }
    //socks5 proxy config
    if (cli->socks5_proxy)
    {
        efree(cli->socks5_proxy->host);
        if (cli->socks5_proxy->username)
        {
            efree(cli->socks5_proxy->username);
        }
        if (cli->socks5_proxy->password)
        {
            efree(cli->socks5_proxy->password);
        }
        efree(cli->socks5_proxy);
    }
    //http proxy config
    if (cli->http_proxy)
    {
        efree(cli->http_proxy->proxy_host);
        if (cli->http_proxy->user)
        {
            efree(cli->http_proxy->user);
        }
        if (cli->http_proxy->password)
        {
            efree(cli->http_proxy->password);
        }
        efree(cli->http_proxy);
    }
    delete cli;

#ifdef SWOOLE_SOCKETS_SUPPORT
    zval *zsocket = (zval *) swoole_get_property(zobject, client_property_socket);
    if (zsocket)
    {
        sw_zval_free(zsocket);
        swoole_set_property(zobject, client_property_socket, NULL);
    }
#endif
    //unset object
    swoole_set_object(zobject, NULL);
    zend_update_property_bool(Z_OBJCE_P(zobject), zobject, SW_STRL("connected")-1, 0);
}

void php_swoole_client_coro_check_setting(Socket *cli, zval *zset TSRMLS_DC)
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
    }
    //open mqtt protocol
    if (php_swoole_array_get_value(vht, "open_mqtt_protocol", v))
    {
        convert_to_boolean(v);
        cli->open_length_check = Z_BVAL_P(v);
        cli->protocol.get_package_length = swMqtt_get_package_length;
    }
    //open length check
    if (php_swoole_array_get_value(vht, "open_length_check", v))
    {
        convert_to_boolean(v);
        cli->open_length_check = Z_BVAL_P(v);
        cli->protocol.get_package_length = swProtocol_get_package_length;
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
                swProtocol_length_function func = (swProtocol_length_function) swoole_get_function(Z_STRVAL_P(v),
                        Z_STRLEN_P(v));
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
        if (value <= 0)
        {
            value = SW_MAX_INT;
        }
        swSocket_set_buffer_size(cli->socket->fd, value);
        cli->socket->buffer_size = value;
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
     * client: tcp_nodelay
     */
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", v))
    {
        convert_to_boolean(v);
        if (Z_BVAL_P(v))
        {
            goto _open_tcp_nodelay;
        }
    }
    else
    {
        _open_tcp_nodelay:
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
        cli->socks5_proxy = (struct _swSocks5 *) emalloc(sizeof(swSocks5));
        bzero(cli->socks5_proxy, sizeof(swSocks5));
        cli->socks5_proxy->host = estrdup(Z_STRVAL_P(v));
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
            cli->socks5_proxy->username = estrdup(Z_STRVAL_P(v));
            cli->socks5_proxy->l_username = Z_STRLEN_P(v);
            cli->socks5_proxy->method = 0x02;
        }
        if (php_swoole_array_get_value(vht, "socks5_password", v))
        {
            convert_to_string(v);
            cli->socks5_proxy->password = estrdup(Z_STRVAL_P(v));
            cli->socks5_proxy->l_password = Z_STRLEN_P(v);
        }
    }
    if (php_swoole_array_get_value(vht, "http_proxy_host", v))
    {
        convert_to_string(v);
        char *host = Z_STRVAL_P(v);
        if (php_swoole_array_get_value(vht, "http_proxy_port", v))
        {
            convert_to_long(v);
            cli->http_proxy = (struct _http_proxy*) ecalloc(1, sizeof(struct _http_proxy));
            cli->http_proxy->proxy_host = estrdup(host);
            cli->http_proxy->proxy_port = Z_LVAL_P(v);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "http_proxy_port can not be null.");
        }
    }
    if (php_swoole_array_get_value(vht, "http_proxy_user", v) && cli->http_proxy)
    {
        convert_to_string(v);
        char *user = Z_STRVAL_P(v);
        zval *v2;
        if (php_swoole_array_get_value(vht, "http_proxy_password", v2))
        {
            convert_to_string(v);
            if (Z_STRLEN_P(v) + Z_STRLEN_P(v2) >= 128 - 1)
            {
                swoole_php_fatal_error(E_WARNING, "http_proxy user and password is too long.");
            }
            cli->http_proxy->l_user = Z_STRLEN_P(v);
            cli->http_proxy->l_password = Z_STRLEN_P(v2);
            cli->http_proxy->user = estrdup(user);
            cli->http_proxy->password = estrdup(Z_STRVAL_P(v2));
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "http_proxy_password can not be null.");
        }
    }
    //https proxy
    if (php_swoole_array_get_value(vht, "http_proxy_ssl", v) && cli->http_proxy)
    {
        convert_to_boolean(v);
        cli->http_proxy->ssl = Z_BVAL_P(v);
    }
#ifdef SW_USE_OPENSSL
    if (cli->open_ssl)
    {
        client_coro_check_ssl_setting(cli, zset);
    }
#endif
}

#ifdef SW_USE_OPENSSL
static void client_coro_check_ssl_setting(Socket *cli, zval *zset)
{
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *v;

    if (php_swoole_array_get_value(vht, "ssl_method", v))
    {
        convert_to_long(v);
        cli->ssl_option.method = (int) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_compress", v))
    {
        convert_to_boolean(v);
        cli->ssl_option.disable_compress = !Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_cert_file", v))
    {
        convert_to_string(v);
        cli->ssl_option.cert_file = sw_strdup(Z_STRVAL_P(v));
        if (access(cli->ssl_option.cert_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", cli->ssl_option.cert_file);
            return;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", v))
    {
        convert_to_string(v);
        cli->ssl_option.key_file = sw_strdup(Z_STRVAL_P(v));
        if (access(cli->ssl_option.key_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", cli->ssl_option.key_file);
            return;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_passphrase", v))
    {
        convert_to_string(v);
        cli->ssl_option.passphrase = sw_strdup(Z_STRVAL_P(v));
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (php_swoole_array_get_value(vht, "ssl_host_name", v))
    {
        convert_to_string(v);
        cli->ssl_option.tls_host_name = sw_strdup(Z_STRVAL_P(v));
    }
#endif
    if (php_swoole_array_get_value(vht, "ssl_verify_peer", v))
    {
        convert_to_boolean(v);
        cli->ssl_option.verify_peer = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", v))
    {
        convert_to_boolean(v);
        cli->ssl_option.allow_self_signed = Z_BVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_cafile", v))
    {
        convert_to_string(v);
        cli->ssl_option.cafile = sw_strdup(Z_STRVAL_P(v));
    }
    if (php_swoole_array_get_value(vht, "ssl_capath", v))
    {
        convert_to_string(v);
        cli->ssl_option.capath = sw_strdup(Z_STRVAL_P(v));
    }
    if (php_swoole_array_get_value(vht, "ssl_verify_depth", v))
    {
        convert_to_long(v);
        cli->ssl_option.verify_depth = (int) Z_LVAL_P(v);
    }
    if (cli->ssl_option.cert_file && !cli->ssl_option.key_file)
    {
        swoole_php_fatal_error(E_ERROR, "ssl require key file.");
        return;
    }
}
#endif

static PHP_METHOD(swoole_client_coro, __construct)
{
    long type = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|ls", &type) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "socket type param is required.");
        RETURN_FALSE;
    }

    int client_type = php_swoole_socktype(type);
    if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_STREAM)
    {
        swoole_php_fatal_error(E_ERROR, "Unknown client type '%d'.", client_type);
    }

    php_swoole_check_reactor();

    zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("type"), type TSRMLS_CC);
    //init
    swoole_set_object(getThis(), NULL);
    swoole_set_property(getThis(), client_property_callback, NULL);
#ifdef SWOOLE_SOCKETS_SUPPORT
    swoole_set_property(getThis(), client_property_socket, NULL);
#endif
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    Socket *cli = (Socket *) swoole_get_object(getThis());
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
}

static PHP_METHOD(swoole_client_coro, set)
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

    zval *zsetting = php_swoole_read_init_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting") TSRMLS_CC);
    sw_php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, connect)
{
    zend_long port = 0, sock_flag = 0;
    char *host = NULL;
    zend_size_t host_len;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 4)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_DOUBLE(timeout)
        Z_PARAM_LONG(sock_flag)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ldl", &host, &host_len, &port, &timeout, &sock_flag) == FAILURE)
    {
        return;
    }
#endif

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "The host is empty.");
        RETURN_FALSE;
    }

    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (cli)
    {
        swoole_php_fatal_error(E_WARNING, "connection to the server has already been established.");
        RETURN_FALSE;
    }

    cli = client_coro_new(getThis(), (int) port);
    if (cli == NULL)
    {
        RETURN_FALSE;
    }
    cli->_timeout = timeout;
    swoole_set_object(getThis(), cli);

    zval *zset = sw_zend_read_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        php_swoole_client_coro_check_setting(cli, zset);
    }

    if (!cli->connect(host, port, sock_flag))
    {
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, cli->errCode);
        swoole_php_error(E_WARNING, "connect to server[%s:%d] failed. Error: %s[%d]", host, (int )port, cli->errMsg,
                cli->errCode);
        RETURN_FALSE;
    }
    zend_update_property_bool(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("connected")-1, 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, send)
{
    char *data;
    zend_size_t data_len;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
    {
        return;
    }
#endif

    if (data_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "data to send is empty.");
        RETURN_FALSE;
    }

    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }

    //clear errno
    SwooleG.error = 0;
    int ret = cli->send_all(data, data_len);
    if (ret < 0)
    {
        swoole_php_sys_error(E_WARNING, "failed to send(%d) %zd bytes.", cli->socket->fd, data_len);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
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
        swoole_php_error(E_WARNING, "data to send is empty.");
        RETURN_FALSE;
    }

    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (!cli)
    {
        cli = client_coro_new(getThis(), (int) port);
        if (cli == NULL)
        {
            RETURN_FALSE;
        }
        cli->socket->active = 1;
        swoole_set_object(getThis(), cli);
    }
    SW_CHECK_RETURN(cli->sendto(ip, port, data, len));
}

static PHP_METHOD(swoole_client_coro, recvfrom)
{
    zend_long length;
    zval *port, *address;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz/|z/", &length, &address, &port) == FAILURE)
    {
        return;
    }

    if (length <= 0)
    {
        swoole_php_error(E_WARNING, "invalid length.");
        RETURN_FALSE;
    }

    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (!cli)
    {
        cli = client_coro_new(getThis());
        if (cli == NULL)
        {
            RETURN_FALSE;
        }
        cli->socket->active = 1;
        swoole_set_object(getThis(), cli);
    }

    zend_string *retval = zend_string_alloc(length + 1, 0);
    ssize_t n_bytes = cli->recvfrom(retval->val, length);
    if (n_bytes < 0)
    {
        zend_string_free(retval);
        RETURN_FALSE;
    }
    else
    {
        ZSTR_LEN(retval) = n_bytes;
        ZSTR_VAL(retval)[ZSTR_LEN(retval)] = '\0';
        ZVAL_STRING(address, swConnection_get_ip(cli->socket));
        ZVAL_LONG(port, swConnection_get_port(cli->socket));
        RETURN_STR(retval);
    }
}

static PHP_METHOD(swoole_client_coro, sendfile)
{
    char *file;
    zend_size_t file_len;
    long offset = 0;
    long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ll", &file, &file_len, &offset, &length) == FAILURE)
    {
        return;
    }
    if (file_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "file to send is empty.");
        RETURN_FALSE;
    }

    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
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
    int ret = cli->sendfile(file, offset, length);
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
    double timeout = 0;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(buf_len)
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|d", &timeout) == FAILURE)
    {
        return;
    }
#endif

    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (timeout != 0)
    {
        cli->setTimeout(timeout);
    }
    ssize_t retval ;
    if (cli->open_length_check || cli->open_eof_check)
    {
        retval = cli->recv_packet();
        if (retval > 0)
        {
            RETVAL_STRINGL(cli->buffer->str, retval);
        }
    }
    else
    {
        zend_string *result = zend_string_alloc(SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string), 0);
        retval = cli->recv(result->val, SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string));
        if (retval > 0)
        {
            result->val[retval] = 0;
            result->len = retval;
            RETURN_STR(result);
        }
        else
        {
            zend_string_free(result);
        }
    }
    if (retval < 0)
    {
        SwooleG.error = cli->errCode;
        swoole_php_error(E_WARNING, "recv() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETURN_FALSE;
    }
    else if (retval == 0)
    {
        RETURN_EMPTY_STRING();
    }
}

static PHP_METHOD(swoole_client_coro, peek)
{
    zend_long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    int ret;
    char *buf = NULL;

#ifdef FAST_ZPP
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(buf_len)
    ZEND_PARSE_PARAMETERS_END();
#else
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &buf_len) == FAILURE)
    {
        return;
    }
#endif

    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }

    buf = (char *) emalloc(buf_len + 1);
    SwooleG.error = 0;
    ret = cli->peek(buf, buf_len);

    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_error(E_WARNING, "recv() failed. Error: %s [%d]", strerror(SwooleG.error), SwooleG.error);
        zend_update_property_long(swoole_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1,
                SwooleG.error TSRMLS_CC);
        swoole_efree(buf);
        RETURN_FALSE;
    }
    else
    {
        buf[ret] = 0;
        SW_RETVAL_STRINGL(buf, ret, 0);
    }
}

static PHP_METHOD(swoole_client_coro, isConnected)
{
    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (cli && cli->socket && cli->socket->active == 1)
    {
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client_coro, getsockname)
{
    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
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
static PHP_METHOD(swoole_client_coro, getSocket)
{
    zval *zsocket = (zval *) swoole_get_property(getThis(), client_property_socket);
    if (zsocket)
    {
        RETURN_ZVAL(zsocket, 1, NULL);
    }
    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
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

static PHP_METHOD(swoole_client_coro, getpeername)
{
    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UDP)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v4.sin_port));
        sw_add_assoc_string(return_value, "host", inet_ntoa(cli->socket->info.addr.inet_v4.sin_addr), 1);
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        array_init(return_value);
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
        swoole_php_fatal_error(E_WARNING, "only supports SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6.");
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client_coro, close)
{
    int ret = 1;
    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "client is not connected to the server.");
        RETURN_FALSE;
    }
    ret = cli->close();
    php_swoole_client_coro_free(getThis(), cli TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL)
{
    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
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
    cli->open_ssl = true;
    zval *zset = sw_zend_read_property(swoole_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        client_coro_check_ssl_setting(cli, zset TSRMLS_CC);
    }
    if (cli->ssl_handshake() == false)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, getPeerCert)
{
    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (!cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL is not ready.");
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
    Socket *cli = client_get_ptr(getThis() TSRMLS_CC);
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (!cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL is not ready.");
        RETURN_FALSE;
    }
    zend_bool allow_self_signed = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &allow_self_signed) == FAILURE)
    {
        return;
    }
    SW_CHECK_RETURN(cli->ssl_verify(allow_self_signed));
}
#endif



