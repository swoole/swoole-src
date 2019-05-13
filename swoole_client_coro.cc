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
#include "socks5.h"
#include "mqtt.h"

#include "ext/standard/basic_functions.h"

using swoole::coroutine::Socket;

enum client_property
{
    client_property_callback = 0,
    client_property_coroutine = 1,
    client_property_socket = 2,
};

using namespace swoole;

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
    ZEND_ARG_INFO(0, sock_flag)
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

static void php_swoole_socket_set_ssl(Socket *cli, zval *zset);
static Socket* client_coro_new(zval *zobject, int port = 0);
void php_swoole_client_coro_socket_free(Socket *cli);

static const zend_function_entry swoole_client_coro_methods[] =
{
    PHP_ME(swoole_client_coro, __construct, arginfo_swoole_client_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client_coro, __destruct, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
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

zend_class_entry *swoole_client_coro_ce;
static zend_object_handlers swoole_client_coro_handlers;

void swoole_client_coro_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_client_coro, "Swoole\\Coroutine\\Client", NULL, "Co\\Client", swoole_client_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_client_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_client_coro, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_client_coro);

    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_client_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_client_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_OOB"), MSG_OOB);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_PEEK"), MSG_PEEK);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL);
}

static sw_inline Socket* client_get_ptr(zval *zobject, bool silent = false)
{
    Socket *cli = (Socket *) swoole_get_object(zobject);
    if (cli && cli->socket && cli->socket->active == 1)
    {
        return cli;
    }
    else
    {
        if (!silent)
        {
            zend_update_property_long(swoole_client_coro_ce, zobject, ZEND_STRL("errCode"), SW_ERROR_CLIENT_NO_CONNECTION);
            zend_update_property_string(swoole_client_coro_ce, zobject, ZEND_STRL("errMsg"), swoole_strerror(SW_ERROR_CLIENT_NO_CONNECTION));
        }
        return nullptr;
    }
}

static Socket* client_coro_new(zval *zobject, int port)
{
    zval *ztype = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("type"), 0);
    zend_long type = zval_get_long(ztype);

    if ((type == SW_SOCK_TCP || type == SW_SOCK_TCP6) && (port <= 0 || port > SW_CLIENT_MAX_PORT))
    {
        swoole_php_fatal_error(E_WARNING, "The port is invalid");
        return NULL;
    }

    php_swoole_check_reactor();
    Socket *cli = new Socket((enum swSocket_type) type);
    if (UNEXPECTED(cli->socket == nullptr))
    {
        swoole_php_sys_error(E_WARNING, "new Socket() failed");
        zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("errCode"), errno);
        zend_update_property_string(Z_OBJCE_P(zobject), zobject, ZEND_STRL("errMsg"), strerror(errno));
        delete cli;
        return NULL;
    }

    zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("sock"), cli->socket->fd);

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL)
    {
        cli->open_ssl = true;
    }
#endif

    swoole_set_object(zobject, cli);

    return cli;
}

static bool client_coro_close(zval *zobject)
{
    Socket *cli = (Socket *) swoole_get_object(zobject);
    if (cli)
    {
        zend_update_property_bool(Z_OBJCE_P(zobject), zobject, ZEND_STRL("connected"), 0);
        if (!cli->get_bound_cid())
        {
#ifdef SWOOLE_SOCKETS_SUPPORT
            zval *zsocket = (zval *) swoole_get_property(zobject, client_property_socket);
            if (zsocket)
            {
                swoole_php_socket_free(zsocket);
                swoole_set_property(zobject, client_property_socket, NULL);
            }
#endif
            swoole_set_object(zobject, NULL);
        }
        php_swoole_client_coro_socket_free(cli);
        return true;
    }
    return false;
}

void php_swoole_client_coro_socket_free_socks5_proxy(Socket *cli)
{
    if (cli->socks5_proxy)
    {
        if (cli->socks5_proxy->host)
        {
            efree(cli->socks5_proxy->host);
            cli->socks5_proxy->host = nullptr;
        }
        if (cli->socks5_proxy->username)
        {
            efree(cli->socks5_proxy->username);
            cli->socks5_proxy->username = nullptr;
        }
        if (cli->socks5_proxy->password)
        {
            efree(cli->socks5_proxy->password);
            cli->socks5_proxy->password = nullptr;
        }
        efree(cli->socks5_proxy);
        cli->socks5_proxy = nullptr;
    }
}

void php_swoole_client_coro_socket_free_http_proxy(Socket *cli)
{
    if (cli->http_proxy)
    {
        if (cli->http_proxy->proxy_host)
        {
            efree(cli->http_proxy->proxy_host);
            cli->http_proxy->proxy_host = nullptr;
        }
        if (cli->http_proxy->user)
        {
            efree(cli->http_proxy->user);
            cli->http_proxy->user = nullptr;
        }
        if (cli->http_proxy->password)
        {
            efree(cli->http_proxy->password);
            cli->http_proxy->password = nullptr;
        }
        efree(cli->http_proxy);
        cli->http_proxy = nullptr;
    }
}

void php_swoole_client_coro_socket_free(Socket *cli)
{
    //FIXME: move to Socket method, we should not manage it externally
    if (!cli->has_bound())
    {
        php_swoole_client_coro_socket_free_socks5_proxy(cli);
        php_swoole_client_coro_socket_free_http_proxy(cli);
        if (cli->protocol.private_data)
        {
            zval *zcallback = (zval *) cli->protocol.private_data;
            sw_zval_free(zcallback);
            cli->protocol.private_data = nullptr;
        }
    }
    if (cli->close())
    {
        delete cli;
    }
}

void php_swoole_client_set(Socket *cli, zval *zset)
{
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *v;
    /**
     * timeout
     */
    if (php_swoole_array_get_value(vht, "timeout", v))
    {
        cli->set_timeout(zval_get_double(v));
    }
    if (php_swoole_array_get_value(vht, "connect_timeout", v))
    {
        cli->set_timeout(zval_get_double(v), SW_TIMEOUT_CONNECT);
    }
    if (php_swoole_array_get_value(vht, "read_timeout", v))
    {
        cli->set_timeout(zval_get_double(v), SW_TIMEOUT_READ);
    }
    if (php_swoole_array_get_value(vht, "write_timeout", v))
    {
        cli->set_timeout(zval_get_double(v), SW_TIMEOUT_WRITE);
    }
    /**
     * bind port
     */
    if (php_swoole_array_get_value(vht, "bind_port", v))
    {
        int bind_port = (int) zval_get_long(v);
        /**
         * bind address
         */
        if (php_swoole_array_get_value(vht, "bind_address", v))
        {
            zend::string str_v(v);
            swSocket_bind(cli->socket->fd, cli->type, str_v.val(), &bind_port);
        }
    }
    /**
     * socket send/recv buffer size
     */
    if (php_swoole_array_get_value(vht, "socket_buffer_size", v))
    {
        zend_long size = zval_get_long(v);
        if (size <= 0)
        {
            swWarn("socket buffer size must be greater than 0");
        }
        else
        {
            cli->set_option(SOL_SOCKET, SO_RCVBUF, size) && cli->set_option(SOL_SOCKET, SO_SNDBUF, size);
        }
    }
    /**
     * client: tcp_nodelay
     */
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", v))
    {
        if (cli->type == SW_SOCK_TCP || cli->type != SW_SOCK_TCP6)
        {
            cli->set_option(IPPROTO_TCP, TCP_NODELAY, zval_is_true(v));
        }
    }
    /**
     * ssl
     */
#ifdef SW_USE_OPENSSL
    if (cli->open_ssl)
    {
        php_swoole_socket_set_ssl(cli, zset);
    }
#endif
    /**
     * about protocol...
     */
    //buffer: eof check
    if (php_swoole_array_get_value(vht, "open_eof_check", v))
    {
        cli->open_eof_check = zval_is_true(v);
    }
    //buffer: split package with eof
    if (php_swoole_array_get_value(vht, "open_eof_split", v))
    {
        cli->protocol.split_by_eof = zval_is_true(v);
        if (cli->protocol.split_by_eof)
        {
            cli->open_eof_check = 1;
        }
    }
    //package eof
    if (php_swoole_array_get_value(vht, "package_eof", v))
    {
        zend::string str_v(v);
        cli->protocol.package_eof_len = str_v.len();
        if (cli->protocol.package_eof_len == 0)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof cannot be an empty string");
            return;
        }
        else if (cli->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            return;
        }
        bzero(cli->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(cli->protocol.package_eof, str_v.val(), str_v.len());
    }
    //open mqtt protocol
    if (php_swoole_array_get_value(vht, "open_mqtt_protocol", v))
    {
        cli->open_length_check = zval_is_true(v);
        cli->protocol.get_package_length = swMqtt_get_package_length;
    }
    //open length check
    if (php_swoole_array_get_value(vht, "open_length_check", v))
    {
        cli->open_length_check = zval_is_true(v);
        cli->protocol.get_package_length = swProtocol_get_package_length;
    }
    //package length size
    if (php_swoole_array_get_value(vht, "package_length_type", v))
    {
        zend::string str_v(v);
        cli->protocol.package_length_type = str_v.val()[0];
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
        cli->protocol.package_length_offset = (int) zval_get_long(v);
    }
    //package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", v))
    {
        cli->protocol.package_body_offset = (int) zval_get_long(v);
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
            if (!sw_zend_is_callable(v, 0, &func_name))
            {
                swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
                return;
            }
            efree(func_name);
            cli->protocol.get_package_length = php_swoole_length_func;
            if (cli->protocol.private_data)
            {
                zval_ptr_dtor((zval *)cli->protocol.private_data);
                efree(cli->protocol.private_data);
            }
            Z_TRY_ADDREF_P(v);
            cli->protocol.private_data = sw_zval_dup(v);
            break;
        }

        cli->protocol.package_length_size = 0;
        cli->protocol.package_length_type = '\0';
        cli->protocol.package_length_offset = SW_IPC_BUFFER_SIZE;
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", v))
    {
        cli->protocol.package_max_length = (int) zval_get_long(v);
    }
    else
    {
        cli->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
    }
    /**
     * socks5 proxy
     */
    if (php_swoole_array_get_value(vht, "socks5_host", v))
    {
        zend::string host(v);
        if (php_swoole_array_get_value(vht, "socks5_port", v))
        {
            php_swoole_client_coro_socket_free_socks5_proxy(cli);
            cli->socks5_proxy = (struct _swSocks5 *) ecalloc(1, sizeof(swSocks5));
            cli->socks5_proxy->host = estrdup(host.val());
            cli->socks5_proxy->port = zval_get_long(v);
            cli->socks5_proxy->dns_tunnel = 1;
            if (php_swoole_array_get_value(vht, "socks5_username", v))
            {
                zend::string username(v);
                if (php_swoole_array_get_value(vht, "socks5_password", v))
                {
                    zend::string password(v);
                    cli->socks5_proxy->method = 0x02;
                    cli->socks5_proxy->username = estrdup(username.val());
                    cli->socks5_proxy->l_username = username.len();
                    cli->socks5_proxy->password = estrdup(password.val());
                    cli->socks5_proxy->l_password = password.len();
                }
                else
                {
                    swoole_php_fatal_error(E_WARNING, "socks5_password should not be null");
                }
            }
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "socks5_port should not be null");
        }
    }
    /**
     * http proxy
     */
    else if (php_swoole_array_get_value(vht, "http_proxy_host", v))
    {
        zend::string host(v);
        if (php_swoole_array_get_value(vht, "http_proxy_port", v))
        {
            php_swoole_client_coro_socket_free_http_proxy(cli);
            cli->http_proxy = (struct _http_proxy*) ecalloc(1, sizeof(struct _http_proxy));
            cli->http_proxy->proxy_host = estrdup(host.val());
            cli->http_proxy->proxy_port = zval_get_long(v);
            if (php_swoole_array_get_value(vht, "http_proxy_username", v) || php_swoole_array_get_value(vht, "http_proxy_user", v))
            {
                zend::string username(v);
                if (php_swoole_array_get_value(vht, "http_proxy_password", v))
                {
                    zend::string password(v);
                    cli->http_proxy->user = estrdup(username.val());
                    cli->http_proxy->l_user = username.len();
                    cli->http_proxy->password = estrdup(password.val());
                    cli->http_proxy->l_password = password.len();
                }
                else
                {
                    swoole_php_fatal_error(E_WARNING, "http_proxy_password should not be null");
                }
            }
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "http_proxy_port should not be null");
        }
    }
}

#ifdef SW_USE_OPENSSL
static void php_swoole_socket_set_ssl(Socket *cli, zval *zset)
{
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *v;

    if (php_swoole_array_get_value(vht, "ssl_method", v))
    {
        cli->ssl_option.method = (int) zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_compress", v))
    {
        cli->ssl_option.disable_compress = !zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_cert_file", v))
    {
        zend::string str_v(v);
        if (cli->ssl_option.cert_file)
        {
            sw_free(cli->ssl_option.cert_file);
        }
        if (access(cli->ssl_option.cert_file, R_OK) == 0)
        {
            cli->ssl_option.cert_file = str_v.dup();
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "ssl cert file[%s] not found", cli->ssl_option.cert_file);
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", v))
    {
        zend::string str_v(v);
        if (cli->ssl_option.key_file)
        {
            sw_free(cli->ssl_option.key_file);
        }
        if (access(cli->ssl_option.key_file, R_OK) == 0)
        {
            cli->ssl_option.key_file = str_v.dup();
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "ssl key file[%s] not found", cli->ssl_option.key_file);
        }
    }
    if (cli->ssl_option.cert_file && !cli->ssl_option.key_file)
    {
        swoole_php_fatal_error(E_WARNING, "ssl require key file");
    }
    else if (cli->ssl_option.key_file && !cli->ssl_option.cert_file)
    {
        swoole_php_fatal_error(E_WARNING, "ssl require cert file");
    }
    if (php_swoole_array_get_value(vht, "ssl_passphrase", v))
    {
        if (cli->ssl_option.passphrase)
        {
            sw_free(cli->ssl_option.passphrase);
        }
        cli->ssl_option.passphrase = zend::string(v).dup();
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (php_swoole_array_get_value(vht, "ssl_host_name", v))
    {
        if (cli->ssl_option.tls_host_name)
        {
            sw_free(cli->ssl_option.tls_host_name);
        }
        cli->ssl_option.tls_host_name = zend::string(v).dup();
        cli->ssl_option.disable_tls_host_name = !cli->ssl_option.tls_host_name;
    }
#endif
    if (php_swoole_array_get_value(vht, "ssl_verify_peer", v))
    {
        cli->ssl_option.verify_peer = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", v))
    {
        cli->ssl_option.allow_self_signed = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "ssl_cafile", v))
    {
        if (cli->ssl_option.cafile)
        {
            sw_free(cli->ssl_option.cafile);
        }
        cli->ssl_option.cafile = zend::string(v).dup();
    }
    if (php_swoole_array_get_value(vht, "ssl_capath", v))
    {
        if (cli->ssl_option.capath)
        {
            sw_free( cli->ssl_option.capath);
        }
        cli->ssl_option.capath = zend::string(v).dup();
    }
    if (php_swoole_array_get_value(vht, "ssl_verify_depth", v))
    {
        cli->ssl_option.verify_depth = (int) zval_get_long(v);
    }
}
#endif

static PHP_METHOD(swoole_client_coro, __construct)
{
    zend_long type = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int client_type = php_swoole_socktype(type);
    if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_STREAM)
    {
        const char *space, *class_name = get_active_class_name(&space);
        zend_type_error(
            "%s%s%s() expects parameter %d to be client type, unknown type " ZEND_LONG_FMT " given",
            class_name, space, get_active_function_name(), 1, type
        );
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("type"), type);
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
    SW_PREVENT_USER_DESTRUCT();

    client_coro_close(getThis());
}

static PHP_METHOD(swoole_client_coro, set)
{
    Socket *cli = client_get_ptr(getThis(), true);
    zval *zset, *zsetting;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zsetting = sw_zend_read_and_convert_property_array(swoole_client_coro_ce, getThis(), ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    if (cli)
    {
        php_swoole_client_set(cli, zset);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, connect)
{
    char *host;
    size_t host_len;
    zend_long port = 0;
    double timeout = 0;
    zend_long sock_flag = 0;

    ZEND_PARSE_PARAMETERS_START(1, 4)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_DOUBLE(timeout)
        Z_PARAM_LONG(sock_flag)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (host_len == 0)
    {
        swoole_php_fatal_error(E_WARNING, "The host is empty");
        RETURN_FALSE;
    }

    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (cli)
    {
        RETURN_FALSE;
    }

    cli = client_coro_new(getThis(), (int) port);
    if (!cli)
    {
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property(swoole_client_coro_ce, getThis(), ZEND_STRL("setting"), 0);
    if (zset && ZVAL_IS_ARRAY(zset))
    {
        php_swoole_client_set(cli, zset);
    }

    cli->set_timeout(timeout, SW_TIMEOUT_CONNECT);
    if (!cli->connect(host, port, sock_flag))
    {
        zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), cli->errMsg);
        client_coro_close(getThis());
        RETURN_FALSE;
    }
    cli->set_timeout(timeout, SW_TIMEOUT_RDWR);
    zend_update_property_bool(swoole_client_coro_ce, getThis(), ZEND_STRL("connected"), 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, send)
{
    char *data;
    size_t data_len;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(data, data_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (data_len == 0)
    {
        swoole_php_fatal_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }

    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }

    Socket::timeout_setter ts(cli, timeout, SW_TIMEOUT_WRITE);
    ssize_t ret = cli->send_all(data, data_len);
    if (ret < 0)
    {
        zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), cli->errMsg);
        RETVAL_FALSE;
    }
    else
    {
        if ((size_t) ret < data_len && cli->errCode)
        {
            zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), cli->errCode);
            zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), cli->errMsg);
        }
        RETURN_LONG(ret);
    }
}

static PHP_METHOD(swoole_client_coro, sendto)
{
    char* ip;
    size_t ip_len;
    long port;
    char *data;
    size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sls", &ip, &ip_len, &port, &data, &len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (len == 0)
    {
        RETURN_FALSE;
    }

    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (!cli)
    {
        cli = client_coro_new(getThis(), (int) port);
        if (!cli)
        {
            RETURN_FALSE;
        }
        cli->socket->active = 1;
    }
    SW_CHECK_RETURN(cli->sendto(ip, port, data, len));
}

static PHP_METHOD(swoole_client_coro, recvfrom)
{
    zend_long length;
    zval *address, *port;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz/|z/", &length, &address, &port) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (length <= 0)
    {
        RETURN_FALSE;
    }

    Socket *cli = (Socket *) swoole_get_object(getThis());
    if (!cli)
    {
        cli = client_coro_new(getThis());
        if (!cli)
        {
            RETURN_FALSE;
        }
        cli->socket->active = 1;
    }

    zend_string *retval = zend_string_alloc(length + 1, 0);
    ssize_t n_bytes = cli->recvfrom(ZSTR_VAL(retval), length);
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
        if (port)
        {
            ZVAL_LONG(port, swConnection_get_port(cli->socket));
        }
        RETURN_STR(retval);
    }
}

static PHP_METHOD(swoole_client_coro, sendfile)
{
    char *file;
    size_t file_len;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &file, &file_len, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (file_len == 0)
    {
        swoole_php_fatal_error(E_WARNING, "file to send is empty");
        RETURN_FALSE;
    }

    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    //only stream socket can sendfile
    if (!(cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_TCP6 || cli->type == SW_SOCK_UNIX_STREAM))
    {
        zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), EINVAL);
        zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), "dgram socket cannot use sendfile");
        RETURN_FALSE;
    }
    int ret = cli->sendfile(file, offset, length);
    if (ret < 0)
    {
        zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), cli->errMsg);
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

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    ssize_t retval ;
    if (cli->open_length_check || cli->open_eof_check)
    {
        retval = cli->recv_packet(timeout);
        if (retval > 0)
        {
            RETVAL_STRINGL(cli->read_buffer->str, retval);
        }
    }
    else
    {
        zend_string *result = zend_string_alloc(SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string), 0);
        Socket::timeout_setter ts(cli, timeout, SW_TIMEOUT_READ);
        retval = cli->recv(ZSTR_VAL(result), SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string));
        if (retval > 0)
        {
            ZSTR_VAL(result)[retval] = '\0';
            ZSTR_LEN(result) = retval;
            RETURN_STR(result);
        }
        else
        {
            zend_string_free(result);
        }
    }
    if (retval < 0)
    {
        zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), cli->errMsg);
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

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(buf_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }

    buf = (char *) emalloc(buf_len + 1);
    ret = cli->peek(buf, buf_len);
    if (ret < 0)
    {
        zend_update_property_long(swoole_client_coro_ce, getThis(), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, getThis(), ZEND_STRL("errMsg"), cli->errMsg);
        efree(buf);
        RETURN_FALSE;
    }
    else
    {
        buf[ret] = 0;
        RETVAL_STRINGL(buf, ret);
        efree(buf);
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
    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UNIX_STREAM || cli->type == SW_SOCK_UNIX_DGRAM)
    {
        swoole_php_fatal_error(E_WARNING, "getsockname() only support AF_INET family socket");
        RETURN_FALSE;
    }

    cli->socket->info.len = sizeof(cli->socket->info.addr);
    if (getsockname(cli->socket->fd, (struct sockaddr*) &cli->socket->info.addr, &cli->socket->info.len) < 0)
    {
        swoole_php_sys_error(E_WARNING, "getsockname() failed");
        RETURN_FALSE;
    }

    array_init(return_value);
    if (cli->type == SW_SOCK_UDP6 || cli->type == SW_SOCK_TCP6)
    {
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v6.sin6_port));
        char tmp[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &cli->socket->info.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)))
        {
            add_assoc_string(return_value, "host", tmp);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "inet_ntop() failed");
        }
    }
    else
    {
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v4.sin_port));
        add_assoc_string(return_value, "host", inet_ntoa(cli->socket->info.addr.inet_v4.sin_addr));
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
    Socket *cli = client_get_ptr(getThis());
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
    Z_TRY_ADDREF_P(zsocket);
    swoole_set_property(getThis(), client_property_socket, zsocket);
}
#endif

static PHP_METHOD(swoole_client_coro, getpeername)
{
    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }

    if (cli->type == SW_SOCK_UDP)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v4.sin_port));
        add_assoc_string(return_value, "host", inet_ntoa(cli->socket->info.addr.inet_v4.sin_addr));
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        array_init(return_value);
        add_assoc_long(return_value, "port", ntohs(cli->socket->info.addr.inet_v6.sin6_port));
        char tmp[INET6_ADDRSTRLEN];

        if (inet_ntop(AF_INET6, &cli->socket->info.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)))
        {
            add_assoc_string(return_value, "host", tmp);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "inet_ntop() failed");
        }
    }
    else if (cli->type == SW_SOCK_UNIX_DGRAM)
    {
        add_assoc_string(return_value, "host", cli->socket->info.addr.un.sun_path);
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "only supports SWOOLE_SOCK_(UDP/UDP6/UNIX_DGRAM)");
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client_coro, close)
{
    RETURN_BOOL(client_coro_close(getThis()));
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL)
{
    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (cli->type != SW_SOCK_TCP && cli->type != SW_SOCK_TCP6)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use enableSSL");
        RETURN_FALSE;
    }
    if (cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL has been enabled");
        RETURN_FALSE;
    }
    cli->open_ssl = true;
    zval *zset = sw_zend_read_property(swoole_client_coro_ce, getThis(), ZEND_STRL("setting"), 0);
    if (ZVAL_IS_ARRAY(zset))
    {
        php_swoole_socket_set_ssl(cli, zset);
    }
    if (cli->ssl_handshake() == false)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, getPeerCert)
{
    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (!cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    char buf[8192];
    int n = swSSL_get_client_certificate(cli->socket->ssl, buf, sizeof(buf));
    if (n < 0)
    {
        RETURN_FALSE;
    }
    RETURN_STRINGL(buf, n);
}

static PHP_METHOD(swoole_client_coro, verifyPeerCert)
{
    Socket *cli = client_get_ptr(getThis());
    if (!cli)
    {
        RETURN_FALSE;
    }
    if (!cli->socket->ssl)
    {
        swoole_php_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    zend_bool allow_self_signed = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &allow_self_signed) == FAILURE)
    {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(cli->ssl_verify(allow_self_signed));
}
#endif
