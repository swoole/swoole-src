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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_protocol.h"
#include "swoole_proxy.h"

using swoole::HttpProxy;
using swoole::Socks5Proxy;
using swoole::String;
using swoole::coroutine::Socket;
using swoole::network::Address;
#ifdef SW_USE_OPENSSL
using swoole::SSLContext;
#endif

static zend_class_entry *swoole_client_coro_ce;
static zend_object_handlers swoole_client_coro_handlers;

struct ClientCoroObject {
    Socket *sock;
    zend_object std;
};

SW_EXTERN_C_BEGIN
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
static PHP_METHOD(swoole_client_coro, exportSocket);
static PHP_METHOD(swoole_client_coro, isConnected);
static PHP_METHOD(swoole_client_coro, getsockname);
static PHP_METHOD(swoole_client_coro, getpeername);
static PHP_METHOD(swoole_client_coro, close);
SW_EXTERN_C_END

static Socket *client_coro_new(zval *zobject, int port = 0);
void php_swoole_client_coro_socket_free(Socket *cli);

// clang-format off
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
    PHP_ME(swoole_client_coro, exportSocket, arginfo_swoole_client_coro_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

static sw_inline ClientCoroObject *php_swoole_client_coro_fetch_object(zend_object *obj) {
    return (ClientCoroObject *) ((char *) obj - swoole_client_coro_handlers.offset);
}

static sw_inline ClientCoroObject *php_swoole_get_client(zval *zobject) {
    return php_swoole_client_coro_fetch_object(Z_OBJ_P(zobject));
}

static sw_inline Socket *php_swoole_get_sock(zval *zobject) {
    return php_swoole_get_client(zobject)->sock;
}

static void php_swoole_client_coro_free_object(zend_object *object) {
    ClientCoroObject *client = php_swoole_client_coro_fetch_object(object);
    if (client->sock) {
        php_swoole_client_coro_socket_free(client->sock);
    }
    zend_object_std_dtor(&client->std);
}

static zend_object *php_swoole_client_coro_create_object(zend_class_entry *ce) {
    ClientCoroObject *sock_t = (ClientCoroObject *) zend_object_alloc(sizeof(ClientCoroObject), ce);
    zend_object_std_init(&sock_t->std, ce);
    object_properties_init(&sock_t->std, ce);
    sock_t->std.handlers = &swoole_client_coro_handlers;
    return &sock_t->std;
}

void php_swoole_client_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(
        swoole_client_coro, "Swoole\\Coroutine\\Client", nullptr, "Co\\Client", swoole_client_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_client_coro);
    SW_SET_CLASS_CLONEABLE(swoole_client_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_client_coro,
                               php_swoole_client_coro_create_object,
                               php_swoole_client_coro_free_object,
                               ClientCoroObject,
                               std);

    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_client_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("fd"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_coro_ce, ZEND_STRL("socket"), ZEND_ACC_PRIVATE);
    zend_declare_property_long(swoole_client_coro_ce, ZEND_STRL("type"), SW_SOCK_TCP, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_client_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_OOB"), MSG_OOB);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_PEEK"), MSG_PEEK);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT);
    zend_declare_class_constant_long(swoole_client_coro_ce, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL);
}

static sw_inline Socket *client_get_ptr(zval *zobject, bool silent = false) {
    Socket *cli = php_swoole_get_client(zobject)->sock;
    if (cli) {
        return cli;
    } else {
        if (!silent) {
            zend_update_property_long(
                swoole_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), SW_ERROR_CLIENT_NO_CONNECTION);
            zend_update_property_string(swoole_client_coro_ce,
                                        SW_Z8_OBJ_P(zobject),
                                        ZEND_STRL("errMsg"),
                                        swoole_strerror(SW_ERROR_CLIENT_NO_CONNECTION));
        }
        return nullptr;
    }
}

static Socket *client_coro_new(zval *zobject, int port) {
    zval *ztype = sw_zend_read_property_ex(Z_OBJCE_P(zobject), zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TYPE), 0);
    zend_long type = zval_get_long(ztype);
    enum swSocketType sock_type = php_swoole_socktype(type);

    if ((sock_type == SW_SOCK_TCP || sock_type == SW_SOCK_TCP6) && (port <= 0 || port > SW_CLIENT_MAX_PORT)) {
        php_swoole_fatal_error(E_WARNING, "The port is invalid");
        return nullptr;
    }

    php_swoole_check_reactor();
    Socket *cli = new Socket(sock_type);
    if (UNEXPECTED(cli->get_fd() < 0)) {
        php_swoole_sys_error(E_WARNING, "new Socket() failed");
        zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), errno);
        zend_update_property_string(
            Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), swoole_strerror(errno));
        delete cli;
        return nullptr;
    }

    zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("fd"), cli->get_fd());

    cli->set_buffer_allocator(sw_zend_string_allocator());
    cli->set_zero_copy(true);

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL) {
        cli->enable_ssl_encrypt();
    }
#endif

    php_swoole_get_client(zobject)->sock = cli;

    return cli;
}

static bool client_coro_close(zval *zobject) {
    Socket *cli = php_swoole_get_sock(zobject);
    if (cli) {
        zend_update_property_bool(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("connected"), 0);
        if (!cli->get_bound_cid()) {
            php_swoole_get_client(zobject)->sock = nullptr;
        }
        php_swoole_client_coro_socket_free(cli);
        return true;
    }
    return false;
}

void php_swoole_client_coro_socket_free(Socket *cli) {
    if (!cli->has_bound()) {
        if (cli->protocol.private_data) {
            sw_zend_fci_cache_discard((zend_fcall_info_cache *) cli->protocol.private_data);
            efree(cli->protocol.private_data);
            cli->protocol.private_data = nullptr;
        }
    }
    if (cli->close()) {
        delete cli;
    }
}

bool php_swoole_client_set(Socket *cli, zval *zset) {
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *ztmp;
    bool ret = true;

    /**
     * timeout
     */
    if (php_swoole_array_get_value(vht, "timeout", ztmp)) {
        cli->set_timeout(zval_get_double(ztmp));
    }
    if (php_swoole_array_get_value(vht, "connect_timeout", ztmp)) {
        cli->set_timeout(zval_get_double(ztmp), Socket::TIMEOUT_CONNECT);
    }
    if (php_swoole_array_get_value(vht, "read_timeout", ztmp)) {
        cli->set_timeout(zval_get_double(ztmp), Socket::TIMEOUT_READ);
    }
    if (php_swoole_array_get_value(vht, "write_timeout", ztmp)) {
        cli->set_timeout(zval_get_double(ztmp), Socket::TIMEOUT_WRITE);
    }
    std::string _bind_address;
    int _bind_port = 0;
    if (php_swoole_array_get_value(vht, "bind_port", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        _bind_port = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    if (php_swoole_array_get_value(vht, "bind_address", ztmp)) {
        zend::String tmp = ztmp;
        _bind_address = tmp.to_std_string();
    }
    if (!_bind_address.empty() && !cli->bind(_bind_address, _bind_port)) {
        ret = false;
    }
    /**
     * socket send/recv buffer size
     */
    if (php_swoole_array_get_value(vht, "socket_buffer_size", ztmp)) {
        zend_long size = zval_get_long(ztmp);
        if (size <= 0) {
            php_swoole_fatal_error(E_WARNING, "socket buffer size must be greater than 0, got " ZEND_LONG_FMT, size);
            ret = false;
        } else {
            cli->set_option(SOL_SOCKET, SO_RCVBUF, size) && cli->set_option(SOL_SOCKET, SO_SNDBUF, size);
        }
    }
    /**
     * client: tcp_nodelay
     */
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", ztmp)) {
        if (cli->get_type() == SW_SOCK_TCP || cli->get_type() != SW_SOCK_TCP6) {
            cli->get_socket()->set_tcp_nodelay(zval_is_true(ztmp));
        }
    }
    /**
     * openssl and protocol options
     */
    if (!php_swoole_socket_set_protocol(cli, zset)) {
        ret = false;
    }
    /**
     * socks5 proxy
     */
    if (php_swoole_array_get_value(vht, "socks5_host", ztmp)) {
        zend::String host(ztmp);
        if (php_swoole_array_get_value(vht, "socks5_port", ztmp)) {
            if (cli->socks5_proxy == nullptr) {
                cli->socks5_proxy = new Socks5Proxy();
            }
            cli->socks5_proxy->host = host.to_std_string();
            cli->socks5_proxy->port = zval_get_long(ztmp);
            cli->socks5_proxy->dns_tunnel = 1;
            if (php_swoole_array_get_value(vht, "socks5_username", ztmp)) {
                zend::String username(ztmp);
                if (username.len() > 0 && php_swoole_array_get_value(vht, "socks5_password", ztmp)) {
                    zend::String password(ztmp);
                    if (password.len() > 0) {
                        cli->socks5_proxy->method = 0x02;
                        cli->socks5_proxy->username = username.to_std_string();
                        cli->socks5_proxy->password = password.to_std_string();
                    }
                } else {
                    php_swoole_fatal_error(E_WARNING, "socks5_password should not be null");
                    ret = false;
                }
            }
        } else {
            php_swoole_fatal_error(E_WARNING, "socks5_port should not be null");
            ret = false;
        }
    }
    /**
     * http proxy
     */
    else if (php_swoole_array_get_value(vht, "http_proxy_host", ztmp)) {
        zend::String host(ztmp);
        if (php_swoole_array_get_value(vht, "http_proxy_port", ztmp)) {
            if (cli->http_proxy == nullptr) {
                cli->http_proxy = new HttpProxy();
            }
            cli->http_proxy->proxy_host = host.to_std_string();
            cli->http_proxy->proxy_port = zval_get_long(ztmp);
            if (php_swoole_array_get_value(vht, "http_proxy_username", ztmp) ||
                php_swoole_array_get_value(vht, "http_proxy_user", ztmp)) {
                zend::String username(ztmp);
                if (username.len() > 0 && php_swoole_array_get_value(vht, "http_proxy_password", ztmp)) {
                    zend::String password(ztmp);
                    if (password.len() > 0) {
                        cli->http_proxy->username = username.to_std_string();
                        cli->http_proxy->password = password.to_std_string();
                    }
                } else {
                    php_swoole_fatal_error(E_WARNING, "http_proxy_password should not be null");
                    ret = false;
                }
            }
        } else {
            php_swoole_fatal_error(E_WARNING, "http_proxy_port should not be null");
            ret = false;
        }
    }

    return ret;
}

#ifdef SW_USE_OPENSSL
bool php_swoole_socket_set_ssl(Socket *sock, zval *zset) {
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *ztmp;
    bool ret = true;

    if (php_swoole_array_get_value(vht, "ssl_protocols", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        sock->get_ssl_context()->protocols = v;
    }
    if (php_swoole_array_get_value(vht, "ssl_compress", ztmp)) {
        sock->get_ssl_context()->disable_compress = !zval_is_true(ztmp);
    } else if (php_swoole_array_get_value(vht, "ssl_disable_compression", ztmp)) {
        sock->get_ssl_context()->disable_compress = !zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "ssl_cert_file", ztmp)) {
        zend::String str_v(ztmp);
        if (access(str_v.val(), R_OK) == 0) {
            sock->get_ssl_context()->cert_file = str_v.to_std_string();
        } else {
            php_swoole_fatal_error(E_WARNING, "ssl cert file[%s] not found", str_v.val());
            ret = false;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", ztmp)) {
        zend::String str_v(ztmp);
        if (access(str_v.val(), R_OK) == 0) {
            sock->get_ssl_context()->key_file = str_v.to_std_string();
        } else {
            php_swoole_fatal_error(E_WARNING, "ssl key file[%s] not found", str_v.val());
            ret = false;
        }
    }
    if (!sock->get_ssl_context()->cert_file.empty() && sock->get_ssl_context()->key_file.empty()) {
        php_swoole_fatal_error(E_WARNING, "ssl require key file");
    } else if (!sock->get_ssl_context()->key_file.empty() && sock->get_ssl_context()->cert_file.empty()) {
        php_swoole_fatal_error(E_WARNING, "ssl require cert file");
    }
    if (php_swoole_array_get_value(vht, "ssl_passphrase", ztmp)) {
        sock->get_ssl_context()->passphrase = zend::String(ztmp).to_std_string();
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (php_swoole_array_get_value(vht, "ssl_host_name", ztmp)) {
        sock->get_ssl_context()->tls_host_name = zend::String(ztmp).to_std_string();
        /* if user set empty ssl_host_name, disable it, otherwise the underlying may set it automatically */
        sock->get_ssl_context()->disable_tls_host_name = sock->get_ssl_context()->tls_host_name.empty();
    }
#endif
    if (php_swoole_array_get_value(vht, "ssl_verify_peer", ztmp)) {
        sock->get_ssl_context()->verify_peer = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", ztmp)) {
        sock->get_ssl_context()->allow_self_signed = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "ssl_cafile", ztmp)) {
        sock->get_ssl_context()->cafile = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "ssl_capath", ztmp)) {
        sock->get_ssl_context()->capath = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "ssl_verify_depth", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        sock->get_ssl_context()->verify_depth = SW_MAX(0, SW_MIN(v, UINT8_MAX));
    }
    if (php_swoole_array_get_value(vht, "ssl_ciphers", ztmp)) {
        sock->get_ssl_context()->ciphers = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "ssl_ecdh_curve", ztmp)) {
        sock->get_ssl_context()->ecdh_curve = zend::String(ztmp).to_std_string();
    }

#ifdef OPENSSL_IS_BORINGSSL
    if (php_swoole_array_get_value(vht, "ssl_grease", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        sock->get_ssl_context()->grease = SW_MAX(0, SW_MIN(v, UINT8_MAX));
    }
#endif

    if (!sock->ssl_check_context()) {
        ret = false;
    }
    return ret;
}
#endif

static PHP_METHOD(swoole_client_coro, __construct) {
    if (php_swoole_get_client(ZEND_THIS)->sock) {
        php_swoole_fatal_error(E_ERROR, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
    }

    zend_long type = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
    Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int client_type = php_swoole_socktype(type);
    if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_DGRAM) {
        const char *space, *class_name = get_active_class_name(&space);
        zend_type_error("%s%s%s() expects parameter %d to be client type, unknown type " ZEND_LONG_FMT " given",
                        class_name,
                        space,
                        get_active_function_name(),
                        1,
                        type);
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("type"), type);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, __destruct) {}

static PHP_METHOD(swoole_client_coro, set) {
    Socket *cli = client_get_ptr(ZEND_THIS, true);
    zval *zset, *zsetting;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_array_length(zset) == 0) {
        RETURN_FALSE;
    } else {
        zsetting = sw_zend_read_and_convert_property_array(swoole_client_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
        php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
        if (cli) {
            RETURN_BOOL(php_swoole_client_set(cli, zset));
        }
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_client_coro, connect) {
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

    if (host_len == 0) {
        php_swoole_fatal_error(E_WARNING, "The host is empty");
        RETURN_FALSE;
    }

    Socket *cli = php_swoole_get_sock(ZEND_THIS);
    if (cli) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), EISCONN);
        zend_update_property_string(
            swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), swoole_strerror(EISCONN));
        RETURN_FALSE;
    }

    cli = client_coro_new(ZEND_THIS, (int) port);
    if (!cli) {
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property_ex(swoole_client_coro_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (zset && ZVAL_IS_ARRAY(zset)) {
        php_swoole_client_set(cli, zset);
    }

    cli->set_timeout(timeout, Socket::TIMEOUT_CONNECT);
    if (!cli->connect(host, port, sock_flag)) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        client_coro_close(ZEND_THIS);
        RETURN_FALSE;
    }
    cli->set_timeout(timeout, Socket::TIMEOUT_RDWR);
    zend_update_property_bool(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("connected"), 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, send) {
    char *data;
    size_t data_len;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(data, data_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (data_len == 0) {
        php_swoole_fatal_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }

    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    Socket::TimeoutSetter ts(cli, timeout, Socket::TIMEOUT_WRITE);
    ssize_t ret = cli->send_all(data, data_len);
    if (ret < 0) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETURN_FALSE;
    }

    if ((size_t) ret < data_len && cli->errCode) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
    }
    RETURN_LONG(ret);
}

static PHP_METHOD(swoole_client_coro, sendto) {
    char *host;
    size_t host_len;
    long port;
    char *data;
    size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sls", &host, &host_len, &port, &data, &len) == FAILURE) {
        RETURN_FALSE;
    }

    if (len == 0) {
        RETURN_FALSE;
    }

    Socket *cli = php_swoole_get_sock(ZEND_THIS);
    if (!cli) {
        cli = client_coro_new(ZEND_THIS, (int) port);
        if (!cli) {
            RETURN_FALSE;
        }
    }

    ssize_t ret = cli->sendto(std::string(host, host_len), port, data, len);
    if (ret < 0) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client_coro, recvfrom) {
    zend_long length;
    zval *address, *port;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz/|z/", &length, &address, &port) == FAILURE) {
        RETURN_FALSE;
    }

    if (length <= 0) {
        RETURN_FALSE;
    }

    Socket *cli = php_swoole_get_sock(ZEND_THIS);
    if (!cli) {
        cli = client_coro_new(ZEND_THIS);
        if (!cli) {
            RETURN_FALSE;
        }
    }

    zend_string *retval = zend_string_alloc(length, 0);
    ssize_t n_bytes = cli->recvfrom(ZSTR_VAL(retval), length);
    if (n_bytes < 0) {
        zend_string_free(retval);
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETURN_FALSE;
    } else {
        zval_ptr_dtor(address);
        ZVAL_STRING(address, cli->get_ip());
        if (port) {
            zval_ptr_dtor(port);
            ZVAL_LONG(port, cli->get_port());
        }

        ZSTR_LEN(retval) = n_bytes;
        ZSTR_VAL(retval)[ZSTR_LEN(retval)] = '\0';
        RETURN_STR(retval);
    }
}

static PHP_METHOD(swoole_client_coro, sendfile) {
    char *file;
    size_t file_len;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &file, &file_len, &offset, &length) == FAILURE) {
        RETURN_FALSE;
    }
    if (file_len == 0) {
        php_swoole_fatal_error(E_WARNING, "file to send is empty");
        RETURN_FALSE;
    }

    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    // only stream socket can sendfile
    if (!(cli->get_type() == SW_SOCK_TCP || cli->get_type() == SW_SOCK_TCP6 ||
          cli->get_type() == SW_SOCK_UNIX_STREAM)) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), EINVAL);
        zend_update_property_string(
            swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), "dgram socket cannot use sendfile");
        RETURN_FALSE;
    }
    if (!cli->sendfile(file, offset, length)) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETVAL_FALSE;
    } else {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client_coro, recv) {
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    ssize_t retval;
    zend_string *result = nullptr;

    if (cli->open_length_check || cli->open_eof_check) {
        retval = cli->recv_packet(timeout);
        if (retval > 0) {
            auto strval = cli->pop_packet();
            if (strval == nullptr) {
                retval = -1;
                cli->set_err(ENOMEM);
            } else {
                result = zend::fetch_zend_string_by_val(strval);
            }
        }
    } else {
        result = zend_string_alloc(SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string), 0);
        Socket::TimeoutSetter ts(cli, timeout, Socket::TIMEOUT_READ);
        retval = cli->recv(ZSTR_VAL(result), SW_PHP_CLIENT_BUFFER_SIZE - sizeof(zend_string));
        if (retval <= 0) {
            zend_string_free(result);
        }
    }
    if (retval < 0) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETURN_FALSE;
    } else if (retval == 0) {
        RETURN_EMPTY_STRING();
    } else {
        ZSTR_VAL(result)[retval] = '\0';
        ZSTR_LEN(result) = retval;
        RETURN_STR(result);
    }
}

static PHP_METHOD(swoole_client_coro, peek) {
    zend_long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    int ret;
    char *buf = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(buf_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    buf = (char *) emalloc(buf_len + 1);
    ret = cli->peek(buf, buf_len);
    if (ret < 0) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        efree(buf);
        RETURN_FALSE;
    } else {
        buf[ret] = 0;
        RETVAL_STRINGL(buf, ret);
        efree(buf);
    }
}

static PHP_METHOD(swoole_client_coro, isConnected) {
    Socket *cli = php_swoole_get_sock(ZEND_THIS);
    if (cli && cli->is_connected()) {
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_client_coro, getsockname) {
    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    Address sa;
    if (!cli->getsockname(&sa)) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETURN_FALSE;
    }

    array_init(return_value);
    zval zaddress;
    ZVAL_STRING(&zaddress, sa.get_ip());
    add_assoc_zval(return_value, "host", &zaddress); /* backward compatibility */
    Z_ADDREF(zaddress);
    add_assoc_zval(return_value, "address", &zaddress);
    add_assoc_long(return_value, "port", sa.get_port());
}

/**
 * export Swoole\Coroutine\Socket object
 */
static PHP_METHOD(swoole_client_coro, exportSocket) {
    zval rv;
    zval *zsocket =
        zend_read_property_ex(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), SW_ZSTR_KNOWN(SW_ZEND_STR_SOCKET), 1, &rv);
    if (!ZVAL_IS_NULL(zsocket)) {
        RETURN_ZVAL(zsocket, 1, 0);
    }

    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!php_swoole_export_socket(return_value, cli)) {
        RETURN_FALSE;
    }
    zend_update_property_ex(
        swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), SW_ZSTR_KNOWN(SW_ZEND_STR_SOCKET), return_value);
}

static PHP_METHOD(swoole_client_coro, getpeername) {
    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    Address sa;
    if (!cli->getpeername(&sa)) {
        zend_update_property_long(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), cli->errCode);
        zend_update_property_string(swoole_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errMsg"), cli->errMsg);
        RETURN_FALSE;
    }

    array_init(return_value);
    zval zaddress;
    ZVAL_STRING(&zaddress, sa.get_ip());
    add_assoc_zval(return_value, "host", &zaddress); /* backward compatibility */
    Z_ADDREF(zaddress);
    add_assoc_zval(return_value, "address", &zaddress);
    add_assoc_long(return_value, "port", sa.get_port());
}

static PHP_METHOD(swoole_client_coro, close) {
    RETURN_BOOL(client_coro_close(ZEND_THIS));
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client_coro, enableSSL) {
    Socket *cli = client_get_ptr(ZEND_THIS);

    if (!cli) {
        RETURN_FALSE;
    }

    if (cli->get_type() != SW_SOCK_TCP && cli->get_type() != SW_SOCK_TCP6) {
        php_swoole_fatal_error(E_WARNING, "cannot use enableSSL");
        RETURN_FALSE;
    }
    if (cli->get_ssl()) {
        php_swoole_fatal_error(E_WARNING, "SSL has been enabled");
        RETURN_FALSE;
    }

    cli->enable_ssl_encrypt();

    zval *zset = sw_zend_read_property_ex(swoole_client_coro_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (php_swoole_array_length_safe(zset) > 0) {
        php_swoole_socket_set_ssl(cli, zset);
    }
    RETURN_BOOL(cli->ssl_handshake());
}

static PHP_METHOD(swoole_client_coro, getPeerCert) {
    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!cli->get_ssl()) {
        php_swoole_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    if (!cli->get_socket()->ssl_get_peer_certificate(sw_tg_buffer())) {
        RETURN_FALSE;
    }
    RETURN_SW_STRING(sw_tg_buffer());
}

static PHP_METHOD(swoole_client_coro, verifyPeerCert) {
    Socket *cli = client_get_ptr(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!cli->get_ssl()) {
        php_swoole_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    zend_bool allow_self_signed = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &allow_self_signed) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->ssl_verify(allow_self_signed));
}
#endif
