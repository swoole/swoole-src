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
#include "php_swoole_client.h"
#include "swoole_mqtt.h"

#include <string>
#include <queue>
#include <unordered_map>

BEGIN_EXTERN_C()
#include "stubs/php_swoole_client_arginfo.h"
END_EXTERN_C()

using swoole::HttpProxy;
using swoole::PacketLength;
using swoole::Protocol;
using swoole::SocketType;
using swoole::Socks5Proxy;
using swoole::String;
using swoole::network::Address;
using swoole::network::Client;
using swoole::network::Socket;

static std::unordered_map<std::string, std::queue<Client *> *> long_connections;

zend_class_entry *swoole_client_ce;
zend_object_handlers swoole_client_handlers;

static zend_class_entry *swoole_client_exception_ce;
static zend_object_handlers swoole_client_exception_handlers;

static Client *php_swoole_client_new(zval *zobject, char *host, int host_len, int port);

static sw_inline void php_swoole_client_set_cli(const zval *zobject, Client *cli) {
    php_swoole_client_fetch_object(Z_OBJ_P(zobject))->cli = cli;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static zval *client_get_zsocket(const zval *zobject) {
    return php_swoole_client_fetch_object(Z_OBJ_P(zobject))->zsocket;
}

static void client_set_zsocket(const zval *zobject, zval *zsocket) {
    php_swoole_client_fetch_object(Z_OBJ_P(zobject))->zsocket = zsocket;
}
#endif

static void client_free_object(zend_object *object) {
    auto client_obj = php_swoole_client_fetch_object(object);
    if (client_obj->async) {
        php_swoole_client_async_free_object(client_obj);
    }
    zend_object_std_dtor(object);
}

static zend_object *client_create_object(zend_class_entry *ce) {
    auto *client = static_cast<ClientObject *>(zend_object_alloc(sizeof(ClientObject), ce));
    zend_object_std_init(&client->std, ce);
    object_properties_init(&client->std, ce);
    client->std.handlers = &swoole_client_handlers;
    client->async = nullptr;
    return &client->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_client, __construct);
static PHP_METHOD(swoole_client, __destruct);
static PHP_METHOD(swoole_client, set);
static PHP_METHOD(swoole_client, connect);
static PHP_METHOD(swoole_client, recv);
static PHP_METHOD(swoole_client, send);
static PHP_METHOD(swoole_client, sendfile);
static PHP_METHOD(swoole_client, sendto);
#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_client, enableSSL);
static PHP_METHOD(swoole_client, getPeerCert);
static PHP_METHOD(swoole_client, verifyPeerCert);
#endif
static PHP_METHOD(swoole_client, isConnected);
static PHP_METHOD(swoole_client, getsockname);
static PHP_METHOD(swoole_client, getpeername);
static PHP_METHOD(swoole_client, close);
static PHP_METHOD(swoole_client, shutdown);

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client, getSocket);
#endif
SW_EXTERN_C_END

static uint32_t client_poll_add(zval *sock_array, uint32_t index, pollfd *fds, int maxevents, int event);
static int client_poll_wait(zval *sock_array, const pollfd *fds, int maxevents, int n_event, int revent);

Client *php_swoole_client_get_cli_safe(const zval *zobject) {
    Client *cli = php_swoole_client_get_cli(zobject);
    if (cli && cli->socket) {
        if (cli->active) {
            return cli;
        }
        if (cli->async_connect) {
            cli->async_connect = false;
            int error = -1;
            if (cli->get_socket()->get_option(SOL_SOCKET, SO_ERROR, &error) == 0) {
                if (error == 0) {
                    cli->active = true;
                    return cli;
                }
            }
            php_swoole_client_free(zobject, cli);
        }
    }
    swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
    zend_update_property_long(swoole_client_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
    php_swoole_error(E_WARNING, "client is not connected to server");
    return nullptr;
}

// clang-format off
static const zend_function_entry swoole_client_methods[] =
{
    PHP_ME(swoole_client, __construct, arginfo_class_Swoole_Client___construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, __destruct,  arginfo_class_Swoole_Client___destruct,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, set,         arginfo_class_Swoole_Client_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, connect,     arginfo_class_Swoole_Client_connect,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, recv,        arginfo_class_Swoole_Client_recv,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, send,        arginfo_class_Swoole_Client_send,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendfile,    arginfo_class_Swoole_Client_sendfile,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendto,      arginfo_class_Swoole_Client_sendto,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, shutdown,    arginfo_class_Swoole_Client_shutdown,    ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_client, enableSSL,      arginfo_class_Swoole_Client_enableSSL,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getPeerCert,    arginfo_class_Swoole_Client_getPeerCert,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, verifyPeerCert, arginfo_class_Swoole_Client_verifyPeerCert, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_client, isConnected, arginfo_class_Swoole_Client_isConnected, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getsockname, arginfo_class_Swoole_Client_getsockname, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getpeername, arginfo_class_Swoole_Client_getpeername, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, close,       arginfo_class_Swoole_Client_close,       ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_client, getSocket, arginfo_class_Swoole_Client_getSocket, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};
// clang-format on

void php_swoole_client_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_client, "Swoole\\Client", nullptr, swoole_client_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_client);
    SW_SET_CLASS_CLONEABLE(swoole_client, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_client, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_client, client_create_object, client_free_object, ClientObject, std);

    SW_INIT_CLASS_ENTRY_EX(swoole_client_exception, "Swoole\\Client\\Exception", nullptr, nullptr, swoole_exception);

    zend_declare_property_long(swoole_client_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_client_ce, ZEND_STRL("reuse"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_ce, ZEND_STRL("reuseCount"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_client_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_ce, ZEND_STRL("id"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_client_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);

    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("MSG_OOB"), MSG_OOB);
    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("MSG_PEEK"), MSG_PEEK);
    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT);
    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL);

    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("SHUT_RDWR"), SHUT_RDWR);
    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("SHUT_RD"), SHUT_RD);
    zend_declare_class_constant_long(swoole_client_ce, ZEND_STRL("SHUT_WR"), SHUT_WR);
}

#ifdef SW_USE_OPENSSL
void php_swoole_client_check_ssl_setting(const Client *cli, const zval *zset) {
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *ztmp;

    if (php_swoole_array_get_value(vht, "ssl_protocols", ztmp)) {
        cli->set_ssl_protocols(zval_get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "ssl_compress", ztmp)) {
        cli->set_ssl_disable_compress(!zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "ssl_cert_file", ztmp)) {
        zend::String str_v(ztmp);
        if (!cli->set_ssl_cert_file(str_v.to_std_string())) {
            php_swoole_fatal_error(E_ERROR, "ssl cert file[%s] not found", str_v.val());
            return;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", ztmp)) {
        zend::String str_v(ztmp);
        if (!cli->set_ssl_key_file(str_v.to_std_string())) {
            php_swoole_fatal_error(E_ERROR, "ssl key file[%s] not found", str_v.val());
            return;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_passphrase", ztmp)) {
        zend::String str_v(ztmp);
        cli->set_ssl_passphrase(str_v.to_std_string());
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (php_swoole_array_get_value(vht, "ssl_host_name", ztmp)) {
        zend::String str_v(ztmp);
        cli->set_tls_host_name(str_v.to_std_string());
    }
#endif
    if (php_swoole_array_get_value(vht, "ssl_verify_peer", ztmp)) {
        cli->set_ssl_verify_peer(zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", ztmp)) {
        cli->set_ssl_allow_self_signed(zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "ssl_cafile", ztmp)) {
        zend::String str_v(ztmp);
        cli->set_ssl_cafile(str_v.to_std_string());
    }
    if (php_swoole_array_get_value(vht, "ssl_capath", ztmp)) {
        zend::String str_v(ztmp);
        cli->set_ssl_capath(str_v.to_std_string());
    }
    if (php_swoole_array_get_value(vht, "ssl_verify_depth", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        cli->set_ssl_verify_depth(SW_MAX(0, SW_MIN(v, UINT8_MAX)));
    }
    if (php_swoole_array_get_value(vht, "ssl_ciphers", ztmp)) {
        zend::String str_v(ztmp);
        cli->set_ssl_ciphers(str_v.to_std_string());
    }
    if (!cli->get_ssl_cert_file().empty() && cli->get_ssl_key_file().empty()) {
        php_swoole_fatal_error(E_ERROR, "ssl require key file");
        return;
    }
    if (!cli->get_ssl_key_file().empty() && cli->get_ssl_cert_file().empty()) {
        php_swoole_fatal_error(E_ERROR, "ssl require cert file");
        return;
    }
}
#endif

bool php_swoole_client_check_setting(Client *cli, const zval *zset) {
    zval *ztmp;
    int value = 1;
    HashTable *vht = Z_ARRVAL_P(zset);

    // buffer: eof check
    if (php_swoole_array_get_value(vht, "open_eof_check", ztmp)) {
        cli->open_eof_check = zval_is_true(ztmp);
    }
    // buffer: split package with eof
    if (php_swoole_array_get_value(vht, "open_eof_split", ztmp)) {
        cli->protocol.split_by_eof = zval_is_true(ztmp);
        if (cli->protocol.split_by_eof) {
            cli->open_eof_check = true;
        }
    }
    // package eof
    if (php_swoole_array_get_value(vht, "package_eof", ztmp)) {
        zend::String str_v(ztmp);
        cli->protocol.package_eof_len = str_v.len();
        if (cli->protocol.package_eof_len == 0) {
            php_swoole_fatal_error(E_ERROR, "package_eof cannot be an empty string");
            return false;
        } else if (cli->protocol.package_eof_len > SW_DATA_EOF_MAXLEN) {
            php_swoole_fatal_error(E_ERROR, "package_eof max length is %d", SW_DATA_EOF_MAXLEN);
            return false;
        }
        memcpy(cli->protocol.package_eof, str_v.val(), str_v.len());
    }
    // open mqtt protocol
    if (php_swoole_array_get_value(vht, "open_mqtt_protocol", ztmp)) {
        cli->open_length_check = zval_is_true(ztmp);
        if (zval_is_true(ztmp)) {
            swoole::mqtt::set_protocol(&cli->protocol);
        }
    }
    // open length check
    if (php_swoole_array_get_value(vht, "open_length_check", ztmp)) {
        cli->open_length_check = zval_is_true(ztmp);
        cli->protocol.get_package_length = Protocol::default_length_func;
    }
    // package length size
    if (php_swoole_array_get_value(vht, "package_length_type", ztmp)) {
        zend::String str_v(ztmp);
        cli->protocol.package_length_type = str_v.val()[0];
        cli->protocol.package_length_size = swoole_type_size(cli->protocol.package_length_type);

        if (cli->protocol.package_length_size == 0) {
            php_swoole_fatal_error(E_ERROR,
                                   "Unknown package_length_type name '%c', see pack(). Link: http://php.net/pack",
                                   cli->protocol.package_length_type);
            return false;
        }
    }
    // package length offset
    if (php_swoole_array_get_value(vht, "package_length_offset", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        cli->protocol.package_length_offset = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    // package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        cli->protocol.package_body_offset = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    // length function
    if (php_swoole_array_get_value(vht, "package_length_func", ztmp)) {
        auto fci_cache = sw_callable_create(ztmp);
        if (!fci_cache) {
            return false;
        }
        cli->protocol.get_package_length = php_swoole_length_func;
        if (cli->protocol.private_data_1) {
            sw_callable_free(cli->protocol.private_data_1);
        }
        cli->protocol.private_data_1 = fci_cache;
        cli->protocol.package_length_size = 0;
        cli->protocol.package_length_type = '\0';
        cli->protocol.package_length_offset = SW_IPC_BUFFER_SIZE;
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", ztmp)) {
        zend_long v = php_swoole_parse_to_size(ztmp);
        cli->protocol.package_max_length = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    } else {
        cli->protocol.package_max_length = SW_INPUT_BUFFER_SIZE;
    }
    /**
     * socket send/recv buffer size
     */
    if (php_swoole_array_get_value(vht, "socket_buffer_size", ztmp)) {
        zend_long v = php_swoole_parse_to_size(ztmp);
        value = SW_MAX(1, SW_MIN(v, INT_MAX));
        cli->socket->set_buffer_size(value);
        cli->socket->buffer_size = value;
    }
    if (php_swoole_array_get_value(vht, "buffer_high_watermark", ztmp)) {
        zend_long v = php_swoole_parse_to_size(ztmp);
        value = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        cli->buffer_high_watermark = value;
    }
    if (php_swoole_array_get_value(vht, "buffer_low_watermark", ztmp)) {
        zend_long v = php_swoole_parse_to_size(ztmp);
        value = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        cli->buffer_low_watermark = value;
    }
    /**
     * bind port
     */
    std::string bind_address;
    int bind_port = 0;
    if (php_swoole_array_get_value(vht, "bind_port", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        bind_port = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    /**
     * bind address
     */
    if (php_swoole_array_get_value(vht, "bind_address", ztmp)) {
        bind_address = zend::String(ztmp).to_std_string();
    }
    if (!bind_address.empty() && cli->bind(bind_address, bind_port) < 0) {
        return false;
    }
    /**
     * client: tcp_nodelay
     */
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", ztmp)) {
        if (zval_is_true(ztmp)) {
            goto _open_tcp_nodelay;
        }
    } else {
    _open_tcp_nodelay:
        // The failure to set tcp_nodelay does not affect the normal operation of the client;
        // therefore, only an error log is printed without returning false.
        if (cli->socket->is_tcp() && !cli->socket->set_tcp_nodelay()) {
            php_swoole_sys_error(E_WARNING, "setsockopt(%d, TCP_NODELAY) failed", cli->socket->fd);
        }
    }
    /**
     * socks5 proxy
     */
    if (php_swoole_array_get_value(vht, "socks5_host", ztmp)) {
        zend::String host(ztmp);
        if (php_swoole_array_get_value(vht, "socks5_port", ztmp)) {
            auto socks5_port = zval_get_long(ztmp);
            std::string username, password;
            if (php_swoole_array_get_value(vht, "socks5_username", ztmp)) {
                zend::String _value(ztmp);
                username = _value.to_std_string();
            }
            if (php_swoole_array_get_value(vht, "socks5_password", ztmp)) {
                zend::String _value(ztmp);
                password = _value.to_std_string();
            }
            cli->set_socks5_proxy(host.to_std_string(), socks5_port, username, password);
        } else {
            php_swoole_fatal_error(E_WARNING, "socks5_port should not be null");
            return false;
        }
    }
    /**
     * http proxy
     */
    else if (php_swoole_array_get_value(vht, "http_proxy_host", ztmp)) {
        zend::String host(ztmp);
        if (php_swoole_array_get_value(vht, "http_proxy_port", ztmp)) {
            std::string username, password;
            auto http_proxy_port = zval_get_long(ztmp);
            if (php_swoole_array_get_value(vht, "http_proxy_username", ztmp) ||
                php_swoole_array_get_value(vht, "http_proxy_user", ztmp)) {
                zend::String _value(ztmp);
                username = _value.to_std_string();
            }
            if (php_swoole_array_get_value(vht, "http_proxy_password", ztmp)) {
                zend::String _value(ztmp);
                password = _value.to_std_string();
            }
            cli->set_http_proxy(host.to_std_string(), http_proxy_port, username, password);
        } else {
            php_swoole_fatal_error(E_WARNING, "http_proxy_port should not be null");
            return false;
        }
    }
    /**
     * ssl
     */
#ifdef SW_USE_OPENSSL
    if (cli->open_ssl) {
        php_swoole_client_check_ssl_setting(cli, zset);
    }
#endif
    return true;
}

void php_swoole_client_free(const zval *zobject, Client *cli) {
    if (cli->timer) {
        swoole_timer_del(cli->timer);
        cli->timer = nullptr;
    }
    if (cli->protocol.private_data_1) {
        sw_callable_free(cli->protocol.private_data_1);
        cli->protocol.private_data_1 = nullptr;
    }
    // long tcp connection, delete from connection pool
    if (cli->keep) {
        auto i = long_connections.find(cli->server_id);
        if (i != long_connections.end()) {
            std::queue<Client *> *q = i->second;
            if (q->empty()) {
                delete q;
                long_connections.erase(cli->server_id);
            }
        }
    }

    delete cli;

#ifdef SWOOLE_SOCKETS_SUPPORT
    zval *zsocket = client_get_zsocket(zobject);
    if (zsocket) {
        sw_zval_free(zsocket);
        client_set_zsocket(zobject, nullptr);
    }
#endif
    // unset object
    php_swoole_client_set_cli(zobject, nullptr);
}

ssize_t php_swoole_length_func(const Protocol *protocol, Socket *_socket, PacketLength *pl) {
    auto *cb = static_cast<zend::Callable *>(protocol->private_data_1);
    zval zdata;
    zval retval;
    ssize_t ret = -1;

    // TODO: reduce memory copy
    ZVAL_STRINGL(&zdata, pl->buf, pl->buf_size);
    if (UNEXPECTED(sw_zend_call_function_ex2(nullptr, cb->ptr(), 1, &zdata, &retval) != SUCCESS)) {
        php_swoole_fatal_error(E_WARNING, "length function handler error");
    } else {
        ret = zval_get_long(&retval);
        zval_ptr_dtor(&retval);
    }
    zval_ptr_dtor(&zdata);

    return ret;
}

static Client *php_swoole_client_new(zval *zobject, char *host, int host_len, int port) {
    zval *ztype = sw_zend_read_property_ex(Z_OBJCE_P(zobject), zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TYPE), 0);
    if (ztype == nullptr || ZVAL_IS_NULL(ztype)) {
        php_swoole_fatal_error(E_ERROR, "failed to get swoole_client->type");
        return nullptr;
    }

    long type = Z_LVAL_P(ztype);
    int socket_type = php_swoole_get_socket_type(type);
    if (Socket::is_tcp(static_cast<SocketType>(socket_type)) && !Address::verify_port(port)) {
        php_swoole_fatal_error(E_WARNING, "The port is invalid");
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        return nullptr;
    }

    Client *cli;
    std::string conn_key;
    zval *zconnection_id =
        sw_zend_read_property_not_null_ex(Z_OBJCE_P(zobject), zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_ID), 1);

    if (zconnection_id && Z_TYPE_P(zconnection_id) == IS_STRING && Z_STRLEN_P(zconnection_id) > 0) {
        conn_key = std::string(Z_STRVAL_P(zconnection_id), Z_STRLEN_P(zconnection_id));
    } else {
        size_t size = sw_snprintf(sw_tg_buffer()->str, sw_tg_buffer()->size, "%s:%d", host, port);
        conn_key = std::string(sw_tg_buffer()->str, size);
    }

    // keep the tcp connection
    if (type & SW_FLAG_KEEP) {
        auto i = long_connections.find(conn_key);
        if (i == long_connections.end() || i->second->empty()) {
            goto _create_socket;
        } else {
            std::queue<Client *> *q = i->second;
            cli = q->front();
            q->pop();
            if (!cli->socket->check_liveness()) {
                cli->close();
                php_swoole_client_free(zobject, cli);
                goto _create_socket;
            }
            cli->reuse_count++;
            zend_update_property_long(
                Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("reuseCount"), cli->reuse_count);
        }
    } else {
    _create_socket:
        cli = new Client(php_swoole_get_socket_type(type), false);
        if (cli->socket == nullptr) {
            php_swoole_sys_error(E_WARNING, "Client_create() failed");
            zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), errno);
            delete cli;
            return nullptr;
        }

        cli->server_id = std::string(conn_key.c_str(), conn_key.length());
    }

    zend_update_property_long(Z_OBJCE_P(zobject), SW_Z8_OBJ_P(zobject), ZEND_STRL("sock"), cli->socket->fd);

    if (type & SW_FLAG_KEEP) {
        cli->keep = true;
    }

#ifdef SW_USE_OPENSSL
    if (type & SW_SOCK_SSL) {
        cli->enable_ssl_encrypt();
    }
#endif

    return cli;
}

static PHP_METHOD(swoole_client, __construct) {
    zend_long type = 0;
    zend_bool async = false;
    char *id = nullptr;
    size_t len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|bs", &type, &async, &id, &len) == FAILURE) {
        zend_throw_error(nullptr, "socket type param is required");
        RETURN_FALSE;
    }

    if (async) {
        zend_throw_error(nullptr, "The $async parameter is not supported");
        RETURN_FALSE;
    }

    int client_type = php_swoole_get_socket_type(type);
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

    zend_update_property_long(swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("type"), type);
    if (id) {
        zend_update_property_stringl(swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("id"), id, len);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, __destruct) {
    SW_PREVENT_USER_DESTRUCT();

    Client *cli = php_swoole_client_get_cli(ZEND_THIS);
    // no keep connection
    if (cli) {
        sw_zend_call_method_with_0_params(ZEND_THIS, swoole_client_ce, nullptr, "close", nullptr);
    }
}

static PHP_METHOD(swoole_client, set) {
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zset) == FAILURE) {
        RETURN_FALSE;
    }
    if (!ZVAL_IS_ARRAY(zset)) {
        RETURN_FALSE;
    }

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_client_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, connect) {
    char *host;
    size_t host_len;
    zend_long port = 0;
    double timeout = SW_CLIENT_CONNECT_TIMEOUT;
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

    Client *cli = php_swoole_client_get_cli(ZEND_THIS);
    if (cli) {
        php_swoole_fatal_error(E_WARNING, "connection to the server has already been established");
        RETURN_FALSE;
    }

    cli = php_swoole_client_new(ZEND_THIS, host, host_len, port);
    if (cli == nullptr) {
        RETURN_FALSE;
    }
    php_swoole_client_set_cli(ZEND_THIS, cli);

    if (cli->keep && cli->active) {
        zend_update_property_bool(swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("reuse"), 1);
        RETURN_TRUE;
    } else if (cli->active == 1) {
        php_swoole_fatal_error(E_WARNING, "connection to the server has already been established");
        RETURN_FALSE;
    }

    zval *zset = sw_zend_read_property_ex(swoole_client_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (zset && ZVAL_IS_ARRAY(zset)) {
        swoole_set_last_error(0);
        if (!php_swoole_client_check_setting(cli, zset)) {
            zend_update_property_long(
                swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
            RETURN_FALSE;
        }
    }

    if (cli->connect(host, port, timeout, sock_flag) < 0) {
        zend_update_property_long(
            swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
        // async connect
        if (cli->async_connect) {
            RETURN_TRUE;
        }
        php_swoole_core_error(E_WARNING,
                              "connect to server[%s:%d] failed. Error: %s[%d]",
                              host,
                              (int) port,
                              swoole_strerror(swoole_get_last_error()),
                              swoole_get_last_error());
        php_swoole_client_free(ZEND_THIS, cli);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, send) {
    char *data;
    size_t data_len;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(data, data_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (data_len == 0) {
        php_swoole_fatal_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }

    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    // clear errno
    swoole_set_last_error(0);
    ssize_t ret = cli->send(data, data_len, flags);
    if (ret < 0) {
        php_swoole_sys_error(E_WARNING, "failed to send(%d) %zu bytes", cli->socket->fd, data_len);
        zend_update_property_long(
            swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
        RETVAL_FALSE;
    } else {
        RETURN_LONG(ret);
    }
}

static PHP_METHOD(swoole_client, sendto) {
    char *host;
    size_t host_len;
    long port;
    char *data;
    size_t len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sls", &host, &host_len, &port, &data, &len) == FAILURE) {
        RETURN_FALSE;
    }

    if (len == 0) {
        php_swoole_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }

    Client *cli = php_swoole_client_get_cli(ZEND_THIS);
    if (!cli) {
        cli = php_swoole_client_new(ZEND_THIS, host, host_len, port);
        if (cli == nullptr) {
            RETURN_FALSE;
        }
        cli->active = true;
        php_swoole_client_set_cli(ZEND_THIS, cli);
    }

    auto rv = cli->sendto(std::string(host, host_len), port, data, len);
    if (rv < 0) {
        zend::object_set(ZEND_THIS, ZEND_STRL("errCode"), swoole_get_last_error());
    }
    SW_CHECK_RETURN(rv);
}

static PHP_METHOD(swoole_client, sendfile) {
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

    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    // only stream socket can sendfile
    if (!(cli->socket->is_stream())) {
        php_swoole_error(E_WARNING, "dgram socket cannot use sendfile");
        RETURN_FALSE;
    }
    // clear errno
    swoole_set_last_error(0);
    int ret = cli->sendfile(file, offset, length);
    if (ret < 0) {
        swoole_set_last_error(errno);
        php_swoole_fatal_error(E_WARNING,
                               "sendfile() failed. Error: %s [%d]",
                               swoole_strerror(swoole_get_last_error()),
                               swoole_get_last_error());
        zend_update_property_long(
            swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
        RETVAL_FALSE;
    } else {
        RETVAL_TRUE;
    }
}

static PHP_METHOD(swoole_client, recv) {
    zend_long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    zend_long flags = 0;
    int ret;
    zend_string *strbuf = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(buf_len)
    Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    // waitall
    if (flags == 1) {
        flags = MSG_WAITALL;
    }

    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    Protocol *protocol = &cli->protocol;

    if (cli->open_eof_check) {
        if (cli->buffer == nullptr) {
            cli->buffer = swoole::make_string(SW_BUFFER_SIZE_BIG, sw_zend_string_allocator());
        }

        String *buffer = cli->buffer;
        ssize_t eof = -1;
        char *buf = nullptr;

        if (buffer->length > 0) {
            goto _find_eof;
        }

        while (true) {
            buf = buffer->str + buffer->length;
            buf_len = buffer->size - buffer->length;

            if (buf_len > SW_BUFFER_SIZE_BIG) {
                buf_len = SW_BUFFER_SIZE_BIG;
            }

            ret = cli->recv(buf, buf_len, 0);
            if (ret < 0) {
                php_swoole_sys_error(E_WARNING, "recv() failed");
                zend_update_property_long(
                    swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
                buffer->length = 0;
                RETURN_FALSE;
            } else if (ret == 0) {
                buffer->length = 0;
                RETURN_EMPTY_STRING();
            }

            buffer->length += ret;

            if (buffer->length < protocol->package_eof_len) {
                continue;
            }

        _find_eof:
            eof = swoole_strnpos(buffer->str, buffer->length, protocol->package_eof, protocol->package_eof_len);
            if (eof >= 0) {
                eof += protocol->package_eof_len;

                if ((ssize_t) buffer->length > eof) {
                    cli->buffer = swoole::make_string(SW_BUFFER_SIZE_BIG, sw_zend_string_allocator());
                    cli->buffer->length = buffer->length - eof;
                    memcpy(cli->buffer->str, buffer->str + eof, cli->buffer->length);
                } else {
                    cli->buffer = nullptr;
                    buffer->length = 0;
                }

                zend::assign_zend_string_by_val(return_value, buffer->str, eof);
                buffer->str = nullptr;
                delete buffer;

                return;
            } else {
                if (buffer->length == protocol->package_max_length) {
                    php_swoole_error(E_WARNING, "no package eof");
                    buffer->length = 0;
                    RETURN_FALSE;
                } else if (buffer->length == buffer->size) {
                    if (buffer->size < protocol->package_max_length) {
                        uint32_t new_size = buffer->size * 2;
                        if (new_size > protocol->package_max_length) {
                            new_size = protocol->package_max_length;
                        }
                        if (!buffer->extend(new_size)) {
                            buffer->length = 0;
                            RETURN_FALSE;
                        }
                    }
                }
            }
        }
        buffer->length = 0;
        RETURN_FALSE;
    } else if (cli->open_length_check) {
        if (cli->buffer == nullptr) {
            cli->buffer = new String(SW_BUFFER_SIZE_STD);
        } else {
            cli->buffer->clear();
        }
        String *buffer = cli->buffer;

        uint32_t header_len = protocol->package_length_offset + protocol->package_length_size;

        while (true) {
            auto retval = cli->recv(buffer->str + buffer->length, header_len - buffer->length, 0);
            if (retval <= 0) {
                break;
            }
            buffer->length += retval;
            PacketLength pl{
                buffer->str,
                (uint32_t) buffer->length,
            };
            buf_len = protocol->get_package_length(protocol, cli->socket, &pl);
            if (buf_len == 0) {
                continue;
            } else if (buf_len < 0) {
                break;
            } else {
                break;
            }
        }

        // error package
        if (buf_len < 0) {
            RETURN_EMPTY_STRING();
        }
        // empty package
        else if (buf_len == header_len) {
            RETURN_STRINGL(buffer->str, header_len);
        } else if (buf_len > protocol->package_max_length) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                             "Package is too big. package_length=%d",
                             (int) buf_len);
            RETURN_EMPTY_STRING();
        } else if (buf_len == (zend_long) buffer->length) {
            RETURN_STRINGL(buffer->str, buffer->length);
        } else if (buf_len < (zend_long) buffer->length) {
            RETVAL_STRINGL(buffer->str, buf_len);
            memmove(buffer->str, buffer->str + buf_len, buffer->length - buf_len);
            buffer->length -= buf_len;
            return;
        }

        strbuf = zend_string_alloc(buf_len, false);
        memcpy(strbuf->val, buffer->str, buffer->length);
        swoole_set_last_error(0);
        ret = cli->recv(strbuf->val + header_len, buf_len - buffer->length, MSG_WAITALL);
        if (ret > 0) {
            ret += header_len;
            if (ret != buf_len) {
                ret = 0;
            }
        }
    } else {
        if (!(flags & MSG_WAITALL) && buf_len > SW_PHP_CLIENT_BUFFER_SIZE) {
            buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
        }
        strbuf = zend_string_alloc(buf_len, false);
        swoole_set_last_error(0);
        ret = cli->recv(strbuf->val, buf_len, flags);
    }

    if (ret < 0) {
        php_swoole_sys_error(E_WARNING, "recv() failed");
        zend_update_property_long(
            swoole_client_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
        if (strbuf) {
            zend_string_free(strbuf);
        }
        RETURN_FALSE;
    } else {
        if (ret == 0) {
            if (strbuf) {
                zend_string_free(strbuf);
            }
            RETURN_EMPTY_STRING();
        } else {
            strbuf->len = ret;
            strbuf->val[ret] = 0;
            RETVAL_STR(strbuf);
        }
    }
}

static PHP_METHOD(swoole_client, isConnected) {
    Client *cli = php_swoole_client_get_cli(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!cli->socket) {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->active);
}

static PHP_METHOD(swoole_client, getsockname) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    if (cli->socket->get_name() < 0) {
        php_swoole_sys_error(E_WARNING, "getsockname() failed");
        zend::object_set(ZEND_THIS, ZEND_STRL("errCode"), errno);
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long(return_value, "port", cli->socket->get_port());
    add_assoc_string(return_value, "host", cli->socket->get_addr());
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client, getSocket) {
    zval *zsocket = client_get_zsocket(ZEND_THIS);
    if (zsocket) {
        RETURN_ZVAL(zsocket, 1, 0);
    }
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (cli->keep) {
        php_swoole_fatal_error(E_WARNING, "the 'getSocket' method can't be used on persistent connection");
        RETURN_FALSE;
    }
    php_socket *socket_object = php_swoole_convert_to_socket(cli->socket->fd);
    if (!socket_object) {
        RETURN_FALSE;
    }
    SW_ZVAL_SOCKET(return_value, socket_object);
    zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
    client_set_zsocket(ZEND_THIS, zsocket);
}
#endif

static PHP_METHOD(swoole_client, getpeername) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }

    Address addr;
    if (cli->get_peer_name(&addr) < 0) {
        php_swoole_sys_error(E_WARNING, "getpeername() failed");
        zend::object_set(ZEND_THIS, ZEND_STRL("errCode"), errno);
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long(return_value, "port", addr.get_port());
    add_assoc_string(return_value, "host", addr.get_addr());
}

static PHP_METHOD(swoole_client, close) {
    int ret = 1;
    zend_bool force = false;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(force)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Client *cli = php_swoole_client_get_cli(ZEND_THIS);
    if (!cli || !cli->socket) {
        php_swoole_fatal_error(E_WARNING, "client is not connected to the server");
        RETURN_FALSE;
    }
    if (cli->closed) {
        php_swoole_error(E_WARNING, "client socket is closed");
        RETURN_FALSE;
    }
    // Connection error, or short tcp connection.
    // No keep connection
    if (force || !cli->keep || cli->socket->catch_error(swoole_get_last_error()) == SW_CLOSE) {
        ret = cli->close();
        php_swoole_client_free(ZEND_THIS, cli);
    } else {
        if (cli->keep) {
            std::queue<Client *> *q;
            auto i = long_connections.find(cli->server_id);
            if (i == long_connections.end()) {
                q = new std::queue<Client *>;
                long_connections[cli->server_id] = q;
            } else {
                q = i->second;
            }
            q->push(cli);
        }
        // unset object
        php_swoole_client_set_cli(ZEND_THIS, nullptr);
    }
    SW_CHECK_RETURN(ret);
}

#ifdef SW_USE_OPENSSL
bool php_swoole_client_enable_ssl_encryption(Client *cli, zval *zobject) {
    if (cli->socket->socket_type != SW_SOCK_TCP && cli->socket->socket_type != SW_SOCK_TCP6) {
        php_swoole_fatal_error(E_WARNING, "cannot use enableSSL");
        return false;
    }
    if (cli->socket->ssl) {
        php_swoole_fatal_error(E_WARNING, "SSL has been enabled");
        return false;
    }
    cli->open_ssl = true;
    zval *zset = sw_zend_read_property_ex(swoole_client_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (ZVAL_IS_ARRAY(zset)) {
        php_swoole_client_check_ssl_setting(cli, zset);
    }
    return cli->enable_ssl_encrypt() == SW_OK;
}

static PHP_METHOD(swoole_client, enableSSL) {
    zval *zcallback = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(zcallback)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zcallback) {
        zend_throw_exception(
            swoole_exception_ce, "sync client does not support `onSslReady` callback", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!php_swoole_client_enable_ssl_encryption(cli, ZEND_THIS)) {
        RETURN_FALSE;
    }
    RETURN_BOOL(cli->ssl_handshake() == SW_OK);
}

static PHP_METHOD(swoole_client, getPeerCert) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!cli->socket->ssl) {
        php_swoole_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    if (!cli->socket->ssl_get_peer_certificate(sw_tg_buffer())) {
        RETURN_FALSE;
    }
    RETURN_SW_STRING(sw_tg_buffer());
}

static PHP_METHOD(swoole_client, verifyPeerCert) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    if (!cli->socket->ssl) {
        php_swoole_fatal_error(E_WARNING, "SSL is not ready");
        RETURN_FALSE;
    }
    zend_bool allow_self_signed = false;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &allow_self_signed) == FAILURE) {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(cli->ssl_verify(allow_self_signed));
}
#endif

static PHP_METHOD(swoole_client, shutdown) {
    Client *cli = php_swoole_client_get_cli_safe(ZEND_THIS);
    if (!cli) {
        RETURN_FALSE;
    }
    long _how;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &_how) == FAILURE) {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(cli->shutdown(_how));
}

PHP_FUNCTION(swoole_client_select) {
    zval *r_array, *w_array, *e_array;
    int retval;
    uint32_t index = 0;
    double timeout = SW_CLIENT_CONNECT_TIMEOUT;

    ZEND_PARSE_PARAMETERS_START(3, 4)
    Z_PARAM_ARRAY_EX2(r_array, 1, 1, 0)
    Z_PARAM_ARRAY_EX2(w_array, 1, 1, 0)
    Z_PARAM_ARRAY_EX2(e_array, 1, 1, 0)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END();

    int maxevents = SW_MAX(SW_MAX(php_swoole_array_length_safe(r_array), php_swoole_array_length_safe(w_array)),
                           php_swoole_array_length_safe(e_array));
    auto *fds = static_cast<struct pollfd *>(ecalloc(maxevents, sizeof(struct pollfd)));

    if (r_array != nullptr && php_swoole_array_length(r_array) > 0) {
        index = client_poll_add(r_array, index, fds, maxevents, POLLIN);
    }
    if (w_array != nullptr && php_swoole_array_length(w_array) > 0) {
        index = client_poll_add(w_array, index, fds, maxevents, POLLOUT);
    }
    if (e_array != nullptr && php_swoole_array_length(e_array) > 0) {
        index = client_poll_add(e_array, index, fds, maxevents, POLLHUP);
    }
    if (index == 0) {
        efree(fds);
        php_swoole_fatal_error(E_WARNING, "no resource arrays were passed to select");
        RETURN_FALSE;
    }

    do {
        retval = poll(fds, maxevents, (int) (timeout * 1000));
    } while (retval < 0 && errno == EINTR);

    if (retval == -1) {
        efree(fds);
        php_swoole_sys_error(E_WARNING, "unable to poll()");
        RETURN_FALSE;
    }

    if (r_array != nullptr && php_swoole_array_length(r_array) > 0) {
        client_poll_wait(r_array, fds, maxevents, retval, POLLIN);
    }
    if (w_array != nullptr && php_swoole_array_length(w_array) > 0) {
        client_poll_wait(w_array, fds, maxevents, retval, POLLOUT);
    }
    if (e_array != nullptr && php_swoole_array_length(e_array) > 0) {
        client_poll_wait(e_array, fds, maxevents, retval, POLLHUP);
    }
    efree(fds);
    RETURN_LONG(retval);
}

static inline int client_poll_get(const pollfd *fds, int maxevents, int fd) {
    for (int i = 0; i < maxevents; i++) {
        if (fds[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

static int client_poll_wait(zval *sock_array, const pollfd *fds, int maxevents, int n_event, int revent) {
    zval *element = nullptr;

    ulong_t num = 0;
    if (!ZVAL_IS_ARRAY(sock_array)) {
        return 0;
    }

    zval new_array;
    array_init(&new_array);
    zend_ulong num_key;
    zend_string *key;
    zval *dest_element;

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(sock_array), num_key, key, element) {
        int sock = php_swoole_convert_to_fd(element);
        if (sock < 0) {
            continue;
        }
        int poll_key = client_poll_get(fds, maxevents, sock);
        if (poll_key == -1) {
            php_swoole_fatal_error(E_WARNING, "bad fd[%d]", sock);
            continue;
        }
        if (!(fds[poll_key].revents & revent)) {
            continue;
        }
        if (key) {
            dest_element = zend_hash_add(Z_ARRVAL(new_array), key, element);
        } else {
            dest_element = zend_hash_index_update(Z_ARRVAL(new_array), num_key, element);
        }
        if (dest_element) {
            Z_ADDREF_P(dest_element);
        }
        num++;
    }
    ZEND_HASH_FOREACH_END();

    zval_ptr_dtor(sock_array);
    ZVAL_COPY_VALUE(sock_array, &new_array);
    return num;
}

static uint32_t client_poll_add(zval *sock_array, uint32_t index, struct pollfd *fds, int maxevents, int event) {
    zval *element = nullptr;
    if (!ZVAL_IS_ARRAY(sock_array)) {
        return 0;
    }

    int key = -1;

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(sock_array), element)
    int sock = php_swoole_convert_to_fd(element);
    if (sock < 0) {
        continue;
    }
    if (event != POLLIN) {
        key = client_poll_get(fds, maxevents, sock);
    }
    if (key < 0) {
        fds[index].fd = sock;
        fds[index].events = event;
        index++;
    } else {
        fds[key].fd = sock;
        fds[key].events |= event;
    }
    SW_HASHTABLE_FOREACH_END();

    return index;
}
