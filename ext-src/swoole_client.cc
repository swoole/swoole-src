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

#include <algorithm>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#ifndef _WIN32
#include <pthread.h>
#include <sys/resource.h>
#endif

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

static void client_release_length_callback(Protocol &protocol) {
    if (auto *callback = std::exchange(protocol.private_data_1, nullptr)) {
        sw_callable_free(callback);
    }
}

static bool client_set_length_callback(Protocol &protocol, zval *value) {
    auto *callback = sw_callable_create_for_setting(value);
    if (!callback) {
        return false;
    }
    client_release_length_callback(protocol);
    protocol.private_data_1 = callback;
    return true;
}

struct ClientDeleter {
    void operator()(Client *cli) const {
        if (cli->timer) {
            swoole_timer_del(cli->timer);
            cli->timer = nullptr;
        }
        client_release_length_callback(cli->protocol);
        delete cli;
    }
};

static bool client_is_reusable(const Client *cli);

namespace {

struct PooledClientDeleter {
    void operator()(Client *cli) const {
        // The fork handler closes the inherited descriptor without sending a TLS shutdown.
        if (cli->closed && cli->socket->ssl) {
            SSL_free(cli->socket->ssl);
            cli->socket->ssl = nullptr;
        }
        delete cli;
    }
};

using PooledClient = std::unique_ptr<Client, PooledClientDeleter>;

class ClientConnectionPool {
    using IdleConnections = std::list<PooledClient>;
    using Connections = std::unordered_map<std::string, IdleConnections>;

    struct Pools {
        std::unordered_map<std::thread::id, Connections> idle;
        // A candidate still belongs to the pool while its socket is checked outside the lock.
        IdleConnections checkout;
        size_t shared_idle = 0;
    };

    static constexpr size_t MAX_SHARED_IDLE = 1024;

    std::mutex mutex_;
    // Fork waits for detached sockets to close without serializing ordinary pool operations.
    std::mutex retirement_mutex_;
    std::unique_ptr<Pools> pools_;
    size_t shared_idle_limit_ = MAX_SHARED_IDLE;
    bool inherited_ = false;

    static std::thread::id owner(bool shared) {
        return shared ? std::thread::id{} : std::this_thread::get_id();
    }

    template <typename T>
    static void append_key(std::string &key, T value) {
        key.append(reinterpret_cast<const char *>(&value), sizeof(value));
    }

    static void append_key(std::string &key, const char *value, size_t length) {
        append_key(key, length);
        key.append(value, length);
    }

    void detach_inherited(std::unique_ptr<Pools> &retired) {
        if (inherited_) {
            retired = std::move(pools_);
            inherited_ = false;
        }
    }

  public:
    struct Key {
        std::string value;
        bool shared = false;
    };

    static Key make_key(
        const char *host, size_t host_len, int port, SocketType type, bool ssl, const zval *id, int socket_flags);

    bool enabled = true;

    void limit_shared_idle(size_t descriptor_limit) {
        // Reserve most of the process descriptor limit for active connections and other I/O.
        shared_idle_limit_ = std::min(static_cast<size_t>(MAX_SHARED_IDLE), descriptor_limit / 4);
    }

    PooledClient take(const Key &key, bool ssl, int socket_flags) {
        std::unique_ptr<Pools> retired;
        IdleConnections::iterator candidate;
        Client *client;
        do {
            std::lock_guard<std::mutex> lock(mutex_);
            detach_inherited(retired);
            if (!pools_) {
                return {};
            }
            auto pool = pools_->idle.find(owner(key.shared));
            if (pool == pools_->idle.end()) {
                return {};
            }
            auto bucket = pool->second.find(key.value);
            if (bucket == pool->second.end()) {
                return {};
            }
            candidate = bucket->second.begin();
            client = candidate->get();
            // A pool ID can be reused by mistake. Never hand out an incompatible socket.
            if (client->open_ssl != ssl ||
                (client->socket->is_dgram() && !ssl && (client->sock_flags_ == 1) != (socket_flags == 1))) {
                return {};
            }
            pools_->checkout.splice(pools_->checkout.end(), bucket->second, candidate);
            if (key.shared) {
                --pools_->shared_idle;
            }
            if (bucket->second.empty()) {
                pool->second.erase(bucket);
                if (pool->second.empty()) {
                    pools_->idle.erase(pool);
                }
            }
        } while (0);

        if (client_is_reusable(client)) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto connection = std::move(*candidate);
            pools_->checkout.erase(candidate);
            return connection;
        }

        std::lock_guard<std::mutex> retirement_lock(retirement_mutex_);
        PooledClient rejected;
        do {
            std::lock_guard<std::mutex> lock(mutex_);
            rejected = std::move(*candidate);
            pools_->checkout.erase(candidate);
        } while (0);
        return {};
    }

    void put(PooledClient connection, bool shared) {
        std::unique_ptr<Pools> retired;
        std::lock_guard<std::mutex> lock(mutex_);
        detach_inherited(retired);
        if (!pools_) {
            pools_ = std::make_unique<Pools>();
        }
        if (shared && pools_->shared_idle >= shared_idle_limit_) {
            // Shared entries are plain TCP. Close before releasing the fork lock on the pool.
            connection->close();
            return;
        }
        auto &bucket = pools_->idle[owner(shared)][connection->server_id];
        bucket.push_back(std::move(connection));
        if (shared) {
            ++pools_->shared_idle;
        }
    }

    void clear_local() {
        std::lock_guard<std::mutex> retirement_lock(retirement_mutex_);
        std::unique_ptr<Pools> inherited;
        Connections retired;
        std::lock_guard<std::mutex> lock(mutex_);
        detach_inherited(inherited);
        if (pools_) {
            auto pool = pools_->idle.find(owner(false));
            if (pool != pools_->idle.end()) {
                retired.swap(pool->second);
                pools_->idle.erase(pool);
            }
        }
    }

    void clear() {
        std::lock_guard<std::mutex> retirement_lock(retirement_mutex_);
        std::unique_ptr<Pools> retired;
        std::lock_guard<std::mutex> lock(mutex_);
        retired = std::move(pools_);
        inherited_ = false;
    }

#ifndef _WIN32
    void prepare_fork() {
        retirement_mutex_.lock();
        mutex_.lock();
    }

    void finish_fork(bool child) {
        if (child && pools_ && !inherited_) {
            // Only close descriptors here. C++ and TLS objects are released later, outside the fork handler.
            auto close_descriptors = [](IdleConnections &bucket) {
                for (auto &client : bucket) {
                    ::close(client->socket->fd);
                    client->socket->fd = SW_BAD_SOCKET;
                    client->closed = true;
                }
            };
            for (auto &pool : pools_->idle) {
                for (auto &bucket : pool.second) {
                    close_descriptors(bucket.second);
                }
            }
            close_descriptors(pools_->checkout);
            inherited_ = true;
        }
        mutex_.unlock();
        retirement_mutex_.unlock();
    }
#endif
};

ClientConnectionPool client_pool;

}  // namespace

zend_class_entry *swoole_client_ce;
zend_object_handlers swoole_client_handlers;

static zend_class_entry *swoole_client_exception_ce;
static zend_object_handlers swoole_client_exception_handlers;

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
#ifndef _WIN32
    if (client_obj->async) {
        php_swoole_client_async_free_object(client_obj);
    }
#endif
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
static PHP_METHOD(swoole_client, enableSSL);
static PHP_METHOD(swoole_client, getPeerCert);
static PHP_METHOD(swoole_client, verifyPeerCert);
static PHP_METHOD(swoole_client, isConnected);
static PHP_METHOD(swoole_client, getsockname);
static PHP_METHOD(swoole_client, getpeername);
static PHP_METHOD(swoole_client, close);
static PHP_METHOD(swoole_client, shutdown);

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_client, getSocket);
#endif
SW_EXTERN_C_END

static uint32_t client_poll_add(const zval *sock_array, uint32_t index, pollfd *fds, int event);
static int client_poll_wait(zval *sock_array, const pollfd *fds, uint32_t nfds, int n_event, int revent);

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
    zend_update_property_long(swoole_client_ce, Z_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
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
    PHP_ME(swoole_client, enableSSL,      arginfo_class_Swoole_Client_enableSSL,      ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getPeerCert,    arginfo_class_Swoole_Client_getPeerCert,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, verifyPeerCert, arginfo_class_Swoole_Client_verifyPeerCert, ZEND_ACC_PUBLIC)
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
#ifndef _WIN32
    rlimit descriptors;
    if (sw_getrlimit(RLIMIT_NOFILE, &descriptors) == 0) {
        client_pool.limit_shared_idle(descriptors.rlim_cur);
    }
    int error = pthread_atfork([] { client_pool.prepare_fork(); },
                               [] { client_pool.finish_fork(false); },
                               [] { client_pool.finish_fork(true); });
    if (error != 0) {
        client_pool.enabled = false;
        swoole_warning("Failed to register Client connection pool fork handlers: %s", strerror(error));
    }
#endif
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

    zend::add_constant("SWOOLE_SYNC", SW_FLAG_SYNC);
    zend::add_constant("SWOOLE_ASYNC", SW_FLAG_ASYNC);
    zend::add_constant("SWOOLE_KEEP", SW_FLAG_KEEP);
}

void php_swoole_client_rshutdown() {
    client_pool.clear_local();
}

void php_swoole_client_mshutdown() {
    client_pool.clear();
}

void php_swoole_client_check_ssl_setting(const Client *cli, const zval *zset) try {
    HashTable *vht = Z_ARRVAL_P(zset);
    zval *ztmp;

    if (php_swoole_array_get_value(vht, "ssl_protocols", ztmp)) {
        cli->set_ssl_protocols(zend::setting::get_long(ztmp));
    }
    if (php_swoole_array_get_value(vht, "ssl_compress", ztmp)) {
        cli->set_ssl_disable_compress(!zval_is_true(ztmp));
    }
    if (php_swoole_array_get_value(vht, "ssl_cert_file", ztmp)) {
        auto str_v = zend::setting::get_string(ztmp);
        if (!cli->set_ssl_cert_file(str_v.to_std_string())) {
            php_swoole_throw_setting_exception("ssl cert file[%s] not found", str_v.val());
            return;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", ztmp)) {
        auto str_v = zend::setting::get_string(ztmp);
        if (!cli->set_ssl_key_file(str_v.to_std_string())) {
            php_swoole_throw_setting_exception("ssl key file[%s] not found", str_v.val());
            return;
        }
    }
    if (php_swoole_array_get_value(vht, "ssl_passphrase", ztmp)) {
        auto str_v = zend::setting::get_string(ztmp);
        cli->set_ssl_passphrase(str_v.to_std_string());
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (php_swoole_array_get_value(vht, "ssl_host_name", ztmp)) {
        auto str_v = zend::setting::get_string(ztmp);
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
        auto str_v = zend::setting::get_string(ztmp);
        cli->set_ssl_cafile(str_v.to_std_string());
    }
    if (php_swoole_array_get_value(vht, "ssl_capath", ztmp)) {
        auto str_v = zend::setting::get_string(ztmp);
        cli->set_ssl_capath(str_v.to_std_string());
    }
    if (php_swoole_array_get_value(vht, "ssl_verify_depth", ztmp)) {
        zend_long v = zend::setting::get_long(ztmp);
        cli->set_ssl_verify_depth(SW_MAX(0, SW_MIN(v, UINT8_MAX)));
    }
    if (php_swoole_array_get_value(vht, "ssl_ciphers", ztmp)) {
        auto str_v = zend::setting::get_string(ztmp);
        cli->set_ssl_ciphers(str_v.to_std_string());
    }
    if (!cli->get_ssl_cert_file().empty() && cli->get_ssl_key_file().empty()) {
        php_swoole_throw_setting_exception("ssl require key file");
        return;
    }
    if (!cli->get_ssl_key_file().empty() && cli->get_ssl_cert_file().empty()) {
        php_swoole_throw_setting_exception("ssl require cert file");
        return;
    }
} catch (const zend::setting::ParseError &) {
    return;
}

static bool client_check_protocol(Client *cli, const HashTable *vht) try {
    zval *ztmp;

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
    if (php_swoole_array_get_value(vht, "package_eof", ztmp) && !php_swoole_protocol_set_eof(&cli->protocol, ztmp)) {
        return false;
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
        auto str_v = zend::setting::get_string(ztmp);
        cli->protocol.package_length_type = str_v.val()[0];
        cli->protocol.package_length_size = swoole_type_size(cli->protocol.package_length_type);

        if (cli->protocol.package_length_size == 0) {
            return php_swoole_throw_setting_exception(
                "Unknown package_length_type name '%c', see pack(). Link: https://php.net/pack",
                cli->protocol.package_length_type);
        }
    }
    // package length offset
    if (php_swoole_array_get_value(vht, "package_length_offset", ztmp)) {
        zend_long v = zend::setting::get_long(ztmp);
        cli->protocol.package_length_offset = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    // package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", ztmp)) {
        zend_long v = zend::setting::get_long(ztmp);
        cli->protocol.package_body_offset = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    // length function
    if (php_swoole_array_get_value(vht, "package_length_func", ztmp)) {
        if (!client_set_length_callback(cli->protocol, ztmp)) {
            return false;
        }
        cli->protocol.get_package_length = php_swoole_length_func;
        cli->protocol.package_length_size = 0;
        cli->protocol.package_length_type = '\0';
        cli->protocol.package_length_offset = SW_IPC_BUFFER_SIZE;
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", ztmp)) {
        zend_long v = zend::setting::get_size(ztmp);
        cli->protocol.package_max_length = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    } else {
        cli->protocol.package_max_length = SW_INPUT_BUFFER_SIZE;
    }
    return !EG(exception);
} catch (const zend::setting::ParseError &) {
    return false;
}

bool php_swoole_client_check_setting(Client *cli, const zval *zset) try {
    auto *vht = Z_ARRVAL_P(zset);
    if (!client_check_protocol(cli, vht)) {
        return false;
    }

    zval *ztmp;
    int value = 1;
    /**
     * socket send/recv buffer size
     */
    if (php_swoole_array_get_value(vht, "socket_buffer_size", ztmp)) {
        zend_long v = zend::setting::get_size(ztmp);
        value = SW_MAX(1, SW_MIN(v, INT_MAX));
        cli->socket->set_buffer_size(value);
        cli->socket->buffer_size = value;
    }
    if (php_swoole_array_get_value(vht, "buffer_high_watermark", ztmp)) {
        zend_long v = zend::setting::get_size(ztmp);
        value = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        cli->buffer_high_watermark = value;
    }
    if (php_swoole_array_get_value(vht, "buffer_low_watermark", ztmp)) {
        zend_long v = zend::setting::get_size(ztmp);
        value = SW_MAX(0, SW_MIN(v, UINT32_MAX));
        cli->buffer_low_watermark = value;
    }
    /**
     * bind port
     */
    std::string bind_address;
    int bind_port = 0;
    if (php_swoole_array_get_value(vht, "bind_port", ztmp)) {
        zend_long v = zend::setting::get_long(ztmp);
        bind_port = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    /**
     * bind address
     */
    if (php_swoole_array_get_value(vht, "bind_address", ztmp)) {
        bind_address = zend::setting::get_string(ztmp).to_std_string();
    }
    if (!bind_address.empty() && cli->bind(bind_address, bind_port) < 0) {
        return php_swoole_throw_setting_exception("failed to bind client to %s:%d", bind_address.c_str(), bind_port);
    }
    /**
     * client: tcp_nodelay
     */
    if (cli->socket->is_tcp() && (!php_swoole_array_get_value(vht, "open_tcp_nodelay", ztmp) || zval_is_true(ztmp)) &&
        !cli->socket->set_tcp_nodelay()) {
        return php_swoole_throw_setting_exception("setsockopt(%d, TCP_NODELAY) failed", cli->socket->fd);
    }
    /**
     * socks5 proxy
     */
    if (php_swoole_array_get_value(vht, "socks5_host", ztmp)) {
        auto host = zend::setting::get_string(ztmp);
        if (php_swoole_array_get_value(vht, "socks5_port", ztmp)) {
            auto socks5_port = zend::setting::get_long(ztmp);
            std::string username, password;
            if (php_swoole_array_get_value(vht, "socks5_username", ztmp)) {
                auto _value = zend::setting::get_string(ztmp);
                username = _value.to_std_string();
            }
            if (php_swoole_array_get_value(vht, "socks5_password", ztmp)) {
                auto _value = zend::setting::get_string(ztmp);
                password = _value.to_std_string();
            }
            cli->set_socks5_proxy(host.to_std_string(), socks5_port, username, password);
        } else {
            return php_swoole_throw_setting_exception("socks5_port should not be null");
        }
    }
    /**
     * http proxy
     */
    else if (php_swoole_array_get_value(vht, "http_proxy_host", ztmp)) {
        auto host = zend::setting::get_string(ztmp);
        if (php_swoole_array_get_value(vht, "http_proxy_port", ztmp)) {
            std::string username, password;
            auto http_proxy_port = zend::setting::get_long(ztmp);
            if (php_swoole_array_get_value(vht, "http_proxy_username", ztmp) ||
                php_swoole_array_get_value(vht, "http_proxy_user", ztmp)) {
                auto _value = zend::setting::get_string(ztmp);
                username = _value.to_std_string();
            }
            if (php_swoole_array_get_value(vht, "http_proxy_password", ztmp)) {
                auto _value = zend::setting::get_string(ztmp);
                password = _value.to_std_string();
            }
            cli->set_http_proxy(host.to_std_string(), http_proxy_port, username, password);
        } else {
            return php_swoole_throw_setting_exception("http_proxy_port should not be null");
        }
    }
    /**
     * ssl
     */
    if (cli->open_ssl) {
        php_swoole_client_check_ssl_setting(cli, zset);
    }
    return !EG(exception);
} catch (const zend::setting::ParseError &) {
    return false;
}

void php_swoole_client_free(const zval *zobject, Client *cli) {
    if (cli->async) {
        ClientDeleter{}(cli);
        cli = nullptr;
    }

    auto *object = php_swoole_client_fetch_object(zobject);
    object->cli = nullptr;
    object->generation++;

#ifdef SWOOLE_SOCKETS_SUPPORT
    auto *zsocket = std::exchange(object->zsocket, nullptr);
#endif
    if (cli) {
        // Releasing a PHP callable can run its destructor.
        ClientDeleter{}(cli);
    }
#ifdef SWOOLE_SOCKETS_SUPPORT
    if (zsocket) {
        sw_zval_free(zsocket);
    }
#endif
}

ssize_t php_swoole_length_func(const Protocol *protocol, Socket *_socket, PacketLength *pl) {
    auto *cb = static_cast<zend::Callable *>(protocol->private_data_1);
    // Keep the PHP callable and its cache alive if the callback closes the connection.
    auto fcc = *cb->ptr();
    zval function;
    cb->copy_function(&function);
    zval zdata;
    zval retval;
    ssize_t ret = -1;

    // TODO: reduce memory copy
    ZVAL_STRINGL(&zdata, pl->buf, pl->buf_size);
    if (UNEXPECTED(sw_zend_call_function_ex2(nullptr, &fcc, 1, &zdata, &retval) != SUCCESS)) {
        php_swoole_fatal_error(E_WARNING, "length function handler error");
    } else {
        ret = zval_get_long(&retval);
        zval_ptr_dtor(&retval);
    }
    zval_ptr_dtor(&zdata);
    zval_ptr_dtor(&function);

    return ret;
}

static bool client_is_reusable(const Client *cli) {
    auto *socket = cli->socket;
    if (!cli->active || cli->async || cli->async_connect || cli->timer || !socket->removed || socket->events ||
        socket->recv_timer || socket->send_timer || socket->out_buffer || cli->is_shutdown() ||
        (cli->buffer && cli->buffer->length > 0) || socket->recv_eof) {
        return false;
    }
    if (socket->ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
        if (SSL_has_pending(socket->ssl)) {
            return false;
        }
#else
        // SSL_pending() cannot detect unread TLS records already buffered by read-ahead.
        return false;
#endif
    }

    // Readability includes unread data and EOF. Poll also reports socket errors without consuming bytes.
    pollfd event{};
    event.fd = socket->get_fd();
    event.events = POLLIN;
    return poll(&event, 1, 0) == 0;
}

ClientConnectionPool::Key ClientConnectionPool::make_key(
    const char *host, size_t host_len, int port, SocketType type, bool ssl, const zval *id, int socket_flags) {
    Key key;
    const bool named = id && Z_TYPE_P(id) == IS_STRING && Z_STRLEN_P(id) > 0;
#ifdef SW_THREAD
    // A named pool lets the application identify connections with interchangeable session state.
    key.shared = SWOOLE_G(cli) && Socket::is_tcp(type) && !ssl && socket_flags == 0 && named;
#endif
    append_key(key.value, type);
    append_key(key.value, host, host_len);
    append_key(key.value, port);
    if (named) {
        append_key(key.value, Z_STRVAL_P(id), Z_STRLEN_P(id));
    } else {
        append_key(key.value, "", 0);
    }

    return key;
}

static Client *php_swoole_client_new(
    zval *zobject, const char *host, size_t host_len, int port, const int *socket_flags = nullptr) {
    zval *ztype = sw_zend_read_property_ex(Z_OBJCE_P(zobject), zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TYPE), 0);
    if (ztype == nullptr || ZVAL_IS_NULL(ztype)) {
        php_swoole_fatal_error(E_ERROR, "failed to get swoole_client->type");
        return nullptr;
    }

    long type = Z_LVAL_P(ztype);
    auto socket_type = php_swoole_client_get_type(type);
    if (Socket::is_tcp(socket_type) && !Address::verify_port(port)) {
        php_swoole_fatal_error(E_WARNING, "The port is invalid");
        swoole_set_last_error(SW_ERROR_INVALID_PARAMS);
        return nullptr;
    }

    const bool keep = type & SW_FLAG_KEEP;
    const bool ssl = type & SW_SOCK_SSL;
    ClientConnectionPool::Key key;
    Client *cli = nullptr;
    // sendto() can create an unconnected datagram socket, which has no persistent peer.
    if (keep && socket_flags && client_pool.enabled) {
        auto *id = sw_zend_read_property_not_null_ex(Z_OBJCE_P(zobject), zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_ID), 1);
        key = ClientConnectionPool::make_key(host, host_len, port, socket_type, ssl, id, *socket_flags);
        cli = client_pool.take(key, ssl, *socket_flags).release();
    }
    if (!cli) {
        cli = new Client(socket_type, false);
        if (cli->socket == nullptr) {
            php_swoole_sys_error(E_WARNING, "Client_create() failed");
            zend_update_property_long(Z_OBJCE_P(zobject), Z_OBJ_P(zobject), ZEND_STRL("errCode"), errno);
            delete cli;
            return nullptr;
        }

        cli->server_id = std::move(key.value);
        cli->keep = keep;
        if (ssl) {
            cli->enable_ssl_encrypt();
        }
    }

    php_swoole_client_fetch_object(zobject)->pool_shared = key.shared;
    zend_update_property_long(Z_OBJCE_P(zobject), Z_OBJ_P(zobject), ZEND_STRL("sock"), cli->socket->fd);
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

    int client_type = php_swoole_client_get_type(type);
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

    zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("type"), type);
    if (id) {
        zend_update_property_stringl(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("id"), id, len);
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
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END();

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_client_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    SEPARATE_ARRAY(zsetting);
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

    auto *object = php_swoole_client_fetch_object(ZEND_THIS);
    if (object->cli || object->connecting) {
        php_swoole_fatal_error(E_WARNING, "connection to the server has already been established");
        RETURN_FALSE;
    }
    object->connecting = true;
    ON_SCOPE_EXIT {
        object->connecting = false;
    };

    zend_update_property_bool(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("reuse"), false);
    zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("reuseCount"), 0);

    const int socket_flags = static_cast<int>(sock_flag);
    std::unique_ptr<Client, ClientDeleter> connection(
        php_swoole_client_new(ZEND_THIS, host, host_len, port, &socket_flags));
    if (!connection) {
        RETURN_FALSE;
    }
    auto *cli = connection.get();

    const bool reused = cli->keep && cli->active;
    const bool needs_callback = reused && cli->protocol.get_package_length == php_swoole_length_func;
    if (!reused || needs_callback) {
        zval settings;
        ZVAL_COPY(&settings,
                  sw_zend_read_property_ex(swoole_client_ce, ZEND_THIS, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0));
        ON_SCOPE_EXIT {
            zval_ptr_dtor(&settings);
        };

        const bool has_settings = Z_TYPE(settings) == IS_ARRAY;
        bool valid = true;
        swoole_set_last_error(0);
        if (needs_callback) {
            zval *callback;
            if (has_settings && php_swoole_array_get_value(Z_ARRVAL(settings), "package_length_func", callback)) {
                valid = client_set_length_callback(cli->protocol, callback);
            } else {
                valid = php_swoole_throw_setting_exception("package_length_func is required for this pooled client");
            }
        } else if (has_settings) {
            valid = php_swoole_client_check_setting(cli, &settings);
        }
        if (!valid || EG(exception)) {
            zend_update_property_long(
                swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
            RETURN_FALSE;
        }
    }

    if (reused) {
        cli->reuse_count++;
        zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("reuseCount"), cli->reuse_count);
        zend_update_property_bool(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("reuse"), 1);
        object->cli = connection.release();
        RETURN_TRUE;
    } else if (cli->active == 1) {
        php_swoole_fatal_error(E_WARNING, "connection to the server has already been established");
        RETURN_FALSE;
    }

    if (cli->connect(host, port, timeout, socket_flags) < 0) {
        zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
        // async connect
        if (cli->async_connect) {
            object->cli = connection.release();
            RETURN_TRUE;
        }
        php_swoole_core_error(E_WARNING,
                              "connect to server[%s:%d] failed. Error: %s[%d]",
                              host,
                              (int) port,
                              swoole_strerror(swoole_get_last_error()),
                              swoole_get_last_error());
        RETURN_FALSE;
    }
    object->cli = connection.release();
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
    const size_t sent = cli->socket->total_send_bytes;
    ssize_t ret = cli->send(data, data_len, flags);
    if (static_cast<size_t>(ret) != data_len && cli->socket->total_send_bytes != sent) {
        cli->server_id.clear();
    }
    if (ret < 0) {
        php_swoole_sys_error(E_WARNING, "failed to send(%d) %zu bytes", cli->socket->fd, data_len);
        zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
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
        if (php_swoole_client_fetch_object(ZEND_THIS)->connecting) {
            php_swoole_error(E_WARNING, "connection to the server is being established");
            RETURN_FALSE;
        }
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
    if (offset < 0) {
        php_swoole_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] must be greater than or equal to 0", offset);
        RETURN_FALSE;
    }
    if (length < 0) {
        php_swoole_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] must be greater than or equal to 0", length);
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
    const size_t sent = cli->socket->total_send_bytes;
    int ret = cli->sendfile(file, offset, length);
    if (ret < 0) {
        if (cli->socket->total_send_bytes != sent) {
            cli->server_id.clear();
        }
        swoole_set_last_error(errno);
        php_swoole_fatal_error(E_WARNING,
                               "sendfile() failed. Error: %s [%d]",
                               swoole_strerror(swoole_get_last_error()),
                               swoole_get_last_error());
        zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
        RETVAL_FALSE;
    } else {
        RETVAL_TRUE;
    }
}

static void client_discard_read_buffer(Client *client) {
    if (client->buffer->length > 0) {
        client->server_id.clear();
        client->buffer->clear();
    }
}

static PHP_METHOD(swoole_client, recv) {
    zend_long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    zend_long flags = 0;
    ssize_t ret;
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
                client_discard_read_buffer(cli);
                php_swoole_sys_error(E_WARNING, "recv() failed");
                zend_update_property_long(
                    swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
                RETURN_FALSE;
            } else if (ret == 0) {
                client_discard_read_buffer(cli);
                RETURN_EMPTY_STRING();
            }

            buffer->length += ret;

            if (buffer->length < protocol->package_eof_len) {
                continue;
            }

        _find_eof:
            eof = protocol->find_eof_end(buffer->str, buffer->length);
            if (eof >= 0) {

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
                    client_discard_read_buffer(cli);
                    php_swoole_error(E_WARNING, "no package eof");
                    RETURN_FALSE;
                } else if (buffer->length == buffer->size) {
                    if (buffer->size < protocol->package_max_length) {
                        buffer->extend(protocol->next_eof_buffer_size(buffer->size));
                    }
                }
            }
        }
        buffer->length = 0;
        RETURN_FALSE;
    } else if (cli->open_length_check) {
        auto *object = php_swoole_client_fetch_object(ZEND_THIS);
        if (UNEXPECTED(object->reading_length)) {
            php_swoole_error(E_WARNING, "cannot receive while resolving a packet length");
            RETURN_FALSE;
        }
        if (cli->buffer == nullptr) {
            cli->buffer = new String(SW_BUFFER_SIZE_STD);
        }
        String *buffer = cli->buffer;

        uint32_t header_len = protocol->package_length_offset + protocol->package_length_size;
        if (sw_unlikely(header_len > buffer->size)) {
            buffer->extend(header_len);
        }

        while (true) {
            // A custom length header can read ahead into the next frame.
            if (buffer->length > 0) {
                ssize_t package_length = 0;
                const auto generation = object->generation;
                const bool custom_length = protocol->get_package_length == php_swoole_length_func;
                object->reading_length = custom_length;
                const auto status = protocol->resolve_package_length(
                    cli->socket, buffer->str, buffer->length, &package_length, nullptr);
                object->reading_length = false;
                // A custom length callback may close the client and release this buffer.
                if (object->generation != generation) {
                    swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
                    zend_update_property_long(
                        swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), SW_ERROR_CLIENT_NO_CONNECTION);
                    RETURN_FALSE;
                }
                if (status == swoole::PackageLengthStatus::MALFORMED) {
                    client_discard_read_buffer(cli);
                    RETURN_EMPTY_STRING();
                }
                if (status != swoole::PackageLengthStatus::NEED_MORE) {
                    buf_len = package_length;
                    break;
                }
                if (buffer->length >= header_len) {
                    client_discard_read_buffer(cli);
                    RETURN_EMPTY_STRING();
                }
            }

            auto retval = cli->recv(buffer->str + buffer->length, header_len - buffer->length, 0);
            if (retval < 0) {
                client_discard_read_buffer(cli);
                php_swoole_sys_error(E_WARNING, "recv() failed");
                zend_update_property_long(
                    swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
                RETURN_FALSE;
            } else if (retval == 0) {
                client_discard_read_buffer(cli);
                RETURN_EMPTY_STRING();
            }
            buffer->length += retval;
        }

        if (buf_len > protocol->package_max_length) {
            client_discard_read_buffer(cli);
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                             "Package is too big. package_length=%d",
                             (int) buf_len);
            RETURN_EMPTY_STRING();
        }
        if (static_cast<size_t>(buf_len) <= buffer->length) {
            RETVAL_STRINGL(buffer->str, buf_len);
            buffer->reduce(buf_len);
            return;
        }

        // The header may be shorter than header_len when package_length_func answers early.
        const size_t received_len = buffer->length;
        strbuf = zend_string_alloc(buf_len, false);
        memcpy(strbuf->val, buffer->str, received_len);
        buffer->clear();
        swoole_set_last_error(0);
        ret = cli->recv(strbuf->val + received_len, buf_len - received_len, MSG_WAITALL);
        if (ret == buf_len - static_cast<zend_long>(received_len)) {
            ret = buf_len;
        } else {
            cli->server_id.clear();
            if (ret > 0) {
                ret = 0;
            }
        }
    } else {
        if (!(flags & MSG_WAITALL) && buf_len > SW_PHP_CLIENT_BUFFER_SIZE) {
            buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
        }
        strbuf = zend_string_alloc(buf_len, false);
        swoole_set_last_error(0);
        const size_t received = cli->socket->total_recv_bytes;
        ret = cli->recv(strbuf->val, buf_len, flags);
        if (ret < 0 && cli->socket->total_recv_bytes != received) {
            cli->server_id.clear();
        }
    }

    if (ret < 0) {
        php_swoole_sys_error(E_WARNING, "recv() failed");
        zend_update_property_long(swoole_client_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("errCode"), swoole_get_last_error());
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
    if (force || !cli->keep || cli->server_id.empty() || SWOOLE_G(req_status) >= PHP_SWOOLE_RSHUTDOWN_BEGIN ||
        !client_is_reusable(cli)) {
        ret = cli->close();
        php_swoole_client_free(ZEND_THIS, cli);
    } else {
        auto connection = PooledClient(cli);
        auto *object = php_swoole_client_fetch_object(ZEND_THIS);
        const bool shared = object->pool_shared;
        php_swoole_client_set_cli(ZEND_THIS, nullptr);
        object->generation++;

        // An empty EOF buffer may still own memory from the current PHP request.
        delete std::exchange(cli->buffer, nullptr);
        // Preserve native framing. Its PHP handler must be supplied by the next borrower.
        client_release_length_callback(cli->protocol);
        client_pool.put(std::move(connection), shared);
    }
    SW_CHECK_RETURN(ret);
}

bool php_swoole_client_enable_ssl_encryption(Client *cli, zval *zobject) {
    if (cli->socket->socket_type != SW_SOCK_TCP && cli->socket->socket_type != SW_SOCK_TCP6) {
        php_swoole_fatal_error(E_WARNING, "cannot use enableSSL");
        return false;
    }
    if (cli->socket->ssl) {
        php_swoole_fatal_error(E_WARNING, "SSL has been enabled");
        return false;
    }
    if (cli->enable_ssl_encrypt() != SW_OK) {
        return false;
    }
    zval *zset = sw_zend_read_property_ex(swoole_client_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0);
    if (ZVAL_IS_ARRAY(zset)) {
        php_swoole_client_check_ssl_setting(cli, zset);
        if (UNEXPECTED(EG(exception))) {
            cli->ssl_context.reset();
            cli->open_ssl = false;
            return false;
        }
    }
    return true;
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
    if (cli->ssl_handshake() < 0) {
        zend::object_set(ZEND_THIS, ZEND_STRL("errCode"), swoole_get_last_error());
        php_swoole_client_free(ZEND_THIS, cli);
        RETURN_FALSE;
    }
    // The old pool key describes the connection before the TLS upgrade.
    cli->server_id.clear();
    RETURN_TRUE;
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

    // The three arrays are merged into one pollfd list, so the upper bound is the sum of their lengths.
    size_t maxevents = (size_t) php_swoole_array_length_safe(r_array) + php_swoole_array_length_safe(w_array) +
                       php_swoole_array_length_safe(e_array);
    if (maxevents == 0) {
        php_swoole_fatal_error(E_WARNING, "no resource arrays were passed to select");
        RETURN_FALSE;
    }
    auto *fds = static_cast<struct pollfd *>(ecalloc(maxevents, sizeof(struct pollfd)));

    if (r_array != nullptr && php_swoole_array_length(r_array) > 0) {
        index = client_poll_add(r_array, index, fds, POLLIN);
    }
    if (w_array != nullptr && php_swoole_array_length(w_array) > 0) {
        index = client_poll_add(w_array, index, fds, POLLOUT);
    }
    if (e_array != nullptr && php_swoole_array_length(e_array) > 0) {
        index = client_poll_add(e_array, index, fds, POLLHUP);
    }
    if (index == 0) {
        efree(fds);
        php_swoole_fatal_error(E_WARNING, "no resource arrays were passed to select");
        RETURN_FALSE;
    }

    do {
        retval = poll(fds, index, (int) (timeout * 1000));
    } while (retval < 0 && errno == EINTR);

    if (retval == -1) {
        efree(fds);
        php_swoole_sys_error(E_WARNING, "unable to poll()");
        RETURN_FALSE;
    }

    if (r_array != nullptr && php_swoole_array_length(r_array) > 0) {
        client_poll_wait(r_array, fds, index, retval, POLLIN);
    }
    if (w_array != nullptr && php_swoole_array_length(w_array) > 0) {
        client_poll_wait(w_array, fds, index, retval, POLLOUT);
    }
    if (e_array != nullptr && php_swoole_array_length(e_array) > 0) {
        client_poll_wait(e_array, fds, index, retval, POLLHUP);
    }
    efree(fds);
    RETURN_LONG(retval);
}

static inline int client_poll_get(const pollfd *fds, uint32_t nfds, swSocketFd fd) {
    for (uint32_t i = 0; i < nfds; i++) {
        if (fds[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

static int client_poll_wait(zval *sock_array, const pollfd *fds, uint32_t nfds, int n_event, int revent) {
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
        int poll_key = client_poll_get(fds, nfds, (swSocketFd) sock);
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

static uint32_t client_poll_add(const zval *sock_array, uint32_t index, struct pollfd *fds, int event) {
    zval *element = nullptr;
    if (!ZVAL_IS_ARRAY(sock_array)) {
        return 0;
    }

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(sock_array), element)
    int sock = php_swoole_convert_to_fd(element);
    if (sock < 0) {
        continue;
    }
    // Merge duplicates, so index never exceeds the sum of the array lengths.
    int key = client_poll_get(fds, index, sock);
    if (key < 0) {
        fds[index].fd = (swSocketFd) sock;
        fds[index].events = event;
        index++;
    } else {
        fds[key].fd = (swSocketFd) sock;
        fds[key].events |= event;
    }
    SW_HASHTABLE_FOREACH_END();

    return index;
}
