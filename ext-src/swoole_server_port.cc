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

#include "php_swoole_server.h"

using namespace swoole;

struct ServerPortEvent {
    enum php_swoole_server_port_callback_type type;
    std::string name;
    ServerPortEvent(enum php_swoole_server_port_callback_type type, std::string &&name) : type(type), name(name) {}
};

// clang-format off
static std::unordered_map<std::string, ServerPortEvent> server_port_event_map({
    { "connect",     ServerPortEvent(SW_SERVER_CB_onConnect,     "Connect") },
    { "receive",     ServerPortEvent(SW_SERVER_CB_onReceive,     "Receive") },
    { "close",       ServerPortEvent(SW_SERVER_CB_onClose,       "Close") },
    { "packet",      ServerPortEvent(SW_SERVER_CB_onPacket,      "Packet") },
    { "bufferfull",  ServerPortEvent(SW_SERVER_CB_onBufferFull,  "BufferFull") },
    { "bufferempty", ServerPortEvent(SW_SERVER_CB_onBufferEmpty, "BufferEmpty") },
    { "request",     ServerPortEvent(SW_SERVER_CB_onRequest,     "Request") },
    { "handshake",   ServerPortEvent(SW_SERVER_CB_onHandshake,   "Handshake") },
    { "open",        ServerPortEvent(SW_SERVER_CB_onOpen,        "Open") },
    { "message",     ServerPortEvent(SW_SERVER_CB_onMessage,     "Message") },
    { "disconnect",  ServerPortEvent(SW_SERVER_CB_onDisconnect,  "Disconnect") },
});
// clang-format on

zend_class_entry *swoole_server_port_ce;
static zend_object_handlers swoole_server_port_handlers;

struct ServerPortObject {
    ListenPort *port;
    ServerPortProperty property;
    zend_object std;
};

static sw_inline ServerPortObject *php_swoole_server_port_fetch_object(zend_object *obj) {
    return (ServerPortObject *) ((char *) obj - swoole_server_port_handlers.offset);
}

static sw_inline ListenPort *php_swoole_server_port_get_ptr(zval *zobject) {
    return php_swoole_server_port_fetch_object(Z_OBJ_P(zobject))->port;
}

ListenPort *php_swoole_server_port_get_and_check_ptr(zval *zobject) {
    ListenPort *port = php_swoole_server_port_get_ptr(zobject);
    if (UNEXPECTED(!port)) {
        php_swoole_fatal_error(E_ERROR, "Invalid instance of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    return port;
}

void php_swoole_server_port_set_ptr(zval *zobject, ListenPort *port) {
    php_swoole_server_port_fetch_object(Z_OBJ_P(zobject))->port = port;
}

ServerPortProperty *php_swoole_server_port_get_property(zval *zobject) {
    return &php_swoole_server_port_fetch_object(Z_OBJ_P(zobject))->property;
}

static ServerPortProperty *php_swoole_server_port_get_and_check_property(zval *zobject) {
    ServerPortProperty *property = php_swoole_server_port_get_property(zobject);
    if (UNEXPECTED(!property->serv)) {
        php_swoole_fatal_error(E_ERROR, "Invalid instance of %s", SW_Z_OBJCE_NAME_VAL_P(zobject));
    }
    return property;
}

// Dereference from server object
void php_swoole_server_port_deref(zend_object *object) {
    ServerPortObject *server_port = php_swoole_server_port_fetch_object(object);
    ServerPortProperty *property = &server_port->property;
    if (property->serv) {
        for (int j = 0; j < PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM; j++) {
            if (property->caches[j]) {
                efree(property->caches[j]);
                property->caches[j] = nullptr;
            }
        }
        property->serv = nullptr;
    }

    ListenPort *port = server_port->port;
    if (port) {
        if (port->protocol.private_data) {
            sw_zend_fci_cache_discard((zend_fcall_info_cache *) port->protocol.private_data);
            efree(port->protocol.private_data);
            port->protocol.private_data = nullptr;
        }
        server_port->port = nullptr;
    }
}

static void php_swoole_server_port_free_object(zend_object *object) {
    php_swoole_server_port_deref(object);
    zend_object_std_dtor(object);
}

static zend_object *php_swoole_server_port_create_object(zend_class_entry *ce) {
    ServerPortObject *server_port = (ServerPortObject *) zend_object_alloc(sizeof(ServerPortObject), ce);
    zend_object_std_init(&server_port->std, ce);
    object_properties_init(&server_port->std, ce);
    server_port->std.handlers = &swoole_server_port_handlers;
    return &server_port->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_server_port, __construct);
static PHP_METHOD(swoole_server_port, __destruct);
static PHP_METHOD(swoole_server_port, on);
static PHP_METHOD(swoole_server_port, set);
static PHP_METHOD(swoole_server_port, getCallback);

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server_port, getSocket);
#endif
SW_EXTERN_C_END

// clang-format off

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_port_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_port_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_CALLABLE_INFO(0, callback, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_port_getCallback, 0, 0, 1)
    ZEND_ARG_INFO(0, event_name)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_server_port_methods[] =
{
    PHP_ME(swoole_server_port, __construct,     arginfo_swoole_void,                    ZEND_ACC_PRIVATE)
    PHP_ME(swoole_server_port, __destruct,      arginfo_swoole_void,                    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, set,             arginfo_swoole_server_port_set,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, on,              arginfo_swoole_server_port_on,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, getCallback,     arginfo_swoole_server_port_getCallback, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_server_port, getSocket,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};
// clang-format on

void php_swoole_server_port_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(
        swoole_server_port, "Swoole\\Server\\Port", "swoole_server_port", nullptr, swoole_server_port_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_server_port);
    SW_SET_CLASS_CLONEABLE(swoole_server_port, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server_port, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_server_port,
                               php_swoole_server_port_create_object,
                               php_swoole_server_port_free_object,
                               ServerPortObject,
                               std);

    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onConnect"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onReceive"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onClose"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onPacket"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onBufferFull"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onBufferEmpty"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onRequest"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onHandshake"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onOpen"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onMessage"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onDisconnect"), ZEND_ACC_PRIVATE);

    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("connections"), ZEND_ACC_PUBLIC);
}

/**
 * [Master-Process]
 */
static ssize_t php_swoole_server_length_func(const Protocol *protocol, network::Socket *conn, PacketLength *pl) {
    Server *serv = (Server *) protocol->private_data_2;
    serv->lock();

    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) protocol->private_data;
    zval zdata;
    zval retval;
    ssize_t ret = -1;

    // TODO: reduce memory copy
    ZVAL_STRINGL(&zdata, pl->buf, pl->buf_size);
    if (UNEXPECTED(sw_zend_call_function_ex(nullptr, fci_cache, 1, &zdata, &retval) != SUCCESS)) {
        php_swoole_fatal_error(E_WARNING, "length function handler error");
    } else {
        ret = zval_get_long(&retval);
        zval_ptr_dtor(&retval);
    }
    zval_ptr_dtor(&zdata);

    serv->unlock();

    /* the exception should only be thrown after unlocked */
    if (UNEXPECTED(EG(exception))) {
        zend_exception_error(EG(exception), E_ERROR);
    }

    return ret;
}

static PHP_METHOD(swoole_server_port, __construct) {
    php_swoole_fatal_error(E_ERROR, "please use the Swoole\\Server->listen method");
    return;
}

static PHP_METHOD(swoole_server_port, __destruct) {}

#ifdef SW_USE_OPENSSL
static bool php_swoole_server_set_ssl_option(zend_array *vht, SSLContext *ctx) {
    zval *ztmp;
    if (php_swoole_array_get_value(vht, "ssl_cert_file", ztmp)) {
        zend::String str_v(ztmp);
        if (access(str_v.val(), R_OK) < 0) {
            php_swoole_fatal_error(E_ERROR, "ssl cert file[%s] not found", str_v.val());
            return false;
        }
        ctx->cert_file = str_v.to_std_string();
    }
    if (php_swoole_array_get_value(vht, "ssl_key_file", ztmp)) {
        zend::String str_v(ztmp);
        if (access(str_v.val(), R_OK) < 0) {
            php_swoole_fatal_error(E_ERROR, "ssl key file[%s] not found", str_v.val());
            return false;
        }
        ctx->key_file = str_v.to_std_string();
    }
    return true;
}
#endif

static PHP_METHOD(swoole_server_port, set) {
    zval *zset = nullptr;
    HashTable *vht;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    ListenPort *port = php_swoole_server_port_get_and_check_ptr(ZEND_THIS);
    ServerPortProperty *property = php_swoole_server_port_get_and_check_property(ZEND_THIS);

    if (port == nullptr || property == nullptr) {
        php_swoole_fatal_error(E_ERROR, "please use the swoole_server->listen method");
        return;
    }

    // backlog
    if (php_swoole_array_get_value(vht, "backlog", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->backlog = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->socket_buffer_size = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
        if (port->socket_buffer_size <= 0) {
            port->socket_buffer_size = INT_MAX;
        }
    }
    /**
     * !!! Don't set this option, for tests only.
     */
    if (php_swoole_array_get_value(vht, "kernel_socket_recv_buffer_size", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->kernel_socket_recv_buffer_size = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
        if (port->kernel_socket_recv_buffer_size <= 0) {
            port->kernel_socket_recv_buffer_size = INT_MAX;
        }
    }
    /**
     * !!! Don't set this option, for tests only.
     */
    if (php_swoole_array_get_value(vht, "kernel_socket_send_buffer_size", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->kernel_socket_send_buffer_size = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
        if (port->kernel_socket_send_buffer_size <= 0) {
            port->kernel_socket_send_buffer_size = INT_MAX;
        }
    }
    // heartbeat idle time
    if (php_swoole_array_get_value(vht, "heartbeat_idle_time", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->heartbeat_idle_time = SW_MAX(0, SW_MIN(v, UINT16_MAX));
    }
    if (php_swoole_array_get_value(vht, "buffer_high_watermark", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->buffer_high_watermark = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    if (php_swoole_array_get_value(vht, "buffer_low_watermark", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->buffer_low_watermark = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }
    // server: tcp_nodelay
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", ztmp)) {
        port->open_tcp_nodelay = zval_is_true(ztmp);
    } else {
        port->open_tcp_nodelay = 1;
    }
    // tcp_defer_accept
    if (php_swoole_array_get_value(vht, "tcp_defer_accept", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->tcp_defer_accept = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
    }
    // tcp_keepalive
    if (php_swoole_array_get_value(vht, "open_tcp_keepalive", ztmp)) {
        port->open_tcp_keepalive = zval_is_true(ztmp);
    }
    // buffer: eof check
    if (php_swoole_array_get_value(vht, "open_eof_check", ztmp)) {
        port->open_eof_check = zval_is_true(ztmp);
    }
    // buffer: split package with eof
    if (php_swoole_array_get_value(vht, "open_eof_split", ztmp)) {
        port->protocol.split_by_eof = zval_is_true(ztmp);
        if (port->protocol.split_by_eof) {
            port->open_eof_check = 1;
        }
    }
    // package eof
    if (php_swoole_array_get_value(vht, "package_eof", ztmp)) {
        zend::String str_v(ztmp);
        port->protocol.package_eof_len = str_v.len();
        if (port->protocol.package_eof_len == 0) {
            php_swoole_fatal_error(E_ERROR, "package_eof cannot be an empty string");
            RETURN_FALSE;
        } else if (port->protocol.package_eof_len > SW_DATA_EOF_MAXLEN) {
            php_swoole_fatal_error(E_ERROR, "package_eof max length is %d", SW_DATA_EOF_MAXLEN);
            RETURN_FALSE;
        }
        memcpy(port->protocol.package_eof, str_v.val(), str_v.len());
    }
    // http_protocol
    if (php_swoole_array_get_value(vht, "open_http_protocol", ztmp)) {
        port->open_http_protocol = zval_is_true(ztmp);
    }
    // websocket protocol
    if (php_swoole_array_get_value(vht, "open_websocket_protocol", ztmp)) {
        port->open_websocket_protocol = zval_is_true(ztmp);
        if (port->open_websocket_protocol) {
            port->open_http_protocol = 1;
        }
    }
    if (php_swoole_array_get_value(vht, "websocket_subprotocol", ztmp)) {
        port->websocket_subprotocol = zend::String(ztmp).to_std_string();
    }
    if (php_swoole_array_get_value(vht, "open_websocket_close_frame", ztmp)) {
        port->open_websocket_close_frame = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "open_websocket_ping_frame", ztmp)) {
        port->open_websocket_ping_frame = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "open_websocket_pong_frame", ztmp)) {
        port->open_websocket_pong_frame = zval_is_true(ztmp);
    }
#ifdef SW_USE_HTTP2
    // http2 protocol
    if (php_swoole_array_get_value(vht, "open_http2_protocol", ztmp)) {
        port->open_http2_protocol = zval_is_true(ztmp);
        if (port->open_http2_protocol) {
            port->open_http_protocol = 1;
        }
    }
#endif
    // buffer: mqtt protocol
    if (php_swoole_array_get_value(vht, "open_mqtt_protocol", ztmp)) {
        port->open_mqtt_protocol = zval_is_true(ztmp);
    }
    // redis protocol
    if (php_swoole_array_get_value(vht, "open_redis_protocol", ztmp)) {
        port->open_redis_protocol = zval_get_long(ztmp);
    }
    if (php_swoole_array_get_value(vht, "max_idle_time", ztmp)) {
        double v = zval_get_double(ztmp);
        port->max_idle_time = SW_MAX(v, SW_TIMER_MIN_SEC);
    }
    // tcp_keepidle
    if (php_swoole_array_get_value(vht, "tcp_keepidle", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->tcp_keepidle = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
    }
    // tcp_keepinterval
    if (php_swoole_array_get_value(vht, "tcp_keepinterval", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->tcp_keepinterval = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
    }
    // tcp_keepcount
    if (php_swoole_array_get_value(vht, "tcp_keepcount", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->tcp_keepcount = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
    }
    // tcp_user_timeout
    if (php_swoole_array_get_value(vht, "tcp_user_timeout", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->tcp_user_timeout = SW_MAX(INT_MIN, SW_MIN(v, INT_MAX));
    }
    // tcp_fastopen
    if (php_swoole_array_get_value(vht, "tcp_fastopen", ztmp)) {
        port->tcp_fastopen = zval_is_true(ztmp);
    }
    // open length check
    if (php_swoole_array_get_value(vht, "open_length_check", ztmp)) {
        port->open_length_check = zval_is_true(ztmp);
    }
    // package length size
    if (php_swoole_array_get_value(vht, "package_length_type", ztmp)) {
        zend::String str_v(ztmp);
        port->protocol.package_length_type = str_v.val()[0];
        port->protocol.package_length_size = swoole_type_size(port->protocol.package_length_type);
        if (port->protocol.package_length_size == 0) {
            php_swoole_fatal_error(E_ERROR, "unknown package_length_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }
    // package length offset
    if (php_swoole_array_get_value(vht, "package_length_offset", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->protocol.package_length_offset = SW_MAX(0, SW_MIN(v, UINT16_MAX));
        if (port->protocol.package_length_offset > SW_IPC_BUFFER_SIZE) {
            php_swoole_fatal_error(E_ERROR, "'package_length_offset' value is too large");
        }
    }
    // package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", ztmp) ||
        php_swoole_array_get_value(vht, "package_body_start", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->protocol.package_body_offset = SW_MAX(0, SW_MIN(v, UINT16_MAX));
        if (port->protocol.package_body_offset > SW_IPC_BUFFER_SIZE) {
            php_swoole_fatal_error(E_ERROR, "'package_body_offset' value is too large");
        }
    }
    // length function
    if (php_swoole_array_get_value(vht, "package_length_func", ztmp)) {
        while (1) {
            if (Z_TYPE_P(ztmp) == IS_STRING) {
                Protocol::LengthFunc func = Protocol::get_function(std::string(Z_STRVAL_P(ztmp), Z_STRLEN_P(ztmp)));
                if (func != nullptr) {
                    port->protocol.get_package_length = func;
                    break;
                }
            }
#ifdef ZTS
            Server *serv = property->serv;
            if (serv->is_process_mode() && !serv->single_thread) {
                php_swoole_fatal_error(E_ERROR, "option [package_length_func] does not support with ZTS");
            }
#endif
            char *func_name;
            zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) ecalloc(1, sizeof(zend_fcall_info_cache));
            if (!sw_zend_is_callable_ex(ztmp, nullptr, 0, &func_name, nullptr, fci_cache, nullptr)) {
                php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
                return;
            }
            efree(func_name);
            port->protocol.get_package_length = php_swoole_server_length_func;
            if (port->protocol.private_data) {
                sw_zend_fci_cache_discard((zend_fcall_info_cache *) port->protocol.private_data);
                efree(port->protocol.private_data);
            }
            sw_zend_fci_cache_persist(fci_cache);
            port->protocol.private_data = fci_cache;
            break;
        }

        port->protocol.package_length_size = 0;
        port->protocol.package_length_type = '\0';
        port->protocol.package_length_offset = SW_IPC_BUFFER_SIZE;
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        port->protocol.package_max_length = SW_MAX(0, SW_MIN(v, UINT32_MAX));
    }

#ifdef SW_USE_OPENSSL
    if (port->ssl) {
        if (!php_swoole_server_set_ssl_option(vht, port->ssl_context)) {
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(vht, "ssl_compress", ztmp)) {
            port->ssl_context->disable_compress = !zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "ssl_protocols", ztmp)) {
            zend_long v = zval_get_long(ztmp);
            port->ssl_context->protocols = v;
#ifdef SW_SUPPORT_DTLS
            if (port->is_dtls() && !port->is_dgram()) {
                port->ssl_context->protocols ^= SW_SSL_DTLS;
            }
#endif
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_peer", ztmp)) {
            port->ssl_context->verify_peer = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", ztmp)) {
            port->ssl_context->allow_self_signed = zval_is_true(ztmp);
        }
        // verify client cert
        if (php_swoole_array_get_value(vht, "ssl_client_cert_file", ztmp)) {
            zend::String str_v(ztmp);
            if (access(str_v.val(), R_OK) < 0) {
                php_swoole_fatal_error(E_ERROR, "ssl_client_cert_file[%s] not found", str_v.val());
                return;
            }
            port->ssl_context->client_cert_file = str_v.to_std_string();
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_depth", ztmp)) {
            zend_long v = zval_get_long(ztmp);
            port->ssl_context->verify_depth = SW_MAX(0, SW_MIN(v, UINT8_MAX));
        }
        if (php_swoole_array_get_value(vht, "ssl_prefer_server_ciphers", ztmp)) {
            port->ssl_context->prefer_server_ciphers = zval_is_true(ztmp);
        }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_session_tickets"))))
        //    {
        //        port->ssl_context->session_tickets = zval_is_true(v);
        //    }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_stapling"))))
        //    {
        //        port->ssl_context->stapling = zval_is_true(v);
        //    }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_stapling_verify"))))
        //    {
        //        port->ssl_context->stapling_verify = zval_is_true(v);
        //    }
        if (php_swoole_array_get_value(vht, "ssl_ciphers", ztmp)) {
            port->ssl_context->ciphers = zend::String(ztmp).to_std_string();
        }
        if (php_swoole_array_get_value(vht, "ssl_ecdh_curve", ztmp)) {
            port->ssl_context->ecdh_curve = zend::String(ztmp).to_std_string();
        }
        if (php_swoole_array_get_value(vht, "ssl_dhparam", ztmp)) {
            port->ssl_context->dhparam = zend::String(ztmp).to_std_string();
        }
        if (php_swoole_array_get_value(vht, "ssl_sni_certs", ztmp)) {
            if (Z_TYPE_P(ztmp) != IS_ARRAY) {
                php_swoole_fatal_error(E_WARNING, "ssl_sni_certs requires an array mapping host names to cert paths");
                RETURN_FALSE;
            }

            zval *current;
            zend_string *key;
            zend_ulong key_index;

            ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(ztmp), key_index, key, current) {
                (void) key_index;
                if (!key) {
                    php_swoole_fatal_error(E_WARNING, "ssl_sni_certs array requires string host name keys");
                    RETURN_FALSE;
                }
                if (Z_TYPE_P(current) != IS_ARRAY) {
                    php_swoole_fatal_error(E_WARNING, "invalid SNI_cert setting");
                    RETURN_FALSE;
                }
                SSLContext *context = new SSLContext();
                *context = *port->ssl_context;
                if (!php_swoole_server_set_ssl_option(Z_ARRVAL_P(current), context)) {
                    delete context;
                    RETURN_FALSE;
                }
                if (!port->ssl_add_sni_cert(std::string(key->val, key->len), context)) {
                    php_swoole_fatal_error(E_ERROR, "ssl_add_sni_cert() failed");
                    delete context;
                    RETURN_FALSE;
                }
            }
            ZEND_HASH_FOREACH_END();
        }

        if (!port->ssl_context->cert_file.empty() || port->sni_contexts.empty()) {
            if (!port->ssl_init()) {
                php_swoole_fatal_error(E_ERROR, "ssl_init() failed");
                RETURN_FALSE;
            }
        }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_session_cache"))))
        //    {
        //        port->ssl_context->session_cache = zend::string_dup(v);
        //    }
    }
#endif

    if (SWOOLE_G(enable_library)) {
        zval params[1] = {
            *zset,
        };
        zend::function::call("\\Swoole\\Server\\Helper::checkOptions", 1, params);
    }

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_server_port_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    property->zsetting = zsetting;
}

static PHP_METHOD(swoole_server_port, on) {
    char *name = nullptr;
    size_t len;
    zval *cb;

    ServerPortProperty *property = php_swoole_server_port_get_and_check_property(ZEND_THIS);
    Server *serv = property->serv;
    if (serv->is_started()) {
        php_swoole_fatal_error(E_WARNING, "can't register event callback function after server started");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &name, &len, &cb) == FAILURE) {
        RETURN_FALSE;
    }

    char *func_name = nullptr;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(cb, nullptr, 0, &func_name, nullptr, fci_cache, nullptr)) {
        php_swoole_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    bool found = false;
    for (auto i = server_port_event_map.begin(); i != server_port_event_map.end(); i++) {
        if (!swoole_strcaseeq(name, len, i->first.c_str(), i->first.length())) {
            continue;
        }

        found = true;
        int index = i->second.type;
        std::string property_name = std::string("on") + i->second.name;
        zend_update_property(
            swoole_server_port_ce, SW_Z8_OBJ_P(ZEND_THIS), property_name.c_str(), property_name.length(), cb);
        property->callbacks[index] =
            sw_zend_read_property(swoole_server_port_ce, ZEND_THIS, property_name.c_str(), property_name.length(), 0);
        sw_copy_to_stack(property->callbacks[index], property->_callbacks[index]);
        if (property->caches[index]) {
            efree(property->caches[index]);
        }
        property->caches[index] = fci_cache;

        if (index == SW_SERVER_CB_onConnect && !serv->onConnect) {
            serv->onConnect = php_swoole_server_onConnect;
        } else if (index == SW_SERVER_CB_onPacket && !serv->onPacket) {
            serv->onPacket = php_swoole_server_onPacket;
        } else if (index == SW_SERVER_CB_onClose && !serv->onClose) {
            serv->onClose = php_swoole_server_onClose;
        } else if (index == SW_SERVER_CB_onBufferFull && !serv->onBufferFull) {
            serv->onBufferFull = php_swoole_server_onBufferFull;
        } else if (index == SW_SERVER_CB_onBufferEmpty && !serv->onBufferEmpty) {
            serv->onBufferEmpty = php_swoole_server_onBufferEmpty;
        }
        break;
    }

    if (!found) {
        php_swoole_error(E_WARNING, "unknown event types[%s]", name);
        efree(fci_cache);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_server_port, getCallback) {
    zval *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(name)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend::String _event_name_ori(name);
    zend::String _event_name_tolower(zend_string_tolower(_event_name_ori.get()), false);
    auto i = server_port_event_map.find(_event_name_tolower.to_std_string());
    if (i != server_port_event_map.end()) {
        std::string property_name = "on" + i->second.name;
        zval rv,
            *property = zend_read_property(
                swoole_server_port_ce, SW_Z8_OBJ_P(ZEND_THIS), property_name.c_str(), property_name.length(), 1, &rv);
        if (!ZVAL_IS_NULL(property)) {
            RETURN_ZVAL(property, 1, 0);
        }
    }
    RETURN_NULL();
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server_port, getSocket) {
    ListenPort *port = php_swoole_server_port_get_and_check_ptr(ZEND_THIS);
    php_socket *socket_object = php_swoole_convert_to_socket(port->get_fd());
    if (!socket_object) {
        RETURN_FALSE;
    }
    SW_ZVAL_SOCKET(return_value, socket_object);
    zval *zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
}
#endif
