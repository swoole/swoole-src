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

using namespace std;
using namespace swoole;

zend_class_entry *swoole_server_port_ce;
static zend_object_handlers swoole_server_port_handlers;

struct server_port_event {
    enum php_swoole_server_port_callback_type type;
    std::string name;
    server_port_event(enum php_swoole_server_port_callback_type type, std::string &&name) : type(type) , name(name) { }
};
static unordered_map<string, server_port_event> server_port_event_map({
    { "connect",     server_port_event(SW_SERVER_CB_onConnect,     "Connect") },
    { "receive",     server_port_event(SW_SERVER_CB_onReceive,     "Receive") },
    { "close",       server_port_event(SW_SERVER_CB_onClose,       "Close") },
    { "packet",      server_port_event(SW_SERVER_CB_onPacket,      "Packet") },
    { "bufferfull",  server_port_event(SW_SERVER_CB_onBufferFull,  "BufferFull") },
    { "bufferempty", server_port_event(SW_SERVER_CB_onBufferEmpty, "BufferEmpty") },
    { "request",     server_port_event(SW_SERVER_CB_onRequest,     "Request") },
    { "handshake",   server_port_event(SW_SERVER_CB_onHandShake,   "Handshake") },
    { "open",        server_port_event(SW_SERVER_CB_onOpen,        "Open") },
    { "message",     server_port_event(SW_SERVER_CB_onMessage,     "Message") },
});

static PHP_METHOD(swoole_server_port, __construct);
static PHP_METHOD(swoole_server_port, __destruct);
static PHP_METHOD(swoole_server_port, on);
static PHP_METHOD(swoole_server_port, set);
static PHP_METHOD(swoole_server_port, getCallback);

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server_port, getSocket);
#endif

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

void swoole_server_port_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_server_port, "Swoole\\Server\\Port", "swoole_server_port", NULL, swoole_server_port_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_server_port, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_server_port, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server_port, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_server_port);

    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onConnect"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onReceive"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onClose"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onPacket"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onBufferFull"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onBufferEmpty"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onRequest"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onHandShake"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onOpen"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("onMessage"), ZEND_ACC_PRIVATE);

    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_server_port_ce, ZEND_STRL("connections"), ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_server_port, __construct)
{
    swoole_php_fatal_error(E_ERROR, "please use the Swoole\\Server->listen method");
    return;
}

static PHP_METHOD(swoole_server_port, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    swoole_server_port_property *property = (swoole_server_port_property *) swoole_get_property(getThis(), 0);

    int j;
    for (j = 0; j < PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM; j++)
    {
        if (property->caches[j])
        {
            efree(property->caches[j]);
            property->caches[j] = NULL;
        }
    }

    efree(property);
    swoole_set_property(getThis(), 0, NULL);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_server_port, set)
{
    zval *zset = NULL;
    HashTable *vht;
    zval *v;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    swListenPort *port = (swListenPort *) swoole_get_object(getThis());
    swoole_server_port_property *property = (swoole_server_port_property *) swoole_get_property(getThis(), 0);

    if (port == NULL || property == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "please use the swoole_server->listen method");
        return;
    }

    //backlog
    if (php_swoole_array_get_value(vht, "backlog", v))
    {
        port->backlog = (int) zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", v))
    {
        port->socket_buffer_size = (int) zval_get_long(v);
        if (port->socket_buffer_size <= 0)
        {
            port->socket_buffer_size = INT_MAX;
        }
    }
    /**
     * !!! Don't set this option, for tests only.
     */
    if (php_swoole_array_get_value(vht, "kernel_socket_recv_buffer_size", v))
    {
        port->kernel_socket_recv_buffer_size = (int) zval_get_long(v);
        if (port->kernel_socket_recv_buffer_size <= 0)
        {
            port->kernel_socket_recv_buffer_size = INT_MAX;
        }
    }
    /**
     * !!! Don't set this option, for tests only.
     */
    if (php_swoole_array_get_value(vht, "kernel_socket_send_buffer_size", v))
    {
        port->kernel_socket_send_buffer_size = (int) zval_get_long(v);
        if (port->kernel_socket_send_buffer_size <= 0)
        {
            port->kernel_socket_send_buffer_size = INT_MAX;
        }
    }
    if (php_swoole_array_get_value(vht, "buffer_high_watermark", v))
    {
        port->buffer_high_watermark = (int) zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "buffer_low_watermark", v))
    {
        port->buffer_low_watermark = (int) zval_get_long(v);
    }
    //server: tcp_nodelay
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", v))
    {
        port->open_tcp_nodelay = zval_is_true(v);
    }
    else
    {
        port->open_tcp_nodelay = 1;
    }
    //tcp_defer_accept
    if (php_swoole_array_get_value(vht, "tcp_defer_accept", v))
    {
        port->tcp_defer_accept = (uint8_t) zval_get_long(v);
    }
    //tcp_keepalive
    if (php_swoole_array_get_value(vht, "open_tcp_keepalive", v))
    {
        port->open_tcp_keepalive = zval_is_true(v);
    }
    //buffer: eof check
    if (php_swoole_array_get_value(vht, "open_eof_check", v))
    {
        port->open_eof_check = zval_is_true(v);
    }
    //buffer: split package with eof
    if (php_swoole_array_get_value(vht, "open_eof_split", v))
    {
        port->protocol.split_by_eof = zval_is_true(v);
        if (port->protocol.split_by_eof)
        {
            port->open_eof_check = 1;
        }
    }
    //package eof
    if (php_swoole_array_get_value(vht, "package_eof", v))
    {
        zend::string str_v(v);
        port->protocol.package_eof_len = str_v.len();
        if (port->protocol.package_eof_len == 0)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof cannot be an empty string");
            RETURN_FALSE;
        }
        else if (port->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            RETURN_FALSE;
        }
        bzero(port->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(port->protocol.package_eof, str_v.val(), str_v.len());
    }
    //http_protocol
    if (php_swoole_array_get_value(vht, "open_http_protocol", v))
    {
        port->open_http_protocol = zval_is_true(v);
    }
    //websocket protocol
    if (php_swoole_array_get_value(vht, "open_websocket_protocol", v))
    {
        port->open_websocket_protocol = zval_is_true(v);
        if (port->open_websocket_protocol)
        {
            port->open_http_protocol = 1;
        }
    }
    if (php_swoole_array_get_value(vht, "websocket_subprotocol", v))
    {
        zend::string str_v(v);
        if (port->websocket_subprotocol)
        {
            sw_free(port->websocket_subprotocol);
        }
        port->websocket_subprotocol = str_v.dup();
        port->websocket_subprotocol_length = str_v.len();
    }
    if (php_swoole_array_get_value(vht, "open_websocket_close_frame", v))
    {
        port->open_websocket_close_frame = zval_is_true(v);
    }
#ifdef SW_USE_HTTP2
    //http2 protocol
    if (php_swoole_array_get_value(vht, "open_http2_protocol", v))
    {
        port->open_http2_protocol = zval_is_true(v);
        if (port->open_http2_protocol)
        {
            port->open_http_protocol = 1;
        }
    }
#endif
    //buffer: mqtt protocol
    if (php_swoole_array_get_value(vht, "open_mqtt_protocol", v))
    {
        port->open_mqtt_protocol = zval_is_true(v);
    }
    //redis protocol
    if (php_swoole_array_get_value(vht, "open_redis_protocol", v))
    {
        port->open_redis_protocol = zval_get_long(v);
    }
    //tcp_keepidle
    if (php_swoole_array_get_value(vht, "tcp_keepidle", v))
    {
        port->tcp_keepidle = (uint16_t) zval_get_long(v);
    }
    //tcp_keepinterval
    if (php_swoole_array_get_value(vht, "tcp_keepinterval", v))
    {
        port->tcp_keepinterval = (uint16_t) zval_get_long(v);
    }
    //tcp_keepcount
    if (php_swoole_array_get_value(vht, "tcp_keepcount", v))
    {
        port->tcp_keepcount = (uint16_t) zval_get_long(v);
    }
    //tcp_fastopen
    if (php_swoole_array_get_value(vht, "tcp_fastopen", v))
    {
        port->tcp_fastopen = zval_is_true(v);
    }
    //open length check
    if (php_swoole_array_get_value(vht, "open_length_check", v))
    {
        port->open_length_check = zval_is_true(v);
    }
    //package length size
    if (php_swoole_array_get_value(vht, "package_length_type", v))
    {
        zend::string str_v(v);
        port->protocol.package_length_type = str_v.val()[0];
        port->protocol.package_length_size = swoole_type_size(port->protocol.package_length_type);
        if (port->protocol.package_length_size == 0)
        {
            swoole_php_fatal_error(E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }
    //package length offset
    if (php_swoole_array_get_value(vht, "package_length_offset", v))
    {
        port->protocol.package_length_offset = (int) zval_get_long(v);
        if (port->protocol.package_length_offset > SW_IPC_BUFFER_SIZE)
        {
            swoole_php_fatal_error(E_ERROR, "'package_length_offset' value is too large");
        }
    }
    //package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", v) || php_swoole_array_get_value(vht, "package_body_start", v))
    {
        port->protocol.package_body_offset = (int) zval_get_long(v);
        if (port->protocol.package_body_offset > SW_IPC_BUFFER_SIZE)
        {
            swoole_php_fatal_error(E_ERROR, "'package_body_offset' value is too large");
        }
    }
    //length function
    if (php_swoole_array_get_value(vht, "package_length_func", v))
    {
        while(1)
        {
            if (Z_TYPE_P(v) == IS_STRING)
            {
                swProtocol_length_function func = (swProtocol_length_function) swoole_get_function(Z_STRVAL_P(v), Z_STRLEN_P(v));
                if (func != NULL)
                {
                    port->protocol.get_package_length = func;
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
            port->protocol.get_package_length = php_swoole_length_func;
            if (port->protocol.private_data)
            {
                zval_ptr_dtor((zval *)port->protocol.private_data);
                efree(port->protocol.private_data);
            }
            Z_TRY_ADDREF_P(v);
            port->protocol.private_data = sw_zval_dup(v);
            break;
        }

        port->protocol.package_length_size = 0;
        port->protocol.package_length_type = '\0';
        port->protocol.package_length_offset = SW_IPC_BUFFER_SIZE;
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", v))
    {
        port->protocol.package_max_length = (int) zval_get_long(v);
    }

#ifdef SW_USE_OPENSSL
    if (port->ssl)
    {
        if (php_swoole_array_get_value(vht, "ssl_cert_file", v))
        {
            zend::string str_v(v);
            if (access(str_v.val(), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found", str_v.val());
                return;
            }
            if (port->ssl_option.cert_file)
            {
                sw_free(port->ssl_option.cert_file);
            }
            port->ssl_option.cert_file = str_v.dup();
            port->open_ssl_encrypt = 1;
        }
        if (php_swoole_array_get_value(vht, "ssl_key_file", v))
        {
            zend::string str_v(v);
            if (access(str_v.val(), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found", str_v.val());
                return;
            }
            if (port->ssl_option.key_file)
            {
                sw_free(port->ssl_option.key_file);
            }
            port->ssl_option.key_file = str_v.dup();
        }
        if (php_swoole_array_get_value(vht, "ssl_method", v))
        {
            port->ssl_option.method = (int) zval_get_long(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_peer", v))
        {
            port->ssl_option.verify_peer = zval_is_true(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", v))
        {
            port->ssl_option.allow_self_signed = zval_is_true(v);
        }
        //verify client cert
        if (php_swoole_array_get_value(vht, "ssl_client_cert_file", v))
        {
            zend::string str_v(v);
            if (access(str_v.val(), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl_client_cert_file[%s] not found", str_v.val());
                return;
            }
            if (port->ssl_option.client_cert_file)
            {
                sw_free(port->ssl_option.client_cert_file);
            }
            port->ssl_option.client_cert_file = str_v.dup();
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_depth", v))
        {
            port->ssl_option.verify_depth = (int) zval_get_long(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_prefer_server_ciphers", v))
        {
            port->ssl_config.prefer_server_ciphers = zval_is_true(v);
        }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_session_tickets"))))
        //    {
        //        port->ssl_config.session_tickets = zval_is_true(v);
        //    }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_stapling"))))
        //    {
        //        port->ssl_config.stapling = zval_is_true(v);
        //    }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_stapling_verify"))))
        //    {
        //        port->ssl_config.stapling_verify = zval_is_true(v);
        //    }
        if (php_swoole_array_get_value(vht, "ssl_ciphers", v))
        {
            if (port->ssl_config.ciphers)
            {
                sw_free(port->ssl_config.ciphers);
            }
            port->ssl_config.ciphers = zend::string(v).dup();
        }
        if (php_swoole_array_get_value(vht, "ssl_ecdh_curve", v))
        {
            if (port->ssl_config.ecdh_curve)
            {
                sw_free(port->ssl_config.ecdh_curve);
            }
            port->ssl_config.ecdh_curve = zend::string(v).dup();
        }
        if (php_swoole_array_get_value(vht, "ssl_dhparam", v))
        {
            if (port->ssl_config.dhparam)
            {
                sw_free(port->ssl_config.dhparam);
            }
            port->ssl_config.dhparam = zend::string(v).dup();
        }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_session_cache"))))
        //    {
        //        port->ssl_config.session_cache = zend::string_dup(v);
        //    }
        if (swPort_enable_ssl_encrypt(port) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "swPort_enable_ssl_encrypt() failed");
            RETURN_FALSE;
        }
    }
#endif

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_server_port_ce, getThis(), ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    property->zsetting = zsetting;
}

static PHP_METHOD(swoole_server_port, on)
{
    char *name = NULL;
    size_t len, i;
    zval *cb;

    swoole_server_port_property *property = (swoole_server_port_property *) swoole_get_property(getThis(), 0);
    swServer *serv = property->serv;
    if (serv->gs->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "can't register event callback function after server started");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &name, &len, &cb) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name = NULL;
    zend_fcall_info_cache *fci_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(cb, NULL, 0, &func_name, NULL, fci_cache, NULL))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        return;
    }
    efree(func_name);

    const char *callback_name[PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM] = {
        "Connect",
        "Receive",
        "Close",
        "Packet",
        "Request",
        "HandShake",
        "Open",
        "Message",
        "BufferFull",
        "BufferEmpty",
    };

    char property_name[128];
    int l_property_name = 0;
    memcpy(property_name, "on", 2);

    for (i = 0; i < PHP_SWOOLE_SERVER_PORT_CALLBACK_NUM; i++)
    {
        if (strncasecmp(callback_name[i], name, len) != 0)
        {
            continue;
        }

        memcpy(property_name + 2, callback_name[i], len);
        l_property_name = len + 2;
        property_name[l_property_name] = '\0';
        zend_update_property(swoole_server_port_ce, getThis(), property_name, l_property_name, cb);
        property->callbacks[i] = sw_zend_read_property(swoole_server_port_ce, getThis(), property_name, l_property_name, 0);
        sw_copy_to_stack(property->callbacks[i], property->_callbacks[i]);
        if (property->caches[i])
        {
            efree(property->caches[i]);
        }
        property->caches[i] = fci_cache;

        if (i == SW_SERVER_CB_onConnect && !serv->onConnect)
        {
            serv->onConnect = php_swoole_onConnect;
        }
        else if (i == SW_SERVER_CB_onPacket && !serv->onPacket)
        {
            serv->onPacket = php_swoole_onPacket;
        }
        else if (i == SW_SERVER_CB_onClose && !serv->onClose)
        {
            serv->onClose = php_swoole_onClose;
        }
        else if (i == SW_SERVER_CB_onBufferFull && !serv->onBufferFull)
        {
            serv->onBufferFull = php_swoole_onBufferFull;
        }
        else if (i == SW_SERVER_CB_onBufferEmpty && !serv->onBufferEmpty)
        {
            serv->onBufferEmpty = php_swoole_onBufferEmpty;
        }
        else if (i == SW_SERVER_CB_onMessage || i == SW_SERVER_CB_onRequest)
        {
            serv->onReceive = php_swoole_http_onReceive;
        }
        break;
    }

    if (l_property_name == 0)
    {
        swoole_php_error(E_WARNING, "unknown event types[%s]", name);
        efree(fci_cache);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_server_port, getCallback)
{
    zval *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(name)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend::string _event_name_ori(name);
    zend::string _event_name_tolower(zend_string_tolower(_event_name_ori.get()));
    auto i = server_port_event_map.find(_event_name_tolower.to_std_string());
    if (i != server_port_event_map.end())
    {
        string property_name = "on" + i->second.name;
        zval rv, *property = zend_read_property(swoole_server_port_ce, getThis(), property_name.c_str(), property_name.length(), 1, &rv);
        if (!ZVAL_IS_NULL(property))
        {
            RETURN_ZVAL(property, 1, 0);
        }
    }
    RETURN_NULL();
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server_port, getSocket)
{
    swListenPort *port = (swListenPort *) swoole_get_object(getThis());
    php_socket *socket_object = swoole_convert_to_socket(port->sock);
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    Z_TRY_ADDREF_P(zsocket);
}
#endif
