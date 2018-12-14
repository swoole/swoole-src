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

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#endif

static zend_class_entry swoole_server_port_ce;
zend_class_entry *swoole_server_port_ce_ptr;
static zend_object_handlers swoole_server_port_handlers;

static PHP_METHOD(swoole_server_port, __construct);
static PHP_METHOD(swoole_server_port, __destruct);
static PHP_METHOD(swoole_server_port, on);
static PHP_METHOD(swoole_server_port, set);

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
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_server_port_methods[] =
{
    PHP_ME(swoole_server_port, __construct,     arginfo_swoole_void, ZEND_ACC_PRIVATE)
    PHP_ME(swoole_server_port, __destruct,      arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, set,             arginfo_swoole_server_port_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, on,              arginfo_swoole_server_port_on, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_server_port, getSocket,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

void swoole_server_port_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_server_port, "Swoole\\Server\\Port", "swoole_server_port", NULL, swoole_server_port_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_server_port, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_server_port, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_server_port, zend_class_unset_property_deny);

    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onConnect"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onReceive"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onClose"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onPacket"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onBufferFull"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onBufferEmpty"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onRequest"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onHandShake"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onMessage"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("onOpen"), ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce_ptr, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_server_port_ce_ptr, ZEND_STRL("sock"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_server_port_ce_ptr, ZEND_STRL("connections"), ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_server_port, __construct)
{
    swoole_php_fatal_error(E_ERROR, "please use the swoole_server->listen method.");
    return;
}

static PHP_METHOD(swoole_server_port, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

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

    php_swoole_array_separate(zset);
    vht = Z_ARRVAL_P(zset);

    swListenPort *port = (swListenPort *) swoole_get_object(getThis());
    swoole_server_port_property *property = (swoole_server_port_property *) swoole_get_property(getThis(), 0);

    if (port == NULL || property == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "please use the swoole_server->listen method.");
        return;
    }

    property->setting = zset;

    //backlog
    if (php_swoole_array_get_value(vht, "backlog", v))
    {
        convert_to_long(v);
        port->backlog = (int) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", v))
    {
        convert_to_long(v);
        port->socket_buffer_size = (int) Z_LVAL_P(v);
        if (port->socket_buffer_size <= 0)
        {
            port->socket_buffer_size = SW_MAX_INT;
        }
    }
    /**
     * !!! Don't set this option, for tests only.
     */
    if (php_swoole_array_get_value(vht, "kernel_socket_recv_buffer_size", v))
    {
        convert_to_long(v);
        port->kernel_socket_recv_buffer_size = (int) Z_LVAL_P(v);
        if (port->kernel_socket_recv_buffer_size <= 0)
        {
            port->kernel_socket_recv_buffer_size = SW_MAX_INT;
        }
    }
    /**
     * !!! Don't set this option, for tests only.
     */
    if (php_swoole_array_get_value(vht, "kernel_socket_send_buffer_size", v))
    {
        convert_to_long(v);
        port->kernel_socket_send_buffer_size = (int) Z_LVAL_P(v);
        if (port->kernel_socket_send_buffer_size <= 0)
        {
            port->kernel_socket_send_buffer_size = SW_MAX_INT;
        }
    }
    if (php_swoole_array_get_value(vht, "buffer_high_watermark", v))
    {
        convert_to_long(v);
        port->buffer_high_watermark = (int) Z_LVAL_P(v);
    }
    if (php_swoole_array_get_value(vht, "buffer_low_watermark", v))
    {
        convert_to_long(v);
        port->buffer_low_watermark = (int) Z_LVAL_P(v);
    }
    //server: tcp_nodelay
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", v))
    {
        convert_to_boolean(v);
        port->open_tcp_nodelay = Z_BVAL_P(v);
    }
    else
    {
        port->open_tcp_nodelay = 1;
    }
    //tcp_defer_accept
    if (php_swoole_array_get_value(vht, "tcp_defer_accept", v))
    {
        convert_to_long(v);
        port->tcp_defer_accept = (uint8_t) Z_LVAL_P(v);
    }
    //tcp_keepalive
    if (php_swoole_array_get_value(vht, "open_tcp_keepalive", v))
    {
        convert_to_boolean(v);
        port->open_tcp_keepalive = Z_BVAL_P(v);
    }
    //buffer: eof check
    if (php_swoole_array_get_value(vht, "open_eof_check", v))
    {
        convert_to_boolean(v);
        port->open_eof_check = Z_BVAL_P(v);
    }
    //buffer: split package with eof
    if (php_swoole_array_get_value(vht, "open_eof_split", v))
    {
        convert_to_boolean(v);
        port->protocol.split_by_eof = Z_BVAL_P(v);
        if (port->protocol.split_by_eof)
        {
            port->open_eof_check = 1;
        }
    }
    //package eof
    if (php_swoole_array_get_value(vht, "package_eof", v))
    {
        convert_to_string(v);
        port->protocol.package_eof_len = Z_STRLEN_P(v);
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
        memcpy(port->protocol.package_eof, Z_STRVAL_P(v), Z_STRLEN_P(v));
    }
    //http_protocol
    if (php_swoole_array_get_value(vht, "open_http_protocol", v))
    {
        convert_to_boolean(v);
        port->open_http_protocol = Z_BVAL_P(v);
    }
    //websocket protocol
    if (php_swoole_array_get_value(vht, "open_websocket_protocol", v))
    {
        convert_to_boolean(v);
        port->open_websocket_protocol = Z_BVAL_P(v);
        if (port->open_websocket_protocol)
        {
            port->open_http_protocol = 1;
            port->open_http2_protocol = 0;
        }
    }
    if (php_swoole_array_get_value(vht, "websocket_subprotocol", v))
    {
        convert_to_string(v);
        if (port->websocket_subprotocol)
        {
            sw_free(port->websocket_subprotocol);
        }
        port->websocket_subprotocol = sw_strdup(Z_STRVAL_P(v));
        port->websocket_subprotocol_length = Z_STRLEN_P(v);
    }
    if (php_swoole_array_get_value(vht, "open_websocket_close_frame", v))
    {
        convert_to_boolean(v);
        port->open_websocket_close_frame = Z_BVAL_P(v);
    }
#ifdef SW_USE_HTTP2
    //http2 protocol
    if (php_swoole_array_get_value(vht, "open_http2_protocol", v))
    {
        convert_to_boolean(v);
        port->open_http2_protocol = Z_BVAL_P(v);
    }
#endif
    //buffer: mqtt protocol
    if (php_swoole_array_get_value(vht, "open_mqtt_protocol", v))
    {
        convert_to_boolean(v);
        port->open_mqtt_protocol = Z_BVAL_P(v);
    }
    //redis protocol
    if (php_swoole_array_get_value(vht, "open_redis_protocol", v))
    {
        convert_to_boolean(v);
        port->open_redis_protocol = Z_BVAL_P(v);
    }
    //tcp_keepidle
    if (php_swoole_array_get_value(vht, "tcp_keepidle", v))
    {
        convert_to_long(v);
        port->tcp_keepidle = (uint16_t) Z_LVAL_P(v);
    }
    //tcp_keepinterval
    if (php_swoole_array_get_value(vht, "tcp_keepinterval", v))
    {
        convert_to_long(v);
        port->tcp_keepinterval = (uint16_t) Z_LVAL_P(v);
    }
    //tcp_keepcount
    if ((v = zend_hash_str_find(vht, ZEND_STRL("tcp_keepcount"))))
    {
        convert_to_long(v);
        port->tcp_keepcount = (uint16_t) Z_LVAL_P(v);
    }
    //tcp_fastopen
    if ((v = zend_hash_str_find(vht, ZEND_STRL("tcp_fastopen"))))
    {
        convert_to_boolean(v);
        port->tcp_fastopen = Z_BVAL_P(v);
    }
    //open length check
    if (php_swoole_array_get_value(vht, "open_length_check", v))
    {
        convert_to_boolean(v);
        port->open_length_check = Z_BVAL_P(v);
    }
    //package length size
    if (php_swoole_array_get_value(vht, "package_length_type", v))
    {
        convert_to_string(v);
        port->protocol.package_length_type = Z_STRVAL_P(v)[0];
        port->protocol.package_length_size = swoole_type_size(port->protocol.package_length_type);
        if (port->protocol.package_length_size == 0)
        {
            swoole_php_fatal_error(E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
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
            Z_TRY_ADDREF_P(v);
            port->protocol.private_data = sw_zval_dup(v);
            break;
        }

        port->protocol.package_length_size = 0;
        port->protocol.package_length_type = '\0';
        port->protocol.package_length_offset = SW_BUFFER_SIZE;
    }
    //package length offset
    if (php_swoole_array_get_value(vht, "package_length_offset", v))
    {
        convert_to_long(v);
        port->protocol.package_length_offset = (int) Z_LVAL_P(v);
        if (port->protocol.package_length_offset > SW_BUFFER_SIZE)
        {
            swoole_php_fatal_error(E_ERROR, "'package_length_offset' value is too large.");
        }
    }
    //package body start
    if (php_swoole_array_get_value(vht, "package_body_offset", v) || php_swoole_array_get_value(vht, "package_body_start", v))
    {
        convert_to_long(v);
        port->protocol.package_body_offset = (int) Z_LVAL_P(v);
        if (port->protocol.package_body_offset > SW_BUFFER_SIZE)
        {
            swoole_php_fatal_error(E_ERROR, "'package_body_offset' value is too large.");
        }
    }
    /**
     * package max length
     */
    if (php_swoole_array_get_value(vht, "package_max_length", v))
    {
        convert_to_long(v);
        port->protocol.package_max_length = (int) Z_LVAL_P(v);
    }

#ifdef SW_USE_OPENSSL
    if (port->ssl)
    {
        if (php_swoole_array_get_value(vht, "ssl_cert_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", Z_STRVAL_P(v));
                return;
            }
            if (port->ssl_option.cert_file)
            {
                sw_free(port->ssl_option.cert_file);
            }
            port->ssl_option.cert_file = sw_strdup(Z_STRVAL_P(v));
            port->open_ssl_encrypt = 1;
        }
        if (php_swoole_array_get_value(vht, "ssl_key_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", Z_STRVAL_P(v));
                return;
            }
            if (port->ssl_option.key_file)
            {
                sw_free(port->ssl_option.key_file);
            }
            port->ssl_option.key_file = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_method", v))
        {
            convert_to_long(v);
            port->ssl_option.method = (int) Z_LVAL_P(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_peer", v))
        {
            convert_to_boolean(v);
            port->ssl_option.verify_peer = Z_BVAL_P(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_allow_self_signed", v))
        {
            convert_to_boolean(v);
            port->ssl_option.allow_self_signed = Z_BVAL_P(v);
        }
        //verify client cert
        if (php_swoole_array_get_value(vht, "ssl_client_cert_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl_client_cert_file[%s] not found.", Z_STRVAL_P(v));
                return;
            }
            if (port->ssl_option.client_cert_file)
            {
                sw_free(port->ssl_option.client_cert_file);
            }
            port->ssl_option.client_cert_file = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_depth", v))
        {
            convert_to_long(v);
            port->ssl_option.verify_depth = (int) Z_LVAL_P(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_prefer_server_ciphers", v))
        {
            convert_to_boolean(v);
            port->ssl_config.prefer_server_ciphers = Z_BVAL_P(v);
        }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_session_tickets"))))
        //    {
        //        convert_to_boolean(v);
        //        port->ssl_config.session_tickets = Z_BVAL_P(v);
        //    }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_stapling"))))
        //    {
        //        convert_to_boolean(v);
        //        port->ssl_config.stapling = Z_BVAL_P(v);
        //    }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_stapling_verify"))))
        //    {
        //        convert_to_boolean(v);
        //        port->ssl_config.stapling_verify = Z_BVAL_P(v);
        //    }
        if (php_swoole_array_get_value(vht, "ssl_ciphers", v))
        {
            convert_to_string(v);
            if (port->ssl_config.ciphers)
            {
                sw_free(port->ssl_config.ciphers);
            }
            port->ssl_config.ciphers = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_ecdh_curve", v))
        {
            convert_to_string(v);
            if (port->ssl_config.ecdh_curve)
            {
                sw_free(port->ssl_config.ecdh_curve);
            }
            port->ssl_config.ecdh_curve = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_dhparam", v))
        {
            convert_to_string(v);
            if (port->ssl_config.dhparam)
            {
                sw_free(port->ssl_config.dhparam);
            }
            port->ssl_config.dhparam = sw_strdup(Z_STRVAL_P(v));
        }
        //    if ((v = zend_hash_str_find(vht, ZEND_STRL("ssl_session_cache"))))
        //    {
        //        convert_to_string(v);
        //        port->ssl_config.session_cache = strdup(Z_STRVAL_P(v));
        //    }
        if (swPort_enable_ssl_encrypt(port) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "swPort_enable_ssl_encrypt() failed.");
            RETURN_FALSE;
        }
    }
#endif

    zval *zsetting = sw_zend_read_property_array(swoole_server_port_ce_ptr, getThis(), ZEND_STRL("setting"), 1);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    zval_ptr_dtor(zset);
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
        swoole_php_fatal_error(E_WARNING, "can't register event callback function after server started.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &name, &len, &cb) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name = NULL;
    zend_fcall_info_cache *func_cache = (zend_fcall_info_cache *) emalloc(sizeof(zend_fcall_info_cache));
    if (!sw_zend_is_callable_ex(cb, NULL, 0, &func_name, NULL, func_cache, NULL))
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
        zend_update_property(swoole_server_port_ce_ptr, getThis(), property_name, l_property_name, cb);
        property->callbacks[i] = sw_zend_read_property(swoole_server_port_ce_ptr, getThis(), property_name, l_property_name, 0);
        sw_copy_to_stack(property->callbacks[i], property->_callbacks[i]);

        if (i == SW_SERVER_CB_onConnect && serv->onConnect == NULL)
        {
            serv->onConnect = php_swoole_onConnect;
        }
        else if (i == SW_SERVER_CB_onPacket && serv->onPacket == NULL)
        {
            serv->onPacket = php_swoole_onPacket;
        }
        else if (i == SW_SERVER_CB_onClose && serv->onClose == NULL)
        {
            serv->onClose = php_swoole_onClose;
        }
        else if (i == SW_SERVER_CB_onBufferFull && serv->onBufferFull == NULL)
        {
            serv->onBufferFull = php_swoole_onBufferFull;
        }
        else if (i == SW_SERVER_CB_onBufferEmpty && serv->onBufferEmpty == NULL)
        {
            serv->onBufferEmpty = php_swoole_onBufferEmpty;
        }
        else if (i == SW_SERVER_CB_onMessage || i == SW_SERVER_CB_onRequest)
        {
            serv->onReceive = php_swoole_http_onReceive;
        }
        property->caches[i] = func_cache;
        break;
    }

    if (l_property_name == 0)
    {
        swoole_php_error(E_WARNING, "unknown event types[%s]", name);
        efree(func_cache);
        RETURN_FALSE;
    }
    RETURN_TRUE;
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
