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
#include "module.h"

zend_class_entry swoole_server_port_ce;
zend_class_entry *swoole_server_port_class_entry_ptr;

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
    PHP_ME(swoole_server_port, __construct,     arginfo_swoole_void, ZEND_ACC_PRIVATE | ZEND_ACC_CTOR)
    PHP_ME(swoole_server_port, __destruct,      arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_server_port, set,             arginfo_swoole_server_port_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, on,              arginfo_swoole_server_port_on, ZEND_ACC_PUBLIC)
#ifdef SWOOLE_SOCKETS_SUPPORT
    PHP_ME(swoole_server_port, getSocket,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
#endif
    PHP_FE_END
};

void swoole_server_port_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_server_port_ce, "swoole_server_port", "Swoole\\Server\\Port", swoole_server_port_methods);
    swoole_server_port_class_entry_ptr = zend_register_internal_class(&swoole_server_port_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_server_port, "Swoole\\Server\\Port");
}

static PHP_METHOD(swoole_server_port, __construct)
{
    swoole_php_fatal_error(E_ERROR, "Please use the swoole_server->listen method.");
    return;
}

static PHP_METHOD(swoole_server_port, __destruct)
{
    swoole_server_port_property *property = swoole_get_property(getThis(), 0);
    efree(property);
    swoole_set_property(getThis(), 0, NULL);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_server_port, set)
{
    zval *zset = NULL;
    HashTable *vht;
    zval *v;

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }

    php_swoole_array_separate(zset);

    vht = Z_ARRVAL_P(zset);
    swListenPort *port = swoole_get_object(getThis());
    swoole_server_port_property *property = swoole_get_property(getThis(), 0);

    if (port == NULL || property == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Please use the swoole_server->listen method.");
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
        if (port->socket_buffer_size <= 0 || port->socket_buffer_size > SW_MAX_INT)
        {
            port->socket_buffer_size = SW_MAX_INT;
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
    //tcp_nodelay
    if (php_swoole_array_get_value(vht, "open_tcp_nodelay", v))
    {
        convert_to_boolean(v);
        port->open_tcp_nodelay = Z_BVAL_P(v);
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
        if (port->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
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
    }
    if (php_swoole_array_get_value(vht, "websocket_subprotocol", v))
    {
        convert_to_string(v);
        port->websocket_subprotocol = strdup(Z_STRVAL_P(v));
        port->websocket_subprotocol_length = Z_STRLEN_P(v);
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
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepcount"), (void **) &v) == SUCCESS)
    {
        convert_to_long(v);
        port->tcp_keepcount = (uint16_t) Z_LVAL_P(v);
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
                swProtocol_length_function func = swModule_get_global_function(Z_STRVAL_P(v), Z_STRLEN_P(v));
                if (func != NULL)
                {
                    port->protocol.get_package_length = func;
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
            port->protocol.get_package_length = php_swoole_length_func;
            sw_zval_add_ref(&v);
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
            port->ssl_cert_file = strdup(Z_STRVAL_P(v));
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
            port->ssl_key_file = strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_method", v))
        {
            convert_to_long(v);
            port->ssl_method = (int) Z_LVAL_P(v);
        }
        //verify client cert
        if (php_swoole_array_get_value(vht, "ssl_client_cert_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", port->ssl_cert_file);
                return;
            }
            port->ssl_client_cert_file = strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_depth", v))
        {
            convert_to_long(v);
            port->ssl_verify_depth = (int) Z_LVAL_P(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_prefer_server_ciphers", v))
        {
            convert_to_boolean(v);
            port->ssl_config.prefer_server_ciphers = Z_BVAL_P(v);
        }
        //    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_session_tickets"), (void **) &v) == SUCCESS)
        //    {
        //        convert_to_boolean(v);
        //        port->ssl_config.session_tickets = Z_BVAL_P(v);
        //    }
        //    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_stapling"), (void **) &v) == SUCCESS)
        //    {
        //        convert_to_boolean(v);
        //        port->ssl_config.stapling = Z_BVAL_P(v);
        //    }
        //    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_stapling_verify"), (void **) &v) == SUCCESS)
        //    {
        //        convert_to_boolean(v);
        //        port->ssl_config.stapling_verify = Z_BVAL_P(v);
        //    }
        if (php_swoole_array_get_value(vht, "ssl_ciphers", v))
        {
            convert_to_string(v);
            port->ssl_config.ciphers = strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_ecdh_curve", v))
        {
            convert_to_string(v);
            port->ssl_config.ecdh_curve = strdup(Z_STRVAL_P(v));
        }
        //    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_session_cache"), (void **) &v) == SUCCESS)
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

    zend_update_property(swoole_server_port_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
}

static PHP_METHOD(swoole_server_port, on)
{
    char *name = NULL;
    zend_size_t len, i;
    zval *cb;

    if (SwooleGS->start > 0)
    {
        swoole_php_fatal_error(E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sz", &name, &len, &cb) == FAILURE)
    {
        return;
    }

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (!sw_zend_is_callable(cb, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);
#endif

    swoole_server_port_property *property = swoole_get_property(getThis(), 0);

    swListenPort *port = swoole_get_object(getThis());
    if (!port->ptr)
    {
        port->ptr = property;
    }

    char *callback_name[PHP_SERVER_CALLBACK_NUM] = {
        "Connect",
        "Receive",
        "Close",
        "Packet",
        "Start",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
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

    for (i = 0; i < PHP_SERVER_CALLBACK_NUM; i++)
    {
        if (callback_name[i] == NULL)
        {
            continue;
        }
        if (strncasecmp(callback_name[i], name, len) == 0)
        {
            memcpy(property_name + 2, callback_name[i], len);
            l_property_name = len + 2;
            property_name[l_property_name] = '\0';
            zend_update_property(swoole_server_port_class_entry_ptr, getThis(), property_name, l_property_name, cb TSRMLS_CC);
            property->callbacks[i] = sw_zend_read_property(swoole_server_port_class_entry_ptr, getThis(), property_name, l_property_name, 0 TSRMLS_CC);
            sw_copy_to_stack(property->callbacks[i], property->_callbacks[i]);

            if (i == SW_SERVER_CB_onConnect && SwooleG.serv->onConnect == NULL)
            {
                SwooleG.serv->onConnect = php_swoole_onConnect;
            }
            else if (i == SW_SERVER_CB_onClose && SwooleG.serv->onClose == NULL)
            {
                SwooleG.serv->onClose = php_swoole_onClose;
            }
            else if (i == SW_SERVER_CB_onBufferFull && SwooleG.serv->onBufferFull == NULL)
            {
                SwooleG.serv->onBufferFull = php_swoole_onBufferFull;
            }
            else if (i == SW_SERVER_CB_onBufferEmpty && SwooleG.serv->onBufferEmpty == NULL)
            {
                SwooleG.serv->onBufferEmpty = php_swoole_onBufferEmpty;
            }
            break;
        }
    }

    if (l_property_name == 0)
    {
        swoole_php_error(E_WARNING, "Unknown event types[%s]", name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
static PHP_METHOD(swoole_server_port, getSocket)
{
    swListenPort *port = swoole_get_object(getThis());
    php_socket *socket_object = swoole_convert_to_socket(port->sock);
    if (!socket_object)
    {
        RETURN_FALSE;
    }
    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    sw_zval_add_ref(&zsocket);
}
#endif
