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
 | Author: Fang  <coooold@live.com>                                     |
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 | Author: Yuanyi   Zhi  <syyuanyizhi@163.com>                          |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"

#ifdef SW_COROUTINE
#include "swoole_http_client.h"
#include "swoole_coroutine.h"
#include "socket.h"

using namespace swoole;

typedef struct
{
    Socket *socket;
    bool ssl;
    bool wait;
    zend_bool defer;
    zend_bool keep_alive;

} http_client_coro_property;

extern swString *http_client_buffer;

extern void php_swoole_client_coro_check_setting(Socket *cli, zval *zset);
extern bool php_swoole_client_coro_socket_free(Socket *cli);

static int http_client_coro_send_request(zval *zobject, http_client_coro_property *hcc, http_client *client);
static int http_client_coro_recv_response(zval *zobject, http_client_coro_property *hcc, http_client *client);
static int http_client_coro_execute(zval *zobject, http_client_coro_property *hcc, char *uri, size_t uri_len);

/**
 * it's a safe function for any calling
 * @return whether close an established connection successfully
 */
static int http_client_coro_close(zval *zobject)
{
    zend_update_property_bool(Z_OBJCE_P(zobject), zobject, ZEND_STRL("connected"), 0);

    bool ret1 = false, ret2 = false;
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(zobject, 0);
    if (hcc->socket)
    {
        sw_coro_check_bind("http client", hcc->socket->has_bound(swoole::SOCKET_LOCK_RW));
        ret1 = php_swoole_client_coro_socket_free(hcc->socket);
        hcc->socket = nullptr;
        ret2 = http_client_free(zobject);
    }

    return (ret1 && ret2) ? SW_OK : SW_ERR;
}

static const swoole_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_client_parser_on_header_field,
    http_client_parser_on_header_value,
    http_client_parser_on_headers_complete,
    http_client_parser_on_body,
    http_client_parser_on_message_complete
};

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setMethod, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setHeaders, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, headers, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setCookies, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cookies, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setData, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setDefer, 0, 0, 0)
    ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_addFile, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_addData, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_execute, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_get, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_post, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_download, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, file)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_upgrade, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

zend_class_entry swoole_http_client_coro_ce;
zend_class_entry *swoole_http_client_coro_class_entry_ptr;
static zend_object_handlers swoole_http_client_coro_handlers;

extern zend_class_entry *swoole_websocket_frame_class_entry_ptr;

static PHP_METHOD(swoole_http_client_coro, __construct);
static PHP_METHOD(swoole_http_client_coro, __destruct);
static PHP_METHOD(swoole_http_client_coro, set);
static PHP_METHOD(swoole_http_client_coro, setMethod);
static PHP_METHOD(swoole_http_client_coro, setHeaders);
static PHP_METHOD(swoole_http_client_coro, setCookies);
static PHP_METHOD(swoole_http_client_coro, setData);
static PHP_METHOD(swoole_http_client_coro, addFile);
static PHP_METHOD(swoole_http_client_coro, addData);
static PHP_METHOD(swoole_http_client_coro, execute);
static PHP_METHOD(swoole_http_client_coro, isConnected);
static PHP_METHOD(swoole_http_client_coro, close);
static PHP_METHOD(swoole_http_client_coro, get);
static PHP_METHOD(swoole_http_client_coro, post);
static PHP_METHOD(swoole_http_client_coro, download);
static PHP_METHOD(swoole_http_client_coro, upgrade);
static PHP_METHOD(swoole_http_client_coro, push);
static PHP_METHOD(swoole_http_client_coro, setDefer);
static PHP_METHOD(swoole_http_client_coro, getDefer);
static PHP_METHOD(swoole_http_client_coro, recv);

static const zend_function_entry swoole_http_client_coro_methods[] =
{
    PHP_ME(swoole_http_client_coro, __construct, arginfo_swoole_http_client_coro_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, set, arginfo_swoole_http_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setMethod, arginfo_swoole_http_client_coro_setMethod, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setHeaders, arginfo_swoole_http_client_coro_setHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setCookies, arginfo_swoole_http_client_coro_setCookies, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setData, arginfo_swoole_http_client_coro_setData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, execute, arginfo_swoole_http_client_coro_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, get, arginfo_swoole_http_client_coro_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, post, arginfo_swoole_http_client_coro_post, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, download, arginfo_swoole_http_client_coro_download, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, upgrade, arginfo_swoole_http_client_coro_upgrade, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, addFile, arginfo_swoole_http_client_coro_addFile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, addData, arginfo_swoole_http_client_coro_addData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, isConnected, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setDefer, arginfo_swoole_http_client_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, recv, arginfo_swoole_http_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, push, arginfo_swoole_http_client_coro_push, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int http_client_coro_execute(zval *zobject, http_client_coro_property *hcc, char *uri, size_t uri_len)
{
    if (uri_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "path is empty.");
        return SW_ERR;
    }

    // when new request, clear all properties about the last response
    http_client_clear_response_properties(zobject);

    http_client *http = (http_client *) swoole_get_object(zobject);
    if (!http)
    {
        http = http_client_create(zobject);
    }

    if (!hcc->socket)
    {
        hcc->socket = new Socket(SW_SOCK_TCP);
        zval *ztmp;
        HashTable *vht;
        zval *zset = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("setting"), 1);
        if (zset && ZVAL_IS_ARRAY(zset))
        {
            vht = Z_ARRVAL_P(zset);
            /**
             * timeout
             */
            if (php_swoole_array_get_value(vht, "timeout", ztmp))
            {
                convert_to_double(ztmp);
                http->timeout = (double) Z_DVAL_P(ztmp);
                hcc->socket->setTimeout(http->timeout);
            }
            /**
             * keep_alive
             */
            if (php_swoole_array_get_value(vht, "keep_alive", ztmp))
            {
                convert_to_boolean(ztmp);
                http->keep_alive = Z_BVAL_P(ztmp);
            }
            if (hcc->socket->http_proxy)
            {
                zval *zrequest_headers = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("requestHeaders"), 1);
                if (zrequest_headers == NULL || Z_TYPE_P(zrequest_headers) != IS_ARRAY)
                {
                    swoole_php_fatal_error (E_WARNING, "http proxy must set Host");
                    return SW_ERR;
                }
                zval *value;
                if (!(value = zend_hash_str_find(Z_ARRVAL_P(zrequest_headers), ZEND_STRL("Host"))))
                {
                    swoole_php_fatal_error (E_WARNING, "http proxy must set Host");
                    return SW_ERR;
                }
                if (hcc->socket->http_proxy->password)
                {
                    char _buf1[128];
                    char _buf2[256];
                    int _n1 = snprintf(_buf1, sizeof(_buf1), "%*s:%*s", http->cli->http_proxy->l_user,
                            http->cli->http_proxy->user, http->cli->http_proxy->l_password,
                            http->cli->http_proxy->password);
                    zend_string *str = php_base64_encode((const unsigned char *) _buf1, _n1);
                    int _n2 = snprintf(_buf2, sizeof(_buf2), "Basic %*s", (int)str->len, str->val);
                    zend_string_free(str);
                    add_assoc_stringl_ex(zrequest_headers, ZEND_STRL("Proxy-Authorization"), _buf2, _n2);
                }
            }
            php_swoole_client_coro_check_setting(hcc->socket, zset);
        }

        if (!hcc->socket->connect(std::string(http->host, http->host_len), http->port))
        {
            zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("errCode"), hcc->socket->errCode);
            zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_TIMEOUT);
            return SW_ERR;
        }
        else
        {
            zend_update_property_bool(Z_OBJCE_P(zobject), zobject, ZEND_STRL("connected"), 1);
        }
#ifdef SW_USE_OPENSSL
        if (hcc->ssl && !hcc->socket->ssl_handshake())
        {
            return SW_ERR;
        }
#endif
        swTraceLog(SW_TRACE_HTTP_CLIENT, "connect to server, object handle=%d, fd=%d", Z_OBJ_HANDLE_P(zobject), hcc->socket->socket->fd);
    }

    // prepare before send a request
    if (http->body == NULL)
    {
        http->body = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
        if (http->body == NULL)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            return SW_ERR;
        }
    }
    else
    {
        swString_clear(http->body);
    }

    if (http->uri)
    {
        efree(http->uri);
    }
    http->uri = estrdup(uri);
    http->uri_len = uri_len;

    int ret = http_client_coro_send_request(zobject, hcc, http);
    // clear request data (backward compatible)
    zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
    zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("uploadFiles"));
    zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("downloadFile"));
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("downloadOffset"), 0);
    if (ret < 0)
    {
        return SW_ERR;
    }
    if (hcc->defer)
    {
        return SW_OK;
    }
    else
    {
        return http_client_coro_recv_response(zobject, hcc, http);
    }
}

static void swoole_http_client_coro_free_storage(zend_object *object)
{
    zval _zobject, *zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    http_client_coro_close(zobject);
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(zobject, 0);
    efree(hcc);
    swoole_set_property(zobject, 0, NULL);

    // dtor object
    zend_object_std_dtor(object);
}

static zend_object *swoole_http_client_coro_create(zend_class_entry *ce)
{
    zend_object *object;
    object = zend_objects_new(ce);
    object->handlers = &swoole_http_client_coro_handlers;
    object_properties_init(object, ce);

    zval _zobject, *zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    http_client_coro_property *hcc = (http_client_coro_property*) emalloc(sizeof(http_client_coro_property));
    bzero(hcc, sizeof(http_client_coro_property));
    swoole_set_property(zobject, 0, hcc);

    php_swoole_check_reactor();

    return object;
}

void swoole_http_client_coro_init(int module_number)
{
    INIT_CLASS_ENTRY(swoole_http_client_coro_ce, "Swoole\\Coroutine\\Http\\Client", swoole_http_client_coro_methods);
    swoole_http_client_coro_class_entry_ptr = zend_register_internal_class(&swoole_http_client_coro_ce);
    swoole_http_client_coro_class_entry_ptr->create_object = swoole_http_client_coro_create;
    swoole_http_client_coro_class_entry_ptr->serialize = zend_class_serialize_deny;
    swoole_http_client_coro_class_entry_ptr->unserialize = zend_class_unserialize_deny;
    memcpy(&swoole_http_client_coro_handlers, zend_get_std_object_handlers(), sizeof(swoole_http_client_coro_handlers));
    swoole_http_client_coro_handlers.free_obj = swoole_http_client_coro_free_storage;

    if (SWOOLE_G(use_shortname))
    {
        sw_zend_register_class_alias("Co\\Http\\Client", swoole_http_client_coro_class_entry_ptr);
    }

    // client status
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    // client info
    zend_declare_property_string(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("host"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);

    // request properties
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("requestMethod"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("requestHeaders"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("requestBody"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("uploadFiles"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("downloadFile"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("downloadOffset"), 0, ZEND_ACC_PUBLIC);

    // response properties
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("body"), "", ZEND_ACC_PUBLIC);
}

static int http_client_coro_recv_response(zval *zobject, http_client_coro_property *hcc, http_client *http)
{
    long parsed_n = 0;
    swString *buffer;
    ssize_t total_bytes = 0, retval = 0;

    sw_coro_check_bind("http client", hcc->socket->has_bound(swoole::SOCKET_LOCK_READ));

    buffer = hcc->socket->get_buffer();
    while (http->completed == 0)
    {
        retval = hcc->socket->recv(buffer->str, buffer->size);
        if (retval > 0)
        {
            total_bytes += retval;
            parsed_n = swoole_http_parser_execute(&http->parser, &http_parser_settings, buffer->str, retval);
            swTraceLog(SW_TRACE_HTTP_CLIENT, "parsed_n=%ld, retval=%ld, total_bytes=%ld, completed=%d.", parsed_n, retval, total_bytes, http->completed);
            if (parsed_n >= 0)
            {
                continue;
            }
        }
        else if (retval == 0 && http->state == HTTP_CLIENT_STATE_WAIT_CLOSE)
        {
            http_client_parser_on_message_complete(&http->parser);
            break;
        }
        hcc->wait = false;
        zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("errCode"), hcc->socket->errCode);
        if (hcc->socket->errCode == ETIMEDOUT)
        {
            zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
        }
        else
        {
            zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        }
        http_client_coro_close(zobject);
        return SW_ERR;
    }
    /**
     * TODO: Sec-WebSocket-Accept check
     */
    if (http->upgrade)
    {
        http->state = HTTP_CLIENT_STATE_UPGRADE;
        hcc->socket->open_length_check = 1;
        hcc->socket->protocol.get_package_length = swWebSocket_get_package_length;
        hcc->socket->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        /**
         * websocket message queue
         */
        if (retval > parsed_n + 3)
        {
            buffer->length = retval - parsed_n - 1;
            memmove(buffer->str, buffer->str + parsed_n + 1, buffer->length);
        }
    }
    if (http->keep_alive == 0 && http->state != HTTP_CLIENT_STATE_WAIT_CLOSE && !http->upgrade)
    {
        http_client_coro_close(zobject);
    }
    else
    {
        http_client_reset(http);
        http_client_clear(http);
    }
    hcc->wait = false;
    return SW_OK;
}

static int http_client_coro_send_request(zval *zobject, http_client_coro_property *hcc, http_client *http)
{
    zval *value = NULL;
    char *method;
    uint32_t header_flag = 0x0;
    zval *zmethod, *zheaders, *zbody, *zupload_files, *zcookies, *z_download_file;

    //clear errno
    SwooleG.error = 0;
    //clear buffer
    swString_clear(http_client_buffer);
    // check coro bind
    sw_coro_check_bind("http client", hcc->socket->has_bound(swoole::SOCKET_LOCK_WRITE));

    zmethod = sw_zend_read_property_not_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestMethod"), 1);
    zheaders = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestHeaders"), 1);
    zbody = sw_zend_read_property_not_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestBody"), 1);
    zupload_files = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("uploadFiles"), 1);
    zcookies = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("cookies"), 1);
    z_download_file = sw_zend_read_property_not_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("downloadFile"), 1);

    // ============ download ============
    if (z_download_file)
    {
        convert_to_string(z_download_file);
        char *download_file_name = Z_STRVAL_P(z_download_file);
        zval *z_download_offset = sw_zend_read_property_not_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("downloadOffset"), 1);
        off_t download_offset = 0;
        if (z_download_offset)
        {
            download_offset = (off_t) Z_LVAL_P(z_download_offset);
        }

        int fd = open(download_file_name, O_CREAT | O_WRONLY, 0664);
        if (fd < 0)
        {
            swSysError("open(%s, O_CREAT | O_WRONLY) failed.", download_file_name);
            return SW_ERR;
        }
        if (download_offset == 0)
        {
            if (ftruncate(fd, 0) < 0)
            {
                swSysError("ftruncate(%s) failed.", download_file_name);
                close(fd);
                return SW_ERR;
            }
        }
        else
        {
            if (lseek(fd, download_offset, SEEK_SET) < 0)
            {
                swSysError("fseek(%s, %jd) failed.", download_file_name, (intmax_t) download_offset);
                close(fd);
                return SW_ERR;
            }
        }
        http->download = 1;
        http->file_fd = fd;
    }

    // ============ method ============
    if (zmethod)
    {
        convert_to_string(zmethod);
        method = Z_STRVAL_P(zmethod);
    }
    else
    {
        method = (char *) (zbody ? "POST" : "GET");
    }
    http->method = swHttp_get_method(method, strlen(method) + 1);
    swString_append_ptr(http_client_buffer, method, strlen(method));
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));

    // ============ proxy ============
#ifdef SW_USE_OPENSSL
    if (hcc->socket->http_proxy && !hcc->socket->open_ssl)
#else
    if (hcc->socket->http_proxy)
#endif
    {
        char *host = http->host;
        size_t host_len = http->host_len;
        if (zheaders && Z_TYPE_P(zheaders) == IS_ARRAY)
        {
            if ((value = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("Host"))))
            {
                host = Z_STRVAL_P(value);
                host_len = Z_STRLEN_P(value);
            }
        }
        const char *pre = "http://";
        size_t proxy_uri_len = http->uri_len + host_len + strlen(pre) + 10;
        char *proxy_uri = (char*) emalloc(http->uri_len + host_len + strlen(pre) + 10);
        http->uri_len = snprintf(proxy_uri, proxy_uri_len, "%s%s:%ld%s", pre, host, http->port, http->uri);
        efree(http->uri);
        http->uri = proxy_uri;
    }

    // ============ uri ============
    swString_append_ptr(http_client_buffer, http->uri, http->uri_len);
    swString_append_ptr(http_client_buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    // ============ headers ============
    char *key;
    uint32_t keylen;
    int keytype;

    if (zheaders && Z_TYPE_P(zheaders) == IS_ARRAY)
    {
        // As much as possible to ensure that Host is the first header.
        // See: http://tools.ietf.org/html/rfc7230#section-5.4
        if ((value = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("Host"))))
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), Z_STRVAL_P(value), Z_STRLEN_P(value));
        }
        else
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
        }

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheaders), key, keylen, keytype, value)
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            if ((Z_STRLEN_P(value) == 0) || (strncasecmp(key, ZEND_STRL("Host")) == 0))
            {
                continue;
            }
            if (strncasecmp(key, ZEND_STRL("Content-Length")) == 0)
            {
                header_flag |= HTTP_HEADER_CONTENT_LENGTH;
                //ignore custom Content-Length value
                continue;
            }
            else if (strncasecmp(key, ZEND_STRL("Connection")) == 0)
            {
                header_flag |= HTTP_HEADER_CONNECTION;
            }
            else if (strncasecmp(key, ZEND_STRL("Accept-Encoding")) == 0)
            {
                header_flag |= HTTP_HEADER_ACCEPT_ENCODING;
            }
            http_client_swString_append_headers(http_client_buffer, key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
        SW_HASHTABLE_FOREACH_END();
    }
    else
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
    }
    if (!(header_flag & HTTP_HEADER_CONNECTION))
    {
        if (http->keep_alive)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        }
        else
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
        }
    }
#ifdef SW_HAVE_ZLIB
    if (!(header_flag & HTTP_HEADER_ACCEPT_ENCODING))
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
    }
#endif

    // ============ cookies ============
    if (zcookies && Z_TYPE_P(zcookies) == IS_ARRAY)
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("Cookie: "));
        int n_cookie = Z_ARRVAL_P(zcookies)->nNumOfElements;
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zcookies), key, keylen, keytype, value)
            i++;
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            if (Z_STRLEN_P(value) == 0)
            {
                continue;
            }
            swString_append_ptr(http_client_buffer, key, keylen);
            swString_append_ptr(http_client_buffer, "=", 1);

            int encoded_value_len;
            encoded_value = sw_php_url_encode(Z_STRVAL_P(value), Z_STRLEN_P(value), &encoded_value_len);
            if (encoded_value)
            {
                swString_append_ptr(http_client_buffer, encoded_value, encoded_value_len);
                efree(encoded_value);
            }
            if (i < n_cookie)
            {
                swString_append_ptr(http_client_buffer, "; ", 2);
            }
        SW_HASHTABLE_FOREACH_END();
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    // ============ multipart/form-data ============
    if (zupload_files && Z_TYPE_P(zupload_files) == IS_ARRAY)
    {
        char header_buf[2048];
        char boundary_str[39];
        int n;

        // ============ content-type ============
        memcpy(boundary_str, SW_HTTP_CLIENT_BOUNDARY_PREKEY, sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1);
        swoole_random_string(
            boundary_str + sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1,
            sizeof(boundary_str) - sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY)
        );
        n = snprintf(
            header_buf,
            sizeof(header_buf), "Content-Type: multipart/form-data; boundary=%*s\r\n",
            (int)(sizeof(boundary_str) - 1), boundary_str
        );
        swString_append_ptr(http_client_buffer, header_buf, n);

        // ============ content-length ============
        size_t content_length = 0;

        // calculate length before encode array
        if (zbody && Z_TYPE_P(zbody) == IS_ARRAY)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zbody), key, keylen, keytype, value)
                if (HASH_KEY_IS_STRING != keytype)
                {
                    continue;
                }
                convert_to_string(value);
                //strlen("%.*")*2 = 6
                //header + body + CRLF
                content_length += (sizeof(SW_HTTP_FORM_DATA_FORMAT_STRING) - 7) + (sizeof(boundary_str) - 1) + keylen + Z_STRLEN_P(value) + 2;
            SW_HASHTABLE_FOREACH_END();
        }

        zval *zname;
        zval *ztype;
        zval *zsize = NULL;
        zval *zpath = NULL;
        zval *zcontent = NULL;
        zval *zfilename;
        zval *zoffset;

        // calculate length of files
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zupload_files), key, keylen, keytype, value)
                if (!(zname = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("name"))))
                {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("filename"))))
                {
                    continue;
                }
                if (!(zsize = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("size"))))
                {
                    continue;
                }
                if (!(ztype = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("type"))))
                {
                    continue;
                }
                //strlen("%.*")*4 = 12
                //header + body + CRLF
                content_length += (sizeof(SW_HTTP_FORM_DATA_FORMAT_FILE) - 13) + (sizeof(boundary_str) - 1)
                        + Z_STRLEN_P(zname) + Z_STRLEN_P(zfilename) + Z_STRLEN_P(ztype) + Z_LVAL_P(zsize) + 2;
            SW_HASHTABLE_FOREACH_END();
        }

        http_client_append_content_length(http_client_buffer, content_length + sizeof(boundary_str) - 1 + 6);

        // ============ form-data body ============
        if (zbody && Z_TYPE_P(zbody) == IS_ARRAY)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zbody), key, keylen, keytype, value)
                if (HASH_KEY_IS_STRING != keytype)
                {
                    continue;
                }
                convert_to_string(value);
                n = snprintf(
                    header_buf, sizeof(header_buf),
                    SW_HTTP_FORM_DATA_FORMAT_STRING, (int)(sizeof(boundary_str) - 1),
                    boundary_str, keylen, key
                );
                swString_append_ptr(http_client_buffer, header_buf, n);
                swString_append_ptr(http_client_buffer, Z_STRVAL_P(value), Z_STRLEN_P(value));
                swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
            SW_HASHTABLE_FOREACH_END();
        }

        if (!hcc->socket->send(http_client_buffer->str, http_client_buffer->length))
        {
            goto _send_fail;
        }

        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zupload_files), key, keylen, keytype, value)
                if (!(zname = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("name"))))
                {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("filename"))))
                {
                    continue;
                }
                /**
                 * from disk file
                 */
                if (!(zcontent = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("content"))))
                {
                    //file path
                    if (!(zpath = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("path"))))
                    {
                        continue;
                    }
                    //file offset
                    if (!(zoffset = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("offset"))))
                    {
                        continue;
                    }
                    zcontent = NULL;
                }
                else
                {
                    zpath = NULL;
                    zoffset = NULL;
                }
                if (!(zsize = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("size"))))
                {
                    continue;
                }
                if (!(ztype = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("type"))))
                {
                    continue;
                }
                /**
                 * part header
                 */
                n = snprintf(
                    header_buf, sizeof(header_buf), SW_HTTP_FORM_DATA_FORMAT_FILE,
                    (int) (sizeof(boundary_str) - 1), boundary_str,
                    (int) Z_STRLEN_P(zname), Z_STRVAL_P(zname),
                    (int) Z_STRLEN_P(zfilename), Z_STRVAL_P(zfilename),
                    (int) Z_STRLEN_P(ztype), Z_STRVAL_P(ztype)
                );
                /**
                 * from memory
                 */
                if (zcontent)
                {
                    swString_clear(http_client_buffer);
                    swString_append_ptr(http_client_buffer, header_buf, n);
                    swString_append_ptr(http_client_buffer, Z_STRVAL_P(zcontent), Z_STRLEN_P(zcontent));
                    swString_append_ptr(http_client_buffer, "\r\n", 2);
                    if (!hcc->socket->send(http_client_buffer->str, http_client_buffer->length))
                    {
                        goto _send_fail;
                    }
                }
                /**
                 * from disk file
                 */
                else
                {
                    if (!hcc->socket->send(header_buf, n))
                    {
                        goto _send_fail;
                    }
                    if (!hcc->socket->sendfile(Z_STRVAL_P(zpath), Z_LVAL_P(zoffset), Z_LVAL_P(zsize)))
                    {
                        goto _send_fail;
                    }
                    if (!hcc->socket->send("\r\n", 2))
                    {
                        goto _send_fail;
                    }
                }
            SW_HASHTABLE_FOREACH_END();
        }

        n = snprintf(header_buf, sizeof(header_buf), "--%*s--\r\n", (int)(sizeof(boundary_str) - 1), boundary_str);
        if (!hcc->socket->send( header_buf, n))
        {
            goto _send_fail;
        }
        else
        {
            goto _send_ok;
        }
    }
    // ============ x-www-form-urlencoded or raw ============
    else if (zbody)
    {
        if (Z_TYPE_P(zbody) == IS_ARRAY)
        {
            size_t len;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            if (php_swoole_array_length(zbody) > 0)
            {
                smart_str formstr_s = { 0 };
                char *formstr = sw_http_build_query(zbody, &len, &formstr_s);
                if (formstr == NULL)
                {
                    swoole_php_error(E_WARNING, "http_build_query failed.");
                    return SW_ERR;
                }
                http_client_append_content_length(http_client_buffer, len);
                swString_append_ptr(http_client_buffer, formstr, len);
                smart_str_free(&formstr_s);
            }
            else
            {
                http_client_append_content_length(http_client_buffer, 0);
            }
        }
        else
        {
            char *body;
            size_t body_length = php_swoole_get_send_data(zbody, &body);
            http_client_append_content_length(http_client_buffer, body_length);
            swString_append_ptr(http_client_buffer, body, body_length);
        }
    }
    // ============ no body ============
    else
    {
        if (header_flag & HTTP_HEADER_CONTENT_LENGTH)
        {
            http_client_append_content_length(http_client_buffer, 0);
        }
        else
        {
            swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
        }
    }

    swTrace("[%zu]:<<EOF\n%.*s\nEOF", http_client_buffer->length, (int) http_client_buffer->length, http_client_buffer->str);

    if (!hcc->socket->send(http_client_buffer->str, http_client_buffer->length))
    {
       _send_fail:
       SwooleG.error = errno;
       swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", hcc->socket->socket->fd, (int )http_client_buffer->length);
       zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error);
       return SW_ERR;
    }

    _send_ok:
    hcc->wait = true;

    return SW_OK;
}

static PHP_METHOD(swoole_http_client_coro, __construct)
{
    char *host;
    size_t host_len;
    zend_long port = 80;
    zend_bool ssl = 0;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_BOOL(ssl)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_ERROR, "host is empty.");
        RETURN_FALSE;
    }

    zend_update_property_stringl(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr,getThis(), ZEND_STRL("port"), port);

    if (ssl)
    {
#ifdef SW_USE_OPENSSL
        http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
        hcc->ssl = 1;
#else
        swoole_php_fatal_error(E_ERROR, "require openssl library.");
#endif
    }

    swTraceLog(SW_TRACE_HTTP_CLIENT, "ctor, object handle=%d.", Z_OBJ_HANDLE_P(getThis()));
}

static PHP_METHOD(swoole_http_client_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swTraceLog(SW_TRACE_HTTP_CLIENT, "dtor, object handle=%d.", Z_OBJ_HANDLE_P(getThis()));
}

static PHP_METHOD(swoole_http_client_coro, set)
{
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval *zsetting = sw_zend_read_property_array(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders)
{
    zval *headers;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(headers)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), headers);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setCookies)
{
    zval *cookies;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(cookies)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("cookies"), cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, getDefer)
{
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    RETURN_BOOL(hcc->defer);
}

static PHP_METHOD(swoole_http_client_coro, setDefer)
{
    zend_bool defer = 1;
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(defer)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    hcc->defer = defer;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, recv)
{
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    http_client *http = (http_client *) swoole_get_object(getThis());
    double timeout = http->timeout;

    if (!http)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SwooleG.error);
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (timeout != 0)
    {
        hcc->socket->setTimeout(timeout);
    }

    if (http->upgrade)
    {
        ssize_t retval = hcc->socket->recv_packet();
        if (retval <= 0)
        {
            zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), hcc->socket->errCode);
            if (hcc->socket->errCode != ETIMEDOUT)
            {
                http_client_coro_close(getThis());
            }
            RETURN_FALSE;
        }
        else
        {
            swString msg;
            msg.length = retval;
            msg.str = hcc->socket->get_buffer()->str;
            php_swoole_websocket_frame_unpack(&msg, return_value);
            return;
        }
    }
    if (!hcc->defer)
    {
        swoole_php_fatal_error(E_WARNING, "you should not use recv without defer.");
        RETURN_FALSE;
    }
    if (!hcc->wait)
    {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(http_client_coro_recv_response(getThis(), hcc, http));
}

static PHP_METHOD(swoole_http_client_coro, setData)
{
    char *data;
    size_t data_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data, data_len);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addFile)
{
    char *path;
    size_t l_path;
    char *name;
    size_t l_name;
    char *type = NULL;
    size_t l_type = 0;
    char *filename = NULL;
    size_t l_filename = 0;
    zend_long offset = 0;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(2, 6)
        Z_PARAM_STRING(path, l_path)
        Z_PARAM_STRING(name, l_name)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(type, l_type)
        Z_PARAM_STRING(filename, l_filename)
        Z_PARAM_LONG(offset)
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (offset < 0)
    {
        offset = 0;
    }
    if (length < 0)
    {
        length = 0;
    }
    struct stat file_stat;
    if (stat(path, &file_stat) < 0)
    {
        swoole_php_sys_error(E_WARNING, "stat(%s) failed.", path);
        RETURN_FALSE;
    }
    if (file_stat.st_size == 0)
    {
        swoole_php_sys_error(E_WARNING, "cannot send empty file[%s].", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= offset)
    {
        swoole_php_error(E_WARNING, "parameter $offset[%ld] exceeds the file size.", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset)
    {
        swoole_php_sys_error(E_WARNING, "parameter $length[%ld] exceeds the file size.", length);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        length = file_stat.st_size - offset;
    }
    if (type == NULL)
    {
        type = swoole_get_mime_type(path);
        l_type = strlen(type);
    }
    if (filename == NULL)
    {
        char *dot = strrchr(path, '/');
        if (dot == NULL)
        {
            filename = path;
            l_filename = l_path;
        }
        else
        {
            filename = dot + 1;
            l_filename = strlen(filename);
        }
    }

    zval *zupload_files = sw_zend_read_property_array(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), 1);
    zval *zupload_file;
    SW_MAKE_STD_ZVAL(zupload_file);
    array_init(zupload_file);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("path"), path, l_path);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(zupload_file, "size", length);
    add_assoc_long(zupload_file, "offset", offset);
    add_next_index_zval(zupload_files, zupload_file);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addData)
{
    char *data;
    size_t l_data;
    char *name;
    size_t l_name;
    char *type = NULL;
    size_t l_type = 0;
    char *filename = NULL;
    size_t l_filename = 0;

    ZEND_PARSE_PARAMETERS_START(2, 4)
        Z_PARAM_STRING(data, l_data)
        Z_PARAM_STRING(name, l_name)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(type, l_type)
        Z_PARAM_STRING(filename, l_filename)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (type == NULL)
    {
        type = (char *) "application/octet-stream";
        l_type = strlen(type);
    }
    if (filename == NULL)
    {
        filename = name;
        l_filename = l_name;
    }

    zval *zupload_files = sw_zend_read_property_array(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), 1);
    zval *zupload_file;
    SW_MAKE_STD_ZVAL(zupload_file);
    array_init(zupload_file);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("content"), data, l_data);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(zupload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(zupload_file, "size", l_data);
    add_next_index_zval(zupload_files, zupload_file);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setMethod)
{
    zval *method;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(method)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);
    
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestMethod"), method);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, isConnected)
{
    http_client *http = (http_client *) swoole_get_object(getThis());
    RETURN_BOOL(http != NULL);
}

static PHP_METHOD(swoole_http_client_coro, close)
{
    SW_CHECK_RETURN(http_client_coro_close(getThis()));
}

static PHP_METHOD(swoole_http_client_coro, execute)
{
    char *uri = NULL;
    size_t uri_len = 0;
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(uri, uri_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, get)
{
    char *uri = NULL;
    size_t uri_len = 0;
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(uri, uri_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, post)
{
    char *uri = NULL;
    size_t uri_len = 0;
    zval *post_data;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(uri, uri_len)
        Z_PARAM_ZVAL(post_data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (Z_TYPE_P(post_data) != IS_ARRAY && Z_TYPE_P(post_data) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "post data must be string or array.");
        RETURN_FALSE;
    }

    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), post_data);

    SW_CHECK_RETURN(
        http_client_coro_execute(
            getThis(),
            (http_client_coro_property *) swoole_get_property(getThis(), 0),
            uri, uri_len
        )
    );
}

static PHP_METHOD(swoole_http_client_coro, download)
{
    char *uri = NULL;
    size_t uri_len = 0;
    zval *download_file;
    zend_long offset = 0;
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(uri, uri_len)
        Z_PARAM_ZVAL(download_file)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("downloadFile"), download_file);
    zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("downloadOffset"), offset);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, upgrade)
{
    char *uri = NULL;
    size_t uri_len = 0;
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(uri, uri_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval *zheaders = sw_zend_read_property_array(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1);

    char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
    http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);

    add_assoc_string(zheaders, "Connection", (char* )"Upgrade");
    add_assoc_string(zheaders, "Upgrade", (char* ) "websocket");
    add_assoc_string(zheaders, "Sec-WebSocket-Version", (char*)SW_WEBSOCKET_VERSION);

    zend_string *str = php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH);
    add_assoc_str_ex(zheaders, ZEND_STRL("Sec-WebSocket-Key"), str);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, push)
{
    zval *zdata = NULL;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zend_bool fin = 1;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL(zdata)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(opcode)
        Z_PARAM_BOOL(fin)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_client *http = (http_client *) swoole_get_object(getThis());

    if (!http)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SwooleG.error);
        RETURN_FALSE;
    }

    if (!http->upgrade)
    {
        swoole_php_fatal_error(E_WARNING, "websocket handshake failed, cannot push data.");
        SwooleG.error = SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED;
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SwooleG.error);
        RETURN_FALSE;
    }

    swString_clear(http_client_buffer);
    if (php_swoole_websocket_frame_pack(http_client_buffer, zdata, opcode, fin, http->websocket_mask) < 0)
    {
        RETURN_FALSE;
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    sw_coro_check_bind("http client", hcc->socket->has_bound(swoole::SOCKET_LOCK_WRITE));
    if (hcc->socket->send(http_client_buffer->str, http_client_buffer->length) < 0)
    {
        SwooleG.error = hcc->socket->errCode;
        swoole_php_sys_error(E_WARNING, "send(%d) %zd bytes failed.", hcc->socket->socket->fd, http_client_buffer->length);
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("errCode"), SwooleG.error);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

#endif
