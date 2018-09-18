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
    zval _object;
    zval _request_body;
    zval _request_header;
    zval _request_upload_files;
    zval _download_file;
    zval _cookies;

    zval *cookies;
    zval *request_header;
    zval *request_body;
    zval *request_upload_files;
    zval *download_file;
    off_t download_offset;
    const char *request_method;
    int callback_index;

    uint8_t error_flag;
    uint8_t shutdown;

    Socket *socket;
    bool ssl;
    bool wait;
    zend_bool defer;
    zend_bool keep_alive;

} http_client_coro_property;

static swString *http_client_buffer;

extern void php_swoole_client_coro_check_setting(Socket *cli, zval *zset);
extern void php_swoole_client_coro_free(zval *zobject, Socket *cli);

static int http_client_coro_send_request(zval *zobject, http_client_coro_property *hcc, http_client *client);
static int http_client_coro_recv_response(zval *zobject, http_client_coro_property *hcc, http_client *client);
static int http_client_coro_execute(zval *zobject, http_client_coro_property *hcc, char *uri, zend_size_t uri_len);

static int http_client_coro_close(zval *zobject)
{
    zend_update_property_bool(Z_OBJCE_P(zobject), zobject, ZEND_STRL("connected"), 0);
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(zobject, 0);
    if (hcc->socket == nullptr)
    {
        return SW_ERR;
    }
    http_client_free(zobject);
    hcc->socket->close();
    php_swoole_client_coro_free(zobject, hcc->socket);
    hcc->socket = nullptr;
    return SW_OK;
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
    PHP_ME(swoole_http_client_coro, __construct, arginfo_swoole_http_client_coro_coro_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http_client_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
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

static int http_client_coro_execute(zval *zobject, http_client_coro_property *hcc, char *uri, zend_size_t uri_len)
{
    if (uri_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "path is empty.");
        return SW_ERR;
    }

    http_client *http = (http_client *) swoole_get_object(zobject);
    if (!http)
    {
        http = http_client_create(zobject);
    }

    // when new request, clear all properties about the last response
    http_client_clear_response_properties(zobject);
    hcc->error_flag = 0;

    if (hcc->socket == nullptr)
    {
        hcc->socket = new Socket(SW_SOCK_TCP);
        zval *ztmp;
        HashTable *vht;
        zval *zset = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("setting"), 1);
        if (zset && !ZVAL_IS_NULL(zset))
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
                zval *send_header = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("requestHeaders"), 1);
                if (send_header == NULL || Z_TYPE_P(send_header) != IS_ARRAY)
                {
                    swoole_php_fatal_error (E_WARNING, "http proxy must set Host");
                    return SW_ERR;
                }
                zval *value;
                if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value) == FAILURE)
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
                    add_assoc_stringl_ex(send_header, ZEND_STRL("Proxy-Authorization"), _buf2, _n2);
                }
            }
            php_swoole_client_coro_check_setting(hcc->socket, zset);
        }

        if (!hcc->socket->connect(std::string(http->host, http->host_len), http->port))
        {
            zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("errCode"), hcc->socket->errCode);
            zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_TIMEOUT );
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
    }

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

    /**
     * download response body
     */
    if (hcc->download_file)
    {
        int fd = open(Z_STRVAL_P(hcc->download_file), O_CREAT | O_WRONLY, 0664);
        if (fd < 0)
        {
            swSysError("open(%s, O_CREAT | O_WRONLY) failed.", Z_STRVAL_P(hcc->download_file));
            return SW_ERR;
        }
        if (hcc->download_offset == 0)
        {
            if (ftruncate(fd, 0) < 0)
            {
                swSysError("ftruncate(%s) failed.", Z_STRVAL_P(hcc->download_file));
                close(fd);
                return SW_ERR;
            }
        }
        else
        {
            if (lseek(fd, hcc->download_offset, SEEK_SET) < 0)
            {
                swSysError("fseek(%s, %jd) failed.", Z_STRVAL_P(hcc->download_file), (intmax_t) hcc->download_offset);
                close(fd);
                return SW_ERR;
            }
        }
        http->download = 1;
        http->file_fd = fd;
    }

    swTraceLog(SW_TRACE_HTTP_CLIENT, "connect to server, object handle=%d, fd=%d", sw_get_object_handle(zobject), hcc->socket->socket->fd);

    if (http_client_coro_send_request(zobject, hcc, http) < 0)
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
    zval _zobject;
    zval *zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    http_client *http = (http_client *) swoole_get_object(zobject);
    if (http)
    {
        http_client_coro_close(zobject);
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(zobject, 0);
    if (hcc)
    {
        efree(hcc);
        swoole_set_property(zobject, 0, NULL);
    }

    // dtor object
    zend_object_std_dtor(object);
}

static zend_object *swoole_http_client_coro_create(zend_class_entry *ce TSRMLS_DC)
{
    zend_object *object;
    object = zend_objects_new(ce);
    object->handlers = &swoole_http_client_coro_handlers;
    object_properties_init(object, ce);

    zval _zobject;
    zval* zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    http_client_coro_property *hcc = (http_client_coro_property*) emalloc(sizeof(http_client_coro_property));
    bzero(hcc, sizeof(http_client_coro_property));

    php_swoole_check_reactor();
    swoole_set_property(zobject, 0, hcc);

    return object;
}

void swoole_http_client_coro_init(int module_number TSRMLS_DC)
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

    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("sock"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("requestMethod"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("requestHeaders"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("requestBody"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("uploadFiles"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("downloadFile"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_class_entry_ptr, ZEND_STRL("body"), ZEND_ACC_PUBLIC);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(2048);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

static int http_client_coro_recv_response(zval *zobject, http_client_coro_property *hcc, http_client *http)
{
    long parsed_n = 0;
    swString *buffer = hcc->socket->get_buffer();
    ssize_t total_bytes = 0, retval = 0;

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
    //clear errno
    SwooleG.error = 0;

    zval *post_data = hcc->request_body;
    zval *send_header = hcc->request_header;
    zval *value = NULL;
    uint8_t enable_length = 0;

    //POST
    if (hcc->request_method == NULL)
    {
        if (post_data)
        {
            hcc->request_method = "POST";
        }
        //GET
        else
        {
            hcc->request_method = "GET";
        }
    }

    http->method = swHttp_get_method(hcc->request_method, strlen(hcc->request_method) + 1);

    swString_clear(http_client_buffer);
    swString_append_ptr(http_client_buffer, (char*) hcc->request_method, strlen(hcc->request_method));
    hcc->request_method = NULL;
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));

#ifdef SW_USE_OPENSSL
    if (hcc->socket->http_proxy && !hcc->socket->open_ssl)
#else
    if (hcc->socket->http_proxy)
#endif
    {
        sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value); //checked before
        const char *pre = "http://";
        int len = http->uri_len + Z_STRLEN_P(value) + strlen(pre) + 10;
        char *addr = (char*) emalloc(http->uri_len + Z_STRLEN_P(value) + strlen(pre) + 10);
        http->uri_len = snprintf(addr, len, "%s%s:%ld%s", pre, Z_STRVAL_P(value), http->port, http->uri);
        efree(http->uri);
        http->uri = addr;
    }

    swString_append_ptr(http_client_buffer, http->uri, http->uri_len);
    swString_append_ptr(http_client_buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    char *key;
    uint32_t keylen;
    int keytype;

    if (send_header && Z_TYPE_P(send_header) == IS_ARRAY)
    {
        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Connection"), (void **) &value) == FAILURE)
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

        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
        }

#ifdef SW_HAVE_ZLIB
        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Accept-Encoding"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
        }
#endif

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(send_header), key, keylen, keytype, value)
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            convert_to_string(value);
            if (Z_STRLEN_P(value) == 0)
            {
                continue;
            }
            //ignore custom Content-Length value
            if (strncasecmp(key, ZEND_STRL("Content-Length")) == 0)
            {
                enable_length = 1;
                continue;
            }
            http_client_swString_append_headers(http_client_buffer, key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
        SW_HASHTABLE_FOREACH_END();
    }
    else
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        http->keep_alive = 1;
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
#ifdef SW_HAVE_ZLIB
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
#endif
    }

    if (hcc->cookies && Z_TYPE_P(hcc->cookies) == IS_ARRAY)
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("Cookie: "));
        int n_cookie = Z_ARRVAL_P(hcc->cookies)->nNumOfElements;
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->cookies), key, keylen, keytype, value)
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

    //multipart/form-data
    if (hcc->request_upload_files)
    {
        char header_buf[2048];
        char boundary_str[39];
        int n;

        memcpy(boundary_str, SW_HTTP_CLIENT_BOUNDARY_PREKEY, sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1);
        swoole_random_string(boundary_str + sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1,
                sizeof(boundary_str) - sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY));

        n = snprintf(header_buf, sizeof(header_buf), "Content-Type: multipart/form-data; boundary=%*s\r\n",
                (int)(sizeof(boundary_str) - 1), boundary_str);

        swString_append_ptr(http_client_buffer, header_buf, n);

        int content_length = 0;

        //post data
        if (post_data && Z_TYPE_P(post_data) == IS_ARRAY)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(post_data), key, keylen, keytype, value)
                if (HASH_KEY_IS_STRING != keytype)
                {
                    continue;
                }
                convert_to_string(value);
                //strlen("%.*")*2 = 6
                //header + body + CRLF
                content_length += (sizeof(SW_HTTP_FORM_DATA_FORMAT_STRING) - 7) + (sizeof(boundary_str) - 1) + keylen
                        + Z_STRLEN_P(value) + 2;
            SW_HASHTABLE_FOREACH_END();
        }

        zval *zname;
        zval *ztype;
        zval *zsize = NULL;
        zval *zpath = NULL;
        zval *zcontent = NULL;
        zval *zfilename;
        zval *zoffset;

        if (hcc->request_upload_files)
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->request_upload_files), key, keylen, keytype, value)
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("name"), (void **) &zname) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("filename"), (void **) &zfilename) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("size"), (void **) &zsize) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("type"), (void **) &ztype) == FAILURE)
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

        //post data
        if (post_data && Z_TYPE_P(post_data) == IS_ARRAY)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(post_data), key, keylen, keytype, value)
                if (HASH_KEY_IS_STRING != keytype)
                {
                    continue;
                }
                convert_to_string(value);
                n = snprintf(header_buf, sizeof(header_buf), SW_HTTP_FORM_DATA_FORMAT_STRING, (int)(sizeof(boundary_str) - 1),
                        boundary_str, keylen, key);
                swString_append_ptr(http_client_buffer, header_buf, n);
                swString_append_ptr(http_client_buffer, Z_STRVAL_P(value), Z_STRLEN_P(value));
                swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
            SW_HASHTABLE_FOREACH_END();

            zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
            hcc->request_body = NULL;
        }

        if (!hcc->socket->send(http_client_buffer->str, http_client_buffer->length))
        {
            goto send_fail;
        }

        if (hcc->request_upload_files)
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->request_upload_files), key, keylen, keytype, value)
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("name"), (void **) &zname) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("filename"), (void **) &zfilename) == FAILURE)
                {
                    continue;
                }
                /**
                 * from disk file
                 */
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("content"), (void **) &zcontent) == FAILURE)
                {
                    //file path
                    if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("path"), (void **) &zpath) == FAILURE)
                    {
                        continue;
                    }
                    //file offset
                    if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("offset"), (void **) &zoffset) == FAILURE)
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
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("size"), (void **) &zsize) == FAILURE)
                {
                    continue;
                }
                if (sw_zend_hash_find(Z_ARRVAL_P(value), ZEND_STRS("type"), (void **) &ztype) == FAILURE)
                {
                    continue;
                }
                /**
                 * part header
                 */
                n = snprintf(header_buf, sizeof(header_buf), SW_HTTP_FORM_DATA_FORMAT_FILE, (int)(sizeof(boundary_str) - 1),
                        boundary_str, (int)Z_STRLEN_P(zname), Z_STRVAL_P(zname), (int)Z_STRLEN_P(zfilename),
                        Z_STRVAL_P(zfilename), (int)Z_STRLEN_P(ztype), Z_STRVAL_P(ztype));
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
                        goto send_fail;
                    }
                }
                /**
                 * from disk file
                 */
                else
                {
                    if (!hcc->socket->send(header_buf, n))
                    {
                        goto send_fail;
                    }
                    if (!hcc->socket->sendfile(Z_STRVAL_P(zpath), Z_LVAL_P(zoffset), Z_LVAL_P(zsize)))
                    {
                        goto send_fail;
                    }
                    if (!hcc->socket->send("\r\n", 2))
                    {
                        goto send_fail;
                    }
                }
            SW_HASHTABLE_FOREACH_END();

            zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("uploadFiles"));
            hcc->request_upload_files = NULL;
        }

        n = snprintf(header_buf, sizeof(header_buf), "--%*s--\r\n", (int)(sizeof(boundary_str) - 1), boundary_str);
        if (!hcc->socket->send( header_buf, n))
        {
            goto send_fail;
        }
        else
        {
            goto send_ok;
        }
    }
    //x-www-form-urlencoded or raw
    else if (post_data)
    {
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            zend_size_t len;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            if (php_swoole_array_length(post_data) > 0)
            {
                smart_str formstr_s = { 0 };
                char *formstr = sw_http_build_query(post_data, &len, &formstr_s);
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
            http_client_append_content_length(http_client_buffer, Z_STRLEN_P(post_data));
            swString_append_ptr(http_client_buffer, Z_STRVAL_P(post_data), Z_STRLEN_P(post_data));
        }
        zend_update_property_null(swoole_http_client_coro_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
        hcc->request_body = NULL;
    }
    //no body
    else
    {
        if (enable_length)
        {
            http_client_append_content_length(http_client_buffer, 0);
        }
        else
        {
            swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
        }
    }

    swTrace("[%d]: %s\n", (int)http_client_buffer->length, http_client_buffer->str);

    if (!hcc->socket->send(http_client_buffer->str, http_client_buffer->length))
    {
       send_fail:
       SwooleG.error = errno;
       swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", hcc->socket->socket->fd, (int )http_client_buffer->length);
       zend_update_property_long(swoole_http_client_coro_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error);
       return SW_ERR;
    }

    send_ok:
    hcc->wait = true;

    return SW_OK;
}

static PHP_METHOD(swoole_http_client_coro, __construct)
{
    char *host;
    zend_size_t host_len;
    long port = 80;
    zend_bool ssl = SW_FALSE;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|lb", &host, &host_len, &port, &ssl) == FAILURE)
    {
        return;
    }

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

    swTraceLog(SW_TRACE_HTTP_CLIENT, "ctor, object handle=%d.", sw_get_object_handle(getThis()));
}

static PHP_METHOD(swoole_http_client_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swTraceLog(SW_TRACE_HTTP_CLIENT, "dtor, object handle=%d.", sw_get_object_handle(getThis()));
}

static PHP_METHOD(swoole_http_client_coro, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zset) == FAILURE)
    {
        return;
    }
    if (Z_TYPE_P(zset) != IS_ARRAY)
    {
        RETURN_FALSE;
    }
    zval *zsetting = php_swoole_read_init_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("setting"));
    sw_php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders)
{
    zval *headers;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &headers) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), headers);
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    hcc->request_header = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1);
    sw_copy_to_stack(hcc->request_header, hcc->_request_header);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setCookies)
{
    zval *cookies;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &cookies) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("cookies"), cookies);
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    hcc->cookies = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("cookies"), 1);
    sw_copy_to_stack(hcc->cookies, hcc->_cookies);

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

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &defer) == FAILURE)
    {
        return;
    }

    hcc->defer = defer;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, recv)
{
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    http_client *http = (http_client *) swoole_get_object(getThis());
    if (!http)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error);
        RETURN_FALSE;
    }
    double timeout = http->timeout;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "|d", &timeout) == FAILURE)
    {
        return;
    }

    if (timeout != 0)
    {
        hcc->socket->setTimeout(timeout);
    }

    if (http->upgrade)
    {
        ssize_t retval = hcc->socket->recv_packet();
        if (retval <= 0)
        {
            zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, hcc->socket->errCode);
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
    zval *data;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &data) == FAILURE)
    {
        return;
    }
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data);
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    hcc->request_body = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addFile)
{
    char *path;
    zend_size_t l_path;
    char *name;
    zend_size_t l_name;
    char *type = NULL;
    zend_size_t l_type;
    char *filename = NULL;
    zend_size_t l_filename;
    long offset = 0;
    long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|ssll", &path, &l_path, &name, &l_name, &type, &l_type,
            &filename, &l_filename, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }
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
        type = swoole_get_mimetype(path);
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

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    zval *files;
    if (!hcc->request_upload_files)
    {
        SW_MAKE_STD_ZVAL(files);
        array_init(files);
        zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), files);
        sw_zval_ptr_dtor(&files);

        hcc->request_upload_files = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), 0);
        sw_copy_to_stack(hcc->request_upload_files, hcc->_request_upload_files);
    }

    zval *upload_file;
    SW_MAKE_STD_ZVAL(upload_file);
    array_init(upload_file);

    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("path"), path, l_path, 1);
    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("name"), name, l_name, 1);
    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("filename"), filename, l_filename, 1);
    sw_add_assoc_stringl_ex(upload_file, ZEND_STRS("type"), type, l_type, 1);
    add_assoc_long(upload_file, "size", length);
    add_assoc_long(upload_file, "offset", offset);

    add_next_index_zval(hcc->request_upload_files, upload_file);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addData)
{
    char *data;
    zend_size_t l_data;
    char *name;
    zend_size_t l_name;
    char *type = NULL;
    zend_size_t l_type;
    char *filename = NULL;
    zend_size_t l_filename;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|ss", &data, &l_data, &name, &l_name, &type, &l_type,
            &filename, &l_filename) == FAILURE)
    {
        RETURN_FALSE;
    }
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

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    zval *files;
    if (!hcc->request_upload_files)
    {
        SW_MAKE_STD_ZVAL(files);
        array_init(files);
        zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), files);
        sw_zval_ptr_dtor(&files);

        hcc->request_upload_files = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), 0);
        sw_copy_to_stack(hcc->request_upload_files, hcc->_request_upload_files);
    }

    zval *upload_file;
    SW_MAKE_STD_ZVAL(upload_file);
    array_init(upload_file);

    add_assoc_stringl_ex(upload_file, ZEND_STRL("content"), data, l_data);
    add_assoc_stringl_ex(upload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(upload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(upload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(upload_file, "size", l_data);

    add_next_index_zval(hcc->request_upload_files, upload_file);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setMethod)
{
    zval *method;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &method) == FAILURE)
    {
        return;
    }
    convert_to_string(method);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestMethod"), method);
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    hcc->request_method = Z_STRVAL_P(method);
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
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }
    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, get)
{
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, post)
{
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *post_data;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &uri, &uri_len, &post_data) == FAILURE)
    {
        return;
    }

    if (Z_TYPE_P(post_data) != IS_ARRAY && Z_TYPE_P(post_data) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "post data must be string or array.");
        RETURN_FALSE;
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), post_data);
    hcc->request_body = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1);
    sw_copy_to_stack(hcc->request_body, hcc->_request_body);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, download)
{
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *download_file;
    off_t offset = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz|l", &uri, &uri_len, &download_file, &offset) == FAILURE)
    {
        return;
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    zend_update_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("downloadFile"), download_file);
    hcc->download_file = sw_zend_read_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("downloadFile"), 1);
    hcc->download_offset = offset;
    sw_copy_to_stack(hcc->download_file, hcc->_download_file);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, upgrade)
{
    char *uri = NULL;
    zend_size_t uri_len = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &uri, &uri_len) == FAILURE)
    {
        return;
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);

    zval *headers = hcc->request_header;
    if (hcc->request_header == NULL)
    {
        headers = php_swoole_read_init_property(swoole_http_client_coro_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"));
        hcc->request_header = headers;
        sw_copy_to_stack(hcc->request_header, hcc->_request_header);
    }

    char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
    http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);

    add_assoc_string(headers, "Connection", (char* )"Upgrade");
    add_assoc_string(headers, "Upgrade", (char* ) "websocket");
    add_assoc_string(headers, "Sec-WebSocket-Version", (char*)SW_WEBSOCKET_VERSION);

    zend_string *str = php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH);
    add_assoc_str_ex(headers, ZEND_STRL("Sec-WebSocket-Key"), str);

    SW_CHECK_RETURN(http_client_coro_execute(getThis(), hcc, uri, uri_len));
}

static PHP_METHOD(swoole_http_client_coro, push)
{
    zval *zdata = NULL;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|lb", &zdata, &opcode, &fin) == FAILURE)
    {
        return;
    }

    http_client *http = (http_client *) swoole_get_object(getThis());

    if (!http)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error);
        RETURN_FALSE;
    }

    if (!http->upgrade)
    {
        swoole_php_fatal_error(E_WARNING, "websocket handshake failed, cannot push data.");
        SwooleG.error = SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED;
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error);
        RETURN_FALSE;
    }

    swString_clear(http_client_buffer);
    if (php_swoole_websocket_frame_pack(http_client_buffer, zdata, opcode, fin, http->websocket_mask) < 0)
    {
        RETURN_FALSE;
    }

    http_client_coro_property *hcc = (http_client_coro_property *) swoole_get_property(getThis(), 0);
    if (hcc->socket->send(http_client_buffer->str, http_client_buffer->length) < 0)
    {
        SwooleG.error = hcc->socket->errCode;
        swoole_php_sys_error(E_WARNING, "send(%d) %zd bytes failed.", hcc->socket->socket->fd, http_client_buffer->length);
        zend_update_property_long(swoole_http_client_coro_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error);
        RETURN_FALSE;
    }
    else
    {
        RETURN_TRUE;
    }
}

#endif
