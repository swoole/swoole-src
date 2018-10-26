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
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "swoole_http_client.h"

swString *http_client_buffer;

static void http_client_onReceive(swClient *cli, char *data, uint32_t length);
static void http_client_onConnect(swClient *cli);
static void http_client_onClose(swClient *cli);
static void http_client_onError(swClient *cli);
static void http_client_onRequestTimeout(swTimer *timer, swTimer_node *tnode);
static void http_client_onResponseException();
static int http_client_onMessage(swConnection *conn, char *data, uint32_t length);

static int http_client_send_http_request(zval *zobject);
static int http_client_execute(zval *zobject, char *uri, size_t uri_len, zval *callback);

#ifdef SW_HAVE_ZLIB
int http_response_uncompress(z_stream *stream, swString *buffer, char *body, int length);
static void http_init_gzip_stream(http_client *);
extern voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size);
extern void php_zlib_free(voidpf opaque, voidpf address);
#endif

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

static zend_class_entry swoole_http_client_ce;
static zend_class_entry *swoole_http_client_class_entry_ptr;

static PHP_METHOD(swoole_http_client, __construct);
static PHP_METHOD(swoole_http_client, __destruct);
static PHP_METHOD(swoole_http_client, set);
static PHP_METHOD(swoole_http_client, setMethod);
static PHP_METHOD(swoole_http_client, setHeaders);
static PHP_METHOD(swoole_http_client, setCookies);
static PHP_METHOD(swoole_http_client, setData);
static PHP_METHOD(swoole_http_client, addFile);
static PHP_METHOD(swoole_http_client, execute);
static PHP_METHOD(swoole_http_client, push);
static PHP_METHOD(swoole_http_client, isConnected);
static PHP_METHOD(swoole_http_client, close);
static PHP_METHOD(swoole_http_client, on);
static PHP_METHOD(swoole_http_client, get);
static PHP_METHOD(swoole_http_client, post);
static PHP_METHOD(swoole_http_client, upgrade);
static PHP_METHOD(swoole_http_client, download);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setMethod, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setHeaders, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, headers, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setCookies, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cookies, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setData, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_addFile, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_execute, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_get, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_post, 0, 0, 3)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_download, 0, 0, 3)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, file)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_upgrade, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_http_client_methods[] =
{
    PHP_ME(swoole_http_client, __construct, arginfo_swoole_http_client_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, set, arginfo_swoole_http_client_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setMethod, arginfo_swoole_http_client_setMethod, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setHeaders, arginfo_swoole_http_client_setHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setCookies, arginfo_swoole_http_client_setCookies, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setData, arginfo_swoole_http_client_setData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, addFile, arginfo_swoole_http_client_addFile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, execute, arginfo_swoole_http_client_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, push, arginfo_swoole_http_client_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, get, arginfo_swoole_http_client_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, post, arginfo_swoole_http_client_post, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, upgrade, arginfo_swoole_http_client_upgrade, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, download, arginfo_swoole_http_client_download, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, isConnected, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, on, arginfo_swoole_http_client_on, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void http_client_clear_response_properties(zval *zobject)
{
    zval *zattr;
    zend_class_entry *ce = Z_OBJCE_P(zobject);
    zend_update_property_long(ce, zobject, ZEND_STRL("errCode"), 0);
    zend_update_property_long(ce, zobject, ZEND_STRL("statusCode"), 0);
    zattr = sw_zend_read_property(ce, zobject, ZEND_STRL("headers"), 1);
    if (Z_TYPE_P(zattr) == IS_ARRAY)
    {
        zend_hash_clean(Z_ARRVAL_P(zattr));
    }
    zattr = sw_zend_read_property(ce, zobject, ZEND_STRL("set_cookie_headers"), 1);
    if (Z_TYPE_P(zattr) == IS_ARRAY)
    {
        zend_hash_clean(Z_ARRVAL_P(zattr));
    }
    zend_update_property_string(ce, zobject, ZEND_STRL("body"), "");
}

static int http_client_execute(zval *zobject, char *uri, size_t uri_len, zval *callback)
{
    if (uri_len <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "path is empty.");
        return SW_ERR;
    }

    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name))
    {
        swoole_php_fatal_error(E_WARNING, "Function '%s' is not callable", func_name);
        efree(func_name);
        return SW_ERR;
    }
    efree(func_name);

    http_client_property *hcc = swoole_get_property(zobject, 0);

    // when new request, clear all properties about the last response
    http_client_clear_response_properties(zobject);
    hcc->error_flag = 0;

    http_client *http = swoole_get_object(zobject);
    //http is not null when keeping alive
    if (http)
    {
        //http not ready
        if (http->state != HTTP_CLIENT_STATE_READY)
        {
            //swWarn("fd=%d, state=%d, active=%d, keep_alive=%d", http->cli->socket->fd, http->state, http->cli->socket->active, http->keep_alive);
            swoole_php_fatal_error(E_WARNING, "Operation now in progress phase %d.", http->state);
            return SW_ERR;
        }
        else if (!http->cli->socket->active)
        {
            swoole_php_fatal_error(E_WARNING, "connection#%d is closed.", http->cli->socket->fd);
            return SW_ERR;
        }
    }
    else
    {
        php_swoole_check_reactor();
        http = http_client_create(zobject);
    }

    if (http == NULL)
    {
        return SW_ERR;
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

    if (callback == NULL || ZVAL_IS_NULL(callback))
    {
        swoole_php_fatal_error(E_WARNING, "response callback is not set.");
    }

    Z_TRY_ADDREF_P(callback);
    hcc->onResponse = sw_zval_dup(callback);

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
        hcc->download_file = NULL;
    }

    //if connection exists
    if (http->cli)
    {
        return http_client_send_http_request(zobject) < 0 ? SW_ERR : SW_OK;
    }

    swClient *cli = php_swoole_client_new(zobject, http->host, http->host_len, http->port);
    if (cli == NULL)
    {
        return SW_ERR;
    }
    http->cli = cli;

    zval *ztmp;
    HashTable *vht;
    zval *zset = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("setting"), 1);
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
        }
        /**
         * keep_alive
         */
        if (php_swoole_array_get_value(vht, "keep_alive", ztmp))
        {
            convert_to_boolean(ztmp);
            http->keep_alive = Z_BVAL_P(ztmp);
        }
        /**
         * websocket mask
         */
        if (php_swoole_array_get_value(vht, "websocket_mask", ztmp))
        {
            convert_to_boolean(ztmp);
            http->websocket_mask = (int) Z_BVAL_P(ztmp);
        }
        //client settings
        php_swoole_client_check_setting(http->cli, zset);

        if (http->cli->http_proxy)
        {
            zval *zsend_header = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestHeaders"), 1);
            if (zsend_header == NULL || Z_TYPE_P(zsend_header) != IS_ARRAY)
            {
                swoole_php_fatal_error (E_WARNING, "http proxy must set Host");
                return SW_ERR;
            }
            zval *value;
            if (!(value = zend_hash_str_find(Z_ARRVAL_P(zsend_header), ZEND_STRL("Host"))) ||
                    Z_TYPE_P(value) != IS_STRING || Z_STRLEN_P(value) < 1)
            {
                swoole_php_fatal_error(E_WARNING, "http proxy must set Host");
                return SW_ERR;
            }
            if (http->cli->http_proxy->password)
            {
                char _buf1[128];
                char _buf2[256];
                int _n1 = snprintf(_buf1, sizeof(_buf1), "%*s:%*s", http->cli->http_proxy->l_user,
                        http->cli->http_proxy->user, http->cli->http_proxy->l_password,
                        http->cli->http_proxy->password);
                zend_string *str = php_base64_encode((const unsigned char *) _buf1, _n1);
                int _n2 = snprintf(_buf2, sizeof(_buf2), "Basic %*s", (int)str->len, str->val);
                zend_string_free(str);
                add_assoc_stringl_ex(zsend_header, ZEND_STRL("Proxy-Authorization"), _buf2, _n2);
            }
        }
    }

    if (cli->socket->active == 1)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client is already connected.");
        return SW_ERR;
    }

    cli->object = zobject;
    sw_copy_to_stack(cli->object, hcc->_object);
    Z_TRY_ADDREF_P(zobject);

    cli->open_eof_check = 0;
    cli->open_length_check = 0;
    cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    cli->onReceive = http_client_onReceive;
    cli->onConnect = http_client_onConnect;
    cli->onClose = http_client_onClose;
    cli->onError = http_client_onError;

    return cli->connect(cli, http->host, http->port, http->timeout, 0);
}

void swoole_http_client_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_http_client_ce, "swoole_http_client", "Swoole\\Http\\Client", swoole_http_client_methods);
    swoole_http_client_class_entry_ptr = zend_register_internal_class(&swoole_http_client_ce);
    SWOOLE_CLASS_ALIAS(swoole_http_client, "Swoole\\Http\\Client");

    zend_declare_property_long(swoole_http_client_class_entry_ptr, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("requestMethod"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("requestHeaders"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("requestBody"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("uploadFiles"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("downloadFile"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("body"), ZEND_ACC_PUBLIC);

    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("onConnect"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("onError"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("onMessage"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, ZEND_STRL("onClose"), ZEND_ACC_PUBLIC);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

static void http_client_execute_callback(zval *zobject, enum php_swoole_client_callback_type type)
{
    zval *callback = NULL;
    zval *retval = NULL;
    zval args[1];

    http_client_property *hcc = swoole_get_property(zobject, 0);
    if (!hcc)
    {
        return;
    }

    char *callback_name;
    switch(type)
    {
    case SW_CLIENT_CB_onConnect:
        callback = hcc->onConnect;
        callback_name = "onConnect";
        break;
    case SW_CLIENT_CB_onError:
        callback = hcc->onError;
        callback_name = "onError";
        break;
    case SW_CLIENT_CB_onClose:
        callback = hcc->onClose;
        callback_name = "onClose";
        break;
    default:
        return;
    }

    //request is not completed
    if (hcc->onResponse && (type == SW_CLIENT_CB_onError || type == SW_CLIENT_CB_onClose))
    {
        int error_code;
        if (type == SW_CLIENT_CB_onError)
        {
            error_code = HTTP_CLIENT_ESTATUS_CONNECT_TIMEOUT;
        }
        else if (hcc->error_flag & HTTP_CLIENT_EFLAG_TIMEOUT)
        {
            error_code = HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT;
        }
        else
        {
            error_code = HTTP_CLIENT_ESTATUS_SERVER_RESET;
        }

        zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("statusCode"), error_code);
        zend_update_property_string(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("body"), "");
        http_client_onResponseException(zobject);
    }
    //callback function is not set
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }
    args[0] = *zobject;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client->%s handler error.", callback_name);
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    //free the callback return value
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
}

/**
 * @zobject: swoole_http_client object
 */
static void http_client_onClose(swClient *cli)
{
    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (http && http->state == HTTP_CLIENT_STATE_WAIT_CLOSE)
    {
        http_client_parser_on_message_complete(&http->parser);
        http_client_property *hcc = swoole_get_property(zobject, 0);
        http_client_onResponseException(zobject);
        sw_zval_free(hcc->onResponse);
        hcc->onResponse = NULL;
    }

    http_client_free(zobject);

    http_client_execute_callback(zobject, SW_CLIENT_CB_onClose);
    zval_ptr_dtor(zobject);
}

static int http_client_onMessage(swConnection *conn, char *data, uint32_t length)
{
    swClient *cli = conn->object;
    zval *zobject = cli->object;
    zval args[2];
    zval *retval;

    zval *zframe;
    SW_MAKE_STD_ZVAL(zframe);
    php_swoole_websocket_frame_unpack(cli->buffer, zframe);

    args[0] = *zobject;
    args[1] = *zframe;

    http_client_property *hcc = swoole_get_property(zobject, 0);
    zval *zcallback = hcc->onMessage;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL)  == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "swoole_http_client->onMessage: onClose handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    //free the callback return value
    if (retval != NULL)
    {
        zval_ptr_dtor(retval);
    }
    zval_ptr_dtor(zframe);

    return SW_OK;
}

/**
 * @zobject: swoole_http_client object
 */
static void http_client_onError(swClient *cli)
{
    zval *zobject = cli->object;
    zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error);
    http_client_free(zobject);
    http_client_execute_callback(zobject, SW_CLIENT_CB_onError);
    zval_ptr_dtor(zobject);
}

static void http_client_onRequestTimeout(swTimer *timer, swTimer_node *tnode)
{
    swClient *cli = (swClient *) tnode->data;
    zval *zobject = (zval *) cli->object;
    zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), ETIMEDOUT);
    zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);

    http_client_property *hcc = swoole_get_property(zobject, 0);
    if (!hcc)
    {
        return;
    }
    hcc->error_flag |= HTTP_CLIENT_EFLAG_TIMEOUT;

    if (cli->buffer && cli->buffer->length > 0) // received something bug not complete
    {
        zval *zheaders = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestHeaders"), 1);
        zval *v;
        if (php_swoole_array_get_value(Z_ARRVAL_P(zheaders), "Connection", v))
        {
            convert_to_string(v);
            if (strcmp(Z_STRVAL_P(v), "Upgrade") == 0) // is upgrade
            {
                hcc->error_flag |= HTTP_CLIENT_EFLAG_UPGRADE;
            }
        }
    }

    zval *retval = NULL;
    sw_zend_call_method_with_0_params(&zobject, swoole_http_client_class_entry_ptr, NULL, "close", &retval);
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void http_client_onResponseException(zval *zobject)
{
    zval args[1];
    zval *retval = NULL;

    http_client_property *hcc = swoole_get_property(zobject, 0);
    if (!hcc)
    {
        return;
    }
    if (!hcc->onResponse)
    {
        return;
    }
    hcc->shutdown = 1;
    zval *zcallback = hcc->onResponse;
    args[0] = *zobject;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onResponse handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void http_client_onReceive(swClient *cli, char *data, uint32_t length)
{
    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return;
    }

    if (http->header_completed == 0)
    {
        swString *buffer = cli->buffer;
        buffer->length += length;

        //HTTP/1.1 200 OK
        if (buffer->length < 16)
        {
            return;
        }
        //No header
        if (swoole_strnpos(buffer->str + buffer->offset, buffer->length - buffer->offset, ZEND_STRL("\r\n\r\n")) < 0)
        {
            if (buffer->length == buffer->size)
            {
                swSysError("Wrong http response.");
                cli->close(cli);
                return;
            }
            buffer->offset = buffer->length - 4 <= 0 ? 0 : buffer->length - 4;
            return;
        }
        else
        {
            http->header_completed = 1;
            data = buffer->str;
            length = buffer->length;
            swString_clear(buffer);
        }
    }

    long parsed_n = swoole_http_parser_execute(&http->parser, &http_parser_settings, data, length);
    if (parsed_n < 0)
    {
        swSysError("Parsing http over socket[%d] failed.", cli->socket->fd);
        cli->close(cli);
        return;
    }

    //not complete
    if (!http->completed)
    {
        return;
    }

    swConnection *conn = cli->socket; // get connection pointer first because it's on Reactor so that it always be safe
    zval *retval = NULL;
    http_client_property *hcc = swoole_get_property(zobject, 0);
    zval *zcallback = hcc->onResponse;
    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client object have not receive callback.");
        return;
    }

    /**
     * TODO: Sec-WebSocket-Accept check
     */
    if (http->upgrade)
    {
        cli->open_length_check = 1;
        cli->protocol.get_package_length = swWebSocket_get_package_length;
        cli->protocol.onPackage = http_client_onMessage;
        cli->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t);
        http->state = HTTP_CLIENT_STATE_UPGRADE;

        //data frame
        if (length > parsed_n + 3)
        {
            cli->buffer->length = length - parsed_n - 1;
            memmove(cli->buffer->str, data + parsed_n + 1, cli->buffer->length);
        }
        else
        {
            swString_clear(cli->buffer);
        }
    }

    http_client_clear(http);
    http_client_reset(http);
    hcc->onResponse = NULL;

    zval args[1];
    args[0] = *zobject;
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL) == FAILURE)
    {
        swoole_php_fatal_error(E_WARNING, "onReactorCallback handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR);
    }
    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    sw_zval_free(zcallback);

    // maybe close in callback, check it
    if (conn->active == 0)
    {
        return;
    }

    if (http->upgrade && cli->buffer->length > 0)
    {
        cli->socket->skip_recv = 1;
        swProtocol_recv_check_length(&cli->protocol, cli->socket, cli->buffer);
        return;
    }

    http_client_check_keep(http);
}

static void http_client_onConnect(swClient *cli)
{
    zval *zobject = cli->object;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return;
    }
    http_client_execute_callback(zobject, SW_CLIENT_CB_onConnect);
    //send http request on write
    http_client_send_http_request(zobject);
}

static int http_client_send_http_request(zval *zobject)
{
    int ret;
    http_client *http = swoole_get_object(zobject);
    if (!http->cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        return SW_ERR;
    }

    if (!http->cli->socket && http->cli->socket->active == 0)
    {
        swoole_php_error(E_WARNING, "server is not connected.");
        return SW_ERR;
    }

    if (http->state != HTTP_CLIENT_STATE_READY)
    {
        swoole_php_error(E_WARNING, "http client is not ready.");
        return SW_ERR;
    }

    http->state = HTTP_CLIENT_STATE_BUSY;
     //clear errno
    SwooleG.error = 0;

    http_client_property *hcc = swoole_get_property(zobject, 0);

    zval *zpost_data = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody"), 1);
    zval *zsend_header = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestHeaders"), 1);
    uint32_t header_flag = 0x0;

    //POST
    if (zpost_data && !ZVAL_IS_NULL(zpost_data))
    {
        if (hcc->request_method == NULL)
        {
            hcc->request_method = "POST";
        }
    }
    //GET
    else
    {
        if (hcc->request_method == NULL)
        {
            hcc->request_method = "GET";
        }
    }

    http->method = swHttp_get_method(hcc->request_method, strlen(hcc->request_method) + 1);

    char *key;
    uint32_t keylen;
    int keytype;
    zval *value = NULL;

    swString_clear(http_client_buffer);
    swString_append_ptr(http_client_buffer, hcc->request_method, strlen(hcc->request_method));
    hcc->request_method = NULL;
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));
#ifdef SW_USE_OPENSSL
    if (http->cli->http_proxy && !http->cli->open_ssl)
#else
    if (http->cli->http_proxy)
#endif
    {
        value = zend_hash_str_find(Z_ARRVAL_P(zsend_header), ZEND_STRL("Host")); //checked before
        char *pre = "http://";
        int len = http->uri_len + Z_STRLEN_P(value) + strlen(pre) + 10;
        void *addr = emalloc(http->uri_len + Z_STRLEN_P(value) + strlen(pre) + 10);
        http->uri_len = snprintf(addr, len, "%s%s:%ld%s", pre, Z_STRVAL_P(value), http->port, http->uri);
        efree(http->uri);
        http->uri = addr;
    }
    swString_append_ptr (http_client_buffer, http->uri, http->uri_len);
    swString_append_ptr(http_client_buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    if (zsend_header && Z_TYPE_P(zsend_header) == IS_ARRAY)
    {
        // As much as possible to ensure that Host is the first header.
        // See: http://tools.ietf.org/html/rfc7230#section-5.4
        if ((value = zend_hash_str_find(Z_ARRVAL_P(zsend_header), ZEND_STRL("Host"))) || (value = zend_hash_str_find(Z_ARRVAL_P(zsend_header), ZEND_STRL("host"))))
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), Z_STRVAL_P(value), Z_STRLEN_P(value));
        }
        else
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
        }

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zsend_header), key, keylen, keytype, value)
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

    zval *zcookies = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("cookies"), 1);
    if (zcookies && Z_TYPE_P(zcookies) == IS_ARRAY)
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("Cookie: "));
        int n_cookie = Z_ARRVAL_P(zcookies)->nNumOfElements;
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zcookies), key, keylen, keytype, value)
            i ++;
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
            encoded_value = sw_php_url_encode( Z_STRVAL_P(value), Z_STRLEN_P(value), &encoded_value_len);
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

    //form-data
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
        if (Z_TYPE_P(zpost_data) == IS_ARRAY && php_swoole_array_length(zpost_data) > 0)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zpost_data), key, keylen, keytype, value)
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
        zval *zpath;
        zval *zfilename;
        zval *zoffset;

        if (hcc->request_upload_files)
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->request_upload_files), key, keylen, keytype, value)
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

        //post data
        if (Z_TYPE_P(zpost_data) == IS_ARRAY && php_swoole_array_length(zpost_data) > 0)
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zpost_data), key, keylen, keytype, value)
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

            //cleanup request body
            zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
        }

        if ((ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0)) < 0)
        {
            goto send_fail;
        }

        if (hcc->request_upload_files)
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->request_upload_files), key, keylen, keytype, value)
                if (!(zname = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("name"))))
                {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("filename"))))
                {
                    continue;
                }
                if (!(zpath = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("path"))))
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
                if (!(zoffset = zend_hash_str_find(Z_ARRVAL_P(value), ZEND_STRL("offset"))))
                {
                    continue;
                }

                n = snprintf(header_buf, sizeof(header_buf), SW_HTTP_FORM_DATA_FORMAT_FILE, (int)(sizeof(boundary_str) - 1),
                        boundary_str, (int)Z_STRLEN_P(zname), Z_STRVAL_P(zname), (int)Z_STRLEN_P(zfilename),
                        Z_STRVAL_P(zfilename), (int)Z_STRLEN_P(ztype), Z_STRVAL_P(ztype));

                if ((ret = http->cli->send(http->cli, header_buf, n, 0)) < 0)
                {
                    goto send_fail;
                }
                if ((ret = http->cli->sendfile(http->cli, Z_STRVAL_P(zpath), Z_LVAL_P(zoffset), Z_LVAL_P(zsize))) < 0)
                {
                    goto send_fail;
                }
                if ((ret = http->cli->send(http->cli, "\r\n", 2, 0)) < 0)
                {
                    goto send_fail;
                }
            SW_HASHTABLE_FOREACH_END();

            zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("uploadFiles"));
            hcc->request_upload_files = NULL;
        }

        n = snprintf(header_buf, sizeof(header_buf), "--%*s--\r\n", (int)(sizeof(boundary_str) - 1), boundary_str);
        if ((ret = http->cli->send(http->cli, header_buf, n, 0)) < 0)
        {
            goto send_fail;
        }
    }
    //x-www-form-urlencoded or raw
    else if (zpost_data && !ZVAL_IS_NULL(zpost_data))
    {
        if (Z_TYPE_P(zpost_data) == IS_ARRAY)
        {
            size_t len;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            if (php_swoole_array_length(zpost_data) > 0) //if it's an empty array, http build will fail
            {
                smart_str formstr_s = { 0 };
                char *formstr = sw_http_build_query(zpost_data, &len, &formstr_s);
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
            //send http header and body
            if ((ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0)) < 0)
            {
                goto send_fail;
            }
            //cleanup request body
            zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
        }
        else if (Z_TYPE_P(zpost_data) == IS_STRING && Z_STRLEN_P(zpost_data) > 0)
        {
            http_client_append_content_length(http_client_buffer, Z_STRLEN_P(zpost_data));
            //send http header
            if ((ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0)) < 0)
            {
                goto send_fail;
            }
            //send http body
            if ((ret = http->cli->send(http->cli, Z_STRVAL_P(zpost_data), Z_STRLEN_P(zpost_data), 0)) < 0)
            {
                goto send_fail;
            }
            //cleanup request body
            zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
        }
        else
        {
            //cleanup request body
            zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody"));
            goto append_crlf;
        }
    }
    //no body
    else
    {
        append_crlf:
        if (header_flag & HTTP_HEADER_CONTENT_LENGTH)
        {
            http_client_append_content_length(http_client_buffer, 0);
        }
        else
        {
            swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
        }
        if ((ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0)) < 0)
        {
            send_fail:
            SwooleG.error = errno;
            swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", http->cli->socket->fd, (int )http_client_buffer->length);
            zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error);
            return SW_ERR;
        }
    }

    if (http->timeout > 0)
    {
        http->timer = swTimer_add(&SwooleG.timer, (int) (http->timeout * 1000), 0, http->cli, http_client_onRequestTimeout);
    }

    swTrace("[%d]: %s\n", (int) http_client_buffer->length, http_client_buffer->str);

    return ret;
}

void http_client_clear(http_client *http)
{
    // clear timeout timer
    if (http->timer)
    {
        swTimer_del(&SwooleG.timer, http->timer);
        http->timer = NULL;
    }

    // Tie up the loose ends
    if (http->download)
    {
        close(http->file_fd);
        http->download = 0;
        http->file_fd = 0;
#ifdef SW_HAVE_ZLIB
        if (http->gzip_buffer)
        {
            swString_free(http->gzip_buffer);
            http->gzip_buffer = NULL;
        }
#endif
    }
#ifdef SW_HAVE_ZLIB
    if (http->gzip)
    {
        inflateEnd(&http->gzip_stream);
        http->gzip = 0;
    }
#endif
}

int http_client_check_keep(http_client *http)
{
    // not keep_alive, try close it actively, and it will destroy the http_client
    if (http->keep_alive == 0 && http->state != HTTP_CLIENT_STATE_WAIT_CLOSE && !http->upgrade)
    {
        zval *zobject = http->cli->object;
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, Z_OBJ_P(zobject)->ce, NULL, "close", &retval);
        if (retval)
        {
            zval_ptr_dtor(retval);
        }
        return 0; // no keep
    }
    else
    {
        return 1; // keep
    }
}

void http_client_reset(http_client *http)
{
    // reset attributes
    http->completed = 0;
    http->header_completed = 0;
    http->state = HTTP_CLIENT_STATE_READY;
}

uint8_t http_client_free(zval *zobject)
{
    http_client *http = swoole_get_object(zobject);
    if (!http)
    {
        return 0;
    }
    if (http->uri)
    {
        efree(http->uri);
    }
    if (http->body)
    {
        swString_free(http->body);
    }

    http_client_clear(http);

    swClient *cli = http->cli;
    if (cli)
    {
        php_swoole_client_free(zobject, cli);
        http->cli = NULL;
    }
    efree(http);

    //unset http_client
    swoole_set_object(zobject, NULL);

    swTraceLog(SW_TRACE_HTTP_CLIENT, "free, object handle=%d.", Z_OBJ_HANDLE_P(zobject));

    return 1;
}

http_client* http_client_create(zval *zobject)
{
    zval *ztmp;
    http_client *http;

    http = (http_client*) emalloc(sizeof(http_client));
    bzero(http, sizeof(http_client));

    swoole_set_object(zobject, http);

    swoole_http_parser_init(&http->parser, PHP_HTTP_RESPONSE);
    http->parser.data = http;

    ztmp = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("host"), 0);
    convert_to_string(ztmp);
    http->host = Z_STRVAL_P(ztmp);
    http->host_len = Z_STRLEN_P(ztmp);

    ztmp = sw_zend_read_property(Z_OBJCE_P(zobject), zobject, ZEND_STRL("port"), 0);
    convert_to_long(ztmp);
    http->port = Z_LVAL_P(ztmp);

    http->timeout = SW_CLIENT_DEFAULT_TIMEOUT;
    http->keep_alive = 1;
    http->state = HTTP_CLIENT_STATE_READY;
    http->object = zobject;
    sw_copy_to_stack(http->object, http->_object);

    swTraceLog(SW_TRACE_HTTP_CLIENT, "create, object handle=%d.", Z_OBJ_HANDLE_P(zobject));

    return http;
}

static PHP_METHOD(swoole_http_client, __construct)
{
    char *host;
    size_t host_len;
    long port = 80;
    zend_bool ssl = SW_FALSE;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|lb", &host, &host_len, &port, &ssl) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (host_len <= 0)
    {
        swoole_php_fatal_error(E_ERROR, "host is empty.");
        RETURN_FALSE;
    }

    if (port <= 0 || port > SW_CLIENT_MAX_PORT)
    {
        swoole_php_fatal_error(E_ERROR, "invalid port.");
        RETURN_FALSE;
    }

    zend_update_property_stringl(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("port"), port);

    //init
    swoole_set_object(getThis(), NULL);

    http_client_property *hcc;
    hcc = (http_client_property*) emalloc(sizeof(http_client_property));
    bzero(hcc, sizeof(http_client_property));
    swoole_set_property(getThis(), 0, hcc);

    int flags = SW_SOCK_TCP | SW_FLAG_ASYNC;

    if (ssl)
    {
#ifdef SW_USE_OPENSSL
        flags |= SW_SOCK_SSL;
#else
        swoole_php_fatal_error(E_ERROR, "require openssl library.");
#endif
    }

    zend_update_property_long(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), flags);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    http_client *http = swoole_get_object(getThis());
    if (http && http->cli)
    {
        zval *zobject = getThis();
        zval *retval = NULL;
        sw_zend_call_method_with_0_params(&zobject, swoole_http_client_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            zval_ptr_dtor(retval);
        }
    }
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc)
    {
        if (hcc->onResponse)
        {
            sw_zval_free(hcc->onResponse);
            hcc->onResponse = NULL;
        }
        efree(hcc);
        swoole_set_property(getThis(), 0, NULL);
    }
}

static PHP_METHOD(swoole_http_client, set)
{
    zval *zset;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zset) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (Z_TYPE_P(zset) != IS_ARRAY)
    {
        RETURN_FALSE;
    }

    zval *zsetting = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setHeaders)
{
    zval *headers;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &headers) == FAILURE)
    {
        RETURN_FALSE;
    }

    zval *zheaders = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1);
    php_array_merge(Z_ARRVAL_P(zheaders), Z_ARRVAL_P(headers));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setCookies)
{
    zval *cookies;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &cookies) == FAILURE)
    {
        RETURN_FALSE;
    }

    zval *zcookies = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("cookies"), 1);
    php_array_merge(Z_ARRVAL_P(zcookies), Z_ARRVAL_P(cookies));

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setData)
{
    zval *data;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &data) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (http_client_check_data(data) < 0)
    {
        RETURN_FALSE;
    }
    if (Z_TYPE_P(data) == IS_ARRAY)
    {
        zval *zbody = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1);
        php_array_merge(Z_ARRVAL_P(zbody), Z_ARRVAL_P(data));
    }
    else
    {
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, addFile)
{
    char *path;
    size_t l_path;
    char *name;
    size_t l_name;
    char *type = NULL;
    size_t l_type;
    char *filename = NULL;
    size_t l_filename;
    long offset = 0;
    long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|ssll", &path, &l_path, &name, &l_name, &type, &l_type,
            &filename, &l_filename, &offset, &length) == FAILURE)
    {
        return;
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

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    zval *files;
    if (!hcc->request_upload_files)
    {
        SW_MAKE_STD_ZVAL(files);
        array_init(files);
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), files);
        zval_ptr_dtor(files);

        hcc->request_upload_files = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("uploadFiles"), 0);
        sw_copy_to_stack(hcc->request_upload_files, hcc->_request_upload_files);
    }

    zval *upload_file;
    SW_MAKE_STD_ZVAL(upload_file);
    array_init(upload_file);

    add_assoc_stringl_ex(upload_file, ZEND_STRL("path"), path, l_path);
    add_assoc_stringl_ex(upload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(upload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(upload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(upload_file, "size", length);
    add_assoc_long(upload_file, "offset", offset);

    add_next_index_zval(hcc->request_upload_files, upload_file);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setMethod)
{
    char *method;
    size_t length = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &method, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    int http_method = swHttp_get_method(method, length + 1);
    if (length == 0 || http_method < 0)
    {
        swoole_php_error(E_WARNING, "invalid http method.");
        RETURN_FALSE;
    }

    const char *http_method_str = swHttp_get_method_string(http_method);
    if (http_method_str == NULL)
    {
        RETURN_FALSE;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    hcc->request_method = (char *) http_method_str;
    zend_update_property_string(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestMethod"),
            (char *) http_method_str);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, isConnected)
{
    http_client *http = swoole_get_object(getThis());
    if (!http || !http->cli)
    {
        RETURN_FALSE;
    }
    if (!http->cli->socket)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(http->cli->socket->active);
}

static PHP_METHOD(swoole_http_client, close)
{
    http_client *http = swoole_get_object(getThis());
    if (!http)
    {
        RETURN_FALSE;
    }
    swClient *cli = http->cli;
    if (!cli)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_http_client.");
        RETURN_FALSE;
    }
    if (!cli->socket)
    {
        swoole_php_error(E_WARNING, "not connected to the server");
        RETURN_FALSE;
    }
    if (cli->socket->closed)
    {
        swoole_php_error(E_WARNING, "client socket is closed.");
        RETURN_FALSE;
    }
    int ret = SW_OK;
    if (!cli->keep || swConnection_error(SwooleG.error) == SW_CLOSE)
    {
        ret = cli->close(cli);
    }
    else
    {
        //unset object
        swoole_set_object(getThis(), NULL);
    }
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, on)
{
    char *cb_name;
    size_t cb_name_len;
    zval *zcallback;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &cb_name, &cb_name_len, &zcallback) == FAILURE)
    {
        RETURN_FALSE;
    }

#ifdef PHP_SWOOLE_CHECK_CALLBACK
    char *func_name = NULL;
    if (!sw_zend_is_callable(zcallback, 0, &func_name))
    {
        swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        return;
    }
    efree(func_name);
#endif

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (strncasecmp("error", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("onError"), zcallback);
        hcc->onError = sw_zend_read_property(swoole_http_client_class_entry_ptr,  getThis(), ZEND_STRL("onError"), 0);
        sw_copy_to_stack(hcc->onError, hcc->_onError);
    }
    else if (strncasecmp("connect", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("onConnect"), zcallback);
        hcc->onConnect = sw_zend_read_property(swoole_http_client_class_entry_ptr,  getThis(), ZEND_STRL("onConnect"), 0);
        sw_copy_to_stack(hcc->onConnect, hcc->_onConnect);
    }
    else if (strncasecmp("close", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("onClose"), zcallback);
        hcc->onClose = sw_zend_read_property(swoole_http_client_class_entry_ptr,  getThis(), ZEND_STRL("onClose"), 0);
        sw_copy_to_stack(hcc->onClose, hcc->_onClose);
    }
    else if (strncasecmp("message", cb_name, cb_name_len) == 0)
    {
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("onMessage"), zcallback);
        hcc->onMessage = sw_zend_read_property(swoole_http_client_class_entry_ptr,  getThis(), ZEND_STRL("onMessage"), 0);
        sw_copy_to_stack(hcc->onMessage, hcc->_onMessage);
    }
    else
    {
        swoole_php_fatal_error(E_WARNING, "swoole_http_client: event callback[%s] is unknow", cb_name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

/**
 * Http Parser Callback
 */
int http_client_parser_on_header_field(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    http->tmp_header_field_name = (char *) at;
    http->tmp_header_field_name_len = length;
    return 0;
}

int http_client_parser_on_header_value(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->object;
    zval *zheaders = sw_zend_read_property_array(Z_OBJCE_P(zobject), zobject, ZEND_STRL("headers"), 1);

    char *header_name = zend_str_tolower_dup(http->tmp_header_field_name, http->tmp_header_field_name_len);
    add_assoc_stringl_ex(zheaders, header_name, http->tmp_header_field_name_len, (char *) at, length);

    //websocket client
    if (strcasecmp(header_name, "Upgrade") == 0 && strncasecmp(at, "websocket", length) == 0)
    {
        http->upgrade = 1;
    }
    else if (strcasecmp(header_name, "Set-Cookie") == 0)
    {
        zval *zcookies = sw_zend_read_property_array(Z_OBJCE_P(zobject), zobject, ZEND_STRL("cookies"), 1);
        zval *zset_cookie_headers = sw_zend_read_property_array(Z_OBJCE_P(zobject), zobject, ZEND_STRL("set_cookie_headers"), 1);
        if (SW_OK != http_parse_set_cookies(at, length, zcookies, zset_cookie_headers))
        {
            efree(header_name);
            return SW_ERR;
        }
    }
#ifdef SW_HAVE_ZLIB
    else if (strcasecmp(header_name, "Content-Encoding") == 0 && strncasecmp(at, "gzip", length) == 0)
    {
        http_init_gzip_stream(http);
        if (Z_OK != inflateInit2(&http->gzip_stream, MAX_WBITS + 16))
        {
            efree(header_name);
            swWarn("inflateInit2() failed.");
            return SW_ERR;
        }
    }
    else if (strcasecmp(header_name, "Content-Encoding") == 0 && strncasecmp(at, "deflate", length) == 0)
    {
        http_init_gzip_stream(http);
        if (Z_OK != inflateInit(&http->gzip_stream))
        {
            efree(header_name);
            swWarn("inflateInit() failed.");
            return SW_ERR;
        }
    }
#endif
    else if (strcasecmp(header_name, "Transfer-Encoding") == 0 && strncasecmp(at, "chunked", length) == 0)
    {
        http->chunked = 1;
    }
    efree(header_name);
    return 0;
}

#ifdef SW_HAVE_ZLIB
/**
 * init zlib stream
 */
static void http_init_gzip_stream(http_client *http)
{
    http->gzip = 1;
    memset(&http->gzip_stream, 0, sizeof(http->gzip_stream));
    if (http->download)
    {
        http->gzip_buffer = swString_new(8192);
    }
    else
    {
        http->gzip_buffer = swoole_zlib_buffer;
    }
    http->gzip_stream.zalloc = php_zlib_alloc;
    http->gzip_stream.zfree = php_zlib_free;
}

int http_response_uncompress(z_stream *stream, swString *buffer, char *body, int length)
{
    int status = 0;

    stream->avail_in = length;
    stream->next_in = (Bytef *) body;
    stream->total_in = 0;
    stream->total_out = 0;

#if 0
    printf(SW_START_LINE"\nstatus=%d\tavail_in=%ld,\tavail_out=%ld,\ttotal_in=%ld,\ttotal_out=%ld\n", status,
            stream->avail_in, stream->avail_out, stream->total_in, stream->total_out);
#endif

    swString_clear(buffer);

    while (1)
    {
        stream->avail_out = buffer->size - buffer->length;
        stream->next_out = (Bytef *) (buffer->str + buffer->length);

        status = inflate(stream, Z_SYNC_FLUSH);

#if 0
        printf("status=%d\tavail_in=%ld,\tavail_out=%ld,\ttotal_in=%ld,\ttotal_out=%ld,\tlength=%ld\n", status,
                stream->avail_in, stream->avail_out, stream->total_in, stream->total_out, buffer->length);
#endif
        if (status >= 0)
        {
            buffer->length = stream->total_out;
        }
        if (status == Z_STREAM_END)
        {
            return SW_OK;
        }
        else if (status == Z_OK)
        {
            if (buffer->length + 4096 >= buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    return SW_ERR;
                }
            }
            if (stream->avail_in == 0)
            {
                return SW_OK;
            }
        }
        else
        {
            return SW_ERR;
        }
    }
    return SW_ERR;
}
#endif

int http_client_parser_on_body(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    if (swString_append_ptr(http->body, at, length) < 0)
    {
        return -1;
    }
    if (http->download)
    {
#ifdef SW_HAVE_ZLIB
        if (http->gzip)
        {
            if (http_response_uncompress(&http->gzip_stream, http->gzip_buffer, http->body->str, http->body->length) != SW_OK)
            {
                return -1;
            }
            if (swoole_sync_writefile(http->file_fd, http->gzip_buffer->str, http->gzip_buffer->length) < 0)
            {
                return -1;
            }
        }
        else
#endif
        {
            if (swoole_sync_writefile(http->file_fd, (void*) http->body->str, http->body->length) < 0)
            {
                return -1;
            }
        }
        swString_clear(http->body);
    }
    return 0;
}

enum flags
{
    F_CONNECTION_CLOSE = 1 << 2,
};

int http_client_parser_on_headers_complete(swoole_http_parser *parser)
{
    http_client* http = (http_client*) parser->data;
    //no content-length
    if (http->chunked == 0 && parser->content_length == -1)
    {
        http->state = HTTP_CLIENT_STATE_WAIT_CLOSE;
        parser->flags |= F_CONNECTION_CLOSE;
    }
    if (http->method == HTTP_HEAD || parser->status_code == SW_HTTP_NO_CONTENT)
    {
        return 1;
    }
    return 0;
}

int http_client_parser_on_message_complete(swoole_http_parser *parser)
{
    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->object;

    if (parser->upgrade && !http->upgrade)
    {
        // not support, continue.
        parser->upgrade = 0;
        return 0;
    }

#ifdef SW_HAVE_ZLIB
    if (http->gzip && http->body->length > 0)
    {
        if (http_response_uncompress(&http->gzip_stream, http->gzip_buffer, http->body->str, http->body->length) == SW_ERR)
        {
            swWarn("http_response_uncompress failed.");
            return 0;
        }
        zend_update_property_stringl(Z_OBJCE_P(zobject), zobject, ZEND_STRL("body"), http->gzip_buffer->str, http->gzip_buffer->length);
    }
    else
#endif
    {
        zend_update_property_stringl(Z_OBJCE_P(zobject), zobject, ZEND_STRL("body"), http->body->str, http->body->length);
    }

    http->completed = 1;

    //http status code
    zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("statusCode"), http->parser.status_code);

    if (parser->upgrade)
    {
        // return 1 will finish the parser and means yes we support it.
        return 1;
    }
    else
    {
        return 0;
    }
}
/**
 * Http Parser End
 */

static PHP_METHOD(swoole_http_client, execute)
{
    int ret;
    char *uri = NULL;
    size_t uri_len = 0;
    zval *finish_cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        RETURN_FALSE;
    }
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->shutdown)
    {
        swoole_php_error(E_WARNING, "Connection failed, the server was unavailable.");
        return;
    }
    ret = http_client_execute(getThis(), uri, uri_len, finish_cb);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, get)
{
    int ret;
    char *uri = NULL;
    size_t uri_len = 0;
    zval *finish_cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        RETURN_FALSE;
    }
    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->shutdown)
    {
        swoole_php_error(E_WARNING, "Connection failed, the server was unavailable.");
        return;
    }
    ret = http_client_execute(getThis(), uri, uri_len, finish_cb);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, download)
{
    int ret;
    char *uri = NULL;
    size_t uri_len = 0;
    zval *finish_cb;
    zval *download_file;
    off_t offset = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "szz|l", &uri, &uri_len, &download_file, &finish_cb, &offset) == FAILURE)
    {
        RETURN_FALSE;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->shutdown)
    {
        swoole_php_error(E_WARNING, "Connection failed, the server was unavailable.");
        return;
    }
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("downloadFile"), download_file);
    hcc->download_file = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("downloadFile"), 1);
    hcc->download_offset = offset;
    sw_copy_to_stack(hcc->download_file, hcc->_download_file);
    ret = http_client_execute(getThis(), uri, uri_len, finish_cb);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, post)
{
    int ret;
    char *uri = NULL;
    size_t uri_len = 0;
    zval *callback;
    zval *data;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "szz", &uri, &uri_len, &data, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (http_client_check_data(data) < 0)
    {
        RETURN_FALSE;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->shutdown)
    {
        swoole_php_error(E_WARNING, "Connection failed, the server was unavailable.");
        return;
    }
    if (Z_TYPE_P(data) == IS_ARRAY)
    {
        zval *zbody = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1);
        php_array_merge(Z_ARRVAL_P(zbody), Z_ARRVAL_P(data));
    }
    else
    {
        zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data);
    }
    ret = http_client_execute(getThis(), uri, uri_len, callback);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, upgrade)
{
    int ret;
    char *uri = NULL;
    size_t uri_len = 0;
    zval *finish_cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &uri, &uri_len, &finish_cb) == FAILURE)
    {
        RETURN_FALSE;
    }

    http_client_property *hcc = swoole_get_property(getThis(), 0);
    if (hcc->shutdown)
    {
        swoole_php_error(E_WARNING, "Connection failed, the server was unavailable.");
        return;
    }
    if (!hcc->onMessage)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use the upgrade method, must first register the onMessage event callback.");
        return;
    }

    zval *zheaders = sw_zend_read_property_array(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1);

    char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
    http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);

    add_assoc_string(zheaders, "Connection", "Upgrade");
    add_assoc_string(zheaders, "Upgrade", "websocket");
    add_assoc_string(zheaders, "Sec-WebSocket-Version", SW_WEBSOCKET_VERSION);

    zend_string *str = php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH);
    add_assoc_str_ex(zheaders, ZEND_STRL("Sec-WebSocket-Key"), str);

    ret = http_client_execute(getThis(), uri, uri_len, finish_cb);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, push)
{
    zval *zdata = NULL;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zend_bool fin = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|lb", &zdata, &opcode, &fin) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (unlikely(opcode > SW_WEBSOCKET_OPCODE_MAX))
    {
        swoole_php_fatal_error(E_WARNING, "the maximum value of opcode is %d.", SW_WEBSOCKET_OPCODE_MAX);
        SwooleG.error = SW_ERROR_WEBSOCKET_BAD_OPCODE;
        RETURN_FALSE;
    }

    http_client *http = swoole_get_object(getThis());
    if (!(http && http->cli && http->cli->socket))
    {
        http_client_property *hcc = swoole_get_property(getThis(), 0);
        if (hcc->error_flag & HTTP_CLIENT_EFLAG_UPGRADE)
        {
            swoole_php_fatal_error(E_WARNING, "websocket handshake failed, cannot push data.");
            SwooleG.error = SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED;
            RETURN_FALSE;
        }
        else
        {
            swoole_php_error(E_WARNING, "not connected to the server");
            SwooleG.error = SW_ERROR_WEBSOCKET_UNCONNECTED;
            RETURN_FALSE;
        }
    }

    swString_clear(http_client_buffer);
    if (php_swoole_websocket_frame_pack(http_client_buffer, zdata, opcode, fin, http->websocket_mask) < 0)
    {
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0));
}
