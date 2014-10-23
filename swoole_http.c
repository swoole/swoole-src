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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include <ext/standard/url.h>
#include "thirdparty/php_http_parser.h"

zend_class_entry swoole_http_server_ce;
zend_class_entry *swoole_http_server_class_entry_ptr;

zend_class_entry swoole_http_channel_ce;
zend_class_entry *swoole_http_channel_class_entry_ptr;

zend_class_entry swoole_http_request_ce;
zend_class_entry *swoole_http_request_class_entry_ptr;

static zval* php_sw_http_server_callbacks[2];
static swHashMap *php_sw_http_channels;

static int php_swoole_http_onReceive(swFactory *factory, swEventData *req);

static int php_swoole_http_request_on_path(php_http_parser *parser, const char *at, size_t length);
static int php_swoole_http_request_on_query_string(php_http_parser *parser, const char *at, size_t length);
static int php_swoole_http_request_on_url(php_http_parser *parser, const char *at, size_t length);

static int php_swoole_http_request_on_body(php_http_parser *parser, const char *at, size_t length);
static int php_swoole_http_request_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int php_swoole_http_request_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int php_swoole_http_request_on_headers_complete(php_http_parser *parser);
static int php_swoole_http_request_message_complete(php_http_parser *parser);

static const php_http_parser_settings php_sw_http_parser_settings =
{
    NULL,
    php_swoole_http_request_on_path,
    php_swoole_http_request_on_query_string,
    php_swoole_http_request_on_url,
    NULL,
    php_swoole_http_request_on_header_field,
    php_swoole_http_request_on_header_value,
    php_swoole_http_request_on_headers_complete,
    php_swoole_http_request_on_body,
    php_swoole_http_request_message_complete
};

const zend_function_entry swoole_http_server_methods[] =
{
    PHP_ME(swoole_http_server, on,         NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server, start,      NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_http_channel_methods[] =
{
    PHP_ME(swoole_http_channel, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_channel, cookie, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_channel, header, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_channel, response, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_channel, message, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

typedef struct php_swoole_http_request
{
    enum php_http_method request_method;
    int protocol_version;
    char *request_uri;
    size_t request_uri_len;
    char *vpath;
    size_t vpath_len;
    char *path_translated;
    size_t path_translated_len;
    char *path_info;
    size_t path_info_len;
    char *query_string;
    size_t query_string_len;
    zval* headers;
    char *content;
    size_t content_len;
    const char *ext;
    size_t ext_len;
} php_swoole_http_request;

typedef struct php_swoole_http_channel
{
    int fd;
    uint16_t from_id;
    zval *object;

    php_http_parser parser;
    unsigned int request_read :1;
    char *current_header_name;
    size_t current_header_name_len;
    unsigned int current_header_name_allocated :1;
    php_swoole_http_request request;
    unsigned int content_sender_initialized :1;
} php_swoole_http_channel;

static int php_swoole_http_request_on_path(php_http_parser *parser, const char *at, size_t length)
{
    php_swoole_http_channel *client = parser->data;
    client->request.vpath = estrndup(at, length);
    client->request.vpath_len = length;
    return 0;
}

static int php_swoole_http_request_on_query_string(php_http_parser *parser, const char *at, size_t length)
{
    php_swoole_http_channel *client = parser->data;
    client->request.query_string = estrndup(at, length);
    client->request.query_string_len = length;
    return 0;
}

static int php_swoole_http_request_on_url(php_http_parser *parser, const char *at, size_t length)
{
    php_swoole_http_channel *client = parser->data;
    client->request.request_method = parser->method;
    client->request.request_uri = estrndup(at, length);
    client->request.request_uri_len = length;
    return 0;
}

static int php_swoole_http_request_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
    php_swoole_http_channel *client = parser->data;
    if (client->current_header_name_allocated) {
        pefree(client->current_header_name, 1);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = (char *)at;
    client->current_header_name_len = length;
    return 0;
}

static int php_swoole_http_request_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
    php_swoole_http_channel *client = parser->data;
    char *value = pestrndup(at, length, 1);
    if (!value)
    {
        return 1;
    }

    char *header_name = zend_str_tolower_dup(client->current_header_name, client->current_header_name_len);
    add_assoc_stringl_ex(client->request.headers, header_name, client->current_header_name_len + 1, value, strlen(value), 1);
    efree(header_name);

    if (client->current_header_name_allocated)
    {
        pefree(client->current_header_name, 1);
        client->current_header_name_allocated = 0;
    }
    return 0;
}

static int php_swoole_http_request_on_headers_complete(php_http_parser *parser)
{
    php_swoole_http_channel *client = parser->data;
    if (client->current_header_name_allocated)
    {
        pefree(client->current_header_name, 1);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = NULL;
    return 0;
}

static int php_swoole_http_request_on_body(php_http_parser *parser, const char *at, size_t length)
{
    php_swoole_http_channel *client = parser->data;
    if (!client->request.content)
    {
        client->request.content = emalloc(parser->content_length);
        if (!client->request.content)
        {
            return -1;
        }
        client->request.content_len = 0;
    }
    client->request.content = erealloc(client->request.content, client->request.content_len + length);
    memmove(client->request.content + client->request.content_len, at, length);
    client->request.content_len += length;

    return 0;
}

static int php_swoole_http_request_message_complete(php_http_parser *parser)
{
    php_swoole_http_channel *client = parser->data;
    client->request.protocol_version = parser->http_major * 100 + parser->http_minor;

    const char *vpath = client->request.vpath, *end = vpath + client->request.vpath_len, *p = end;
    client->request.ext = end;
    client->request.ext_len = 0;
    while (p > vpath)
    {
        --p;
        if (*p == '.')
        {
            ++p;
            client->request.ext = p;
            client->request.ext_len = end - p;
            break;
        }
    }
    client->request_read = 1;
    return 0;
}

static int php_swoole_http_onReceive(swFactory *factory, swEventData *req)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    zval *zchannel;
    int fd = req->info.fd;
    php_swoole_http_channel *channel = swHashMap_find_int(php_sw_http_channels, fd);

    if (!channel)
    {
        channel = emalloc(sizeof(php_swoole_http_channel));
        bzero(channel, sizeof(php_swoole_http_channel));
        channel->fd = fd;
        channel->from_id = req->info.from_id;
        swHashMap_add_int(php_sw_http_channels, fd, channel, NULL);

        MAKE_STD_ZVAL(zchannel);
        object_init_ex(zchannel, swoole_http_channel_class_entry_ptr TSRMLS_CC);

        channel->object = zchannel;
        zend_update_property_long(swoole_http_channel_class_entry_ptr, zchannel, ZEND_STRL("fd"), fd TSRMLS_CC);
    }
    else
    {
        zchannel = channel->object;
    }
    php_http_parser *parser = &channel->parser;

    parser->data = channel;
    php_http_parser_init(parser, PHP_HTTP_REQUEST);

    MAKE_STD_ZVAL(channel->request.headers);
    array_init(channel->request.headers);

    zval *zdata = php_swoole_get_data(req TSRMLS_CC);
    size_t n = php_http_parser_execute(parser, &php_sw_http_parser_settings, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    if (n < 0)
    {
        swWarn("error");
    }
    else
    {
        zval *zrequest;
        zval *retval;
        zval **args[2];

        MAKE_STD_ZVAL(zrequest);
        object_init_ex(zrequest, swoole_http_request_class_entry_ptr TSRMLS_CC);

        zend_update_property(swoole_http_request_class_entry_ptr, zrequest, ZEND_STRL("header"), channel->request.headers TSRMLS_CC);

        args[0] = &zchannel;
        args[1] = &zrequest;

        if (call_user_function_ex(EG(function_table), NULL, php_sw_http_server_callbacks[0], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onRequest handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
        }
    }
    return SW_OK;
}

void swoole_http_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http_server_ce, "swoole_http_server", swoole_http_server_methods);
    swoole_http_server_class_entry_ptr = zend_register_internal_class_ex(&swoole_http_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_http_channel_ce, "swoole_http_channel", swoole_http_channel_methods);
    swoole_http_channel_class_entry_ptr = zend_register_internal_class(&swoole_http_channel_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_http_channel_ce, "swoole_http_request", NULL);
    swoole_http_request_class_entry_ptr = zend_register_internal_class(&swoole_http_request_ce TSRMLS_CC);
}

PHP_METHOD(swoole_http_server, on)
{
    zval *callback;
    char *event_name;
    swServer *serv;
    int len;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &event_name, &len, &callback) == FAILURE)
    {
        return;
    }

    SWOOLE_GET_SERVER(getThis(), serv);

    char *func_name = NULL;
    if (!zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    if (strncasecmp("request", event_name, len) == 0)
    {
        zval_add_ref(&callback);
        php_sw_http_server_callbacks[0] = callback;
    }
    else if (strncasecmp("message", event_name, len) == 0)
    {
        zval_add_ref(&callback);
        php_sw_http_server_callbacks[1] = callback;
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Unknown event types[%s]", event_name);
        RETURN_FALSE;
    }
}

static void php_swoole_http_channel_free(void *channel)
{
    efree(channel);
}

static void php_swoole_http_request_free(php_swoole_http_request *req) /* {{{ */
{
    if (req->request_uri)
    {
        efree(req->request_uri);
    }
    if (req->vpath)
    {
        efree(req->vpath);
    }
    if (req->path_translated)
    {
        efree(req->path_translated);
    }
    if (req->path_info)
    {
        efree(req->path_info);
    }
    if (req->query_string)
    {
        efree(req->query_string);
    }
    zval_ptr_dtor(&req->headers);
    if (req->content)
    {
        efree(req->content);
    }
    bzero(req, sizeof(php_swoole_http_request));
}

PHP_METHOD(swoole_http_server, start)
{
    swServer *serv;
    int ret;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to execute swoole_server::start.");
        RETURN_FALSE;
    }

    SWOOLE_GET_SERVER(getThis(), serv);
    php_swoole_register_callback(serv);

    if (php_sw_http_server_callbacks[0] == NULL)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "require onRequest callback");
        RETURN_FALSE;
    }

    serv->dispatch_mode = SW_DISPATCH_QUEUE;
    serv->onReceive = php_swoole_http_onReceive;
    serv->open_http_protocol = 1;

    serv->ptr2 = getThis();

    php_sw_http_channels = swHashMap_new(1024, php_swoole_http_channel_free);

    ret = swServer_create(serv);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "create server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    zend_update_property_long(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("master_pid"), getpid() TSRMLS_CC);
    ret = swServer_start(serv);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "start server failed. Error: %s", sw_error);
        RETURN_LONG(ret);
    }
    RETURN_TRUE;
}

PHP_METHOD(swoole_http_channel, close)
{

}

PHP_METHOD(swoole_http_channel, response)
{
    swString body;
    body.length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &body.str, &body.length) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_channel_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);

    char content_length[128];
    swString *response = swString_new(body.length + 1024);
    swString_append_ptr(response, ZEND_STRL("HTTP/1.1 200 OK\r\nServer: swoole-http-server\r\nCContent-Type: text/html\r\nConnection: keep-alive\r\n"));

    int n = snprintf(content_length, 128, "Content-Length: %d\r\n\r\n", body.length);
    swString_append_ptr(response, content_length, n);
    swString_append(response, &body);

    int ret = swServer_tcp_send(SwooleG.serv, Z_LVAL_P(zfd), response->str, response->length);

    php_swoole_http_channel *channel = swHashMap_find_int(php_sw_http_channels, Z_LVAL_P(zfd));

    swString_free(response);

    php_swoole_http_request_free(&channel->request);
    SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_http_channel, cookie)
{

}

PHP_METHOD(swoole_http_channel, header)
{

}

PHP_METHOD(swoole_http_channel, message)
{

}

