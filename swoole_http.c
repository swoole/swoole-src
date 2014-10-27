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
#include <ext/date/php_date.h>
#include <main/php_variables.h>

#include "thirdparty/php_http_parser.h"

typedef struct
{
    enum php_http_method method;
    int version;
    char *request_uri;
    size_t request_uri_len;
    char *vpath;
    size_t vpath_len;
    const char *ext;
    size_t ext_len;
    zval *content;
} http_request;

typedef struct
{
    enum php_http_method method;
    int version;
    int status;
    swString *cookie;
} http_response;

typedef struct
{
    int fd;
    http_request request;
    http_response response;

    zval *zresponse;
    zval *zrequest;

    php_http_parser parser;
    unsigned int request_read :1;
    char *current_header_name;
    size_t current_header_name_len;
    unsigned int current_header_name_allocated :1;
    unsigned int content_sender_initialized :1;
} http_channel;

zend_class_entry swoole_http_server_ce;
zend_class_entry *swoole_http_server_class_entry_ptr;

zend_class_entry swoole_http_response_ce;
zend_class_entry *swoole_http_response_class_entry_ptr;

zend_class_entry swoole_http_request_ce;
zend_class_entry *swoole_http_request_class_entry_ptr;

static zval* php_sw_http_server_callbacks[2];
static swHashMap *php_sw_http_channels;

static int http_onReceive(swFactory *factory, swEventData *req);
static void http_onClose(swServer *serv, int fd, int from_id);

static int http_request_on_path(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_query_string(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_url(php_http_parser *parser, const char *at, size_t length);

static int http_request_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_request_on_headers_complete(php_http_parser *parser);
static int http_request_message_complete(php_http_parser *parser);

static void http_channel_free(void *channel);
static void http_request_free(http_channel *channel);
static http_channel* http_channel_new(int fd TSRMLS_DC);

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    http_request_on_path,
    http_request_on_query_string,
    http_request_on_url,
    NULL,
    http_request_on_header_field,
    http_request_on_header_value,
    http_request_on_headers_complete,
    http_request_on_body,
    http_request_message_complete
};

const zend_function_entry swoole_http_server_methods[] =
{
    PHP_ME(swoole_http_server, on,         NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_server, start,      NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry swoole_http_response_methods[] =
{
    PHP_ME(swoole_http_response, cookie, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, status, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, header, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, end, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, message, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int http_request_on_path(php_http_parser *parser, const char *at, size_t length)
{
    http_channel *client = parser->data;
    client->request.vpath = estrndup(at, length);
    client->request.vpath_len = length;

    return 0;
}

static int http_request_on_query_string(php_http_parser *parser, const char *at, size_t length)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    http_channel *channel = parser->data;
    char *query = estrndup(at, length);

    zval *get;
    MAKE_STD_ZVAL(get);
    array_init(get);
    zend_update_property(swoole_http_request_class_entry_ptr, channel->zrequest, ZEND_STRL("get"), get TSRMLS_CC);
    sapi_module.treat_data(PARSE_STRING, query, get TSRMLS_CC);

    return 0;
}

static int http_request_on_url(php_http_parser *parser, const char *at, size_t length)
{
    http_channel *client = parser->data;
    client->request.method = parser->method;
    client->request.request_uri = estrndup(at, length);
    client->request.request_uri_len = length;
    return 0;
}

static int http_request_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
    http_channel *client = parser->data;
    if (client->current_header_name_allocated)
    {
        efree(client->current_header_name);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = (char *)at;
    client->current_header_name_len = length;
    return 0;
}

static int http_request_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    http_channel *channel = parser->data;
    char *header_name = zend_str_tolower_dup(channel->current_header_name, channel->current_header_name_len);

    if (strncmp(header_name, "cookie", 6) == 0)
    {
        zval *cookie;
        MAKE_STD_ZVAL(cookie);
        array_init(cookie);
        zend_update_property(swoole_http_request_class_entry_ptr, channel->zrequest, ZEND_STRL("cookie"), cookie TSRMLS_CC);

        struct
        {
            char *k;
            int klen;
            char *v;
            int vlen;
        } kv = { 0 };

        char *_c = (char *) at;
        int n = 1;
        kv.k = _c;

        while (_c < at + length)
        {
            if (*_c == '=')
            {
                kv.v = _c + 1;
                kv.klen = n;
                n = 0;
            }
            else if (*_c == ';')
            {
                kv.vlen = n;
                add_assoc_stringl_ex(cookie, kv.k, kv.klen, kv.v, kv.vlen, 1);
                kv.k = _c + 2;
                n = 0;
            }
            else
            {
                n++;
            }
            _c++;
        }
        kv.vlen = n;
        add_assoc_stringl_ex(cookie, kv.k, kv.klen, kv.v, kv.vlen, 1);
    }
    else
    {
        zval *header = zend_read_property(swoole_http_request_class_entry_ptr, channel->zrequest, ZEND_STRL("header"), 1 TSRMLS_CC);
        add_assoc_stringl_ex(header, header_name, channel->current_header_name_len + 1, (char *) at, length, 1);
    }

    if (channel->current_header_name_allocated)
    {
        efree(channel->current_header_name);
        channel->current_header_name_allocated = 0;
    }
    efree(header_name);
    return 0;
}

static int http_request_on_headers_complete(php_http_parser *parser)
{
    http_channel *client = parser->data;
    if (client->current_header_name_allocated)
    {
        efree(client->current_header_name);
        client->current_header_name_allocated = 0;
    }
    client->current_header_name = NULL;
    return 0;
}

static int http_request_on_body(php_http_parser *parser, const char *at, size_t length)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    http_channel *channel = parser->data;
    char *body = estrndup(at, length);

    zval *post;
    MAKE_STD_ZVAL(post);
    array_init(post);
    zend_update_property(swoole_http_request_class_entry_ptr, channel->zrequest, ZEND_STRL("post"), post TSRMLS_CC);
    sapi_module.treat_data(PARSE_STRING, body, post TSRMLS_CC);

    return 0;
}

static int http_request_message_complete(php_http_parser *parser)
{
    http_channel *client = parser->data;
    client->request.version = parser->http_major * 100 + parser->http_minor;

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

static void http_onClose(swServer *serv, int fd, int from_id)
{
    swHashMap_del_int(php_sw_http_channels, fd);
}

static int http_onReceive(swFactory *factory, swEventData *req)
{
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);

    int fd = req->info.fd;
    http_channel *channel = swHashMap_find_int(php_sw_http_channels, fd);

    if (!channel)
    {
        channel = http_channel_new(fd TSRMLS_CC);
    }
    php_http_parser *parser = &channel->parser;

    zval *zrequest;
    MAKE_STD_ZVAL(zrequest);
    object_init_ex(zrequest, swoole_http_request_class_entry_ptr TSRMLS_CC);

    zval *header;
    MAKE_STD_ZVAL(header);

    //request header
    array_init(header);
    zend_update_property(swoole_http_request_class_entry_ptr, zrequest, ZEND_STRL("header"), header TSRMLS_CC);

    zval *zresponse;
    MAKE_STD_ZVAL(zresponse);
    object_init_ex(zresponse, swoole_http_response_class_entry_ptr TSRMLS_CC);
    //socket fd
    zend_update_property_long(swoole_http_response_class_entry_ptr, zresponse, ZEND_STRL("fd"), fd TSRMLS_CC);

    channel->zresponse = zresponse;
    channel->zrequest = zrequest;

    parser->data = channel;
    php_http_parser_init(parser, PHP_HTTP_REQUEST);

    zval *zdata = php_swoole_get_data(req TSRMLS_CC);
    size_t n = php_http_parser_execute(parser, &http_parser_settings, Z_STRVAL_P(zdata), Z_STRLEN_P(zdata));
    if (n < 0)
    {
        zval_ptr_dtor(&zdata);
        swWarn("php_http_parser_execute failed.");
    }
    else
    {
        zval *retval;
        zval **args[2];

        args[0] = &zrequest;
        args[1] = &zresponse;

        channel->request.content = zdata;

        if (call_user_function_ex(EG(function_table), NULL, php_sw_http_server_callbacks[0], &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onRequest handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_WARNING TSRMLS_CC);
        }
        if (retval)
        {
            zval_ptr_dtor(&retval);
        }
    }
    return SW_OK;
}

void swoole_http_init(int module_number TSRMLS_DC)
{
    INIT_CLASS_ENTRY(swoole_http_server_ce, "swoole_http_server", swoole_http_server_methods);
    swoole_http_server_class_entry_ptr = zend_register_internal_class_ex(&swoole_http_server_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_http_response_ce, "swoole_http_response", swoole_http_response_methods);
    swoole_http_response_class_entry_ptr = zend_register_internal_class(&swoole_http_response_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(swoole_http_response_ce, "swoole_http_request", NULL);
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

static void http_channel_free(void *channel)
{
    efree(channel);
}

static http_channel* http_channel_new(int fd TSRMLS_DC)
{
    http_channel *channel = emalloc(sizeof(http_channel));
    bzero(channel, sizeof(http_channel));
    channel->fd = fd;
    swHashMap_add_int(php_sw_http_channels, fd, channel, NULL);
    return channel;
}

static void http_request_free(http_channel *channel)
{
    http_request *req = &channel->request;
    if (req->request_uri)
    {
        efree(req->request_uri);
    }
    if (req->vpath)
    {
        efree(req->vpath);
    }

    zval_ptr_dtor(&req->content);
    bzero(req, sizeof(http_request));

    http_response *resp = &channel->response;
    if (resp->cookie)
    {
        swString_free(resp->cookie);
    }
    bzero(resp, sizeof(http_response));
    zval_ptr_dtor(&channel->zrequest);
    zval_ptr_dtor(&channel->zresponse);
}

static char *http_status_message(int code)
{
    switch (code)
    {
    case 100:
        return "100 Continue";
    case 101:
        return "101 Switching Protocols";
    case 201:
        return "201 Created";
    case 204:
        return "204 No Content";
    case 206:
        return "206 Partial Content";
    case 300:
        return "300 Multiple Choices";
    case 301:
        return "301 Moved Permanently";
    case 302:
        return "302 Found";
    case 303:
        return "303 See Other";
    case 304:
        return "304 Not Modified";
    case 307:
        return "307 Temporary Redirect";
    case 400:
        return "400 Bad Request";
    case 401:
        return "401 Unauthorized";
    case 403:
        return "403 Forbidden";
    case 404:
        return "404 Not Found";
    case 405:
        return "405 Method Not Allowed";
    case 406:
        return "406 Not Acceptable";
    case 408:
        return "408 Request Timeout";
    case 410:
        return "410 Gone";
    case 413:
        return "413 Request Entity Too Large";
    case 414:
        return "414 Request URI Too Long";
    case 415:
        return "415 Unsupported Media Type";
    case 416:
        return "416 Requested Range Not Satisfiable";
    case 417:
        return "417 Expectation Failed";
    case 500:
        return "500 Internal Server Error";
    case 501:
        return "501 Method Not Implemented";
    case 503:
        return "503 Service Unavailable";
    case 506:
        return "506 Variant Also Negotiates";
    case 200:
    default:
        return "200 OK";
    }
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
    serv->onReceive = http_onReceive;
    serv->onClose = http_onClose;
    serv->open_http_protocol = 1;

    serv->ptr2 = getThis();

    php_sw_http_channels = swHashMap_new(1024, http_channel_free);

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

//PHP_METHOD(swoole_http_response, close)
//{
//    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
//
//    swServer *serv = SwooleG.serv;
//    swDataHead ev;
//    ev.fd = Z_LVAL_P(zfd);
//    ev.type = SW_EVENT_CLOSE;
//
//    swConnection *conn = swServer_connection_get(serv, ev.fd);
//    if (conn == NULL)
//    {
//        php_error_docref(NULL TSRMLS_CC, E_WARNING, "The connection[%d] not found.", ev.fd);
//        RETURN_FALSE;
//    }
//    else if (conn->active & SW_STATE_CLOSEING)
//    {
//        php_error_docref(NULL TSRMLS_CC, E_WARNING, "The connection[%d] is closeing.", ev.fd);
//        RETURN_FALSE;
//    }
//    SW_CHECK_RETURN(serv->factory.end(&serv->factory, &ev));
//}

PHP_METHOD(swoole_http_response, end)
{
    swString body;
    body.length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &body.str, &body.length) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    http_channel *channel = swHashMap_find_int(php_sw_http_channels, Z_LVAL_P(zfd));

    char buf[128];
    int n;

    int keepalive = php_http_should_keep_alive(&channel->parser);
    swString *response = swString_new(body.length + 1024);

    /**
     * Http status line
     */
    n = snprintf(buf, 128, "HTTP/1.1 %s\r\n", http_status_message(channel->response.status));
    swString_append_ptr(response, buf, n);

    /**
     * Http header
     */
    zval *header =  zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("header"), 1 TSRMLS_CC);
    if (!ZVAL_IS_NULL(header))
    {
        HashTable *ht = Z_ARRVAL_P(header);
        if (!zend_hash_exists(ht, ZEND_STRL("Server")))
        {
            swString_append_ptr(response, ZEND_STRL("Server: "SW_HTTP_SERVER_SOFTWARE"\r\n"));
        }
        if (!zend_hash_exists(ht, ZEND_STRL("Connection")))
        {
            if (keepalive)
            {
                swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
            }
            else
            {
                swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
            }
        }
        if (!zend_hash_exists(ht, ZEND_STRL("Content-Length")))
        {
            n = snprintf(buf, 128, "Content-Length: %d\r\n", body.length);
            swString_append_ptr(response, buf, n);
        }
        if (!zend_hash_exists(ht, ZEND_STRL("Date")))
        {
            n = snprintf(buf, 128, "Date: %s\r\n", php_format_date(ZEND_STRL("D, d-M-Y H:i:s T"), SwooleGS->now, 0 TSRMLS_CC));
            swString_append_ptr(response, buf, n);
        }
        for (zend_hash_internal_pointer_reset(ht); zend_hash_has_more_elements(ht) == 0; zend_hash_move_forward(ht))
        {
            char *key;
            uint keylen;
            ulong idx;
            int type;
            zval **value;

            type = zend_hash_get_current_key_ex(ht, &key, &keylen, &idx, 0, NULL);
            if (type == HASH_KEY_IS_LONG || zend_hash_get_current_data(ht, (void**)&value) == FAILURE)
            {
                continue;
            }
            n = snprintf(buf, 128, "%s: %s\r\n", key, Z_STRVAL_PP(value));
            swString_append_ptr(response, buf, n);
        }
    }
    else
    {
        swString_append_ptr(response, ZEND_STRL("Server: "SW_HTTP_SERVER_SOFTWARE"\r\n"));
        if (keepalive)
        {
            swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
        }
        else
        {
            swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
        }
        n = snprintf(buf, 128, "Date: %s\r\n", php_format_date(ZEND_STRL("D, d-M-Y H:i:s T"), 1, 0 TSRMLS_CC));
        swString_append_ptr(response, buf, n);

        n = snprintf(buf, 128, "Content-Length: %d\r\n", body.length);
        swString_append_ptr(response, buf, n);
    }

    if (channel->response.cookie)
    {
        swString_append(response, channel->response.cookie);
    }

    swString_append_ptr(response, ZEND_STRL("\r\n"));
    swString_append(response, &body);

    int ret = swServer_tcp_send(SwooleG.serv, Z_LVAL_P(zfd), response->str, response->length);

    swString_free(response);
    http_request_free(channel);

    if (!keepalive)
    {
        SwooleG.serv->factory.end(&SwooleG.serv->factory, Z_LVAL_P(zfd));
    }
    SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_http_response, cookie)
{
    char *name, *value = NULL, *path = NULL, *domain = NULL;
    long expires = 0;
    zend_bool secure = 0, httponly = 0;
    int name_len, value_len = 0, path_len = 0, domain_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|slssbb", &name, &name_len, &value, &value_len, &expires,
            &path, &path_len, &domain, &domain_len, &secure, &httponly) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    http_channel *channel = swHashMap_find_int(php_sw_http_channels, Z_LVAL_P(zfd));

    char *cookie, *encoded_value = NULL;
    int len = sizeof("Set-Cookie: ");
    char *dt;

    if (name && strpbrk(name, "=,; \t\r\n\013\014") != NULL)
    {
        zend_error(E_WARNING, "Cookie names cannot contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }

    if (!channel->response.cookie)
    {
        channel->response.cookie = swString_new(1024);
    }

    len += name_len;
    if (value)
    {
        int encoded_value_len;
        encoded_value = php_url_encode(value, value_len, &encoded_value_len);
        len += encoded_value_len;
    }
    else if (value)
    {
        encoded_value = estrdup(value);
        len += value_len;
    }
    if (path)
    {
        len += path_len;
    }
    if (domain)
    {
        len += domain_len;
    }

    cookie = emalloc(len + 100);

    if (value && value_len == 0)
    {
        dt = php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, 1, 0 TSRMLS_CC);
        snprintf(cookie, len + 100, "Set-Cookie: %s=deleted; expires=%s", name, dt);
        efree(dt);
    }
    else
    {
        snprintf(cookie, len + 100, "Set-Cookie: %s=%s", name, value ? encoded_value : "");
        if (expires > 0)
        {
            const char *p;
            strlcat(cookie, "; expires=", len + 100);
            dt = php_format_date("D, d-M-Y H:i:s T", sizeof("D, d-M-Y H:i:s T") - 1, expires, 0 TSRMLS_CC);
            p = zend_memrchr(dt, '-', strlen(dt));
            if (!p || *(p + 5) != ' ')
            {
                efree(dt);
                efree(cookie);
                efree(encoded_value);
                zend_error(E_WARNING, "Expiry date cannot have a year greater than 9999");
                RETURN_FALSE;
            }
            strlcat(cookie, dt, len + 100);
            efree(dt);
        }
    }
    if (encoded_value)
    {
        efree(encoded_value);
    }
    if (path && path_len > 0)
    {
        strlcat(cookie, "; path=", len + 100);
        strlcat(cookie, path, len + 100);
    }
    if (domain && domain_len > 0)
    {
        strlcat(cookie, "; domain=", len + 100);
        strlcat(cookie, domain, len + 100);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", len + 100);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", len + 100);
    }
    swString_append_ptr(channel->response.cookie, cookie, strlen(cookie));
    swString_append_ptr(channel->response.cookie, ZEND_STRL("\r\n"));
    efree(cookie);
}

PHP_METHOD(swoole_http_response, status)
{
    long http_status;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &http_status) == FAILURE)
    {
        return;
    }

    zval *zfd = zend_read_property(swoole_http_response_class_entry_ptr, getThis(), ZEND_STRL("fd"), 0 TSRMLS_CC);
    http_channel *channel = swHashMap_find_int(php_sw_http_channels, Z_LVAL_P(zfd));

    channel->response.status = http_status;
}

PHP_METHOD(swoole_http_response, header)
{
    char *k, *v;
    int klen, vlen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &k, &klen, &v, &vlen) == FAILURE)
    {
        return;
    }
    zval *header = zend_read_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("header"), 1 TSRMLS_CC);
    if (!header || ZVAL_IS_NULL(header))
    {
        MAKE_STD_ZVAL(header);
        array_init(header);
        zend_update_property(swoole_http_request_class_entry_ptr, getThis(), ZEND_STRL("header"), header TSRMLS_CC);
    }
    add_assoc_stringl_ex(header, k, klen + 1, v, vlen, 1);
}

/**
 * For websocket send message
 */
PHP_METHOD(swoole_http_response, message)
{

}

