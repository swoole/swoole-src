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

#include "php_swoole_cxx.h"

#include "swoole_http_client.h"
#include "swoole_coroutine.h"
#include "coroutine_c_api.h"

using namespace swoole;

swString *http_client_buffer;

extern void php_swoole_client_coro_socket_free(Socket *cli);

static int http_parser_on_header_field(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_header_value(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_headers_complete(swoole_http_parser *parser);
static int http_parser_on_body(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_message_complete(swoole_http_parser *parser);

static const swoole_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_parser_on_header_field,
    http_parser_on_header_value,
    http_parser_on_headers_complete,
    http_parser_on_body,
    http_parser_on_message_complete
};

class http_client
{
    public:
    /* states */
    http_client_state state = HTTP_CLIENT_STATE_WAIT;
    bool wait = false;
    bool defer = false;

    /* request info */
    std::string host = "127.0.0.1";
    uint16_t port = 80;
#ifdef SW_USE_OPENSSL
    uint8_t ssl = false;
#endif
    double connect_timeout = Socket::default_connect_timeout;
    int8_t method = SW_HTTP_GET;       // method
    std::string uri;

    /* response parse */
    char *tmp_header_field_name = nullptr;
    int tmp_header_field_name_len = 0;
    swString *body = nullptr;
#ifdef SW_HAVE_ZLIB
    z_stream gzip_stream = {0};
    swString *gzip_buffer = nullptr;
    swString *_gzip_buffer = nullptr;
#endif

    /* options */
    uint8_t reconnect_interval = 1;
    uint8_t reconnected_count = 0;
    bool keep_alive = true;          // enable default
    bool websocket = false;          // if upgrade successfully
    bool gzip = false;               // enable gzip
    bool chunked = false;            // Transfer-Encoding: chunked
    bool websocket_mask = false;     // enable websocket mask
    bool is_download = false;        // save http response to file
    int download_file_fd = 0;
    bool has_upload_files = false;

    /* safety zval */
    zval _zobject;
    zval *zobject = &_zobject;

    http_client(zval* zobject, std::string host, zend_long port = 80, zend_bool ssl = false);

    private:
#ifdef SW_HAVE_ZLIB
    void init_gzip();
#endif
    bool connect();
    bool keep_liveness();
    bool send();
    void reset();

    public:
#ifdef SW_HAVE_ZLIB
    bool init_compression(enum http_compress_method method);
    bool uncompress_response();
#endif
    void check_bind();
    void set(zval *zset);
    bool exec(std::string uri);
    bool recv(double timeout = 0);
    void recv(zval *zframe, double timeout = 0);
    bool recv_http_response(double timeout = 0);
    bool upgrade(std::string uri);
    bool push(zval *zdata, zend_long opcode = WEBSOCKET_OPCODE_TEXT, bool _fin = true);
    bool close();

    ~http_client();

private:
    Socket* socket = nullptr;
    swSocket_type socket_type = SW_SOCK_TCP;
    swoole_http_parser parser = {0};
};

static zend_class_entry swoole_http_client_coro_ce;
zend_class_entry *swoole_http_client_coro_ce_ptr;
static zend_object_handlers swoole_http_client_coro_handlers;

static zend_class_entry swoole_http_client_coro_exception_ce;
zend_class_entry *swoole_http_client_coro_exception_ce_ptr;
static zend_object_handlers swoole_http_client_coro_exception_handlers;

typedef struct
{
    http_client* phc;
    zend_object std;
} http_client_coro;

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setDefer, 0, 0, 0)
    ZEND_ARG_INFO(0, defer)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_upgrade, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_http_client_coro, __construct);
static PHP_METHOD(swoole_http_client_coro, __destruct);
static PHP_METHOD(swoole_http_client_coro, set);
static PHP_METHOD(swoole_http_client_coro, getDefer);
static PHP_METHOD(swoole_http_client_coro, setDefer);
static PHP_METHOD(swoole_http_client_coro, setMethod);
static PHP_METHOD(swoole_http_client_coro, setHeaders);
static PHP_METHOD(swoole_http_client_coro, setCookies);
static PHP_METHOD(swoole_http_client_coro, setData);
static PHP_METHOD(swoole_http_client_coro, addFile);
static PHP_METHOD(swoole_http_client_coro, addData);
static PHP_METHOD(swoole_http_client_coro, execute);
static PHP_METHOD(swoole_http_client_coro, get);
static PHP_METHOD(swoole_http_client_coro, post);
static PHP_METHOD(swoole_http_client_coro, download);
static PHP_METHOD(swoole_http_client_coro, upgrade);
static PHP_METHOD(swoole_http_client_coro, push);
static PHP_METHOD(swoole_http_client_coro, recv);
static PHP_METHOD(swoole_http_client_coro, close);

static const zend_function_entry swoole_http_client_coro_methods[] =
{
    PHP_ME(swoole_http_client_coro, __construct, arginfo_swoole_http_client_coro_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, set, arginfo_swoole_http_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setDefer, arginfo_swoole_http_client_coro_setDefer, ZEND_ACC_PUBLIC)
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
    PHP_ME(swoole_http_client_coro, recv, arginfo_swoole_http_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, push, arginfo_swoole_http_client_coro_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int http_parser_on_header_field(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    http->tmp_header_field_name = (char *) at;
    http->tmp_header_field_name_len = length;
    return 0;
}

static int http_parser_on_header_value(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->zobject;
    zval *zheaders = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("headers"), 1);
    char *header_name = zend_str_tolower_dup(http->tmp_header_field_name, http->tmp_header_field_name_len);
    int ret = 0;

    add_assoc_stringl_ex(zheaders, header_name, http->tmp_header_field_name_len, (char *) at, length);

    if (parser->status_code == SW_HTTP_SWITCHING_PROTOCOLS && strcmp(header_name, "upgrade") == 0 && strncasecmp(at, "websocket", length) == 0)
    {
        http->websocket = true;
    }
    else if (strcmp(header_name, "set-cookie") == 0)
    {
        zval *zcookies = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("cookies"), 1);
        zval *zset_cookie_headers = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("set_cookie_headers"), 1);
        ret = http_parse_set_cookies(at, length, zcookies, zset_cookie_headers);
    }
#ifdef SW_HAVE_ZLIB
    else if (strcmp(header_name, "content-encoding") == 0 && strncasecmp(at, "gzip", length) == 0)
    {
        ret = http->init_compression(HTTP_COMPRESS_GZIP) ? 0 : -1;
    }
    else if (strcasecmp(header_name, "content-encoding") == 0 && strncasecmp(at, "deflate", length) == 0)
    {
        ret = http->init_compression(HTTP_COMPRESS_DEFLATE) ? 0 : -1;
    }
#endif
    else if (strcasecmp(header_name, "transfer-encoding") == 0 && strncasecmp(at, "chunked", length) == 0)
    {
        http->chunked = true;
    }

    efree(header_name);
    return ret;
}

static int http_parser_on_headers_complete(swoole_http_parser *parser)
{
    http_client* http = (http_client*) parser->data;
    //no content-length
    if (http->chunked == 0 && parser->content_length == -1)
    {
        enum flags { F_CONNECTION_CLOSE = 1 << 2 };
        parser->flags |= F_CONNECTION_CLOSE;
    }
    if (http->method == SW_HTTP_HEAD || parser->status_code == SW_HTTP_NO_CONTENT)
    {
        return 1;
    }
    return 0;
}

static int http_parser_on_body(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    if (swString_append_ptr(http->body, at, length) < 0)
    {
        return -1;
    }
    if (http->is_download)
    {
#ifdef SW_HAVE_ZLIB
        if (http->gzip)
        {
            if (!http->uncompress_response())
            {
                return -1;
            }
            if (swoole_coroutine_write(http->download_file_fd, SW_STRINGL(http->gzip_buffer)) != (ssize_t) http->gzip_buffer->length)
            {
                return -1;
            }
        }
        else
#endif
        {
            if (swoole_coroutine_write(http->download_file_fd, SW_STRINGL(http->body)) != (ssize_t) http->body->length)
            {
                return -1;
            }
        }
        swString_clear(http->body);
    }
    return 0;
}

static int http_parser_on_message_complete(swoole_http_parser *parser)
{
    http_client* http = (http_client*) parser->data;
    zval* zobject = (zval*) http->zobject;

    if (parser->upgrade && !http->websocket)
    {
        // not support, continue.
        parser->upgrade = 0;
        return 0;
    }

#ifdef SW_HAVE_ZLIB
    if (http->gzip && http->body->length > 0 && http->uncompress_response())
    {
        zend_update_property_stringl(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("body"), SW_STRINGL(http->gzip_buffer));
    }
    else
#endif
    {
        zend_update_property_stringl(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("body"), SW_STRINGL(http->body));
    }

    //http status code
    zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), parser->status_code);

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

http_client::http_client(zval* zobject, std::string host, zend_long port, zend_bool ssl)
{
    if (host.compare(0, 6, "unix:/", 0, 6) == 0)
    {
        host = host.substr(sizeof("unix:") - 1);
        host.erase(0, host.find_first_not_of('/') - 1);
        socket_type = SW_SOCK_UNIX_STREAM;
    }
    else if (host.find(':') != std::string::npos)
    {
        socket_type = SW_SOCK_TCP6;
    }
    else
    {
        socket_type = SW_SOCK_TCP;
    }
    this->host = host;
    this->port = port;
#ifdef SW_USE_OPENSSL
    this->ssl = ssl;
#endif
    _zobject = *zobject;
    // TODO: zend_read_property cache here (strong type properties)
}

#ifdef SW_HAVE_ZLIB
void http_client::init_gzip()
{
    gzip = true;
    memset(&gzip_stream, 0, sizeof(gzip_stream));
    if (is_download)
    {
        if (!_gzip_buffer)
        {
            _gzip_buffer = swString_new(SW_BUFFER_SIZE_STD);
        }
        gzip_buffer = _gzip_buffer;
    }
    else
    {
        gzip_buffer = swoole_zlib_buffer;
    }
    gzip_stream.zalloc = php_zlib_alloc;
    gzip_stream.zfree = php_zlib_free;
}

bool http_client::init_compression(http_compress_method method)
{
    switch(method)
    {
    case HTTP_COMPRESS_DEFLATE:
        init_gzip();
        if (Z_OK != inflateInit(&gzip_stream))
        {
            swWarn("inflateInit() failed");
            return false;
        }
        break;
    case HTTP_COMPRESS_GZIP:
        init_gzip();
        if (Z_OK != inflateInit2(&gzip_stream, MAX_WBITS + 16))
        {
            swWarn("inflateInit2() failed");
            return false;
        }
        break;
    default:
        assert(0);
    }

    return true;
}

bool http_client::uncompress_response()
{
    int status = 0;

    swString_clear(gzip_buffer);
    gzip_stream.avail_in = body->length;
    gzip_stream.next_in = (Bytef *) body->str;
    gzip_stream.total_in = 0;
    gzip_stream.total_out = 0;

    while (1)
    {
        gzip_stream.avail_out = gzip_buffer->size - gzip_buffer->length;
        gzip_stream.next_out = (Bytef *) (gzip_buffer->str + gzip_buffer->length);
        status = inflate(&gzip_stream, Z_SYNC_FLUSH);
        if (status >= 0)
        {
            gzip_buffer->length = gzip_stream.total_out;
        }
        if (status == Z_STREAM_END)
        {
            return true;
        }
        else if (status == Z_OK)
        {
            if (gzip_buffer->length + 4096 >= gzip_buffer->size)
            {
                if (swString_extend(gzip_buffer, gzip_buffer->size * 2) < 0)
                {
                    break;
                }
            }
            if (gzip_stream.avail_in == 0)
            {
                return true;
            }
        }
        else
        {
            break;
        }
    }
    swWarn("http_response_uncompress failed");
    return false;
}
#endif

void http_client::check_bind()
{
    if (socket)
    {
        PHPCoroutine::check_bind("http client", socket->get_bound_cid());
    }
}

void http_client::set(zval *zset = nullptr)
{
    zval *ztmp;
    HashTable *vht;
    zval *zsettings = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("setting"), 1);

    if (zset)
    {
        SW_ASSERT(ZVAL_IS_ARRAY(zset));
        php_array_merge(Z_ARRVAL_P(zsettings), Z_ARRVAL_P(zset));
        // will be set immediately
        vht = Z_ARRVAL_P(zset);
        if (php_swoole_array_get_value(vht, "connect_timeout", ztmp) || php_swoole_array_get_value(vht, "timeout", ztmp) /* backward compatibility */)
        {
            connect_timeout = zval_get_double(ztmp);
        }
        if (php_swoole_array_get_value(vht, "reconnect", ztmp))
        {
            reconnect_interval = (uint8_t) MIN(zval_get_long(ztmp), UINT8_MAX);
        }
        if (php_swoole_array_get_value(vht, "defer", ztmp))
        {
            defer = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "keep_alive", ztmp))
        {
            keep_alive = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "websocket_mask", ztmp))
        {
            websocket_mask = zval_is_true(ztmp);
        }
    }
    if (socket)
    {
        php_swoole_client_set(socket, zset ? zset : zsettings);
    }
}

bool http_client::connect()
{
    if (!socket)
    {
        php_swoole_check_reactor();
        socket = new Socket(socket_type);
        if (UNEXPECTED(socket->socket == nullptr))
        {
            swoole_php_fatal_error(E_WARNING, "new Socket() failed. Error: %s [%d]", strerror(errno), errno);
            zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), errno);
            zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), strerror(errno));
            delete socket;
            socket = nullptr;
            return false;
        }
#ifdef SW_USE_OPENSSL
        socket->open_ssl = ssl;
#endif
        // check settings
        set();

        // connect
        socket->set_timeout(connect_timeout, SW_TIMEOUT_CONNECT);
        if (!socket->connect(host, port))
        {
            zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), socket->errCode);
            zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), socket->errMsg);
            zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            close();
            return false;
        }
        reconnected_count = 0;
        zend_update_property_bool(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("connected"), 1);
        if (!body)
        {
            body = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
            if (!body)
            {
                swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
                return false;
            }
        }
    }
    return true;
}

bool http_client::keep_liveness()
{
    if (!socket || !socket->check_liveness())
    {
        if (socket)
        {
            zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), socket->errCode);
            zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), socket->errMsg);
            zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
            close();
        }
        for (; reconnected_count < reconnect_interval; reconnected_count++)
        {
            if (connect())
            {
                return true;
            }
        }
        return false;
    }
    return true;
}

bool http_client::send()
{
    zval *value = NULL;
    char *method;
    uint32_t header_flag = 0x0;
    zval *zmethod, *zheaders, *zbody, *zupload_files, *zcookies, *z_download_file;

    check_bind();

    if (uri.length() == 0)
    {
        swoole_php_fatal_error(E_WARNING, "path is empty");
        return false;
    }

    // when new request, clear all properties about the last response
    {
        zval *zattr;
        zattr = sw_zend_read_property(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("headers"), 0);
        if (Z_TYPE_P(zattr) == IS_ARRAY)
        {
            zend_hash_clean(Z_ARRVAL_P(zattr));
        }
        zattr = sw_zend_read_property(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("set_cookie_headers"), 0);
        if (Z_TYPE_P(zattr) == IS_ARRAY)
        {
            zend_hash_clean(Z_ARRVAL_P(zattr));
        }
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("body"), "");
    }

    if (!keep_liveness())
    {
        return false;
    }
    else
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), 0);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), "");
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), 0);
    }

    //clear errno
    SwooleG.error = 0;
    //clear buffer
    swString_clear(http_client_buffer);
    // clear body
    swString_clear(body);

    zmethod = sw_zend_read_property_not_null(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("requestMethod"), 1);
    zheaders = sw_zend_read_property(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("requestHeaders"), 1);
    zbody = sw_zend_read_property_not_null(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("requestBody"), 1);
    zupload_files = sw_zend_read_property(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("uploadFiles"), 1);
    zcookies = sw_zend_read_property(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("cookies"), 1);
    z_download_file = sw_zend_read_property_not_null(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("downloadFile"), 1);

    // ============ download ============
    if (z_download_file)
    {
        zend::string str_download_file(z_download_file);
        char *download_file_name = str_download_file.val();
        zval *z_download_offset = sw_zend_read_property_not_null(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("downloadOffset"), 1);
        off_t download_offset = 0;
        if (z_download_offset)
        {
            download_offset = (off_t) Z_LVAL_P(z_download_offset);
        }

        int fd = ::open(download_file_name, O_CREAT | O_WRONLY, 0664);
        if (fd < 0)
        {
            swSysWarn("open(%s, O_CREAT | O_WRONLY) failed", download_file_name);
            return SW_ERR;
        }
        if (download_offset == 0)
        {
            if (ftruncate(fd, 0) < 0)
            {
                swSysWarn("ftruncate(%s) failed", download_file_name);
                ::close(fd);
                return SW_ERR;
            }
        }
        else
        {
            if (lseek(fd, download_offset, SEEK_SET) < 0)
            {
                swSysWarn("fseek(%s, %jd) failed", download_file_name, (intmax_t) download_offset);
                ::close(fd);
                return SW_ERR;
            }
        }
        is_download = 1;
        download_file_fd = fd;
    }

    // ============ method ============
    zend::string str_method;
    if (zmethod)
    {
        str_method = zmethod;
        method = str_method.val();
    }
    else
    {
        method = (char *) (zbody ? "POST" : "GET");
    }

    this->method = swHttp_get_method(method, strlen(method) + 1);
    swString_append_ptr(http_client_buffer, method, strlen(method));
    swString_append_ptr(http_client_buffer, ZEND_STRL(" "));

    // ============ proxy ============
#ifdef SW_USE_OPENSSL
    if (socket->http_proxy && !socket->open_ssl)
#else
    if (socket->http_proxy)
#endif
    {
        zend::string str_host;
        const static char *pre = "http://";
        char *_host = (char *) host.c_str();
        size_t _host_len = host.length();
        if (zheaders && Z_TYPE_P(zheaders) == IS_ARRAY)
        {
            if ((value = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("Host"))))
            {
                str_host = value;
                _host = str_host.val();
                _host_len = str_host.len();
            }
        }
        size_t proxy_uri_len = uri.length() + _host_len + strlen(pre) + 10;
        char *proxy_uri = (char*) emalloc(proxy_uri_len);
        proxy_uri_len = sw_snprintf(proxy_uri, proxy_uri_len, "%s%s:%u%s", pre, _host, port, uri.c_str());
        uri = std::string(proxy_uri, proxy_uri_len);
        efree(proxy_uri);
    }

    // ============ uri ============
    swString_append_ptr(http_client_buffer, uri.c_str(), uri.length());
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
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), host.c_str(), host.length());
        }

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheaders), key, keylen, keytype, value)
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            zend::string str_value(value);
            if ((str_value.len() == 0) || (strncasecmp(key, ZEND_STRL("Host")) == 0))
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
            http_client_swString_append_headers(http_client_buffer, key, keylen, str_value.val(), str_value.len());
        SW_HASHTABLE_FOREACH_END();
    }
    else
    {
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), host.c_str(), host.length());
    }
    if (!(header_flag & HTTP_HEADER_CONNECTION))
    {
        if (keep_alive)
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
        int n_cookie = php_swoole_array_length(zcookies);
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zcookies), key, keylen, keytype, value)
            i++;
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            zend::string str_value(value);
            if (str_value.len() == 0)
            {
                continue;
            }
            swString_append_ptr(http_client_buffer, key, keylen);
            swString_append_ptr(http_client_buffer, "=", 1);

            int encoded_value_len;
            encoded_value = sw_php_url_encode(str_value.val(), str_value.len(), &encoded_value_len);
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
    if (ZVAL_IS_ARRAY(zupload_files))
    {
        char header_buf[2048];
        char boundary_str[SW_HTTP_CLIENT_BOUNDARY_TOTAL_SIZE];
        int n;

        has_upload_files = php_swoole_array_length(zupload_files) > 0;

        // ============ content-type ============
        memcpy(boundary_str, SW_HTTP_CLIENT_BOUNDARY_PREKEY, sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1);
        swoole_random_string(
            boundary_str + sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1,
            sizeof(boundary_str) - sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY)
        );
        n = sw_snprintf(
            header_buf,
            sizeof(header_buf), "Content-Type: multipart/form-data; boundary=%.*s\r\n",
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
                zend::string str_value(value);
                //strlen("%.*s")*2 = 8
                //header + body + CRLF(2)
                content_length += (sizeof(SW_HTTP_FORM_RAW_DATA_FMT) - SW_HTTP_FORM_RAW_DATA_FMT_LEN -1) + (sizeof(boundary_str) - 1) + keylen + str_value.len() + 2;
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
                //strlen("%.*s")*4 = 16
                //header + body + CRLF(2)
                content_length += (sizeof(SW_HTTP_FORM_FILE_DATA_FMT) - SW_HTTP_FORM_FILE_DATA_FMT_LEN - 1) + (sizeof(boundary_str) - 1)
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
                zend::string str_value(value);
                n = sw_snprintf(
                    header_buf, sizeof(header_buf),
                    SW_HTTP_FORM_RAW_DATA_FMT, (int)(sizeof(boundary_str) - 1),
                    boundary_str, keylen, key
                );
                swString_append_ptr(http_client_buffer, header_buf, n);
                swString_append_ptr(http_client_buffer, str_value.val(), str_value.len());
                swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
            SW_HASHTABLE_FOREACH_END();
        }

        if (socket->send_all(http_client_buffer->str, http_client_buffer->length) != (ssize_t) http_client_buffer->length)
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
                n = sw_snprintf(
                    header_buf, sizeof(header_buf), SW_HTTP_FORM_FILE_DATA_FMT,
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
                    if (socket->send_all(http_client_buffer->str, http_client_buffer->length) != (ssize_t) http_client_buffer->length)
                    {
                        goto _send_fail;
                    }
                }
                /**
                 * from disk file
                 */
                else
                {
                    if (socket->send_all(header_buf, n) != n)
                    {
                        goto _send_fail;
                    }
                    if (!socket->sendfile(Z_STRVAL_P(zpath), Z_LVAL_P(zoffset), Z_LVAL_P(zsize)))
                    {
                        goto _send_fail;
                    }
                    if (socket->send_all("\r\n", 2) != 2)
                    {
                        goto _send_fail;
                    }
                }
            SW_HASHTABLE_FOREACH_END();
        }

        n = sw_snprintf(header_buf, sizeof(header_buf), "--%.*s--\r\n", (int)(sizeof(boundary_str) - 1), boundary_str);
        if (socket->send_all(header_buf, n) != n)
        {
            goto _send_fail;
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
                    swoole_php_error(E_WARNING, "http_build_query failed");
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

    swTraceLog(
        SW_TRACE_HTTP_CLIENT,
        "to [%s:%u%s] by fd#%d in cid#%ld with [%zu] bytes: <<EOF\n%.*s\nEOF",
        host.c_str(), port, uri.c_str(), socket->get_fd(), Coroutine::get_current_cid(),
        http_client_buffer->length, (int) http_client_buffer->length, http_client_buffer->str
    );

    if (socket->send_all(http_client_buffer->str, http_client_buffer->length) != (ssize_t) http_client_buffer->length)
    {
       _send_fail:
       zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error = errno);
       zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), strerror(SwooleG.error));
       zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
       close();
       return false;
    }

    wait = true;
    return true;
}

bool http_client::exec(std::string uri)
{
    this->uri = uri;
    // bzero when make a new reqeust
    reconnected_count = 0;
    if (defer)
    {
        return send();
    }
    else
    {
        return send() && recv();
    }
}

bool http_client::recv(double timeout)
{
    check_bind();

    if (!wait)
    {
        return false;
    }
    if (!socket || !socket->is_connect())
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return false;
    }
    if (!recv_http_response(timeout))
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(
            swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"),
            socket->errCode == ETIMEDOUT ? HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT : HTTP_CLIENT_ESTATUS_SERVER_RESET
        );
        close();
        return false;
    }
    /**
     * TODO: Sec-WebSocket-Accept check
     */
    if (websocket)
    {
        socket->open_length_check = 1;
        socket->protocol.get_package_length = swWebSocket_get_package_length;
        socket->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
    }
    // handler keep alive
    if (!keep_alive && !websocket)
    {
        close();
    }
    else
    {
        reset();
    }

    return true;
}

void http_client::recv(zval *zframe, double timeout)
{
    check_bind();

    SW_ASSERT(websocket);
    ZVAL_FALSE(zframe);
    if (!socket || !socket->is_connect())
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return;
    }

    ssize_t retval = socket->recv_packet(timeout);
    if (retval <= 0)
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        if (socket->errCode != ETIMEDOUT)
        {
            close();
        }
    }
    else
    {
        swString msg;
        msg.length = retval;
        msg.str = socket->get_read_buffer()->str;
        php_swoole_websocket_frame_unpack(&msg, zframe);
    }
}

bool http_client::recv_http_response(double timeout)
{
    ssize_t retval = 0;
    size_t total_bytes = 0, parsed_n = 0;
    swString *buffer = socket->get_read_buffer();

    // re-init http response parser
    swoole_http_parser_init(&parser, PHP_HTTP_RESPONSE);
    parser.data = this;

    if (timeout == 0)
    {
        timeout = socket->get_timeout(SW_TIMEOUT_READ);
    }
    Socket::timeout_controller tc(socket, timeout, SW_TIMEOUT_READ);
    while (true)
    {
        retval = socket->recv(buffer->str, buffer->size);
        if (unlikely(retval <= 0))
        {
            if (retval == 0)
            {
                socket->set_err(ECONNRESET);
                if (total_bytes > 0 && !swoole_http_should_keep_alive(&parser))
                {
                    http_parser_on_message_complete(&parser);
                    return true;
                }
            }
            return false;
        }
        total_bytes += retval;
        parsed_n = swoole_http_parser_execute(&parser, &http_parser_settings, buffer->str, retval);
        swTraceLog(SW_TRACE_HTTP_CLIENT, "parsed_n=%ld, retval=%ld, total_bytes=%ld, completed=%d", parsed_n, retval, total_bytes, parser.state == s_start_res);
        if (parser.state == s_start_res)
        {
            // websocket stick package
            if (parser.upgrade && (size_t) retval > parsed_n + 1 + SW_WEBSOCKET_HEADER_LEN)
            {
                swString_sub(buffer, parsed_n + 1, retval - parsed_n - 1);
            }
            return true;
        }
        if (unlikely(parser.state == s_dead))
        {
            socket->set_err(EPROTO);
            return false;
        }
        if (unlikely(tc.has_timedout()))
        {
            socket->set_err(ETIMEDOUT);
            return false;
        }
    }
}

bool http_client::upgrade(std::string uri)
{
    defer = false;
    if (!websocket)
    {
        char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
        zval *zheaders = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("requestHeaders"), 1);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("requestMethod"), "GET");
        http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);
        add_assoc_string(zheaders, "Connection", (char* )"Upgrade");
        add_assoc_string(zheaders, "Upgrade", (char* ) "websocket");
        add_assoc_string(zheaders, "Sec-WebSocket-Version", (char*)SW_WEBSOCKET_VERSION);
        add_assoc_str_ex(zheaders, ZEND_STRL("Sec-WebSocket-Key"), php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH));
        exec(uri);
    }
    return websocket;
}

bool http_client::push(zval *zdata, zend_long opcode, bool fin)
{
    check_bind();

    if (!websocket)
    {
        swoole_php_fatal_error(E_WARNING, "websocket handshake failed, cannot push data");
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error = SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), "websocket handshake failed, cannot push data");
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
        return false;
    }
    if (!socket || !socket->is_connect())
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return false;
    }

    swString_clear(http_client_buffer);
    if (php_swoole_websocket_frame_pack(http_client_buffer, zdata, opcode, fin, websocket_mask) < 0)
    {
        return false;
    }

    if (socket->send_all(http_client_buffer->str, http_client_buffer->length) != (ssize_t) http_client_buffer->length)
    {
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error = socket->errCode);
        zend_update_property_string(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("errMsg"), strerror(SwooleG.error));
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        close();
        return false;
    }
    else
    {
        return true;
    }
}

void http_client::reset()
{
    wait = false;
    // clear
#ifdef SW_HAVE_ZLIB
    if (gzip)
    {
        inflateEnd(&gzip_stream);
        gzip = false;
    }
#endif
    if (has_upload_files)
    {
        zend_update_property_null(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("uploadFiles"));
    }
    if (is_download)
    {
        ::close(download_file_fd);
        is_download = false;
        download_file_fd = 0;
        zend_update_property_null(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("downloadFile"));
        zend_update_property_long(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("downloadOffset"), 0);
    }
}

bool http_client::close()
{
    Socket *socket = this->socket;
    if (socket)
    {
        zend_update_property_bool(swoole_http_client_coro_ce_ptr, zobject, ZEND_STRL("connected"), 0);
        if (!socket->has_bound())
        {
            // reset some request period states
            reset();
            // reset the properties that depend on the connection
            this->websocket = false;
            this->socket = nullptr;
        }
        php_swoole_client_coro_socket_free(socket);
        return true;
    }
    return false;
}

http_client::~http_client()
{
    close();
    if (body)
    {
        swString_free(body);
    }
#ifdef SW_HAVE_ZLIB
    if (_gzip_buffer)
    {
        swString_free(_gzip_buffer);
        _gzip_buffer = nullptr;
    }
#endif
}

static sw_inline http_client_coro* swoole_http_client_coro_fetch_object(zend_object *obj)
{
    return (http_client_coro *) ((char *) obj - swoole_http_client_coro_handlers.offset);
}

static sw_inline http_client * swoole_get_phc(zval *zobject)
{
    http_client *phc = swoole_http_client_coro_fetch_object(Z_OBJ_P(zobject))->phc;
    if (UNEXPECTED(!phc))
    {
        swoole_php_fatal_error(E_ERROR, "you must call Http Client constructor first");
    }
    return phc;
}

static void swoole_http_client_coro_free_object(zend_object *object)
{
    http_client_coro *hcc_t = swoole_http_client_coro_fetch_object(object);
    if (hcc_t->phc)
    {
        delete hcc_t->phc;
        hcc_t->phc = nullptr;
    }
    zend_object_std_dtor(&hcc_t->std);
}

static zend_object *swoole_http_client_coro_create_object(zend_class_entry *ce)
{
    http_client_coro *hcc_t = (http_client_coro *) ecalloc(1, sizeof(http_client_coro) + zend_object_properties_size(ce));
    zend_object_std_init(&hcc_t->std, ce);
    object_properties_init(&hcc_t->std, ce);
    hcc_t->std.handlers = &swoole_http_client_coro_handlers;
    return &hcc_t->std;
}

void swoole_http_client_coro_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_http_client_coro, "Swoole\\Coroutine\\Http\\Client", NULL, "Co\\Http\\Client", swoole_http_client_coro_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_http_client_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_http_client_coro, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_client_coro, zend_class_unset_property_deny);
    SWOOLE_SET_CLASS_CUSTOM_OBJECT(swoole_http_client_coro, swoole_http_client_coro_create_object, swoole_http_client_coro_free_object, http_client_coro, std);

    // client status
    zend_declare_property_long(swoole_http_client_coro_ce_ptr, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http_client_coro_ce_ptr, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_client_coro_ce_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    // client info
    zend_declare_property_string(swoole_http_client_coro_ce_ptr, ZEND_STRL("host"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_ce_ptr, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_client_coro_ce_ptr, ZEND_STRL("ssl"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);

    // request properties
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("requestMethod"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("requestHeaders"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("requestBody"), ZEND_ACC_PUBLIC);
    // always set by API (make it private?)
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("uploadFiles"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("downloadFile"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_ce_ptr, ZEND_STRL("downloadOffset"), 0, ZEND_ACC_PUBLIC);

    // response properties
    zend_declare_property_long(swoole_http_client_coro_ce_ptr, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce_ptr, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http_client_coro_ce_ptr, ZEND_STRL("body"), "", ZEND_ACC_PUBLIC);

    SWOOLE_INIT_CLASS_ENTRY_EX(swoole_http_client_coro_exception, "Swoole\\Coroutine\\Http\\Client\\Exception", NULL, "Co\\Http\\Client\\Exception", NULL, swoole_exception);

    SWOOLE_DEFINE_NS(HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
    SWOOLE_DEFINE_NS(HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
    SWOOLE_DEFINE_NS(HTTP_CLIENT_ESTATUS_SERVER_RESET);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

static PHP_METHOD(swoole_http_client_coro, __construct)
{
    http_client_coro *hcc_t = swoole_http_client_coro_fetch_object(Z_OBJ_P(getThis()));
    char *host;
    size_t host_len;
    zend_long port = 80;
    zend_bool ssl = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 3)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_BOOL(ssl)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http_client_coro_ce_ptr,getThis(), ZEND_STRL("port"), port);
    zend_update_property_bool(swoole_http_client_coro_ce_ptr,getThis(), ZEND_STRL("ssl"), ssl);
    // check host
    if (host_len == 0)
    {
        zend_throw_exception_ex(swoole_http_client_coro_exception_ce_ptr, EINVAL, "host is empty");
        RETURN_FALSE;
    }
    // check ssl
#ifndef SW_USE_OPENSSL
    if (ssl)
    {
        zend_throw_exception_ex(
            swoole_http_client_coro_exception_ce_ptr,
            EINVAL, "Need to use `--enable-openssl` to support ssl when compiling swoole"
        );
        RETURN_FALSE;
    }
#endif
    hcc_t->phc = new http_client(getThis(), std::string(host, host_len), port, ssl);
}

static PHP_METHOD(swoole_http_client_coro, __destruct) { }

static PHP_METHOD(swoole_http_client_coro, set)
{
    zval *zset;
    http_client* phc = swoole_get_phc(getThis());

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    phc->set(zset);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, getDefer)
{
    http_client *phc = swoole_get_phc(getThis());

    RETURN_BOOL(phc->defer);
}

static PHP_METHOD(swoole_http_client_coro, setDefer)
{
    http_client *phc = swoole_get_phc(getThis());
    zend_bool defer = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(defer)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    phc->defer = defer;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setMethod)
{
    zval *method;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(method)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("requestMethod"), method);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders)
{
    zval *headers;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(headers)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("requestHeaders"), headers);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setCookies)
{
    zval *cookies;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(cookies)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("cookies"), cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setData)
{
    char *data;
    size_t data_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("requestBody"), data, data_len);

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
        swoole_php_sys_error(E_WARNING, "stat(%s) failed", path);
        RETURN_FALSE;
    }
    if (file_stat.st_size == 0)
    {
        swoole_php_sys_error(E_WARNING, "cannot send empty file[%s]", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= offset)
    {
        swoole_php_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] exceeds the file size", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset)
    {
        swoole_php_sys_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] exceeds the file size", length);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        length = file_stat.st_size - offset;
    }
    if (l_type == 0)
    {
        type = (char *) swoole_get_mime_type(path);
        l_type = strlen(type);
    }
    if (l_filename == 0)
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

    zval *zupload_files = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("uploadFiles"), 1);
    zval zupload_file;
    array_init(&zupload_file);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("path"), path, l_path);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(&zupload_file, "size", length);
    add_assoc_long(&zupload_file, "offset", offset);

    RETURN_BOOL(add_next_index_zval(zupload_files, &zupload_file) == SUCCESS);
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

    if (l_type == 0)
    {
        type = (char *) "application/octet-stream";
        l_type = strlen(type);
    }
    if (l_filename == 0)
    {
        filename = name;
        l_filename = l_name;
    }

    zval *zupload_files = sw_zend_read_property_array(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("uploadFiles"), 1);
    zval zupload_file;
    array_init(&zupload_file);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("content"), data, l_data);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(&zupload_file, "size", l_data);

    RETURN_BOOL(add_next_index_zval(zupload_files, &zupload_file) == SUCCESS);
}

static PHP_METHOD(swoole_http_client_coro, execute)
{
    http_client* phc = swoole_get_phc(getThis());
    char *uri = NULL;
    size_t uri_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(uri, uri_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->exec(std::string(uri, uri_len)));
}

static PHP_METHOD(swoole_http_client_coro, get)
{
    http_client* phc = swoole_get_phc(getThis());
    char *uri = NULL;
    size_t uri_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(uri, uri_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_string(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("requestMethod"), "GET");

    RETURN_BOOL(phc->exec(std::string(uri, uri_len)));
}

static PHP_METHOD(swoole_http_client_coro, post)
{
    http_client* phc = swoole_get_phc(getThis());
    char *uri = NULL;
    size_t uri_len = 0;
    zval *post_data;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(uri, uri_len)
        Z_PARAM_ZVAL(post_data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_string(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("requestMethod"), "POST");
    zend_update_property(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("requestBody"), post_data);

    RETURN_BOOL(phc->exec(std::string(uri, uri_len)));
}

static PHP_METHOD(swoole_http_client_coro, download)
{
    http_client* phc = swoole_get_phc(getThis());
    char *uri;
    size_t uri_len;
    zval *download_file;
    zend_long offset = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(uri, uri_len)
        Z_PARAM_ZVAL(download_file)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("downloadFile"), download_file);
    zend_update_property_long(swoole_http_client_coro_ce_ptr, getThis(), ZEND_STRL("downloadOffset"), offset);

    RETURN_BOOL(phc->exec(std::string(uri, uri_len)));
}

static PHP_METHOD(swoole_http_client_coro, upgrade)
{
    http_client* phc = swoole_get_phc(getThis());
    char *uri = NULL;
    size_t uri_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(uri, uri_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->upgrade(std::string(uri, uri_len)));
}

static PHP_METHOD(swoole_http_client_coro, push)
{
    http_client* phc = swoole_get_phc(getThis());
    zval *zdata;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zend_bool fin = 1;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL(zdata)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(opcode)
        Z_PARAM_BOOL(fin)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->push(zdata, opcode, fin));
}

static PHP_METHOD(swoole_http_client_coro, recv)
{
    http_client *phc = swoole_get_phc(getThis());
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (phc->websocket)
    {
        phc->recv(return_value, timeout);
        return;
    }
    else
    {
        RETURN_BOOL(phc->recv(timeout));
    }
}

static PHP_METHOD(swoole_http_client_coro, close)
{
    http_client* phc = swoole_get_phc(getThis());

    RETURN_BOOL(phc->close());
}
