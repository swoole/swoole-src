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
 | Author: Twosee  <twose@qq.com>                                       |
 | Author: Fang  <coooold@live.com>                                     |
 | Author: Yuanyi   Zhi  <syyuanyizhi@163.com>                          |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"
#include "coroutine_c_api.h"
#include "swoole_http_client.h"

#include "mime_type.h"
#include "base64.h"

#ifdef SW_HAVE_BROTLI
#include <brotli/decode.h>
#endif

using namespace swoole;
using swoole::coroutine::Socket;

extern void php_swoole_client_coro_socket_free(Socket *cli);

static int http_parser_on_header_field(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_header_value(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_headers_complete(swoole_http_parser *parser);
static int http_parser_on_body(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_message_complete(swoole_http_parser *parser);

static const swoole_http_parser_settings http_parser_settings =
{
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    http_parser_on_header_field,
    http_parser_on_header_value,
    http_parser_on_headers_complete,
    http_parser_on_body,
    http_parser_on_message_complete
};

class http_client
{
public:
    /* request info */
    std::string host = "127.0.0.1";
    uint16_t port = 80;
    /* must bind address first */
    std::string bind_address;
    int bind_port = 0;
#ifdef SW_USE_OPENSSL
    uint8_t ssl = false;
#endif
    double connect_timeout = Socket::default_connect_timeout;
    bool defer = false;
    bool lowercase_header = true;

    int8_t method = SW_HTTP_GET;
    std::string path;
    std::string basic_auth;

    /* for response parser */
    char *tmp_header_field_name = nullptr;
    int tmp_header_field_name_len = 0;
    swString *body = nullptr;
#ifdef SW_HAVE_COMPRESSION
    enum http_compress_method compress_method = HTTP_COMPRESS_NONE;
    bool compression_error = false;
#endif

    /* options */
    uint8_t reconnect_interval = 1;
    uint8_t reconnected_count = 0;
    bool keep_alive = true;             // enable by default
    bool websocket = false;             // if upgrade successfully
    bool chunked = false;               // Transfer-Encoding: chunked
    bool websocket_mask = true;         // enable websocket mask
#ifdef SW_HAVE_ZLIB
    bool websocket_compression = false; // allow to compress websocket messages
#endif
    int download_file_fd = -1;          // save http response to file
    zend::string download_file_name;    // unlink the file on error
    zend_long download_offset = 0;
    bool has_upload_files = false;

    /* safety zval */
    zval _zobject;
    zval *zobject = &_zobject;

    http_client(zval* zobject, std::string host, zend_long port = 80, zend_bool ssl = false);

private:
#ifdef SW_HAVE_ZLIB
    bool gzip_stream_active = false;
    z_stream gzip_stream;
#endif
#ifdef SW_HAVE_BROTLI
    BrotliDecoderState *brotli_decoder_state = nullptr;
#endif
    bool bind(std::string address, int port = 0);
    bool connect();
    bool keep_liveness();
    bool send();
    void reset();

public:
#ifdef SW_HAVE_COMPRESSION
    bool decompress_response(const char *in, size_t in_len);
#endif
    void apply_setting(zval *zset, const bool check_all = true);
    void set_basic_auth(const std::string & username, const std::string & password);
    bool exec(std::string path);
    bool recv(double timeout = 0);
    void recv(zval *zframe, double timeout = 0);
    bool recv_http_response(double timeout = 0);
    bool upgrade(std::string path);
    bool push(zval *zdata, zend_long opcode = WEBSOCKET_OPCODE_TEXT, uint8_t flags = SW_WEBSOCKET_FLAG_FIN);
    bool close(const bool should_be_reset = true);

    void get_header_out(zval *return_value)
    {
        swString *buffer = socket->get_write_buffer();
        if (buffer == nullptr)
        {
            RETURN_FALSE;
        }
        off_t offset = swoole_strnpos(buffer->str, buffer->length, ZEND_STRL("\r\n\r\n"));
        if (offset <= 0)
        {
            RETURN_FALSE;
        }

        RETURN_STRINGL(buffer->str, offset);
    }

    void getsockname(zval *return_value)
    {
        swSocketAddress sa;
        if (!socket || !socket->getsockname(&sa))
        {
            ZVAL_FALSE(return_value);
            return;
        }

        array_init(return_value);
        add_assoc_string(return_value, "address", (char *) swSocket_get_ip(socket->get_type(), &sa));
        add_assoc_long(return_value, "port", swSocket_get_port(socket->get_type(), &sa));
    }

    void getpeername(zval *return_value)
    {
        swSocketAddress sa;
        if (!socket || !socket->getpeername(&sa))
        {
            ZVAL_FALSE(return_value);
            return;
        }

        array_init(return_value);
        add_assoc_string(return_value, "address", (char *) swSocket_get_ip(socket->get_type(), &sa));
        add_assoc_long(return_value, "port", swSocket_get_port(socket->get_type(), &sa));
    }

#ifdef SW_USE_OPENSSL
    void getpeercert(zval *return_value)
    {
        auto cert = socket->ssl_get_peer_cert();
        if (cert.empty())
        {
            ZVAL_FALSE(return_value);
            return;
        }
        else
        {
            ZVAL_STRINGL(return_value, cert.c_str(), cert.length());
        }
    }
#endif

    ~http_client();

private:
    Socket* socket = nullptr;
    swSocket_type socket_type = SW_SOCK_TCP;
    swoole_http_parser parser = {};
    bool wait = false;
};

static zend_class_entry *swoole_http_client_coro_ce;
static zend_object_handlers swoole_http_client_coro_handlers;

static zend_class_entry *swoole_http_client_coro_exception_ce;
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_setBasicAuth, 0, 0, 2)
    ZEND_ARG_INFO(0, username)
    ZEND_ARG_INFO(0, password)
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
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_http_client_coro, __construct);
static PHP_METHOD(swoole_http_client_coro, __destruct);
static PHP_METHOD(swoole_http_client_coro, set);
static PHP_METHOD(swoole_http_client_coro, getDefer);
static PHP_METHOD(swoole_http_client_coro, setDefer);
static PHP_METHOD(swoole_http_client_coro, setMethod);
static PHP_METHOD(swoole_http_client_coro, setHeaders);
static PHP_METHOD(swoole_http_client_coro, setBasicAuth);
static PHP_METHOD(swoole_http_client_coro, setCookies);
static PHP_METHOD(swoole_http_client_coro, setData);
static PHP_METHOD(swoole_http_client_coro, addFile);
static PHP_METHOD(swoole_http_client_coro, addData);
static PHP_METHOD(swoole_http_client_coro, execute);
static PHP_METHOD(swoole_http_client_coro, getsockname);
static PHP_METHOD(swoole_http_client_coro, getpeername);
static PHP_METHOD(swoole_http_client_coro, get);
static PHP_METHOD(swoole_http_client_coro, post);
static PHP_METHOD(swoole_http_client_coro, download);
static PHP_METHOD(swoole_http_client_coro, getBody);
static PHP_METHOD(swoole_http_client_coro, getHeaders);
static PHP_METHOD(swoole_http_client_coro, getCookies);
static PHP_METHOD(swoole_http_client_coro, getStatusCode);
static PHP_METHOD(swoole_http_client_coro, getHeaderOut);
#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_http_client_coro, getPeerCert);
#endif
static PHP_METHOD(swoole_http_client_coro, upgrade);
static PHP_METHOD(swoole_http_client_coro, push);
static PHP_METHOD(swoole_http_client_coro, recv);
static PHP_METHOD(swoole_http_client_coro, close);
SW_EXTERN_C_END

static const zend_function_entry swoole_http_client_coro_methods[] =
{
    PHP_ME(swoole_http_client_coro, __construct, arginfo_swoole_http_client_coro_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, set, arginfo_swoole_http_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setDefer, arginfo_swoole_http_client_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setMethod, arginfo_swoole_http_client_coro_setMethod, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setHeaders, arginfo_swoole_http_client_coro_setHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setBasicAuth, arginfo_swoole_http_client_coro_setBasicAuth, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setCookies, arginfo_swoole_http_client_coro_setCookies, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, setData, arginfo_swoole_http_client_coro_setData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, addFile, arginfo_swoole_http_client_coro_addFile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, addData, arginfo_swoole_http_client_coro_addData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, execute, arginfo_swoole_http_client_coro_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getpeername, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getsockname, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, get, arginfo_swoole_http_client_coro_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, post, arginfo_swoole_http_client_coro_post, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, download, arginfo_swoole_http_client_coro_download, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getBody, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getHeaders, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getCookies, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getStatusCode, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, getHeaderOut, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#ifdef SW_USE_OPENSSL
    PHP_ME(swoole_http_client_coro, getPeerCert, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_http_client_coro, upgrade, arginfo_swoole_http_client_coro_upgrade, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, push, arginfo_swoole_http_client_coro_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, recv, arginfo_swoole_http_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void http_parse_set_cookies(const char *at, size_t length, zval *zcookies, zval *zset_cookie_headers)
{
    const char *p, *eof = at + length;
    size_t key_len = 0, value_len = 0;
    zval zvalue;

    // key
    p = (char *) memchr(at, '=', length);
    if (p)
    {
        key_len = p - at;
        p++; // point to value
    }
    else
    {
        p = at; // key is empty
    }
    // value
    eof = (char*) memchr(p, ';', at + length - p);
    if (!eof)
    {
        eof = at + length;
    }
    value_len = eof - p;
    if (value_len != 0)
    {
        ZVAL_STRINGL(&zvalue, p, value_len);
        Z_STRLEN(zvalue) = php_url_decode(Z_STRVAL(zvalue), value_len);
    }
    else
    {
        ZVAL_EMPTY_STRING(&zvalue);
    }
    if (key_len == 0)
    {
        add_next_index_zval(zcookies, &zvalue);
    }
    else
    {
        add_assoc_zval_ex(zcookies, at, key_len, &zvalue);
    }

    // set_cookie_headers
    add_next_index_stringl(zset_cookie_headers, (char *) at, length);
}

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
    zval *zheaders = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, zobject, ZEND_STRL("headers"), 0);
    char *header_name = http->tmp_header_field_name;
    size_t header_len = http->tmp_header_field_name_len;

    if (http->lowercase_header)
    {
        header_name = zend_str_tolower_dup(header_name, header_len);
    }

    add_assoc_stringl_ex(zheaders, header_name, header_len, (char *) at, length);

    if (parser->status_code == SW_HTTP_SWITCHING_PROTOCOLS && SW_STREQ(header_name, header_len, "upgrade"))
    {
        if (SW_STRCASEEQ(at, length, "websocket"))
        {
            http->websocket = true;
        }
        /* TODO: protocol error? */
    }
#ifdef SW_HAVE_ZLIB
    else if (http->websocket && http->websocket_compression && SW_STREQ(header_name, header_len, "sec-websocket-extensions"))
    {
        if (
            SW_STRCASECT(at, length, "permessage-deflate") &&
            SW_STRCASECT(at, length, "client_no_context_takeover") &&
            SW_STRCASECT(at, length, "server_no_context_takeover")
        )
        {
            http->websocket_compression = true;
        }
    }
#endif
    else if (SW_STREQ(header_name, header_len, "set-cookie"))
    {
        zval *zcookies = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, zobject, ZEND_STRL("cookies"), 0);
        zval *zset_cookie_headers = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, zobject, ZEND_STRL("set_cookie_headers"), 0);
        http_parse_set_cookies(at, length, zcookies, zset_cookie_headers);
    }
#ifdef SW_HAVE_COMPRESSION
    else if (SW_STREQ(header_name, header_len, "content-encoding"))
    {
        if (0) { }
#ifdef SW_HAVE_BROTLI
        else if (SW_STRCASECT(at, length, "br"))
        {
            http->compress_method = HTTP_COMPRESS_BR;
        }
#endif
#ifdef SW_HAVE_ZLIB
        else if (SW_STRCASECT(at, length, "gzip"))
        {
            http->compress_method = HTTP_COMPRESS_GZIP;
        }
        else if (SW_STRCASECT(at, length, "deflate"))
        {
            http->compress_method = HTTP_COMPRESS_DEFLATE;
        }
#endif
    }
#endif
    else if (SW_STREQ(header_name, header_len, "transfer-encoding") && SW_STRCASECT(at, length, "chunked"))
    {
        http->chunked = true;
    }

    if (http->lowercase_header)
    {
        efree(header_name);
    }

    return 0;
}

static int http_parser_on_headers_complete(swoole_http_parser *parser)
{
    http_client* http = (http_client*) parser->data;
    if (http->method == SW_HTTP_HEAD || parser->status_code == SW_HTTP_NO_CONTENT)
    {
        return 1;
    }
    return 0;
}

static int http_parser_on_body(swoole_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
#ifdef SW_HAVE_COMPRESSION
    if (!http->compression_error && http->compress_method != HTTP_COMPRESS_NONE)
    {
        if (!http->decompress_response(at, length))
        {
            http->compression_error = true;
            goto _append_raw;
        }
    }
    else
#endif
    {
#ifdef SW_HAVE_COMPRESSION
        _append_raw:
#endif
        if (swString_append_ptr(http->body, at, length) < 0)
        {
            return -1;
        }
    }
    if (http->download_file_name.get() && http->body->length > 0)
    {
        if (http->download_file_fd < 0)
        {
            char *download_file_name = http->download_file_name.val();
            int fd = ::open(download_file_name, O_CREAT | O_WRONLY, 0664);
            if (fd < 0)
            {
                swSysWarn("open(%s, O_CREAT | O_WRONLY) failed", download_file_name);
                return false;
            }
            if (http->download_offset == 0)
            {
                if (::ftruncate(fd, 0) < 0)
                {
                    swSysWarn("ftruncate(%s) failed", download_file_name);
                    ::close(fd);
                    return false;
                }
            }
            else
            {
                if (::lseek(fd, http->download_offset, SEEK_SET) < 0)
                {
                    swSysWarn("fseek(%s, %jd) failed", download_file_name, (intmax_t) http->download_offset);
                    ::close(fd);
                    return false;
                }
            }
            http->download_file_fd = fd;
        }
        if (swoole_coroutine_write(http->download_file_fd, SW_STRINGL(http->body)) != (ssize_t) http->body->length)
        {
            return -1;
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

    zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), parser->status_code);
    if (http->download_file_fd <= 0)
    {
        zend_update_property_stringl(swoole_http_client_coro_ce, zobject, ZEND_STRL("body"), SW_STRINGL(http->body));
    }
    else
    {
        http->download_file_name.release();
    }

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
    this->socket_type = Socket::convert_to_type(host);
    this->host = host;
    this->port = port;
#ifdef SW_USE_OPENSSL
    this->ssl = ssl;
#endif
    _zobject = *zobject;
    // TODO: zend_read_property cache here (strong type properties)
}

#ifdef SW_HAVE_COMPRESSION
bool http_client::decompress_response(const char *in, size_t in_len)
{
    if (in_len == 0)
    {
        return false;
    }

    size_t reserved_body_length = body->length;

    switch(compress_method)
    {
#ifdef SW_HAVE_ZLIB
    case HTTP_COMPRESS_GZIP:
    case HTTP_COMPRESS_DEFLATE:
    {
        int status;
        int encoding = compress_method == HTTP_COMPRESS_GZIP ? SW_ZLIB_ENCODING_GZIP : SW_ZLIB_ENCODING_DEFLATE;
        bool first_decompress = !gzip_stream_active;
        size_t total_out;

        if (!gzip_stream_active)
        {
            _retry:
            memset(&gzip_stream, 0, sizeof(gzip_stream));
            gzip_stream.zalloc = php_zlib_alloc;
            gzip_stream.zfree = php_zlib_free;
            // gzip_stream.total_out = 0;
            status = inflateInit2(&gzip_stream, encoding);
            if (status != Z_OK)
            {
                swWarn("inflateInit2() failed by %s", zError(status));
                return false;
            }
            gzip_stream_active = true;
        }

        gzip_stream.next_in = (Bytef *) in;
        gzip_stream.avail_in = in_len;
        gzip_stream.total_in = 0;

        while (1)
        {
            total_out = gzip_stream.total_out;
            gzip_stream.avail_out = body->size - body->length;
            gzip_stream.next_out = (Bytef *) (body->str + body->length);
            SW_ASSERT(body->length <= body->size);
            status = inflate(&gzip_stream, Z_SYNC_FLUSH);
            if (status >= 0)
            {
                body->length += (gzip_stream.total_out - total_out);
                if (body->length + (SW_BUFFER_SIZE_STD / 2) >= body->size)
                {
                    if (swString_extend(body, body->size * 2) < 0)
                    {
                        status = Z_MEM_ERROR;
                        break;
                    }
                }
            }
            if (status == Z_STREAM_END || (status == Z_OK && gzip_stream.avail_in == 0))
            {
                return true;
            }
            if (status != Z_OK)
            {
                break;
            }
        }

        if (status == Z_DATA_ERROR && first_decompress)
        {
            first_decompress = false;
            inflateEnd(&gzip_stream);
            encoding = SW_ZLIB_ENCODING_RAW;
            body->length = reserved_body_length;
            goto _retry;
        }

        swWarn("http_client::decompress_response failed by %s", zError(status));
        body->length = reserved_body_length;
        return false;
    }
#endif
#ifdef SW_HAVE_BROTLI
    case HTTP_COMPRESS_BR:
    {
        if (!brotli_decoder_state) {
            brotli_decoder_state = BrotliDecoderCreateInstance(php_brotli_alloc, php_brotli_free, nullptr);
            if (!brotli_decoder_state)
            {
                swWarn("BrotliDecoderCreateInstance() failed");
                return false;
            }
        }

        const char *next_in = in;
        size_t available_in = in_len;
        while (1) {
            size_t available_out = body->size - body->length, reserved_available_out = available_out;
            char * next_out = body->str + body->length;
            size_t total_out;
            BrotliDecoderResult result;
            SW_ASSERT(body->length <= body->size);
            result = BrotliDecoderDecompressStream(
                brotli_decoder_state,
                &available_in, (const uint8_t **) &next_in,
                &available_out, (uint8_t **) &next_out,
                &total_out
            );
            body->length += reserved_available_out - available_out;
            if (result == BROTLI_DECODER_RESULT_SUCCESS || result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
            {
                return true;
            }
            else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT)
            {
                if (swString_extend_align(body, body->size * 2) < 0)
                {
                    swWarn("BrotliDecoderDecompressStream() failed, no memory is available");
                    break;
                }
            }
            else
            {
                swWarn("BrotliDecoderDecompressStream() failed, %s", BrotliDecoderErrorString(BrotliDecoderGetErrorCode(brotli_decoder_state)));
                break;
            }
        }

        body->length = reserved_body_length;
        return false;
    }
#endif
    default:
        break;
    }

    swWarn("http_client::decompress_response unknown compress method [%d]", compress_method);
    return false;
}
#endif

void http_client::apply_setting(zval *zset, const bool check_all)
{
    if (!ZVAL_IS_ARRAY(zset) || php_swoole_array_length(zset) == 0)
    {
        return;
    }
    if (check_all)
    {
        zval *ztmp;
        HashTable *vht = Z_ARRVAL_P(zset);

        if (php_swoole_array_get_value(vht, "connect_timeout", ztmp) || php_swoole_array_get_value(vht, "timeout", ztmp) /* backward compatibility */)
        {
            connect_timeout = zval_get_double(ztmp);
        }
        if (php_swoole_array_get_value(vht, "reconnect", ztmp))
        {
            reconnect_interval = (uint8_t) SW_MIN(zval_get_long(ztmp), UINT8_MAX);
        }
        if (php_swoole_array_get_value(vht, "defer", ztmp))
        {
            defer = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "lowercase_header", ztmp))
        {
            lowercase_header = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "keep_alive", ztmp))
        {
            keep_alive = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "websocket_mask", ztmp))
        {
            websocket_mask = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "bind_address", ztmp))
        {
            zend::string tmp = ztmp;
            bind_address = tmp.to_std_string();
        }
        if (php_swoole_array_get_value(vht, "bind_port", ztmp))
        {
            bind_port = zval_get_long(ztmp);
            bind_port = bind_port > 0 ? bind_port : 0;
        }
#ifdef SW_HAVE_ZLIB
        if (php_swoole_array_get_value(vht, "websocket_compression", ztmp))
        {
            websocket_compression = zval_is_true(ztmp);
        }
#endif
    }
    if (socket)
    {
        php_swoole_client_set(socket, zset);
#ifdef SW_USE_OPENSSL
        if (socket->http_proxy && !socket->open_ssl)
#else
        if (socket->http_proxy)
#endif
        {
            socket->http_proxy->dont_handshake = 1;
        }

        if (!bind_address.empty())
        {
            if (!bind(bind_address, bind_port))
            {
                return;
            }
        }
    }
}

void http_client::set_basic_auth(const std::string &username, const std::string &password)
{
    std::string input = username + ":" + password;
    size_t output_size = sizeof("Basic ") + BASE64_ENCODE_OUT_SIZE(input.size());
    char *output = (char *) emalloc(output_size);
    if (sw_likely(output))
    {
        size_t output_len = sprintf(output, "Basic ");
        output_len += swBase64_encode((const unsigned char *) input.c_str(), input.size(), output + output_len);
        basic_auth = std::string((const char *) output, output_len);
        efree(output);
    }
}

bool http_client::bind(std::string address, int port)
{
    return socket->bind(address, port);
}

bool http_client::connect()
{
    if (!socket)
    {
        if (!body)
        {
            body = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
            if (!body)
            {
                zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), ENOMEM);
                zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), swoole_strerror(ENOMEM));
                zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
                return false;
            }
        }

        php_swoole_check_reactor();
        socket = new Socket(socket_type);
        if (UNEXPECTED(socket->get_fd() < 0))
        {
            php_swoole_sys_error(E_WARNING, "new Socket() failed");
            zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), errno);
            zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), swoole_strerror(errno));
            zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            delete socket;
            socket = nullptr;
            return false;
        }
#ifdef SW_USE_OPENSSL
        socket->open_ssl = ssl;
#endif
        // apply settings
        apply_setting(sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0), false);

        // socket->set_buffer_allocator(&SWOOLE_G(zend_string_allocator));
        // connect
        socket->set_timeout(connect_timeout, SW_TIMEOUT_CONNECT);
        if (!socket->connect(host, port))
        {
            zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), socket->errCode);
            zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), socket->errMsg);
            zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            close();
            return false;
        }
        reconnected_count = 0;
        zend_update_property_bool(swoole_http_client_coro_ce, zobject, ZEND_STRL("connected"), 1);
    }
    return true;
}

bool http_client::keep_liveness()
{
    if (!socket || !socket->check_liveness())
    {
        if (socket)
        {
            /* in progress */
            socket->check_bound_co(SW_EVENT_RDWR);
            zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), socket->errCode);
            zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), socket->errMsg);
            zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
            close(false);
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
    zval *zvalue = nullptr;
    uint32_t header_flag = 0x0;
    zval *zmethod, *zheaders, *zbody, *zupload_files, *zcookies, *z_download_file;

    if (path.length() == 0)
    {
        php_swoole_fatal_error(E_WARNING, "path is empty");
        return false;
    }

    // when new request, clear all properties about the last response
    {
        zval *zattr;
        zattr = sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_HEADERS), 0);
        if (ZVAL_IS_ARRAY(zattr))
        {
            zend_hash_clean(Z_ARRVAL_P(zattr));
        }
        zattr = sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SET_COOKIE_HEADERS), 0);
        if (ZVAL_IS_ARRAY(zattr))
        {
            zend_hash_clean(Z_ARRVAL_P(zattr));
        }
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("body"), "");
    }

    if (!keep_liveness())
    {
        return false;
    }
    else
    {
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), 0);
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), "");
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), 0);
    }

    /* another coroutine is connecting */
    socket->check_bound_co(SW_EVENT_WRITE);

    //clear errno
    swoole_set_last_error(0);
    //alloc buffer
    swString *buffer = socket->get_write_buffer();
    swString_clear(buffer);
    // clear body
    swString_clear(body);

    zmethod = sw_zend_read_property_not_null_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_METHOD), 0);
    zheaders = sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_HEADERS), 0);
    zbody = sw_zend_read_property_not_null_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_BODY), 0);
    zupload_files = sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_UPLOAD_FILES), 0);
    zcookies = sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIES), 0);
    z_download_file = sw_zend_read_property_not_null_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_DOWNLOAD_FILE), 0);

    // ============   host   ============
    zend::string str_host;

    if ((ZVAL_IS_ARRAY(zheaders)) && ((zvalue = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("Host"))) || (zvalue = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("host")))))
    {
        str_host = zvalue;
    }

    // ============ download ============
    if (z_download_file)
    {
        download_file_name = z_download_file;
        download_offset = zval_get_long(sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_DOWNLOAD_OFFSET), 0));
    }

    // ============ method ============
    {
        zend::string str_method;
        const char *method;
        size_t method_len;
        if (zmethod)
        {
            str_method = zmethod;
            method = str_method.val();
            method_len = str_method.len();
        }
        else
        {
            method = zbody ? "POST" : "GET";
            method_len = strlen(method);
        }
        this->method = swHttp_get_method(method, method_len);
        swString_append_ptr(buffer, method, method_len);
        swString_append_ptr(buffer, ZEND_STRL(" "));
    }

    // ============ path & proxy ============
#ifdef SW_USE_OPENSSL
    if (socket->http_proxy && !socket->open_ssl)
#else
    if (socket->http_proxy)
#endif
    {
        const static char *pre = "http://";
        char *_host = (char *) host.c_str();
        size_t _host_len = host.length();
        if (str_host.get())
        {
            _host = str_host.val();
            _host_len = str_host.len();
        }
        size_t proxy_uri_len = path.length() + _host_len + strlen(pre) + 10;
        char *proxy_uri = (char*) emalloc(proxy_uri_len);
        proxy_uri_len = sw_snprintf(proxy_uri, proxy_uri_len, "%s%s:%u%s", pre, _host, port, path.c_str());
        swString_append_ptr(buffer, proxy_uri, proxy_uri_len);
        efree(proxy_uri);
    }
    else
    {
        swString_append_ptr(buffer, path.c_str(), path.length());
    }

    // ============ protocol ============
    swString_append_ptr(buffer, ZEND_STRL(" HTTP/1.1\r\n"));

    // ============ headers ============
    char *key;
    uint32_t keylen;
    int keytype;

    // As much as possible to ensure that Host is the first header.
    // See: http://tools.ietf.org/html/rfc7230#section-5.4
    if (str_host.get())
    {
        http_client_swString_append_headers(buffer, ZEND_STRL("Host"), str_host.val(), str_host.len());
    }
    else
    {
        // See: https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.23
        const std::string *_host;
        std::string __host;
#ifndef SW_USE_OPENSSL
        if (port != 80)
#else
        if (!ssl ? port != 80 : port != 443)
#endif
        {
            __host = std_string::format("%s:%u", host.c_str(), port);
            _host = &__host;
        } else {
            _host = &host;
        }
        http_client_swString_append_headers(buffer, ZEND_STRL("Host"), _host->c_str(), _host->length());
    }

    if (ZVAL_IS_ARRAY(zheaders))
    {
        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheaders), key, keylen, keytype, zvalue)
        {
            if (UNEXPECTED(HASH_KEY_IS_STRING != keytype || ZVAL_IS_NULL(zvalue)))
            {
                continue;
            }
            if (SW_STRCASEEQ(key, keylen, "Host"))
            {
                continue;
            }
            if (SW_STRCASEEQ(key, keylen, "Content-Length"))
            {
                header_flag |= HTTP_HEADER_CONTENT_LENGTH;
                //ignore custom Content-Length value
                continue;
            }
            else if (SW_STRCASEEQ(key, keylen, "Connection"))
            {
                header_flag |= HTTP_HEADER_CONNECTION;
            }
            else if (SW_STRCASEEQ(key, keylen, "Accept-Encoding"))
            {
                header_flag |= HTTP_HEADER_ACCEPT_ENCODING;
            }
            zend::string str_value(zvalue);
            http_client_swString_append_headers(buffer, key, keylen, str_value.val(), str_value.len());
        }
        SW_HASHTABLE_FOREACH_END();
    }

    if (!basic_auth.empty())
    {
        http_client_swString_append_headers(buffer, ZEND_STRL("Authorization"), basic_auth.c_str(), basic_auth.size());
    }
    if (!(header_flag & HTTP_HEADER_CONNECTION))
    {
        if (keep_alive)
        {
            http_client_swString_append_headers(buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        }
        else
        {
            http_client_swString_append_headers(buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
        }
    }
#ifdef SW_HAVE_COMPRESSION
    if (!(header_flag & HTTP_HEADER_ACCEPT_ENCODING))
    {
        http_client_swString_append_headers(
            buffer, ZEND_STRL("Accept-Encoding"),
#if defined(SW_HAVE_ZLIB) && defined(SW_HAVE_BROTLI)
            ZEND_STRL("gzip, deflate, br")
#else
#ifdef SW_HAVE_ZLIB
            ZEND_STRL("gzip, deflate")
#else
#ifdef SW_HAVE_BROTLI
            ZEND_STRL("br")
#endif
#endif
#endif
        );
    }
#endif

    // ============ cookies ============
    if (ZVAL_IS_ARRAY(zcookies))
    {
        swString_append_ptr(buffer, ZEND_STRL("Cookie: "));
        int n_cookie = php_swoole_array_length(zcookies);
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zcookies), key, keylen, keytype, zvalue)
        {
            i++;
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }
            zend::string str_value(zvalue);
            if (str_value.len() == 0)
            {
                continue;
            }
            swString_append_ptr(buffer, key, keylen);
            swString_append_ptr(buffer, "=", 1);

            int encoded_value_len;
            encoded_value = php_swoole_url_encode(str_value.val(), str_value.len(), &encoded_value_len);
            if (encoded_value)
            {
                swString_append_ptr(buffer, encoded_value, encoded_value_len);
                efree(encoded_value);
            }
            if (i < n_cookie)
            {
                swString_append_ptr(buffer, "; ", 2);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        swString_append_ptr(buffer, ZEND_STRL("\r\n"));
    }

    // ============ multipart/form-data ============
    if ((has_upload_files = (php_swoole_array_length_safe(zupload_files) > 0)))
    {
        char header_buf[2048];
        char boundary_str[SW_HTTP_CLIENT_BOUNDARY_TOTAL_SIZE];
        int n;

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
        swString_append_ptr(buffer, header_buf, n);

        // ============ content-length ============
        size_t content_length = 0;

        // calculate length before encode array
        if (zbody && ZVAL_IS_ARRAY(zbody))
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zbody), key, keylen, keytype, zvalue)
                if (UNEXPECTED(HASH_KEY_IS_STRING != keytype || ZVAL_IS_NULL(zvalue)))
                {
                    continue;
                }
                zend::string str_value(zvalue);
                //strlen("%.*s")*2 = 8
                //header + body + CRLF(2)
                content_length += (sizeof(SW_HTTP_FORM_RAW_DATA_FMT) - SW_HTTP_FORM_RAW_DATA_FMT_LEN -1) + (sizeof(boundary_str) - 1) + keylen + str_value.len() + 2;
            SW_HASHTABLE_FOREACH_END();
        }

        zval *zname;
        zval *ztype;
        zval *zsize = nullptr;
        zval *zpath = nullptr;
        zval *zcontent = nullptr;
        zval *zfilename;
        zval *zoffset;

        // calculate length of files
        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zupload_files), key, keylen, keytype, zvalue)
            {
                HashTable *ht = Z_ARRVAL_P(zvalue);
                if (!(zname = zend_hash_str_find(ht, ZEND_STRL("name"))))
                {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(ht, ZEND_STRL("filename"))))
                {
                    continue;
                }
                if (!(zsize = zend_hash_str_find(ht, ZEND_STRL("size"))))
                {
                    continue;
                }
                if (!(ztype = zend_hash_str_find(ht, ZEND_STRL("type"))))
                {
                    continue;
                }
                //strlen("%.*s")*4 = 16
                //header + body + CRLF(2)
                content_length +=
                    (sizeof(SW_HTTP_FORM_FILE_DATA_FMT) - SW_HTTP_FORM_FILE_DATA_FMT_LEN - 1) + (sizeof(boundary_str) - 1) +
                    Z_STRLEN_P(zname) + Z_STRLEN_P(zfilename) + Z_STRLEN_P(ztype) + Z_LVAL_P(zsize) + 2;
            }
            SW_HASHTABLE_FOREACH_END();
        }

        http_client_append_content_length(buffer, content_length + sizeof(boundary_str) - 1 + 6);

        // ============ form-data body ============
        if (zbody && ZVAL_IS_ARRAY(zbody))
        {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zbody), key, keylen, keytype, zvalue)
            {
                if (UNEXPECTED(HASH_KEY_IS_STRING != keytype || ZVAL_IS_NULL(zvalue)))
                {
                    continue;
                }
                zend::string str_value(zvalue);
                n = sw_snprintf(
                    header_buf, sizeof(header_buf),
                    SW_HTTP_FORM_RAW_DATA_FMT, (int)(sizeof(boundary_str) - 1),
                    boundary_str, keylen, key
                );
                swString_append_ptr(buffer, header_buf, n);
                swString_append_ptr(buffer, str_value.val(), str_value.len());
                swString_append_ptr(buffer, ZEND_STRL("\r\n"));
            }
            SW_HASHTABLE_FOREACH_END();
        }

        if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length)
        {
            goto _send_fail;
        }

        {
            //upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zupload_files), key, keylen, keytype, zvalue)
            {
                if (!(zname = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("name"))))
                {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("filename"))))
                {
                    continue;
                }
                /**
                 * from disk file
                 */
                if (!(zcontent = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("content"))))
                {
                    //file path
                    if (!(zpath = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("path"))))
                    {
                        continue;
                    }
                    //file offset
                    if (!(zoffset = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("offset"))))
                    {
                        continue;
                    }
                    zcontent = nullptr;
                }
                else
                {
                    zpath = nullptr;
                    zoffset = nullptr;
                }
                if (!(zsize = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("size"))))
                {
                    continue;
                }
                if (!(ztype = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("type"))))
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
                    swString_clear(buffer);
                    swString_append_ptr(buffer, header_buf, n);
                    swString_append_ptr(buffer, Z_STRVAL_P(zcontent), Z_STRLEN_P(zcontent));
                    swString_append_ptr(buffer, "\r\n", 2);

                    if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length)
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
            }
            SW_HASHTABLE_FOREACH_END();
        }

        n = sw_snprintf(header_buf, sizeof(header_buf), "--%.*s--\r\n", (int)(sizeof(boundary_str) - 1), boundary_str);
        if (socket->send_all(header_buf, n) != n)
        {
            goto _send_fail;
        }
        wait = true;
        return true;
    }
    // ============ x-www-form-urlencoded or raw ============
    else if (zbody)
    {
        if (ZVAL_IS_ARRAY(zbody))
        {
            size_t len;
            http_client_swString_append_headers(buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            if (php_swoole_array_length(zbody) > 0)
            {
                smart_str formstr_s = {};
                char *formstr = php_swoole_http_build_query(zbody, &len, &formstr_s);
                if (formstr == nullptr)
                {
                    php_swoole_error(E_WARNING, "http_build_query failed");
                    return false;
                }
                http_client_append_content_length(buffer, len);
                swString_append_ptr(buffer, formstr, len);
                smart_str_free(&formstr_s);
            }
            else
            {
                http_client_append_content_length(buffer, 0);
            }
        }
        else
        {
            char *body;
            size_t body_length = php_swoole_get_send_data(zbody, &body);
            http_client_append_content_length(buffer, body_length);
            swString_append_ptr(buffer, body, body_length);
        }
    }
    // ============ no body ============
    else
    {
        if (header_flag & HTTP_HEADER_CONTENT_LENGTH)
        {
            http_client_append_content_length(buffer, 0);
        }
        else
        {
            swString_append_ptr(buffer, ZEND_STRL("\r\n"));
        }
    }

    swTraceLog(
        SW_TRACE_HTTP_CLIENT,
        "to [%s:%u%s] by fd#%d in cid#%ld with [%zu] bytes: <<EOF\n%.*s\nEOF",
        host.c_str(), port, path.c_str(), socket->get_fd(), Coroutine::get_current_cid(),
        buffer->length, (int) buffer->length, buffer->str
    );

    if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length)
    {
       _send_fail:
       zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), socket->errCode);
       zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), socket->errMsg);
       zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SEND_FAILED);
       close();
       return false;
    }
    wait = true;
    return true;
}

bool http_client::exec(std::string path)
{
    this->path = path;
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
    if (!wait)
    {
        return false;
    }
    if (!socket || !socket->is_connect())
    {
        swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return false;
    }
    if (!recv_http_response(timeout))
    {
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(
            swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"),
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
        socket->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        socket->protocol.package_length_offset = 0;
        socket->protocol.package_body_offset = 0;
        socket->protocol.get_package_length = swWebSocket_get_package_length;
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
    SW_ASSERT(websocket);
    ZVAL_FALSE(zframe);
    if (!socket || !socket->is_connect())
    {
        swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return;
    }

    ssize_t retval = socket->recv_packet(timeout);
    if (retval <= 0)
    {
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
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
#ifdef SW_HAVE_ZLIB
        php_swoole_websocket_frame_unpack_ex(&msg, zframe, websocket_compression);
#else
        php_swoole_websocket_frame_unpack(&msg, zframe);
#endif
        zend_update_property_long(swoole_websocket_frame_ce, zframe, ZEND_STRL("fd"), socket->get_fd());
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
        if (sw_unlikely(tc.has_timedout(SW_TIMEOUT_READ)))
        {
            return false;
        }
        retval = socket->recv(buffer->str, buffer->size);
        if (sw_unlikely(retval <= 0))
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
            // handle redundant data (websocket packet)
            if (parser.upgrade && (size_t) retval > parsed_n + SW_WEBSOCKET_HEADER_LEN)
            {
                buffer->length = retval;
                buffer->offset = parsed_n;
                swString_reduce(buffer, parsed_n);
            }
            return true;
        }
        if (sw_unlikely(parser.state == s_dead))
        {
            socket->set_err(EPROTO);
            return false;
        }
    }
}

bool http_client::upgrade(std::string path)
{
    defer = false;
    if (!websocket)
    {
        char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
        zval *zheaders = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, zobject, ZEND_STRL("requestHeaders"), 0);
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("requestMethod"), "GET");
        http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);
        add_assoc_string(zheaders, "Connection", (char* ) "Upgrade");
        add_assoc_string(zheaders, "Upgrade", (char* ) "websocket");
        add_assoc_string(zheaders, "Sec-WebSocket-Version", (char*) SW_WEBSOCKET_VERSION);
        add_assoc_str_ex(zheaders, ZEND_STRL("Sec-WebSocket-Key"), php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH));
#ifdef SW_HAVE_ZLIB
        if (websocket_compression)
        {
            add_assoc_string(zheaders, "Sec-Websocket-Extensions", (char*) SW_WEBSOCKET_EXTENSION_DEFLATE);
        }
#endif
        exec(path);
    }
    return websocket;
}

bool http_client::push(zval *zdata, zend_long opcode, uint8_t flags)
{
    if (!websocket)
    {
        swoole_set_last_error(SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
        php_swoole_fatal_error(E_WARNING, "websocket handshake failed, cannot push data");
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), "websocket handshake failed, cannot push data");
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
        return false;
    }
    if (!socket || !socket->is_connect())
    {
        swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return false;
    }

    swString *buffer = socket->get_write_buffer();
    swString_clear(buffer);
    if (php_swoole_websocket_frame_is_object(zdata))
    {
        if (php_swoole_websocket_frame_object_pack(buffer, zdata, websocket_mask, websocket_compression) < 0)
        {
            return false;
        }
    }
    else
    {
        if (php_swoole_websocket_frame_pack(buffer, zdata, opcode, flags, websocket_mask, websocket_compression) < 0)
        {
            return false;
        }
    }

    if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length)
    {
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(swoole_http_client_coro_ce, zobject, ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("statusCode"), HTTP_CLIENT_ESTATUS_SERVER_RESET);
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
#ifdef SW_HAVE_COMPRESSION
    compress_method = HTTP_COMPRESS_NONE;
    compression_error = false;
#endif
#ifdef SW_HAVE_ZLIB
    if (gzip_stream_active)
    {
        inflateEnd(&gzip_stream);
        gzip_stream_active = false;
    }
#endif
#ifdef SW_HAVE_BROTLI
    if (brotli_decoder_state)
    {
        BrotliDecoderDestroyInstance(brotli_decoder_state);
        brotli_decoder_state = nullptr;
    }
#endif
    if (has_upload_files)
    {
        zend_update_property_null(swoole_http_client_coro_ce, zobject, ZEND_STRL("uploadFiles"));
    }
    if (download_file_fd >= 0)
    {
        ::close(download_file_fd);
        download_file_fd = -1;
        download_file_name.release();
        download_offset = 0;
        zend_update_property_null(swoole_http_client_coro_ce, zobject, ZEND_STRL("downloadFile"));
        zend_update_property_long(swoole_http_client_coro_ce, zobject, ZEND_STRL("downloadOffset"), 0);
    }
}

bool http_client::close(const bool should_be_reset)
{
    Socket *_socket = socket;
    if (_socket)
    {
        zend_update_property_bool(swoole_http_client_coro_ce, zobject, ZEND_STRL("connected"), 0);
        if (!_socket->has_bound())
        {
            if (should_be_reset)
            {
                reset();
            }
            // reset the properties that depend on the connection
            websocket = false;
#ifdef SW_HAVE_ZLIB
            websocket_compression = false;
#endif
            socket = nullptr;
        }
        php_swoole_client_coro_socket_free(_socket);
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
}

static sw_inline http_client_coro* php_swoole_http_client_coro_fetch_object(zend_object *obj)
{
    return (http_client_coro *) ((char *) obj - swoole_http_client_coro_handlers.offset);
}

static sw_inline http_client * php_swoole_get_phc(zval *zobject)
{
    http_client *phc = php_swoole_http_client_coro_fetch_object(Z_OBJ_P(zobject))->phc;
    if (UNEXPECTED(!phc))
    {
        php_swoole_fatal_error(E_ERROR, "you must call Http Client constructor first");
    }
    return phc;
}

static void php_swoole_http_client_coro_free_object(zend_object *object)
{
    http_client_coro *hcc = php_swoole_http_client_coro_fetch_object(object);
    if (hcc->phc)
    {
        delete hcc->phc;
        hcc->phc = nullptr;
    }
    zend_object_std_dtor(&hcc->std);
}

static zend_object *php_swoole_http_client_coro_create_object(zend_class_entry *ce)
{
    http_client_coro *hcc = (http_client_coro *) zend_object_alloc(sizeof(http_client_coro), ce);
    zend_object_std_init(&hcc->std, ce);
    object_properties_init(&hcc->std, ce);
    hcc->std.handlers = &swoole_http_client_coro_handlers;
    return &hcc->std;
}

void php_swoole_http_client_coro_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_http_client_coro, "Swoole\\Coroutine\\Http\\Client", nullptr, "Co\\Http\\Client", swoole_http_client_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_client_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_client_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_client_coro, php_swoole_http_client_coro_create_object, php_swoole_http_client_coro_free_object, http_client_coro, std);

    // client status
    zend_declare_property_long(swoole_http_client_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http_client_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_client_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);

    // client info
    zend_declare_property_string(swoole_http_client_coro_ce, ZEND_STRL("host"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http_client_coro_ce, ZEND_STRL("ssl"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);

    // request properties
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("requestMethod"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("requestHeaders"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("requestBody"), ZEND_ACC_PUBLIC);
    // always set by API (make it private?)
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("uploadFiles"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("downloadFile"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http_client_coro_ce, ZEND_STRL("downloadOffset"), 0, ZEND_ACC_PUBLIC);

    // response properties
    zend_declare_property_long(swoole_http_client_coro_ce, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_client_coro_ce, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http_client_coro_ce, ZEND_STRL("body"), "", ZEND_ACC_PUBLIC);

    SW_INIT_CLASS_ENTRY_EX(swoole_http_client_coro_exception, "Swoole\\Coroutine\\Http\\Client\\Exception", nullptr, "Co\\Http\\Client\\Exception", nullptr, swoole_exception);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED", HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT", HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET", HTTP_CLIENT_ESTATUS_SERVER_RESET);

#ifdef SW_HAVE_COMPRESSION
    swoole_zlib_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!swoole_zlib_buffer)
    {
        php_swoole_fatal_error(E_ERROR, "[2] swString_new(%d) failed", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

static PHP_METHOD(swoole_http_client_coro, __construct)
{
    http_client_coro *hcc = php_swoole_http_client_coro_fetch_object(Z_OBJ_P(ZEND_THIS));
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

    zend_update_property_stringl(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("port"), port);
    zend_update_property_bool(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("ssl"), ssl);
    // check host
    if (host_len == 0)
    {
        zend_throw_exception_ex(swoole_http_client_coro_exception_ce, EINVAL, "host is empty");
        RETURN_FALSE;
    }
    // check ssl
#ifndef SW_USE_OPENSSL
    if (ssl)
    {
        zend_throw_exception_ex(
            swoole_http_client_coro_exception_ce,
            EPROTONOSUPPORT, "you must configure with `--enable-openssl` to support ssl connection when compiling Swoole"
        );
        RETURN_FALSE;
    }
#endif
    hcc->phc = new http_client(ZEND_THIS, std::string(host, host_len), port, ssl);
}

static PHP_METHOD(swoole_http_client_coro, __destruct) { }

static PHP_METHOD(swoole_http_client_coro, set)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_array_length(zset) == 0)
    {
        RETURN_FALSE;
    }
    else
    {
        zval *zsettings = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
        php_array_merge(Z_ARRVAL_P(zsettings), Z_ARRVAL_P(zset));
        phc->apply_setting(zset);
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_http_client_coro, getDefer)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);

    RETURN_BOOL(phc->defer);
}

static PHP_METHOD(swoole_http_client_coro, setDefer)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);
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
    char *method;
    size_t method_length;

    // Notice: maybe string or array
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(method, method_length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("requestMethod"), method, method_length);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders)
{
    zval *headers;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY_EX(headers, 0, 1)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("requestHeaders"), headers);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setBasicAuth)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    char *username, *password;
    size_t username_len, password_len;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(username, username_len)
        Z_PARAM_STRING(password, password_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    phc->set_basic_auth(std::string(username, username_len), std::string(password, password_len));
}

static PHP_METHOD(swoole_http_client_coro, setCookies)
{
    zval *cookies;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY_EX(cookies, 0, 1)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("cookies"), cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setData)
{
    zval *zdata;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(zdata)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("requestBody"), zdata);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addFile)
{
    char *path;
    size_t l_path;
    char *name;
    size_t l_name;
    char *type = nullptr;
    size_t l_type = 0;
    char *filename = nullptr;
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
        php_swoole_sys_error(E_WARNING, "stat(%s) failed", path);
        RETURN_FALSE;
    }
    if (file_stat.st_size == 0)
    {
        php_swoole_sys_error(E_WARNING, "cannot send empty file[%s]", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= offset)
    {
        php_swoole_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] exceeds the file size", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset)
    {
        php_swoole_sys_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] exceeds the file size", length);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        length = file_stat.st_size - offset;
    }
    if (l_type == 0)
    {
        type = (char *) swoole::mime_type::get(path).c_str();
        l_type = strlen(type);
    }
    if (l_filename == 0)
    {
        char *dot = strrchr(path, '/');
        if (dot == nullptr)
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

    zval *zupload_files = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("uploadFiles"), 0);
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
    char *type = nullptr;
    size_t l_type = 0;
    char *filename = nullptr;
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

    zval *zupload_files = sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("uploadFiles"), 0);
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
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, get)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_string(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("requestMethod"), "GET");

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, post)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;
    zval *post_data;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_ZVAL(post_data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_string(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("requestMethod"), "POST");
    zend_update_property(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("requestBody"), post_data);

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, download)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    char *path;
    size_t path_len;
    zval *download_file;
    zend_long offset = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_ZVAL(download_file)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("downloadFile"), download_file);
    zend_update_property_long(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("downloadOffset"), offset);

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, upgrade)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->upgrade(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, push)
{
    http_client* phc = php_swoole_get_phc(ZEND_THIS);
    zval *zdata;
    zend_long opcode = WEBSOCKET_OPCODE_TEXT;
    zval *zflags = nullptr;
    zend_long flags = SW_WEBSOCKET_FLAG_FIN;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL(zdata)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(opcode)
        Z_PARAM_ZVAL_EX(zflags, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zflags != nullptr)
    {
        flags = zval_get_long(zflags);
    }

    RETURN_BOOL(phc->push(zdata, opcode, flags & SW_WEBSOCKET_FLAGS_ALL));
}

static PHP_METHOD(swoole_http_client_coro, recv)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);
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
    http_client* phc = php_swoole_get_phc(ZEND_THIS);

    RETURN_BOOL(phc->close());
}

static PHP_METHOD(swoole_http_client_coro, getBody)
{
    SW_RETURN_PROPERTY("body");
}

static PHP_METHOD(swoole_http_client_coro, getHeaders)
{
    SW_RETURN_PROPERTY("headers");
}

static PHP_METHOD(swoole_http_client_coro, getCookies)
{
    SW_RETURN_PROPERTY("cookies");
}

static PHP_METHOD(swoole_http_client_coro, getStatusCode)
{
    SW_RETURN_PROPERTY("statusCode");
}

static PHP_METHOD(swoole_http_client_coro, getHeaderOut)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);
    phc->get_header_out(return_value);
}

static PHP_METHOD(swoole_http_client_coro, getsockname)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);
    phc->getsockname(return_value);
}

static PHP_METHOD(swoole_http_client_coro, getpeername)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);
    phc->getpeername(return_value);
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_http_client_coro, getPeerCert)
{
    http_client *phc = php_swoole_get_phc(ZEND_THIS);
    phc->getpeercert(return_value);
}
#endif
