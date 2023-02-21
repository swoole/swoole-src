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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 | Author: Twosee  <twose@qq.com>                                       |
 | Author: Fang  <coooold@live.com>                                     |
 | Author: Yuanyi   Zhi  <syyuanyizhi@163.com>                          |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"
#include "php_swoole_http.h"

#include "swoole_string.h"
#include "swoole_protocol.h"
#include "swoole_file.h"
#include "swoole_util.h"
#include "swoole_websocket.h"
#include "swoole_mime_type.h"
#include "swoole_base64.h"
#include "swoole_socket.h"

SW_EXTERN_C_BEGIN

#include "thirdparty/swoole_http_parser.h"

#include "ext/standard/base64.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

SW_EXTERN_C_END

#ifdef SW_HAVE_BROTLI
#include <brotli/decode.h>
#endif

using swoole::File;
using swoole::String;
using swoole::coroutine::Socket;
using swoole::network::Address;

namespace WebSocket = swoole::websocket;

enum http_client_error_status_code {
    HTTP_CLIENT_ESTATUS_CONNECT_FAILED = -1,
    HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT = -2,
    HTTP_CLIENT_ESTATUS_SERVER_RESET = -3,
    HTTP_CLIENT_ESTATUS_SEND_FAILED = -4,
};

extern void php_swoole_client_coro_socket_free(Socket *cli);

static int http_parser_on_header_field(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_header_value(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_headers_complete(swoole_http_parser *parser);
static int http_parser_on_body(swoole_http_parser *parser, const char *at, size_t length);
static int http_parser_on_message_complete(swoole_http_parser *parser);

// clang-format off
static const swoole_http_parser_settings http_parser_settings = {
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
// clang-format on

namespace swoole {
namespace coroutine {
class HttpClient {
  public:
    /* request info */
    std::string host = "127.0.0.1";
    uint16_t port = 80;
#ifdef SW_USE_OPENSSL
    uint8_t ssl = false;
#endif
    double connect_timeout = network::Socket::default_connect_timeout;
    bool defer = false;
    bool lowercase_header = true;

    int8_t method = SW_HTTP_GET;
    std::string path;
    std::string basic_auth;

    /* for response parser */
    char *tmp_header_field_name = nullptr;
    int tmp_header_field_name_len = 0;
    String *body = nullptr;
#ifdef SW_HAVE_COMPRESSION
    enum swHttpCompressMethod compress_method = HTTP_COMPRESS_NONE;
    bool compression_error = false;
#endif

    /* options */
    uint8_t reconnect_interval = 1;
    uint8_t reconnected_count = 0;
    bool keep_alive = true;      // enable by default
    bool websocket = false;      // if upgrade successfully
    bool chunked = false;        // Transfer-Encoding: chunked
    bool websocket_mask = true;  // enable websocket mask
    bool body_decompression = true;
    bool http_compression = true;
#ifdef SW_HAVE_ZLIB
    bool websocket_compression = false;  // allow to compress websocket messages
#endif
    File *download_file = nullptr;    // save http response to file
    zend::String download_file_name;  // unlink the file on error
    zend_long download_offset = 0;
    bool has_upload_files = false;

    /* safety zval */
    zval _zobject;
    zval *zobject = &_zobject;
    String *tmp_write_buffer = nullptr;
    bool connection_close = false;

    HttpClient(zval *zobject, std::string host, zend_long port = 80, zend_bool ssl = false);

  private:
#ifdef SW_HAVE_ZLIB
    bool gzip_stream_active = false;
    z_stream gzip_stream = {};
#endif
#ifdef SW_HAVE_BROTLI
    BrotliDecoderState *brotli_decoder_state = nullptr;
#endif
    bool bind(std::string address, int port = 0);
    bool connect();
    void set_error(int error, const char *msg, int status);
    bool keep_liveness();
    bool send();
    void reset();

    static void add_headers(String *buf, const char *key, size_t key_len, const char *data, size_t data_len) {
        buf->append(key, key_len);
        buf->append(ZEND_STRL(": "));
        buf->append(data, data_len);
        buf->append(ZEND_STRL("\r\n"));
    }

    static void add_content_length(String *buf, size_t length) {
        char content_length_str[64];
        size_t n = sw_snprintf(SW_STRS(content_length_str), "Content-Length: %zu\r\n\r\n", length);
        buf->append(content_length_str, n);
    }

    static void create_token(int length, char *buf) {
        char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"§$%&/()=[]{}";
        int i;
        assert(length < 1024);
        for (i = 0; i < length; i++) {
            buf[i] = characters[rand() % (sizeof(characters) - 1)];
        }
        buf[length] = '\0';
    }

  public:
#ifdef SW_HAVE_COMPRESSION
    bool decompress_response(const char *in, size_t in_len);
#endif
    void apply_setting(zval *zset, const bool check_all = true);
    void set_basic_auth(const std::string &username, const std::string &password);
    bool exec(std::string _path);
    bool recv(double timeout = 0);
    void recv(zval *zframe, double timeout = 0);
    bool recv_http_response(double timeout = 0);
    bool upgrade(std::string path);
    bool push(zval *zdata, zend_long opcode = websocket::OPCODE_TEXT, uint8_t flags = websocket::FLAG_FIN);
    bool close(const bool should_be_reset = true);

    void get_header_out(zval *return_value) {
        String *buffer = nullptr;
        if (socket == nullptr) {
            if (tmp_write_buffer) {
                buffer = tmp_write_buffer;
            }
        } else {
            buffer = socket->get_write_buffer();
        }
        if (buffer == nullptr) {
            RETURN_FALSE;
        }
        off_t offset = swoole_strnpos(buffer->str, buffer->length, ZEND_STRL("\r\n\r\n"));
        if (offset <= 0) {
            RETURN_FALSE;
        }

        RETURN_STRINGL(buffer->str, offset);
    }

    void getsockname(zval *return_value) {
        Address sa;
        if (!socket || !socket->getsockname(&sa)) {
            ZVAL_FALSE(return_value);
            return;
        }

        array_init(return_value);
        add_assoc_string(return_value, "address", (char *) sa.get_ip());
        add_assoc_long(return_value, "port", sa.get_port());
    }

    void getpeername(zval *return_value) {
        Address sa;
        if (!socket || !socket->getpeername(&sa)) {
            ZVAL_FALSE(return_value);
            return;
        }

        array_init(return_value);
        add_assoc_string(return_value, "address", (char *) sa.get_ip());
        add_assoc_long(return_value, "port", sa.get_port());
    }

#ifdef SW_USE_OPENSSL
    void getpeercert(zval *return_value) {
        auto cert = socket->ssl_get_peer_cert();
        if (cert.empty()) {
            ZVAL_FALSE(return_value);
            return;
        } else {
            ZVAL_STRINGL(return_value, cert.c_str(), cert.length());
        }
    }
#endif

    ~HttpClient();

  private:
    Socket *socket = nullptr;
    SocketType socket_type = SW_SOCK_TCP;
    swoole_http_parser parser = {};
    bool wait = false;
};

}  // namespace coroutine
}  // namespace swoole

static zend_class_entry *swoole_http_client_coro_ce;
static zend_object_handlers swoole_http_client_coro_handlers;

static zend_class_entry *swoole_http_client_coro_exception_ce;
static zend_object_handlers swoole_http_client_coro_exception_handlers;

using swoole::coroutine::HttpClient;

struct HttpClientObject {
    HttpClient *phc;
    zend_object std;
};

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

// clang-format off

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

// clang-format on

void http_parse_set_cookies(const char *at, size_t length, zval *zcookies, zval *zset_cookie_headers) {
    const char *p, *eof = at + length;
    size_t key_len = 0, value_len = 0;
    zval zvalue;

    // key
    p = (char *) memchr(at, '=', length);
    if (p) {
        key_len = p - at;
        p++;  // point to value
    } else {
        p = at;  // key is empty
    }
    // value
    eof = (char *) memchr(p, ';', at + length - p);
    if (!eof) {
        eof = at + length;
    }
    value_len = eof - p;
    if (value_len != 0) {
        ZVAL_STRINGL(&zvalue, p, value_len);
        Z_STRLEN(zvalue) = php_url_decode(Z_STRVAL(zvalue), value_len);
    } else {
        ZVAL_EMPTY_STRING(&zvalue);
    }
    if (key_len == 0) {
        add_next_index_zval(zcookies, &zvalue);
    } else {
        add_assoc_zval_ex(zcookies, at, key_len, &zvalue);
    }

    // set_cookie_headers
    add_next_index_stringl(zset_cookie_headers, (char *) at, length);
}

static int http_parser_on_header_field(swoole_http_parser *parser, const char *at, size_t length) {
    HttpClient *http = (HttpClient *) parser->data;
    http->tmp_header_field_name = (char *) at;
    http->tmp_header_field_name_len = length;
    return 0;
}

static int http_parser_on_header_value(swoole_http_parser *parser, const char *at, size_t length) {
    HttpClient *http = (HttpClient *) parser->data;
    zval *zobject = (zval *) http->zobject;
    zval *zheaders =
        sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, zobject, ZEND_STRL("headers"), 0);
    char *header_name = http->tmp_header_field_name;
    size_t header_len = http->tmp_header_field_name_len;

    if (http->lowercase_header) {
        header_name = zend_str_tolower_dup(header_name, header_len);
    }

    add_assoc_stringl_ex(zheaders, header_name, header_len, (char *) at, length);

    if (parser->status_code == SW_HTTP_SWITCHING_PROTOCOLS && SW_STREQ(header_name, header_len, "upgrade")) {
        if (swoole_http_token_list_contains_value(at, length, "websocket")) {
            http->websocket = true;
        }
        /* TODO: protocol error? */
    }
#ifdef SW_HAVE_ZLIB
    else if (http->websocket && http->websocket_compression &&
             SW_STREQ(header_name, header_len, "sec-websocket-extensions")) {
        if (SW_STRCASECT(at, length, "permessage-deflate") && SW_STRCASECT(at, length, "client_no_context_takeover") &&
            SW_STRCASECT(at, length, "server_no_context_takeover")) {
            http->websocket_compression = true;
        }
    }
#endif
    else if (SW_STREQ(header_name, header_len, "set-cookie")) {
        zval *zcookies =
            sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, zobject, ZEND_STRL("cookies"), 0);
        zval *zset_cookie_headers = sw_zend_read_and_convert_property_array(
            swoole_http_client_coro_ce, zobject, ZEND_STRL("set_cookie_headers"), 0);
        http_parse_set_cookies(at, length, zcookies, zset_cookie_headers);
    }
#ifdef SW_HAVE_COMPRESSION
    else if (SW_STREQ(header_name, header_len, "content-encoding")) {
        if (0) {
        }
#ifdef SW_HAVE_BROTLI
        else if (SW_STRCASECT(at, length, "br")) {
            http->compress_method = HTTP_COMPRESS_BR;
        }
#endif
#ifdef SW_HAVE_ZLIB
        else if (SW_STRCASECT(at, length, "gzip")) {
            http->compress_method = HTTP_COMPRESS_GZIP;
        } else if (SW_STRCASECT(at, length, "deflate")) {
            http->compress_method = HTTP_COMPRESS_DEFLATE;
        }
#endif
    }
#endif
    else if (SW_STREQ(header_name, header_len, "transfer-encoding") && SW_STRCASECT(at, length, "chunked")) {
        http->chunked = true;
    } else if (SW_STREQ(header_name, header_len, "connection")) {
        http->connection_close = SW_STRCASECT(at, length, "close");
    }

    if (http->lowercase_header) {
        efree(header_name);
    }

    return 0;
}

static int http_parser_on_headers_complete(swoole_http_parser *parser) {
    HttpClient *http = (HttpClient *) parser->data;
    if (http->method == SW_HTTP_HEAD || parser->status_code == SW_HTTP_NO_CONTENT) {
        return 1;
    }
    return 0;
}

static int http_parser_on_body(swoole_http_parser *parser, const char *at, size_t length) {
    HttpClient *http = (HttpClient *) parser->data;
#ifdef SW_HAVE_COMPRESSION
    if (http->body_decompression && !http->compression_error && http->compress_method != HTTP_COMPRESS_NONE) {
        if (!http->decompress_response(at, length)) {
            http->compression_error = true;
            goto _append_raw;
        }
    } else
#endif
    {
#ifdef SW_HAVE_COMPRESSION
    _append_raw:
#endif
        if (http->body->append(at, length) < 0) {
            return -1;
        }
    }
    if (http->download_file_name.get() && http->body->length > 0) {
        if (http->download_file == nullptr) {
            char *download_file_name = http->download_file_name.val();
            std::unique_ptr<File> fp(new File(download_file_name, O_CREAT | O_WRONLY, 0664));
            if (!fp->ready()) {
                swoole_sys_warning("open(%s, O_CREAT | O_WRONLY) failed", download_file_name);
                return false;
            }
            if (http->download_offset == 0) {
                if (!fp->truncate(0)) {
                    swoole_sys_warning("ftruncate(%s) failed", download_file_name);
                    return false;
                }
            } else {
                if (!fp->set_offest(http->download_offset)) {
                    swoole_sys_warning("fseek(%s, %jd) failed", download_file_name, (intmax_t) http->download_offset);
                    return false;
                }
            }
            http->download_file = fp.release();
        }
        if (swoole_coroutine_write(http->download_file->get_fd(), SW_STRINGL(http->body)) !=
            (ssize_t) http->body->length) {
            return -1;
        }
        http->body->clear();
    }
    return 0;
}

static int http_parser_on_message_complete(swoole_http_parser *parser) {
    HttpClient *http = (HttpClient *) parser->data;
    zval *zobject = (zval *) http->zobject;

    if (parser->upgrade && !http->websocket) {
        // not support, continue.
        parser->upgrade = 0;
        return 0;
    }

    zend_update_property_long(
        swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("statusCode"), parser->status_code);
    if (http->download_file == nullptr) {
        zend_update_property_stringl(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("body"), SW_STRINGL(http->body));
    } else {
        http->download_file_name.release();
    }

    if (parser->upgrade) {
        // return 1 will finish the parser and means yes we support it.
        return 1;
    } else {
        return 0;
    }
}

HttpClient::HttpClient(zval *zobject, std::string host, zend_long port, zend_bool ssl) {
    this->socket_type = network::Socket::convert_to_type(host);
    this->host = host;
    this->port = port;
#ifdef SW_USE_OPENSSL
    this->ssl = ssl;
#endif
    _zobject = *zobject;
    // TODO: zend_read_property cache here (strong type properties)
}

#ifdef SW_HAVE_COMPRESSION
bool HttpClient::decompress_response(const char *in, size_t in_len) {
    if (in_len == 0) {
        return false;
    }

    size_t reserved_body_length = body->length;

    switch (compress_method) {
#ifdef SW_HAVE_ZLIB
    case HTTP_COMPRESS_GZIP:
    case HTTP_COMPRESS_DEFLATE: {
        int status;
        int encoding = compress_method == HTTP_COMPRESS_GZIP ? SW_ZLIB_ENCODING_GZIP : SW_ZLIB_ENCODING_DEFLATE;
        bool first_decompress = !gzip_stream_active;
        size_t total_out;

        if (!gzip_stream_active) {
        _retry:
            memset(&gzip_stream, 0, sizeof(gzip_stream));
            gzip_stream.zalloc = php_zlib_alloc;
            gzip_stream.zfree = php_zlib_free;
            // gzip_stream.total_out = 0;
            status = inflateInit2(&gzip_stream, encoding);
            if (status != Z_OK) {
                swoole_warning("inflateInit2() failed by %s", zError(status));
                return false;
            }
            gzip_stream_active = true;
        }

        gzip_stream.next_in = (Bytef *) in;
        gzip_stream.avail_in = in_len;
        gzip_stream.total_in = 0;

        while (1) {
            total_out = gzip_stream.total_out;
            gzip_stream.avail_out = body->size - body->length;
            gzip_stream.next_out = (Bytef *) (body->str + body->length);
            SW_ASSERT(body->length <= body->size);
            status = inflate(&gzip_stream, Z_SYNC_FLUSH);
            if (status >= 0) {
                body->length += (gzip_stream.total_out - total_out);
                if (body->length + (SW_BUFFER_SIZE_STD / 2) >= body->size) {
                    if (!body->extend()) {
                        status = Z_MEM_ERROR;
                        break;
                    }
                }
            }
            if (status == Z_STREAM_END || (status == Z_OK && gzip_stream.avail_in == 0)) {
                return true;
            }
            if (status != Z_OK) {
                break;
            }
        }

        if (status == Z_DATA_ERROR && first_decompress) {
            first_decompress = false;
            inflateEnd(&gzip_stream);
            encoding = SW_ZLIB_ENCODING_RAW;
            body->length = reserved_body_length;
            goto _retry;
        }

        swoole_warning("HttpClient::decompress_response failed by %s", zError(status));
        body->length = reserved_body_length;
        return false;
    }
#endif
#ifdef SW_HAVE_BROTLI
    case HTTP_COMPRESS_BR: {
        if (!brotli_decoder_state) {
            brotli_decoder_state = BrotliDecoderCreateInstance(php_brotli_alloc, php_brotli_free, nullptr);
            if (!brotli_decoder_state) {
                swoole_warning("BrotliDecoderCreateInstance() failed");
                return false;
            }
        }

        const char *next_in = in;
        size_t available_in = in_len;
        while (1) {
            size_t available_out = body->size - body->length, reserved_available_out = available_out;
            char *next_out = body->str + body->length;
            size_t total_out;
            BrotliDecoderResult result;
            SW_ASSERT(body->length <= body->size);
            result = BrotliDecoderDecompressStream(brotli_decoder_state,
                                                   &available_in,
                                                   (const uint8_t **) &next_in,
                                                   &available_out,
                                                   (uint8_t **) &next_out,
                                                   &total_out);
            body->length += reserved_available_out - available_out;
            if (result == BROTLI_DECODER_RESULT_SUCCESS || result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
                return true;
            } else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
                if (!body->extend()) {
                    swoole_warning("BrotliDecoderDecompressStream() failed, no memory is available");
                    break;
                }
            } else {
                swoole_warning("BrotliDecoderDecompressStream() failed, %s",
                               BrotliDecoderErrorString(BrotliDecoderGetErrorCode(brotli_decoder_state)));
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

    swoole_warning("HttpClient::decompress_response unknown compress method [%d]", compress_method);
    return false;
}
#endif

void HttpClient::apply_setting(zval *zset, const bool check_all) {
    if (!ZVAL_IS_ARRAY(zset) || php_swoole_array_length(zset) == 0) {
        return;
    }
    if (check_all) {
        zval *ztmp;
        HashTable *vht = Z_ARRVAL_P(zset);

        if (php_swoole_array_get_value(vht, "connect_timeout", ztmp) ||
            php_swoole_array_get_value(vht, "timeout", ztmp) /* backward compatibility */) {
            connect_timeout = zval_get_double(ztmp);
        }
        if (php_swoole_array_get_value(vht, "reconnect", ztmp)) {
            reconnect_interval = (uint8_t) SW_MIN(zval_get_long(ztmp), UINT8_MAX);
        }
        if (php_swoole_array_get_value(vht, "defer", ztmp)) {
            defer = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "lowercase_header", ztmp)) {
            lowercase_header = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "keep_alive", ztmp)) {
            keep_alive = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "websocket_mask", ztmp)) {
            websocket_mask = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "http_compression", ztmp)) {
            http_compression = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(vht, "body_decompression", ztmp)) {
            body_decompression = zval_is_true(ztmp);
        }
#ifdef SW_HAVE_ZLIB
        if (php_swoole_array_get_value(vht, "websocket_compression", ztmp)) {
            websocket_compression = zval_is_true(ztmp);
        }
#endif
    }
    if (socket) {
        php_swoole_client_set(socket, zset);
#ifdef SW_USE_OPENSSL
        if (socket->http_proxy && !socket->ssl_is_enable())
#else
        if (socket->http_proxy)
#endif
        {
            socket->http_proxy->dont_handshake = 1;
        }
    }
}

void HttpClient::set_basic_auth(const std::string &username, const std::string &password) {
    std::string input = username + ":" + password;
    size_t output_size = sizeof("Basic ") + BASE64_ENCODE_OUT_SIZE(input.size());
    char *output = (char *) emalloc(output_size);
    if (sw_likely(output)) {
        size_t output_len = sprintf(output, "Basic ");
        output_len += base64_encode((const unsigned char *) input.c_str(), input.size(), output + output_len);
        basic_auth = std::string((const char *) output, output_len);
        efree(output);
    }
}

bool HttpClient::connect() {
    if (!socket) {
        if (!body) {
            body = new String(SW_HTTP_RESPONSE_INIT_SIZE);
            if (!body) {
                set_error(ENOMEM, swoole_strerror(ENOMEM), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
                return false;
            }
        }

        php_swoole_check_reactor();
        socket = new Socket(socket_type);
        if (UNEXPECTED(socket->get_fd() < 0)) {
            php_swoole_sys_error(E_WARNING, "new Socket() failed");
            set_error(errno, swoole_strerror(errno), HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            delete socket;
            socket = nullptr;
            return false;
        }
#ifdef SW_USE_OPENSSL
        if (ssl) {
            socket->enable_ssl_encrypt();
        }
#endif
        // apply settings
        apply_setting(
            sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0),
            false);

        // socket->set_buffer_allocator(&SWOOLE_G(zend_string_allocator));
        // connect
        socket->set_timeout(connect_timeout, Socket::TIMEOUT_CONNECT);
        if (!socket->connect(host, port)) {
            set_error(socket->errCode, socket->errMsg, HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            close();
            return false;
        }
        reconnected_count = 0;
        zend_update_property_bool(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("connected"), 1);
    }
    return true;
}

void HttpClient::set_error(int error, const char *msg, int status) {
    auto ce = swoole_http_client_coro_ce;
    auto obj = SW_Z8_OBJ_P(zobject);
    zend_update_property_long(ce, obj, ZEND_STRL("errCode"), error);
    zend_update_property_string(ce, obj, ZEND_STRL("errMsg"), msg);
    zend_update_property_long(ce, obj, ZEND_STRL("statusCode"), status);
}

bool HttpClient::keep_liveness() {
    if (!socket || !socket->check_liveness()) {
        if (socket) {
            /* in progress */
            socket->check_bound_co(SW_EVENT_RDWR);
            set_error(socket->errCode, socket->errMsg, HTTP_CLIENT_ESTATUS_SERVER_RESET);
            close(false);
        }
        for (; reconnected_count < reconnect_interval; reconnected_count++) {
            if (connect()) {
                return true;
            }
        }
        return false;
    }
    return true;
}

bool HttpClient::send() {
    zval *zvalue = nullptr;
    uint32_t header_flag = 0x0;
    zval *zmethod, *zheaders, *zbody, *zupload_files, *zcookies, *z_download_file;

    if (path.length() == 0) {
        php_swoole_fatal_error(E_WARNING, "path is empty");
        return false;
    }

    // when new request, clear all properties about the last response
    {
        zend_update_property_null(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("headers"));
        zend_update_property_null(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("set_cookie_headers"));
        zend_update_property_string(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("body"), "");
    }

    if (!keep_liveness()) {
        return false;
    } else {
        zend_update_property_long(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), 0);
        zend_update_property_string(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "");
        zend_update_property_long(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("statusCode"), 0);
    }

    /* another coroutine is connecting */
    socket->check_bound_co(SW_EVENT_WRITE);

    // clear errno
    swoole_set_last_error(0);
    // alloc buffer
    String *buffer = socket->get_write_buffer();
    buffer->clear();
    // clear body
    body->clear();

    zmethod = sw_zend_read_property_not_null_ex(
        swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_METHOD), 0);
    zheaders =
        sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_HEADERS), 0);
    zbody = sw_zend_read_property_not_null_ex(
        swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_BODY), 0);
    zupload_files =
        sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_UPLOAD_FILES), 0);
    zcookies = sw_zend_read_property_ex(swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIES), 0);
    z_download_file = sw_zend_read_property_not_null_ex(
        swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_DOWNLOAD_FILE), 0);

    // ============   host   ============
    zend::String str_host;

    if ((ZVAL_IS_ARRAY(zheaders)) && ((zvalue = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("Host"))) ||
                                      (zvalue = zend_hash_str_find(Z_ARRVAL_P(zheaders), ZEND_STRL("host"))))) {
        str_host = zvalue;
    }

    // ============ download ============
    if (z_download_file) {
        download_file_name = z_download_file;
        download_offset = zval_get_long(sw_zend_read_property_ex(
            swoole_http_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_DOWNLOAD_OFFSET), 0));
    }

    // ============ method ============
    {
        zend::String str_method;
        const char *method;
        size_t method_len;
        if (zmethod) {
            str_method = zmethod;
            method = str_method.val();
            method_len = str_method.len();
        } else {
            method = zbody ? "POST" : "GET";
            method_len = strlen(method);
        }
        this->method = http_server::get_method(method, method_len);
        buffer->append(method, method_len);
        buffer->append(ZEND_STRL(" "));
    }

    // ============ path & proxy ============
    bool require_proxy_authentication = false;
#ifdef SW_USE_OPENSSL
    if (socket->http_proxy && !socket->ssl_is_enable())
#else
    if (socket->http_proxy)
#endif
    {
        const static char *pre = "http://";
        char *_host = (char *) host.c_str();
        size_t _host_len = host.length();
        if (str_host.get()) {
            _host = str_host.val();
            _host_len = str_host.len();
        }
        size_t proxy_uri_len = path.length() + _host_len + strlen(pre) + 10;
        char *proxy_uri = (char *) emalloc(proxy_uri_len);
        if (nullptr == memchr(_host, ':', _host_len)) {
            proxy_uri_len = sw_snprintf(proxy_uri, proxy_uri_len, "%s%s:%u%s", pre, _host, port, path.c_str());
        } else {
            proxy_uri_len = sw_snprintf(proxy_uri, proxy_uri_len, "%s%s%s", pre, _host, path.c_str());
        }
        buffer->append(proxy_uri, proxy_uri_len);
        if (!socket->http_proxy->password.empty()) {
            require_proxy_authentication = true;
        }
        efree(proxy_uri);
    } else {
        buffer->append(path.c_str(), path.length());
    }

    // ============ protocol ============
    buffer->append(ZEND_STRL(" HTTP/1.1\r\n"));

    // ============ headers ============
    char *key;
    uint32_t keylen;
    int keytype;

    // As much as possible to ensure that Host is the first header.
    // See: http://tools.ietf.org/html/rfc7230#section-5.4
    if (str_host.get()) {
        add_headers(buffer, ZEND_STRL("Host"), str_host.val(), str_host.len());
    } else {
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
        add_headers(buffer, ZEND_STRL("Host"), _host->c_str(), _host->length());
    }

    if (ZVAL_IS_ARRAY(zheaders)) {
        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheaders), key, keylen, keytype, zvalue) {
            if (UNEXPECTED(HASH_KEY_IS_STRING != keytype || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            if (SW_STRCASEEQ(key, keylen, "Host")) {
                continue;
            }
            if (SW_STRCASEEQ(key, keylen, "Content-Length")) {
                header_flag |= HTTP_HEADER_CONTENT_LENGTH;
                // ignore custom Content-Length value
                continue;
            }

            if (SW_STRCASEEQ(key, keylen, "Accept-Encoding")) {
#ifdef SW_HAVE_COMPRESSION
                header_flag |= HTTP_HEADER_ACCEPT_ENCODING;
#else
                php_swoole_error(E_WARNING, "Missing a compression package, 'Accept-Encoding' is ignored");
                continue;
#endif
            }

            zend::String str_value(zvalue);
            add_headers(buffer, key, keylen, str_value.val(), str_value.len());

            if (SW_STRCASEEQ(key, keylen, "Connection")) {
                header_flag |= HTTP_HEADER_CONNECTION;
                if (SW_STRCASEEQ(str_value.val(), str_value.len(), "close")) {
                    keep_alive = 0;
                }
            }
        }
        SW_HASHTABLE_FOREACH_END();
    }
    // http proxy authentication
    if (require_proxy_authentication) {
        std::string value("Basic ");
        value += socket->http_proxy->get_auth_str();
        add_headers(buffer, ZEND_STRL("Proxy-Authorization"), value.c_str(), value.length());
    }
    if (!basic_auth.empty()) {
        add_headers(buffer, ZEND_STRL("Authorization"), basic_auth.c_str(), basic_auth.size());
    }
    if (!(header_flag & HTTP_HEADER_CONNECTION)) {
        if (keep_alive) {
            add_headers(buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        } else {
            add_headers(buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
        }
    }
#ifdef SW_HAVE_COMPRESSION
    if (http_compression && !(header_flag & HTTP_HEADER_ACCEPT_ENCODING)) {
        add_headers(buffer,
                    ZEND_STRL("Accept-Encoding"),
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
    if (ZVAL_IS_ARRAY(zcookies)) {
        buffer->append(ZEND_STRL("Cookie: "));
        int n_cookie = php_swoole_array_length(zcookies);
        int i = 0;
        char *encoded_value;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zcookies), key, keylen, keytype, zvalue) {
            i++;
            if (HASH_KEY_IS_STRING != keytype) {
                continue;
            }
            zend::String str_value(zvalue);
            if (str_value.len() == 0) {
                continue;
            }
            buffer->append(key, keylen);
            buffer->append("=", 1);

            size_t encoded_value_len;
            encoded_value = php_swoole_url_encode(str_value.val(), str_value.len(), &encoded_value_len);
            if (encoded_value) {
                buffer->append(encoded_value, encoded_value_len);
                efree(encoded_value);
            }
            if (i < n_cookie) {
                buffer->append("; ", 2);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        buffer->append(ZEND_STRL("\r\n"));
    }

    // ============ multipart/form-data ============
    if ((has_upload_files = (php_swoole_array_length_safe(zupload_files) > 0))) {
        char header_buf[2048];
        char boundary_str[SW_HTTP_CLIENT_BOUNDARY_TOTAL_SIZE];
        int n;

        // ============ content-type ============
        memcpy(boundary_str, SW_HTTP_CLIENT_BOUNDARY_PREKEY, sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1);
        swoole_random_string(boundary_str + sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY) - 1,
                             sizeof(boundary_str) - sizeof(SW_HTTP_CLIENT_BOUNDARY_PREKEY));
        n = sw_snprintf(header_buf,
                        sizeof(header_buf),
                        "Content-Type: multipart/form-data; boundary=%.*s\r\n",
                        (int) (sizeof(boundary_str) - 1),
                        boundary_str);
        buffer->append(header_buf, n);

        // ============ content-length ============
        size_t content_length = 0;

        // calculate length before encode array
        if (zbody && ZVAL_IS_ARRAY(zbody)) {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zbody), key, keylen, keytype, zvalue)
            if (UNEXPECTED(HASH_KEY_IS_STRING != keytype || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            zend::String str_value(zvalue);
            // strlen("%.*s")*2 = 8
            // header + body + CRLF(2)
            content_length += (sizeof(SW_HTTP_FORM_RAW_DATA_FMT) - SW_HTTP_FORM_RAW_DATA_FMT_LEN - 1) +
                              (sizeof(boundary_str) - 1) + keylen + str_value.len() + 2;
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
            // upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zupload_files), key, keylen, keytype, zvalue) {
                HashTable *ht = Z_ARRVAL_P(zvalue);
                if (!(zname = zend_hash_str_find(ht, ZEND_STRL("name")))) {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(ht, ZEND_STRL("filename")))) {
                    continue;
                }
                if (!(zsize = zend_hash_str_find(ht, ZEND_STRL("size")))) {
                    continue;
                }
                if (!(ztype = zend_hash_str_find(ht, ZEND_STRL("type")))) {
                    continue;
                }
                // strlen("%.*s")*4 = 16
                // header + body + CRLF(2)
                content_length += (sizeof(SW_HTTP_FORM_FILE_DATA_FMT) - SW_HTTP_FORM_FILE_DATA_FMT_LEN - 1) +
                                  (sizeof(boundary_str) - 1) + Z_STRLEN_P(zname) + Z_STRLEN_P(zfilename) +
                                  Z_STRLEN_P(ztype) + Z_LVAL_P(zsize) + 2;
            }
            SW_HASHTABLE_FOREACH_END();
        }

        add_content_length(buffer, content_length + sizeof(boundary_str) - 1 + 6);

        // ============ form-data body ============
        if (zbody && ZVAL_IS_ARRAY(zbody)) {
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zbody), key, keylen, keytype, zvalue) {
                if (UNEXPECTED(HASH_KEY_IS_STRING != keytype || ZVAL_IS_NULL(zvalue))) {
                    continue;
                }
                zend::String str_value(zvalue);
                n = sw_snprintf(header_buf,
                                sizeof(header_buf),
                                SW_HTTP_FORM_RAW_DATA_FMT,
                                (int) (sizeof(boundary_str) - 1),
                                boundary_str,
                                keylen,
                                key);
                buffer->append(header_buf, n);
                buffer->append(str_value.val(), str_value.len());
                buffer->append(ZEND_STRL("\r\n"));
            }
            SW_HASHTABLE_FOREACH_END();
        }

        if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length) {
            goto _send_fail;
        }

        {
            // upload files
            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zupload_files), key, keylen, keytype, zvalue) {
                if (!(zname = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("name")))) {
                    continue;
                }
                if (!(zfilename = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("filename")))) {
                    continue;
                }
                /**
                 * from disk file
                 */
                if (!(zcontent = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("content")))) {
                    // file path
                    if (!(zpath = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("path")))) {
                        continue;
                    }
                    // file offset
                    if (!(zoffset = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("offset")))) {
                        continue;
                    }
                    zcontent = nullptr;
                } else {
                    zpath = nullptr;
                    zoffset = nullptr;
                }
                if (!(zsize = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("size")))) {
                    continue;
                }
                if (!(ztype = zend_hash_str_find(Z_ARRVAL_P(zvalue), ZEND_STRL("type")))) {
                    continue;
                }
                /**
                 * part header
                 */
                n = sw_snprintf(header_buf,
                                sizeof(header_buf),
                                SW_HTTP_FORM_FILE_DATA_FMT,
                                (int) (sizeof(boundary_str) - 1),
                                boundary_str,
                                (int) Z_STRLEN_P(zname),
                                Z_STRVAL_P(zname),
                                (int) Z_STRLEN_P(zfilename),
                                Z_STRVAL_P(zfilename),
                                (int) Z_STRLEN_P(ztype),
                                Z_STRVAL_P(ztype));
                /**
                 * from memory
                 */
                if (zcontent) {
                    buffer->clear();
                    buffer->append(header_buf, n);
                    buffer->append(Z_STRVAL_P(zcontent), Z_STRLEN_P(zcontent));
                    buffer->append("\r\n", 2);

                    if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length) {
                        goto _send_fail;
                    }
                }
                /**
                 * from disk file
                 */
                else {
                    if (socket->send_all(header_buf, n) != n) {
                        goto _send_fail;
                    }
                    if (!socket->sendfile(Z_STRVAL_P(zpath), Z_LVAL_P(zoffset), Z_LVAL_P(zsize))) {
                        goto _send_fail;
                    }
                    if (socket->send_all("\r\n", 2) != 2) {
                        goto _send_fail;
                    }
                }
            }
            SW_HASHTABLE_FOREACH_END();
        }

        n = sw_snprintf(header_buf, sizeof(header_buf), "--%.*s--\r\n", (int) (sizeof(boundary_str) - 1), boundary_str);
        if (socket->send_all(header_buf, n) != n) {
            goto _send_fail;
        }
        wait = true;
        return true;
    }
    // ============ x-www-form-urlencoded or raw ============
    else if (zbody) {
        if (ZVAL_IS_ARRAY(zbody)) {
            size_t len;
            add_headers(buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            if (php_swoole_array_length(zbody) > 0) {
                smart_str formstr_s = {};
                char *formstr = php_swoole_http_build_query(zbody, &len, &formstr_s);
                if (formstr == nullptr) {
                    php_swoole_error(E_WARNING, "http_build_query failed");
                    return false;
                }
                add_content_length(buffer, len);
                buffer->append(formstr, len);
                smart_str_free(&formstr_s);
            } else {
                add_content_length(buffer, 0);
            }
        } else {
            char *body;
            size_t body_length = php_swoole_get_send_data(zbody, &body);
            add_content_length(buffer, body_length);
            buffer->append(body, body_length);
        }
    }
    // ============ no body ============
    else {
        if (header_flag & HTTP_HEADER_CONTENT_LENGTH) {
            add_content_length(buffer, 0);
        } else {
            buffer->append(ZEND_STRL("\r\n"));
        }
    }

    swoole_trace_log(SW_TRACE_HTTP_CLIENT,
                     "to [%s:%u%s] by fd#%d in cid#%ld with [%zu] bytes: <<EOF\n%.*s\nEOF",
                     host.c_str(),
                     port,
                     path.c_str(),
                     socket->get_fd(),
                     Coroutine::get_current_cid(),
                     buffer->length,
                     (int) buffer->length,
                     buffer->str);

    if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length) {
    _send_fail:
        set_error(socket->errCode, socket->errMsg, HTTP_CLIENT_ESTATUS_SEND_FAILED);
        close();
        return false;
    }
    wait = true;
    return true;
}

bool HttpClient::exec(std::string _path) {
    path = _path;
    // bzero when make a new reqeust
    reconnected_count = 0;
    if (defer) {
        return send();
    } else {
        return send() && recv();
    }
}

bool HttpClient::recv(double timeout) {
    if (!wait) {
        return false;
    }
    if (!socket || !socket->is_connected()) {
        swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce,
                                  SW_Z8_OBJ_P(zobject),
                                  ZEND_STRL("statusCode"),
                                  HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return false;
    }
    if (!recv_http_response(timeout)) {
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(
            swoole_http_client_coro_ce,
            SW_Z8_OBJ_P(zobject),
            ZEND_STRL("statusCode"),
            socket->errCode == ETIMEDOUT ? HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT : HTTP_CLIENT_ESTATUS_SERVER_RESET);
        close();
        return false;
    }
    /**
     * TODO: Sec-WebSocket-Accept check
     */
    if (websocket) {
        socket->open_length_check = 1;
        socket->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        socket->protocol.package_length_offset = 0;
        socket->protocol.package_body_offset = 0;
        socket->protocol.get_package_length = websocket::get_package_length;
    }
    // handler keep alive
    if (!websocket && (!keep_alive || connection_close)) {
        close();
    } else {
        reset();
    }

    return true;
}

void HttpClient::recv(zval *zframe, double timeout) {
    SW_ASSERT(websocket);
    ZVAL_FALSE(zframe);
    if (!socket || !socket->is_connected()) {
        swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce,
                                  SW_Z8_OBJ_P(zobject),
                                  ZEND_STRL("statusCode"),
                                  HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return;
    }

    ssize_t retval = socket->recv_packet(timeout);
    if (retval <= 0) {
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(swoole_http_client_coro_ce,
                                  SW_Z8_OBJ_P(zobject),
                                  ZEND_STRL("statusCode"),
                                  HTTP_CLIENT_ESTATUS_SERVER_RESET);
        if (socket->errCode != ETIMEDOUT) {
            close();
        }
    } else {
        String msg;
        msg.length = retval;
        msg.str = socket->get_read_buffer()->str;
#ifdef SW_HAVE_ZLIB
        php_swoole_websocket_frame_unpack_ex(&msg, zframe, websocket_compression);
#else
        php_swoole_websocket_frame_unpack(&msg, zframe);
#endif
        zend_update_property_long(swoole_websocket_frame_ce, SW_Z8_OBJ_P(zframe), ZEND_STRL("fd"), socket->get_fd());
    }
}

bool HttpClient::recv_http_response(double timeout) {
    ssize_t retval = 0;
    size_t total_bytes = 0, parsed_n = 0;
    String *buffer = socket->get_read_buffer();
    bool header_completed = false;
    off_t header_crlf_offset = 0;

    // re-init http response parser
    swoole_http_parser_init(&parser, PHP_HTTP_RESPONSE);
    parser.data = this;

    if (timeout == 0) {
        timeout = socket->get_timeout(Socket::TIMEOUT_READ);
    }
    Socket::timeout_controller tc(socket, timeout, Socket::TIMEOUT_READ);
    while (true) {
        if (sw_unlikely(tc.has_timedout(Socket::TIMEOUT_READ))) {
            return false;
        }
        retval = socket->recv(buffer->str + buffer->length, buffer->size - buffer->length);
        if (sw_unlikely(retval <= 0)) {
            if (retval == 0) {
                socket->set_err(ECONNRESET);
                if (total_bytes > 0 && !swoole_http_should_keep_alive(&parser)) {
                    http_parser_on_message_complete(&parser);
                    return true;
                }
            }
            return false;
        }

        if (!header_completed) {
            buffer->length += retval;
            if (swoole_strnpos(
                    buffer->str + header_crlf_offset, buffer->length - header_crlf_offset, ZEND_STRL("\r\n\r\n")) < 0) {
                if (buffer->length == buffer->size) {
                    swoole_error_log(SW_LOG_TRACE, SW_ERROR_HTTP_INVALID_PROTOCOL, "Http header too large");
                    socket->set_err(SW_ERROR_HTTP_INVALID_PROTOCOL);
                    return false;
                }
                header_crlf_offset = buffer->length > 4 ? buffer->length - 4 : 0;
                continue;
            } else {
                header_completed = true;
                header_crlf_offset = 0;
                retval = buffer->length;
                buffer->clear();
            }
        }

        total_bytes += retval;
        parsed_n = swoole_http_parser_execute(&parser, &http_parser_settings, buffer->str, retval);
        swoole_trace_log(SW_TRACE_HTTP_CLIENT,
                         "parsed_n=%ld, retval=%ld, total_bytes=%ld, completed=%d",
                         parsed_n,
                         retval,
                         total_bytes,
                         parser.state == s_start_res);
        if (parser.state == s_start_res) {
            // handle redundant data (websocket packet)
            if (parser.upgrade && (size_t) retval > parsed_n + SW_WEBSOCKET_HEADER_LEN) {
                buffer->length = retval;
                buffer->offset = parsed_n;
                buffer->reduce(parsed_n);
            }
            return true;
        }
        if (sw_unlikely(parser.state == s_dead)) {
            socket->set_err(SW_ERROR_HTTP_INVALID_PROTOCOL);
            return false;
        }
    }
}

bool HttpClient::upgrade(std::string path) {
    defer = false;
    if (!websocket) {
        char buf[SW_WEBSOCKET_KEY_LENGTH + 1];
        zval *zheaders = sw_zend_read_and_convert_property_array(
            swoole_http_client_coro_ce, zobject, ZEND_STRL("requestHeaders"), 0);
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("requestMethod"), "GET");
        create_token(SW_WEBSOCKET_KEY_LENGTH, buf);
        add_assoc_string(zheaders, "Connection", (char *) "Upgrade");
        add_assoc_string(zheaders, "Upgrade", (char *) "websocket");
        add_assoc_string(zheaders, "Sec-WebSocket-Version", (char *) SW_WEBSOCKET_VERSION);
        add_assoc_str_ex(zheaders,
                         ZEND_STRL("Sec-WebSocket-Key"),
                         php_base64_encode((const unsigned char *) buf, SW_WEBSOCKET_KEY_LENGTH));
#ifdef SW_HAVE_ZLIB
        if (websocket_compression) {
            add_assoc_string(zheaders, "Sec-Websocket-Extensions", (char *) SW_WEBSOCKET_EXTENSION_DEFLATE);
        }
#endif
        exec(path);
    }
    return websocket;
}

bool HttpClient::push(zval *zdata, zend_long opcode, uint8_t flags) {
    if (!websocket) {
        swoole_set_last_error(SW_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
        php_swoole_fatal_error(E_WARNING, "websocket handshake failed, cannot push data");
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(swoole_http_client_coro_ce,
                                    SW_Z8_OBJ_P(zobject),
                                    ZEND_STRL("errMsg"),
                                    "websocket handshake failed, cannot push data");
        zend_update_property_long(swoole_http_client_coro_ce,
                                  SW_Z8_OBJ_P(zobject),
                                  ZEND_STRL("statusCode"),
                                  HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
        return false;
    }
    if (!socket || !socket->is_connected()) {
        swoole_set_last_error(SW_ERROR_CLIENT_NO_CONNECTION);
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), swoole_get_last_error());
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), "connection is not available");
        zend_update_property_long(swoole_http_client_coro_ce,
                                  SW_Z8_OBJ_P(zobject),
                                  ZEND_STRL("statusCode"),
                                  HTTP_CLIENT_ESTATUS_SERVER_RESET);
        return false;
    }

    String *buffer = socket->get_write_buffer();
    buffer->clear();
    if (php_swoole_websocket_frame_is_object(zdata)) {
        if (php_swoole_websocket_frame_object_pack(buffer, zdata, websocket_mask, websocket_compression) < 0) {
            return false;
        }
    } else {
        if (php_swoole_websocket_frame_pack(buffer, zdata, opcode, flags, websocket_mask, websocket_compression) < 0) {
            return false;
        }
    }

    if (socket->send_all(buffer->str, buffer->length) != (ssize_t) buffer->length) {
        zend_update_property_long(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errCode"), socket->errCode);
        zend_update_property_string(
            swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("errMsg"), socket->errMsg);
        zend_update_property_long(swoole_http_client_coro_ce,
                                  SW_Z8_OBJ_P(zobject),
                                  ZEND_STRL("statusCode"),
                                  HTTP_CLIENT_ESTATUS_SERVER_RESET);
        close();
        return false;
    } else {
        return true;
    }
}

void HttpClient::reset() {
    wait = false;
#ifdef SW_HAVE_COMPRESSION
    compress_method = HTTP_COMPRESS_NONE;
    compression_error = false;
#endif
#ifdef SW_HAVE_ZLIB
    if (gzip_stream_active) {
        inflateEnd(&gzip_stream);
        gzip_stream_active = false;
    }
#endif
#ifdef SW_HAVE_BROTLI
    if (brotli_decoder_state) {
        BrotliDecoderDestroyInstance(brotli_decoder_state);
        brotli_decoder_state = nullptr;
    }
#endif
    if (has_upload_files) {
        zend_update_property_null(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("uploadFiles"));
    }
    if (download_file != nullptr) {
        delete download_file;
        download_file = nullptr;
        download_file_name.release();
        download_offset = 0;
        zend_update_property_null(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("downloadFile"));
        zend_update_property_long(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("downloadOffset"), 0);
    }
}

bool HttpClient::close(const bool should_be_reset) {
    Socket *_socket = socket;
    if (_socket) {
        zend_update_property_bool(swoole_http_client_coro_ce, SW_Z8_OBJ_P(zobject), ZEND_STRL("connected"), 0);
        if (!_socket->has_bound()) {
            if (should_be_reset) {
                reset();
            }
            // reset the properties that depend on the connection
            websocket = false;
#ifdef SW_HAVE_ZLIB
            websocket_compression = false;
#endif
            if (tmp_write_buffer) {
                delete tmp_write_buffer;
            }
            tmp_write_buffer = socket->pop_write_buffer();
            socket = nullptr;
        }
        php_swoole_client_coro_socket_free(_socket);
        return true;
    }
    return false;
}

HttpClient::~HttpClient() {
    close();
    if (body) {
        delete body;
    }
    if (tmp_write_buffer) {
        delete tmp_write_buffer;
    }
}

static sw_inline HttpClientObject *php_swoole_http_client_coro_fetch_object(zend_object *obj) {
    return (HttpClientObject *) ((char *) obj - swoole_http_client_coro_handlers.offset);
}

static sw_inline HttpClient *php_swoole_get_phc(zval *zobject) {
    HttpClient *phc = php_swoole_http_client_coro_fetch_object(Z_OBJ_P(zobject))->phc;
    if (UNEXPECTED(!phc)) {
        php_swoole_fatal_error(E_ERROR, "you must call Http Client constructor first");
    }
    return phc;
}

static void php_swoole_http_client_coro_free_object(zend_object *object) {
    HttpClientObject *hcc = php_swoole_http_client_coro_fetch_object(object);
    if (hcc->phc) {
        delete hcc->phc;
        hcc->phc = nullptr;
    }
    zend_object_std_dtor(&hcc->std);
}

static zend_object *php_swoole_http_client_coro_create_object(zend_class_entry *ce) {
    HttpClientObject *hcc = (HttpClientObject *) zend_object_alloc(sizeof(HttpClientObject), ce);
    zend_object_std_init(&hcc->std, ce);
    object_properties_init(&hcc->std, ce);
    hcc->std.handlers = &swoole_http_client_coro_handlers;
    return &hcc->std;
}

void php_swoole_http_client_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_http_client_coro,
                        "Swoole\\Coroutine\\Http\\Client",
                        nullptr,
                        "Co\\Http\\Client",
                        swoole_http_client_coro_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http_client_coro);
    SW_SET_CLASS_CLONEABLE(swoole_http_client_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_client_coro,
                               php_swoole_http_client_coro_create_object,
                               php_swoole_http_client_coro_free_object,
                               HttpClientObject,
                               std);
#if PHP_VERSION_ID >= 80200
	zend_add_parameter_attribute((zend_function *) zend_hash_str_find_ptr(&swoole_http_client_coro_ce->function_table, SW_STRL("setbasicauth")), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);
#endif

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

    SW_INIT_CLASS_ENTRY_EX(swoole_http_client_coro_exception,
                           "Swoole\\Coroutine\\Http\\Client\\Exception",
                           nullptr,
                           "Co\\Http\\Client\\Exception",
                           nullptr,
                           swoole_exception);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED", HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT", HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET", HTTP_CLIENT_ESTATUS_SERVER_RESET);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP_CLIENT_ESTATUS_SEND_FAILED", HTTP_CLIENT_ESTATUS_SEND_FAILED);

#ifdef SW_HAVE_COMPRESSION
    swoole_zlib_buffer = new String(SW_HTTP_RESPONSE_INIT_SIZE);
#endif
}

static PHP_METHOD(swoole_http_client_coro, __construct) {
    HttpClientObject *hcc = php_swoole_http_client_coro_fetch_object(Z_OBJ_P(ZEND_THIS));
    char *host;
    size_t host_len;
    zend_long port = 0;
    zend_bool ssl = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 3)
    Z_PARAM_STRING(host, host_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(port)
    Z_PARAM_BOOL(ssl)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("port"), port);
    zend_update_property_bool(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("ssl"), ssl);
    // check host
    if (host_len == 0) {
        zend_throw_exception_ex(swoole_http_client_coro_exception_ce, EINVAL, "host is empty");
        RETURN_FALSE;
    }
    // check ssl
#ifndef SW_USE_OPENSSL
    if (ssl) {
        zend_throw_exception_ex(
            swoole_http_client_coro_exception_ce,
            EPROTONOSUPPORT,
            "you must configure with `--enable-openssl` to support ssl connection when compiling Swoole");
        RETURN_FALSE;
    }
#endif
    if (port == 0) {
        port = ssl ? 443 : 80;
    }
    hcc->phc = new HttpClient(ZEND_THIS, std::string(host, host_len), port, ssl);
}

static PHP_METHOD(swoole_http_client_coro, __destruct) {}

static PHP_METHOD(swoole_http_client_coro, set) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (php_swoole_array_length(zset) == 0) {
        RETURN_FALSE;
    } else {
        zval *zsettings =
            sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
        php_array_merge(Z_ARRVAL_P(zsettings), Z_ARRVAL_P(zset));
        phc->apply_setting(zset);
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_http_client_coro, getDefer) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);

    RETURN_BOOL(phc->defer);
}

static PHP_METHOD(swoole_http_client_coro, setDefer) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    zend_bool defer = 1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(defer)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    phc->defer = defer;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setMethod) {
    char *method;
    size_t method_length;

    // Notice: maybe string or array
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(method, method_length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_stringl(
        swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("requestMethod"), method, method_length);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setHeaders) {
    zval *headers;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY_EX(headers, 0, 1)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("requestHeaders"), headers);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setBasicAuth) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    char *username, *password;
    size_t username_len, password_len;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(username, username_len)
    Z_PARAM_STRING(password, password_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    phc->set_basic_auth(std::string(username, username_len), std::string(password, password_len));
}

static PHP_METHOD(swoole_http_client_coro, setCookies) {
    zval *cookies;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY_EX(cookies, 0, 1)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("cookies"), cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, setData) {
    zval *zdata;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zdata)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("requestBody"), zdata);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client_coro, addFile) {
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

    if (offset < 0) {
        offset = 0;
    }
    if (length < 0) {
        length = 0;
    }
    struct stat file_stat;
    if (stat(path, &file_stat) < 0) {
        php_swoole_sys_error(E_WARNING, "stat(%s) failed", path);
        RETURN_FALSE;
    }
    if (file_stat.st_size == 0) {
        php_swoole_sys_error(E_WARNING, "cannot send empty file[%s]", filename);
        RETURN_FALSE;
    }
    if (file_stat.st_size <= offset) {
        php_swoole_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] exceeds the file size", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset) {
        php_swoole_sys_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] exceeds the file size", length);
        RETURN_FALSE;
    }
    if (length == 0) {
        length = file_stat.st_size - offset;
    }
    if (l_type == 0) {
        type = (char *) swoole::mime_type::get(path).c_str();
        l_type = strlen(type);
    }
    if (l_filename == 0) {
        char *dot = strrchr(path, '/');
        if (dot == nullptr) {
            filename = path;
            l_filename = l_path;
        } else {
            filename = dot + 1;
            l_filename = strlen(filename);
        }
    }

    zval *zupload_files =
        sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("uploadFiles"), 0);
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

static PHP_METHOD(swoole_http_client_coro, addData) {
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

    if (l_type == 0) {
        type = (char *) "application/octet-stream";
        l_type = strlen(type);
    }
    if (l_filename == 0) {
        filename = name;
        l_filename = l_name;
    }

    zval *zupload_files =
        sw_zend_read_and_convert_property_array(swoole_http_client_coro_ce, ZEND_THIS, ZEND_STRL("uploadFiles"), 0);
    zval zupload_file;
    array_init(&zupload_file);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("content"), data, l_data);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("name"), name, l_name);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("filename"), filename, l_filename);
    add_assoc_stringl_ex(&zupload_file, ZEND_STRL("type"), type, l_type);
    add_assoc_long(&zupload_file, "size", l_data);

    RETURN_BOOL(add_next_index_zval(zupload_files, &zupload_file) == SUCCESS);
}

static PHP_METHOD(swoole_http_client_coro, execute) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, get) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_string(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("requestMethod"), "GET");

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, post) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;
    zval *post_data;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(path, path_len)
    Z_PARAM_ZVAL(post_data)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_update_property_string(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("requestMethod"), "POST");
    zend_update_property(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("requestBody"), post_data);

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, download) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
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

    zend_update_property(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("downloadFile"), download_file);
    zend_update_property_long(swoole_http_client_coro_ce, SW_Z8_OBJ_P(ZEND_THIS), ZEND_STRL("downloadOffset"), offset);

    RETURN_BOOL(phc->exec(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, upgrade) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    char *path = nullptr;
    size_t path_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    RETURN_BOOL(phc->upgrade(std::string(path, path_len)));
}

static PHP_METHOD(swoole_http_client_coro, push) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    zval *zdata;
    zend_long opcode = WebSocket::OPCODE_TEXT;
    zval *zflags = nullptr;
    zend_long flags = WebSocket::FLAG_FIN;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_ZVAL(zdata)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(opcode)
    Z_PARAM_ZVAL_EX(zflags, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zflags != nullptr) {
        flags = zval_get_long(zflags);
    }

    RETURN_BOOL(phc->push(zdata, opcode, flags & WebSocket::FLAGS_ALL));
}

static PHP_METHOD(swoole_http_client_coro, recv) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (phc->websocket) {
        phc->recv(return_value, timeout);
        return;
    } else {
        RETURN_BOOL(phc->recv(timeout));
    }
}

static PHP_METHOD(swoole_http_client_coro, close) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);

    RETURN_BOOL(phc->close());
}

static PHP_METHOD(swoole_http_client_coro, getBody) {
    SW_RETURN_PROPERTY("body");
}

static PHP_METHOD(swoole_http_client_coro, getHeaders) {
    SW_RETURN_PROPERTY("headers");
}

static PHP_METHOD(swoole_http_client_coro, getCookies) {
    SW_RETURN_PROPERTY("cookies");
}

static PHP_METHOD(swoole_http_client_coro, getStatusCode) {
    SW_RETURN_PROPERTY("statusCode");
}

static PHP_METHOD(swoole_http_client_coro, getHeaderOut) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    phc->get_header_out(return_value);
}

static PHP_METHOD(swoole_http_client_coro, getsockname) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    phc->getsockname(return_value);
}

static PHP_METHOD(swoole_http_client_coro, getpeername) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    phc->getpeername(return_value);
}

#ifdef SW_USE_OPENSSL
static PHP_METHOD(swoole_http_client_coro, getPeerCert) {
    HttpClient *phc = php_swoole_get_phc(ZEND_THIS);
    phc->getpeercert(return_value);
}
#endif
