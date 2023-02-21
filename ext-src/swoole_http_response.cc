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
  +----------------------------------------------------------------------+
*/

#include "php_swoole_http_server.h"

#include "swoole_util.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_HAVE_BROTLI
#include <brotli/encode.h>
#endif

using swoole::Connection;
using swoole::Server;
using swoole::String;
using swoole::substr_len;
using swoole::coroutine::Socket;

using HttpResponse = swoole::http::Response;
using HttpContext = swoole::http::Context;

namespace WebSocket = swoole::websocket;
namespace HttpServer = swoole::http_server;

zend_class_entry *swoole_http_response_ce;
static zend_object_handlers swoole_http_response_handlers;

static inline void http_header_key_format(char *key, int length) {
    int i, state = 0;
    for (i = 0; i < length; i++) {
        if (state == 0) {
            if (key[i] >= 97 && key[i] <= 122) {
                key[i] -= 32;
            }
            state = 1;
        } else if (key[i] == '-') {
            state = 0;
        } else {
            if (key[i] >= 65 && key[i] <= 90) {
                key[i] += 32;
            }
        }
    }
}

String *HttpContext::get_write_buffer() {
    if (co_socket) {
        String *buffer = ((Socket *) private_data)->get_write_buffer();
        if (buffer != nullptr) {
            return buffer;
        }
    }
    return swoole_http_buffer;
}

typedef struct {
    HttpContext *ctx;
    zend_object std;
} http_response_t;

static sw_inline http_response_t *php_swoole_http_response_fetch_object(zend_object *obj) {
    return (http_response_t *) ((char *) obj - swoole_http_response_handlers.offset);
}

HttpContext *php_swoole_http_response_get_context(zval *zobject) {
    return php_swoole_http_response_fetch_object(Z_OBJ_P(zobject))->ctx;
}

void php_swoole_http_response_set_context(zval *zobject, HttpContext *ctx) {
    php_swoole_http_response_fetch_object(Z_OBJ_P(zobject))->ctx = ctx;
}

static void php_swoole_http_response_free_object(zend_object *object) {
    http_response_t *response = php_swoole_http_response_fetch_object(object);
    HttpContext *ctx = response->ctx;
    zval ztmp; /* bool, not required to release it */

    if (ctx) {
        if (!ctx->end_ && (ctx->send_chunked || !ctx->send_header_) && !ctx->detached && sw_reactor()) {
            if (ctx->response.status == 0) {
                ctx->response.status = SW_HTTP_INTERNAL_SERVER_ERROR;
            }

#ifdef SW_USE_HTTP2
            if (ctx->http2) {
                if (ctx->stream) {
                    ctx->http2_end(nullptr, &ztmp);
                }
            } else
#endif
            {
                if (ctx->is_available()) {
                    ctx->end(nullptr, &ztmp);
                }
            }
        }
        ctx->response.zobject = nullptr;
        ctx->free();
    }

    zend_object_std_dtor(&response->std);
}

static zend_object *php_swoole_http_response_create_object(zend_class_entry *ce) {
    http_response_t *response = (http_response_t *) zend_object_alloc(sizeof(http_response_t), ce);
    zend_object_std_init(&response->std, ce);
    object_properties_init(&response->std, ce);
    response->std.handlers = &swoole_http_response_handlers;
    return &response->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_http_response, write);
static PHP_METHOD(swoole_http_response, end);
static PHP_METHOD(swoole_http_response, sendfile);
static PHP_METHOD(swoole_http_response, redirect);
static PHP_METHOD(swoole_http_response, cookie);
static PHP_METHOD(swoole_http_response, rawcookie);
static PHP_METHOD(swoole_http_response, header);
static PHP_METHOD(swoole_http_response, initHeader);
static PHP_METHOD(swoole_http_response, isWritable);
static PHP_METHOD(swoole_http_response, detach);
static PHP_METHOD(swoole_http_response, create);
/**
 * for WebSocket Client
 */
static PHP_METHOD(swoole_http_response, upgrade);
static PHP_METHOD(swoole_http_response, push);
static PHP_METHOD(swoole_http_response, recv);
static PHP_METHOD(swoole_http_response, close);
#ifdef SW_USE_HTTP2
static PHP_METHOD(swoole_http_response, trailer);
static PHP_METHOD(swoole_http_response, ping);
static PHP_METHOD(swoole_http_response, goaway);
#endif
static PHP_METHOD(swoole_http_response, status);
static PHP_METHOD(swoole_http_response, __destruct);
SW_EXTERN_C_END

// clang-format off

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_status, 0, 0, 1)
    ZEND_ARG_INFO(0, http_code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_header, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, format)
ZEND_END_ARG_INFO()

#ifdef SW_USE_HTTP2
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_trailer, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_cookie, 0, 0, 1)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, expires)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, domain)
    ZEND_ARG_INFO(0, secure)
    ZEND_ARG_INFO(0, httponly)
    ZEND_ARG_INFO(0, samesite)
    ZEND_ARG_INFO(0, priority)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_write, 0, 0, 1)
    ZEND_ARG_INFO(0, content)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_end, 0, 0, 0)
    ZEND_ARG_INFO(0, content)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_redirect, 0, 0, 1)
    ZEND_ARG_INFO(0, location)
    ZEND_ARG_INFO(0, http_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_create, 0, 0, 1)
    ZEND_ARG_INFO(0, server)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_http_response_methods[] =
{
    PHP_ME(swoole_http_response, initHeader, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, isWritable, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, cookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_http_response, setCookie, cookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, rawcookie, arginfo_swoole_http_response_cookie, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, status, arginfo_swoole_http_response_status, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_http_response, setStatusCode, status, arginfo_swoole_http_response_status, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, header, arginfo_swoole_http_response_header, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_http_response, setHeader, header, arginfo_swoole_http_response_header, ZEND_ACC_PUBLIC)
#ifdef SW_USE_HTTP2
    PHP_ME(swoole_http_response, trailer, arginfo_swoole_http_response_trailer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, ping, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, goaway, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_http_response, write, arginfo_swoole_http_response_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, end, arginfo_swoole_http_response_end, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, sendfile, arginfo_swoole_http_response_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, redirect, arginfo_swoole_http_response_redirect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, detach, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, create, arginfo_swoole_http_response_create, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    /**
     * WebSocket
     */
    PHP_ME(swoole_http_response, upgrade, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, push, arginfo_swoole_http_response_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, recv, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, close, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_response, __destruct, arginfo_swoole_http_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_http_response_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(
        swoole_http_response, "Swoole\\Http\\Response", "swoole_http_response", nullptr, swoole_http_response_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http_response);
    SW_SET_CLASS_CLONEABLE(swoole_http_response, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_response, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_response,
                               php_swoole_http_response_create_object,
                               php_swoole_http_response_free_object,
                               http_response_t,
                               std);

    zend_declare_property_long(swoole_http_response_ce, ZEND_STRL("fd"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("socket"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("trailer"), ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_http_response, write) {
    zval *zdata;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE) {
        RETURN_FALSE;
    }

    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

#ifdef SW_USE_HTTP2
    if (ctx->http2) {
        php_swoole_error(E_WARNING, "HTTP2 client does not support HTTP-CHUNK");
        RETURN_FALSE;
    }
#endif

#ifdef SW_HAVE_COMPRESSION
    ctx->accept_compression = 0;
#endif

    String *http_buffer = ctx->get_write_buffer();

    if (!ctx->send_header_) {
        ctx->send_chunked = 1;
        http_buffer->clear();
        ctx->build_header(http_buffer, 0);
        if (!ctx->send(ctx, http_buffer->str, http_buffer->length)) {
            ctx->send_chunked = 0;
            ctx->send_header_ = 0;
            RETURN_FALSE;
        }
    }

    struct {
        char *str;
        size_t length;
    } http_body;
    size_t length = php_swoole_get_send_data(zdata, &http_body.str);

    if (length == 0) {
        php_swoole_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    } else {
        http_body.length = length;
    }

    // Why not enable compression?
    // If both compression and chunked encoding are enabled,
    // then the content stream is first compressed, then chunked;
    // so the chunk encoding itself is not compressed,
    // **and the data in each chunk is not compressed individually.**
    // The remote endpoint then decodes the stream by concatenating the chunks and decompressing the result.
    http_buffer->clear();
    char *hex_string = swoole_dec2hex(http_body.length, 16);
    int hex_len = strlen(hex_string);
    //"%.*s\r\n%.*s\r\n", hex_len, hex_string, body.length, body.str
    http_buffer->append(hex_string, hex_len);
    http_buffer->append(ZEND_STRL("\r\n"));
    http_buffer->append(http_body.str, http_body.length);
    http_buffer->append(ZEND_STRL("\r\n"));
    sw_free(hex_string);

    RETURN_BOOL(ctx->send(ctx, http_buffer->str, http_buffer->length));
}

static bool parse_header_flags(HttpContext *ctx, const char *key, size_t keylen, uint32_t &header_flags) {
    if (SW_STRCASEEQ(key, keylen, "Server")) {
        header_flags |= HTTP_HEADER_SERVER;
    } else if (SW_STRCASEEQ(key, keylen, "Connection")) {
        header_flags |= HTTP_HEADER_CONNECTION;
    } else if (SW_STRCASEEQ(key, keylen, "Date")) {
        header_flags |= HTTP_HEADER_DATE;
    } else if (SW_STRCASEEQ(key, keylen, "Content-Length")) {
        // https://github.com/swoole/swoole-src/issues/4857
#ifdef SW_HAVE_COMPRESSION
        if (ctx->accept_compression) {
            php_swoole_error(E_WARNING, "The client has set 'Accept-Encoding', 'Content-Length' is ignored");
            return false;
        }
#endif
        if (ctx->send_chunked) {
            php_swoole_error(E_WARNING, "You have set 'Transfer-Encoding', 'Content-Length' is ignored");
            return false;
        }
        header_flags |= HTTP_HEADER_CONTENT_LENGTH;
    } else if (SW_STRCASEEQ(key, keylen, "Content-Type")) {
        header_flags |= HTTP_HEADER_CONTENT_TYPE;
    } else if (SW_STRCASEEQ(key, keylen, "Transfer-Encoding")) {
        header_flags |= HTTP_HEADER_TRANSFER_ENCODING;
    }
    return true;
}

static void http_set_date_header(String *response) {
    static struct {
        time_t time;
        size_t len;
        char buf[64];
    } cache{};

    time_t now = time(nullptr);
    if (now != cache.time) {
        char *date_str = php_swoole_format_date((char *) ZEND_STRL(SW_HTTP_DATE_FORMAT), now, 0);
        cache.len = sw_snprintf(cache.buf, sizeof(cache.buf), "Date: %s\r\n", date_str);
        efree(date_str);
        cache.time = now;
    }
    response->append(cache.buf, cache.len);
}

void HttpContext::build_header(String *http_buffer, size_t body_length) {
    char *buf = sw_tg_buffer()->str;
    size_t l_buf = sw_tg_buffer()->size;
    size_t n;

    assert(send_header_ == 0);

    /**
     * http status line
     */
    if (!response.reason) {
        n = sw_snprintf(buf, l_buf, "HTTP/1.1 %s\r\n", HttpServer::get_status_message(response.status));
    } else {
        n = sw_snprintf(buf, l_buf, "HTTP/1.1 %d %s\r\n", response.status, response.reason);
    }
    http_buffer->append(buf, n);

    uint32_t header_flags = 0x0;

    /**
     * http header
     */
    zval *zheader =
        sw_zend_read_property_ex(swoole_http_response_ce, response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_HEADER), 0);
    if (ZVAL_IS_ARRAY(zheader)) {
        const char *key;
        uint32_t keylen;
        int type;
        zval *zvalue;

        auto add_header = [](String *response, const char *key, size_t l_key, zval *value) {
            if (ZVAL_IS_NULL(value)) {
                return;
            }
            zend::String str_value(value);
            str_value.rtrim();
            if (swoole_http_has_crlf(str_value.val(), str_value.len())) {
                return;
            }
            response->append(key, l_key);
            response->append(SW_STRL(": "));
            response->append(str_value.val(), str_value.len());
            response->append(SW_STRL("\r\n"));
        };

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheader), key, keylen, type, zvalue) {
            // TODO: numeric key name neccessary?
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            if (!parse_header_flags(this, key, keylen, header_flags)) {
                continue;
            }
            if (ZVAL_IS_ARRAY(zvalue)) {
                zval *zvalue_2;
                SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(zvalue), zvalue_2) {
                    add_header(http_buffer, key, keylen, zvalue_2);
                }
                SW_HASHTABLE_FOREACH_END();
            } else {
                add_header(http_buffer, key, keylen, zvalue);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void) type;
    }

    // http cookies
    zval *zcookie =
        sw_zend_read_property_ex(swoole_http_response_ce, response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIE), 0);
    if (ZVAL_IS_ARRAY(zcookie)) {
        zval *zvalue;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(zcookie), zvalue) {
            if (Z_TYPE_P(zvalue) != IS_STRING) {
                continue;
            }
            http_buffer->append(ZEND_STRL("Set-Cookie: "));
            http_buffer->append(Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue));
            http_buffer->append(ZEND_STRL("\r\n"));
        }
        SW_HASHTABLE_FOREACH_END();
    }

    if (!(header_flags & HTTP_HEADER_SERVER)) {
        http_buffer->append(ZEND_STRL("Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"));
    }

    // websocket protocol (subsequent header info is unnecessary)
    if (upgrade == 1) {
        http_buffer->append(ZEND_STRL("\r\n"));
        send_header_ = 1;
        return;
    }

    if (!(header_flags & HTTP_HEADER_CONNECTION)) {
        if (keepalive) {
            http_buffer->append(ZEND_STRL("Connection: keep-alive\r\n"));
        } else {
            http_buffer->append(ZEND_STRL("Connection: close\r\n"));
        }
    }
    if (!(header_flags & HTTP_HEADER_CONTENT_TYPE)) {
        http_buffer->append(ZEND_STRL("Content-Type: text/html\r\n"));
    }
    if (!(header_flags & HTTP_HEADER_DATE)) {
        http_set_date_header(http_buffer);
    }

    if (send_chunked) {
        SW_ASSERT(body_length == 0);
        if (!(header_flags & HTTP_HEADER_TRANSFER_ENCODING)) {
            http_buffer->append(ZEND_STRL("Transfer-Encoding: chunked\r\n"));
        }
    }
    // Content-Length
    else if (body_length > 0 || parser.method != PHP_HTTP_HEAD) {
#ifdef SW_HAVE_COMPRESSION
        if (accept_compression) {
            body_length = swoole_zlib_buffer->length;
        }
#endif
        if (!(header_flags & HTTP_HEADER_CONTENT_LENGTH)) {
            n = sw_snprintf(buf, l_buf, "Content-Length: %zu\r\n", body_length);
            http_buffer->append(buf, n);
        }
    }
#ifdef SW_HAVE_COMPRESSION
    // http compress
    if (accept_compression) {
        const char *content_encoding = get_content_encoding();
        http_buffer->append(ZEND_STRL("Content-Encoding: "));
        http_buffer->append((char *) content_encoding, strlen(content_encoding));
        http_buffer->append(ZEND_STRL("\r\n"));
    }
#endif
    http_buffer->append(ZEND_STRL("\r\n"));
    send_header_ = 1;
}

ssize_t HttpContext::build_trailer(String *http_buffer) {
    char *buf = sw_tg_buffer()->str;
    size_t l_buf = sw_tg_buffer()->size;
    int n;
    ssize_t ret = 0;

    zval *ztrailer =
        sw_zend_read_property_ex(swoole_http_response_ce, response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    uint32_t size = php_swoole_array_length_safe(ztrailer);

    if (size > 0) {
        const char *key;
        uint32_t keylen;
        int type;
        zval *zvalue;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(ztrailer), key, keylen, type, zvalue) {
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue))) {
                continue;
            }

            if (!ZVAL_IS_NULL(zvalue)) {
                zend::String str_value(zvalue);
                n = sw_snprintf(
                    buf, l_buf, "%.*s: %.*s\r\n", (int) keylen, key, (int) str_value.len(), str_value.val());
                http_buffer->append(buf, n);
                ret += n;
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void) type;
        http_buffer->append(ZEND_STRL("\r\n"));
    }

    return ret;
}

#ifdef SW_HAVE_ZLIB
voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size) {
    return (voidpf) safe_emalloc(items, size, 0);
}

void php_zlib_free(voidpf opaque, voidpf address) {
    efree((void *) address);
}
#endif

#ifdef SW_HAVE_BROTLI
void *php_brotli_alloc(void *opaque, size_t size) {
    return emalloc(size);
}

void php_brotli_free(void *opaque, void *address) {
    efree(address);
}
#endif

#ifdef SW_HAVE_COMPRESSION
int swoole_http_response_compress(const char *data, size_t length, int method, int level) {
#ifdef SW_HAVE_ZLIB
    int encoding;
#endif

    if (0) {
    }
#ifdef SW_HAVE_ZLIB
    // gzip: 0x1f
    else if (method == HTTP_COMPRESS_GZIP) {
        encoding = 0x1f;
    }
    // deflate: -0xf
    else if (method == HTTP_COMPRESS_DEFLATE) {
        encoding = -0xf;
    }
#endif
#ifdef SW_HAVE_BROTLI
    else if (method == HTTP_COMPRESS_BR) {
        if (level < BROTLI_MIN_QUALITY) {
            level = BROTLI_MIN_QUALITY;
        } else if (level > BROTLI_MAX_QUALITY) {
            level = BROTLI_MAX_QUALITY;
        }

        size_t memory_size = BrotliEncoderMaxCompressedSize(length);
        if (memory_size > swoole_zlib_buffer->size) {
            if (!swoole_zlib_buffer->extend(memory_size)) {
                return SW_ERR;
            }
        }

        size_t input_size = length;
        const uint8_t *input_buffer = (const uint8_t *) data;
        size_t encoded_size = swoole_zlib_buffer->size;
        uint8_t *encoded_buffer = (uint8_t *) swoole_zlib_buffer->str;

        if (BROTLI_TRUE != BrotliEncoderCompress(level,
                                                 BROTLI_DEFAULT_WINDOW,
                                                 BROTLI_DEFAULT_MODE,
                                                 input_size,
                                                 input_buffer,
                                                 &encoded_size,
                                                 encoded_buffer)) {
            swoole_warning("BrotliEncoderCompress() failed");
            return SW_ERR;
        } else {
            swoole_zlib_buffer->length = encoded_size;
            return SW_OK;
        }
    }
#endif
    else {
        swoole_warning("Unknown compression method");
        return SW_ERR;
    }
#ifdef SW_HAVE_ZLIB
    if (level < Z_NO_COMPRESSION) {
        level = Z_DEFAULT_COMPRESSION;
    } else if (level == Z_NO_COMPRESSION) {
        level = Z_BEST_SPEED;
    } else if (level > Z_BEST_COMPRESSION) {
        level = Z_BEST_COMPRESSION;
    }

    size_t memory_size = ((size_t) ((double) length * (double) 1.015)) + 10 + 8 + 4 + 1;
    if (memory_size > swoole_zlib_buffer->size) {
        if (!swoole_zlib_buffer->extend(memory_size)) {
            return SW_ERR;
        }
    }

    z_stream zstream = {};
    int status;

    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;

    status = deflateInit2(&zstream, level, Z_DEFLATED, encoding, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        swoole_warning("deflateInit2() failed, Error: [%d]", status);
        return SW_ERR;
    }

    zstream.next_in = (Bytef *) data;
    zstream.avail_in = length;
    zstream.next_out = (Bytef *) swoole_zlib_buffer->str;
    zstream.avail_out = swoole_zlib_buffer->size;

    status = deflate(&zstream, Z_FINISH);
    deflateEnd(&zstream);
    if (status != Z_STREAM_END) {
        swoole_warning("deflate() failed, Error: [%d]", status);
        return SW_ERR;
    }

    swoole_zlib_buffer->length = zstream.total_out;
    swoole_zlib_buffer->offset = 0;
    return SW_OK;
#endif
}
#endif

static PHP_METHOD(swoole_http_response, initHeader) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    zval *zresponse_object = ctx->response.zobject;
    swoole_http_init_and_read_property(
        swoole_http_response_ce, zresponse_object, &ctx->response.zheader, ZEND_STRL("header"));
    swoole_http_init_and_read_property(
        swoole_http_response_ce, zresponse_object, &ctx->response.zcookie, ZEND_STRL("cookie"));
    swoole_http_init_and_read_property(
        swoole_http_response_ce, zresponse_object, &ctx->response.ztrailer, ZEND_STRL("trailer"));
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, isWritable) {
    HttpContext *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (!ctx || (ctx->end_ || ctx->detached)) {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, end) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

    zval *zdata = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL_EX(zdata, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef SW_USE_HTTP2
    if (ctx->http2) {
        ctx->http2_end(zdata, return_value);
    } else
#endif
    {
        ctx->end(zdata, return_value);
    }
}

void HttpContext::send_trailer(zval *return_value) {
    String *http_buffer = get_write_buffer();

    http_buffer->clear();
    if (build_trailer(http_buffer) == 0) {
        return;
    }
    if (!send(this, http_buffer->str, http_buffer->length)) {
        end_ = 1;
        close(this);
        RETURN_FALSE;
    }
}

bool HttpContext::send_file(const char *file, uint32_t l_file, off_t offset, size_t length) {
    zval *zheader =
        sw_zend_read_and_convert_property_array(swoole_http_response_ce, response.zobject, ZEND_STRL("header"), 0);
    if (!zend_hash_str_exists(Z_ARRVAL_P(zheader), ZEND_STRL("Content-Type"))) {
        add_assoc_string(zheader, "Content-Type", (char *) swoole::mime_type::get(file).c_str());
    }

    if (!send_header_) {
#ifdef SW_HAVE_COMPRESSION
        accept_compression = 0;
#endif
        String *http_buffer = get_write_buffer();
        http_buffer->clear();

        build_header(http_buffer, length);

        if (!send(this, http_buffer->str, http_buffer->length)) {
            send_header_ = 0;
            return false;
        }
    }

    if (length > 0 && !sendfile(this, file, l_file, offset, length)) {
        close(this);
        return false;
    }

    end_ = 1;

    if (!keepalive) {
        close(this);
    }
    return true;
}

void HttpContext::end(zval *zdata, zval *return_value) {
    struct {
        char *str;
        size_t length;
    } http_body;
    if (zdata) {
        http_body.length = php_swoole_get_send_data(zdata, &http_body.str);
    } else {
        http_body.length = 0;
        http_body.str = nullptr;
    }

    if (send_chunked) {
        if (send_trailer_) {
            if (!send(this, ZEND_STRL("0\r\n"))) {
                RETURN_FALSE;
            }
            send_trailer(return_value);
            send_trailer_ = 0;
        } else {
            if (!send(this, ZEND_STRL("0\r\n\r\n"))) {
                RETURN_FALSE;
            }
        }
        send_chunked = 0;
    }
    // no http chunk
    else {
        String *http_buffer = get_write_buffer();

        http_buffer->clear();
#ifdef SW_HAVE_COMPRESSION
        if (accept_compression) {
            if (http_body.length == 0 || http_body.length < compression_min_length ||
                swoole_http_response_compress(http_body.str, http_body.length, compression_method, compression_level) !=
                    SW_OK) {
                accept_compression = 0;
            }
        }
#endif
        build_header(http_buffer, http_body.length);

        char *send_body_str;
        size_t send_body_len;

        if (http_body.length > 0) {
#ifdef SW_HAVE_COMPRESSION
            if (accept_compression) {
                send_body_str = swoole_zlib_buffer->str;
                send_body_len = swoole_zlib_buffer->length;
            } else
#endif
            {
                send_body_str = http_body.str;
                send_body_len = http_body.length;
            }
            // send twice to reduce memory copy
            if (send_body_len < SwooleG.pagesize) {
                if (http_buffer->append(send_body_str, send_body_len) < 0) {
                    send_header_ = 0;
                    RETURN_FALSE;
                }
            } else {
                if (!send(this, http_buffer->str, http_buffer->length)) {
                    send_header_ = 0;
                    RETURN_FALSE;
                }
                if (!send(this, send_body_str, send_body_len)) {
                    end_ = 1;
                    close(this);
                    RETURN_FALSE;
                }
                goto _skip_copy;
            }
        }

        if (!send(this, http_buffer->str, http_buffer->length)) {
            end_ = 1;
            close(this);
            RETURN_FALSE;
        }
    }

_skip_copy:
    if (upgrade && !co_socket) {
        Server *serv = (Server *) private_data;
        Connection *conn = serv->get_connection_verify(fd);
        if (conn && conn->websocket_status == websocket::STATUS_HANDSHAKE) {
            if (response.status == 101) {
                conn->websocket_status = websocket::STATUS_ACTIVE;
            } else {
                /* connection should be closed when handshake failed */
                conn->websocket_status = websocket::STATUS_NONE;
                keepalive = 0;
            }
        }
    }
    if (!keepalive) {
        close(this);
    }
    end_ = 1;
    RETURN_TRUE;
}

bool HttpContext::set_header(const char *k, size_t klen, const char *v, size_t vlen, bool format) {
    zval ztmp;
    ZVAL_STRINGL(&ztmp, v, vlen);
    Z_ADDREF(ztmp);
    return set_header(k, klen, &ztmp, format);
}

bool HttpContext::set_header(const char *k, size_t klen, zval *zvalue, bool format) {
    if (UNEXPECTED(klen > SW_HTTP_HEADER_KEY_SIZE - 1)) {
        php_swoole_error(E_WARNING, "header key is too long");
        Z_TRY_DELREF_P(zvalue);
        return false;
    }

    if (swoole_http_has_crlf(k, klen)) {
        Z_TRY_DELREF_P(zvalue);
        return false;
    }

    zval *zheader = swoole_http_init_and_read_property(
        swoole_http_response_ce, response.zobject, &response.zheader, ZEND_STRL("header"));
    if (format) {
        swoole_strlcpy(sw_tg_buffer()->str, k, SW_HTTP_HEADER_KEY_SIZE);
#ifdef SW_USE_HTTP2
        if (http2) {
            swoole_strtolower(sw_tg_buffer()->str, klen);
        } else
#endif
        {
            http_header_key_format(sw_tg_buffer()->str, klen);
        }
        k = sw_tg_buffer()->str;
    }
    add_assoc_zval_ex(zheader, k, klen, zvalue);
    return true;
}

static PHP_METHOD(swoole_http_response, sendfile) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

    if (ctx->send_chunked) {
        php_swoole_fatal_error(E_WARNING, "can't use sendfile when HTTP chunk is enabled");
        RETURN_FALSE;
    }

    char *file;
    size_t l_file;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &file, &l_file, &offset, &length) == FAILURE) {
        RETURN_FALSE;
    }

    if (l_file == 0) {
        php_swoole_error(E_WARNING, "file name is empty");
        RETURN_FALSE;
    }

    struct stat file_stat;
    if (stat(file, &file_stat) < 0) {
        php_swoole_sys_error(E_WARNING, "stat(%s) failed", file);
        RETURN_FALSE;
    }
    if (!S_ISREG(file_stat.st_mode)) {
        php_swoole_error(E_WARNING, "parameter $file[%s] given is not a regular file", file);
        swoole_set_last_error(SW_ERROR_SERVER_IS_NOT_REGULAR_FILE);
        RETURN_FALSE;
    }
    if (file_stat.st_size < offset) {
        php_swoole_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] exceeds the file size", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset) {
        php_swoole_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] exceeds the file size", length);
        RETURN_FALSE;
    }
    if (length == 0) {
        length = file_stat.st_size - offset;
    }

#ifdef SW_USE_HTTP2
    if (ctx->http2) {
        RETURN_BOOL(ctx->http2_send_file(file, l_file, offset, length));
    } else
#endif
    {
        RETURN_BOOL(ctx->send_file(file, l_file, offset, length));
    }
}

static void php_swoole_http_response_cookie(INTERNAL_FUNCTION_PARAMETERS, const bool url_encode) {
    char *name = nullptr, *value = nullptr, *path = nullptr, *domain = nullptr, *samesite = nullptr,
         *priority = nullptr;
    zend_long expires = 0;
    size_t name_len, value_len = 0, path_len = 0, domain_len = 0, samesite_len = 0, priority_len = 0;
    zend_bool secure = 0, httponly = 0;

    ZEND_PARSE_PARAMETERS_START(1, 9)
    Z_PARAM_STRING(name, name_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(value, value_len)
    Z_PARAM_LONG(expires)
    Z_PARAM_STRING(path, path_len)
    Z_PARAM_STRING(domain, domain_len)
    Z_PARAM_BOOL(secure)
    Z_PARAM_BOOL(httponly)
    Z_PARAM_STRING(samesite, samesite_len)
    Z_PARAM_STRING(priority, priority_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

    size_t cookie_size = name_len /* + value_len */ + path_len + domain_len + 100;
    char *cookie = nullptr, *date = nullptr;

    if (name_len > 0 && strpbrk(name, "=,; \t\r\n\013\014") != nullptr) {
        php_swoole_error(E_WARNING, "Cookie names can't contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }

    if (!url_encode && swoole_http_has_crlf(value, value_len)) {
        RETURN_FALSE;
    }

    if (value_len == 0) {
        cookie = (char *) emalloc(cookie_size);
        date = php_swoole_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), 1, 0);
        snprintf(cookie, cookie_size, "%s=deleted; expires=%s", name, date);
        efree(date);
    } else {
        if (url_encode) {
            char *encoded_value;
            size_t encoded_value_len;
            encoded_value = php_swoole_url_encode(value, value_len, &encoded_value_len);
            cookie_size += encoded_value_len;
            cookie = (char *) emalloc(cookie_size);
            sw_snprintf(cookie, cookie_size, "%s=%s", name, encoded_value);
            efree(encoded_value);
        } else {
            cookie_size += value_len;
            cookie = (char *) emalloc(cookie_size);
            sw_snprintf(cookie, cookie_size, "%s=%s", name, value);
        }
        if (expires > 0) {
            strlcat(cookie, "; expires=", cookie_size);
            date = php_swoole_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), expires, 0);
            const char *p = (const char *) zend_memrchr(date, '-', strlen(date));
            if (!p || *(p + 5) != ' ') {
                php_swoole_error(E_WARNING, "Expiry date can't be a year greater than 9999");
                efree(date);
                efree(cookie);
                RETURN_FALSE;
            }
            strlcat(cookie, date, cookie_size);
            efree(date);
        }
    }
    if (path_len > 0) {
        strlcat(cookie, "; path=", cookie_size);
        strlcat(cookie, path, cookie_size);
    }
    if (domain_len > 0) {
        strlcat(cookie, "; domain=", cookie_size);
        strlcat(cookie, domain, cookie_size);
    }
    if (secure) {
        strlcat(cookie, "; secure", cookie_size);
    }
    if (httponly) {
        strlcat(cookie, "; httponly", cookie_size);
    }
    if (samesite_len > 0) {
        strlcat(cookie, "; samesite=", cookie_size);
        strlcat(cookie, samesite, cookie_size);
    }
    if (priority_len > 0) {
        strlcat(cookie, "; priority=", cookie_size);
        strlcat(cookie, priority, cookie_size);
    }
    add_next_index_stringl(
        swoole_http_init_and_read_property(
            swoole_http_response_ce, ctx->response.zobject, &ctx->response.zcookie, ZEND_STRL("cookie")),
        cookie,
        strlen(cookie));
    efree(cookie);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, cookie) {
    php_swoole_http_response_cookie(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static PHP_METHOD(swoole_http_response, rawcookie) {
    php_swoole_http_response_cookie(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_METHOD(swoole_http_response, status) {
    zend_long http_status;
    char *reason = nullptr;
    size_t reason_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(http_status)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(reason, reason_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

    ctx->response.status = http_status;
    ctx->response.reason = reason_len > 0 ? estrndup(reason, reason_len) : nullptr;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, header) {
    char *k;
    size_t klen;
    zval *zvalue;
    zend_bool format = 1;

    ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_STRING(k, klen)
    Z_PARAM_ZVAL(zvalue)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(format)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    Z_TRY_ADDREF_P(zvalue);
    RETURN_BOOL(ctx->set_header(k, klen, zvalue, format));
}

#ifdef SW_USE_HTTP2
static PHP_METHOD(swoole_http_response, trailer) {
    char *k, *v;
    size_t klen, vlen;
    char key_buf[SW_HTTP_HEADER_KEY_SIZE];

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(k, klen)
    Z_PARAM_STRING_EX(v, vlen, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (!ctx) {
        RETURN_FALSE;
    }
    if (UNEXPECTED(klen > SW_HTTP_HEADER_KEY_SIZE - 1)) {
        php_swoole_error(E_WARNING, "trailer key is too long");
        RETURN_FALSE;
    }
    zval *ztrailer = swoole_http_init_and_read_property(
        swoole_http_response_ce, ctx->response.zobject, &ctx->response.ztrailer, ZEND_STRL("trailer"));
    swoole_strlcpy(key_buf, k, sizeof(key_buf));
    swoole_strtolower(key_buf, klen);
    if (UNEXPECTED(!v)) {
        add_assoc_null_ex(ztrailer, key_buf, klen);
    } else {
        add_assoc_stringl_ex(ztrailer, key_buf, klen, v, vlen);
    }
    ctx->send_trailer_ = 1;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, ping) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->http2)) {
        php_swoole_fatal_error(E_WARNING, "fd[%ld] is not a HTTP2 conncetion", ctx->fd);
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(swoole_http2_server_ping(ctx));
}

static PHP_METHOD(swoole_http_response, goaway) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->http2)) {
        php_swoole_fatal_error(E_WARNING, "fd[%ld] is not a HTTP2 conncetion", ctx->fd);
        RETURN_FALSE;
    }
    zend_long error_code = SW_HTTP2_ERROR_NO_ERROR;
    char *debug_data = nullptr;
    size_t debug_data_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ls", &error_code, &debug_data, &debug_data_len) == FAILURE) {
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(swoole_http2_server_goaway(ctx, error_code, debug_data, debug_data_len));
}
#endif

static PHP_METHOD(swoole_http_response, upgrade) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->co_socket)) {
        php_swoole_fatal_error(E_WARNING, "async server dose not support protocol upgrade");
        RETURN_FALSE;
    }
    RETVAL_BOOL(swoole_websocket_handshake(ctx));
}

static PHP_METHOD(swoole_http_response, push) {
    HttpContext *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        swoole_set_last_error(SW_ERROR_SESSION_CLOSED);
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->co_socket || !ctx->upgrade)) {
        php_swoole_fatal_error(E_WARNING, "fd[%ld] is not a websocket conncetion", ctx->fd);
        RETURN_FALSE;
    }

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

    String *http_buffer = ctx->get_write_buffer();
    http_buffer->clear();
    if (php_swoole_websocket_frame_is_object(zdata)) {
        if (php_swoole_websocket_frame_object_pack(http_buffer, zdata, 0, ctx->websocket_compression) < 0) {
            RETURN_FALSE;
        }
    } else {
        if (php_swoole_websocket_frame_pack(
                http_buffer, zdata, opcode, flags & WebSocket::FLAGS_ALL, 0, ctx->websocket_compression) < 0) {
            RETURN_FALSE;
        }
    }
    RETURN_BOOL(ctx->send(ctx, http_buffer->str, http_buffer->length));
}

static PHP_METHOD(swoole_http_response, close) {
    HttpContext *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        swoole_set_last_error(SW_ERROR_SESSION_CLOSED);
        RETURN_FALSE;
    }
    RETURN_BOOL(ctx->close(ctx));
}

static PHP_METHOD(swoole_http_response, recv) {
    HttpContext *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        swoole_set_last_error(SW_ERROR_SESSION_CLOSED);
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->co_socket || !ctx->upgrade)) {
        php_swoole_fatal_error(E_WARNING, "fd[%ld] is not a websocket conncetion", ctx->fd);
        RETURN_FALSE;
    }

    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *sock = (Socket *) ctx->private_data;
    ssize_t retval = sock->recv_packet(timeout);
    String _tmp;

    if (retval < 0) {
        swoole_set_last_error(sock->errCode);
        RETURN_FALSE;
    } else if (retval == 0) {
        RETURN_EMPTY_STRING();
    } else {
        _tmp.str = sock->get_read_buffer()->str;
        _tmp.length = retval;

#ifdef SW_HAVE_ZLIB
        php_swoole_websocket_frame_unpack_ex(&_tmp, return_value, ctx->websocket_compression);
#else
        php_swoole_websocket_frame_unpack(&_tmp, return_value);
#endif
        zend_update_property_long(
            swoole_websocket_frame_ce, SW_Z8_OBJ_P(return_value), ZEND_STRL("fd"), sock->get_fd());
    }
}

static PHP_METHOD(swoole_http_response, detach) {
    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (!ctx) {
        RETURN_FALSE;
    }
    ctx->detached = 1;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, create) {
    zval *zobject = nullptr;
    zval *zrequest = nullptr;
    zend_long fd = -1;
    Server *serv = nullptr;
    Socket *sock = nullptr;
    HttpContext *ctx = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(zobject)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(fd)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (ZVAL_IS_OBJECT(zobject)) {
    _type_detect:
        if (instanceof_function(Z_OBJCE_P(zobject), swoole_server_ce)) {
            serv = php_swoole_server_get_and_check_server(zobject);
            if (serv->get_connection_verify(fd) == nullptr) {
                php_swoole_fatal_error(E_WARNING, "parameter $2 must be valid connection session id");
                RETURN_FALSE;
            }
        } else if (instanceof_function(Z_OBJCE_P(zobject), swoole_socket_coro_ce)) {
            sock = php_swoole_get_socket(zobject);
            fd = sock->get_fd();
        } else {
        _bad_type:
            php_swoole_fatal_error(E_WARNING, "parameter $1 must be instanceof Server or Coroutine\\Socket");
            RETURN_FALSE;
        }
    } else if (ZVAL_IS_ARRAY(zobject)) {
        zrequest = zend_hash_index_find(Z_ARR_P(zobject), 1);
        if (!ZVAL_IS_OBJECT(zrequest) || !instanceof_function(Z_OBJCE_P(zrequest), swoole_http_request_ce)) {
            php_swoole_fatal_error(E_WARNING, "parameter $1.second must be instanceof Http\\Request");
            RETURN_FALSE;
        }
        zobject = zend_hash_index_find(Z_ARR_P(zobject), 0);
        if (!ZVAL_IS_OBJECT(zobject)) {
            goto _bad_type;
        } else {
            ctx = php_swoole_http_request_get_context(zrequest);
            goto _type_detect;
        }
    } else {
        fd = zval_get_long(zobject);
        serv = sw_server();
    }

    if (serv && !serv->is_started()) {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    if (!ctx) {
        ctx = new HttpContext();
        ctx->keepalive = 1;

        if (serv) {
            ctx->init(serv);
        } else if (sock) {
            ctx->init(sock);
            ctx->parser.data = ctx;
            swoole_http_parser_init(&ctx->parser, PHP_HTTP_REQUEST);
        } else {
            delete ctx;
            assert(0);
            RETURN_FALSE;
        }
    } else {
        if (serv) {
            ctx->bind(serv);
        } else if (sock) {
            ctx->bind(sock);
        } else {
            assert(0);
            RETURN_FALSE;
        }
    }

    if (sw_unlikely(swoole_http_buffer == nullptr)) {
        php_swoole_http_server_init_global_variant();
    }

    object_init_ex(return_value, swoole_http_response_ce);
    php_swoole_http_response_set_context(return_value, ctx);
    ctx->fd = fd;
    ctx->response.zobject = return_value;
    sw_copy_to_stack(ctx->response.zobject, ctx->response._zobject);
    zend_update_property_long(swoole_http_response_ce, SW_Z8_OBJ_P(return_value), ZEND_STRL("fd"), fd);
    if (ctx->co_socket) {
        zend_update_property_ex(
            swoole_http_response_ce, SW_Z8_OBJ_P(ctx->response.zobject), SW_ZSTR_KNOWN(SW_ZEND_STR_SOCKET), zobject);
    }
    if (zrequest) {
        zend_update_property_long(swoole_http_request_ce, SW_Z8_OBJ_P(ctx->request.zobject), ZEND_STRL("fd"), fd);
    }
}

static PHP_METHOD(swoole_http_response, redirect) {
    zval *zurl;
    zval *zhttp_code = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(zurl)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL_EX(zhttp_code, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HttpContext *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx)) {
        RETURN_FALSE;
    }

    // status
    if (zhttp_code) {
        ctx->response.status = zval_get_long(zhttp_code);
    } else {
        ctx->response.status = 302;
    }

    zval zkey;
    ZVAL_STRINGL(&zkey, "Location", 8);
    sw_zend_call_method_with_2_params(ZEND_THIS, nullptr, nullptr, "header", return_value, &zkey, zurl);
    zval_ptr_dtor(&zkey);
    if (!Z_BVAL_P(return_value)) {
        return;
    }
    ctx->end(nullptr, return_value);
}

static PHP_METHOD(swoole_http_response, __destruct) {}
