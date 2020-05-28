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

#include "swoole_http_server.h"

#include "mime_type.h"

extern "C"
{
#include "ext/standard/url.h"
#include "ext/standard/sha1.h"
#include "ext/standard/php_var.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_math.h"
#include "ext/standard/php_array.h"
#include "ext/date/php_date.h"
#include "ext/standard/md5.h"
}

#include "websocket.h"
#include "base64.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_HAVE_BROTLI
#include <brotli/encode.h>
#endif

#ifdef SW_USE_HTTP2
#include "http2.h"
#endif

using namespace swoole;
using swoole::coroutine::Socket;

zend_class_entry *swoole_http_response_ce;
static zend_object_handlers swoole_http_response_handlers;

static void http_build_header(http_context *, swString *response, size_t body_length);

static inline void http_header_key_format(char *key, int length)
{
    int i, state = 0;
    for (i = 0; i < length; i++)
    {
        if (state == 0)
        {
            if (key[i] >= 97 && key[i] <= 122)
            {
                key[i] -= 32;
            }
            state = 1;
        }
        else if (key[i] == '-')
        {
            state = 0;
        }
        else
        {
            if (key[i] >= 65 && key[i] <= 90)
            {
                key[i] += 32;
            }
        }
    }
}

static inline swString* http_get_write_buffer(http_context *ctx)
{
    if (ctx->co_socket)
    {
        swString *buffer = ((Socket *) ctx->private_data)->get_write_buffer();
        if (buffer != nullptr)
        {
            return buffer;
        }
    }
    return swoole_http_buffer;
}

typedef struct
{
    http_context *ctx;
    zend_object std;
} http_response_t;

static sw_inline http_response_t* php_swoole_http_response_fetch_object(zend_object *obj)
{
    return (http_response_t *) ((char *) obj - swoole_http_response_handlers.offset);
}

http_context * php_swoole_http_response_get_context(zval *zobject)
{
    return php_swoole_http_response_fetch_object(Z_OBJ_P(zobject))->ctx;
}

void php_swoole_http_response_set_context(zval *zobject, http_context *ctx)
{
    php_swoole_http_response_fetch_object(Z_OBJ_P(zobject))->ctx = ctx;
}

static void php_swoole_http_response_free_object(zend_object *object)
{
    http_response_t *response = php_swoole_http_response_fetch_object(object);
    http_context *ctx = response->ctx;
    zval ztmp; /* bool, not required to release it */

    if (ctx)
    {
        if (!ctx->end && !ctx->detached && sw_reactor())
        {
            if (ctx->response.status == 0)
            {
                ctx->response.status = SW_HTTP_INTERNAL_SERVER_ERROR;
            }

#ifdef SW_USE_HTTP2
            if (ctx->http2)
            {
                if (ctx->stream)
                {
                    swoole_http2_response_end(ctx, nullptr, &ztmp);
                }
            }
            else
#endif
            {
                if (ctx->co_socket)
                {
                    swoole_http_response_end(ctx, nullptr, &ztmp);
                }
                else
                {
                    swServer *serv = (swServer *) ctx->private_data;
                    swConnection *conn = swWorker_get_connection(serv, ctx->fd);
                    if (conn && !conn->closed && !conn->peer_closed)
                    {
                        swoole_http_response_end(ctx, nullptr, &ztmp);
                    }
                }
            }
        }
        ctx->response.zobject = nullptr;
        swoole_http_context_free(ctx);
    }

    zend_object_std_dtor(&response->std);
}

static zend_object *php_swoole_http_response_create_object(zend_class_entry *ce)
{
    http_response_t *response = (http_response_t *) zend_object_alloc(sizeof(http_response_t), ce);
    zend_object_std_init(&response->std, ce);
    object_properties_init(&response->std, ce);
    response->std.handlers = &swoole_http_response_handlers;
    return &response->std;
}

static PHP_METHOD(swoole_http_response, write);
static PHP_METHOD(swoole_http_response, end);
static PHP_METHOD(swoole_http_response, sendfile);
static PHP_METHOD(swoole_http_response, redirect);
static PHP_METHOD(swoole_http_response, cookie);
static PHP_METHOD(swoole_http_response, rawcookie);
static PHP_METHOD(swoole_http_response, header);
static PHP_METHOD(swoole_http_response, initHeader);
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
#endif
static PHP_METHOD(swoole_http_response, status);
static PHP_METHOD(swoole_http_response, __destruct);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_status, 0, 0, 1)
    ZEND_ARG_INFO(0, http_code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_response_header, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
    ZEND_ARG_INFO(0, ucwords)
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

void php_swoole_http_response_minit(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_http_response, "Swoole\\Http\\Response", "swoole_http_response", nullptr, swoole_http_response_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http_response, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http_response, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http_response, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http_response, php_swoole_http_response_create_object, php_swoole_http_response_free_object, http_response_t, std);

    zend_declare_property_long(swoole_http_response_ce, ZEND_STRL("fd"), 0,  ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("socket"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("header"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("cookie"), ZEND_ACC_PUBLIC);
#ifdef SW_USE_HTTP2
    zend_declare_property_null(swoole_http_response_ce, ZEND_STRL("trailer"), ZEND_ACC_PUBLIC);
#endif
}

static PHP_METHOD(swoole_http_response, write)
{
    zval *zdata;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE)
    {
        RETURN_FALSE;
    }

    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

#ifdef SW_USE_HTTP2
    if (ctx->http2)
    {
        php_swoole_error(E_WARNING, "HTTP2 client does not support HTTP-CHUNK");
        RETURN_FALSE;
    }
#endif

#ifdef SW_HAVE_COMPRESSION
    ctx->accept_compression = 0;
#endif

    swString *http_buffer = http_get_write_buffer(ctx);

    if (!ctx->send_header)
    {
        ctx->send_chunked = 1;
        swString_clear(http_buffer);
        http_build_header(ctx, http_buffer, 0);
        if (!ctx->send(ctx, http_buffer->str, http_buffer->length))
        {
            ctx->send_chunked = 0;
            ctx->send_header = 0;
            RETURN_FALSE;
        }
    }

    swString http_body;
    size_t length = php_swoole_get_send_data(zdata, &http_body.str);

    if (length == 0)
    {
        php_swoole_error(E_WARNING, "data to send is empty");
        RETURN_FALSE;
    }
    else
    {
        http_body.length = length;
    }

    // Why not enable compression?
    // If both compression and chunked encoding are enabled,
    // then the content stream is first compressed, then chunked;
    // so the chunk encoding itself is not compressed,
    // **and the data in each chunk is not compressed individually.**
    // The remote endpoint then decodes the stream by concatenating the chunks and decompressing the result.
    swString_clear(http_buffer);
    char *hex_string = swoole_dec2hex(http_body.length, 16);
    int hex_len = strlen(hex_string);
    //"%.*s\r\n%.*s\r\n", hex_len, hex_string, body.length, body.str
    swString_append_ptr(http_buffer, hex_string, hex_len);
    swString_append_ptr(http_buffer, ZEND_STRL("\r\n"));
    swString_append_ptr(http_buffer, http_body.str, http_body.length);
    swString_append_ptr(http_buffer, ZEND_STRL("\r\n"));
    sw_free(hex_string);

    RETURN_BOOL(ctx->send(ctx, http_buffer->str, http_buffer->length));
}

static void http_build_header(http_context *ctx, swString *response, size_t body_length)
{
    char *buf = SwooleTG.buffer_stack->str;
    size_t l_buf = SwooleTG.buffer_stack->size;
    int n;
    char *date_str;

    assert(ctx->send_header == 0);

    /**
     * http status line
     */
    if (!ctx->response.reason)
    {
        n = sw_snprintf(buf, l_buf, "HTTP/1.1 %s\r\n", swHttp_get_status_message(ctx->response.status));
    }
    else
    {
        n = sw_snprintf(buf, l_buf, "HTTP/1.1 %d %s\r\n", ctx->response.status, ctx->response.reason);
    }
    swString_append_ptr(response, buf, n);

    /**
     * http header
     */
    zval *zheader = sw_zend_read_property(swoole_http_response_ce, ctx->response.zobject, ZEND_STRL("header"), 0);
    uint32_t header_flag = 0x0;
    if (ZVAL_IS_ARRAY(zheader))
    {
        const char *key;
        uint32_t keylen;
        int type;
        zval *zvalue;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheader), key, keylen, type, zvalue)
        {
            // TODO: numeric key name neccessary?
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue)))
            {
                continue;
            }
            if (SW_STRCASEEQ(key, keylen, "Server"))
            {
                header_flag |= HTTP_HEADER_SERVER;
            }
            else if (SW_STRCASEEQ(key, keylen, "Connection"))
            {
                header_flag |= HTTP_HEADER_CONNECTION;
            }
            else if (SW_STRCASEEQ(key, keylen, "Date"))
            {
                header_flag |= HTTP_HEADER_DATE;
            }
            else if (SW_STRCASEEQ(key, keylen, "Content-Length") && ctx->parser.method != PHP_HTTP_HEAD)
            {
                continue; // ignore
            }
            else if (SW_STRCASEEQ(key, keylen, "Content-Type"))
            {
                header_flag |= HTTP_HEADER_CONTENT_TYPE;
            }
            else if (SW_STRCASEEQ(key, keylen, "Transfer-Encoding"))
            {
                header_flag |= HTTP_HEADER_TRANSFER_ENCODING;
            }
            if (!ZVAL_IS_NULL(zvalue))
            {
                zend::string str_value(zvalue);
                n = sw_snprintf(buf, l_buf, "%.*s: %.*s\r\n", (int) keylen, key, (int) str_value.len(), str_value.val());
                swString_append_ptr(response, buf, n);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void)type;
    }

    //http cookies
    zval *zcookie = sw_zend_read_property(swoole_http_response_ce, ctx->response.zobject, ZEND_STRL("cookie"), 0);
    if (ZVAL_IS_ARRAY(zcookie))
    {
        zval *zvalue;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(zcookie), zvalue)
        {
            if (Z_TYPE_P(zvalue) != IS_STRING)
            {
                continue;
            }
            swString_append_ptr(response, ZEND_STRL("Set-Cookie: "));
            swString_append_ptr(response, Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue));
            swString_append_ptr(response, ZEND_STRL("\r\n"));
        }
        SW_HASHTABLE_FOREACH_END();
    }

    if (!(header_flag & HTTP_HEADER_SERVER))
    {
        swString_append_ptr(response, ZEND_STRL("Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"));
    }

    // websocket protocol (subsequent header info is unnecessary)
    if (ctx->upgrade == 1)
    {
        swString_append_ptr(response, ZEND_STRL("\r\n"));
        ctx->send_header = 1;
        return;
    }

    if (!(header_flag & HTTP_HEADER_CONNECTION))
    {
        if (ctx->keepalive)
        {
            swString_append_ptr(response, ZEND_STRL("Connection: keep-alive\r\n"));
        }
        else
        {
            swString_append_ptr(response, ZEND_STRL("Connection: close\r\n"));
        }
    }
    if (!(header_flag & HTTP_HEADER_CONTENT_TYPE))
    {
        swString_append_ptr(response, ZEND_STRL("Content-Type: text/html\r\n"));
    }
    if (!(header_flag & HTTP_HEADER_DATE))
    {
        date_str = php_swoole_format_date((char *) ZEND_STRL(SW_HTTP_DATE_FORMAT), time(nullptr), 0);
        n = sw_snprintf(buf, l_buf, "Date: %s\r\n", date_str);
        swString_append_ptr(response, buf, n);
        efree(date_str);
    }

    if (ctx->send_chunked)
    {
        SW_ASSERT(body_length == 0);
        if (!(header_flag & HTTP_HEADER_TRANSFER_ENCODING))
        {
            swString_append_ptr(response, ZEND_STRL("Transfer-Encoding: chunked\r\n"));
        }
    }
    // Content-Length
    else if (body_length > 0 || ctx->parser.method != PHP_HTTP_HEAD)
    {
#ifdef SW_HAVE_COMPRESSION
        if (ctx->accept_compression)
        {
            body_length = swoole_zlib_buffer->length;
        }
#endif
        n = sw_snprintf(buf, l_buf, "Content-Length: %zu\r\n", body_length);
        swString_append_ptr(response, buf, n);
    }
#ifdef SW_HAVE_COMPRESSION
    //http compress
    if (ctx->accept_compression)
    {
        const char *content_encoding = swoole_http_get_content_encoding(ctx);
        swString_append_ptr(response, ZEND_STRL("Content-Encoding: "));
        swString_append_ptr(response, (char*) content_encoding, strlen(content_encoding));
        swString_append_ptr(response, ZEND_STRL("\r\n"));
    }
#endif
    swString_append_ptr(response, ZEND_STRL("\r\n"));
    ctx->send_header = 1;
}

#ifdef SW_HAVE_ZLIB
voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size)
{
    return (voidpf) safe_emalloc(items, size, 0);
}

void php_zlib_free(voidpf opaque, voidpf address)
{
    efree((void *)address);
}
#endif

#ifdef SW_HAVE_BROTLI
void* php_brotli_alloc(void* opaque, size_t size)
{
    return emalloc(size);
}

void php_brotli_free(void* opaque, void* address)
{
    efree(address);
}
#endif

#ifdef SW_HAVE_COMPRESSION
int swoole_http_response_compress(swString *body, int method, int level)
{
#ifdef SW_HAVE_ZLIB
    int encoding;
#endif

    if (0) { }
#ifdef SW_HAVE_ZLIB
    //gzip: 0x1f
    else if (method == HTTP_COMPRESS_GZIP)
    {
        encoding = 0x1f;
    }
    //deflate: -0xf
    else if (method == HTTP_COMPRESS_DEFLATE)
    {
        encoding = -0xf;
    }
#endif
#ifdef SW_HAVE_BROTLI
    else if (method == HTTP_COMPRESS_BR)
    {
        if (level < BROTLI_MIN_QUALITY)
        {
            level = BROTLI_MIN_QUALITY;
        }
        else if (level > BROTLI_MAX_QUALITY)
        {
            level = BROTLI_MAX_QUALITY;
        }

        size_t memory_size = BrotliEncoderMaxCompressedSize(body->length);
        if (memory_size > swoole_zlib_buffer->size)
        {
            if (swString_extend(swoole_zlib_buffer, memory_size) < 0)
            {
                return SW_ERR;
            }
        }

        size_t input_size = body->length;
        const uint8_t *input_buffer = (const uint8_t *) body->str;
        size_t encoded_size = swoole_zlib_buffer->size;
        uint8_t *encoded_buffer = (uint8_t *) swoole_zlib_buffer->str;

        if (BROTLI_TRUE != BrotliEncoderCompress(
            level, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
            input_size, input_buffer, &encoded_size, encoded_buffer
        ))
        {
            swWarn("BrotliEncoderCompress() failed");
            return SW_ERR;
        }
        else
        {
            swoole_zlib_buffer->length = encoded_size;
            return SW_OK;
        }
    }
#endif
    else
    {
        swWarn("Unknown compression method");
        return SW_ERR;
    }
#ifdef SW_HAVE_ZLIB
    if (level < Z_NO_COMPRESSION)
    {
        level = Z_DEFAULT_COMPRESSION;
    }
    else if (level == Z_NO_COMPRESSION)
    {
        level = Z_BEST_SPEED;
    }
    else if (level > Z_BEST_COMPRESSION)
    {
        level = Z_BEST_COMPRESSION;
    }

    size_t memory_size = ((size_t) ((double) body->length * (double) 1.015)) + 10 + 8 + 4 + 1;
    if (memory_size > swoole_zlib_buffer->size)
    {
        if (swString_extend(swoole_zlib_buffer, memory_size) < 0)
        {
            return SW_ERR;
        }
    }

    z_stream zstream = {};
    int status;

    zstream.zalloc = php_zlib_alloc;
    zstream.zfree = php_zlib_free;

    status = deflateInit2(&zstream, level, Z_DEFLATED, encoding, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (status != Z_OK)
    {
        swWarn("deflateInit2() failed, Error: [%d]", status);
        return SW_ERR;
    }

    zstream.next_in = (Bytef *) body->str;
    zstream.avail_in = body->length;
    zstream.next_out = (Bytef *) swoole_zlib_buffer->str;
    zstream.avail_out = swoole_zlib_buffer->size;

    status = deflate(&zstream, Z_FINISH);
    deflateEnd(&zstream);
    if (status != Z_STREAM_END)
    {
        swWarn("deflate() failed, Error: [%d]", status);
        return SW_ERR;
    }

    swoole_zlib_buffer->length = zstream.total_out;
    return SW_OK;
#endif
}
#endif

static PHP_METHOD(swoole_http_response, initHeader)
{
    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }
    zval *zresponse_object = ctx->response.zobject;
    swoole_http_init_and_read_property(swoole_http_response_ce, zresponse_object, &ctx->response.zheader, ZEND_STRL("header"));
    swoole_http_init_and_read_property(swoole_http_response_ce, zresponse_object, &ctx->response.zcookie, ZEND_STRL("cookie"));
#ifdef SW_USE_HTTP2
    swoole_http_init_and_read_property(swoole_http_response_ce, zresponse_object, &ctx->response.ztrailer, ZEND_STRL("trailer"));
#endif
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, end)
{
    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    zval *zdata = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL_EX(zdata, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

#ifdef SW_USE_HTTP2
    if (ctx->http2)
    {
        swoole_http2_response_end(ctx, zdata, return_value);
    }
    else
#endif
    {
        swoole_http_response_end(ctx, zdata, return_value);
    }
}

void swoole_http_response_end(http_context *ctx, zval *zdata, zval *return_value)
{
    swString http_body;
    if (zdata)
    {
        http_body.length = php_swoole_get_send_data(zdata, &http_body.str);
    }
    else
    {
        http_body.length = 0;
        http_body.str = nullptr;
    }

    if (ctx->send_chunked)
    {
        if (!ctx->send(ctx, ZEND_STRL("0\r\n\r\n")))
        {
            RETURN_FALSE;
        }
        ctx->send_chunked = 0;
    }
    //no http chunk
    else
    {
        swString *http_buffer = http_get_write_buffer(ctx);

        swString_clear(http_buffer);
#ifdef SW_HAVE_COMPRESSION
        if (ctx->accept_compression)
        {
            if (http_body.length == 0 || swoole_http_response_compress(&http_body, ctx->compression_method, ctx->compression_level) != SW_OK)
            {
                ctx->accept_compression = 0;
            }
        }
#endif
        http_build_header(ctx, http_buffer, http_body.length);

        char *send_body_str;
        size_t send_body_len;

        if (http_body.length > 0)
        {
#ifdef SW_HAVE_COMPRESSION
            if (ctx->accept_compression)
            {
                send_body_str = swoole_zlib_buffer->str;
                send_body_len = swoole_zlib_buffer->length;
            }
            else
#endif
            {
                send_body_str = http_body.str;
                send_body_len = http_body.length;
            }
            /**
             *
             */
#ifdef SW_HTTP_SEND_TWICE
            if (send_body_len < SwooleG.pagesize)
#endif
            {
                if (swString_append_ptr(http_buffer, send_body_str, send_body_len) < 0)
                {
                    ctx->send_header = 0;
                    RETURN_FALSE;
                }
            }
#ifdef SW_HTTP_SEND_TWICE
            else
            {
                if (!ctx->send(ctx, http_buffer->str, http_buffer->length))
                {
                    ctx->send_header = 0;
                    RETURN_FALSE;
                }
                if (!ctx->send(ctx, send_body_str, send_body_len))
                {
                    ctx->end = 1;
                    ctx->close(ctx);
                    RETURN_FALSE;
                }
                goto _skip_copy;
            }
#endif
        }

        if (!ctx->send(ctx, http_buffer->str, http_buffer->length))
        {
            ctx->end = 1;
            ctx->close(ctx);
            RETURN_FALSE;
        }
    }

#ifdef SW_HTTP_SEND_TWICE
    _skip_copy:
#endif
    if (ctx->upgrade && !ctx->co_socket)
    {
        swServer *serv = (swServer*) ctx->private_data;
        swConnection *conn = swWorker_get_connection(serv, ctx->fd);
        if (conn && conn->websocket_status == WEBSOCKET_STATUS_HANDSHAKE)
        {
            if (ctx->response.status == 101)
            {
                conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;
            }
            else
            {
                /* connection should be closed when handshake failed */
                conn->websocket_status = WEBSOCKET_STATUS_NONE;
                ctx->keepalive = 0;
            }
        }
    }
    if (!ctx->keepalive)
    {
        ctx->close(ctx);
    }
    ctx->end = 1;
    RETURN_TRUE;
}

bool swoole_http_response_set_header(http_context *ctx, const char *k, size_t klen, const char *v, size_t vlen, bool ucwords)
{
    if (UNEXPECTED(klen > SW_HTTP_HEADER_KEY_SIZE - 1))
    {
        php_swoole_error(E_WARNING, "header key is too long");
        return false;
    }
    zval *zheader = swoole_http_init_and_read_property(swoole_http_response_ce, ctx->response.zobject, &ctx->response.zheader, ZEND_STRL("header"));
    if (ucwords)
    {
        char key_buf[SW_HTTP_HEADER_KEY_SIZE];
        strncpy(key_buf, k, klen)[klen] = '\0';
#ifdef SW_USE_HTTP2
        if (ctx->http2)
        {
            swoole_strtolower(key_buf, klen);
        }
        else
#endif
        {
            http_header_key_format(key_buf, klen);
        }
        if (UNEXPECTED(!v))
        {
            add_assoc_null_ex(zheader, key_buf, klen);
        }
        else
        {
            add_assoc_stringl_ex(zheader, key_buf, klen, (char *) v, vlen);
        }
    }
    else
    {
        if (UNEXPECTED(!v))
        {
            add_assoc_null_ex(zheader, k, klen);
        }
        else
        {
            add_assoc_stringl_ex(zheader, k, klen, (char *) v, vlen);
        }
    }
    return true;
}

static PHP_METHOD(swoole_http_response, sendfile)
{
    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    if (ctx->send_chunked)
    {
        php_swoole_fatal_error(E_WARNING, "can't use sendfile when HTTP chunk is enabled");
        RETURN_FALSE;
    }

    char *file;
    size_t l_file;
    zend_long offset = 0;
    zend_long length = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ll", &file, &l_file, &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (l_file == 0)
    {
        php_swoole_error(E_WARNING, "file name is empty");
        RETURN_FALSE;
    }

    struct stat file_stat;
    if (stat(file, &file_stat) < 0)
    {
        php_swoole_sys_error(E_WARNING, "stat(%s) failed", file);
        RETURN_FALSE;
    }
    if (file_stat.st_size < offset)
    {
        php_swoole_error(E_WARNING, "parameter $offset[" ZEND_LONG_FMT "] exceeds the file size", offset);
        RETURN_FALSE;
    }
    if (length > file_stat.st_size - offset)
    {
        php_swoole_error(E_WARNING, "parameter $length[" ZEND_LONG_FMT "] exceeds the file size", length);
        RETURN_FALSE;
    }
    if (length == 0)
    {
        length = file_stat.st_size - offset;
    }

#ifdef SW_USE_HTTP2
    if (!ctx->http2)
#endif
    if (!ctx->send_header)
    {
#ifdef SW_HAVE_COMPRESSION
        ctx->accept_compression = 0;
#endif
        swString *http_buffer = http_get_write_buffer(ctx);

        swString_clear(http_buffer);

        zval *zheader = sw_zend_read_and_convert_property_array(swoole_http_response_ce, ctx->response.zobject, ZEND_STRL("header"), 0);
        if (!zend_hash_str_exists(Z_ARRVAL_P(zheader), ZEND_STRL("Content-Type")))
        {
            add_assoc_string(zheader, "Content-Type", (char *) swoole::mime_type::get(file).c_str());
        }

        http_build_header(ctx, http_buffer, length);

        if (!ctx->send(ctx, http_buffer->str, http_buffer->length))
        {
            ctx->send_header = 0;
            RETURN_FALSE;
        }
    }

    if (length != 0)
    {
        if (!ctx->sendfile(ctx, file, l_file, offset, length))
        {
            ctx->close(ctx);
            RETURN_FALSE;
        }
    }

    ctx->end = 1;

    if (!ctx->keepalive)
    {
        ctx->close(ctx);
    }

    RETURN_TRUE;
}

static void php_swoole_http_response_cookie(INTERNAL_FUNCTION_PARAMETERS, const bool url_encode)
{
    char *name, *value = nullptr, *path = nullptr, *domain = nullptr, *samesite = nullptr;
    zend_long expires = 0;
    size_t name_len, value_len = 0, path_len = 0, domain_len = 0, samesite_len = 0;
    zend_bool secure = 0, httponly = 0;

    ZEND_PARSE_PARAMETERS_START(1, 8)
        Z_PARAM_STRING(name, name_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(value, value_len)
        Z_PARAM_LONG(expires)
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_STRING(domain, domain_len)
        Z_PARAM_BOOL(secure)
        Z_PARAM_BOOL(httponly)
        Z_PARAM_STRING(samesite, samesite_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    int cookie_size = name_len /* + value_len */ + path_len + domain_len + 100;
    char *cookie = nullptr, *date = nullptr;

    if (name_len > 0 && strpbrk(name, "=,; \t\r\n\013\014") != nullptr)
    {
        php_swoole_error(E_WARNING, "Cookie names can't contain any of the following '=,; \\t\\r\\n\\013\\014'");
        RETURN_FALSE;
    }
    if (value_len == 0)
    {
        cookie = (char *) emalloc(cookie_size);
        date = php_swoole_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), 1, 0);
        snprintf(cookie, cookie_size, "%s=deleted; expires=%s", name, date);
        efree(date);
    }
    else
    {
        if (url_encode)
        {
            char *encoded_value;
            int encoded_value_len;
            encoded_value = php_swoole_url_encode(value, value_len, &encoded_value_len);
            cookie_size += encoded_value_len;
            cookie = (char *) emalloc(cookie_size);
            snprintf(cookie, cookie_size, "%s=%s", name, encoded_value);
            efree(encoded_value);
        }
        else
        {
            cookie_size += value_len;
            cookie = (char *) emalloc(cookie_size);
            snprintf(cookie, cookie_size, "%s=%s", name, value);
        }
        if (expires > 0)
        {
            strlcat(cookie, "; expires=", cookie_size);
            date = php_swoole_format_date((char *) ZEND_STRL("D, d-M-Y H:i:s T"), expires, 0);
            const char *p = (const char *) zend_memrchr(date, '-', strlen(date));
            if (!p || *(p + 5) != ' ')
            {
                php_swoole_error(E_WARNING, "Expiry date can't be a year greater than 9999");
                efree(date);
                efree(cookie);
                RETURN_FALSE;
            }
            strlcat(cookie, date, cookie_size);
            efree(date);
        }
    }
    if (path_len > 0)
    {
        strlcat(cookie, "; path=", cookie_size);
        strlcat(cookie, path, cookie_size);
    }
    if (domain_len > 0)
    {
        strlcat(cookie, "; domain=", cookie_size);
        strlcat(cookie, domain, cookie_size);
    }
    if (secure)
    {
        strlcat(cookie, "; secure", cookie_size);
    }
    if (httponly)
    {
        strlcat(cookie, "; httponly", cookie_size);
    }
    if (samesite_len > 0)
    {
        strlcat(cookie, "; samesite=", cookie_size);
        strlcat(cookie, samesite, cookie_size);
    }
    add_next_index_stringl(
        swoole_http_init_and_read_property(swoole_http_response_ce, ctx->response.zobject, &ctx->response.zcookie, ZEND_STRL("cookie")),
        cookie, strlen(cookie)
    );
    efree(cookie);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, cookie)
{
    php_swoole_http_response_cookie(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static PHP_METHOD(swoole_http_response, rawcookie)
{
    php_swoole_http_response_cookie(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_METHOD(swoole_http_response, status)
{
    zend_long http_status;
    char* reason = nullptr;
    size_t reason_len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(http_status)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(reason, reason_len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    ctx->response.status = http_status;
    ctx->response.reason = reason_len > 0 ? estrndup(reason, reason_len) : nullptr;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, header)
{
    char *k, *v;
    size_t klen, vlen;
    zend_bool ucwords = 1;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(k, klen)
        Z_PARAM_STRING_EX(v, vlen, 1, 0)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(ucwords)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(swoole_http_response_set_header(ctx, k, klen, v, vlen, ucwords));
}

#ifdef SW_USE_HTTP2
static PHP_METHOD(swoole_http_response, trailer)
{
    char *k, *v;
    size_t klen, vlen;
    char key_buf[SW_HTTP_HEADER_KEY_SIZE];

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(k, klen)
        Z_PARAM_STRING_EX(v, vlen, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (!ctx || !ctx->http2)
    {
        RETURN_FALSE;
    }
    if (UNEXPECTED(klen > SW_HTTP_HEADER_KEY_SIZE - 1))
    {
        php_swoole_error(E_WARNING, "trailer key is too long");
        RETURN_FALSE;
    }
    zval *ztrailer = swoole_http_init_and_read_property(swoole_http_response_ce, ctx->response.zobject, &ctx->response.ztrailer, ZEND_STRL("trailer"));
    strncpy(key_buf, k, klen)[klen] = '\0';
    swoole_strtolower(key_buf, klen);
    if (UNEXPECTED(!v))
    {
        add_assoc_null_ex(ztrailer, key_buf, klen);
    }
    else
    {
        add_assoc_stringl_ex(ztrailer, key_buf, klen, v, vlen);
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, ping)
{
    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->http2))
    {
        php_swoole_fatal_error(E_WARNING, "fd[%d] is not a HTTP2 conncetion", ctx->fd);
        RETURN_FALSE;
    }
    SW_CHECK_RETURN(swoole_http2_server_ping(ctx));
}
#endif

static PHP_METHOD(swoole_http_response, upgrade)
{
    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->co_socket))
    {
        php_swoole_fatal_error(E_WARNING, "async server dose not support protocol upgrade");
        RETURN_FALSE;
    }
    RETVAL_BOOL(swoole_websocket_handshake(ctx));
}

static PHP_METHOD(swoole_http_response, push)
{
    http_context *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        swoole_set_last_error(SW_ERROR_SESSION_CLOSED);
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->co_socket || !ctx->upgrade))
    {
        php_swoole_fatal_error(E_WARNING, "fd[%d] is not a websocket conncetion", ctx->fd);
        RETURN_FALSE;
    }

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

    swString *http_buffer = http_get_write_buffer(ctx);
    swString_clear(http_buffer);
    if (php_swoole_websocket_frame_is_object(zdata))
    {
        if (php_swoole_websocket_frame_object_pack(http_buffer, zdata, 0, ctx->websocket_compression) < 0)
        {
            RETURN_FALSE;
        }
    }
    else
    {
        if (php_swoole_websocket_frame_pack(http_buffer, zdata, opcode, flags & SW_WEBSOCKET_FLAGS_ALL, 0, ctx->websocket_compression) < 0)
        {
            RETURN_FALSE;
        }
    }
    RETURN_BOOL(ctx->send(ctx, http_buffer->str, http_buffer->length));
}

static PHP_METHOD(swoole_http_response, close)
{
    http_context *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        swoole_set_last_error(SW_ERROR_SESSION_CLOSED);
        RETURN_FALSE;
    }
    RETURN_BOOL(ctx->close(ctx));
}

static PHP_METHOD(swoole_http_response, recv)
{
    http_context *ctx = php_swoole_http_response_get_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        swoole_set_last_error(SW_ERROR_SESSION_CLOSED);
        RETURN_FALSE;
    }
    if (UNEXPECTED(!ctx->co_socket || !ctx->upgrade))
    {
        php_swoole_fatal_error(E_WARNING, "fd[%d] is not a websocket conncetion", ctx->fd);
        RETURN_FALSE;
    }

    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    Socket *sock = (Socket *) ctx->private_data;
    ssize_t retval = sock->recv_packet(timeout);
    swString _tmp;

    if (retval < 0)
    {
        swoole_set_last_error(sock->errCode);
        RETURN_FALSE;
    }
    else if (retval == 0)
    {
        RETURN_EMPTY_STRING();
    }
    else
    {
        _tmp.str = sock->get_read_buffer()->str;
        _tmp.length = retval;

#ifdef SW_HAVE_ZLIB
        php_swoole_websocket_frame_unpack_ex(&_tmp, return_value, ctx->websocket_compression);
#else
        php_swoole_websocket_frame_unpack(&_tmp, return_value);
#endif
    }
}

static PHP_METHOD(swoole_http_response, detach)
{
    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (!ctx)
    {
        RETURN_FALSE;
    }
    ctx->detached = 1;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_response, create)
{
    zval *zserver = nullptr;
    zend_long fd;
    swServer *serv;

    if (ZEND_NUM_ARGS() == 1)
    {
        ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_LONG(fd)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        serv = sw_server();
    }
    else
    {
        ZEND_PARSE_PARAMETERS_START(2, 2)
            Z_PARAM_OBJECT_OF_CLASS(zserver, swoole_server_ce)
            Z_PARAM_LONG(fd)
        ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

        serv = php_swoole_server_get_and_check_server(zserver);
    }

    if (serv == nullptr || !serv->gs->start)
    {
        php_swoole_fatal_error(E_WARNING, "server is not running");
        RETURN_FALSE;
    }

    http_context *ctx = (http_context *) ecalloc(1, sizeof(http_context));
    if (!ctx)
    {
        RETURN_FALSE;
    }

    ctx->fd = (int) fd;
    ctx->keepalive = 1;

    swoole_http_server_init_context(sw_server(), ctx);

    if (sw_unlikely(swoole_http_buffer == nullptr))
    {
        php_swoole_http_server_init_global_variant();
    }

    object_init_ex(return_value, swoole_http_response_ce);
    php_swoole_http_response_set_context(return_value, ctx);
    ctx->response.zobject = return_value;
    sw_copy_to_stack(ctx->response.zobject, ctx->response._zobject);

    zend_update_property_long(swoole_http_response_ce, return_value, ZEND_STRL("fd"), fd);
}

static PHP_METHOD(swoole_http_response, redirect)
{
    zval *zurl;
    zval *zhttp_code = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(zurl)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL_EX(zhttp_code, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    http_context *ctx = php_swoole_http_response_get_and_check_context(ZEND_THIS);
    if (UNEXPECTED(!ctx))
    {
        RETURN_FALSE;
    }

    // status
    if (zhttp_code)
    {
        ctx->response.status = zval_get_long(zhttp_code);
    }
    else
    {
        ctx->response.status = 302;
    }

    zval zkey;
    ZVAL_STRINGL(&zkey, "Location", 8);
    sw_zend_call_method_with_2_params(ZEND_THIS, nullptr, nullptr, "header", return_value, &zkey, zurl);
    zval_ptr_dtor(&zkey);
    if (!Z_BVAL_P(return_value))
    {
        return;
    }
    swoole_http_response_end(ctx, nullptr, return_value);
}

static PHP_METHOD(swoole_http_response, __destruct) { }
