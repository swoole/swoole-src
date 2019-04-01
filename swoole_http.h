/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#ifndef SWOOLE_HTTP_H_
#define SWOOLE_HTTP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "thirdparty/swoole_http_parser.h"
#include "thirdparty/multipart_parser.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef SW_USE_HTTP2
#include "thirdparty/http2/nghttp2.h"
#endif

enum http_header_flag
{
    HTTP_HEADER_SERVER            = 1u << 1,
    HTTP_HEADER_CONNECTION        = 1u << 2,
    HTTP_HEADER_CONTENT_LENGTH    = 1u << 3,
    HTTP_HEADER_DATE              = 1u << 4,
    HTTP_HEADER_CONTENT_TYPE      = 1u << 5,
    HTTP_HEADER_TRANSFER_ENCODING = 1u << 6,
    HTTP_HEADER_ACCEPT_ENCODING = 1u << 7,
};

enum http_compress_method
{
    HTTP_COMPRESS_GZIP = 1,
    HTTP_COMPRESS_DEFLATE,
    HTTP_COMPRESS_BR,
};

typedef struct
{
    enum swoole_http_method method;
    int version;
    char *path;
    uint32_t path_len;
    const char *ext;
    uint32_t ext_len;
    uint8_t post_form_urlencoded;

#ifdef SW_USE_HTTP2
    swString *post_buffer;
#endif
    uint32_t post_length;

    zval *zobject;
    zval *zserver;
    zval *zheader;
    zval *zget;
    zval *zpost;
    zval *zcookie;
    zval *zrequest;
    zval *zfiles;
    zval *ztmpfiles;
    zval _zobject;
    zval _zrequest;
    zval _zserver;
    zval _zheader;
    zval _zget;
    zval _zpost;
    zval _zfiles;
    zval _zcookie;
    zval _ztmpfiles;
} http_request;

typedef struct
{
    enum swoole_http_method method;
    int version;
    int status;
    char* reason;
    zval *zobject;
    zval *zheader;
    zval *zcookie;
    zval *ztrailer;

    zval _zobject;
    zval _zheader;
    zval _zcookie;
    zval _ztrailer;
} http_response;

typedef struct
{
    int fd;
    uint32_t end :1;
    uint32_t send_header :1;
#ifdef SW_HAVE_ZLIB
    uint32_t enable_compression :1;
#endif
    uint32_t chunk :1;
    uint32_t keepalive :1;
    uint32_t upgrade :1;
    uint32_t detached :1;

#ifdef SW_HAVE_ZLIB
    int8_t compression_level;
    int8_t compression_method;
#endif

#ifdef SW_USE_HTTP2
    void* stream;
#endif
    http_request request;
    http_response response;

    swoole_http_parser parser;
    multipart_parser *mt_parser;

    uint16_t input_var_num;
    char *current_header_name;
    size_t current_header_name_len;
    char *current_input_name;
    char *current_form_data_name;
    size_t current_form_data_name_len;
    zval *current_multipart_header;

} http_context;


/**
 * WebSocket
 */
int swoole_websocket_onMessage(swServer *serv, swEventData *);
int swoole_websocket_onHandshake(swServer *serv, swListenPort *port, http_context *);
void swoole_websocket_onOpen(http_context *);
void swoole_websocket_onRequest(http_context *);

/**
 * Http Context
 */
http_context* swoole_http_context_new(int fd);
void swoole_http_context_free(http_context *ctx);
int swoole_http_parse_form_data(http_context *ctx, const char *boundary_str, int boundary_len);
void swoole_http_parse_cookie(zval *array, const char *at, size_t length);

#define swoole_http_server_array_init(name, class)    SW_MAKE_STD_ZVAL(z##name);\
array_init(z##name);\
zend_update_property(swoole_http_##class##_ce_ptr, z##class##_object, ZEND_STRL(#name), z##name);\
ctx->class.z##name = sw_zend_read_property(swoole_http_##class##_ce_ptr, z##class##_object, ZEND_STRL(#name), 0);\
sw_copy_to_stack(ctx->class.z##name, ctx->class._z##name);\
zval_ptr_dtor(z##name);\
z##name = ctx->class.z##name;

#define http_strncasecmp(const_str, at, length) ((length >= sizeof(const_str)-1) &&\
        (strncasecmp(at, ZEND_STRL(const_str)) == 0))

#ifdef SW_USE_HTTP2
/**
 * Http v2
 */
int swoole_http2_onFrame(swConnection *conn, swEventData *req);
int swoole_http2_do_response(http_context *ctx, swString *body);
void swoole_http2_free(swConnection *conn);
#endif

extern zend_class_entry *swoole_http_server_ce_ptr;
extern zend_class_entry *swoole_http_response_ce_ptr;
extern zend_class_entry *swoole_http_request_ce_ptr;

extern swString *swoole_http_buffer;

#ifdef SW_HAVE_ZLIB
extern swString *swoole_zlib_buffer;
int swoole_http_response_compress(swString *body, int method, int level);
void swoole_http_get_compression_method(http_context *ctx, const char *accept_encoding, size_t length);
const char* swoole_http_get_content_encoding(http_context *ctx);

static sw_inline voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size)
{
    return (voidpf) safe_emalloc(items, size, 0);
}

static sw_inline void php_zlib_free(voidpf opaque, voidpf address)
{
    efree((void* )address);
}
#endif

static sw_inline int http_parse_set_cookies(const char *at, size_t length, zval *cookies, zval *set_cookie_headers)
{
    size_t klen = 0, vlen = 0;
    char *p, *eof;
    // key
    p = (char*) memchr(at, '=', length);
    if (p)
    {
        klen = p - at;
    }
    if (klen == 0 || klen >= SW_HTTP_COOKIE_KEYLEN || klen >= length - 1)
    {
        swWarn("cookie key format is wrong.");
        return SW_ERR;
    }
    add_assoc_stringl_ex(set_cookie_headers, at, klen, (char *) at, length);
    // val
    p+=1;
    eof = (char*) memchr(p, ';', length);
    if (!eof)
    {
        eof = (char *) at + length;
    }
    vlen = php_url_decode(p, eof - p);
    add_assoc_stringl_ex(cookies, at, klen, p, vlen);
    return SW_OK;
}

#ifdef __cplusplus
}
#endif

#ifdef SW_USE_HTTP2
namespace swoole
{
namespace http2
{
class headers
{
public:
    headers(size_t size) : size(size), index(0)
    {
        nvs = (nghttp2_nv *) ecalloc(size, sizeof(nghttp2_nv));
    }

    inline nghttp2_nv* get()
    {
        return nvs;
    }

    inline size_t len()
    {
        return index;
    }

    void reserve_one()
    {
        index++;
    }

    inline void add(
        size_t index,
        const char *name, size_t name_len,
        const char *value, size_t value_len,
        const uint8_t flags = NGHTTP2_NV_FLAG_NONE)
    {
        if (likely(index < size || nvs[index].name == nullptr))
        {
            nghttp2_nv *nv = &nvs[index];
            name = zend_str_tolower_dup(name, name_len); // auto to lower
            nv->name = (uchar*) name;
            nv->namelen = name_len;
            nv->value = (uchar*) emalloc(value_len);
            memcpy(nv->value, value, value_len);
            nv->valuelen = value_len;
            nv->flags = flags | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
            swTraceLog(SW_TRACE_HTTP2,"name=(%zu)[%.*s], value=(%zu)[%.*s]", name_len, (int) name_len, name, value_len, (int) value_len, value);
        }
        else
        {
            swoole_php_fatal_error(E_WARNING, "unexpect http2 header [%.*s] (duplicated or overflow)", (int) name_len, name);
        }
    }

    inline void add(
        const char *name, size_t name_len,
        const char *value, size_t value_len,
        const uint8_t flags = NGHTTP2_NV_FLAG_NONE
    )
    {
        add(index++, name, name_len, value, value_len, flags);
    }

    ~headers()
    {
        for (size_t i = 0; i < size; ++i)
        {
            if (likely(nvs[i].name/* && nvs[i].value */))
            {
                efree((void *) nvs[i].name);
                efree((void *) nvs[i].value);
            }
        }
        efree(nvs);
    }

private:
    nghttp2_nv *nvs;
    size_t size;
    size_t index;
};
}
}
#endif

#endif /* SWOOLE_HTTP_H_ */
