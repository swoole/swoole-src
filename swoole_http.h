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

#pragma once

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

    // Notice: Do not change the order
    zval *zobject;
    zval _zobject;
    zval *zserver;
    zval _zserver;
    zval *zheader;
    zval _zheader;
    zval *zget;
    zval _zget;
    zval *zpost;
    zval _zpost;
    zval *zcookie;
    zval _zcookie;
    zval *zrequest;
    zval _zrequest;
    zval *zfiles;
    zval _zfiles;
    zval *ztmpfiles;
    zval _ztmpfiles;
} http_request;

typedef struct
{
    enum swoole_http_method method;
    int version;
    int status;
    char* reason;

    // Notice: Do not change the order
    zval *zobject;
    zval _zobject;
    zval *zheader;
    zval _zheader;
    zval *zcookie;
    zval _zcookie;
    zval *ztrailer;
    zval _ztrailer;
} http_response;

typedef struct _http_context
{
    int fd;
    uint32_t completed :1;
    uint32_t end :1;
    uint32_t send_header :1;
#ifdef SW_HAVE_ZLIB
    uint32_t enable_compression :1;
    uint32_t accept_compression :1;
#endif
    uint32_t chunk :1;
    uint32_t keepalive :1;
    uint32_t websocket :1;
    uint32_t upgrade :1;
    uint32_t detached :1;
    uint32_t parse_cookie :1;
    uint32_t parse_body :1;
    uint32_t co_socket :1;

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

    void *private_data;
    void *private_data_2;
    bool (*send)(struct _http_context* ctx, const char *data, size_t length);
    bool (*close)(struct _http_context* ctx);

} http_context;

extern zend_class_entry *swoole_http_server_ce;
extern zend_class_entry *swoole_http_request_ce;
extern zend_class_entry *swoole_http_response_ce;

extern swString *swoole_http_buffer;
#ifdef SW_HAVE_ZLIB
extern swString *swoole_zlib_buffer;
#endif

#define http_strncasecmp(const_str, at, length) \
    ((length >= sizeof(const_str)-1) && \
    (strncasecmp(at, ZEND_STRL(const_str)) == 0))

http_context* swoole_http_context_new(int fd);
void swoole_http_context_free(http_context *ctx);
static sw_inline zval* swoole_http_init_and_read_property(zend_class_entry *ce, zval *zobject, zval** zproperty_store_pp, const char *name, size_t name_len)
{
    if (UNEXPECTED(!*zproperty_store_pp))
    {
        // Notice: swoole http server properties can not be unset anymore, so we can read it without checking
        zval rv, *property = zend_read_property(ce, zobject, name, name_len, 0, &rv);
        array_init(property);
        *zproperty_store_pp = (zval *) (zproperty_store_pp + 1);
        **zproperty_store_pp = *property;
    }
    return *zproperty_store_pp;
}
int swoole_http_parse_form_data(http_context *ctx, const char *boundary_str, int boundary_len);
void swoole_http_parse_cookie(zval *array, const char *at, size_t length);
const swoole_http_parser_settings* swoole_http_get_parser_setting();

void swoole_http_server_init_context(swServer *serv, http_context *ctx);

bool swoole_http_response_set_header(http_context *ctx, const char *k, size_t klen, const char *v, size_t vlen, bool ucwords);
void swoole_http_response_end(http_context *ctx, zval *zdata, zval *return_value);

#ifdef SW_HAVE_ZLIB
int swoole_http_response_compress(swString *body, int method, int level);
void swoole_http_get_compression_method(http_context *ctx, const char *accept_encoding, size_t length);
const char* swoole_http_get_content_encoding(http_context *ctx);

static sw_inline voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size)
{
    return (voidpf) safe_emalloc(items, size, 0);
}

static sw_inline void php_zlib_free(voidpf opaque, voidpf address)
{
    efree((void *)address);
}
#endif

static int http_parse_set_cookies(const char *at, size_t length, zval *cookies, zval *set_cookie_headers)
{
    const char *key = at;
    zval val;
    size_t key_len = 0, val_len = 0;
    const char *p, *eof = at + length;
    // key
    p = (char *) memchr(at, '=', length);
    if (p)
    {
        key_len = p - at;
    }
    if (key_len == 0 || key_len >= length - 1)
    {
        swWarn("cookie key format is wrong");
        return SW_ERR;
    }
    if (key_len > SW_HTTP_COOKIE_KEYLEN)
    {
        swWarn("cookie[%.8s...] name length %d is exceed the max name len %d", key, key_len, SW_HTTP_COOKIE_KEYLEN);
        return SW_ERR;
    }
    add_assoc_stringl_ex(set_cookie_headers, key, key_len, (char *) at, length);
    // val
    p++;
    eof = (char*) memchr(p, ';', at + length - p);
    if (!eof)
    {
        eof = at + length;
    }
    val_len = eof - p;
    if (val_len > SW_HTTP_COOKIE_VALLEN)
    {
        swWarn("cookie[%.*s]'s value[v=%.8s...] length %d is exceed the max value len %d", (int) key_len, key, p, val_len, SW_HTTP_COOKIE_VALLEN);
        return SW_ERR;
    }
    ZVAL_STRINGL(&val, p, val_len);
    Z_STRLEN(val) = php_url_decode(Z_STRVAL(val), val_len);
    add_assoc_zval_ex(cookies, at, key_len, &val);
    return SW_OK;
}

int swoole_websocket_onMessage(swServer *serv, swEventData *req);
int swoole_websocket_onHandshake(swServer *serv, swListenPort *port, http_context *ctx);
void swoole_websocket_onOpen(http_context *ctx);
void swoole_websocket_onRequest(http_context *ctx);
bool swoole_websocket_handshake(http_context *ctx);

#ifdef SW_USE_HTTP2
int swoole_http2_server_onFrame(swConnection *conn, swEventData *req);
int swoole_http2_server_do_response(http_context *ctx, swString *body);
void swoole_http2_server_session_free(swConnection *conn);
int swoole_http2_server_ping(http_context *ctx);

namespace swoole { namespace http2 {
//-----------------------------------namespace begin--------------------------------------------
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
//-----------------------------------namespace end--------------------------------------------
}}
#endif
