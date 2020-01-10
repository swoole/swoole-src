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

#include <unordered_map>

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#define SW_ZLIB_ENCODING_RAW        -0xf
#define SW_ZLIB_ENCODING_GZIP       0x1f
#define SW_ZLIB_ENCODING_DEFLATE    0x0f
#define SW_ZLIB_ENCODING_ANY        0x2f
#endif

#ifdef SW_USE_HTTP2
#include "thirdparty/nghttp2/nghttp2.h"
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
    HTTP_COMPRESS_NONE,
    HTTP_COMPRESS_GZIP,
    HTTP_COMPRESS_DEFLATE,
    HTTP_COMPRESS_BR,
};

struct http_request
{
    int version;
    char *path;
    uint32_t path_len;
    const char *ext;
    uint32_t ext_len;
    uint8_t post_form_urlencoded;

    zval zdata;
    size_t body_length;
#ifdef SW_USE_HTTP2
    swString *h2_data_buffer;
#endif

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
    zval *zfiles;
    zval _zfiles;
    zval *ztmpfiles;
    zval _ztmpfiles;
};

struct http_response
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
};

struct http_context
{
    int fd;
    uint32_t completed :1;
    uint32_t end :1;
    uint32_t send_header :1;
#ifdef SW_HAVE_COMPRESSION
    uint32_t enable_compression :1;
    uint32_t accept_compression :1;
#endif
    uint32_t chunk :1;
    uint32_t keepalive :1;
    uint32_t websocket :1;
#ifdef SW_HAVE_ZLIB
    uint32_t websocket_compression :1;
#endif
    uint32_t upgrade :1;
    uint32_t detached :1;
    uint32_t parse_cookie :1;
    uint32_t parse_body :1;
    uint32_t parse_files :1;
    uint32_t co_socket :1;

#ifdef SW_HAVE_COMPRESSION
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
    size_t current_input_name_len;
    char *current_form_data_name;
    size_t current_form_data_name_len;
    zval *current_multipart_header;

    const char *upload_tmp_dir;

    void *private_data;
    void *private_data_2;
    bool (*send)(http_context* ctx, const char *data, size_t length);
    bool (*sendfile)(http_context* ctx, const char *file, uint32_t l_file, off_t offset, size_t length);
    bool (*close)(http_context* ctx);
};

#ifdef SW_USE_HTTP2
class http2_stream
{
public:
    http_context* ctx;
    // uint8_t priority; // useless now
    uint32_t id;
    // flow control
    uint32_t send_window;
    uint32_t recv_window;

    http2_stream(int _fd, uint32_t _id);
    ~http2_stream();

    bool send_header(size_t body_length, bool end_stream);
    bool send_body(swString *body, bool end_stream, size_t max_frame_size);
    bool send_trailer();

    void reset(uint32_t error_code);
};

class http2_session
{
public:
    int fd;
    std::unordered_map<uint32_t, http2_stream*> streams;

    nghttp2_hd_inflater *inflater = nullptr;
    nghttp2_hd_deflater *deflater = nullptr;

    uint32_t header_table_size;
    uint32_t send_window;
    uint32_t recv_window;
    uint32_t max_concurrent_streams;
    uint32_t max_frame_size;

    http_context *default_ctx = nullptr;
    void *private_data = nullptr;

    void (*handle)(http2_session *, http2_stream *) = nullptr;

    http2_session(int _fd);
    ~http2_session();
};
#endif

extern zend_class_entry *swoole_http_server_ce;
extern zend_class_entry *swoole_http_request_ce;
extern zend_class_entry *swoole_http_response_ce;

extern swString *swoole_http_buffer;
extern swString *swoole_http_form_data_buffer;
#ifdef SW_HAVE_COMPRESSION
extern swString *swoole_zlib_buffer;
#endif

http_context* swoole_http_context_new(int fd);
http_context* php_swoole_http_request_get_and_check_context(zval *zobject);
http_context* php_swoole_http_response_get_and_check_context(zval *zobject);
void swoole_http_context_free(http_context *ctx);
void swoole_http_context_copy(http_context *src, http_context *dst);

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

http_context * php_swoole_http_request_get_context(zval *zobject);
void php_swoole_http_request_set_context(zval *zobject, http_context *context);
http_context * php_swoole_http_response_get_context(zval *zobject);
void php_swoole_http_response_set_context(zval *zobject, http_context *context);
size_t swoole_http_requset_parse(http_context *ctx, const char *data, size_t length);

bool swoole_http_response_set_header(http_context *ctx, const char *k, size_t klen, const char *v, size_t vlen, bool ucwords);
void swoole_http_response_end(http_context *ctx, zval *zdata, zval *return_value);

#ifdef SW_HAVE_COMPRESSION
int swoole_http_response_compress(swString *body, int method, int level);
void swoole_http_get_compression_method(http_context *ctx, const char *accept_encoding, size_t length);
const char* swoole_http_get_content_encoding(http_context *ctx);
#endif

#ifdef SW_HAVE_ZLIB
voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size);
void php_zlib_free(voidpf opaque, voidpf address);
#endif

#ifdef SW_HAVE_BROTLI
void* php_brotli_alloc(void* opaque, size_t size);
void php_brotli_free(void* opaque, void* address);
#endif

#ifdef SW_USE_HTTP2
int swoole_http2_server_parse(http2_session *client, const char *buf);
bool swoole_http2_server_sendfile(http_context *ctx, const char* file, struct stat *file_stat);
void swoole_http2_server_session_free(swConnection *conn);
void swoole_http2_response_end(http_context *ctx, zval *zdata, zval *return_value);
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
        if (sw_likely(index < size || nvs[index].name == nullptr))
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
            php_swoole_fatal_error(E_WARNING, "unexpect http2 header [%.*s] (duplicated or overflow)", (int) name_len, name);
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
            if (sw_likely(nvs[i].name/* && nvs[i].value */))
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
