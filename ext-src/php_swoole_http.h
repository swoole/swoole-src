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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#pragma once

#include "swoole_http.h"
#include "swoole_http2.h"
#include "thirdparty/swoole_http_parser.h"
#include "thirdparty/multipart_parser.h"

#include <unordered_map>
#include <unordered_set>

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#define SW_ZLIB_ENCODING_RAW -0xf
#define SW_ZLIB_ENCODING_GZIP 0x1f
#define SW_ZLIB_ENCODING_DEFLATE 0x0f
#define SW_ZLIB_ENCODING_ANY 0x2f
#endif

#include <nghttp2/nghttp2.h>

enum swHttpHeaderFlag {
    HTTP_HEADER_SERVER = 1u << 1,
    HTTP_HEADER_CONNECTION = 1u << 2,
    HTTP_HEADER_CONTENT_LENGTH = 1u << 3,
    HTTP_HEADER_DATE = 1u << 4,
    HTTP_HEADER_CONTENT_TYPE = 1u << 5,
    HTTP_HEADER_TRANSFER_ENCODING = 1u << 6,
    HTTP_HEADER_ACCEPT_ENCODING = 1u << 7,
    HTTP_HEADER_CONTENT_ENCODING = 1u << 8,
};

enum swHttpCompressMethod {
    HTTP_COMPRESS_NONE,
    HTTP_COMPRESS_GZIP,
    HTTP_COMPRESS_DEFLATE,
    HTTP_COMPRESS_BR,
};

namespace swoole {
class Server;
class Coroutine;
namespace http2 {
class Stream;
class Session;
}  // namespace http2

namespace http {

struct Request {
    int version;
    char *path;
    uint32_t path_len;
    const char *ext;
    uint32_t ext_len;
    uint8_t post_form_urlencoded;

    zval zdata;
    const char *body_at;
    size_t body_length;
    String *chunked_body;
    String *h2_data_buffer;

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

struct Response {
    enum swoole_http_method method;
    int version;
    int status;
    char *reason;

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

struct Header {
    const char *key = nullptr;
    const char *value = nullptr;
    Header *next = nullptr;
    size_t length = 0;
};

struct Status {
    const char *protocol = nullptr;
    const char *status = nullptr;
    const char *reason = nullptr;
    Header *next = nullptr;
    size_t length = 0;
};

struct ByteBuffer {
    Status *start = nullptr;
    Header *current = nullptr;
    size_t total = 0;

    inline void add_status(int status, const char *reason) {
        char buf[16];
        int length = swoole_itoa(buf, status);
        buf[length] = '\0';
        add_status(buf, reason);
    }

    inline void add_status(const char *status, const char *reason) {
        start = (Status *) emalloc(sizeof(Status));
        start->protocol = "HTTP/1.1 ";
        start->status = status;
        start->reason = reason;
        start->next = nullptr;

        // calculate http status line length
        if (!reason) {
            start->length = strlen(start->protocol) + strlen(status) + SW_CRLF_LEN;
        } else {
            start->length = strlen(start->protocol) + strlen(status) + strlen(status) + SW_CRLF_LEN + 1;
        }
    }

    inline void add_header(const char *key, size_t key_length, const char *value, size_t value_length) {
        Header *header = (Header *) emalloc(sizeof(Header));
        header->key = key;
        header->value = value;
        header->next = nullptr;
        // calculate http response header length, 2 => strlen(": ")
        header->length = key_length + value_length + SW_CRLF_LEN + 2;

        if (current) {
            current->next = header;
        } else {
            start->next = header;
        }
        current = header;
    }

    inline size_t get_protocol_length(size_t length = 0) {
        // calculate http protocol length
        total = length + start->length + SW_CRLF_LEN;
        Header *header = start->next;

        while (header) {
            total += header->length;
            header = header->next;
        }

        return total;
    }

    inline void write_protocol(String *http_buffer, const char *data, size_t length) {
        http_buffer->append(start->protocol, strlen(start->protocol));
        http_buffer->append(start->status, strlen(start->status));
        if (start->reason) {
            http_buffer->append(" ", 1);
            http_buffer->append(start->reason, strlen(start->reason));
        }
        http_buffer->append(SW_CRLF, SW_CRLF_LEN);

        size_t key_length = 0;
        size_t value_length = 0;
        Header *header = start->next;
        while (header) {
            key_length = strlen(header->key);
            value_length = strlen(header->value);

            if (SW_STRCASEEQ(header->key, key_length, "Content-Type")) {
                if (SW_STRCASEEQ(header->value, value_length, SW_HTTP_TEXT_PLAIN)) {
                    http_buffer->append(ZEND_STRL("Content-Type: " SW_HTTP_TEXT_PLAIN "\r\n"));
                    header = header->next;
                    continue;
                }

                if (SW_STRCASEEQ(header->value, value_length, SW_HTTP_DEFAULT_CONTENT_TYPE)) {
                    http_buffer->append(ZEND_STRL("Content-Type: " SW_HTTP_DEFAULT_CONTENT_TYPE "\r\n"));
                    header = header->next;
                    continue;
                }

                if (SW_STRCASEEQ(header->value, value_length, SW_HTTP_APPLICATION_JSON)) {
                    http_buffer->append(ZEND_STRL("Content-Type: " SW_HTTP_APPLICATION_JSON "\r\n"));
                    header = header->next;
                    continue;
                }
            }

            if (SW_STRCASEEQ(header->key, key_length, "Server") &&
                SW_STRCASEEQ(header->value, value_length, SW_HTTP_SERVER_SOFTWARE)) {
                http_buffer->append(ZEND_STRL("Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"));
                header = header->next;
                continue;
            }

            if (SW_STRCASEEQ(header->key, key_length, "Transfer-Encoding") &&
                SW_STRCASEEQ(header->value, value_length, "chunked")) {
                http_buffer->append(ZEND_STRL("Transfer-Encoding: chunked\r\n"));
                header = header->next;
                continue;
            }

            if (SW_STRCASEEQ(header->key, key_length, "Connection")) {
                if (SW_STRCASEEQ(header->value, value_length, "keep-alive")) {
                    http_buffer->append(ZEND_STRL("Connection: keep-alive\r\n"));
                } else {
                    http_buffer->append(ZEND_STRL("Connection: close\r\n"));
                }
                header = header->next;
                continue;
            }

            http_buffer->append(header->key, key_length);
            http_buffer->append(ZEND_STRL(": "));
            http_buffer->append(header->value, value_length);
            http_buffer->append(SW_CRLF, SW_CRLF_LEN);
            header = header->next;
        }

        http_buffer->append(SW_CRLF, SW_CRLF_LEN);

        if (data) {
            http_buffer->append(data, length);
        }

        assert(http_buffer->length == total);
    }

    ~ByteBuffer() {
        Header *header = nullptr;
        while (start->next) {
            header = start->next;
            start->next = header->next;
            efree(header);
        }

        efree(start);
    }
};

struct Context {
    SessionId fd;
    uchar completed : 1;
    uchar end_ : 1;
    uchar send_header_ : 1;
#ifdef SW_HAVE_COMPRESSION
    uchar enable_compression : 1;
    uchar accept_compression : 1;
    uchar content_compressed : 1;
#endif
    uchar send_chunked : 1;
    uchar recv_chunked : 1;
    uchar send_trailer_ : 1;
    uchar keepalive : 1;
    uchar websocket : 1;
#ifdef SW_HAVE_ZLIB
    uchar websocket_compression : 1;
#endif
    uchar upgrade : 1;
    uchar detached : 1;
    uchar parse_cookie : 1;
    uchar parse_body : 1;
    uchar parse_files : 1;
    uchar co_socket : 1;
    uchar http2 : 1;

    http2::Stream *stream;
    String *write_buffer;

#ifdef SW_HAVE_COMPRESSION
    int8_t compression_level;
    int8_t compression_method;
    uint32_t compression_min_length;
    std::shared_ptr<std::unordered_set<std::string>> compression_types;
    std::shared_ptr<String> zlib_buffer;
#endif

    Request request;
    Response response;

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
    String *form_data_buffer;

    std::string upload_tmp_dir;

    void *private_data;
    void *private_data_2;
    bool (*send)(Context *ctx, const char *data, size_t length);
    bool (*sendfile)(Context *ctx, const char *file, uint32_t l_file, off_t offset, size_t length);
    bool (*close)(Context *ctx);
    bool (*onBeforeRequest)(Context *ctx);
    void (*onAfterResponse)(Context *ctx);

    void init(Server *server);
    void init(coroutine::Socket *socket);
    void bind(Server *server);
    void bind(coroutine::Socket *socket);
    void copy(Context *ctx);
    bool init_multipart_parser(const char *boundary_str, int boundary_len);
    bool get_multipart_boundary(
        const char *at, size_t length, size_t offset, char **out_boundary_str, int *out_boundary_len);
    size_t parse(const char *data, size_t length);
    bool parse_multipart_data(const char *at, size_t length);
    bool set_header(const char *, size_t, zval *, bool);
    bool set_header(const char *, size_t, const char *, size_t, bool);
    void end(zval *zdata, zval *return_value);
    bool send_file(const char *file, uint32_t l_file, off_t offset, size_t length);
    void send_trailer(zval *return_value);
    String *get_write_buffer(size_t capacity = SW_BUFFER_SIZE_STD);
    void build_header(const char *body, size_t length);
    ssize_t build_trailer(String *http_buffer);

    size_t get_content_length() {
        return parser.content_length;
    }

#ifdef SW_HAVE_COMPRESSION
    void set_compression_method(const char *accept_encoding, size_t length);
    const char *get_content_encoding();
    bool compress(const char *data, size_t length);
#endif

    void http2_end(zval *zdata, zval *return_value);
    bool http2_send_file(const char *file, uint32_t l_file, off_t offset, size_t length);

    bool is_available();
    void free();
};
}  // namespace http

namespace http2 {
class Stream {
  public:
    http::Context *ctx;
    // uint8_t priority; // useless now
    uint32_t id;
    // flow control
    uint32_t remote_window_size;
    uint32_t local_window_size;
    Coroutine *waiting_coroutine = nullptr;

    Stream(Session *client, uint32_t _id);
    ~Stream();

    bool send_header(const String *body, bool end_stream);
    bool send_body(const String *body, bool end_stream, size_t max_frame_size, off_t offset = 0, size_t length = 0);
    bool send_trailer();

    void reset(uint32_t error_code);
};

class Session {
  public:
    int fd;
    std::unordered_map<uint32_t, Stream *> streams;

    nghttp2_hd_inflater *inflater = nullptr;
    nghttp2_hd_deflater *deflater = nullptr;

    http2::Settings local_settings = {};
    http2::Settings remote_settings = {};

    // flow control
    uint32_t remote_window_size;
    uint32_t local_window_size;

    uint32_t last_stream_id;
    bool shutting_down;
    bool is_coro;

    http::Context *default_ctx = nullptr;
    void *private_data = nullptr;

    void (*handle)(Session *, Stream *) = nullptr;

    Session(SessionId _fd);
    ~Session();
};
}  // namespace http2

}  // namespace swoole

extern zend_class_entry *swoole_http_server_ce;
extern zend_class_entry *swoole_http_request_ce;
extern zend_class_entry *swoole_http_response_ce;

swoole::http::Context *swoole_http_context_new(swoole::SessionId fd);
swoole::http::Context *php_swoole_http_request_get_and_check_context(zval *zobject);
swoole::http::Context *php_swoole_http_response_get_and_check_context(zval *zobject);

/**
 *  These class properties cannot be modified by the user before assignment, such as Swoole\\Http\\Request.
 *  So we can use this function to init property.
 */
static sw_inline zval *swoole_http_init_and_read_property(
    zend_class_entry *ce, zval *zobject, zval **zproperty_store_pp, zend_string *name, int size = HT_MIN_SIZE) {
    if (UNEXPECTED(!*zproperty_store_pp)) {
        zval *zv = zend_hash_find(&ce->properties_info, name);
        zend_property_info *property_info = (zend_property_info *) Z_PTR_P(zv);
        zval *property = OBJ_PROP(SW_Z8_OBJ_P(zobject), property_info->offset);
        array_init_size(property, size);
        *zproperty_store_pp = (zval *) (zproperty_store_pp + 1);
        **zproperty_store_pp = *property;
    }
    return *zproperty_store_pp;
}

static sw_inline zval *swoole_http_init_and_read_property(
    zend_class_entry *ce, zval *zobject, zval **zproperty_store_pp, const char *name, size_t name_len) {
    if (UNEXPECTED(!*zproperty_store_pp)) {
        // Notice: swoole http server properties can not be unset anymore, so we can read it without checking
        zval rv, *property = zend_read_property(ce, SW_Z8_OBJ_P(zobject), name, name_len, 0, &rv);
        array_init(property);
        *zproperty_store_pp = (zval *) (zproperty_store_pp + 1);
        **zproperty_store_pp = *property;
    }
    return *zproperty_store_pp;
}

static inline bool swoole_http_has_crlf(const char *value, size_t length) {
    /* new line/NUL character safety check */
    for (size_t i = 0; i < length; i++) {
        /* RFC 7230 ch. 3.2.4 deprecates folding support */
        if (value[i] == '\n' || value[i] == '\r') {
            php_swoole_error(E_WARNING, "Header may not contain more than a single header, new line detected");
            return true;
        }
        if (value[i] == '\0') {
            php_swoole_error(E_WARNING, "Header may not contain NUL bytes");
            return true;
        }
    }

    return false;
}

void swoole_http_parse_cookie(zval *array, const char *at, size_t length);
bool swoole_http_token_list_contains_value(const char *at, size_t length, const char *value);

swoole::http::Context *php_swoole_http_request_get_context(zval *zobject);
void php_swoole_http_request_set_context(zval *zobject, swoole::http::Context *context);
swoole::http::Context *php_swoole_http_response_get_context(zval *zobject);
void php_swoole_http_response_set_context(zval *zobject, swoole::http::Context *context);

#ifdef SW_HAVE_ZLIB
voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size);
void php_zlib_free(voidpf opaque, voidpf address);
#endif

#ifdef SW_HAVE_BROTLI
void *php_brotli_alloc(void *opaque, size_t size);
void php_brotli_free(void *opaque, void *address);
#endif

static sw_inline nghttp2_mem *php_nghttp2_mem() {
    static nghttp2_mem mem = {nullptr,
                              [](size_t size, void *mem_user_data) { return emalloc(size); },
                              [](void *ptr, void *mem_user_data) { return efree(ptr); },
                              [](size_t nmemb, size_t size, void *mem_user_data) { return ecalloc(nmemb, size); },
                              [](void *ptr, size_t size, void *mem_user_data) { return erealloc(ptr, size); }};
    return &mem;
}

namespace swoole {
namespace http2 {
//-----------------------------------namespace begin--------------------------------------------
class HeaderSet {
  public:
    HeaderSet(size_t size) : size(size), index(0) {
        nvs = (nghttp2_nv *) ecalloc(size, sizeof(nghttp2_nv));
    }

    inline nghttp2_nv *get() {
        return nvs;
    }

    inline size_t len() {
        return index;
    }

    void reserve_one() {
        index++;
    }

    inline void add(size_t index,
                    const char *name,
                    size_t name_len,
                    const char *value,
                    size_t value_len,
                    const uint8_t flags = NGHTTP2_NV_FLAG_NONE) {
        if (sw_likely(index < size || nvs[index].name == nullptr)) {
            nghttp2_nv *nv = &nvs[index];
            name = zend_str_tolower_dup(name, name_len);  // auto to lower
            nv->name = (uchar *) name;
            nv->namelen = name_len;
            nv->value = (uchar *) emalloc(value_len);
            memcpy(nv->value, value, value_len);
            nv->valuelen = value_len;
            nv->flags = flags | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
            swoole_trace_log(SW_TRACE_HTTP2,
                             "name=(%zu)[" SW_ECHO_LEN_BLUE "], value=(%zu)[" SW_ECHO_LEN_CYAN "]",
                             name_len,
                             (int) name_len,
                             name,
                             value_len,
                             (int) value_len,
                             value);
        } else {
            php_swoole_fatal_error(
                E_WARNING, "unexpect http2 header [%.*s] (duplicated or overflow)", (int) name_len, name);
        }
    }

    inline void add(const char *name,
                    size_t name_len,
                    const char *value,
                    size_t value_len,
                    const uint8_t flags = NGHTTP2_NV_FLAG_NONE) {
        add(index++, name, name_len, value, value_len, flags);
    }

    ~HeaderSet() {
        for (size_t i = 0; i < size; ++i) {
            if (sw_likely(nvs[i].name /* && nvs[i].value */)) {
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
}  // namespace http2
}  // namespace swoole
