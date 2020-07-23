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

#ifdef SW_USE_HTTP2

#include "static_handler.h"
#include "http2.h"

#include "main/php_variables.h"

#include <vector>

extern swString *swoole_http_buffer;

using namespace swoole;
using std::string;
using swoole::coroutine::System;
using swoole::http::StaticHandler;
using Http2Stream = swoole::http2::Stream;
using Http2Session = swoole::http2::Session;

static std::unordered_map<int, Http2Session *> http2_sessions;

static bool swoole_http2_server_respond(http_context *ctx, swString *body);

Http2Stream::Stream(Http2Session *client, uint32_t _id) {
    ctx = swoole_http_context_new(client->fd);
    swoole_http_context_copy(client->default_ctx, ctx);
    ctx->http2 = true;
    ctx->stream = this;
    ctx->keepalive = true;
    id = _id;
    send_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    recv_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
}

Http2Stream::~Stream() {
    ctx->stream = nullptr;
    ctx->end = true;
    swoole_http_context_free(ctx);
}

void Http2Stream::reset(uint32_t error_code) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE];
    swTraceLog(SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, error_code=%u", "RST_STREAM", id, error_code);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(error_code);
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_RST_STREAM, SW_HTTP2_RST_STREAM_SIZE, 0, id);
    ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE);
}

Http2Session::Session(int _fd) {
    fd = _fd;
    header_table_size = SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE;
    send_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    recv_window = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    max_concurrent_streams = SW_HTTP2_MAX_MAX_CONCURRENT_STREAMS;
    max_frame_size = SW_HTTP2_MAX_MAX_FRAME_SIZE;

    http2_sessions[_fd] = this;
}

Http2Session::~Session() {
    for (auto iter = streams.begin(); iter != streams.end(); iter++) {
        delete iter->second;
    }
    if (inflater) {
        nghttp2_hd_inflate_del(inflater);
    }
    if (deflater) {
        nghttp2_hd_deflate_del(deflater);
    }
    if (default_ctx) {
        efree(default_ctx);
    }
    http2_sessions.erase(fd);
}

static void http2_server_send_window_update(http_context *ctx, uint32_t stream_id, uint32_t size) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE];
    swTraceLog(SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, size=%u", "WINDOW_UPDATE", stream_id, size);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(size);
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_WINDOW_UPDATE, SW_HTTP2_WINDOW_UPDATE_SIZE, 0, stream_id);
    ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE);
}

static ssize_t http2_build_trailer(http_context *ctx, uchar *buffer) {
    zval *ztrailer =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    uint32_t size = php_swoole_array_length_safe(ztrailer);

    if (size > 0) {
        http2::headers trailer(size);
        zend_string *key;
        zval *zvalue;

        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(ztrailer), key, zvalue) {
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            zend::String str_value(zvalue);
            trailer.add(ZSTR_VAL(key), ZSTR_LEN(key), str_value.val(), str_value.len());
        }
        ZEND_HASH_FOREACH_END();

        ssize_t rv;
        size_t buflen;
        Http2Session *client = http2_sessions[ctx->fd];
        nghttp2_hd_deflater *deflater = client->deflater;

        if (!deflater) {
            int ret = nghttp2_hd_deflate_new2(&deflater, SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE, php_nghttp2_mem());
            if (ret != 0) {
                swWarn("nghttp2_hd_deflate_new2() failed with error: %s", nghttp2_strerror(ret));
                return -1;
            }
            client->deflater = deflater;
        }

        buflen = nghttp2_hd_deflate_bound(deflater, trailer.get(), trailer.len());
        /*
        if (buflen > SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE)
        {
            php_swoole_error(E_WARNING, "header cannot bigger than remote max_header_list_size %u",
        SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE); return -1;
        }
        */
        rv = nghttp2_hd_deflate_hd(deflater, (uchar *) buffer, buflen, trailer.get(), trailer.len());
        if (rv < 0) {
            swWarn("nghttp2_hd_deflate_hd() failed with error: %s", nghttp2_strerror((int) rv));
            return -1;
        }
        return rv;
    }
    return 0;
}

static bool swoole_http2_is_static_file(swServer *serv, http_context *ctx) {
    zval *zserver = ctx->request.zserver;
    zval *zrequest_uri = zend_hash_str_find(Z_ARR_P(zserver), ZEND_STRL("request_uri"));
    if (zrequest_uri && Z_TYPE_P(zrequest_uri) == IS_STRING) {
        StaticHandler handler(serv, Z_STRVAL_P(zrequest_uri), Z_STRLEN_P(zrequest_uri));
        if (!handler.hit()) {
            return false;
        }

        if (handler.status_code == SW_HTTP_NOT_FOUND) {
            swString null_body = {};

            ctx->response.status = SW_HTTP_NOT_FOUND;
            swoole_http2_server_respond(ctx, &null_body);
            return true;
        }

        auto date_str = handler.get_date();
        auto date_str_last_modified = handler.get_date_last_modified();

        zval *zheader = ctx->request.zserver;
        swoole_http_response_set_header(ctx, ZEND_STRL("Last-Modified"), date_str.c_str(), date_str.length(), 0);

        zval *zdate_if_modified_since = zend_hash_str_find(Z_ARR_P(zheader), ZEND_STRL("if-modified-since"));
        if (zdate_if_modified_since) {
            string date_if_modified_since(Z_STRVAL_P(zdate_if_modified_since), Z_STRLEN_P(zdate_if_modified_since));
            if (!date_if_modified_since.empty() && handler.is_modified(date_if_modified_since)) {
                ctx->response.status = SW_HTTP_NOT_MODIFIED;
                return true;
            }
        }

        zend::String _filename(handler.get_filename_std_string());
        zval zfilename;
        ZVAL_STR(&zfilename, _filename.get());
        zval retval; /* do not care the retval (the connection will be closed if failed) */
        sw_zend_call_method_with_1_params(
            ctx->response.zobject, swoole_http_response_ce, nullptr, "sendfile", &retval, &zfilename);

        return true;
    }

    return false;
}

static void swoole_http2_onRequest(Http2Session *client, Http2Stream *stream) {
    http_context *ctx = stream->ctx;
    zval *zserver = ctx->request.zserver;
    swServer *serv = (swServer *) ctx->private_data;

    swConnection *conn = serv->get_connection_by_session_id(ctx->fd);
    int server_fd = conn->server_fd;
    swConnection *serv_sock = serv->get_connection(server_fd);

    ctx->request.version = SW_HTTP_OK;

    if (serv->enable_static_handler && swoole_http2_is_static_file(serv, ctx)) {
        zval_ptr_dtor(ctx->request.zobject);
        zval_ptr_dtor(ctx->response.zobject);
        return;
    }

    add_assoc_long(zserver, "request_time", time(nullptr));
    add_assoc_double(zserver, "request_time_float", swoole_microtime());
    if (serv_sock) {
        add_assoc_long(zserver, "server_port", swSocket_get_port(serv_sock->socket_type, &serv_sock->info));
    }
    add_assoc_long(zserver, "remote_port", swSocket_get_port(conn->socket_type, &conn->info));
    add_assoc_string(zserver, "remote_addr", (char *) swSocket_get_ip(conn->socket_type, &conn->info));
    add_assoc_long(zserver, "master_time", conn->last_time);
    add_assoc_string(zserver, "server_protocol", (char *) "HTTP/2");

    zend_fcall_info_cache *fci_cache = php_swoole_server_get_fci_cache(serv, server_fd, SW_SERVER_CB_onRequest);
    zval args[2] = {*ctx->request.zobject, *ctx->response.zobject};
    if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, SwooleG.enable_coroutine))) {
        stream->reset(SW_HTTP2_ERROR_INTERNAL_ERROR);
        php_swoole_error(E_WARNING, "%s->onRequest[v2] handler error", ZSTR_VAL(swoole_http_server_ce->name));
    }

    zval_ptr_dtor(&args[0]);
    zval_ptr_dtor(&args[1]);
}

static ssize_t http2_build_header(http_context *ctx, uchar *buffer, size_t body_length) {
    zval *zheader =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_HEADER), 0);
    zval *zcookie =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIE), 0);
    http2::headers headers(8 + php_swoole_array_length_safe(zheader) + php_swoole_array_length_safe(zcookie));
    char *date_str = nullptr;
    char intbuf[2][16];
    int ret;

    assert(ctx->send_header == 0);

    // status code
    if (ctx->response.status == 0) {
        ctx->response.status = SW_HTTP_OK;
    }
    ret = swoole_itoa(intbuf[0], ctx->response.status);
    headers.add(ZEND_STRL(":status"), intbuf[0], ret);

    // headers
    if (ZVAL_IS_ARRAY(zheader)) {
        uint32_t header_flag = 0x0;
        zend_string *key;
        zval *zvalue;

        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zheader), key, zvalue) {
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            zend::String str_value(zvalue);
            char *c_key = ZSTR_VAL(key);
            size_t c_keylen = ZSTR_LEN(key);
            if (SW_STREQ(c_key, c_keylen, "server")) {
                header_flag |= HTTP_HEADER_SERVER;
            } else if (SW_STREQ(c_key, c_keylen, "content-length")) {
                continue;  // ignore
            } else if (SW_STREQ(c_key, c_keylen, "date")) {
                header_flag |= HTTP_HEADER_DATE;
            } else if (SW_STREQ(c_key, c_keylen, "content-type")) {
                header_flag |= HTTP_HEADER_CONTENT_TYPE;
            }
            headers.add(c_key, c_keylen, str_value.val(), str_value.len());
        }
        ZEND_HASH_FOREACH_END();

        if (!(header_flag & HTTP_HEADER_SERVER)) {
            headers.add(ZEND_STRL("server"), ZEND_STRL(SW_HTTP_SERVER_SOFTWARE));
        }
        if (!(header_flag & HTTP_HEADER_DATE)) {
            date_str = php_swoole_format_date((char *) ZEND_STRL(SW_HTTP_DATE_FORMAT), time(nullptr), 0);
            headers.add(ZEND_STRL("date"), date_str, strlen(date_str));
        }
        if (!(header_flag & HTTP_HEADER_CONTENT_TYPE)) {
            headers.add(ZEND_STRL("content-type"), ZEND_STRL("text/html"));
        }
    } else {
        headers.add(ZEND_STRL("server"), ZEND_STRL(SW_HTTP_SERVER_SOFTWARE));
        headers.add(ZEND_STRL("content-type"), ZEND_STRL("text/html"));
        date_str = php_swoole_format_date((char *) ZEND_STRL(SW_HTTP_DATE_FORMAT), time(nullptr), 0);
        headers.add(ZEND_STRL("date"), date_str, strlen(date_str));
    }
    if (date_str) {
        efree(date_str);
    }

    // cookies
    if (ZVAL_IS_ARRAY(zcookie)) {
        zval *zvalue;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(zcookie), zvalue) {
            if (Z_TYPE_P(zvalue) != IS_STRING) {
                continue;
            }
            headers.add(ZEND_STRL("set-cookie"), Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue));
        }
        SW_HASHTABLE_FOREACH_END();
    }

    // content encoding
#ifdef SW_HAVE_COMPRESSION
    if (ctx->accept_compression) {
        const char *content_encoding = swoole_http_get_content_encoding(ctx);
        headers.add(ZEND_STRL("content-encoding"), (char *) content_encoding, strlen(content_encoding));
    }
#endif

    // content length
#ifdef SW_HAVE_COMPRESSION
    if (ctx->accept_compression) {
        body_length = swoole_zlib_buffer->length;
    }
#endif
    ret = swoole_itoa(intbuf[1], body_length);
    headers.add(ZEND_STRL("content-length"), intbuf[1], ret);

    Http2Session *client = http2_sessions[ctx->fd];
    nghttp2_hd_deflater *deflater = client->deflater;
    if (!deflater) {
        ret = nghttp2_hd_deflate_new2(&deflater, client->header_table_size, php_nghttp2_mem());
        if (ret != 0) {
            swWarn("nghttp2_hd_deflate_new2() failed with error: %s", nghttp2_strerror(ret));
            return -1;
        }
        client->deflater = deflater;
    }

    size_t buflen = nghttp2_hd_deflate_bound(deflater, headers.get(), headers.len());
    /*
    if (buflen > SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE)
    {
        php_swoole_error(E_WARNING, "header cannot bigger than remote max_header_list_size %u",
    SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE); return -1;
    }
    */
    ssize_t rv = nghttp2_hd_deflate_hd(deflater, (uchar *) buffer, buflen, headers.get(), headers.len());
    if (rv < 0) {
        swWarn("nghttp2_hd_deflate_hd() failed with error: %s", nghttp2_strerror((int) rv));
        return -1;
    }

    ctx->send_header = 1;
    return rv;
}

int swoole_http2_server_ping(http_context *ctx) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_NONE, 0);
    return ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE) ? SW_OK : SW_ERR;
}

bool Http2Stream::send_header(size_t body_length, bool end_stream) {
    char header_buffer[SW_BUFFER_SIZE_STD];
    ssize_t bytes = http2_build_header(ctx, (uchar *) header_buffer, body_length);
    if (bytes < 0) {
        return false;
    }

    swString_clear(swoole_http_buffer);

    /**
     +---------------+
     |Pad Length? (8)|
     +-+-------------+-----------------------------------------------+
     |E|                 Stream Dependency? (31)                     |
     +-+-------------+-----------------------------------------------+
     |  Weight? (8)  |
     +-+-------------+-----------------------------------------------+
     |                   Header Block Fragment (*)                 ...
     +---------------------------------------------------------------+
     |                           Padding (*)                       ...
     +---------------------------------------------------------------+
     */
    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];

    if (end_stream && body_length == 0) {
        swHttp2_set_frame_header(
            frame_header, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS | SW_HTTP2_FLAG_END_STREAM, id);
    } else {
        swHttp2_set_frame_header(frame_header, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS, id);
    }

    swString_append_ptr(swoole_http_buffer, frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
    swString_append_ptr(swoole_http_buffer, header_buffer, bytes);

    if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length)) {
        ctx->send_header = 0;
        return false;
    }

    return true;
}

bool Http2Stream::send_body(swString *body, bool end_stream, size_t max_frame_size, off_t offset, size_t length) {
    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];
    char *p = body->str + offset;
    size_t l = length == 0 ? body->length : length;

    int flag = end_stream ? SW_HTTP2_FLAG_END_STREAM : SW_HTTP2_FLAG_NONE;

    while (l > 0) {
        size_t send_n;
        int _send_flag;
        swString_clear(swoole_http_buffer);
        if (l > max_frame_size) {
            send_n = max_frame_size;
            _send_flag = 0;
        } else {
            send_n = l;
            _send_flag = flag;
        }
        swHttp2_set_frame_header(frame_header, SW_HTTP2_TYPE_DATA, send_n, _send_flag, id);
        swString_append_ptr(swoole_http_buffer, frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
        swString_append_ptr(swoole_http_buffer, p, send_n);

        if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length)) {
            return false;
        } else {
            l -= send_n;
            p += send_n;
        }
    }

    return true;
}

bool Http2Stream::send_trailer() {
    char header_buffer[SW_BUFFER_SIZE_STD] = {};
    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];

    swString_clear(swoole_http_buffer);
    ssize_t bytes = http2_build_trailer(ctx, (uchar *) header_buffer);
    if (bytes > 0) {
        swHttp2_set_frame_header(
            frame_header, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS | SW_HTTP2_FLAG_END_STREAM, id);
        swString_append_ptr(swoole_http_buffer, frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
        swString_append_ptr(swoole_http_buffer, header_buffer, bytes);
        if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length)) {
            return false;
        }
    }

    return true;
}

static bool swoole_http2_server_respond(http_context *ctx, swString *body) {
    Http2Session *client = http2_sessions[ctx->fd];
    Http2Stream *stream = ctx->stream;
    swServer *serv = (swServer *) ctx->private_data;

#ifdef SW_HAVE_COMPRESSION
    if (ctx->accept_compression) {
        if (body->length == 0 ||
            swoole_http_response_compress(body->str, body->length, ctx->compression_method, ctx->compression_level) !=
                SW_OK) {
            ctx->accept_compression = 0;
        } else {
            body = swoole_zlib_buffer;
        }
    }
#endif

    zval *ztrailer =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    if (php_swoole_array_length_safe(ztrailer) == 0) {
        ztrailer = nullptr;
    }

    bool end_stream = (ztrailer == nullptr);
    if (!stream->send_header(body->length, end_stream)) {
        return false;
    }

    /* headers has already been sent, retries are no longer allowed (even if send body failed) */
    ctx->end = 1;

    bool error = false;

    while (true) {
        size_t send_len = body->length - body->offset;

        if (send_len == 0) {
            break;
        }

        /**
         * If send_yield is not supported, ignore flow control
         */
        if (!serv->send_yield) {
            if (!stream->send_body(body, end_stream, client->max_frame_size)) {
                error = true;
            }
            break;
        }

        if (stream->send_window == 0) {
            stream->waiting_coroutine = Coroutine::get_current();
            stream->waiting_coroutine->yield();
            stream->waiting_coroutine = nullptr;
            continue;
        } else if (send_len <= stream->send_window) {
            error = !stream->send_body(body, true && end_stream, client->max_frame_size, body->offset, send_len);
            break;
        } else {
            send_len = client->max_frame_size;
            error = !stream->send_body(body, false, client->max_frame_size, body->offset, send_len);
        }
        if (!error) {
            swTraceLog(SW_TRACE_HTTP2, "body: send length=%zu", send_len);

            body->offset += send_len;
            if (send_len > stream->send_window) {
                stream->send_window = 0;
            } else {
                stream->send_window -= send_len;
            }
        }
    }

    if (!error && ztrailer) {
        if (!stream->send_trailer()) {
            error = true;
        }
    }

    if (error) {
        ctx->close(ctx);
    } else {
        client->streams.erase(stream->id);
        delete stream;
    }

    return !error;
}

static bool http2_context_sendfile(http_context *ctx, const char *file, uint32_t l_file, off_t offset, size_t length) {
    Http2Session *client = http2_sessions[ctx->fd];
    Http2Stream *stream = (Http2Stream *) ctx->stream;
    swString *body;

#ifdef SW_HAVE_COMPRESSION
    ctx->accept_compression = 0;
#endif
    if (swoole_coroutine_is_in()) {
        body = System::read_file(file, false);
        if (!body) {
            return false;
        }
        if (!ctx->stream) {
            /* closed */
            return false;
        }
    } else {
        int fd = open(file, O_RDONLY);
        if (fd < 0) {
            return false;
        }
        body = swoole_sync_readfile_eof(fd);
        close(fd);
        if (!body) {
            return false;
        }
    }
    body->length = SW_MIN(length, body->length);

    zval *ztrailer =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    if (php_swoole_array_length_safe(ztrailer) == 0) {
        ztrailer = nullptr;
    }

    const char *mimetype = swoole::mime_type::get(file).c_str();
    swoole_http_response_set_header(ctx, ZEND_STRL("content-type"), mimetype, strlen(mimetype), 0);

    bool end_stream = (ztrailer == nullptr);
    if (!stream->send_header(length, end_stream)) {
        return false;
    }

    /* headers has already been sent, retries are no longer allowed (even if send body failed) */
    ctx->end = 1;

    bool error = false;

    if (body->length > 0) {
        if (!stream->send_body(body, end_stream, client->max_frame_size, offset, length)) {
            error = true;
        } else {
            client->send_window -= length;  // TODO: flow control?
        }
    }

    swString_free(body);

    if (!error && ztrailer) {
        if (!stream->send_trailer()) {
            error = true;
        }
    }

    if (error) {
        ctx->close(ctx);
    } else {
        client->streams.erase(stream->id);
        delete stream;
    }

    return true;
}

static int http2_parse_header(Http2Session *client, http_context *ctx, int flags, const char *in, size_t inlen) {
    nghttp2_hd_inflater *inflater = client->inflater;

    if (!inflater) {
        int ret = nghttp2_hd_inflate_new2(&inflater, php_nghttp2_mem());
        if (ret != 0) {
            swWarn("nghttp2_hd_inflate_new2() failed, Error: %s[%d]", nghttp2_strerror(ret), ret);
            return SW_ERR;
        }
        client->inflater = inflater;
    }

    if (flags & SW_HTTP2_FLAG_PRIORITY) {
        // int stream_deps = ntohl(*(int *) (in));
        // uint8_t weight = in[4];
        in += 5;
        inlen -= 5;
    }

    zval *zheader = ctx->request.zheader;
    zval *zserver = ctx->request.zserver;

    ssize_t rv;
    for (;;) {
        nghttp2_nv nv;
        int inflate_flags = 0;
        size_t proclen;

        rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, (uchar *) in, inlen, 1);
        if (rv < 0) {
            swWarn("inflate failed, Error: %s[%zd]", nghttp2_strerror(rv), rv);
            return SW_ERR;
        }

        proclen = (size_t) rv;

        in += proclen;
        inlen -= proclen;

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            swTraceLog(
                SW_TRACE_HTTP2, "Header: " SW_ECHO_BLUE "[%zu]: %s[%zu]", nv.name, nv.namelen, nv.value, nv.valuelen);

            if (nv.name[0] == ':') {
                if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "method")) {
                    add_assoc_stringl_ex(zserver, ZEND_STRL("request_method"), (char *) nv.value, nv.valuelen);
                } else if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "path")) {
                    char *pathbuf = SwooleTG.buffer_stack->str;
                    char *v_str = strchr((char *) nv.value, '?');
                    zend_string *zstr_path;
                    if (v_str) {
                        v_str++;
                        int k_len = v_str - (char *) nv.value - 1;
                        int v_len = nv.valuelen - k_len - 1;
                        memcpy(pathbuf, nv.value, k_len);
                        pathbuf[k_len] = 0;
                        add_assoc_stringl_ex(zserver, ZEND_STRL("query_string"), v_str, v_len);
                        zstr_path = zend_string_init(pathbuf, k_len, 0);
                        // parse url params
                        sapi_module.treat_data(
                            PARSE_STRING,
                            estrndup(v_str, v_len),  // it will be freed by treat_data
                            swoole_http_init_and_read_property(
                                swoole_http_request_ce, ctx->request.zobject, &ctx->request.zget, ZEND_STRL("get")));
                    } else {
                        zstr_path = zend_string_init((char *) nv.value, nv.valuelen, 0);
                    }
                    ctx->request.path = (char *) estrndup((char *) nv.value, nv.valuelen);
                    ctx->request.path_len = nv.valuelen;
                    add_assoc_str_ex(zserver, ZEND_STRL("request_uri"), zstr_path);
                    // path_info should be decoded
                    zstr_path = zend_string_dup(zstr_path, 0);
                    ZSTR_LEN(zstr_path) = php_url_decode(ZSTR_VAL(zstr_path), ZSTR_LEN(zstr_path));
                    add_assoc_str_ex(zserver, ZEND_STRL("path_info"), zstr_path);
                } else if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "authority")) {
                    add_assoc_stringl_ex(zheader, ZEND_STRL("host"), (char *) nv.value, nv.valuelen);
                }
            } else {
                if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "content-type")) {
                    if (SW_STRCASECT((char *) nv.value, nv.valuelen, "application/x-www-form-urlencoded")) {
                        ctx->request.post_form_urlencoded = 1;
                    } else if (SW_STRCASECT((char *) nv.value, nv.valuelen, "multipart/form-data")) {
                        int boundary_len = nv.valuelen - (sizeof("multipart/form-data; boundary=") - 1);
                        if (boundary_len <= 0) {
                            swWarn("invalid multipart/form-data body fd:%d", ctx->fd);
                            return SW_ERR;
                        }
                        swoole_http_parse_form_data(ctx, (char *) nv.value + nv.valuelen - boundary_len, boundary_len);
                        ctx->parser.data = ctx;
                    }
                } else if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "cookie")) {
                    swoole_http_parse_cookie(
                        swoole_http_init_and_read_property(
                            swoole_http_request_ce, ctx->request.zobject, &ctx->request.zcookie, ZEND_STRL("cookie")),
                        (const char *) nv.value,
                        nv.valuelen);
                    continue;
                }
#ifdef SW_HAVE_COMPRESSION
                else if (ctx->enable_compression && SW_STRCASEEQ((char *) nv.name, nv.namelen, "accept-encoding")) {
                    swoole_http_get_compression_method(ctx, (char *) nv.value, nv.valuelen);
                }
#endif
                add_assoc_stringl_ex(zheader, (char *) nv.name, nv.namelen, (char *) nv.value, nv.valuelen);
            }
        }

        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }

        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
            break;
        }
    }

    return SW_OK;
}

int swoole_http2_server_parse(Http2Session *client, const char *buf) {
    Http2Stream *stream = nullptr;
    int type = buf[3];
    int flags = buf[4];
    uint32_t stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;
    ssize_t length = swHttp2_get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    uint16_t id = 0;
    uint32_t value = 0;

    switch (type) {
    case SW_HTTP2_TYPE_SETTINGS: {
        if (flags & SW_HTTP2_FLAG_ACK) {
            swHttp2FrameTraceLog(recv, "ACK");
            break;
        }

        while (length > 0) {
            id = ntohs(*(uint16_t *) (buf));
            value = ntohl(*(uint32_t *) (buf + sizeof(uint16_t)));
            swHttp2FrameTraceLog(recv, "id=%d, value=%d", id, value);
            switch (id) {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                if (value != client->header_table_size) {
                    client->header_table_size = value;
                    if (client->deflater) {
                        int ret = nghttp2_hd_deflate_change_table_size(client->deflater, value);
                        if (ret != 0) {
                            swWarn("nghttp2_hd_deflate_change_table_size() failed, errno=%s, errmsg=%s",
                                   ret,
                                   nghttp2_strerror(ret));
                            return SW_ERROR;
                        }
                    }
                }
                swTraceLog(SW_TRACE_HTTP2, "setting: header_table_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                client->max_concurrent_streams = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_concurrent_streams=%u", value);
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                client->send_window = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: init_send_window=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                client->max_frame_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_frame_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                // client->max_header_list_size = value; // useless now
                swTraceLog(SW_TRACE_HTTP2, "setting: max_header_list_size=%u", value);
                break;
            default:
                // disable warning and ignore it because some websites are not following http2 protocol totally
                // swWarn("unknown option[%d]: %d", id, value);
                break;
            }
            buf += sizeof(id) + sizeof(value);
            length -= sizeof(id) + sizeof(value);
        }
        break;
    }
    case SW_HTTP2_TYPE_HEADERS: {
        stream = client->streams[stream_id];
        swHttp2FrameTraceLog(recv, "%s", (stream ? "exist stream" : "new stream"));
        http_context *ctx;
        if (!stream) {
            stream = new Http2Stream(client, stream_id);
            if (sw_unlikely(!stream->ctx)) {
                swoole_error_log(
                    SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_NO_HEADER, "http2 create stream#%d context error", stream_id);
                return SW_ERR;
            }
            ctx = stream->ctx;
            client->streams[stream_id] = stream;
            zend_update_property_long(swoole_http_request_ce, ctx->request.zobject, ZEND_STRL("streamId"), stream_id);
        } else {
            ctx = stream->ctx;
        }
        if (http2_parse_header(client, ctx, flags, buf, length) < 0) {
            return SW_ERR;
        }

        if (flags & SW_HTTP2_FLAG_END_STREAM) {
            client->handle(client, stream);
        } else {
            // need continue frame
        }
        break;
    }
    case SW_HTTP2_TYPE_DATA: {
        swHttp2FrameTraceLog(recv, "data");
        auto stream_iterator = client->streams.find(stream_id);
        if (stream_iterator == client->streams.end()) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_NOT_FOUND, "http2 stream#%d not found", stream_id);
            return SW_ERR;
        }
        stream = stream_iterator->second;
        http_context *ctx = stream->ctx;

        zend_update_property_long(swoole_http_request_ce, ctx->request.zobject, ZEND_STRL("streamId"), stream_id);

        swString *buffer = ctx->request.h2_data_buffer;
        if (!buffer) {
            buffer = swString_new(SW_HTTP2_DATA_BUFFER_SIZE);
            ctx->request.h2_data_buffer = buffer;
        }
        swString_append_ptr(buffer, buf, length);

        // flow control
        client->recv_window -= length;
        stream->recv_window -= length;
        if (length > 0) {
            if (client->recv_window < (SW_HTTP2_MAX_WINDOW_SIZE / 4)) {
                http2_server_send_window_update(ctx, 0, SW_HTTP2_MAX_WINDOW_SIZE - client->recv_window);
                client->recv_window = SW_HTTP2_MAX_WINDOW_SIZE;
            }
            if (stream->recv_window < (SW_HTTP2_MAX_WINDOW_SIZE / 4)) {
                http2_server_send_window_update(ctx, stream_id, SW_HTTP2_MAX_WINDOW_SIZE - stream->recv_window);
                stream->recv_window = SW_HTTP2_MAX_WINDOW_SIZE;
            }
        }

        if (flags & SW_HTTP2_FLAG_END_STREAM) {
            if (ctx->parse_body && ctx->request.post_form_urlencoded) {
                sapi_module.treat_data(
                    PARSE_STRING,
                    estrndup(buffer->str, buffer->length),  // it will be freed by treat_data
                    swoole_http_init_and_read_property(
                        swoole_http_request_ce, ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post")));
            } else if (ctx->mt_parser != nullptr) {
                multipart_parser *multipart_parser = ctx->mt_parser;
                size_t n = multipart_parser_execute(multipart_parser, buffer->str, buffer->length);
                if (n != (size_t) length) {
                    swoole_error_log(
                        SW_LOG_WARNING, SW_ERROR_SERVER_INVALID_REQUEST, "parse multipart body failed, n=%zu", n);
                }
            }
            client->handle(client, stream);
        }
        break;
    }
    case SW_HTTP2_TYPE_PING: {
        swHttp2FrameTraceLog(recv, "ping");
        if (!(flags & SW_HTTP2_FLAG_ACK)) {
            char ping_frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];
            swHttp2_set_frame_header(
                ping_frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_ACK, stream_id);
            memcpy(ping_frame + SW_HTTP2_FRAME_HEADER_SIZE, buf, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
            client->default_ctx->send(
                client->default_ctx, ping_frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
        }
        break;
    }
    case SW_HTTP2_TYPE_WINDOW_UPDATE: {
        value = ntohl(*(uint32_t *) buf);
        if (stream_id == 0) {
            client->send_window += value;
        } else if (client->streams.find(stream_id) != client->streams.end()) {
            swServer *serv;

            stream = client->streams[stream_id];
            serv = (swServer *) stream->ctx->private_data;

            stream->send_window += value;
            if (serv->send_yield && stream->waiting_coroutine) {
                stream->waiting_coroutine->resume();
            }
        }
        swHttp2FrameTraceLog(recv, "window_size_increment=%d", value);
        break;
    }
    case SW_HTTP2_TYPE_RST_STREAM: {
        value = ntohl(*(int *) (buf));
        swHttp2FrameTraceLog(recv, "error_code=%d", value);
        if (client->streams.find(stream_id) != client->streams.end()) {
            // TODO: i onRequest and use request->recv
            // stream exist
            stream = client->streams[stream_id];
            client->streams.erase(stream_id);
            delete stream;
        }
        break;
    }
    case SW_HTTP2_TYPE_GOAWAY: {
        uint32_t server_last_stream_id = ntohl(*(uint32_t *) (buf));
        buf += 4;
        value = ntohl(*(uint32_t *) (buf));
        buf += 4;
        swHttp2FrameTraceLog(recv,
                             "last_stream_id=%d, error_code=%d, opaque_data=[%.*s]",
                             server_last_stream_id,
                             value,
                             (int) (length - SW_HTTP2_GOAWAY_SIZE),
                             buf);
        // TODO: onRequest
        (void) server_last_stream_id;

        break;
    }
    default: {
        swHttp2FrameTraceLog(recv, "");
    }
    }
    return SW_OK;
}

/**
 * Http2
 */
int swoole_http2_server_onFrame(swServer *serv, swConnection *conn, swRecvData *req) {
    int session_id = req->info.fd;
    Http2Session *client = http2_sessions[session_id];
    if (client == nullptr) {
        client = new Http2Session(session_id);
    }

    client->handle = swoole_http2_onRequest;
    if (!client->default_ctx) {
        client->default_ctx = (http_context *) ecalloc(1, sizeof(http_context));
        swoole_http_server_init_context(serv, client->default_ctx);
        client->default_ctx->fd = session_id;
        client->default_ctx->http2 = true;
        client->default_ctx->stream = (Http2Stream *) -1;
        client->default_ctx->keepalive = true;
        client->default_ctx->sendfile = http2_context_sendfile;
    }

    zval zdata;
    php_swoole_get_recv_data(serv, &zdata, req);
    swoole_http2_server_parse(client, Z_STRVAL(zdata));
    zval_ptr_dtor(&zdata);

    return SW_OK;
}

void swoole_http2_server_session_free(swConnection *conn) {
    auto session_iterator = http2_sessions.find(conn->session_id);
    if (session_iterator == http2_sessions.end()) {
        return;
    }
    Http2Session *client = session_iterator->second;
    delete client;
}

void swoole_http2_response_end(http_context *ctx, zval *zdata, zval *return_value) {
    swString http_body = {};
    if (zdata) {
        http_body.length = php_swoole_get_send_data(zdata, &http_body.str);
    } else {
        http_body.length = 0;
        http_body.str = nullptr;
    }

    RETURN_BOOL(swoole_http2_server_respond(ctx, &http_body));
}

#endif
