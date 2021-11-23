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

#include "php_swoole_http_server.h"

#ifdef SW_USE_HTTP2

#include "swoole_static_handler.h"

#include "main/php_variables.h"

using namespace swoole;
using std::string;
using swoole::coroutine::System;
using swoole::http_server::StaticHandler;

namespace Http2 = swoole::http2;

using HttpContext = swoole::http::Context;
using Http2Stream = Http2::Stream;
using Http2Session = Http2::Session;

static std::unordered_map<SessionId, Http2Session *> http2_sessions;
extern String *swoole_http_buffer;

static bool http2_server_respond(HttpContext *ctx, String *body);

Http2Stream::Stream(Http2Session *client, uint32_t _id) {
    ctx = swoole_http_context_new(client->fd);
    ctx->copy(client->default_ctx);
    ctx->http2 = true;
    ctx->stream = this;
    ctx->keepalive = true;
    id = _id;
    local_window_size = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    remote_window_size = SW_HTTP2_DEFAULT_WINDOW_SIZE;
}

Http2Stream::~Stream() {
    ctx->stream = nullptr;
    ctx->end_ = true;
    ctx->free();
}

void Http2Stream::reset(uint32_t error_code) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE];
    swoole_trace_log(
        SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, error_code=%u", "RST_STREAM", id, error_code);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(error_code);
    http2::set_frame_header(frame, SW_HTTP2_TYPE_RST_STREAM, SW_HTTP2_RST_STREAM_SIZE, 0, id);
    ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE);
}

Http2Session::Session(SessionId _fd) {
    fd = _fd;
    Http2::init_settings(&local_settings);
    // [init]: we must set default value, peer is not always send all the settings
    Http2::init_settings(&remote_settings);
    last_stream_id = 0;
    shutting_down = false;
    is_coro = false;
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
        delete default_ctx;
    }
    http2_sessions.erase(fd);
}

static void http2_server_send_window_update(HttpContext *ctx, uint32_t stream_id, uint32_t size) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE];
    swoole_trace_log(
        SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, size=%u", "WINDOW_UPDATE", stream_id, size);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(size);
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_WINDOW_UPDATE, SW_HTTP2_WINDOW_UPDATE_SIZE, 0, stream_id);
    ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE);
}

static ssize_t http2_server_build_trailer(HttpContext *ctx, uchar *buffer) {
    zval *ztrailer =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    uint32_t size = php_swoole_array_length_safe(ztrailer);

    if (size > 0) {
        Http2::HeaderSet trailer(size);
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
                swoole_warning("nghttp2_hd_deflate_new2() failed with error: %s", nghttp2_strerror(ret));
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
            swoole_warning("nghttp2_hd_deflate_hd() failed with error: %s", nghttp2_strerror((int) rv));
            return -1;
        }
        return rv;
    }
    return 0;
}

static bool http2_server_is_static_file(Server *serv, HttpContext *ctx) {
    zval *zserver = ctx->request.zserver;
    zval *zrequest_uri = zend_hash_str_find(Z_ARR_P(zserver), ZEND_STRL("request_uri"));
    if (zrequest_uri && Z_TYPE_P(zrequest_uri) == IS_STRING) {
        StaticHandler handler(serv, Z_STRVAL_P(zrequest_uri), Z_STRLEN_P(zrequest_uri));
        if (!handler.hit()) {
            return false;
        }

        if (handler.status_code == SW_HTTP_NOT_FOUND) {
            String null_body = {};

            ctx->response.status = SW_HTTP_NOT_FOUND;
            http2_server_respond(ctx, &null_body);
            return true;
        }

        auto date_str = handler.get_date();
        auto date_str_last_modified = handler.get_date_last_modified();

        zval *zheader = ctx->request.zserver;
        ctx->set_header(ZEND_STRL("Last-Modified"), date_str.c_str(), date_str.length(), 0);

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
        ctx->onAfterResponse = nullptr;
        ctx->onBeforeRequest = nullptr;
        sw_zend_call_method_with_1_params(
            ctx->response.zobject, swoole_http_response_ce, nullptr, "sendfile", &retval, &zfilename);

        return true;
    }

    return false;
}

static void http2_server_onRequest(Http2Session *client, Http2Stream *stream) {
    HttpContext *ctx = stream->ctx;
    zval *zserver = ctx->request.zserver;
    Server *serv = (Server *) ctx->private_data;
    zval args[2];
    zend_fcall_info_cache *fci_cache = nullptr;
    Connection *conn = serv->get_connection_by_session_id(ctx->fd);
    int server_fd = conn->server_fd;
    Connection *serv_sock = serv->get_connection(server_fd);

    ctx->request.version = SW_HTTP_VERSION_2;

    if (serv->enable_static_handler && http2_server_is_static_file(serv, ctx)) {
        goto _destroy;
    }

    add_assoc_long(zserver, "request_time", time(nullptr));
    add_assoc_double(zserver, "request_time_float", microtime());
    if (serv_sock) {
        add_assoc_long(zserver, "server_port", serv_sock->info.get_port());
    }
    add_assoc_long(zserver, "remote_port", conn->info.get_port());
    add_assoc_string(zserver, "remote_addr", (char *) conn->info.get_ip());
    add_assoc_long(zserver, "master_time", conn->last_recv_time);
    add_assoc_string(zserver, "server_protocol", (char *) "HTTP/2");

    fci_cache = php_swoole_server_get_fci_cache(serv, server_fd, SW_SERVER_CB_onRequest);
    ctx->private_data_2 = fci_cache;

    if (ctx->onBeforeRequest && !ctx->onBeforeRequest(ctx)) {
        return;
    }

    args[0] = *ctx->request.zobject;
    args[1] = *ctx->response.zobject;
    if (UNEXPECTED(!zend::function::call(fci_cache, 2, args, nullptr, serv->is_enable_coroutine()))) {
        stream->reset(SW_HTTP2_ERROR_INTERNAL_ERROR);
        php_swoole_error(E_WARNING, "%s->onRequest[v2] handler error", ZSTR_VAL(swoole_http_server_ce->name));
    }

_destroy:
    zval_ptr_dtor(ctx->request.zobject);
    zval_ptr_dtor(ctx->response.zobject);
}

static void http2_server_set_date_header(Http2::HeaderSet *headers) {
    static struct {
        time_t time;
        size_t len;
        char buf[64];
    } cache{};

    time_t now = time(nullptr);
    if (now != cache.time) {
        char *date_str = php_swoole_format_date((char *) ZEND_STRL(SW_HTTP_DATE_FORMAT), now, 0);
        cache.len = strlen(date_str);
        memcpy(cache.buf, date_str, cache.len);
        cache.time = now;
        efree(date_str);
    }
    headers->add(ZEND_STRL("date"), cache.buf, cache.len);
}

static ssize_t http2_server_build_header(HttpContext *ctx, uchar *buffer, size_t body_length) {
    zval *zheader =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_HEADER), 0);
    zval *zcookie =
        sw_zend_read_property_ex(swoole_http_response_ce, ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIE), 0);
    Http2::HeaderSet headers(32 + php_swoole_array_length_safe(zheader) + php_swoole_array_length_safe(zcookie));
    char intbuf[2][16];
    int ret;

    assert(ctx->send_header_ == 0);

    // status code
    if (ctx->response.status == 0) {
        ctx->response.status = SW_HTTP_OK;
    }
    ret = swoole_itoa(intbuf[0], ctx->response.status);
    headers.add(ZEND_STRL(":status"), intbuf[0], ret);

    uint32_t header_flags = 0x0;

    // headers
    if (ZVAL_IS_ARRAY(zheader)) {
        const char *key;
        uint32_t keylen;
        zval *zvalue;
        int type;

        auto add_header =
            [](Http2::HeaderSet &headers, const char *key, size_t l_key, zval *value, uint32_t &header_flags) {
                if (ZVAL_IS_NULL(value)) {
                    return;
                }
                zend::String str_value(value);
                str_value.rtrim();
                if (swoole_http_has_crlf(str_value.val(), str_value.len())) {
                    return;
                }
                if (SW_STREQ(key, l_key, "server")) {
                    header_flags |= HTTP_HEADER_SERVER;
                } else if (SW_STREQ(key, l_key, "content-length")) {
                    return;  // ignore
                } else if (SW_STREQ(key, l_key, "date")) {
                    header_flags |= HTTP_HEADER_DATE;
                } else if (SW_STREQ(key, l_key, "content-type")) {
                    header_flags |= HTTP_HEADER_CONTENT_TYPE;
                }
                headers.add(key, l_key, str_value.val(), str_value.len());
            };

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(zheader), key, keylen, type, zvalue) {
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            if (ZVAL_IS_ARRAY(zvalue)) {
                zval *zvalue_2;
                SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(zvalue), zvalue_2) {
                    add_header(headers, key, keylen, zvalue_2, header_flags);
                }
                SW_HASHTABLE_FOREACH_END();
            } else {
                add_header(headers, key, keylen, zvalue, header_flags);
            }
        }
        SW_HASHTABLE_FOREACH_END();
        (void) type;
    }

    if (!(header_flags & HTTP_HEADER_SERVER)) {
        headers.add(ZEND_STRL("server"), ZEND_STRL(SW_HTTP_SERVER_SOFTWARE));
    }
    if (!(header_flags & HTTP_HEADER_DATE)) {
        http2_server_set_date_header(&headers);
    }
    if (!(header_flags & HTTP_HEADER_CONTENT_TYPE)) {
        headers.add(ZEND_STRL("content-type"), ZEND_STRL("text/html"));
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
        const char *content_encoding = ctx->get_content_encoding();
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
        ret = nghttp2_hd_deflate_new2(&deflater, client->local_settings.header_table_size, php_nghttp2_mem());
        if (ret != 0) {
            swoole_warning("nghttp2_hd_deflate_new2() failed with error: %s", nghttp2_strerror(ret));
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
        swoole_warning("nghttp2_hd_deflate_hd() failed with error: %s", nghttp2_strerror((int) rv));
        return -1;
    }

    ctx->send_header_ = 1;
    return rv;
}

int swoole_http2_server_ping(HttpContext *ctx) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_NONE, 0);
    return ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE) ? SW_OK : SW_ERR;
}

int swoole_http2_server_goaway(HttpContext *ctx, zend_long error_code, const char *debug_data, size_t debug_data_len) {
    size_t length = SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + debug_data_len;
    char *frame = (char *) ecalloc(1, length);
    bool ret;
    Http2Session *client = http2_sessions[ctx->fd];
    uint32_t last_stream_id = client->last_stream_id;
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_GOAWAY, SW_HTTP2_GOAWAY_SIZE + debug_data_len, error_code, 0);
    *(uint32_t *) (frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(last_stream_id);
    *(uint32_t *) (frame + SW_HTTP2_FRAME_HEADER_SIZE + 4) = htonl(error_code);
    if (debug_data_len > 0) {
        memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE, debug_data, debug_data_len);
    }
    ret = ctx->send(ctx, frame, length);
    efree(frame);
    client->shutting_down = true;
    return ret;
}

bool Http2Stream::send_header(size_t body_length, bool end_stream) {
    char header_buffer[SW_BUFFER_SIZE_STD];
    ssize_t bytes = http2_server_build_header(ctx, (uchar *) header_buffer, body_length);
    if (bytes < 0) {
        return false;
    }

    swoole_http_buffer->clear();

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
        http2::set_frame_header(
            frame_header, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS | SW_HTTP2_FLAG_END_STREAM, id);
    } else {
        http2::set_frame_header(frame_header, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS, id);
    }

    swoole_http_buffer->append(frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
    swoole_http_buffer->append(header_buffer, bytes);

    if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length)) {
        ctx->send_header_ = 0;
        return false;
    }

    return true;
}

bool Http2Stream::send_body(String *body, bool end_stream, size_t max_frame_size, off_t offset, size_t length) {
    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];
    char *p = body->str + offset;
    size_t l = length == 0 ? body->length : length;

    int flags = end_stream ? SW_HTTP2_FLAG_END_STREAM : SW_HTTP2_FLAG_NONE;

    while (l > 0) {
        size_t send_n;
        int _send_flags;
        if (l > max_frame_size) {
            send_n = max_frame_size;
            _send_flags = 0;
        } else {
            send_n = l;
            _send_flags = flags;
        }
        http2::set_frame_header(frame_header, SW_HTTP2_TYPE_DATA, send_n, _send_flags, id);

        // send twice to reduce memory copy
        if (send_n < SwooleG.pagesize) {
            swoole_http_buffer->clear();
            swoole_http_buffer->append(frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
            swoole_http_buffer->append(p, send_n);
            if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length)) {
                return false;
            }
        } else {
            if (!ctx->send(ctx, frame_header, SW_HTTP2_FRAME_HEADER_SIZE)) {
                return false;
            }
            if (!ctx->send(ctx, p, send_n)) {
                return false;
            }
        }

        swoole_trace_log(
            SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, flags=%d, send_n=%lu", "DATA", id, flags, send_n);

        l -= send_n;
        p += send_n;
    }

    return true;
}

bool Http2Stream::send_trailer() {
    char header_buffer[SW_BUFFER_SIZE_STD] = {};
    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];

    swoole_http_buffer->clear();
    ssize_t bytes = http2_server_build_trailer(ctx, (uchar *) header_buffer);
    if (bytes > 0) {
        http2::set_frame_header(
            frame_header, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS | SW_HTTP2_FLAG_END_STREAM, id);
        swoole_http_buffer->append(frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
        swoole_http_buffer->append(header_buffer, bytes);
        if (!ctx->send(ctx, swoole_http_buffer->str, swoole_http_buffer->length)) {
            return false;
        }
    }

    return true;
}

static bool http2_server_respond(HttpContext *ctx, String *body) {
    Http2Session *client = http2_sessions[ctx->fd];
    Http2Stream *stream = ctx->stream;

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

    // The headers has already been sent, retries are no longer allowed (even if send body failed)
    ctx->end_ = 1;

    bool error = false;

    // If send_yield is not supported, ignore flow control
    if (ctx->co_socket || !((Server *) ctx->private_data)->send_yield || !swoole_coroutine_is_in()) {
        if (body->length > client->remote_settings.window_size) {
            swoole_warning("The data sent exceeded remote_window_size");
        }
        if (!stream->send_body(body, end_stream, client->local_settings.max_frame_size)) {
            error = true;
        }
    } else {
        while (true) {
            size_t send_len = body->length - body->offset;

            if (send_len == 0) {
                break;
            }

            if (stream->remote_window_size == 0) {
                stream->waiting_coroutine = Coroutine::get_current();
                stream->waiting_coroutine->yield();
                stream->waiting_coroutine = nullptr;
                continue;
            }

            bool _end_stream;
            if (send_len > stream->remote_window_size) {
                send_len = stream->remote_window_size;
                _end_stream = false;
            } else {
                _end_stream = true && end_stream;
            }

            error =
                !stream->send_body(body, _end_stream, client->local_settings.max_frame_size, body->offset, send_len);
            if (!error) {
                swoole_trace_log(SW_TRACE_HTTP2,
                                 "body: send length=%zu, stream->remote_window_size=%u",
                                 send_len,
                                 stream->remote_window_size);

                body->offset += send_len;
                if (send_len > stream->remote_window_size) {
                    stream->remote_window_size = 0;
                } else {
                    stream->remote_window_size -= send_len;
                }
            }
        }
    }

    if (!error && ztrailer && !stream->send_trailer()) {
        error = true;
    }

    if (error) {
        ctx->close(ctx);
    } else {
        client->streams.erase(stream->id);
        delete stream;
    }

    if (client->shutting_down && client->streams.size() == 0) {
        ctx->close(ctx);
    }

    return !error;
}

bool HttpContext::http2_send_file(const char *file, uint32_t l_file, off_t offset, size_t length) {
    Http2Session *client = http2_sessions[fd];
    std::shared_ptr<String> body;

#ifdef SW_HAVE_COMPRESSION
    accept_compression = 0;
#endif
    if (swoole_coroutine_is_in()) {
        body = System::read_file(file, false);
        if (!body) {
            return false;
        }
        if (!stream) {
            /* closed */
            return false;
        }
    } else {
        File fp(file, O_RDONLY);
        if (!fp.ready()) {
            return false;
        }
        body = fp.read_content();
        if (body->empty()) {
            return false;
        }
    }
    body->length = SW_MIN(length, body->length);

    zval *ztrailer =
        sw_zend_read_property_ex(swoole_http_response_ce, response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    if (php_swoole_array_length_safe(ztrailer) == 0) {
        ztrailer = nullptr;
    }

    zval *zheader =
        sw_zend_read_and_convert_property_array(swoole_http_response_ce, response.zobject, ZEND_STRL("header"), 0);
    if (!zend_hash_str_exists(Z_ARRVAL_P(zheader), ZEND_STRL("content-type"))) {
        const char *mimetype = swoole::mime_type::get(file).c_str();
        set_header(ZEND_STRL("content-type"), mimetype, strlen(mimetype), 0);
    }

    bool end_stream = (ztrailer == nullptr);
    if (!stream->send_header(length, end_stream)) {
        return false;
    }

    /* headers has already been sent, retries are no longer allowed (even if send body failed) */
    end_ = 1;

    bool error = false;

    if (body->length > 0) {
        if (!stream->send_body(body.get(), end_stream, client->local_settings.max_frame_size, offset, length)) {
            error = true;
        } else {
            client->remote_settings.window_size -= length;  // TODO: flow control?
        }
    }

    if (!error && ztrailer) {
        if (!stream->send_trailer()) {
            error = true;
        }
    }

    if (error) {
        close(this);
    } else {
        client->streams.erase(stream->id);
        delete stream;
    }

    return true;
}

static bool http2_server_context_onBeforeRequest(HttpContext *ctx) {
    Server *serv = (Server *) ctx->private_data;
    if (serv->is_unavailable()) {
        String null_body{};
        ctx->response.status = SW_HTTP_SERVICE_UNAVAILABLE;
        http2_server_respond(ctx, &null_body);
        zval_ptr_dtor(ctx->request.zobject);
        zval_ptr_dtor(ctx->response.zobject);
        return false;
    }
    return swoole_http_server_onBeforeRequest(ctx);
}

static int http2_server_parse_header(Http2Session *client, HttpContext *ctx, int flags, const char *in, size_t inlen) {
    nghttp2_hd_inflater *inflater = client->inflater;

    if (!inflater) {
        int ret = nghttp2_hd_inflate_new2(&inflater, php_nghttp2_mem());
        if (ret != 0) {
            swoole_warning("nghttp2_hd_inflate_new2() failed, Error: %s[%d]", nghttp2_strerror(ret), ret);
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
            swoole_warning("inflate failed, Error: %s[%zd]", nghttp2_strerror(rv), rv);
            return SW_ERR;
        }

        proclen = (size_t) rv;

        in += proclen;
        inlen -= proclen;

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            swoole_trace_log(SW_TRACE_HTTP2,
                             "name=(%zu)[" SW_ECHO_BLUE "], value=(%zu)[" SW_ECHO_CYAN "]",
                             nv.namelen,
                             nv.name,
                             nv.valuelen,
                             nv.value);

            if (nv.name[0] == ':') {
                if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "method")) {
                    add_assoc_stringl_ex(zserver, ZEND_STRL("request_method"), (char *) nv.value, nv.valuelen);
                } else if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "path")) {
                    char *pathbuf = sw_tg_buffer()->str;
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
                            swoole_warning("invalid multipart/form-data body fd:%ld", ctx->fd);
                            return SW_ERR;
                        }
                        ctx->parse_form_data((char *) nv.value + nv.valuelen - boundary_len, boundary_len);
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
                    ctx->set_compression_method((char *) nv.value, nv.valuelen);
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
    int retval = SW_ERR;
    uint32_t stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;

    if (stream_id > client->last_stream_id) {
        client->last_stream_id = stream_id;
    }

    if (client->shutting_down) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_IGNORE, "ignore http2 stream#%d after sending goaway", stream_id);
        return retval;
    }

    ssize_t length = Http2::get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    uint16_t id = 0;
    uint32_t value = 0;

    switch (type) {
    case SW_HTTP2_TYPE_SETTINGS: {
        if (flags & SW_HTTP2_FLAG_ACK) {
            swoole_http2_frame_trace_log(recv, "ACK");
            break;
        }

        while (length > 0) {
            id = ntohs(*(uint16_t *) (buf));
            value = ntohl(*(uint32_t *) (buf + sizeof(uint16_t)));
            swoole_http2_frame_trace_log(recv, "id=%d, value=%d", id, value);
            switch (id) {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                if (value != client->remote_settings.header_table_size) {
                    client->remote_settings.header_table_size = value;
                    if (client->deflater) {
                        int ret = nghttp2_hd_deflate_change_table_size(client->deflater, value);
                        if (ret != 0) {
                            swoole_warning("nghttp2_hd_deflate_change_table_size() failed, errno=%d, errmsg=%s",
                                           ret,
                                           nghttp2_strerror(ret));
                            return SW_ERR;
                        }
                    }
                }
                swoole_trace_log(SW_TRACE_HTTP2, "setting: header_table_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                client->remote_settings.max_concurrent_streams = value;
                swoole_trace_log(SW_TRACE_HTTP2, "setting: max_concurrent_streams=%u", value);
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                client->remote_settings.window_size = value;
                swoole_trace_log(SW_TRACE_HTTP2, "setting: init_window_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                client->remote_settings.max_frame_size = value;
                swoole_trace_log(SW_TRACE_HTTP2, "setting: max_frame_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                client->remote_settings.max_header_list_size = value;  // useless now
                swoole_trace_log(SW_TRACE_HTTP2, "setting: max_header_list_size=%u", value);
                break;
            default:
                // disable warning and ignore it because some websites are not following http2 protocol totally
                // swoole_warning("unknown option[%d]: %d", id, value);
                break;
            }
            buf += sizeof(id) + sizeof(value);
            length -= sizeof(id) + sizeof(value);
        }
        break;
    }
    case SW_HTTP2_TYPE_HEADERS: {
        stream = client->streams[stream_id];
        swoole_http2_frame_trace_log(recv, "%s", (stream ? "exist stream" : "new stream"));
        HttpContext *ctx;
        if (!stream) {
            stream = new Http2Stream(client, stream_id);
            if (sw_unlikely(!stream->ctx)) {
                swoole_error_log(
                    SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_NO_HEADER, "http2 create stream#%d context error", stream_id);
                return SW_ERR;
            }
            ctx = stream->ctx;
            client->streams[stream_id] = stream;
            zend_update_property_long(
                swoole_http_request_ce, SW_Z8_OBJ_P(ctx->request.zobject), ZEND_STRL("streamId"), stream_id);
        } else {
            ctx = stream->ctx;
        }
        if (http2_server_parse_header(client, ctx, flags, buf, length) < 0) {
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
        swoole_http2_frame_trace_log(recv, "data");
        auto stream_iterator = client->streams.find(stream_id);
        if (stream_iterator == client->streams.end()) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_NOT_FOUND, "http2 stream#%d not found", stream_id);
            return SW_ERR;
        }
        stream = stream_iterator->second;
        HttpContext *ctx = stream->ctx;

        zend_update_property_long(
            swoole_http_request_ce, SW_Z8_OBJ_P(ctx->request.zobject), ZEND_STRL("streamId"), stream_id);

        String *buffer = ctx->request.h2_data_buffer;
        if (!buffer) {
            buffer = new String(SW_HTTP2_DATA_BUFFER_SIZE);
            ctx->request.h2_data_buffer = buffer;
        }
        buffer->append(buf, length);

        // flow control
        client->local_settings.window_size -= length;
        stream->local_window_size -= length;

        if (length > 0) {
            if (client->local_settings.window_size < (SW_HTTP2_MAX_WINDOW_SIZE / 4)) {
                http2_server_send_window_update(ctx, 0, SW_HTTP2_MAX_WINDOW_SIZE - client->local_settings.window_size);
                client->local_settings.window_size = SW_HTTP2_MAX_WINDOW_SIZE;
            }
            if (stream->local_window_size < (SW_HTTP2_MAX_WINDOW_SIZE / 4)) {
                http2_server_send_window_update(ctx, stream_id, SW_HTTP2_MAX_WINDOW_SIZE - stream->local_window_size);
                stream->local_window_size = SW_HTTP2_MAX_WINDOW_SIZE;
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

            if (!client->is_coro) {
                retval = SW_OK;
            }

            client->handle(client, stream);
        }
        break;
    }
    case SW_HTTP2_TYPE_PING: {
        swoole_http2_frame_trace_log(recv, "ping");
        if (!(flags & SW_HTTP2_FLAG_ACK)) {
            char ping_frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];
            Http2::set_frame_header(
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
            client->remote_settings.window_size += value;
        } else {
            if (client->streams.find(stream_id) != client->streams.end()) {
                stream = client->streams[stream_id];
                stream->remote_window_size += value;
                if (!client->is_coro) {
                    Server *serv = (Server *) stream->ctx->private_data;
                    if (serv->send_yield && stream->waiting_coroutine) {
                        stream->waiting_coroutine->resume();
                    }
                }
            }
        }
        swoole_http2_frame_trace_log(recv, "window_size_increment=%d", value);
        break;
    }
    case SW_HTTP2_TYPE_RST_STREAM: {
        value = ntohl(*(int *) (buf));
        swoole_http2_frame_trace_log(recv, "error_code=%d", value);
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
        swoole_http2_frame_trace_log(recv,
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
        swoole_http2_frame_trace_log(recv, "");
    }
    }

    return retval;
}

/**
 * Http2
 */
int swoole_http2_server_onReceive(Server *serv, Connection *conn, RecvData *req) {
    int session_id = req->info.fd;
    Http2Session *client = http2_sessions[session_id];
    if (client == nullptr) {
        client = new Http2Session(session_id);
    }

    client->handle = http2_server_onRequest;
    if (!client->default_ctx) {
        client->default_ctx = new HttpContext();
        client->default_ctx->init(serv);
        client->default_ctx->fd = session_id;
        client->default_ctx->http2 = true;
        client->default_ctx->stream = (Http2Stream *) -1;
        client->default_ctx->keepalive = true;
        client->default_ctx->onBeforeRequest = http2_server_context_onBeforeRequest;
    }

    zval zdata;
    php_swoole_get_recv_data(serv, &zdata, req);
    int retval = swoole_http2_server_parse(client, Z_STRVAL(zdata));
    zval_ptr_dtor(&zdata);

    return retval;
}

void swoole_http2_server_session_free(Connection *conn) {
    auto session_iterator = http2_sessions.find(conn->session_id);
    if (session_iterator == http2_sessions.end()) {
        return;
    }
    Http2Session *client = session_iterator->second;
    delete client;
}

void HttpContext::http2_end(zval *zdata, zval *return_value) {
    String http_body = {};
    if (zdata) {
        http_body.length = php_swoole_get_send_data(zdata, &http_body.str);
    } else {
        http_body.length = 0;
        http_body.str = nullptr;
    }

    RETURN_BOOL(http2_server_respond(this, &http_body));
}

#endif
