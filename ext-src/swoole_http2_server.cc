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

#include <memory>
#include <sstream>
#include <utility>

#include "swoole_static_handler.h"
#include "swoole_coroutine_channel.h"

#include "main/php_variables.h"

using swoole::Connection;
using swoole::Coroutine;
using swoole::File;
using swoole::RecvData;
using swoole::Server;
using swoole::SessionId;
using swoole::String;
using swoole::http_server::StaticHandler;

namespace Http2 = swoole::http2;

using HttpContext = swoole::http::Context;
using Http2Stream = Http2::Stream;
using Http2Session = Http2::Session;

static SW_THREAD_LOCAL std::unordered_map<SessionId, std::shared_ptr<Http2Session>> http2_sessions;

static bool http2_server_respond(HttpContext *ctx, const String *body);
static bool http2_server_send_range_file(HttpContext *ctx, StaticHandler *handler);
static bool http2_server_send_status_code(HttpContext *ctx, int status_code);

static double http2_server_now() {
    return swoole::time<std::chrono::microseconds>(true) / 1000000.0;
}

static double http2_server_send_timeout(HttpContext *ctx) {
    double timeout;
    if (ctx->is_co_socket()) {
        timeout = ctx->get_co_socket()->get_timeout(SW_TIMEOUT_WRITE);
    } else {
#ifndef _WIN32
        timeout = ctx->get_async_server()->send_timeout;
#else
        timeout = 0;
#endif
    }
    // A stalled peer must not retain a connection indefinitely, even with an unlimited socket timeout.
    return timeout > 0 ? timeout : SW_SOCKET_DEFAULT_WRITE_TIMEOUT;
}

class Http2WriteDeadline {
    HttpContext *ctx_;
    double previous_;

  public:
    explicit Http2WriteDeadline(HttpContext *ctx) : ctx_(ctx), previous_(ctx->http2_write_deadline) {
        if (previous_ == 0) {
            ctx->http2_write_deadline = http2_server_now() + http2_server_send_timeout(ctx);
        }
    }
    ~Http2WriteDeadline() {
        ctx_->http2_write_deadline = previous_;
    }
};

// Connection errors and local timeouts share a bounded, best-effort GOAWAY path. Never insert GOAWAY into a
// partially transmitted frame. The response object (or the reader) pins the coroutine socket during cleanup.
static void http2_server_abort(const std::shared_ptr<Http2Session> &session, uint32_t error, const char *reason) {
    if (session->terminating || !session->default_ctx) {
        return;
    }
    session->terminating = true;
    HttpContext *ctx = session->default_ctx;
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + 64];
    size_t reason_length = std::min(strlen(reason), size_t(64));
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_GOAWAY, SW_HTTP2_GOAWAY_SIZE + reason_length, 0, 0);
    uint32_t last_stream = htonl(session->last_stream_id);
    uint32_t code = htonl(error);
    memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE, &last_stream, sizeof(last_stream));
    memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + 4, &code, sizeof(code));
    memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + 8, reason, reason_length);
    if (ctx->is_co_socket()) {
        auto *socket = ctx->get_co_socket();
        if (session->write_owner == 0 && !session->queued_partial) {
            session->write_owner = Coroutine::get_current_cid();
            session->queued_frames.clear();
            SocketImpl::TimeoutSetter timeout(socket, 0.1, SW_TIMEOUT_WRITE);
            socket->send_all(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + reason_length);
        }
        socket->close();
    } else {
#ifndef _WIN32
        // Bypass HttpContext::send(): its send-yield fallback could wait again while aborting a timed-out send.
        auto *server = ctx->get_async_server();
        const auto fd = ctx->fd;
        if (server->send(fd, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + reason_length) &&
            server->close(fd)) {
            // TLS and process-mode output may still be queued after send() succeeds. Give the graceful close a
            // bounded chance to drain, then abort by session ID so a recycled socket cannot be closed by this timer.
            if (swoole_timer_after(100, [server, fd](swoole::Timer *, swoole::TimerNode *) {
                    auto *conn = server->get_connection_by_session_id(fd);
                    if (conn && conn->active) {
                        server->close(fd, true);
                    }
                }) < 0) {
                server->close(fd, true);
            }
        } else {
            server->close(fd, true);
        }
#endif
    }
    session->notify_flow_control_waiters();
}

static bool http2_server_write_timed_out(const std::shared_ptr<Http2Session> &session) {
    http2_server_abort(session, SW_HTTP2_ERROR_NO_ERROR, "flow control or write timeout");
    swoole_set_last_error(SW_ERROR_CO_TIMEDOUT);
    return false;
}

static bool http2_server_wait_send_buffer(HttpContext *ctx, const std::shared_ptr<Http2Session> &session) {
#ifndef _WIN32
    double remaining = ctx->http2_write_deadline - http2_server_now();
    if (remaining <= 0) {
        return http2_server_write_timed_out(session);
    }
    if (php_swoole_server_wait_send_buffer(ctx->get_async_server(), ctx->fd, remaining)) {
        return true;
    }
    if (swoole_get_last_error() == SW_ERROR_CO_TIMEDOUT) {
        return http2_server_write_timed_out(session);
    }
#endif
    return false;
}

// In the coroutine server each stream's handler runs in its own coroutine. One of them at a time owns the
// connection's writes, from building a frame (HPACK state, the socket's write buffer) until the frame is sent.
// The receive loop never waits to write: a client may not read until its upload has been read. It queues its frames
// in encoding order. The owner sends the queue before its next frame and before releasing; with no owner, the
// coroutine server sends it after each parse, starting a writer that takes the lock when the socket is full.
class Http2WriteLock {
    std::shared_ptr<Http2Session> session_;
    SocketImpl *socket_ = nullptr;
    bool owned_ = false;
    bool queued_ = false;
    double deadline_ = 0;
    String buffer_;

    void close() {
        session_->terminating = true;
        session_->queued_frames.clear();
        socket_->close();
        session_->notify_flow_control_waiters();
    }

    bool send(const char *data, size_t length) {
        double remaining = deadline_ - http2_server_now();
        if (remaining <= 0) {
            return http2_server_write_timed_out(session_);
        }
        SocketImpl::TimeoutSetter timeout(socket_, remaining, SW_TIMEOUT_WRITE);
        if (socket_->send_all(data, length) == (ssize_t) length) {
            return true;
        }
        // Part of a frame may have been sent, so nothing can follow it
        close();
        return false;
    }

    bool queue(const char *data, size_t length) {
        auto &queued = session_->queued_frames;
        if (session_->write_owner != 0 && queued.length() + length > SW_HTTP2_MAX_QUEUED_FRAMES_SIZE) {
            // The client keeps sending without reading the replies
            close();
            return false;
        }
        queued.append(data, length);
        return true;
    }

  public:
    bool lock(SocketImpl *socket, const std::shared_ptr<Http2Session> &session, double deadline = 0) {
        long cid = Coroutine::get_current_cid();
        session_ = session;
        socket_ = socket;
        double timeout = socket->get_timeout(SW_TIMEOUT_WRITE);
        deadline_ =
            deadline > 0 ? deadline : http2_server_now() + (timeout > 0 ? timeout : SW_SOCKET_DEFAULT_WRITE_TIMEOUT);
        if (session->terminating) {
            return false;
        }
        if (session->write_owner == cid) {
            return true;
        }
        if (cid == session->reader_cid) {
            queued_ = true;
            return true;
        }
        double remaining = deadline_ - http2_server_now();
        if (remaining <= 0) {
            return http2_server_write_timed_out(session_);
        }
        if (!session->write_lock->push(nullptr, remaining)) {
            if (session->write_lock->get_error() == swoole::coroutine::Channel::ERROR_TIMEOUT) {
                return http2_server_write_timed_out(session_);
            }
            return false;
        }
        session->write_owner = cid;
        owned_ = true;
        return true;
    }

    // The owner's unsent bytes may still be in the socket's write buffer.
    String *get_write_buffer(HttpContext *ctx) {
        return queued_ ? &buffer_ : ctx->get_write_buffer();
    }

    // Called before a stream's frame and again right before a header block is sent: the queued frames were
    // encoded first. Frames queued while they are sent wait for the next frame or the release.
    bool flush() {
        if (!owned_ || session_->queued_frames.empty()) {
            return true;
        }
        std::string frames;
        frames.swap(session_->queued_frames);
        bool sent = send(frames.data(), frames.length());
        if (sent) {
            session_->queued_partial = false;
        }
        return sent;
    }

    bool write(const char *data, size_t length) {
        return queued_ ? queue(data, length) : flush() && send(data, length);
    }

    ~Http2WriteLock() {
        if (owned_) {
            while (!session_->queued_frames.empty()) {
                flush();
            }
            session_->write_owner = 0;
            session_->write_lock->pop();
        }
    }
};

Http2Stream::Stream(const Http2Session *client, uint32_t _id) {
    ctx = swoole_http_context_new(client->fd);
    ctx->copy(client->default_ctx);
    ctx->http2 = true;
    ctx->stream_id = _id;
    ctx->keepalive = true;
    id = _id;
    local_window_size = client->local_settings.init_window_size;
    remote_window_size = client->remote_settings.init_window_size;
}

Http2Stream::~Stream() {
    if (receive_phase != ReceivePhase::COMPLETE) {
        // The receive path owns the PHP objects until the request is dispatched.
        ctx->end_ = true;
        zval_ptr_dtor(&ctx->request.zobject);
        zval_ptr_dtor(&ctx->response.zobject);
    }
    ctx->stream_id = 0;
    ctx->end_ = true;
    ctx->free();
}

bool Http2Stream::reset(uint32_t error_code) const {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE];
    swoole_trace_log(
        SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, error_code=%u", "RST_STREAM", id, error_code);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(error_code);
    set_frame_header(frame, SW_HTTP2_TYPE_RST_STREAM, SW_HTTP2_RST_STREAM_SIZE, 0, id);
    return ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE);
}

Http2Session::Session(SessionId _fd) {
    fd = _fd;
    init_settings(&local_settings);
    // [init]: we must set default value, peer is not always send all the settings
    init_settings(&remote_settings);
    local_window_size = SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;
    remote_settings.init_window_size = SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;
    remote_window_size = SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;
    last_stream_id = 0;
    shutting_down = false;
    is_coro = false;
    max_body_size = 0;
}

std::shared_ptr<Http2Stream> Http2Session::get_stream(uint32_t stream_id) {
    auto iter = streams.find(stream_id);
    if (iter == streams.end()) {
        return {};
    } else {
        return iter->second;
    }
}

std::shared_ptr<Http2Stream> Http2Session::take_stream(uint32_t stream_id) {
    auto iter = streams.find(stream_id);
    if (iter == streams.end()) {
        return {};
    }

    auto stream = std::move(iter->second);
    streams.erase(iter);
    stream->ctx->end_ = true;
    return stream;
}

void Http2Session::notify_flow_control_waiters() {
    if (flow_control_waiters.empty() || flow_control_wakeup_scheduled) {
        return;
    }
    flow_control_wakeup_scheduled = true;
    auto session = shared_from_this();
    sw_reactor()->defer([session](void *) {
        session->flow_control_wakeup_scheduled = false;
        std::vector<std::shared_ptr<swoole::coroutine::Channel>> ready;
        for (const auto &entry : session->flow_control_waiters) {
            auto stream = session->get_stream(entry.second.stream_id);
            if (session->terminating || !stream ||
                (session->remote_window_size > 0 && stream->remote_window_size > 0)) {
                ready.push_back(entry.second.channel);
            }
        }
        // Snapshot before resuming PHP: a resumed sender can remove streams or register another wait.
        for (const auto &channel : ready) {
            if (channel->is_empty() && !channel->is_closed()) {
                channel->push_data(channel.get());
            }
        }
    });
}

bool Http2Session::remove_stream(uint32_t stream_id) {
    if (auto stream = take_stream(stream_id)) {
        notify_flow_control_waiters();
        return true;
    }
    return false;
}

std::shared_ptr<Http2Stream> Http2Session::create_stream(uint32_t stream_id) {
    auto stream = std::make_shared<Http2Stream>(this, stream_id);
    streams.emplace(stream_id, stream);
    if (sw_unlikely(!stream->ctx)) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_NO_HEADER, "http2 create stream#%d context error", stream_id);
        return {};
    }
    auto ctx = stream->ctx;
    zend::object_set(&ctx->request.zobject, ZEND_STRL("streamId"), stream_id);
    return stream;
}

Http2Session::~Session() {
    if (inflater) {
        nghttp2_hd_inflate_del(inflater);
    }
    if (deflater) {
        nghttp2_hd_deflate_del(deflater);
    }
    delete default_ctx;
}

// The async server parses outside a coroutine, so a send can't wait for output-buffer space. Close the connection
// instead of silently losing a control frame.
static bool http2_server_send_blocked() {
    return swoole_get_last_error() == SW_ERROR_OUTPUT_SEND_YIELD;
}

static bool http2_server_send_window_update(HttpContext *ctx, uint32_t stream_id, uint32_t size) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE];
    swoole_trace_log(
        SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, size=%u", "WINDOW_UPDATE", stream_id, size);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(size);
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_WINDOW_UPDATE, SW_HTTP2_WINDOW_UPDATE_SIZE, 0, stream_id);
    return ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE);
}

static ssize_t http2_server_deflate_header_block(const std::shared_ptr<Http2Session> &client,
                                                 Http2::HeaderSet &headers,
                                                 String *buffer) {
    size_t buflen = nghttp2_hd_deflate_bound(client->deflater, headers.get(), headers.len());
    size_t buffer_size = SW_HTTP2_FRAME_HEADER_SIZE + buflen;
    buffer->clear();
    if (buffer_size > buffer->size) {
        buffer->reserve(buffer_size);
    }

    ssize_t rv = nghttp2_hd_deflate_hd(
        client->deflater, (uchar *) buffer->str + SW_HTTP2_FRAME_HEADER_SIZE, buflen, headers.get(), headers.len());
    if (rv < 0) {
        swoole_warning("nghttp2_hd_deflate_hd() failed with error: %s", nghttp2_strerror((int) rv));
        return rv;
    }
    if ((uint64_t) rv > client->remote_settings.max_frame_size) {
        swoole_warning("encoded HTTP/2 header block size %" PRId64 " exceeds peer max frame size %u",
                       (int64_t) rv,
                       client->remote_settings.max_frame_size);
        return NGHTTP2_ERR_FRAME_SIZE_ERROR;
    }

    buffer->length = SW_HTTP2_FRAME_HEADER_SIZE + rv;
    return rv;
}

static ssize_t http2_server_build_trailer(const HttpContext *ctx, String *buffer) {
    zval *ztrailer = sw_zend_read_property_ex(
        swoole_http_response_ce, &ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
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

        auto session = http2_sessions.find(ctx->fd);
        if (session == http2_sessions.end() || !session->second->get_stream(ctx->stream_id)) {
            return -1;
        }
        auto &client = session->second;
        auto deflater = client->deflater;

        if (!deflater) {
            int ret = nghttp2_hd_deflate_new2(&deflater, client->remote_settings.header_table_size, php_nghttp2_mem());
            if (ret != 0) {
                swoole_warning("nghttp2_hd_deflate_new2() failed with error: %s", nghttp2_strerror(ret));
                return -1;
            }
            client->deflater = deflater;
        }

        return http2_server_deflate_header_block(client, trailer, buffer);
    }
    return 0;
}

#ifndef _WIN32
static bool http2_server_is_static_file(Server *serv, HttpContext *ctx) {
    zval *zserver = &ctx->request.zserver;
    zval *method = zend_hash_str_find(Z_ARR_P(zserver), ZEND_STRL("request_method"));
    if (!method || Z_TYPE_P(method) != IS_STRING) {
        return false;
    }
    const bool head = SW_STRCASEEQ(Z_STRVAL_P(method), Z_STRLEN_P(method), "HEAD");
    if (!head && !SW_STRCASEEQ(Z_STRVAL_P(method), Z_STRLEN_P(method), "GET")) {
        return false;
    }
    zval *uri = zend_hash_str_find(Z_ARR_P(zserver), ZEND_STRL("request_uri"));
    if (!uri || Z_TYPE_P(uri) != IS_STRING) {
        return false;
    }
    StaticHandler handler(serv,
                          ctx->request.path ? ZSTR_VAL(ctx->request.path) : Z_STRVAL_P(uri),
                          ctx->request.path ? ZSTR_LEN(ctx->request.path) : Z_STRLEN_P(uri));
    if (!handler.try_serve()) {
        return false;
    }
    const auto redirect = handler.status_code == SW_HTTP_OK ? handler.get_directory_redirect() : std::string{};
    if (handler.status_code == SW_HTTP_OK && (!handler.try_serve_index_file() || !handler.open_file())) {
        return false;
    }
    if (!swoole_coroutine_is_in() && serv->is_enable_coroutine()) {
        // Static responses bypass the PHP request callback. Give them a PHP coroutine as well, so a depleted
        // connection window can suspend this response without blocking frame parsing.
        zend_fcall_info_cache fci{};
        fci.function_handler = static_cast<zend_function *>(
            zend_hash_str_find_ptr(&swoole_http_response_ce->function_table, ZEND_STRL("sendstaticfile")));
        fci.object = Z_OBJ(ctx->response.zobject);
        fci.called_scope = swoole_http_response_ce;
        if (swoole::PHPCoroutine::create(&fci, 1, &ctx->request.zobject, nullptr) < 0) {
            ctx->end_ = true;
            ctx->close(ctx);
        }
        return true;
    }
    ctx->onAfterResponse = nullptr;
    ctx->onBeforeRequest = nullptr;
#ifdef SW_HAVE_COMPRESSION
    // Static lengths describe the selected file/listing, including HEAD responses.
    ctx->accept_compression = 0;
#endif
    const auto respond = [&](int status, String &body) {
        ctx->response.status = status;
        if (status != SW_HTTP_NOT_MODIFIED) {
            ctx->set_header(ZEND_STRL("Content-Length"), std::to_string(body.length), false);
        }
        String empty;
        return http2_server_respond(ctx, head ? &empty : &body);
    };
    if (handler.status_code == SW_HTTP_NOT_FOUND || handler.status_code == SW_HTTP_BAD_REQUEST) {
        String body;
        if (handler.status_code == SW_HTTP_NOT_FOUND) {
            body.append(SW_STRL(SW_HTTP_PAGE_404));
        }
        ctx->set_header(ZEND_STRL("Content-Type"), SW_STRL("text/html"), false);
        respond(handler.status_code, body);
        return true;
    }
    if (!redirect.empty()) {
        ctx->set_header(ZEND_STRL("Location"), redirect, false);
        String empty;
        respond(SW_HTTP_MOVED_PERMANENTLY, empty);
        return true;
    }
    ctx->set_header(ZEND_STRL("Last-Modified"), handler.get_date_last_modified(), false);
    ctx->set_header(ZEND_STRL("ETag"), handler.get_etag(), false);
    const auto header = [&](const char *name, size_t length) -> const char * {
        zval *value = zend_hash_str_find(Z_ARR_P(&ctx->request.zheader), name, length);
        return value && Z_TYPE_P(value) == IS_STRING ? Z_STRVAL_P(value) : "";
    };
    const int condition = handler.evaluate_preconditions(header(ZEND_STRL("if-match")),
                                                         header(ZEND_STRL("if-unmodified-since")),
                                                         header(ZEND_STRL("if-none-match")),
                                                         header(ZEND_STRL("if-modified-since")));
    if (condition != SW_HTTP_OK) {
        String empty;
        respond(condition, empty);
        return true;
    }
    if (!handler.has_index_file() && handler.is_enabled_auto_index() && handler.is_dir()) {
        String body(1024);
        handler.make_index_page(&body);
        ctx->set_header(ZEND_STRL("Content-Type"), SW_STRL("text/html"), false);
        respond(SW_HTTP_OK, body);
        return true;
    }
    handler.parse_range(header(ZEND_STRL("range")), header(ZEND_STRL("if-range")));
    ctx->response.status = handler.status_code;
    const auto &tasks = handler.get_tasks();
    if (handler.status_code == SW_HTTP_RANGE_NOT_SATISFIABLE) {
        ctx->set_header(ZEND_STRL("Content-Range"), "bytes */" + std::to_string(handler.get_filesize()), false);
        String empty;
        respond(handler.status_code, empty);
        return true;
    }
    if (handler.status_code == SW_HTTP_PARTIAL_CONTENT && tasks.size() == 1) {
        const auto &part = tasks.front();
        const std::string value = "bytes " + std::to_string(part.offset) + "-" +
                                  std::to_string(part.offset + part.length - 1) + "/" +
                                  std::to_string(handler.get_filesize());
        ctx->set_header(ZEND_STRL("Content-Range"), value, false);
    } else if (handler.status_code == SW_HTTP_OK) {
        ctx->set_header(ZEND_STRL("Accept-Ranges"), SW_STRL("bytes"), false);
    }
    if (head) {
        ctx->set_header(ZEND_STRL("Content-Length"), std::to_string(handler.get_content_length()), false);
        ctx->set_header(ZEND_STRL("Content-Type"), handler.get_content_type(), false);
        String empty;
        http2_server_respond(ctx, &empty);
    } else {
        http2_server_send_range_file(ctx, &handler);
    }
    // Once a static response is selected, a send failure must not dispatch PHP.
    return true;
}

void swoole_http2_server_send_static_file(HttpContext *ctx) {
    Http2WriteDeadline deadline(ctx);
    auto iter = http2_sessions.find(ctx->fd);
    if (iter == http2_sessions.end() || !iter->second->get_stream(ctx->stream_id)) {
        ctx->end_ = true;
        return;
    }
    http2_server_is_static_file(ctx->get_async_server(), ctx);
}

bool swoole_http2_server_call_request(HttpContext *ctx, zend::Callable *cb, zval *args) {
    auto *serv = ctx->get_async_server();
    if (!serv->http2_cancel_on_stream_reset) {
        return zend::function::call(cb, 2, args, nullptr, serv->is_enable_coroutine());
    }

    // This also runs when a request queued by worker_max_concurrency gets its turn.
    auto session = http2_sessions.find(ctx->fd);
    if (session == http2_sessions.end()) {
        return true;
    }
    auto stream = session->second->get_stream(ctx->stream_id);
    if (!stream || stream->ctx != ctx) {
        return true;
    }

    // The worker can parse another frame only after the callback yields to the event loop.
    auto cid = swoole::PHPCoroutine::create(cb->ptr(), 2, args, nullptr);
    if (UNEXPECTED(EG(exception))) {
        sw_zend_exception_error(EG(exception), E_ERROR);
    }
    if (cid > 0 && swoole::PHPCoroutine::get_context_by_cid(cid)) {
        stream->request_cid = cid;
    }
    return cid >= 0;
}

static void http2_server_onRequest(const std::shared_ptr<Http2Session> &client,
                                   const std::shared_ptr<Http2Stream> &stream) {
    HttpContext *ctx = stream->ctx;
    auto serv = ctx->get_async_server();
    zval args[2];
    zend::Callable *cb = nullptr;

    Connection *conn = serv->get_connection_by_session_id(ctx->fd);
    if (!conn) {
        goto _destroy;
    }

    ctx->request.version = SW_HTTP_VERSION_2;
    if (serv->enable_static_handler && http2_server_is_static_file(serv, ctx)) {
        goto _destroy;
    }

    do {
        zval *zserver = &ctx->request.zserver;
        HashTable *ht = Z_ARR_P(zserver);
        swoole_http_server_populate_ip_and_port(serv, ht, conn, client->fd, ctx->keepalive);
        http_server_add_server_array(ht, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_TIME), (zend_long) time(nullptr));
        http_server_add_server_array(ht, SW_ZSTR_KNOWN(SW_ZEND_STR_REQUEST_TIME_FLOAT), swoole::microtime());
        http_server_add_server_array(
            ht, SW_ZSTR_KNOWN(SW_ZEND_STR_MASTER_TIME), (zend_long) conn->get_last_recv_time());
        http_server_add_server_array(ht, SW_ZSTR_KNOWN(SW_ZEND_STR_SERVER_PROTOCOL), SW_ZSTR_KNOWN(SW_ZEND_STR_HTTP2));
    } while (false);

    cb = php_swoole_server_get_callback(serv, conn->server_fd, SW_SERVER_CB_onRequest);
    ctx->private_data_2 = cb;

    if (ctx->onBeforeRequest && !ctx->onBeforeRequest(ctx)) {
        return;
    }

    args[0] = ctx->request.zobject;
    args[1] = ctx->response.zobject;
    if (UNEXPECTED(!swoole_http2_server_call_request(ctx, cb, args))) {
        stream->reset(SW_HTTP2_ERROR_INTERNAL_ERROR);
        php_swoole_error(E_WARNING, "%s->onRequest[v2] handler error", ZSTR_VAL(swoole_http_server_ce->name));
    }

_destroy:
    zval_ptr_dtor(&ctx->request.zobject);
    zval_ptr_dtor(&ctx->response.zobject);
}
#endif

static ssize_t http2_server_build_header(HttpContext *ctx, String *buffer, const String *body) {
    zval *zheader =
        sw_zend_read_property_ex(swoole_http_response_ce, &ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_HEADER), 0);
    zval *zcookie =
        sw_zend_read_property_ex(swoole_http_response_ce, &ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIE), 0);
    Http2::HeaderSet headers(32 + php_swoole_array_length_safe(zheader) + php_swoole_array_length_safe(zcookie));
    char intbuf[2][16];

    assert(ctx->send_header_ == 0);

    // status code
    if (ctx->response.status == 0) {
        ctx->response.status = SW_HTTP_OK;
    }
    int ret = swoole_itoa(intbuf[0], ctx->response.status);
    headers.add(ZEND_STRL(":status"), intbuf[0], ret);

    uint32_t header_flags = 0x0;
    std::vector<std::string> content_lengths;

    // headers
    if (ZVAL_IS_ARRAY(zheader)) {
        const char *key;
        uint32_t keylen;
        zval *zvalue;
        int type;

        zend_string *content_type = nullptr;
        auto add_header =
            [ctx, &content_type, &content_lengths](
                Http2::HeaderSet &headers, const char *key, size_t l_key, zval *value, uint32_t &header_flags) {
                if (ZVAL_IS_NULL(value)) {
                    return;
                }
                zend::String str_value(value);
                str_value.rtrim();
                if (swoole_http_has_crlf(str_value.val(), str_value.len())) {
                    return;
                }
                if (SW_STRCASEEQ(key, l_key, "server")) {
                    header_flags |= HTTP_HEADER_SERVER;
                } else if (SW_STRCASEEQ(key, l_key, "content-length")) {
                    header_flags |= HTTP_HEADER_CONTENT_LENGTH;
                    // Defer the field until compression has actually succeeded. Accept-Encoding alone
                    // is insufficient because compression may still be disabled by the representation
                    // headers or skipped for a body below compression_min_length.
                    if (str_value.len() > 0) {
                        content_lengths.emplace_back(str_value.val(), str_value.len());
                    }
                    return;
                } else if (SW_STRCASEEQ(key, l_key, "content-encoding")) {
#ifdef SW_HAVE_COMPRESSION
                    // The application owns the representation encoding; do not compress it again.
                    ctx->accept_compression = 0;
#endif
                    // An empty value keeps the field explicit without emitting it, like other known headers.
                    if (str_value.len() == 0) {
                        return;
                    }
                } else if (SW_STRCASEEQ(key, l_key, "date")) {
                    header_flags |= HTTP_HEADER_DATE;
                } else if (SW_STRCASEEQ(key, l_key, "content-type")) {
                    header_flags |= HTTP_HEADER_CONTENT_TYPE;
#ifdef SW_HAVE_COMPRESSION
                    if (ctx->accept_compression && ctx->compression_types) {
                        content_type = zval_get_string(value);
                    }
#endif
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

#ifdef SW_HAVE_COMPRESSION
        if (ctx->accept_compression && ctx->compression_types) {
            std::string str_content_type = content_type ? std::string(ZSTR_VAL(content_type), ZSTR_LEN(content_type))
                                                        : std::string(ZEND_STRL(SW_HTTP_DEFAULT_CONTENT_TYPE));
            ctx->accept_compression = ctx->compression_types->find(str_content_type) != ctx->compression_types->end();
        }
        // Released unconditionally: an application content-encoding can clear accept_compression
        // after content-type was captured, which would skip the refinement above.
        if (content_type) {
            zend_string_release(content_type);
        }
#endif
    }

    if (!(header_flags & HTTP_HEADER_SERVER)) {
        headers.add(ZEND_STRL("server"), ZEND_STRL(SW_HTTP_SERVER_SOFTWARE));
    }
    if (!(header_flags & HTTP_HEADER_DATE)) {
        auto date_str = php_swoole_http_get_date();
        headers.add(ZEND_STRL("date"), ZSTR_VAL(date_str), ZSTR_LEN(date_str));
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

    size_t content_length = body ? body->length : 0;
    bool content_compressed = false;
#ifdef SW_HAVE_COMPRESSION
    if (body && ctx->compress(body->str, body->length)) {
        content_compressed = true;
        content_length = ctx->zlib_buffer->length;
        const char *content_encoding = ctx->get_content_encoding();
        headers.add(ZEND_STRL("content-encoding"), (char *) content_encoding, strlen(content_encoding));
    }
#endif

    if (content_compressed) {
        if (header_flags & HTTP_HEADER_CONTENT_LENGTH) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_HTTP_CONFLICT_HEADER,
                             "The client has set 'Accept-Encoding', 'Content-Length' will be ignored");
        }
        ret = swoole_itoa(intbuf[1], content_length);
        headers.add(ZEND_STRL("content-length"), intbuf[1], ret);
    } else if (header_flags & HTTP_HEADER_CONTENT_LENGTH) {
        for (const auto &value : content_lengths) {
            headers.add(ZEND_STRL("content-length"), value.c_str(), value.length());
        }
    } else if (body) {
        // Synthesize a length only when the caller did not supply one, and never rewrite a
        // zero-length HEAD representation to an explicit zero.
        if (body->length > 0 || ctx->parser.method != HTTP_HEAD) {
            ret = swoole_itoa(intbuf[1], content_length);
            headers.add(ZEND_STRL("content-length"), intbuf[1], ret);
        }
    }

    auto session = http2_sessions.find(ctx->fd);
    if (session == http2_sessions.end() || !session->second->get_stream(ctx->stream_id)) {
        return -1;
    }
    auto &client = session->second;
    auto deflater = client->deflater;
    if (!deflater) {
        ret = nghttp2_hd_deflate_new2(&deflater, client->remote_settings.header_table_size, php_nghttp2_mem());
        if (ret != 0) {
            swoole_warning("nghttp2_hd_deflate_new2() failed with error: %s", nghttp2_strerror(ret));
            return -1;
        }
        client->deflater = deflater;
    }

    ssize_t rv = http2_server_deflate_header_block(client, headers, buffer);
    if (rv < 0) {
        return rv;
    }

    ctx->send_header_ = 1;
    return rv;
}

bool swoole_http2_server_coro_send(HttpContext *ctx, const char *data, size_t length) {
    auto iter = http2_sessions.find(ctx->fd);
    if (iter == http2_sessions.end()) {
        return false;
    }
    Http2WriteLock lock;
    return lock.lock(ctx->get_co_socket(), iter->second, ctx->http2_write_deadline) && lock.write(data, length);
}

void swoole_http2_server_coro_write_queued(SocketImpl *socket) {
    auto iter = http2_sessions.find(socket->get_fd());
    // The fd may belong to another connection by now
    if (iter == http2_sessions.end() || iter->second->default_ctx->get_co_socket() != socket) {
        return;
    }
    // Releasing the lock sends the queue
    Http2WriteLock lock;
    lock.lock(socket, iter->second);
}

bool swoole_http2_server_ping(HttpContext *ctx) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE] = {};
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_NONE, 0);
    return ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
}

static bool http2_server_send_setting_ack(HttpContext *ctx) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE];
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 0, SW_HTTP2_FLAG_ACK, 0);
    return ctx->send(ctx, frame, SW_HTTP2_FRAME_HEADER_SIZE);
}

bool swoole_http2_server_goaway(HttpContext *ctx, zend_long error_code, zend_string *sdata) {
    const char *debug_data = sdata ? ZSTR_VAL(sdata) : nullptr;
    size_t debug_data_len = sdata ? ZSTR_LEN(sdata) : 0;
    auto client = http2_sessions[ctx->fd];
    // GOAWAY cannot be fragmented; include its fixed fields in the peer's payload limit.
    if (debug_data_len > client->remote_settings.max_frame_size - SW_HTTP2_GOAWAY_SIZE) {
        php_swoole_error(E_WARNING, "GOAWAY debug data exceeds the peer's maximum frame size");
        return false;
    }
    size_t length = SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + debug_data_len;
    char *frame = (char *) ecalloc(1, length);
    uint32_t last_stream_id = client->last_stream_id;
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_GOAWAY, SW_HTTP2_GOAWAY_SIZE + debug_data_len, SW_HTTP2_FLAG_NONE, 0);
    *(uint32_t *) (frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(last_stream_id);
    *(uint32_t *) (frame + SW_HTTP2_FRAME_HEADER_SIZE + 4) = htonl(error_code);
    if (debug_data_len > 0) {
        memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE, debug_data, debug_data_len);
    }
    bool rv = ctx->send(ctx, frame, length);
    efree(frame);
    if (rv) {
        client->shutting_down = true;
    }
    return rv;
}

bool Http2Stream::send_header_block(const String *frame) const {
#ifndef _WIN32
    // Preserve encoded header order and the operation's deadline on every async send-yield path.
    if (!ctx->is_co_socket()) {
        if (send_frame(frame->str, frame->length, false)) {
            return true;
        }
        // Encoding has already changed the connection's HPACK state.
        ctx->end_ = 1;
        ctx->get_async_server()->close(ctx->fd, true);
        return false;
    }
#endif
    if (!ctx->send(ctx, frame->str, frame->length)) {
        ctx->end_ = 1;
        ctx->close(ctx);
        return false;
    }
    return true;
}

bool Http2Stream::send_header(const String *body, bool end_stream, const std::shared_ptr<Http2Session> &session) const {
    Http2WriteLock lock;
    if (ctx->is_co_socket() &&
        (!lock.lock(ctx->get_co_socket(), session, ctx->http2_write_deadline) || !lock.flush())) {
        return false;
    }
    String *http_buffer = lock.get_write_buffer(ctx);
    ssize_t bytes = http2_server_build_header(ctx, http_buffer, body);
    if (bytes < 0) {
        if (session->deflater && session->get_stream(id)) {
            ctx->end_ = 1;
            ctx->close(ctx);
        }
        return false;
    }

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
    if (end_stream && (!body || body->length == 0)) {
        http2::set_frame_header(
            http_buffer->str, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS | SW_HTTP2_FLAG_END_STREAM, id);
        ctx->end_ = 1;
    } else {
        http2::set_frame_header(http_buffer->str, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS, id);
    }

    if (!lock.flush() || !send_header_block(http_buffer)) {
        ctx->send_header_ = 0;
        return false;
    }

    return true;
}

bool Http2Stream::send_end_stream_data_frame(const std::shared_ptr<Http2Session> &session) const {
    Http2WriteLock lock;
    if (ctx->is_co_socket() &&
        (!lock.lock(ctx->get_co_socket(), session, ctx->http2_write_deadline) || !lock.flush())) {
        return false;
    }
    if (session->get_stream(id).get() != this) {
        swoole_set_last_error(SW_ERROR_HTTP2_STREAM_NOT_FOUND);
        return false;
    }
    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];
    http2::set_frame_header(frame_header, SW_HTTP2_TYPE_DATA, 0, SW_HTTP2_FLAG_END_STREAM, id);
    return send_frame(frame_header, sizeof(frame_header), true);
}

static bool http2_server_check_stream(const std::shared_ptr<Http2Session> &session, Http2Stream *stream) {
    if (session->get_stream(stream->id).get() == stream) {
        return true;
    }
    stream->ctx->end_ = 1;
    return false;
}

bool Http2Stream::send_frame(const char *frame, size_t length, bool data_frame) const {
#ifndef _WIN32
    if (!ctx->is_co_socket()) {
        auto *serv = ctx->get_async_server();
        if (serv->send(ctx->fd, frame, length)) {
            return true;
        }
        if (swoole_get_last_error() != SW_ERROR_OUTPUT_SEND_YIELD || !swoole_coroutine_is_in()) {
            return false;
        }

        auto iter = http2_sessions.find(ctx->fd);
        if (iter == http2_sessions.end()) {
            return false;
        }
        auto session = iter->second;
        // Another writer can reuse the context's buffer while we are suspended.
        zend::String pending(frame, length);
        auto *header_task = data_frame ? nullptr : static_cast<swoole::PHPContext *>(Coroutine::get_current_task());
        const bool was_header_pending = header_task && std::exchange(header_task->http2_header_send_pending, true);
        ON_SCOPE_EXIT {
            if (header_task) {
                header_task->http2_header_send_pending = was_header_pending;
            }
        };
        SW_LOOP {
            if (!http2_server_wait_send_buffer(ctx, session)) {
                break;
            }
            if (data_frame && session->get_stream(id).get() != this) {
                swoole_set_last_error(SW_ERROR_HTTP2_STREAM_NOT_FOUND);
                return false;
            }
            if (serv->send(ctx->fd, pending.val(), pending.len())) {
                return true;
            }
            if (swoole_get_last_error() != SW_ERROR_OUTPUT_SEND_YIELD) {
                break;
            }
        }
        return false;
    }
#endif
    return ctx->send(ctx, frame, length);
}

static bool http2_server_wait_for_window(const std::shared_ptr<Http2Session> &session,
                                         const std::shared_ptr<Http2Stream> &stream) {
    if (!stream) {
        return false;
    }
    auto *ctx = stream->ctx;
    while (true) {
        if (session->terminating || !http2_server_check_stream(session, stream.get())) {
            return false;
        }
        if (session->remote_window_size > 0 && stream->remote_window_size > 0) {
            return true;
        }
        if (!swoole_coroutine_is_in()) {
            swoole_set_last_error(SW_ERROR_OUTPUT_SEND_YIELD);
            return false;
        }
        const long cid = Coroutine::get_current_cid();
        auto channel = std::make_shared<swoole::coroutine::Channel>(1);
        session->flow_control_waiters.emplace(cid, Http2Session::FlowControlWaiter{stream->id, channel});
        ON_SCOPE_EXIT {
            session->flow_control_waiters.erase(cid);
        };
        // Registration and the predicate check do not yield. Notifications are retained by the channel, and
        // cancellation (including a throwing cancellation) removes the registration on every exit path.
        double remaining = ctx->http2_write_deadline - http2_server_now();
        if (remaining <= 0) {
            return http2_server_write_timed_out(session);
        }
        if (!channel->pop(remaining)) {
            if (channel->get_error() == swoole::coroutine::Channel::ERROR_TIMEOUT) {
                return http2_server_write_timed_out(session);
            }
            swoole_set_last_error(SW_ERROR_CO_CANCELED);
            return false;
        }
    }
}

bool Http2Stream::send_body(
    const String *body, bool end_stream, const std::shared_ptr<Http2Session> &session, off_t offset, size_t length) {
    if (!http2_server_check_stream(session, this)) {
        return false;
    }

    char frame_header[SW_HTTP2_FRAME_HEADER_SIZE];
    char *p = body->str + offset;
    size_t l = length == 0 ? body->length : length;

    int flags = end_stream ? SW_HTTP2_FLAG_END_STREAM : SW_HTTP2_FLAG_NONE;
    const bool co_socket = ctx->is_co_socket();
    uint32_t max_payload = UINT32_MAX;
#ifndef _WIN32
    if (!co_socket && ctx->get_async_server()->is_process_mode()) {
        const auto limit = ctx->get_async_server()->output_buffer_size;
        if (limit <= sizeof(frame_header)) {
            swoole_set_last_error(SW_ERROR_DATA_LENGTH_TOO_LARGE);
            return false;
        }
        max_payload = limit - sizeof(frame_header);
    }
#endif

    while (l > 0) {
        if (!http2_server_wait_for_window(session, session->get_stream(id))) {
            return false;
        }
        Http2WriteLock lock;
        if (co_socket && (!lock.lock(ctx->get_co_socket(), session, ctx->http2_write_deadline) || !lock.flush() ||
                          !http2_server_check_stream(session, this))) {
            return false;
        }
        // Waiting for the lock or flushing queued frames can consume the available connection credit.
        if (session->remote_window_size <= 0 || remote_window_size <= 0) {
            continue;
        }
        auto max_frame_size = std::min(session->remote_settings.max_frame_size, max_payload);
        size_t send_n =
            std::min({l, size_t(max_frame_size), size_t(session->remote_window_size), size_t(remote_window_size)});
        int _send_flags = send_n == l ? flags : SW_HTTP2_FLAG_NONE;
        // Reserve both windows before socket I/O can yield. SETTINGS may reduce a stream window while the frame
        // is in flight; signed accounting preserves that debt rather than wrapping to a large allowance.
        remote_window_size -= send_n;
        session->remote_window_size -= send_n;
        bool frame_sent = false;
        ON_SCOPE_EXIT {
            // Async sends enqueue complete frames atomically. A reset/cancellation before acceptance must return
            // the reserved connection credit; otherwise unrelated streams eventually stall on a phantom debt.
            if (!co_socket && !frame_sent) {
                remote_window_size += send_n;
                session->remote_window_size += send_n;
                if (remote_window_size > INT32_MAX || session->remote_window_size > INT32_MAX) {
                    http2_server_abort(
                        session, SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "window overflow after canceled send");
                } else {
                    session->notify_flow_control_waiters();
                }
            }
        };

        http2::set_frame_header(frame_header, SW_HTTP2_TYPE_DATA, send_n, _send_flags, id);

        // An async send may wait for buffer space. Submit each complete frame so
        // cancellation cannot leave its header in the connection without its payload.
        if (!co_socket || send_n < swoole_pagesize()) {
            String *http_buffer = lock.get_write_buffer(ctx);
            http_buffer->clear();
            http_buffer->append(frame_header, SW_HTTP2_FRAME_HEADER_SIZE);
            http_buffer->append(p, send_n);
            if (!send_frame(http_buffer->str, http_buffer->length, true)) {
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

        frame_sent = true;
        swoole_trace_log(
            SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, flags=%d, send_n=%lu", "DATA", id, flags, send_n);

        l -= send_n;
        p += send_n;
    }

    return true;
}

bool Http2Stream::send_trailer(const std::shared_ptr<Http2Session> &session) const {
    Http2WriteLock lock;
    if (ctx->is_co_socket() &&
        (!lock.lock(ctx->get_co_socket(), session, ctx->http2_write_deadline) || !lock.flush())) {
        return false;
    }
    String *http_buffer = lock.get_write_buffer(ctx);

    http_buffer->clear();
    ssize_t bytes = http2_server_build_trailer(ctx, http_buffer);
    if (bytes < 0) {
        return false;
    }
    if (bytes == 0) {
        http_buffer->length = SW_HTTP2_FRAME_HEADER_SIZE;
    }

    http2::set_frame_header(
        http_buffer->str, SW_HTTP2_TYPE_HEADERS, bytes, SW_HTTP2_FLAG_END_HEADERS | SW_HTTP2_FLAG_END_STREAM, id);
    return lock.flush() && send_header_block(http_buffer);
}

bool swoole_http2_server_end(HttpContext *ctx, zend_string *sdata) {
    Http2WriteDeadline deadline(ctx);
    String http_body = {};
    if (sdata) {
        http_body.length = ZSTR_LEN(sdata);
        http_body.str = ZSTR_VAL(sdata);
    } else {
        http_body.length = 0;
        http_body.str = nullptr;
    }
    return http2_server_respond(ctx, &http_body);
}

bool swoole_http2_server_write(HttpContext *ctx, zend_string *sdata) {
    Http2WriteDeadline deadline(ctx);
    String chunk = {};
    chunk.length = ZSTR_LEN(sdata);
    chunk.str = ZSTR_VAL(sdata);
    if (chunk.length == 0) {
        php_swoole_error_ex(E_WARNING, SW_ERROR_NO_PAYLOAD, "the data sent must not be empty");
        return false;
    }

    auto client = http2_sessions[ctx->fd];
    auto stream = client->get_stream(ctx->stream_id);

    ctx->send_chunked = 1;

    if (!ctx->send_header_ && !stream->send_header(nullptr, false, client)) {
        return false;
    }

    if (!stream->send_body(&chunk, false, client)) {
        return false;
    }

    return true;
}

static bool http2_server_respond(HttpContext *ctx, const String *body) {
    auto iter = http2_sessions.find(ctx->fd);
    // After a fatal error, request shutdown releases the sessions before Zend frees unfinished responses.
    if (iter == http2_sessions.end()) {
        return false;
    }
    auto client = iter->second;
    auto stream = client->get_stream(ctx->stream_id);

    zval *ztrailer = sw_zend_read_property_ex(
        swoole_http_response_ce, &ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    if (php_swoole_array_length_safe(ztrailer) == 0) {
        ztrailer = nullptr;
    }

    bool end_stream = (ztrailer == nullptr);

    if (!ctx->send_header_ && !stream->send_header(body, end_stream, client)) {
        return false;
    }

    // The headers have already been sent, retries are no longer allowed (even if send body failed)
    ctx->end_ = 1;

    bool error = true;

#ifdef SW_HAVE_COMPRESSION
    if (ctx->content_compressed) {
        body = ctx->zlib_buffer.get();
    }
#endif

    SW_LOOP {
        if (body->length == 0) {
            // Trailer HEADERS carry END_STREAM, so only trailerless streamed responses need an empty DATA frame.
            if (ctx->send_chunked && !ztrailer && !stream->send_end_stream_data_frame(client)) {
                break;
            }
        } else if (!stream->send_body(body, end_stream, client)) {
            break;
        }
        if (ztrailer && !stream->send_trailer(client)) {
            break;
        }
        error = false;
        break;
    }

    if (!error) {
        client->remove_stream(stream->id);
    } else if (client->get_stream(stream->id)) {
        ctx->close(ctx);
    }

    if (client->shutting_down && client->streams.empty()) {
        if (ctx->is_co_socket() && client->reader_cid == Coroutine::get_current_cid()) {
            // The receive loop queued this response. It stops reading here, so it can wait to send it first.
            client->reader_cid = 0;
            Http2WriteLock lock;
            lock.lock(ctx->get_co_socket(), client);
        }
        ctx->close(ctx);
    }

    return !error;
}

static bool http2_server_send_status_code(HttpContext *ctx, int status_code) {
    auto client = http2_sessions[ctx->fd];
    auto stream = client->get_stream(ctx->stream_id);
    ctx->response.status = status_code;
    return stream->send_header(nullptr, true, client);
}

static bool http2_server_send_range_file(HttpContext *ctx, StaticHandler *handler) {
    Http2WriteDeadline deadline(ctx);
    auto client = http2_sessions[ctx->fd];
    auto stream = client->get_stream(ctx->stream_id);

#ifdef SW_HAVE_COMPRESSION
    ctx->accept_compression = 0;
#endif
    bool error = false;
    zval *ztrailer = sw_zend_read_property_ex(
        swoole_http_response_ce, &ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    if (php_swoole_array_length_safe(ztrailer) == 0) {
        ztrailer = nullptr;
    }
    zval *zheader = sw_zend_read_and_convert_property_array(
        swoole_http_response_ce, &ctx->response.zobject, ZEND_STRL("header"), 0);
    if (!zend_hash_str_exists(Z_ARRVAL_P(zheader), ZEND_STRL("content-type"))) {
        ctx->set_header(ZEND_STRL("content-type"), handler->get_content_type(), false);
    }

    bool end_stream = (ztrailer == nullptr);
    auto body = std::make_shared<String>();
    body->length = handler->get_content_length();
    if (!stream->send_header(body.get(), end_stream, client)) {
        return false;
    }

    /* headers has already been sent, retries are no longer allowed (even if send body failed) */
    ctx->end_ = 1;

    const auto &tasks = handler->get_tasks();
    if (!tasks.empty()) {
        const auto &file = handler->get_file();
        if (!file || !file->ready()) {
            ctx->close(ctx);
            return true;
        }

        const auto read_range = [&file, &body](off_t offset, size_t length) -> bool {
            // This callback can run on an AIO thread, which must not allocate from Zend's request heap.
            body = std::make_shared<String>(length);
            while (body->length < length) {
                const auto n = file->pread(body->str + body->length, length - body->length, offset + body->length);
                if (n < 0 && errno == EINTR) {
                    continue;
                }
                if (n <= 0) {
                    // The advertised range can become stale if the file is truncated/replaced.
                    // Abort the response rather than expose unread bytes or finish with a false Content-Length.
                    return false;
                }
                body->length += n;
            }
            return true;
        };

        if (tasks.size() > 1) {
            for (auto i = tasks.begin(); i != tasks.end(); ++i) {
                body = std::make_shared<String>(i->part_header, strlen(i->part_header));
                if (!stream->send_body(body.get(), false, client)) {
                    error = true;
                    break;
                }

                if (!read_range(i->offset, i->length)) {
                    error = true;
                    break;
                }
                if (!stream->send_body(body.get(), false, client)) {
                    error = true;
                    break;
                }
            }

            if (!error) {
                body = std::make_shared<String>(handler->get_end_part());
                if (!stream->send_body(body.get(), end_stream, client)) {
                    error = true;
                }
            }
        } else if (tasks[0].length > 0) {
            bool read_ok = false;
            auto callback = [&]() { read_ok = read_range(tasks[0].offset, tasks[0].length); };
            if (swoole_coroutine_is_in()) {
                if (!swoole::coroutine::async(callback)) {
                    error = true;
                }
            } else {
                callback();
            }
            error = error || !read_ok;
            if (!error && !stream->send_body(body.get(), end_stream, client)) {
                error = true;
            }
        }
    }

    if (!error && ztrailer) {
        if (!stream->send_trailer(client)) {
            error = true;
        }
    }

    if (!error) {
        client->remove_stream(ctx->stream_id);
    } else if (client->get_stream(ctx->stream_id)) {
        ctx->close(ctx);
    }

    return true;
}

bool swoole_http2_server_send_file(HttpContext *ctx, zend_string *file, off_t offset, size_t length) {
    Http2WriteDeadline deadline(ctx);
    auto client = http2_sessions[ctx->fd];
    auto stream = client->get_stream(ctx->stream_id);

#ifdef SW_HAVE_COMPRESSION
    ctx->accept_compression = 0;
#endif

    File fp(ZSTR_VAL(file), O_RDONLY);
    if (!fp.ready()) {
        return false;
    }

    zval *ztrailer = sw_zend_read_property_ex(
        swoole_http_response_ce, &ctx->response.zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER), 0);
    if (php_swoole_array_length_safe(ztrailer) == 0) {
        ztrailer = nullptr;
    }

    zval *zheader = sw_zend_read_and_convert_property_array(
        swoole_http_response_ce, &ctx->response.zobject, ZEND_STRL("header"), 0);
    if (!zend_hash_str_exists(Z_ARRVAL_P(zheader), ZEND_STRL("content-type"))) {
        ctx->set_header(ZEND_STRL("content-type"), swoole::mime_type::get({ZSTR_VAL(file), ZSTR_LEN(file)}), false);
    }

    bool end_stream = (ztrailer == nullptr);

    // Compression is disabled above, so send_header() reads only the transfer length.
    String content_length{};
    content_length.length = length;
    if (!stream->send_header(&content_length, end_stream, client)) {
        return false;
    }

    /* headers has already been sent, retries are no longer allowed (even if send body failed) */
    ctx->end_ = 1;

    bool error = false;
    String chunk(SW_FILE_CHUNK_SIZE);
    off_t file_offset = offset;
    size_t remaining = length;

    while (remaining > 0) {
        const size_t read_size = SW_MIN(remaining, chunk.size);
        ssize_t n_read = -1;
        auto read_chunk = [&]() { n_read = fp.pread(chunk.str, read_size, file_offset); };

        if (swoole_coroutine_is_in()) {
            if (!swoole::coroutine::async(read_chunk)) {
                error = true;
                break;
            }
        } else {
            read_chunk();
        }

        // A positive short read is progress; a zero-length read before the requested
        // range ends is a premature end of file.
        if (n_read <= 0) {
            error = true;
            break;
        }

        chunk.length = n_read;
        file_offset += n_read;
        remaining -= n_read;

        const bool last_data = remaining == 0 && !ztrailer;
        if (!stream->send_body(&chunk, last_data, client)) {
            error = true;
            break;
        }
    }

    if (!error && ztrailer) {
        if (!stream->send_trailer(client)) {
            error = true;
        }
    }

    if (!error) {
        client->remove_stream(stream->id);
    } else if (client->get_stream(stream->id)) {
        ctx->close(ctx);
    }

    return !error;
}

static bool http2_server_onBeforeRequest(HttpContext *ctx) {
    auto serv = ctx->get_async_server();
    if (serv->is_unavailable()) {
        String null_body{};
        ctx->response.status = SW_HTTP_SERVICE_UNAVAILABLE;
        http2_server_respond(ctx, &null_body);
        zval_ptr_dtor(&ctx->request.zobject);
        zval_ptr_dtor(&ctx->response.zobject);
        return false;
    }
    return swoole_http_server_onBeforeRequest(ctx);
}

// A semantic field error must not interrupt HPACK decoding of this connection's header block.
static bool http2_server_valid_trailer(const nghttp2_nv &nv) {
    for (size_t i = 0; i < nv.namelen; i++) {
        auto c = nv.name[i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            continue;
        }
        if (c == 0 || !strchr("!#$%&'*+-.^_`|~", c)) {
            return false;
        }
    }
    if (nv.valuelen > 0 && (nv.value[0] == ' ' || nv.value[0] == '\t' || nv.value[nv.valuelen - 1] == ' ' ||
                            nv.value[nv.valuelen - 1] == '\t')) {
        return false;
    }
    for (size_t i = 0; i < nv.valuelen; i++) {
        if ((nv.value[i] < 0x20 && nv.value[i] != '\t') || nv.value[i] == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool http2_server_reject_request(const std::shared_ptr<Http2Session> &client,
                                        const std::shared_ptr<Http2Stream> &stream,
                                        uint32_t error_code) {
    if (!stream->reset(error_code) && http2_server_send_blocked()) {
        return false;
    }
    client->remove_stream(stream->id);
    return true;
}

static void http2_server_complete_request(const std::shared_ptr<Http2Session> &client,
                                          const std::shared_ptr<Http2Stream> &stream) {
    auto ctx = stream->ctx;
    if (ctx->get_http2_data_length() > 0) {
        auto buffer = ctx->get_http2_data_buffer();
        if (ctx->parse_body && ctx->request.post_form_urlencoded) {
            auto post_prop = swoole_http_init_and_read_property(
                swoole_http_request_ce, &ctx->request.zobject, &ctx->request.zpost, ZEND_STRL("post"));
            // treat_data takes ownership of the copied body.
            sapi_module.treat_data(PARSE_STRING, estrndup(buffer->str, buffer->length), post_prop);
        } else if (ctx->mt_parser != nullptr) {
            if (!ctx->parse_multipart_data(buffer->str, buffer->length) ||
                !multipart_parser_is_complete(ctx->mt_parser)) {
                http2_server_send_status_code(ctx, SW_HTTP_BAD_REQUEST);
                client->remove_stream(stream->id);
                return;
            }
        }
    }
    // Set before dispatch: an async handler can yield while this stream receives more frames.
    stream->receive_phase = Http2Stream::ReceivePhase::COMPLETE;
    client->handle(client, stream);
}

static int http2_server_on_headers_complete(HttpContext *ctx) {
    zval *content_type = zend_hash_find(Z_ARR(ctx->request.zheader), SW_ZSTR_KNOWN(SW_ZEND_STR_CONTENT_TYPE));
    if (!content_type) {
        return SW_OK;
    }
    const char *value = Z_STRVAL_P(content_type);
    size_t length = Z_STRLEN_P(content_type);
    if (SW_STR_ISTARTS_WITH(value, length, "application/x-www-form-urlencoded")) {
        ctx->request.post_form_urlencoded = 1;
    } else if (SW_STR_ISTARTS_WITH(value, length, "multipart/form-data")) {
        char *boundary;
        int boundary_length;
        if (!ctx->get_multipart_boundary(
                value, length, sizeof("multipart/form-data") - 1, &boundary, &boundary_length) ||
            !ctx->init_multipart_parser(boundary, boundary_length)) {
            return SW_ERR;
        }
        ctx->parser.data = ctx;
    }
    return SW_OK;
}

static int http2_server_parse_field(const std::shared_ptr<Http2Session> &client,
                                    const std::shared_ptr<Http2Stream> &stream,
                                    const nghttp2_nv &nv,
                                    uint32_t max_headers) {
    auto ctx = stream->ctx;
    zval *zheader = &ctx->request.zheader;
    zval *zserver = &ctx->request.zserver;
    if (stream->header_error != SW_HTTP2_ERROR_NO_ERROR || ctx->end_) {
        return SW_OK;
    }
    if (++stream->header_count > max_headers) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_HTTP2_TOO_MANY_HEADERS,
                         "http2 stream#%d exceeded max_headers limit (%u)",
                         ctx->stream_id,
                         max_headers);
        stream->header_error = SW_HTTP2_ERROR_ENHANCE_YOUR_CALM;
        return SW_OK;
    }
    if (nv.namelen == 0 || (SW_STRCASEEQ((char *) nv.name, nv.namelen, "te") &&
                            !SW_STRCASEEQ((char *) nv.value, nv.valuelen, "trailers"))) {
        stream->header_error = SW_HTTP2_ERROR_PROTOCOL_ERROR;
        return SW_OK;
    }
    if (stream->receive_phase == Http2Stream::ReceivePhase::TRAILERS) {
        if (!http2_server_valid_trailer(nv)) {
            stream->header_error = SW_HTTP2_ERROR_PROTOCOL_ERROR;
            return SW_OK;
        }
        zval value;
        ZVAL_STRINGL(&value, (const char *) nv.value, nv.valuelen);
        zend::array_add_or_merge(&ctx->request.ztrailer, (const char *) nv.name, nv.namelen, &value);
        return SW_OK;
    }

    swoole_trace_log(SW_TRACE_HTTP2,
                     "name=(%zu)[" SW_ECHO_BLUE "], value=(%zu)[" SW_ECHO_CYAN "]",
                     nv.namelen,
                     nv.name,
                     nv.valuelen,
                     nv.value);

    if (nv.name[0] == ':') {
        if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "method")) {
            add_assoc_stringl_ex(zserver, ZEND_STRL("request_method"), (char *) nv.value, nv.valuelen);
            // The response may be ended after the request object and its server array are freed.
            if (SW_STRCASEEQ((char *) nv.value, nv.valuelen, "HEAD")) {
                ctx->parser.method = HTTP_HEAD;
            }
        } else if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "path")) {
            const char *v_str = (const char *) memchr(nv.value, '?', nv.valuelen);
            zend_string *zstr_path;
            if (v_str) {
                v_str++;
                size_t k_len = v_str - (const char *) nv.value - 1;
                size_t v_len = nv.valuelen - k_len - 1;
                add_assoc_stringl_ex(zserver, ZEND_STRL("query_string"), v_str, v_len);
                zstr_path = zend_string_init((char *) nv.value, k_len, false);
                // parse url params
                sapi_module.treat_data(
                    PARSE_STRING,
                    estrndup(v_str, v_len),  // it will be freed by treat_data
                    swoole_http_init_and_read_property(
                        swoole_http_request_ce, &ctx->request.zobject, &ctx->request.zget, ZEND_STRL("get")));
            } else {
                zstr_path = zend_string_init((char *) nv.value, nv.valuelen, false);
            }
            // A repeated :path must not leak the previous value.
            if (ctx->request.path) {
                zend_string_release(ctx->request.path);
            }
            ctx->request.path =
                v_str ? zend_string_init((char *) nv.value, nv.valuelen, false) : zend_string_copy(zstr_path);
            add_assoc_str_ex(zserver, ZEND_STRL("request_uri"), zstr_path);
            // path_info should be decoded
            zstr_path = zend_string_dup(zstr_path, false);
            ZSTR_LEN(zstr_path) = php_url_decode(ZSTR_VAL(zstr_path), ZSTR_LEN(zstr_path));
            add_assoc_str_ex(zserver, ZEND_STRL("path_info"), zstr_path);
        } else if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "authority")) {
            add_assoc_stringl_ex(zheader, ZEND_STRL("host"), (char *) nv.value, nv.valuelen);
        }
    } else {
        if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "content-type")) {
            // Only the last value configures body parsing, after the complete initial header block.
            zval value;
            ZVAL_STRINGL(&value, (const char *) nv.value, nv.valuelen);
            zend_hash_update(Z_ARR_P(zheader), SW_ZSTR_KNOWN(SW_ZEND_STR_CONTENT_TYPE), &value);
            return SW_OK;
        } else if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "cookie")) {
            swoole_http_parse_cookie(
                swoole_http_init_and_read_property(
                    swoole_http_request_ce, &ctx->request.zobject, &ctx->request.zcookie, ZEND_STRL("cookie")),
                (const char *) nv.value,
                nv.valuelen);
            // RFC 9113 requires separate Cookie fields to be joined with "; " when forwarding them.
            zval *previous = zend_hash_str_find(Z_ARRVAL_P(zheader), ZEND_STRL("cookie"));
            if (previous) {
                zend_string *cookie =
                    zend_string_append(Z_STR_P(previous), ZEND_STRL("; "), (const char *) nv.value, nv.valuelen);
                ZVAL_STR(previous, cookie);
            } else {
                add_assoc_stringl_ex(zheader, ZEND_STRL("cookie"), (const char *) nv.value, nv.valuelen);
            }
            return SW_OK;
        } else if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "content-length")) {
            if (!Http2::parse_content_length((char *) nv.value, nv.valuelen, client->max_body_size, nullptr)) {
                // The rest of the block is still decoded for HPACK; the stream is reset after it. The 413's header
                // block is already encoded, so if it isn't sent the connection's HPACK state is out of sync.
                if (!http2_server_send_status_code(ctx, SW_HTTP_REQUEST_ENTITY_TOO_LARGE)) {
                    return SW_ERR;
                }
                return SW_OK;
            }
        }
#ifdef SW_HAVE_COMPRESSION
        else if (ctx->enable_compression && SW_STRCASEEQ((char *) nv.name, nv.namelen, "accept-encoding")) {
            ctx->set_compression_method((char *) nv.value, nv.valuelen);
        }
#endif
        add_assoc_stringl_ex(zheader, (char *) nv.name, nv.namelen, (char *) nv.value, nv.valuelen);
    }
    return SW_OK;
}

static int http2_server_parse_header(const std::shared_ptr<Http2Session> &client,
                                     const std::shared_ptr<Http2Stream> &stream,
                                     int flags,
                                     const char *in,
                                     size_t inlen) {
    nghttp2_hd_inflater *inflater = client->inflater;

    if (!inflater) {
        int ret = nghttp2_hd_inflate_new2(&inflater, php_nghttp2_mem());
        if (ret != 0) {
            swoole_warning("nghttp2_hd_inflate_new2() failed, Error: %s[%d]", nghttp2_strerror(ret), ret);
            return SW_ERR;
        }
        client->inflater = inflater;
    }

    uint32_t max_headers = Http2::get_http2_max_headers();

    for (;;) {
        nghttp2_nv nv;
        int inflate_flags = 0;

        ssize_t rv = nghttp2_hd_inflate_hd(
            inflater, &nv, &inflate_flags, (uchar *) in, inlen, (flags & SW_HTTP2_FLAG_END_HEADERS) != 0);
        if (rv < 0) {
            swoole_warning("inflate failed, Error: %s[%zd]", nghttp2_strerror(rv), rv);
            return SW_ERR;
        }

        auto proclen = (size_t) rv;

        in += proclen;
        inlen -= proclen;

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            if (!stream) {
                // Trailers can't carry pseudo-headers, so this is a new request on a closed stream.
                if (nv.namelen > 0 && nv.name[0] == ':') {
                    return SW_ERR;
                }
            } else if (http2_server_parse_field(client, stream, nv, max_headers) < 0) {
                return SW_ERR;
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

int swoole_http2_server_parse(const std::shared_ptr<Http2Session> &client, const char *buf) {
    int type = buf[3];
    int flags = buf[4];

    uint32_t stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;

    if (client->shutting_down) {
        swoole_error_log(
            SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_IGNORE, "ignore http2 stream#%d after sending goaway", stream_id);
        return SW_ERR;
    }

    ssize_t length = Http2::get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    uint32_t value = 0;

    if (client->continuation_stream_id != 0 &&
        (type != SW_HTTP2_TYPE_CONTINUATION || stream_id != client->continuation_stream_id)) {
        return SW_ERR;
    }

    switch (type) {
    case SW_HTTP2_TYPE_SETTINGS: {
        uint16_t id = 0;
        if (flags & SW_HTTP2_FLAG_ACK) {
            swoole_http2_frame_trace_log("ACK");
            break;
        }

        if (length % (sizeof(uint16_t) + sizeof(uint32_t)) != 0) {
            return SW_ERR;
        }

        while (length > 0) {
            id = ntohs(*(uint16_t *) (buf));
            value = ntohl(*(uint32_t *) (buf + sizeof(uint16_t)));
            swoole_http2_frame_trace_log("id=%d, value=%d", id, value);
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
                if (value > INT32_MAX) {
                    http2_server_abort(client, SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "invalid initial window");
                    return SW_ERR;
                }
                {
                    int64_t delta = int64_t(value) - client->remote_settings.init_window_size;
                    for (const auto &entry : client->streams) {
                        if (entry.second->remote_window_size + delta > INT32_MAX) {
                            http2_server_abort(client, SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "stream window overflow");
                            return SW_ERR;
                        }
                    }
                    for (const auto &entry : client->streams) {
                        entry.second->remote_window_size += delta;
                    }
                    client->remote_settings.init_window_size = value;
                    client->notify_flow_control_waiters();
                }
                swoole_trace_log(SW_TRACE_HTTP2, "setting: init_window_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                if (value < SW_HTTP2_DEFAULT_MAX_FRAME_SIZE || value > SW_HTTP2_MAX_FRAME_SIZE) {
                    swoole_warning("invalid SETTINGS_MAX_FRAME_SIZE value %u", value);
                    client->default_ctx->close(client->default_ctx);
                    return SW_ERR;
                }
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
        // After receiving the setting frame sent by the client, it is necessary to reply with an ACK,
        // otherwise the client will assume that the server has not applied the setting
        if (!http2_server_send_setting_ack(client->default_ctx) && http2_server_send_blocked()) {
            return SW_ERR;
        }
        break;
    }
    case SW_HTTP2_TYPE_HEADERS:
    case SW_HTTP2_TYPE_CONTINUATION: {
        auto stream = client->get_stream(stream_id);
        if (type == SW_HTTP2_TYPE_HEADERS) {
            if (stream_id == 0 || !(stream_id & 1)) {
                return SW_ERR;
            }
            if (!stream && stream_id > client->last_stream_id) {
                bool refused = client->streams.size() >= client->local_settings.max_concurrent_streams;
                stream = client->create_stream(stream_id);
                if (!stream) {
                    return SW_ERR;
                }
                client->last_stream_id = stream_id;
                if (refused) {
                    swoole_error_log(SW_LOG_WARNING,
                                     SW_ERROR_HTTP2_TOO_MANY_STREAMS,
                                     "http2 stream#%d refused, max_concurrent_streams limit (%u) reached",
                                     stream_id,
                                     client->local_settings.max_concurrent_streams);
                    // Decode even refused streams to preserve the connection's HPACK state.
                    stream->header_error = SW_HTTP2_ERROR_REFUSED_STREAM;
                }
            } else if (!stream) {
                // RFC 9113 §5.1: a block on a closed stream, such as trailers sent before the client received our
                // RST_STREAM, is decoded to keep HPACK state and then discarded.
            } else if (stream->receive_phase == Http2Stream::ReceivePhase::BODY) {
                stream->receive_phase = Http2Stream::ReceivePhase::TRAILERS;
                swoole_http_init_and_read_property(swoole_http_request_ce,
                                                   &stream->ctx->request.zobject,
                                                   &stream->ctx->request.ztrailer,
                                                   SW_ZSTR_KNOWN(SW_ZEND_STR_TRAILER));
                if (!(flags & SW_HTTP2_FLAG_END_STREAM)) {
                    stream->header_error = SW_HTTP2_ERROR_PROTOCOL_ERROR;
                }
            } else {
                stream->header_error = SW_HTTP2_ERROR_STREAM_CLOSED;
            }
            if (stream) {
                stream->header_count = 0;
                stream->header_end_stream = flags & SW_HTTP2_FLAG_END_STREAM;
            }
            if (flags & SW_HTTP2_FLAG_PADDED) {
                if (length < 1) {
                    return SW_ERR;
                }
                uint8_t padding = (uint8_t) *buf++;
                if (padding > --length) {
                    return SW_ERR;
                }
                length -= padding;
            }
            if (flags & SW_HTTP2_FLAG_PRIORITY) {
                if (length < SW_HTTP2_PRIORITY_SIZE) {
                    return SW_ERR;
                }
                buf += SW_HTTP2_PRIORITY_SIZE;
                length -= SW_HTTP2_PRIORITY_SIZE;
            }
        } else if (client->continuation_stream_id == 0) {
            return SW_ERR;
        }

        if (http2_server_parse_header(client, stream, flags, buf, length) < 0) {
            return SW_ERR;
        }
        if (!(flags & SW_HTTP2_FLAG_END_HEADERS)) {
            client->continuation_stream_id = stream_id;
            break;
        }
        client->continuation_stream_id = 0;
        if (!stream) {
            break;
        }
        // The response has already ended when the content-length is over the limit.
        if (stream->header_error != SW_HTTP2_ERROR_NO_ERROR || stream->ctx->end_) {
            if (!http2_server_reject_request(client, stream, stream->header_error)) {
                return SW_ERR;
            }
            break;
        }
        if (stream->receive_phase == Http2Stream::ReceivePhase::HEADERS &&
            http2_server_on_headers_complete(stream->ctx) < 0) {
            return SW_ERR;
        }
        if (stream->header_end_stream) {
            http2_server_complete_request(client, stream);
        } else {
            stream->receive_phase = Http2Stream::ReceivePhase::BODY;
        }
        break;
    }
    case SW_HTTP2_TYPE_DATA: {
        swoole_http2_frame_trace_log("data");
        auto stream = client->get_stream(stream_id);
        if (!stream && (!(stream_id & 1) || stream_id > client->last_stream_id)) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP2_STREAM_NOT_FOUND, "http2 stream#%d not found", stream_id);
            return SW_ERR;
        }

        // Count the complete DATA payload, including padding, even when this stream has already been reset.
        if (length > client->local_window_size) {
            http2_server_abort(client, SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "connection receive window exceeded");
            return SW_ERR;
        }
        client->local_window_size -= length;
        const uint32_t connection_target =
            std::max(client->local_settings.init_window_size, uint32_t(SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE));
        if (client->local_window_size <= connection_target / 2) {
            uint32_t increment = connection_target - client->local_window_size;
            if (!http2_server_send_window_update(client->default_ctx, 0, increment)) {
                return SW_ERR;
            }
            client->local_window_size += increment;
        }

        // RFC 9113 §5.1: the client may have sent DATA before it received our RST_STREAM.
        if (!stream) {
            break;
        }

        if (stream->receive_phase != Http2Stream::ReceivePhase::BODY) {
            if (!http2_server_reject_request(client, stream, SW_HTTP2_ERROR_STREAM_CLOSED)) {
                return SW_ERR;
            }
            break;
        }

        HttpContext *ctx = stream->ctx;
        if (length > stream->local_window_size) {
            if (!http2_server_reject_request(client, stream, SW_HTTP2_ERROR_FLOW_CONTROL_ERROR)) {
                return SW_ERR;
            }
            break;
        }
        stream->local_window_size -= length;
        const char *data = buf;
        ssize_t data_length = length;
        if (flags & SW_HTTP2_FLAG_PADDED) {
            if (data_length == 0 || uint8_t(*data) >= data_length) {
                http2_server_abort(client, SW_HTTP2_ERROR_PROTOCOL_ERROR, "invalid DATA padding");
                return SW_ERR;
            }
            data_length -= 1 + uint8_t(*data++);
        }
        if (data_length > 0) {
            auto buffer = ctx->get_http2_data_buffer();
            if (buffer->length + data_length > client->max_body_size) {
                if (!http2_server_send_status_code(ctx, SW_HTTP_REQUEST_ENTITY_TOO_LARGE) ||
                    !http2_server_reject_request(client, stream, SW_HTTP2_ERROR_NO_ERROR)) {
                    return SW_ERR;
                }
                break;
            }
            buffer->append(data, data_length);
        }
        if (client->local_settings.init_window_size > 0 &&
            stream->local_window_size <= client->local_settings.init_window_size / 2) {
            uint32_t increment = client->local_settings.init_window_size - stream->local_window_size;
            if (!http2_server_send_window_update(ctx, stream_id, increment)) {
                return SW_ERR;
            }
            stream->local_window_size += increment;
        }

        if (flags & SW_HTTP2_FLAG_END_STREAM) {
            http2_server_complete_request(client, stream);
        }
        break;
    }
    case SW_HTTP2_TYPE_PING: {
        swoole_http2_frame_trace_log("ping");
        if (length != SW_HTTP2_FRAME_PING_PAYLOAD_SIZE) {
            return SW_ERR;
        }
        if (!(flags & SW_HTTP2_FLAG_ACK)) {
            char ping_frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];
            Http2::set_frame_header(
                ping_frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_ACK, stream_id);
            memcpy(ping_frame + SW_HTTP2_FRAME_HEADER_SIZE, buf, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
            if (!client->default_ctx->send(
                    client->default_ctx, ping_frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE) &&
                http2_server_send_blocked()) {
                return SW_ERR;
            }
        }
        break;
    }
    case SW_HTTP2_TYPE_WINDOW_UPDATE: {
        if (length != SW_HTTP2_WINDOW_UPDATE_SIZE) {
            http2_server_abort(client, SW_HTTP2_ERROR_FRAME_SIZE_ERROR, "invalid WINDOW_UPDATE length");
            return SW_ERR;
        }
        value = ntohl(*(uint32_t *) buf) & 0x7fffffff;
        if (stream_id == 0) {
            if (value == 0 || client->remote_window_size + value > INT32_MAX) {
                http2_server_abort(client,
                                   value == 0 ? SW_HTTP2_ERROR_PROTOCOL_ERROR : SW_HTTP2_ERROR_FLOW_CONTROL_ERROR,
                                   "invalid connection WINDOW_UPDATE");
                return SW_ERR;
            }
            client->remote_window_size += value;
        } else {
            if (!(stream_id & 1) || stream_id > client->last_stream_id) {
                http2_server_abort(client, SW_HTTP2_ERROR_PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream");
                return SW_ERR;
            }
            auto stream = client->get_stream(stream_id);
            if (stream) {
                if (value == 0 || stream->remote_window_size + value > INT32_MAX) {
                    if (!http2_server_reject_request(
                            client,
                            stream,
                            value == 0 ? SW_HTTP2_ERROR_PROTOCOL_ERROR : SW_HTTP2_ERROR_FLOW_CONTROL_ERROR)) {
                        return SW_ERR;
                    }
                    break;
                }
                stream->remote_window_size += value;
            }
        }
        client->notify_flow_control_waiters();
        swoole_http2_frame_trace_log("window_size_increment=%d", value);
        break;
    }
    case SW_HTTP2_TYPE_RST_STREAM: {
        if (length != SW_HTTP2_RST_STREAM_SIZE) {
            return SW_ERR;
        }
        value = ntohl(*(int *) (buf));
        swoole_http2_frame_trace_log("error_code=%d", value);
        if (auto stream = client->take_stream(stream_id)) {
            // The stream is already inactive before either form of wakeup can reenter PHP.
            if (stream->request_cid != 0) {
                auto *task = swoole::PHPCoroutine::get_context_by_cid(stream->request_cid);
                if (task && task->callback_running) {
                    zend::Variable reason;
                    array_init_size(reason.ptr(), 4);
                    add_assoc_long(reason.ptr(), "session_id", client->fd);
                    add_assoc_long(reason.ptr(), "stream_id", stream_id);
                    add_assoc_long(reason.ptr(), "code", value);
                    add_assoc_string(reason.ptr(), "message", "HTTP2 Stream Reset");
                    // Preserve the original send queue position for an encoded HPACK block.
                    const bool wake = !task->http2_header_send_pending;
                    php_swoole_coroutine_throw_exception(stream->request_cid, true, nullptr, reason.ptr(), wake);
                }
            }
            client->notify_flow_control_waiters();
        }
        break;
    }
    case SW_HTTP2_TYPE_GOAWAY: {
        if (length < SW_HTTP2_GOAWAY_SIZE) {
            return SW_ERR;
        }
        uint32_t server_last_stream_id = ntohl(*(uint32_t *) (buf));
        buf += 4;
        value = ntohl(*(uint32_t *) (buf));
        buf += 4;
        swoole_http2_frame_trace_log("last_stream_id=%d, error_code=%d, opaque_data=[%.*s]",
                                     server_last_stream_id,
                                     value,
                                     (int) (length - SW_HTTP2_GOAWAY_SIZE),
                                     buf);
        // TODO: onRequest
        (void) server_last_stream_id;

        break;
    }
    default: {
        swoole_http2_frame_trace_log("");
    }
    }

    return SW_OK;
}

#ifndef _WIN32
int swoole_http2_server_onReceive(Server *serv, Connection *conn, RecvData *req) {
    SessionId session_id = req->info.fd;
    auto iter = http2_sessions.find(session_id);
    std::shared_ptr<Http2Session> client;
    if (iter == http2_sessions.end()) {
        client = swoole_http2_server_session_new(session_id);
        client->default_ctx = new HttpContext();
        client->default_ctx->init(serv);
        client->default_ctx->fd = session_id;
        client->default_ctx->http2 = true;
        client->default_ctx->keepalive = true;
        client->default_ctx->onBeforeRequest = http2_server_onBeforeRequest;
        client->max_body_size = serv->get_package_max_length(conn);
        client->handle = http2_server_onRequest;
    } else {
        client = iter->second;
    }

    zval zdata;
    php_swoole_get_recv_data(serv, &zdata, req);
    int retval = swoole_http2_server_parse(client, Z_STRVAL(zdata));
    if (retval < 0) {
        client->default_ctx->close(client->default_ctx);
    }

    zval_ptr_dtor(&zdata);
    return SW_OK;
}

void php_swoole_http2_server_onClose(Server *serv, SessionId session_id) {
    swoole_http2_server_session_free(session_id);
}
#endif

std::shared_ptr<Http2Session> swoole_http2_server_session_new(SessionId fd) {
    auto session = std::make_shared<Http2Session>(fd);
    http2_sessions.emplace(fd, session);
    return session;
}

void swoole_http2_server_session_free(SessionId session_id) {
    auto iter = http2_sessions.find(session_id);
    if (iter == http2_sessions.end()) {
        return;
    }
    auto session = iter->second;
    if (session->is_coro) {
        // A coroutine session borrows default_ctx from its request/response objects; an async session owns it.
        session->default_ctx = nullptr;
    }
    while (!session->streams.empty()) {
        session->remove_stream(session->streams.begin()->first);
    }
    http2_sessions.erase(iter);
}

void swoole_http2_server_release_sessions() {
    while (!http2_sessions.empty()) {
        swoole_http2_server_session_free(http2_sessions.begin()->first);
    }
}
