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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_http3.h"
#include "swoole_string.h"

#ifdef SW_USE_HTTP3

#include <string.h>

using namespace swoole;
using namespace swoole::http3;

// ==================== Helper Functions ====================

const char* swoole::http3::get_error_string(uint64_t error_code) {
    switch (error_code) {
    case SW_HTTP3_NO_ERROR:
        return "NO_ERROR";
    case SW_HTTP3_GENERAL_PROTOCOL_ERROR:
        return "GENERAL_PROTOCOL_ERROR";
    case SW_HTTP3_INTERNAL_ERROR:
        return "INTERNAL_ERROR";
    case SW_HTTP3_STREAM_CREATION_ERROR:
        return "STREAM_CREATION_ERROR";
    case SW_HTTP3_CLOSED_CRITICAL_STREAM:
        return "CLOSED_CRITICAL_STREAM";
    case SW_HTTP3_FRAME_UNEXPECTED:
        return "FRAME_UNEXPECTED";
    case SW_HTTP3_FRAME_ERROR:
        return "FRAME_ERROR";
    case SW_HTTP3_EXCESSIVE_LOAD:
        return "EXCESSIVE_LOAD";
    case SW_HTTP3_ID_ERROR:
        return "ID_ERROR";
    case SW_HTTP3_SETTINGS_ERROR:
        return "SETTINGS_ERROR";
    case SW_HTTP3_MISSING_SETTINGS:
        return "MISSING_SETTINGS";
    case SW_HTTP3_REQUEST_REJECTED:
        return "REQUEST_REJECTED";
    case SW_HTTP3_REQUEST_CANCELLED:
        return "REQUEST_CANCELLED";
    case SW_HTTP3_REQUEST_INCOMPLETE:
        return "REQUEST_INCOMPLETE";
    case SW_HTTP3_MESSAGE_ERROR:
        return "MESSAGE_ERROR";
    case SW_HTTP3_CONNECT_ERROR:
        return "CONNECT_ERROR";
    case SW_HTTP3_VERSION_FALLBACK:
        return "VERSION_FALLBACK";
    case SW_HTTP3_QPACK_DECOMPRESSION_FAILED:
        return "QPACK_DECOMPRESSION_FAILED";
    case SW_HTTP3_QPACK_ENCODER_STREAM_ERROR:
        return "QPACK_ENCODER_STREAM_ERROR";
    case SW_HTTP3_QPACK_DECODER_STREAM_ERROR:
        return "QPACK_DECODER_STREAM_ERROR";
    default:
        return "UNKNOWN_ERROR";
    }
}

nghttp3_nv swoole::http3::make_nv(const char *name, const char *value, bool never_index) {
    nghttp3_nv nv;
    nv.name = (uint8_t *) name;
    nv.namelen = strlen(name);
    nv.value = (uint8_t *) value;
    nv.valuelen = strlen(value);
    nv.flags = never_index ? NGHTTP3_NV_FLAG_NEVER_INDEX : NGHTTP3_NV_FLAG_NONE;
    return nv;
}

nghttp3_nv swoole::http3::make_nv(const std::string &name, const std::string &value, bool never_index) {
    nghttp3_nv nv;
    nv.name = (uint8_t *) name.c_str();
    nv.namelen = name.length();
    nv.value = (uint8_t *) value.c_str();
    nv.valuelen = value.length();
    nv.flags = never_index ? NGHTTP3_NV_FLAG_NEVER_INDEX : NGHTTP3_NV_FLAG_NONE;
    return nv;
}

// ==================== HTTP/3 Stream Implementation ====================

Stream::Stream(int64_t id, Connection *c, swoole::quic::Stream *qs)
    : stream_id(id),
      conn(c),
      quic_stream(qs),
      type(SW_HTTP3_STREAM_TYPE_REQUEST),
      http3_conn(nullptr),
      body(nullptr),
      status_code(0),
      headers_complete(0),
      body_complete(0),
      is_request(0),
      is_response(0),
      user_data(nullptr) {

    body = new swoole::String(SW_BUFFER_SIZE_STD);

    if (qs) {
        qs->user_data = this;
    }
}

Stream::~Stream() {
    headers.clear();

    if (body) {
        delete body;
    }
}

void Stream::add_header(const std::string &name, const std::string &value, bool never_index) {
    headers.emplace_back(name, value, never_index);
}

const char* Stream::get_header(const std::string &name) {
    for (auto &hf : headers) {
        if (hf.name == name) {
            return hf.value.c_str();
        }
    }
    return nullptr;
}

// Callback to read response body data for nghttp3
static nghttp3_ssize stream_read_data_callback(nghttp3_conn *conn, int64_t stream_id,
                                                nghttp3_vec *vec, size_t veccnt,
                                                uint32_t *pflags, void *user_data,
                                                void *stream_user_data) {
    Stream *stream = (Stream *) stream_user_data;
    if (!stream || !stream->body) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    size_t body_len = stream->body->length;
    if (body_len == 0) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    // Provide the body data
    if (veccnt > 0) {
        vec[0].base = (uint8_t *) stream->body->str;
        vec[0].len = body_len;
        *pflags |= NGHTTP3_DATA_FLAG_EOF;  // All data sent at once
        return 1;  // Number of vec entries filled
    }

    return 0;
}

bool Stream::send_headers(const std::vector<HeaderField> &hdrs, bool fin) {
    if (!conn || !conn->conn || !quic_stream) {
        return false;
    }

    // Convert headers to nghttp3_nv array
    std::vector<nghttp3_nv> nva;
    nva.reserve(hdrs.size());

    for (const auto &hf : hdrs) {
        nva.push_back(make_nv(hf.name, hf.value, hf.never_index));
    }

    nghttp3_data_reader data_reader;
    data_reader.read_data = stream_read_data_callback;

    int rv = nghttp3_conn_submit_response(conn->conn, stream_id,
                                           nva.data(), nva.size(),
                                           fin ? nullptr : &data_reader);

    if (rv != 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP3_SEND,
                         "nghttp3_conn_submit_response failed: %s", nghttp3_strerror(rv));
        return false;
    }

    return true;
}

bool Stream::send_body(const uint8_t *data, size_t len, bool fin) {
    if (!conn || !conn->conn || !quic_stream) {
        return false;
    }

    // Store data in buffer for later transmission
    if (len > 0) {
        body->append((const char *) data, len);
    }

    // The actual sending will be done in write_streams()
    return true;
}

bool Stream::send_response(int status, const std::vector<HeaderField> &hdrs,
                            const uint8_t *body_data, size_t body_len) {
    std::vector<HeaderField> response_hdrs;
    response_hdrs.emplace_back(":status", std::to_string(status));

    for (const auto &hf : hdrs) {
        response_hdrs.push_back(hf);
    }

    bool has_body = (body_data != nullptr && body_len > 0);

    if (!send_headers(response_hdrs, !has_body)) {
        return false;
    }

    if (has_body) {
        return send_body(body_data, body_len, true);
    }

    return true;
}

bool Stream::recv_headers(const nghttp3_nv *nva, size_t nvlen) {
    for (size_t i = 0; i < nvlen; i++) {
        std::string name((const char *) nva[i].name, nva[i].namelen);
        std::string value((const char *) nva[i].value, nva[i].valuelen);

        // Handle pseudo-headers
        if (name[0] == ':') {
            if (name == ":method") {
                method = value;
            } else if (name == ":path") {
                path = value;
            } else if (name == ":scheme") {
                scheme = value;
            } else if (name == ":authority") {
                authority = value;
            } else if (name == ":status") {
                status_code = std::stoi(value);
            }
        }

        headers.emplace_back(name, value, false);
    }

    headers_complete = 1;
    return true;
}

bool Stream::recv_body(const uint8_t *data, size_t len) {
    if (len > 0) {
        body->append((const char *) data, len);
    }
    return true;
}

bool Stream::close() {
    if (quic_stream) {
        quic_stream->close();
    }
    return true;
}

// ==================== Request/Response Builder Implementation ====================

RequestBuilder& RequestBuilder::set_method(const std::string &m) {
    method = m;
    return *this;
}

RequestBuilder& RequestBuilder::set_scheme(const std::string &s) {
    scheme = s;
    return *this;
}

RequestBuilder& RequestBuilder::set_authority(const std::string &a) {
    authority = a;
    return *this;
}

RequestBuilder& RequestBuilder::set_path(const std::string &p) {
    path = p;
    return *this;
}

RequestBuilder& RequestBuilder::add_header(const std::string &name, const std::string &value) {
    headers.emplace_back(name, value);
    return *this;
}

RequestBuilder& RequestBuilder::set_body(const std::string &b) {
    body = b;
    return *this;
}

std::vector<HeaderField> RequestBuilder::build_headers() {
    std::vector<HeaderField> result;

    result.emplace_back(":method", method);
    result.emplace_back(":scheme", scheme);
    result.emplace_back(":authority", authority);
    result.emplace_back(":path", path);

    for (const auto &hf : headers) {
        result.push_back(hf);
    }

    if (!body.empty()) {
        result.emplace_back("content-length", std::to_string(body.length()));
    }

    return result;
}

ResponseBuilder& ResponseBuilder::set_status(int s) {
    status = s;
    return *this;
}

ResponseBuilder& ResponseBuilder::add_header(const std::string &name, const std::string &value) {
    headers.emplace_back(name, value);
    return *this;
}

ResponseBuilder& ResponseBuilder::set_body(const std::string &b) {
    body = b;
    return *this;
}

std::vector<HeaderField> ResponseBuilder::build_headers() {
    std::vector<HeaderField> result;

    result.emplace_back(":status", std::to_string(status));

    for (const auto &hf : headers) {
        result.push_back(hf);
    }

    if (!body.empty()) {
        result.emplace_back("content-length", std::to_string(body.length()));
    }

    return result;
}

// ==================== HTTP/3 Connection Callbacks ====================

static int on_recv_header(nghttp3_conn *conn, int64_t stream_id,
                           int32_t token, nghttp3_rcbuf *name,
                           nghttp3_rcbuf *value, uint8_t flags,
                           void *user_data, void *stream_user_data) {
    Connection *h3conn = (Connection *) user_data;
    Stream *stream = (Stream *) stream_user_data;

    if (!stream) {
        stream = h3conn->get_stream(stream_id);
    }

    if (stream) {
        std::string n((const char *) nghttp3_rcbuf_get_buf(name).base,
                      nghttp3_rcbuf_get_buf(name).len);
        std::string v((const char *) nghttp3_rcbuf_get_buf(value).base,
                      nghttp3_rcbuf_get_buf(value).len);

        // Handle pseudo-headers
        if (!n.empty() && n[0] == ':') {
            if (n == ":method") {
                stream->method = v;
            } else if (n == ":path") {
                stream->path = v;
            } else if (n == ":scheme") {
                stream->scheme = v;
            } else if (n == ":authority") {
                stream->authority = v;
            } else if (n == ":status") {
                stream->status_code = std::stoi(v);
            }
        }

        stream->add_header(n, v, (flags & NGHTTP3_NV_FLAG_NEVER_INDEX) != 0);
    }

    return 0;
}

static int on_end_headers(nghttp3_conn *conn, int64_t stream_id,
                           int fin, void *user_data, void *stream_user_data) {
    Connection *h3conn = (Connection *) user_data;
    Stream *stream = (Stream *) stream_user_data;

    if (!stream) {
        stream = h3conn->get_stream(stream_id);
    }

    if (stream) {
        stream->headers_complete = 1;

        if (h3conn->on_recv_header) {
            h3conn->on_recv_header(h3conn, stream);
        }
    }

    return 0;
}

static int on_recv_data(nghttp3_conn *conn, int64_t stream_id,
                         const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data) {
    Connection *h3conn = (Connection *) user_data;
    Stream *stream = (Stream *) stream_user_data;

    if (!stream) {
        stream = h3conn->get_stream(stream_id);
    }

    if (stream) {
        stream->recv_body(data, datalen);

        if (h3conn->on_recv_body) {
            h3conn->on_recv_body(h3conn, stream, data, datalen);
        }
    }

    return 0;
}

static int on_end_stream(nghttp3_conn *conn, int64_t stream_id,
                          void *user_data, void *stream_user_data) {
    Connection *h3conn = (Connection *) user_data;
    Stream *stream = (Stream *) stream_user_data;

    if (!stream) {
        stream = h3conn->get_stream(stream_id);
    }

    if (stream) {
        stream->body_complete = 1;

        if (h3conn->on_recv_data_complete) {
            h3conn->on_recv_data_complete(h3conn, stream);
        }
    }

    return 0;
}

static int on_stream_close(nghttp3_conn *conn, int64_t stream_id,
                            uint64_t app_error_code, void *user_data,
                            void *stream_user_data) {
    Connection *h3conn = (Connection *) user_data;
    Stream *stream = (Stream *) stream_user_data;

    if (!stream) {
        stream = h3conn->get_stream(stream_id);
    }

    if (stream) {
        if (h3conn->on_stream_close) {
            h3conn->on_stream_close(h3conn, stream);
        }

        h3conn->close_stream(stream_id);
    }

    return 0;
}

static int on_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                            uint64_t app_error_code, void *user_data,
                            void *stream_user_data) {
    swoole_trace("HTTP/3: stop_sending stream=%ld, error=%lu", stream_id, app_error_code);
    return 0;
}

static int on_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                            uint64_t app_error_code, void *user_data,
                            void *stream_user_data) {
    swoole_trace("HTTP/3: reset_stream stream=%ld, error=%lu", stream_id, app_error_code);
    return 0;
}

// ==================== HTTP/3 Connection Implementation ====================

Connection::Connection(swoole::quic::Connection *qc)
    : quic_conn(qc),
      conn(nullptr),
      next_stream_id(0),
      control_stream_id(-1),
      qpack_enc_stream_id(-1),
      qpack_dec_stream_id(-1),
      on_stream_open(nullptr),
      on_stream_close(nullptr),
      on_recv_header(nullptr),
      on_recv_body(nullptr),
      on_recv_data_complete(nullptr),
      user_data(nullptr),
      is_server(0),
      control_stream_opened(0),
      qpack_streams_opened(0) {

    memset(&settings, 0, sizeof(settings));
    setup_settings(&settings);

    // QPACK encoder/decoder are managed by nghttp3_conn internally
    // nghttp3_qpack_encoder_init(&qpack_enc);
    // nghttp3_qpack_decoder_init(&qpack_dec, SW_HTTP3_MAX_TABLE_CAPACITY, SW_HTTP3_MAX_BLOCKED_STREAMS);

    if (qc) {
        qc->user_data = this;
    }
}

Connection::~Connection() {
    for (auto &pair : streams) {
        delete pair.second;
    }
    streams.clear();

    if (conn) {
        nghttp3_conn_del(conn);
        conn = nullptr;
    }

    // QPACK encoder/decoder are managed by nghttp3_conn internally
    // nghttp3_qpack_encoder_free(&qpack_enc);
    // nghttp3_qpack_decoder_free(&qpack_dec);
}

nghttp3_callbacks Connection::create_callbacks() {
    nghttp3_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));

    callbacks.recv_header = ::on_recv_header;
    callbacks.end_headers = ::on_end_headers;
    callbacks.recv_data = ::on_recv_data;
    callbacks.end_stream = ::on_end_stream;
    callbacks.stream_close = ::on_stream_close;
    callbacks.stop_sending = ::on_stop_sending;
    callbacks.reset_stream = ::on_reset_stream;

    return callbacks;
}

void Connection::setup_settings(nghttp3_settings *settings) {
    nghttp3_settings_default(settings);
    settings->qpack_max_dtable_capacity = SW_HTTP3_MAX_TABLE_CAPACITY;
    settings->qpack_blocked_streams = SW_HTTP3_MAX_BLOCKED_STREAMS;
    settings->max_field_section_size = SW_HTTP3_MAX_FIELD_SECTION_SIZE;
}

bool Connection::init_server() {
    is_server = 1;

    nghttp3_callbacks callbacks = create_callbacks();
    nghttp3_settings settings;
    setup_settings(&settings);

    int rv = nghttp3_conn_server_new(&conn, &callbacks, &settings, nullptr, this);
    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_HTTP3_INIT,
                         "nghttp3_conn_server_new failed: %s", nghttp3_strerror(rv));
        return false;
    }

    nghttp3_conn_set_max_client_streams_bidi(conn, SW_QUIC_MAX_STREAMS);

    return open_control_streams();
}

bool Connection::init_client() {
    is_server = 0;

    nghttp3_callbacks callbacks = create_callbacks();
    nghttp3_settings settings;
    setup_settings(&settings);

    int rv = nghttp3_conn_client_new(&conn, &callbacks, &settings, nullptr, this);
    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_HTTP3_INIT,
                         "nghttp3_conn_client_new failed: %s", nghttp3_strerror(rv));
        return false;
    }

    return open_control_streams();
}

bool Connection::open_control_streams() {
    if (!quic_conn || !conn) {
        return false;
    }

    // Open control stream
    // QUIC stream IDs: bit 0 = initiator (0=client, 1=server), bit 1 = type (0=bidi, 1=uni)
    // Server must use server-initiated unidirectional streams: 3, 7, 11, 15...
    // Client must use client-initiated unidirectional streams: 2, 6, 10, 14...
    control_stream_id = is_server ? 3 : 2;  // Server uses stream 3, client uses stream 2
    swoole::quic::Stream *qs = quic_conn->open_stream(control_stream_id);
    if (!qs) {
        return false;
    }

    int rv = nghttp3_conn_bind_control_stream(conn, control_stream_id);
    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_HTTP3_STREAM,
                         "nghttp3_conn_bind_control_stream failed: %s", nghttp3_strerror(rv));
        return false;
    }

    // Open QPACK encoder/decoder streams
    // Server uses 7 (encoder) and 11 (decoder)
    // Client uses 6 (encoder) and 10 (decoder)
    qpack_enc_stream_id = is_server ? 7 : 6;
    qpack_dec_stream_id = is_server ? 11 : 10;

    rv = nghttp3_conn_bind_qpack_streams(conn, qpack_enc_stream_id, qpack_dec_stream_id);
    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_HTTP3_STREAM,
                         "nghttp3_conn_bind_qpack_streams failed: %s", nghttp3_strerror(rv));
        return false;
    }

    swoole::quic::Stream *enc_stream = quic_conn->open_stream(qpack_enc_stream_id);
    swoole::quic::Stream *dec_stream = quic_conn->open_stream(qpack_dec_stream_id);

    if (!enc_stream || !dec_stream) {
        return false;
    }

    control_stream_opened = 1;
    qpack_streams_opened = 1;

    return send_settings();
}

bool Connection::send_settings() {
    // Settings are prepared by nghttp3 during connection setup (bind_control_stream)
    // But we need to call write_streams() to actually send them via QUIC
    ssize_t rv = write_streams();
    if (rv < 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP3_SEND,
                         "Failed to send SETTINGS and control stream data");
        return false;
    }

    swoole_trace_log(SW_TRACE_HTTP3, "SETTINGS and control stream data sent successfully");
    return true;
}

Stream* Connection::open_stream(int64_t stream_id) {
    if (!quic_conn) {
        return nullptr;
    }

    if (stream_id < 0) {
        stream_id = next_stream_id;
        next_stream_id += 4;
    }

    if (streams.find(stream_id) != streams.end()) {
        return streams[stream_id];
    }

    swoole::quic::Stream *qs = quic_conn->open_stream(stream_id);
    if (!qs) {
        return nullptr;
    }

    Stream *stream = new Stream(stream_id, this, qs);
    streams[stream_id] = stream;

    return stream;
}

Stream* Connection::get_stream(int64_t stream_id) {
    auto it = streams.find(stream_id);
    if (it == streams.end()) {
        return nullptr;
    }
    return it->second;
}

bool Connection::close_stream(int64_t stream_id) {
    auto it = streams.find(stream_id);
    if (it == streams.end()) {
        return false;
    }

    Stream *stream = it->second;
    delete stream;
    streams.erase(it);

    return true;
}

ssize_t Connection::read_stream(int64_t stream_id, const uint8_t *data, size_t datalen, bool fin) {
    if (!conn) {
        return -1;
    }

    Stream *stream = get_stream(stream_id);
    bool stream_is_new = false;

    if (!stream) {
        // Create new stream for incoming data
        stream = open_stream(stream_id);
        if (!stream) {
            return -1;
        }

        stream->is_request = 1;
        stream_is_new = true;
    }

    // Register stream with nghttp3 by setting stream_user_data
    // This is critical - nghttp3 needs to know about the stream before reading data
    // Call unconditionally to ensure stream is always registered
    nghttp3_conn_set_stream_user_data(conn, stream_id, stream);

    swoole_trace_log(SW_TRACE_HTTP3, "read_stream: stream_id=%ld, datalen=%zu, fin=%d, is_new=%d",
                    stream_id, datalen, fin, stream_is_new);

    if (stream_is_new && on_stream_open) {
        on_stream_open(this, stream);
    }

    int rv = nghttp3_conn_read_stream(conn, stream_id, data, datalen, fin);
    if (rv < 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP3_RECV,
                         "nghttp3_conn_read_stream failed for stream %ld: %s (error code: %d)",
                         stream_id, nghttp3_strerror(rv), rv);

        // Continue despite error to allow debugging
        // return rv;
    }

    return datalen;
}

ssize_t Connection::write_streams() {
    if (!conn || !quic_conn) {
        return -1;
    }

    nghttp3_vec vec[16];
    int64_t stream_id;
    int fin;

    for (;;) {
        ssize_t sveccnt = nghttp3_conn_writev_stream(conn, &stream_id, &fin, vec, 16);

        if (sveccnt == 0) {
            break;
        }

        if (sveccnt < 0) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_HTTP3_SEND,
                             "nghttp3_conn_writev_stream failed: %s", nghttp3_strerror(sveccnt));
            return sveccnt;
        }

        swoole::quic::Stream *qs = quic_conn->get_stream(stream_id);
        if (!qs) {
            continue;
        }

        size_t total = 0;
        for (ssize_t i = 0; i < sveccnt; i++) {
            if (!qs->send_data(vec[i].base, vec[i].len, 0)) {
                return -1;
            }
            total += vec[i].len;
        }

        if (fin) {
            qs->send_data(nullptr, 0, true);
        }

        nghttp3_conn_add_write_offset(conn, stream_id, total);
    }

    return 0;
}

bool Connection::close() {
    if (conn) {
        nghttp3_conn_shutdown(conn);
    }

    if (quic_conn) {
        quic_conn->close();
    }

    return true;
}

// ==================== HTTP/3 Server Implementation ====================

swoole::http3::Server::Server()
    : quic_server(nullptr),
      max_field_section_size(SW_HTTP3_MAX_FIELD_SECTION_SIZE),
      qpack_max_table_capacity(SW_HTTP3_MAX_TABLE_CAPACITY),
      qpack_blocked_streams(SW_HTTP3_MAX_BLOCKED_STREAMS),
      on_connection(nullptr),
      on_request(nullptr),
      on_stream_close(nullptr),
      user_data(nullptr) {

    memset(&settings, 0, sizeof(settings));
    Connection::setup_settings(&settings);
}

swoole::http3::Server::~Server() {
    stop();
}

bool swoole::http3::Server::bind(const char *host, int port, SSL_CTX *ssl_ctx) {
    quic_server = new swoole::quic::Server();
    if (!quic_server) {
        return false;
    }

    quic_server->ssl_ctx = ssl_ctx;

    if (!quic_server->bind(host, port)) {
        delete quic_server;
        quic_server = nullptr;
        return false;
    }

    // Set QUIC server callbacks
    quic_server->on_connection = [](swoole::quic::Server *qs, swoole::quic::Connection *qc) {
        Server *h3s = (Server *) qs->user_data;
        if (h3s) {
            h3s->accept_connection(qc);
        }
    };

    quic_server->on_stream_open = [](swoole::quic::Connection *qc, swoole::quic::Stream *qs) {
        Connection *h3c = (Connection *) qc->user_data;
        if (h3c && h3c->on_stream_open) {
            Stream *h3s = (Stream *) qs->user_data;
            if (h3s) {
                h3c->on_stream_open(h3c, h3s);
            }
        }
    };

    quic_server->on_stream_data = [](swoole::quic::Connection *qc, swoole::quic::Stream *qs,
                                      const uint8_t *data, size_t len) {
        Connection *h3c = (Connection *) qc->user_data;
        if (h3c) {
            bool fin = qs->fin_received;
            h3c->read_stream(qs->stream_id, data, len, fin);
            h3c->write_streams();
        }
    };

    quic_server->on_stream_close = [](swoole::quic::Connection *qc, swoole::quic::Stream *qs) {
        Connection *h3c = (Connection *) qc->user_data;
        if (h3c && h3c->on_stream_close) {
            Stream *h3s = (Stream *) qs->user_data;
            if (h3s) {
                h3c->on_stream_close(h3c, h3s);
            }
        }
    };

    quic_server->user_data = this;

    return true;
}

Connection* swoole::http3::Server::accept_connection(swoole::quic::Connection *quic_conn) {
    if (!quic_conn) {
        return nullptr;
    }

    Connection *conn = new Connection(quic_conn);
    if (!conn->init_server()) {
        delete conn;
        return nullptr;
    }

    // Set HTTP/3 callbacks
    conn->on_stream_open = [](Connection *c, Stream *s) {
        // Stream opened - don't call request handler yet
        // Wait for headers to be complete
    };

    conn->on_recv_header = [](Connection *c, Stream *s) {
        // Headers are complete - now call the request handler
        Server *server = (Server *) c->user_data;
        if (server && server->on_request) {
            server->on_request(c, s);
        }
    };

    conn->on_stream_close = [](Connection *c, Stream *s) {
        Server *server = (Server *) c->user_data;
        if (server && server->on_stream_close) {
            server->on_stream_close(c, s);
        }
    };

    conn->user_data = this;
    connections[quic_conn] = conn;

    if (on_connection) {
        on_connection(this, conn);
    }

    return conn;
}

bool swoole::http3::Server::remove_connection(Connection *conn) {
    for (auto it = connections.begin(); it != connections.end(); ++it) {
        if (it->second == conn) {
            delete conn;
            connections.erase(it);
            return true;
        }
    }
    return false;
}

bool swoole::http3::Server::start() {
    if (!quic_server) {
        return false;
    }

    quic_server->run();
    return true;
}

void swoole::http3::Server::stop() {
    for (auto &pair : connections) {
        delete pair.second;
    }
    connections.clear();

    if (quic_server) {
        delete quic_server;
        quic_server = nullptr;
    }
}

#endif // SW_USE_HTTP3
