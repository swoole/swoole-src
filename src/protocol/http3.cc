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

    body = swString_new(SW_BUFFER_SIZE_STD);

    if (qs) {
        qs->user_data = this;
    }
}

Stream::~Stream() {
    headers.clear();

    if (body) {
        swString_free(body);
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
    data_reader.read_data = nullptr;  // Will be set if sending body

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
        if (swString_append_ptr(body, (const char *) data, len) < 0) {
            return false;
        }
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
        if (swString_append_ptr(body, (const char *) data, len) < 0) {
            return false;
        }
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

// Remaining implementation will be in the next part due to size constraints...

#endif // SW_USE_HTTP3
