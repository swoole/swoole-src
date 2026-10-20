#include "swoole_server.h"
#include "swoole_http.h"
#include "swoole_http2.h"
#include "swoole_llhttp.h"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace swoole {

namespace {

struct GatewayStream {
    int32_t id = 0;
    std::string method;
    std::string path;
    std::string authority;
    std::string headers;
    std::string cookie;
    std::string body;
    bool dispatched = false;
    bool answered = false;
    int worker = -1;
    pid_t pid = 0;
    llhttp_t parser{};
    bool parser_ready = false;
    std::string field;
    std::string value;
    bool in_value = false;
    std::vector<std::pair<std::string, std::string>> response_headers;
    std::string out;
    size_t out_offset = 0;
    bool headers_complete = false;
    bool submitted = false;
    bool complete = false;
    bool deferred = false;
    bool failed = false;
};

struct Gateway {
    nghttp2_session *session = nullptr;
    std::map<int32_t, GatewayStream> streams;
    const Server *server = nullptr;
    SessionId session_id = 0;
    bool paused = false;
    int32_t last_request_stream = 0;
    std::set<int32_t> reset_streams;
    size_t preface_left = sizeof(SW_HTTP2_PRI_STRING) - 1;
    size_t payload_left = 0;
    uint8_t header[9]{};
    size_t header_fill = 0;
    size_t header_carried = 0;
    bool in_block = false;
    std::string held;
    size_t held_need = 0;
    bool refused = false;
    bool draining = false;
    bool drain_seen = false;
};

Gateway *gateway_of(const Connection *conn) {
    return static_cast<Gateway *>(conn->http2_gateway);
}

GatewayStream *gateway_stream(Gateway *gateway, int32_t stream_id) {
    auto found = gateway->streams.find(stream_id);
    return found == gateway->streams.end() ? nullptr : &found->second;
}

bool is_hop_by_hop(const std::string &name) {
    return name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
           name == "transfer-encoding" || name == "upgrade";
}

void gateway_store_header(GatewayStream *stream) {
    if (stream->field.empty()) {
        return;
    }
    std::string name = stream->field;
    for (auto &c : name) {
        c = (char) tolower((unsigned char) c);
    }
    if (!is_hop_by_hop(name)) {
        stream->response_headers.emplace_back(name, stream->value);
    }
    stream->field.clear();
    stream->value.clear();
    stream->in_value = false;
}

int response_on_header_field(llhttp_t *parser, const char *at, size_t length) {
    auto *stream = static_cast<GatewayStream *>(parser->data);
    if (stream->in_value) {
        gateway_store_header(stream);
    }
    stream->field.append(at, length);
    return 0;
}

int response_on_header_value(llhttp_t *parser, const char *at, size_t length) {
    auto *stream = static_cast<GatewayStream *>(parser->data);
    stream->in_value = true;
    stream->value.append(at, length);
    return 0;
}

int response_on_headers_complete(llhttp_t *parser) {
    auto *stream = static_cast<GatewayStream *>(parser->data);
    gateway_store_header(stream);
    stream->headers_complete = true;
    return stream->method == "HEAD" ? 1 : 0;
}

int response_on_body(llhttp_t *parser, const char *at, size_t length) {
    auto *stream = static_cast<GatewayStream *>(parser->data);
    stream->out.append(at, length);
    return 0;
}

int response_on_message_complete(llhttp_t *parser) {
    auto *stream = static_cast<GatewayStream *>(parser->data);
    stream->complete = true;
    return HPE_PAUSED;
}

constexpr llhttp_settings_t response_settings = {
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    response_on_header_field,
    response_on_header_value,
    nullptr,
    nullptr,
    response_on_headers_complete,
    response_on_body,
    response_on_message_complete,
};

nghttp2_ssize gateway_read_body(nghttp2_session *session,
                                int32_t stream_id,
                                uint8_t *buf,
                                size_t length,
                                uint32_t *data_flags,
                                nghttp2_data_source *source,
                                void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    auto *stream = gateway_stream(gateway, stream_id);
    if (stream == nullptr) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    const size_t available = stream->out.size() - stream->out_offset;
    const size_t n = available < length ? available : length;
    if (n > 0) {
        memcpy(buf, stream->out.data() + stream->out_offset, n);
        stream->out_offset += n;
        if (stream->out_offset == stream->out.size()) {
            stream->out.clear();
            stream->out_offset = 0;
        }
    }
    if (stream->out.empty() && stream->complete) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return (nghttp2_ssize) n;
    }
    if (n == 0) {
        stream->deferred = true;
        return NGHTTP2_ERR_DEFERRED;
    }
    return (nghttp2_ssize) n;
}

void gateway_respond(Gateway *gateway, int32_t stream_id, int status, const char *body) {
    auto *stream = gateway_stream(gateway, stream_id);
    if (stream == nullptr || stream->submitted) {
        return;
    }
    stream->response_headers.clear();
    stream->out = body;
    stream->out_offset = 0;
    stream->complete = true;
    stream->headers_complete = true;
    stream->submitted = true;
    stream->answered = true;
    std::string status_text = std::to_string(status);
    std::string length = std::to_string(stream->out.size());
    nghttp2_nv nva[3] = {
        {(uint8_t *) ":status", (uint8_t *) status_text.data(), 7, status_text.size(), NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) "content-type", (uint8_t *) "text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) "content-length", (uint8_t *) length.data(), 14, length.size(), NGHTTP2_NV_FLAG_NONE},
    };
    nghttp2_data_provider2 provider{};
    provider.read_callback = gateway_read_body;
    nghttp2_submit_response2(gateway->session, stream_id, nva, 3, &provider);
}

void gateway_submit(Gateway *gateway, GatewayStream *stream) {
    int status = stream->parser.status_code;
    std::string status_text = std::to_string(status);
    std::vector<nghttp2_nv> nva;
    nva.reserve(stream->response_headers.size() + 1);
    nva.push_back({(uint8_t *) ":status", (uint8_t *) status_text.data(), 7, status_text.size(), NGHTTP2_NV_FLAG_NONE});
    for (auto &header : stream->response_headers) {
        nva.push_back({(uint8_t *) header.first.data(),
                       (uint8_t *) header.second.data(),
                       header.first.size(),
                       header.second.size(),
                       NGHTTP2_NV_FLAG_NONE});
    }
    nghttp2_data_provider2 provider{};
    provider.read_callback = gateway_read_body;
    stream->submitted = true;
    nghttp2_submit_response2(gateway->session, stream->id, nva.data(), nva.size(), &provider);
}

void gateway_dispatch(Gateway *gateway, GatewayStream *stream) {
    const Server *serv = gateway->server;
    Connection *conn = serv->get_connection_verify_no_ssl(gateway->session_id);
    if (conn == nullptr) {
        return;
    }
    stream->dispatched = true;
    if (stream->method.empty() || stream->path.empty()) {
        gateway_respond(gateway, stream->id, 400, "Bad Request");
        return;
    }
    std::string request;
    request.reserve(stream->method.size() + stream->path.size() + stream->authority.size() + stream->headers.size() +
                    stream->cookie.size() + stream->body.size() + 96);
    request.append(stream->method).append(" ").append(stream->path).append(" HTTP/1.1\r\n");
    if (!stream->authority.empty()) {
        request.append("host: ").append(stream->authority).append("\r\n");
    }
    request.append(stream->headers);
    if (!stream->cookie.empty()) {
        request.append("cookie: ").append(stream->cookie).append("\r\n");
    }
    if (!stream->body.empty() || (stream->method != "GET" && stream->method != "HEAD" && stream->method != "OPTIONS")) {
        request.append("content-length: ").append(std::to_string(stream->body.size())).append("\r\n");
    }
    request.append("\r\n").append(stream->body);
    stream->body.clear();
    stream->body.shrink_to_fit();

    ListenPort *port = serv->get_port_by_fd(conn->fd);
    RecvData rdata{};
    rdata.info.len = request.size();
    rdata.info.reserved = (uint32_t) stream->id;
    rdata.data = request.data();
    if (http_server::dispatch_request(const_cast<Server *>(serv), &port->protocol, conn->socket, &rdata) < 0) {
        gateway_respond(gateway, stream->id, 503, "Service Unavailable");
    }
}

int gateway_on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    auto &stream = gateway->streams[frame->hd.stream_id];
    stream.id = frame->hd.stream_id;
    return 0;
}

int gateway_on_header(nghttp2_session *session,
                      const nghttp2_frame *frame,
                      const uint8_t *name,
                      size_t namelen,
                      const uint8_t *value,
                      size_t valuelen,
                      uint8_t flags,
                      void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    auto *stream = gateway_stream(gateway, frame->hd.stream_id);
    if (stream == nullptr) {
        return 0;
    }
    const std::string key((const char *) name, namelen);
    const std::string text((const char *) value, valuelen);
    if (key == ":method") {
        stream->method = text;
    } else if (key == ":path") {
        stream->path = text;
    } else if (key == ":authority") {
        stream->authority = text;
    } else if (key == ":scheme") {
    } else if (key == "host") {
        if (stream->authority.empty()) {
            stream->authority = text;
        }
    } else if (key == "cookie") {
        if (!stream->cookie.empty()) {
            stream->cookie.append("; ");
        }
        stream->cookie.append(text);
    } else if (key == "content-length" || is_hop_by_hop(key)) {
    } else {
        stream->headers.append(key).append(": ").append(text).append("\r\n");
    }
    return 0;
}

int gateway_on_data(
    nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    auto *stream = gateway_stream(gateway, stream_id);
    if (stream == nullptr || stream->dispatched) {
        return 0;
    }
    const Connection *conn = gateway->server->get_connection_verify_no_ssl(gateway->session_id);
    const size_t limit = conn ? const_cast<Server *>(gateway->server)->get_package_max_length(const_cast<Connection *>(conn)) : 0;
    if (stream->body.size() + len > limit) {
        stream->dispatched = true;
        stream->body.clear();
        gateway_respond(gateway, stream_id, 413, "Request Entity Too Large");
        return 0;
    }
    stream->body.append((const char *) data, len);
    return 0;
}

int gateway_on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) {
        return 0;
    }
    if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        return 0;
    }
    auto *stream = gateway_stream(gateway, frame->hd.stream_id);
    if (stream == nullptr || stream->dispatched) {
        return 0;
    }
    gateway_dispatch(gateway, stream);
    return 0;
}

int gateway_on_begin_frame(nghttp2_session *session, const nghttp2_frame_hd *hd, void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    if (hd->type != NGHTTP2_HEADERS || !(hd->stream_id & 1)) {
        return 0;
    }
    if (hd->stream_id > gateway->last_request_stream) {
        gateway->last_request_stream = hd->stream_id;
    } else if (nghttp2_session_find_stream(session, hd->stream_id) == nullptr &&
               gateway->reset_streams.count(hd->stream_id) == 0) {
        nghttp2_session_terminate_session(session, NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
}

int gateway_on_frame_send(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    if (frame->hd.type == NGHTTP2_RST_STREAM) {
        static_cast<Gateway *>(user_data)->reset_streams.insert(frame->hd.stream_id);
    }
    return 0;
}

uint32_t gateway_read_u31(const uint8_t *p) {
    return (((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | (uint32_t) p[3]) & 0x7fffffffu;
}

void gateway_refuse(Gateway *gateway) {
    nghttp2_session_terminate_session(gateway->session, NGHTTP2_PROTOCOL_ERROR);
    gateway->refused = true;
}

bool gateway_screen(Gateway *gateway) {
    const auto *frame = (const uint8_t *) gateway->held.data();
    const int32_t stream_id = (int32_t) gateway_read_u31(frame + 5);
    const uint32_t value = gateway_read_u31(frame + 9);
    if (frame[3] == NGHTTP2_PRIORITY) {
        if (stream_id == 0) {
            gateway_refuse(gateway);
            return false;
        }
        if (value != (uint32_t) stream_id) {
            return true;
        }
        if (nghttp2_session_find_stream(gateway->session, stream_id) == nullptr) {
            gateway_refuse(gateway);
        } else {
            nghttp2_submit_rst_stream(gateway->session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_PROTOCOL_ERROR);
        }
        return false;
    }
    const int32_t window = nghttp2_session_get_stream_remote_window_size(gateway->session, stream_id);
    if (window < 0 || value == 0 || value <= (uint32_t) (INT32_MAX - window)) {
        return true;
    }
    nghttp2_submit_rst_stream(gateway->session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_FLOW_CONTROL_ERROR);
    return false;
}

int gateway_on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    auto *gateway = static_cast<Gateway *>(user_data);
    gateway->streams.erase(stream_id);
    return 0;
}

}  // namespace

bool Server::http2_gateway_start(Connection *conn, const char *data, size_t length) const {
    auto *gateway = new Gateway();
    gateway->server = this;
    gateway->session_id = conn->session_id;
    nghttp2_session_callbacks *callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, gateway_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, gateway_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, gateway_on_data);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, gateway_on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, gateway_on_stream_close);
    nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks, gateway_on_begin_frame);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, gateway_on_frame_send);
    const int created = nghttp2_session_server_new(&gateway->session, callbacks, gateway);
    nghttp2_session_callbacks_del(callbacks);
    if (created != 0) {
        delete gateway;
        return false;
    }
    conn->http2_gateway = gateway;
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, http2::get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE)},
    };
    nghttp2_submit_settings(gateway->session, NGHTTP2_FLAG_NONE, settings, 2);
    nghttp2_session_set_local_window_size(
        gateway->session, NGHTTP2_FLAG_NONE, 0, (int32_t) http2::get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE));
    return http2_gateway_receive(conn, data, length);
}

bool Server::http2_gateway_receive(Connection *conn, const char *data, size_t length) const {
    auto *gateway = gateway_of(conn);
    if (gateway->draining) {
        return true;
    }
    const SessionId session_id = conn->session_id;
    const auto *in = (const uint8_t *) data;
    auto feed = [&](const uint8_t *from, size_t n) -> bool {
        if (n == 0 || gateway->refused) {
            return true;
        }
        const nghttp2_ssize consumed = nghttp2_session_mem_recv2(gateway->session, from, n);
        if (get_connection_verify_no_ssl(session_id) == nullptr) {
            return false;
        }
        if (consumed < 0) {
            gateway_refuse(gateway);
        }
        return true;
    };
    size_t pos = 0;
    size_t run = 0;
    size_t header_start = 0;
    while (pos < length && !gateway->refused) {
        if (gateway->preface_left > 0 || gateway->payload_left > 0) {
            size_t &left = gateway->preface_left > 0 ? gateway->preface_left : gateway->payload_left;
            const size_t n = std::min(left, length - pos);
            left -= n;
            pos += n;
            continue;
        }
        if (gateway->held_need > 0) {
            const size_t n = std::min(gateway->held_need, length - pos);
            gateway->held.append(data + pos, n);
            gateway->held_need -= n;
            pos += n;
            run = pos;
            if (gateway->held_need == 0) {
                const bool pass = gateway_screen(gateway);
                std::string frame;
                frame.swap(gateway->held);
                if (pass && !feed((const uint8_t *) frame.data(), frame.size())) {
                    return false;
                }
            }
            continue;
        }
        if (gateway->header_fill == 0) {
            header_start = pos;
        }
        const size_t n = std::min(sizeof(gateway->header) - gateway->header_fill, length - pos);
        memcpy(gateway->header + gateway->header_fill, in + pos, n);
        gateway->header_fill += n;
        pos += n;
        if (gateway->header_fill < sizeof(gateway->header)) {
            break;
        }
        const uint8_t *hd = gateway->header;
        const size_t frame_length = ((size_t) hd[0] << 16) | ((size_t) hd[1] << 8) | (size_t) hd[2];
        const uint8_t type = hd[3];
        const uint8_t flags = hd[4];
        const bool screened = !gateway->in_block && ((type == NGHTTP2_PRIORITY && frame_length == 5) ||
                                                     (type == NGHTTP2_WINDOW_UPDATE && frame_length == 4 &&
                                                      gateway_read_u31(hd + 5) != 0));
        if (type == NGHTTP2_HEADERS || type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION) {
            gateway->in_block = !(flags & NGHTTP2_FLAG_END_HEADERS);
        }
        gateway->header_fill = 0;
        if (screened) {
            if (!feed(in + run, header_start - run)) {
                return false;
            }
            gateway->held.assign((const char *) hd, sizeof(gateway->header));
            gateway->held_need = frame_length;
            run = pos;
        } else {
            if (gateway->header_carried > 0 && !feed(hd, gateway->header_carried)) {
                return false;
            }
            gateway->payload_left = frame_length;
        }
        gateway->header_carried = 0;
    }
    if (gateway->header_fill > 0 && gateway->header_fill < sizeof(gateway->header)) {
        if (!feed(in + run, header_start - run)) {
            return false;
        }
        gateway->header_carried = gateway->header_fill;
    } else if (!feed(in + run, pos - run)) {
        return false;
    }
    http2_gateway_flush(conn);
    return true;
}

int Server::http2_gateway_readable(Reactor *reactor, Event *event) const {
    network::Socket *_socket = event->socket;
    auto *conn = static_cast<Connection *>(_socket->object);
    static thread_local char buffer[65536];
    for (int round = 0; round < 16; round++) {
        if (conn->http2_gateway == nullptr) {
            return SW_OK;
        }
        const ssize_t n = _socket->recv(buffer, sizeof(buffer), 0);
        if (n < 0) {
            switch (_socket->catch_read_error(errno)) {
            case SW_CLOSE:
                conn->close_errno = errno;
                return reactor->trigger_close_event(event);
            default:
                return SW_OK;
            }
        }
        if (n == 0) {
            return reactor->trigger_close_event(event);
        }
        if (!http2_gateway_receive(conn, buffer, (size_t) n)) {
            return SW_OK;
        }
        if (static_cast<size_t>(n) < sizeof(buffer)) {
            return SW_OK;
        }
    }
    return SW_OK;
}

void Server::http2_gateway_flush(Connection *conn) const {
    auto *gateway = gateway_of(conn);
    if (gateway == nullptr) {
        return;
    }
    const SessionId session_id = conn->session_id;
    while (nghttp2_session_want_write(gateway->session)) {
        if (conn->socket->get_out_buffer_length() > conn->socket->buffer_size) {
            break;
        }
        const uint8_t *data = nullptr;
        const nghttp2_ssize n = nghttp2_session_mem_send2(gateway->session, &data);
        if (n <= 0) {
            break;
        }
        SendData raw{};
        raw.info.fd = session_id;
        raw.info.type = SW_SERVER_EVENT_SEND_DATA;
        raw.info.len = (uint32_t) n;
        raw.data = (const char *) data;
        send_to_connection_now(&raw);
        if (get_connection_verify_no_ssl(session_id) == nullptr) {
            return;
        }
    }
    const bool full = conn->socket->get_out_buffer_length() > conn->socket->buffer_size;
    if (full && !gateway->paused) {
        gateway->paused = true;
        SendData pause{};
        pause.info.fd = session_id;
        pause.info.type = SW_SERVER_EVENT_PAUSE_RECV;
        send_to_connection_now(&pause);
    } else if (!full && gateway->paused) {
        gateway->paused = false;
        SendData resume{};
        resume.info.fd = session_id;
        resume.info.type = SW_SERVER_EVENT_RESUME_RECV;
        send_to_connection_now(&resume);
    }
    if (!nghttp2_session_want_read(gateway->session) && !nghttp2_session_want_write(gateway->session)) {
        gateway->draining = true;
    }
}

int Server::http2_gateway_send(Connection *conn, const SendData *_send, uint32_t tag) const {
    auto *gateway = gateway_of(conn);
    const int32_t stream_id = (int32_t) (tag & SW_HTTP_ORDER_SEQ);
    const bool ended = tag & SW_HTTP_ORDER_END;
    if (tag == 0) {
        if (_send->info.type == SW_SERVER_EVENT_CLOSE) {
            nghttp2_session_terminate_session(gateway->session, NGHTTP2_NO_ERROR);
            http2_gateway_flush(conn);
            if (get_connection_verify_no_ssl(_send->info.fd) != nullptr) {
                return send_to_connection_now(_send);
            }
            return SW_OK;
        }
        if (_send->info.type == SW_SERVER_EVENT_SEND_DATA || _send->info.type == SW_SERVER_EVENT_SEND_FILE) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SESSION_INVALID_ID,
                             "session#%ld speaks HTTP/2: %u bytes sent outside a request were dropped",
                             _send->info.fd,
                             _send->info.len);
            return SW_ERR;
        }
        return send_to_connection_now(_send);
    }
    auto *stream = gateway_stream(gateway, stream_id);
    if (stream == nullptr) {
        return SW_OK;
    }
    if (_send->info.type == SW_SERVER_EVENT_SEND_DATA && _send->info.len > 0 && !stream->failed && !stream->complete) {
        if (!stream->parser_ready) {
            swoole_llhttp_parser_init(&stream->parser, HTTP_RESPONSE, stream);
            stream->parser_ready = true;
        }
        stream->answered = true;
        const size_t parsed =
            swoole_llhttp_parser_execute(&stream->parser, &response_settings, _send->data, _send->info.len);
        if (parsed < _send->info.len && !stream->complete) {
            stream->failed = true;
        }
    } else if (_send->info.type == SW_SERVER_EVENT_SEND_FILE) {
        stream->failed = true;
    } else if (_send->info.type == SW_SERVER_EVENT_CLOSE && !stream->complete) {
        stream->failed = true;
    }
    if (stream->failed) {
        nghttp2_submit_rst_stream(gateway->session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_INTERNAL_ERROR);
        stream->complete = true;
    } else {
        if (ended && !stream->complete && stream->headers_complete) {
            stream->complete = true;
        }
        if (stream->headers_complete && !stream->submitted) {
            gateway_submit(gateway, stream);
        } else if (stream->submitted && stream->deferred && (!stream->out.empty() || stream->complete)) {
            stream->deferred = false;
            nghttp2_session_resume_data(gateway->session, stream_id);
        }
        if (ended && !stream->headers_complete) {
            nghttp2_submit_rst_stream(gateway->session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_INTERNAL_ERROR);
        }
    }
    http2_gateway_flush(conn);
    return SW_OK;
}

void Server::http2_gateway_dispatched(Connection *conn, uint32_t stream_id, int worker_id, pid_t pid) const {
    auto *stream = gateway_stream(gateway_of(conn), (int32_t) stream_id);
    if (stream) {
        stream->worker = worker_id;
        stream->pid = pid;
    }
}

void Server::http2_gateway_check(Connection *conn) const {
    auto *gateway = gateway_of(conn);
    if (gateway->draining) {
        if (gateway->drain_seen) {
            SendData close{};
            close.info.fd = conn->session_id;
            close.info.type = SW_SERVER_EVENT_CLOSE;
            send_to_connection_now(&close);
            return;
        }
        gateway->drain_seen = true;
        return;
    }
    bool reset = false;
    for (auto &entry : gateway->streams) {
        auto &stream = entry.second;
        if (!stream.dispatched || stream.complete || stream.worker < 0) {
            continue;
        }
        if (get_worker(stream.worker)->pid == stream.pid) {
            continue;
        }
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SESSION_CLOSED,
                         "session#%ld stream#%d reset: worker#%d exited before answering it",
                         conn->session_id,
                         stream.id,
                         stream.worker);
        stream.complete = true;
        nghttp2_submit_rst_stream(gateway->session, NGHTTP2_FLAG_NONE, stream.id, NGHTTP2_INTERNAL_ERROR);
        reset = true;
    }
    if (reset) {
        http2_gateway_flush(conn);
    }
}

void Server::http2_gateway_release(Connection *conn) const {
    auto *gateway = gateway_of(conn);
    if (gateway == nullptr) {
        return;
    }
    conn->http2_gateway = nullptr;
    nghttp2_session_del(gateway->session);
    delete gateway;
}

}  // namespace swoole
