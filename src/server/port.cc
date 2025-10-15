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

#include "swoole_server.h"
#include "swoole_http.h"
#include "swoole_http2.h"
#include "swoole_websocket.h"
#include "swoole_client.h"
#include "swoole_mqtt.h"
#include "swoole_redis.h"

using swoole::http_server::Request;
using swoole::network::Address;
using swoole::network::Socket;

namespace swoole {

ListenPort::ListenPort(Server *server) {
    protocol.package_length_type = 'N';
    protocol.package_length_size = 4;
    protocol.package_body_offset = 4;
    protocol.package_max_length = SW_INPUT_BUFFER_SIZE;

    protocol.package_eof_len = sizeof(SW_DATA_EOF) - 1;
    memcpy(protocol.package_eof, SW_DATA_EOF, protocol.package_eof_len);

    protocol.private_data_2 = server;
}

#ifdef SW_USE_OPENSSL

bool ListenPort::ssl_add_sni_cert(const std::string &name, const std::shared_ptr<SSLContext> &ctx) {
    if (!ssl_context_create(ctx.get())) {
        return false;
    }
    sni_contexts.emplace(name, ctx);
    return true;
}

bool ListenPort::ssl_matches_wildcard_name(const char *subject_name, const char *cert_name) {
    const char *wildcard = nullptr;

    if (strcasecmp(subject_name, cert_name) == 0) {
        return true;
    }

    /* wildcard, if present, must only be present in the left-most component */
    if (!((wildcard = strchr(cert_name, '*'))) || memchr(cert_name, '.', wildcard - cert_name)) {
        return false;
    }

    /* 1) prefix, if not empty, must match subject */
    ptrdiff_t prefix_len = wildcard - cert_name;
    if (prefix_len && strncasecmp(subject_name, cert_name, prefix_len) != 0) {
        return false;
    }

    size_t suffix_len = strlen(wildcard + 1);
    size_t subject_len = strlen(subject_name);
    if (suffix_len <= subject_len) {
        /* 2) suffix must match
         * 3) no . between prefix and suffix
         **/
        return strcasecmp(wildcard + 1, subject_name + subject_len - suffix_len) == 0 &&
               memchr(subject_name + prefix_len, '.', subject_len - suffix_len - prefix_len) == nullptr;
    }

    return false;
}

int ListenPort::ssl_server_sni_callback(SSL *ssl, int *al, void *arg) {
    const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!server_name) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    auto *port = static_cast<ListenPort *>(SSL_get_ex_data(ssl, swoole_ssl_get_ex_port_index()));

    if (port->sni_contexts.empty()) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    for (auto &sni_context : port->sni_contexts) {
        if (ssl_matches_wildcard_name(server_name, sni_context.first.c_str())) {
            SSL_set_SSL_CTX(ssl, sni_context.second->get_context());
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

#ifdef SW_SUPPORT_DTLS
dtls::Session *ListenPort::create_dtls_session(Socket *sock) const {
    auto *session = new dtls::Session(sock, ssl_context);
    if (!session->init()) {
        delete session;
        return nullptr;
    }
    dtls_sessions->emplace(sock->get_fd(), session);
    return session;
}
#endif

bool ListenPort::ssl_context_init() {
    ssl_context = std::make_shared<SSLContext>();
    ssl_context->prefer_server_ciphers = 1;
    ssl_context->session_tickets = 0;
    ssl_context->stapling = 1;
    ssl_context->stapling_verify = 1;
    ssl_context->ciphers = SW_SSL_CIPHER_LIST;
    ssl_context->ecdh_curve = SW_SSL_ECDH_CURVE;

    if (is_dgram()) {
#ifdef SW_SUPPORT_DTLS
        ssl_context->protocols = SW_SSL_DTLS;
        dtls_sessions = new std::unordered_map<int, dtls::Session *>;
#else
        swoole_warning("DTLS support require openssl-1.1 or later");
        return false;
#endif
    }
    return true;
}

bool ListenPort::ssl_init() const {
    if (!ssl_context_create(ssl_context.get())) {
        return false;
    }
    if (!sni_contexts.empty()) {
        SSL_CTX_set_tlsext_servername_callback(ssl_context->get_context(), ssl_server_sni_callback);
    }
    return true;
}

bool ListenPort::ssl_create(Socket *sock) {
    if (sock->ssl_create(ssl_context.get(), SW_SSL_SERVER) < 0) {
        swoole_set_last_error(SW_ERROR_SSL_CREATE_SESSION_FAILED);
        return false;
    }
    if (SSL_set_ex_data(sock->ssl, swoole_ssl_get_ex_port_index(), this) == 0) {
        swoole_warning("SSL_set_ex_data() failed");
        return false;
    }
    return true;
}

bool ListenPort::ssl_context_create(SSLContext *context) const {
    if (context->cert_file.empty() || context->key_file.empty()) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_WRONG_OPERATION, "require `ssl_cert_file` and `ssl_key_file` options");
        return false;
    }
    if (open_http_protocol) {
        context->http = 1;
    }
    if (open_http2_protocol) {
        context->http_v2 = 1;
    }
    if (!context->create()) {
        swoole_warning("failed to create ssl content");
        return false;
    }
    return true;
}
#endif

int ListenPort::listen() {
    // listen stream socket
    if (!listening && socket->listen(backlog) < 0) {
        swoole_sys_warning("listen(%s:%d, %d) failed", host.c_str(), port, backlog);
        return SW_ERR;
    }
    listening = true;

#ifdef TCP_DEFER_ACCEPT
    if (tcp_defer_accept) {
        if (socket->set_option(IPPROTO_TCP, TCP_DEFER_ACCEPT, tcp_defer_accept) != 0) {
            swoole_sys_warning("setsockopt(TCP_DEFER_ACCEPT) failed");
        }
    }
#endif

#ifdef SO_ACCEPTFILTER
    if (tcp_defer_accept) {
        struct accept_filter_arg a;
        memset(&a, 0, sizeof(a));
        strcpy(a.af_name, "httpready");
        if (socket->set_option(SOL_SOCKET, SO_ACCEPTFILTER, &a, sizeof(a)) != 0) {
            swoole_sys_warning("setsockopt(SO_ACCEPTFILTER) failed");
        }
    }
#endif

#ifdef TCP_FASTOPEN
    if (tcp_fastopen) {
        if (socket->set_option(IPPROTO_TCP, TCP_FASTOPEN, tcp_fastopen) != 0) {
            swoole_sys_warning("setsockopt(TCP_FASTOPEN) failed");
        }
    }
#endif

#ifdef SO_KEEPALIVE
    if (open_tcp_keepalive == 1) {
        if (socket->set_option(SOL_SOCKET, SO_KEEPALIVE, 1) != 0) {
            swoole_sys_warning("setsockopt(SO_KEEPALIVE) failed");
        }
#ifdef TCP_KEEPIDLE
        if (socket->set_option(IPPROTO_TCP, TCP_KEEPIDLE, tcp_keepidle) < 0) {
            swoole_sys_warning("setsockopt(TCP_KEEPIDLE) failed");
        }
        if (socket->set_option(IPPROTO_TCP, TCP_KEEPINTVL, tcp_keepinterval) < 0) {
            swoole_sys_warning("setsockopt(TCP_KEEPINTVL) failed");
        }
        if (socket->set_option(IPPROTO_TCP, TCP_KEEPCNT, tcp_keepcount) < 0) {
            swoole_sys_warning("setsockopt(TCP_KEEPCNT) failed");
        }
#endif
#ifdef TCP_USER_TIMEOUT
        if (tcp_user_timeout > 0 && socket->set_option(IPPROTO_TCP, TCP_USER_TIMEOUT, tcp_user_timeout) != 0) {
            swoole_sys_warning("setsockopt(TCP_USER_TIMEOUT) failed");
        }
#endif
    }
#endif

    if (buffer_high_watermark == 0) {
        buffer_high_watermark = socket_buffer_size * 0.8;
    }

    return SW_OK;
}

void ListenPort::init_protocol() {
    if (is_dgram() && !is_dtls()) {
        return;
    }

    if (open_eof_check) {
        if (protocol.package_eof_len > SW_DATA_EOF_MAXLEN) {
            protocol.package_eof_len = SW_DATA_EOF_MAXLEN;
        }
        protocol.onPackage = Server::dispatch_task;
        onRead = readable_callback_eof;
    } else if (open_length_check) {
        if (protocol.package_length_type != '\0') {
            protocol.get_package_length = Protocol::default_length_func;
        }
        protocol.onPackage = Server::dispatch_task;
        onRead = readable_callback_length;
    } else if (open_http_protocol) {
        if (open_http2_protocol && open_websocket_protocol) {
            protocol.get_package_length = http_server::get_package_length;
            protocol.get_package_length_size = http_server::get_package_length_size;
            protocol.onPackage = http_server::dispatch_frame;
        } else if (open_http2_protocol) {
            protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
            protocol.get_package_length = http2::get_frame_length;
            protocol.onPackage = Server::dispatch_task;
        } else if (open_websocket_protocol) {
            protocol.package_length_size = SW_WEBSOCKET_FRAME_HEADER_SIZE;
            protocol.get_package_length = websocket::get_package_length;
            protocol.onPackage = websocket::dispatch_frame;
        }
        protocol.package_length_offset = 0;
        protocol.package_body_offset = 0;
        onRead = readable_callback_http;
    } else if (open_mqtt_protocol) {
        mqtt::set_protocol(&protocol);
        protocol.onPackage = Server::dispatch_task;
        onRead = readable_callback_length;
    } else if (open_redis_protocol) {
        protocol.onPackage = Server::dispatch_task;
        onRead = readable_callback_redis;
    } else {
        onRead = readable_callback_raw;
    }
}

void ListenPort::set_eof_protocol(const std::string &eof, bool find_from_right) {
    open_eof_check = true;
    protocol.split_by_eof = !find_from_right;
    protocol.package_eof_len = std::min(eof.length(), sizeof(protocol.package_eof));
    memcpy(protocol.package_eof, eof.c_str(), protocol.package_eof_len);
}

void ListenPort::set_length_protocol(uint32_t length_offset, char length_type, uint32_t body_offset) {
    open_length_check = true;
    protocol.package_length_type = length_type;
    protocol.package_length_size = swoole_type_size(length_type);
    protocol.package_length_offset = length_offset;
    protocol.package_body_offset = body_offset;
}

void ListenPort::set_stream_protocol() {
    open_length_check = true;
    network::Stream::set_protocol(&protocol);
}

/**
 * @description: import listen port from socket-fd
 */
bool ListenPort::import(int sock) {
    int _type;

    auto tmp_sock = socket = new Socket();
    tmp_sock->fd = sock;

    // get socket type
    if (socket->get_option(SOL_SOCKET, SO_TYPE, &_type) < 0) {
        swoole_sys_warning("getsockopt(%d, SOL_SOCKET, SO_TYPE) failed", sock);
    _fail:
        tmp_sock->move_fd();
        delete tmp_sock;
        return false;
    }

    if (tmp_sock->get_name() < 0) {
        swoole_sys_warning("getsockname(%d) failed", sock);
        goto _fail;
    }

    int optval;
    if (tmp_sock->get_option(SOL_SOCKET, SO_ACCEPTCONN, &optval) < 0) {
        swoole_sys_warning("getsockopt(%d, SOL_SOCKET, SO_ACCEPTCONN) failed", sock);
        goto _fail;
    }

    if (optval == 0) {
        swoole_error_log(SW_LOG_WARNING, EINVAL, "the socket[%d] is not a listening socket", sock);
        goto _fail;
    }

    socket = tmp_sock;
    int _family = socket->info.addr.ss.sa_family;
    socket->socket_type = socket->info.type = type = Socket::convert_to_type(_family, _type);
    host = socket->info.get_addr();
    port = socket->info.get_port();
    listening = true;

    socket->fd_type = socket->is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER;
    socket->removed = 1;

    return true;
}

void ListenPort::clear_protocol() {
    open_eof_check = false;
    open_length_check = false;
    open_http_protocol = false;
    open_websocket_protocol = false;
    open_http2_protocol = false;
    open_mqtt_protocol = false;
    open_redis_protocol = false;
}

int ListenPort::readable_callback_raw(Reactor *reactor, ListenPort *port, Event *event) {
    auto _socket = event->socket;
    auto conn = static_cast<Connection *>(_socket->object);
    auto serv = static_cast<Server *>(reactor->ptr);
    auto buffer = serv->get_recv_buffer(_socket);
    RecvData rdata{};

    ssize_t n = _socket->recv(buffer->str, buffer->size, 0);
    if (n < 0) {
        switch (_socket->catch_read_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("recv from connection#%d failed", event->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            goto _close_fd;
        default:
            return SW_OK;
        }
    } else if (n == 0) {
    _close_fd:
        reactor->trigger_close_event(event);
        return SW_OK;
    } else {
        buffer->offset = buffer->length = n;
        rdata.info.len = n;
        rdata.data = buffer->str;
        return Server::dispatch_task(&port->protocol, _socket, &rdata);
    }
}

int ListenPort::readable_callback_length(Reactor *reactor, ListenPort *port, Event *event) {
    auto _socket = event->socket;
    auto conn = static_cast<Connection *>(_socket->object);
    auto protocol = &port->protocol;
    auto serv = static_cast<Server *>(reactor->ptr);
    auto buffer = serv->get_recv_buffer(_socket);

    if (protocol->recv_with_length_protocol(_socket, buffer) < 0) {
        swoole_trace("Close Event.FD=%d|From=%d", event->fd, event->reactor_id);
        conn->close_errno = errno;
        reactor->trigger_close_event(event);
    }

    /**
     * if the length is 0, which means the onPackage has been called, we can free the buffer.
     */
    if (_socket->recv_buffer && _socket->recv_buffer->length == 0 &&
        _socket->recv_buffer->size > SW_BUFFER_SIZE_BIG * 2) {
        delete _socket->recv_buffer;
        _socket->recv_buffer = nullptr;
    }

    return SW_OK;
}

#define CLIENT_INFO_FMT " from session#%ld on %s:%d"
#define CLIENT_INFO_ARGS conn->session_id, port->host.c_str(), port->port

/**
 * For Http Protocol
 */
int ListenPort::readable_callback_http(Reactor *reactor, ListenPort *port, Event *event) {
    Socket *_socket = event->socket;
    auto *conn = static_cast<Connection *>(_socket->object);
    auto *serv = static_cast<Server *>(reactor->ptr);
    RecvData dispatch_data{};

    if (conn->websocket_status >= websocket::STATUS_HANDSHAKE) {
        if (conn->http_upgrade == 0) {
            port->destroy_http_request(conn);
            conn->websocket_status = websocket::STATUS_ACTIVE;
            conn->http_upgrade = 1;
        }
        return readable_callback_length(reactor, port, event);
    }

    if (conn->http2_stream) {
        return readable_callback_length(reactor, port, event);
    }

    Request *request = nullptr;
    Protocol *protocol = &port->protocol;

    if (conn->object == nullptr) {
        request = new Request();
        conn->object = request;
    } else {
        request = static_cast<Request *>(conn->object);
    }

    if (!request->buffer_) {
        request->buffer_ = serv->get_recv_buffer(_socket);
    }

    String *buffer = request->buffer_;

_recv_data:
    ssize_t n = _socket->recv(buffer->str + buffer->length, buffer->size - buffer->length, 0);
    if (n < 0) {
        switch (_socket->catch_read_error(errno)) {
        case SW_ERROR:
            swoole_sys_warning("recv from connection#%d failed", event->fd);
            return SW_OK;
        case SW_CLOSE:
            conn->close_errno = errno;
            goto _close_fd;
        default:
            return SW_OK;
        }
    }

    if (n == 0) {
        if (false) {
        _bad_request:
            _socket->send(SW_STRL(SW_HTTP_BAD_REQUEST_PACKET), 0);
        }
        if (false) {
        _too_large:
            _socket->send(SW_STRL(SW_HTTP_REQUEST_ENTITY_TOO_LARGE_PACKET), 0);
        }
        if (false) {
        _unavailable:
            _socket->send(SW_STRL(SW_HTTP_SERVICE_UNAVAILABLE_PACKET), 0);
        }
    _close_fd:
        port->destroy_http_request(conn);
        reactor->trigger_close_event(event);
        return SW_OK;
    }

    buffer->length += n;

_parse:
    if (request->method == 0 && request->get_protocol() < 0) {
        if (!request->excepted && buffer->length < SW_HTTP_HEADER_MAX_SIZE) {
            return SW_OK;
        }
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_HTTP_INVALID_PROTOCOL,
                         "Bad Request: unknown protocol" CLIENT_INFO_FMT,
                         CLIENT_INFO_ARGS);
        goto _bad_request;
    }

    if (request->method > SW_HTTP_PRI) {
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_HTTP_INVALID_PROTOCOL,
                         "Bad Request: unknown HTTP method" CLIENT_INFO_FMT,
                         CLIENT_INFO_ARGS);
        goto _bad_request;
    } else if (request->method == SW_HTTP_PRI) {
        if (sw_unlikely(!port->open_http2_protocol)) {
            swoole_error_log(SW_LOG_TRACE,
                             SW_ERROR_HTTP_INVALID_PROTOCOL,
                             "Bad Request: can not handle HTTP2 request" CLIENT_INFO_FMT,
                             CLIENT_INFO_ARGS);
            goto _bad_request;
        }
        conn->http2_stream = 1;
        http2::send_setting_frame(protocol, _socket);
        if (buffer->length == sizeof(SW_HTTP2_PRI_STRING) - 1) {
            port->destroy_http_request(conn);
            buffer->clear();
            return SW_OK;
        }
        buffer->reduce(buffer->offset);
        port->destroy_http_request(conn);
        conn->socket->skip_recv = 1;
        return readable_callback_length(reactor, port, event);
    }

    // http header is not the end
    if (request->header_length_ == 0) {
        if (request->get_header_length() < 0) {
            if (buffer->size == buffer->length) {
                swoole_error_log(SW_LOG_TRACE,
                                 SW_ERROR_HTTP_INVALID_PROTOCOL,
                                 "Bad Request: request header size is too large" CLIENT_INFO_FMT,
                                 CLIENT_INFO_ARGS);
                goto _bad_request;
            }
            goto _recv_data;
        }
    }

    // parse http header and got http body length
    if (!request->header_parsed) {
        request->parse_header_info();
        request->max_length_ = protocol->package_max_length;
        swoole_trace_log(SW_TRACE_SERVER,
                         "content-length=%" PRIu64 ", keep-alive=%u, chunked=%u",
                         request->content_length_,
                         request->keep_alive,
                         request->chunked);
        if (request->form_data_) {
            if (serv->upload_max_filesize > 0 &&
                request->header_length_ + request->content_length_ > request->max_length_) {
                request->init_multipart_parser(serv);

                buffer = request->buffer_;
            } else {
                delete request->form_data_;
                request->form_data_ = nullptr;
            }
        }
    }

    if (request->form_data_) {
        if (!request->multipart_header_parsed && memmem(buffer->str, buffer->length, SW_STRL("\r\n\r\n")) == nullptr) {
            return SW_OK;
        }
        if (!request->parse_multipart_data(buffer)) {
            goto _bad_request;
        }
        if (request->too_large) {
            goto _too_large;
        }
        if (request->unavailable) {
            goto _unavailable;
        }
        if (!request->tried_to_dispatch) {
            return SW_OK;
        }
        request->destroy_multipart_parser();
        buffer = request->buffer_;
    }

    // content length (equal to 0) or (field not found but not chunked)
    if (!request->tried_to_dispatch) {
        // recv nobody_chunked eof
        if (request->nobody_chunked) {
            if (buffer->length < request->header_length_ + (sizeof(SW_HTTP_CHUNK_EOF) - 1)) {
                goto _recv_data;
            }
            request->header_length_ += (sizeof(SW_HTTP_CHUNK_EOF) - 1);
        }
        request->tried_to_dispatch = 1;
        // (know content-length is equal to 0) or (no content-length field and no chunked)
        if (request->content_length_ == 0 && (request->known_length || !request->chunked)) {
            buffer->offset = request->header_length_;
            // send static file content directly in the reactor thread
            if (!serv->enable_static_handler || !serv->select_static_handler(request, conn)) {
                // dynamic request, dispatch to worker
                dispatch_data.info.len = request->header_length_;
                dispatch_data.data = buffer->str;
                if (http_server::dispatch_request(serv, protocol, _socket, &dispatch_data) < 0) {
                    goto _close_fd;
                }
            }
            if (!conn->active || _socket->removed) {
                return SW_OK;
            }
            if (buffer->length > request->header_length_) {
                // http pipeline, multi requests, parse the next one
                buffer->reduce(request->header_length_);
                request->clean();
                goto _parse;
            } else {
                port->destroy_http_request(conn);
                buffer->clear();
                return SW_OK;
            }
        }
    }

    size_t request_length;
    if (request->chunked) {
        /* unknown length, should find chunked eof */
        if (request->get_chunked_body_length() < 0) {
            if (request->excepted) {
                swoole_error_log(SW_LOG_TRACE,
                                 SW_ERROR_HTTP_INVALID_PROTOCOL,
                                 "Bad Request: protocol error when parse chunked length" CLIENT_INFO_FMT,
                                 CLIENT_INFO_ARGS);
                goto _bad_request;
            }
            request_length = buffer->size + SW_BUFFER_SIZE_BIG;
            if (request_length > protocol->package_max_length) {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_HTTP_INVALID_PROTOCOL,
                                 "Request Entity Too Large: request length (chunked) has already been greater than the "
                                 "package_max_length(%u)" CLIENT_INFO_FMT,
                                 protocol->package_max_length,
                                 CLIENT_INFO_ARGS);
                goto _too_large;
            }
            if (buffer->length == buffer->size && !buffer->extend(request_length)) {
                goto _unavailable;
            }
            goto _recv_data;
        } else {
            request_length = request->header_length_ + request->content_length_;
        }
        swoole_trace_log(
            SW_TRACE_SERVER, "received chunked eof, real content-length=%" PRIu64, request->content_length_);
    } else {
        request_length = request->header_length_ + request->content_length_;
        if (request_length > protocol->package_max_length) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_HTTP_INVALID_PROTOCOL,
                             "Request Entity Too Large: header-length (%u) + content-length (%" PRIu64
                             ") is greater than the "
                             "package_max_length(%u)" CLIENT_INFO_FMT,
                             request->header_length_,
                             request->content_length_,
                             protocol->package_max_length,
                             CLIENT_INFO_ARGS);
            goto _too_large;
        }

        if (request_length > buffer->size && !buffer->extend(request_length)) {
            goto _unavailable;
        }

        if (buffer->length < request_length) {
            // Expect: 100-continue
            if (request->has_expect_header()) {
                _socket->send(SW_STRL(SW_HTTP_100_CONTINUE_PACKET), 0);
            } else {
                swoole_trace_log(
                    SW_TRACE_SERVER,
                    "PostWait: request->content_length=%d, buffer->length=%zu, request->header_length=%d\n",
                    request->content_length_,
					buffer->length,
                    request->header_length_);
            }
            goto _recv_data;
        }
    }

    // discard the redundant data
    if (buffer->length > request_length) {
        swoole_error_log(SW_LOG_TRACE,
                         SW_ERROR_HTTP_INVALID_PROTOCOL,
                         "Invalid Request: %zu bytes has been discard" CLIENT_INFO_FMT,
                         buffer->length - request_length,
                         CLIENT_INFO_ARGS);
        buffer->length = request_length;
    }

    buffer->offset = request_length;
    dispatch_data.data = buffer->str;
    dispatch_data.info.len = buffer->length;

    if (http_server::dispatch_request(serv, protocol, _socket, &dispatch_data) < 0) {
        goto _close_fd;
    }

    if (conn->active && !_socket->removed) {
        port->destroy_http_request(conn);
        if (_socket->recv_buffer && _socket->recv_buffer->size > SW_BUFFER_SIZE_BIG * 2) {
            delete _socket->recv_buffer;
            _socket->recv_buffer = nullptr;
        } else {
            buffer->clear();
        }
    }

    return SW_OK;
}

int ListenPort::readable_callback_redis(Reactor *reactor, ListenPort *port, Event *event) {
    auto _socket = event->socket;
    auto conn = static_cast<Connection *>(_socket->object);
    auto protocol = &port->protocol;
    auto serv = static_cast<Server *>(reactor->ptr);
    auto buffer = serv->get_recv_buffer(_socket);

    if (redis::recv_packet(protocol, conn, buffer) < 0) {
        conn->close_errno = errno;
        reactor->trigger_close_event(event);
    }

    return SW_OK;
}

int ListenPort::readable_callback_eof(Reactor *reactor, ListenPort *port, Event *event) {
    Socket *_socket = event->socket;
    auto *conn = static_cast<Connection *>(_socket->object);
    Protocol *protocol = &port->protocol;
    auto *serv = static_cast<Server *>(reactor->ptr);

    String *buffer = serv->get_recv_buffer(_socket);
    if (!buffer) {
        reactor->trigger_close_event(event);
        return SW_ERR;
    }

    if (protocol->recv_with_eof_protocol(_socket, buffer) < 0) {
        conn->close_errno = errno;
        reactor->trigger_close_event(event);
    }

    // If the length is 0, which means the onPackage has been called, we can free the buffer.
    if (_socket->recv_buffer && _socket->recv_buffer->length == 0 &&
        _socket->recv_buffer->size > SW_BUFFER_SIZE_BIG * 2) {
        delete _socket->recv_buffer;
        _socket->recv_buffer = nullptr;
    }

    return SW_OK;
}

void ListenPort::close() {
#ifdef SW_USE_OPENSSL
    if (ssl) {
        if (ssl_context) {
            ssl_context.reset();
        }
#ifdef SW_SUPPORT_DTLS
        delete dtls_sessions;
#endif
    }
#endif

    if (socket) {
        socket->free();
        socket = nullptr;
    }

    // remove unix socket file
    if (type == SW_SOCK_UNIX_STREAM || type == SW_SOCK_UNIX_DGRAM) {
        unlink(host.c_str());
    }
}

const char *ListenPort::get_protocols() const {
    if (is_dgram()) {
        return "dgram";
    }
    if (open_eof_check) {
        return "eof";
    } else if (open_length_check) {
        return "length";
    } else if (open_http_protocol) {
        if (open_http2_protocol && open_websocket_protocol) {
            return "http|http2|websocket";
        } else if (open_http2_protocol) {
            return "http|http2";
        } else if (open_websocket_protocol) {
            return "http|websocket";
        } else {
            return "http";
        }
    } else if (open_mqtt_protocol) {
        return "mqtt";
    } else if (open_redis_protocol) {
        return "redis";
    } else {
        return "raw";
    }
}

size_t ListenPort::get_connection_num() const {
    if (gs->connection_nums) {
        size_t num = 0;
        for (uint32_t i = 0; i < sw_server()->worker_num; i++) {
            num += gs->connection_nums[i];
        }
        return num;
    } else {
        return gs->connection_num;
    }
}

int ListenPort::create_socket() {
    auto *server = static_cast<Server *>(protocol.private_data_2);
    if (socket) {
#if defined(__linux__) && defined(HAVE_REUSEPORT)
        if (server->enable_reuse_port) {
            close_socket();
        } else
#endif
        {
            return SW_OK;
        }
    }

    socket =
        make_socket(type, is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (socket == nullptr) {
        swoole_set_last_error(errno);
        return SW_ERR;
    }

#if defined(SW_SUPPORT_DTLS) && defined(HAVE_KQUEUE)
    if (is_dtls()) {
        socket->set_reuse_port();
    }
#endif

#if defined(__linux__) && defined(HAVE_REUSEPORT)
    if (server->enable_reuse_port) {
        if (socket->set_reuse_port() < 0) {
            goto __cleanup;
        }
    }
#endif

    Address addr;
    if (!addr.assign(type, host, port, true)) {
        auto type_str = Address::type_str(type);
        swoole_warning("Invalid %s address '%s:%d'", type_str, host.c_str(), port);
        goto __cleanup;
    }

    if (socket->set_reuse_addr() < 0) {
        swoole_sys_warning("setsockopt(%d, SO_REUSEADDR) failed", socket->get_fd());
    }

    if (socket->bind(addr) < 0) {
        goto __cleanup;
    }

    if (socket->get_name() < 0) {
    __cleanup:
        swoole_set_last_error(errno);
        socket->free();
        return SW_ERR;
    }

    port = socket->get_port();

    return SW_OK;
}

void ListenPort::close_socket() {
    if (::close(socket->fd) < 0) {
        swoole_sys_warning("close(%d) failed", socket->fd);
    }
    delete socket;
    socket = nullptr;
}

void ListenPort::destroy_http_request(Connection *conn) {
    auto request = static_cast<Request *>(conn->object);
    if (!request) {
        return;
    }
    delete request;
    conn->object = nullptr;
}

}  // namespace swoole
