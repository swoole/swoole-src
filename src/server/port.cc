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
#include "swoole_mqtt.h"
#include "swoole_redis.h"

using swoole::http_server::Request;
using swoole::network::Address;
using swoole::network::Socket;

namespace swoole {

static int Port_onRead_raw(Reactor *reactor, ListenPort *lp, Event *event);
static int Port_onRead_check_length(Reactor *reactor, ListenPort *lp, Event *event);
static int Port_onRead_check_eof(Reactor *reactor, ListenPort *lp, Event *event);
static int Port_onRead_http(Reactor *reactor, ListenPort *lp, Event *event);
static int Port_onRead_redis(Reactor *reactor, ListenPort *lp, Event *event);

ListenPort::ListenPort() {
    protocol.package_length_type = 'N';
    protocol.package_length_size = 4;
    protocol.package_body_offset = 4;
    protocol.package_max_length = SW_INPUT_BUFFER_SIZE;

    protocol.package_eof_len = sizeof(SW_DATA_EOF) - 1;
    memcpy(protocol.package_eof, SW_DATA_EOF, protocol.package_eof_len);
}

#ifdef SW_USE_OPENSSL

bool ListenPort::ssl_add_sni_cert(const std::string &name, SSLContext *ctx) {
    if (!ssl_create_context(ctx)) {
        return false;
    }
    sni_contexts.emplace(name, std::shared_ptr<SSLContext>(ctx));
    return true;
}

static bool ssl_matches_wildcard_name(const char *subjectname, const char *certname) {
    const char *wildcard = NULL;
    ptrdiff_t prefix_len;
    size_t suffix_len, subject_len;

    if (strcasecmp(subjectname, certname) == 0) {
        return 1;
    }

    /* wildcard, if present, must only be present in the left-most component */
    if (!(wildcard = strchr(certname, '*')) || memchr(certname, '.', wildcard - certname)) {
        return 0;
    }

    /* 1) prefix, if not empty, must match subject */
    prefix_len = wildcard - certname;
    if (prefix_len && strncasecmp(subjectname, certname, prefix_len) != 0) {
        return 0;
    }

    suffix_len = strlen(wildcard + 1);
    subject_len = strlen(subjectname);
    if (suffix_len <= subject_len) {
        /* 2) suffix must match
         * 3) no . between prefix and suffix
         **/
        return strcasecmp(wildcard + 1, subjectname + subject_len - suffix_len) == 0 &&
               memchr(subjectname + prefix_len, '.', subject_len - suffix_len - prefix_len) == NULL;
    }

    return 0;
}

static int ssl_server_sni_callback(SSL *ssl, int *al, void *arg) {
    const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!server_name) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    ListenPort *port = (ListenPort *) SSL_get_ex_data(ssl, swoole_ssl_get_ex_port_index());

    if (port->sni_contexts.empty()) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    for (auto i = port->sni_contexts.begin(); i != port->sni_contexts.end(); i++) {
        if (ssl_matches_wildcard_name(server_name, i->first.c_str())) {
            SSL_set_SSL_CTX(ssl, i->second->get_context());
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

bool ListenPort::ssl_init() {
    if (!ssl_create_context(ssl_context)) {
        return false;
    }
    if (sni_contexts.size() > 0) {
        SSL_CTX_set_tlsext_servername_callback(ssl_context->get_context(), ssl_server_sni_callback);
    }
    return true;
}

bool ListenPort::ssl_create(Connection *conn, Socket *sock) {
    if (sock->ssl_create(ssl_context, SW_SSL_SERVER) < 0) {
        return false;
    }
    conn->ssl = 1;
    if (SSL_set_ex_data(sock->ssl, swoole_ssl_get_ex_port_index(), this) == 0) {
        swoole_warning("SSL_set_ex_data() failed");
        return false;
    }
    return true;
}

bool ListenPort::ssl_create_context(SSLContext *context) {
    if (context->cert_file.empty() || context->key_file.empty()) {
        swoole_warning("SSL error, require ssl_cert_file and ssl_key_file");
        return false;
    }
    if (open_http_protocol) {
        context->http = 1;
    }
    if (open_http2_protocol) {
        context->http_v2 = 1;
    }
    if (!context->create()) {
        swoole_warning("swSSL_get_context() error");
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

    buffer_high_watermark = socket_buffer_size * 0.8;
    buffer_low_watermark = 0;

    return SW_OK;
}

void Server::init_port_protocol(ListenPort *ls) {
    ls->protocol.private_data_2 = this;
    // Thread mode must copy the data.
    // will free after onFinish
    if (ls->open_eof_check) {
        if (ls->protocol.package_eof_len > SW_DATA_EOF_MAXLEN) {
            ls->protocol.package_eof_len = SW_DATA_EOF_MAXLEN;
        }
        ls->protocol.onPackage = Server::dispatch_task;
        ls->onRead = Port_onRead_check_eof;
    } else if (ls->open_length_check) {
        if (ls->protocol.package_length_type != '\0') {
            ls->protocol.get_package_length = Protocol::default_length_func;
        }
        ls->protocol.onPackage = Server::dispatch_task;
        ls->onRead = Port_onRead_check_length;
    } else if (ls->open_http_protocol) {
#ifdef SW_USE_HTTP2
        if (ls->open_http2_protocol && ls->open_websocket_protocol) {
            ls->protocol.get_package_length = http_server::get_package_length;
            ls->protocol.get_package_length_size = http_server::get_package_length_size;
            ls->protocol.onPackage = http_server::dispatch_frame;
        } else if (ls->open_http2_protocol) {
            ls->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
            ls->protocol.get_package_length = http2::get_frame_length;
            ls->protocol.onPackage = Server::dispatch_task;
        } else
#endif
            if (ls->open_websocket_protocol) {
            ls->protocol.package_length_size = SW_WEBSOCKET_MESSAGE_HEADER_SIZE;
            ls->protocol.get_package_length = websocket::get_package_length;
            ls->protocol.onPackage = websocket::dispatch_frame;
        }
        ls->protocol.package_length_offset = 0;
        ls->protocol.package_body_offset = 0;
        ls->onRead = Port_onRead_http;
    } else if (ls->open_mqtt_protocol) {
        mqtt::set_protocol(&ls->protocol);
        ls->protocol.onPackage = Server::dispatch_task;
        ls->onRead = Port_onRead_check_length;
    } else if (ls->open_redis_protocol) {
        ls->protocol.onPackage = Server::dispatch_task;
        ls->onRead = Port_onRead_redis;
    } else {
        ls->onRead = Port_onRead_raw;
    }
}

/**
 * @description: import listen port from socket-fd
 */
bool ListenPort::import(int sock) {
    int _type, _family;

    socket = new Socket();
    socket->fd = sock;

    // get socket type
    if (socket->get_option(SOL_SOCKET, SO_TYPE, &_type) < 0) {
        swoole_sys_warning("getsockopt(%d, SOL_SOCKET, SO_TYPE) failed", sock);
        return false;
    }
    if (socket->get_name(&socket->info) < 0) {
        swoole_sys_warning("getsockname(%d) failed", sock);
        return false;
    }

    _family = socket->info.addr.ss.sa_family;
    socket->socket_type = socket->info.type = type = Socket::convert_to_type(_family, _type);
    host = socket->info.get_addr();
    port = socket->info.get_port();
    listening = true;

    socket->fd_type = socket->is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER;
    socket->removed = 1;

    return true;
}

void ListenPort::clear_protocol() {
    open_eof_check = 0;
    open_length_check = 0;
    open_http_protocol = 0;
    open_websocket_protocol = 0;
#ifdef SW_USE_HTTP2
    open_http2_protocol = 0;
#endif
    open_mqtt_protocol = 0;
    open_redis_protocol = 0;
}

static int Port_onRead_raw(Reactor *reactor, ListenPort *port, Event *event) {
    ssize_t n;
    Socket *_socket = event->socket;
    Connection *conn = (Connection *) _socket->object;
    Server *serv = (Server *) reactor->ptr;
    RecvData rdata{};

    String *buffer = serv->get_recv_buffer(_socket);
    if (!buffer) {
        return SW_ERR;
    }

    n = _socket->recv(buffer->str, buffer->size, 0);
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

static int Port_onRead_check_length(Reactor *reactor, ListenPort *port, Event *event) {
    Socket *_socket = event->socket;
    Connection *conn = (Connection *) _socket->object;
    Protocol *protocol = &port->protocol;
    Server *serv = (Server *) reactor->ptr;

    String *buffer = serv->get_recv_buffer(_socket);
    if (!buffer) {
        reactor->trigger_close_event(event);
        return SW_ERR;
    }

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
static int Port_onRead_http(Reactor *reactor, ListenPort *port, Event *event) {
    Socket *_socket = event->socket;
    Connection *conn = (Connection *) _socket->object;
    Server *serv = (Server *) reactor->ptr;
    RecvData dispatch_data{};

    if (conn->websocket_status >= websocket::STATUS_HANDSHAKE) {
        if (conn->http_upgrade == 0) {
            serv->destroy_http_request(conn);
            conn->websocket_status = websocket::STATUS_ACTIVE;
            conn->http_upgrade = 1;
        }
        return Port_onRead_check_length(reactor, port, event);
    }

#ifdef SW_USE_HTTP2
    if (conn->http2_stream) {
        return Port_onRead_check_length(reactor, port, event);
    }
#endif

    Request *request = nullptr;
    Protocol *protocol = &port->protocol;

    if (conn->object == nullptr) {
        request = new Request();
        conn->object = request;
    } else {
        request = reinterpret_cast<Request *>(conn->object);
    }

    if (!request->buffer_) {
        request->buffer_ = serv->get_recv_buffer(_socket);
        if (!request->buffer_) {
            reactor->trigger_close_event(event);
            return SW_ERR;
        }
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
        if (0) {
        _bad_request:
#ifdef SW_HTTP_BAD_REQUEST_PACKET
            _socket->send(SW_STRL(SW_HTTP_BAD_REQUEST_PACKET), 0);
#endif
        }
        if (0) {
        _too_large:
#ifdef SW_HTTP_REQUEST_ENTITY_TOO_LARGE_PACKET
            _socket->send(SW_STRL(SW_HTTP_REQUEST_ENTITY_TOO_LARGE_PACKET), 0);
#endif
        }
        if (0) {
        _unavailable:
#ifdef SW_HTTP_SERVICE_UNAVAILABLE_PACKET
            _socket->send(SW_STRL(SW_HTTP_SERVICE_UNAVAILABLE_PACKET), 0);
#endif
        }
    _close_fd:
        serv->destroy_http_request(conn);
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
#ifdef SW_USE_HTTP2
        if (sw_unlikely(!port->open_http2_protocol)) {
#endif
            swoole_error_log(SW_LOG_TRACE,
                             SW_ERROR_HTTP_INVALID_PROTOCOL,
                             "Bad Request: can not handle HTTP2 request" CLIENT_INFO_FMT,
                             CLIENT_INFO_ARGS);
            goto _bad_request;
#ifdef SW_USE_HTTP2
        }
        conn->http2_stream = 1;
        http2::send_setting_frame(protocol, _socket);
        if (buffer->length == sizeof(SW_HTTP2_PRI_STRING) - 1) {
            serv->destroy_http_request(conn);
            buffer->clear();
            return SW_OK;
        }
        buffer->reduce(buffer->offset);
        serv->destroy_http_request(conn);
        conn->socket->skip_recv = 1;
        return Port_onRead_check_length(reactor, port, event);
#endif
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
        swoole_trace_log(SW_TRACE_SERVER,
                         "content-length=%" PRIu64 ", keep-alive=%u, chunked=%u",
                         request->content_length_,
                         request->keep_alive,
                         request->chunked);
    }

    // content length (equal to 0) or (field not found but not chunked)
    if (!request->tried_to_dispatch) {
        // recv nobody_chunked eof
        if (request->nobody_chunked) {
            if (buffer->length < request->header_length_ + (sizeof(SW_HTTP_CHUNK_EOF) - 1)) {
                goto _recv_data;
            }
            request->header_length_ += (sizeof("0\r\n\r\n") - 1);
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
                if (Server::dispatch_task(protocol, _socket, &dispatch_data) < 0) {
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
                serv->destroy_http_request(conn);
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
            request_length = request->header_length_ + request->content_length_;
            if (request_length > protocol->package_max_length) {
                swoole_error_log(SW_LOG_WARNING,
                                 SW_ERROR_HTTP_INVALID_PROTOCOL,
                                 "Request Entity Too Large: request length (chunked) has already been greater than the "
                                 "package_max_length(%u)" CLIENT_INFO_FMT,
                                 protocol->package_max_length,
                                 CLIENT_INFO_ARGS);
                goto _too_large;
            }
            if (buffer->length == buffer->size && !buffer->extend()) {
                goto _unavailable;
            }
            if (request_length > buffer->size && !buffer->extend_align(request_length)) {
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
#ifdef SW_HTTP_100_CONTINUE
            // Expect: 100-continue
            if (request->has_expect_header()) {
                _socket->send(SW_STRL(SW_HTTP_100_CONTINUE_PACKET), 0);
            } else {
                swoole_trace_log(
                    SW_TRACE_SERVER,
                    "PostWait: request->content_length=%d, buffer->length=%zu, request->header_length=%d\n",
                    request->content_length,
                    buffer_->length,
                    request->header_length);
            }
#endif
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

    if (Server::dispatch_task(protocol, _socket, &dispatch_data) < 0) {
        goto _close_fd;
    }

    if (conn->active && !_socket->removed) {
        serv->destroy_http_request(conn);
        if (_socket->recv_buffer && _socket->recv_buffer->size > SW_BUFFER_SIZE_BIG * 2) {
            delete _socket->recv_buffer;
            _socket->recv_buffer = nullptr;
        } else {
            buffer->clear();
        }
    }

    return SW_OK;
}

static int Port_onRead_redis(Reactor *reactor, ListenPort *port, Event *event) {
    Socket *_socket = event->socket;
    Connection *conn = (Connection *) _socket->object;
    Protocol *protocol = &port->protocol;
    Server *serv = (Server *) reactor->ptr;

    String *buffer = serv->get_recv_buffer(_socket);
    if (!buffer) {
        reactor->trigger_close_event(event);
        return SW_ERR;
    }

    if (redis::recv_packet(protocol, conn, buffer) < 0) {
        conn->close_errno = errno;
        reactor->trigger_close_event(event);
    }

    return SW_OK;
}

static int Port_onRead_check_eof(Reactor *reactor, ListenPort *port, Event *event) {
    Socket *_socket = event->socket;
    Connection *conn = (Connection *) _socket->object;
    Protocol *protocol = &port->protocol;
    Server *serv = (Server *) reactor->ptr;

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
            delete ssl_context;
        }
#ifdef SW_SUPPORT_DTLS
        if (dtls_sessions) {
            delete dtls_sessions;
        }
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

const char *ListenPort::get_protocols() {
    if (is_dgram()) {
        return "dgram";
    }
    if (open_eof_check) {
        return "eof";
    } else if (open_length_check) {
        return "length";
    } else if (open_http_protocol) {
#ifdef SW_USE_HTTP2
        if (open_http2_protocol && open_websocket_protocol) {
            return "http|http2|websocket";
        } else if (open_http2_protocol) {
            return "http|http2";
        } else
#endif
            if (open_websocket_protocol) {
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

}  // namespace swoole
