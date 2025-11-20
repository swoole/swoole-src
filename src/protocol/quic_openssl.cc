/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
  | Author: Refactored for OpenSSL 3.5 native QUIC API                   |
  +----------------------------------------------------------------------+
*/

#include "swoole_quic_openssl.h"
#include "swoole_string.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>

#ifdef SW_USE_QUIC

namespace swoole {
namespace quic {

using ::swoole::make_string;
using ::swoole::microtime;

// ALPN protocol for HTTP/3
static const unsigned char alpn_h3[] = { 2, 'h', '3' };

// ============================================================================
// ALPN Callback
// ============================================================================

int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *out_len,
                         const unsigned char *in, unsigned int in_len, void *arg) {
    swoole_trace_log(SW_TRACE_QUIC, "ALPN callback: client offers %u bytes", in_len);

    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_h3, sizeof(alpn_h3),
                              in, in_len) == OPENSSL_NPN_NEGOTIATED) {
        swoole_trace_log(SW_TRACE_QUIC, "ALPN: Successfully negotiated h3");
        return SSL_TLSEXT_ERR_OK;
    }

    swoole_warning("ALPN: No match, client did not offer h3");
    return SSL_TLSEXT_ERR_NOACK;
}

// ============================================================================
// SSL_CTX Creation
// ============================================================================

SSL_CTX* create_quic_server_context(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx;

    swoole_trace_log(SW_TRACE_QUIC, "Creating QUIC server context");

    // Use OpenSSL 3.5 native QUIC server method
    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == nullptr) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_CTX_new(OSSL_QUIC_server_method) failed");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Loading certificate chain: %s", cert_file);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "Failed to load certificate chain: %s", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Loading private key: %s", key_file);
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "Failed to load private key: %s", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // No client certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // Setup ALPN negotiation callback
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, nullptr);

    swoole_trace_log(SW_TRACE_QUIC, "SSL_CTX created successfully");
    return ctx;
}

// ============================================================================
// Stream Implementation
// ============================================================================

Stream::Stream(int64_t id, Connection *c) {
    stream_id = id;
    conn = c;
    state = SW_QUIC_STREAM_IDLE;
    ssl_stream = nullptr;

    recv_buffer = make_string(SW_QUIC_MAX_STREAM_DATA);
    send_buffer = make_string(SW_QUIC_MAX_STREAM_DATA);

    rx_max_data = SW_QUIC_MAX_STREAM_DATA;
    rx_offset = 0;
    tx_max_data = SW_QUIC_MAX_STREAM_DATA;
    tx_offset = 0;

    fin_received = 0;
    fin_sent = 0;
    rst_received = 0;
    rst_sent = 0;

    user_data = nullptr;

    // Create or accept SSL stream object
    if (conn && conn->ssl) {
        // For server-initiated unidirectional streams (like HTTP/3 control streams),
        // we need to create new streams. Client-initiated streams will be accepted later.
        // HTTP/3 control streams: 3 (control), 7 (QPACK encoder), 11 (QPACK decoder)
        bool is_server_stream = (stream_id % 4) == 3 || (stream_id % 4) == 2;  // Server-initiated

        if (is_server_stream) {
            // Create new outgoing stream
            ssl_stream = SSL_new_stream(conn->ssl, SSL_STREAM_FLAG_UNI);
            if (ssl_stream) {
                uint64_t actual_stream_id = SSL_get_stream_id(ssl_stream);
                swoole_warning("[DEBUG] Stream %ld: SSL stream created, actual SSL stream ID=%lu", stream_id, actual_stream_id);
            } else {
                swoole_warning("Stream %ld: Failed to create SSL stream", stream_id);
            }
        }
        // For client-initiated streams, ssl_stream will be set later when needed
    }

    swoole_trace_log(SW_TRACE_QUIC, "Stream %ld created", stream_id);
}

Stream::~Stream() {
    if (ssl_stream) {
        SSL_free(ssl_stream);
        ssl_stream = nullptr;
    }

    if (recv_buffer) {
        delete recv_buffer;
    }
    if (send_buffer) {
        delete send_buffer;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Stream %ld destroyed", stream_id);
}

bool Stream::send_data(const uint8_t *data, size_t len, bool fin) {
    if (state == SW_QUIC_STREAM_CLOSED) {
        swoole_warning("Stream %ld is closed, cannot send", stream_id);
        return false;
    }

    if (!ssl_stream) {
        swoole_warning("Stream %ld: No SSL stream object", stream_id);
        return false;
    }

    // Write data directly using per-stream SSL object
    if (len > 0) {
        size_t nwritten = 0;
        int ret = SSL_write_ex(ssl_stream, data, len, &nwritten);
        if (ret <= 0) {
            int ssl_error = SSL_get_error(ssl_stream, ret);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                swoole_warning("Stream %ld: SSL_write_ex failed, error=%d", stream_id, ssl_error);
                return false;
            }
        }
        swoole_trace_log(SW_TRACE_QUIC, "Stream %ld: wrote %zu bytes", stream_id, nwritten);
    }

    if (fin) {
        // Send FIN by concluding the stream
        if (SSL_stream_conclude(ssl_stream, 0) != 1) {
            swoole_warning("Stream %ld: SSL_stream_conclude failed", stream_id);
        }
        fin_sent = 1;
        state = SW_QUIC_STREAM_HALF_CLOSED_LOCAL;
    }

    return true;
}

bool Stream::recv_data(const uint8_t *data, size_t len, bool fin) {
    if (state == SW_QUIC_STREAM_CLOSED) {
        swoole_warning("Stream %ld is closed, ignoring data", stream_id);
        return false;
    }

    // Append to receive buffer
    recv_buffer->append((const char *)data, len);

    if (fin) {
        fin_received = 1;
        if (state == SW_QUIC_STREAM_HALF_CLOSED_LOCAL) {
            state = SW_QUIC_STREAM_CLOSED;
        } else {
            state = SW_QUIC_STREAM_HALF_CLOSED_REMOTE;
        }
    }

    swoole_trace_log(SW_TRACE_QUIC, "Stream %ld: received %zu bytes (fin=%d)",
                    stream_id, len, fin);

    // Trigger callback if set
    if (conn && conn->on_stream_data) {
        conn->on_stream_data(conn, this, data, len);
    }

    return true;
}

bool Stream::close(uint64_t error_code) {
    if (state == SW_QUIC_STREAM_CLOSED) {
        return true;
    }

    state = SW_QUIC_STREAM_CLOSED;

    swoole_trace_log(SW_TRACE_QUIC, "Stream %ld closed with error code %lu",
                    stream_id, error_code);

    // Trigger callback if set
    if (conn && conn->on_stream_close) {
        conn->on_stream_close(conn, this);
    }

    return true;
}

// ============================================================================
// Listener Implementation
// ============================================================================

Listener::Listener() {
    ssl_ctx = nullptr;
    ssl_listener = nullptr;
    udp_fd = -1;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addrlen = 0;

    cert_file = nullptr;
    key_file = nullptr;

    on_connection = nullptr;
    on_stream_open = nullptr;
    on_stream_close = nullptr;
    on_stream_data = nullptr;
    user_data = nullptr;

    swoole_trace_log(SW_TRACE_QUIC, "Listener created");
}

Listener::~Listener() {
    close();
    swoole_trace_log(SW_TRACE_QUIC, "Listener destroyed");
}

bool Listener::init(const char *cert, const char *key) {
    cert_file = cert;
    key_file = key;

    // Create SSL_CTX with QUIC server method
    ssl_ctx = create_quic_server_context(cert, key);
    if (!ssl_ctx) {
        return false;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Listener initialized");
    return true;
}

bool Listener::listen(const struct sockaddr *addr, socklen_t addrlen) {
    if (!ssl_ctx) {
        swoole_error_log(SW_ERROR_WRONG_OPERATION, SW_ERROR_WRONG_OPERATION,
                        "SSL_CTX not initialized. Either call init() first or set ssl_ctx before calling listen()");
        return false;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Using existing SSL_CTX: %p", ssl_ctx);

    // Save address
    memcpy(&local_addr, addr, addrlen);
    local_addrlen = addrlen;

    // Step 1: Create UDP socket
    udp_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        swoole_error_log(SW_ERROR_SYSTEM_CALL_FAIL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "Failed to create UDP socket");
        return false;
    }

    // Step 2: Bind UDP socket
    if (::bind(udp_fd, addr, addrlen) < 0) {
        swoole_error_log(SW_ERROR_SYSTEM_CALL_FAIL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "Failed to bind UDP socket");
        ::close(udp_fd);
        udp_fd = -1;
        return false;
    }

    swoole_trace_log(SW_TRACE_QUIC, "UDP socket bound successfully (fd=%d)", udp_fd);

    // Step 3: Create QUIC listener
    ssl_listener = SSL_new_listener(ssl_ctx, 0);
    if (!ssl_listener) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_new_listener failed");
        ERR_print_errors_fp(stderr);
        ::close(udp_fd);
        udp_fd = -1;
        return false;
    }

    // Step 4: Attach UDP socket to SSL listener
    if (!SSL_set_fd(ssl_listener, udp_fd)) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_set_fd failed");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_listener);
        ssl_listener = nullptr;
        ::close(udp_fd);
        udp_fd = -1;
        return false;
    }

    // Step 5: Start listening for QUIC connections
    if (!SSL_listen(ssl_listener)) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_listen failed");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_listener);
        ssl_listener = nullptr;
        ::close(udp_fd);
        udp_fd = -1;
        return false;
    }

    swoole_trace_log(SW_TRACE_QUIC, "QUIC listener ready and listening");
    return true;
}

Connection* Listener::accept_connection() {
    if (!ssl_listener) {
        swoole_warning("Listener not started");
        return nullptr;
    }

    ERR_clear_error();

    // Accept incoming connection
    SSL *conn_ssl = SSL_accept_connection(ssl_listener, 0);
    if (!conn_ssl) {
        unsigned long err = ERR_peek_last_error();
        if (err == 0) {  // No error, just no connection pending
            // No connection available, this is normal
            return nullptr;
        }

        // Real error
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_accept_connection failed");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Create new Connection object
    Connection *new_conn = new Connection();
    if (!new_conn->init_from_ssl(conn_ssl, ssl_ctx)) {
        delete new_conn;
        SSL_free(conn_ssl);
        return nullptr;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Connection accepted");

    // Trigger callback if set
    if (on_connection) {
        on_connection(this, new_conn);
    }

    return new_conn;
}

bool Listener::close() {
    if (ssl_listener) {
        SSL_free(ssl_listener);
        ssl_listener = nullptr;
    }

    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }

    if (udp_fd >= 0) {
        ::close(udp_fd);
        udp_fd = -1;
    }

    swoole_trace_log(SW_TRACE_QUIC, "Listener closed");
    return true;
}

bool Listener::bind(const char *host, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_INVALID_PARAMS, "Invalid host address: %s", host);
        return false;
    }

    return listen((struct sockaddr *)&addr, sizeof(addr));
}

void Listener::run() {
    swoole_trace_log(SW_TRACE_QUIC, "Starting QUIC listener event loop");

    if (!ssl_listener || udp_fd < 0) {
        swoole_error_log(SW_ERROR_WRONG_OPERATION, SW_ERROR_WRONG_OPERATION,
                        "Listener not initialized");
        return;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(udp_fd, F_GETFL, 0);
    fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK);

    swoole_trace_log(SW_TRACE_QUIC, "Event loop started, UDP fd=%d", udp_fd);

    // Simple event loop for accepting connections
    while (true) {
        // Use select to wait for incoming packets
        fd_set readfds;
        struct timeval tv;

        FD_ZERO(&readfds);
        FD_SET(udp_fd, &readfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(udp_fd + 1, &readfds, nullptr, nullptr, &tv);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal, retry
            }
            swoole_error_log(SW_ERROR_SYSTEM_CALL_FAIL, SW_ERROR_SYSTEM_CALL_FAIL,
                            "select() failed: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            // Timeout, continue waiting
            swoole_trace_log(SW_TRACE_QUIC, "select timeout, waiting for connections...");
            continue;
        }

        if (FD_ISSET(udp_fd, &readfds)) {
            swoole_trace_log(SW_TRACE_QUIC, "Incoming QUIC packet detected");

            // Try to accept new connection
            Connection *conn = accept_connection();
            if (conn) {
                swoole_trace_log(SW_TRACE_QUIC, "Connection accepted");

                // Set up stream callbacks on the connection
                if (on_stream_open) {
                    conn->on_stream_open = on_stream_open;
                }
                if (on_stream_close) {
                    conn->on_stream_close = on_stream_close;
                }
                if (on_stream_data) {
                    conn->on_stream_data = on_stream_data;
                }

                // Add to active connections list
                active_connections.push_back(conn);

                // Trigger connection callback
                if (on_connection) {
                    on_connection(this, conn);
                }
            }
        }

        // Process events for all active connections
        for (auto it = active_connections.begin(); it != active_connections.end(); ) {
            Connection *conn = *it;

            // Process streams and I/O for this connection
            if (!conn->process_events()) {
                swoole_trace_log(SW_TRACE_QUIC, "Connection closed, removing from active list");
                it = active_connections.erase(it);
                delete conn;
                continue;
            }

            ++it;
        }
    }

    swoole_trace_log(SW_TRACE_QUIC, "Event loop exited");
}

// ============================================================================
// Connection Implementation
// ============================================================================

Connection::Connection() {
    ssl = nullptr;
    ssl_ctx = nullptr;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addrlen = 0;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addrlen = 0;

    state = SW_QUIC_STATE_INITIAL;

    next_stream_id = 0;
    max_streams = SW_QUIC_MAX_STREAMS;

    send_buffer_size = SW_QUIC_MAX_PACKET_SIZE * 4;
    send_buffer = (uint8_t *)sw_malloc(send_buffer_size);

    recv_buffer_size = SW_QUIC_MAX_PACKET_SIZE * 4;
    recv_buffer = (uint8_t *)sw_malloc(recv_buffer_size);

    last_ts = swoole::microtime();

    on_stream_open = nullptr;
    on_stream_close = nullptr;
    on_stream_data = nullptr;
    on_connection_close = nullptr;

    user_data = nullptr;

    is_server = 1;
    handshake_completed = 0;
    draining = 0;

    swoole_trace_log(SW_TRACE_QUIC, "Connection created");
}

Connection::~Connection() {
    close();

    if (send_buffer) {
        sw_free(send_buffer);
    }
    if (recv_buffer) {
        sw_free(recv_buffer);
    }

    // Clean up streams
    for (auto &pair : streams) {
        delete pair.second;
    }
    streams.clear();

    swoole_trace_log(SW_TRACE_QUIC, "Connection destroyed");
}

bool Connection::init_from_ssl(SSL *ssl_conn, SSL_CTX *ctx) {
    ssl = ssl_conn;
    ssl_ctx = ctx;  // Note: shared with Listener, don't free
    state = SW_QUIC_STATE_ESTABLISHED;
    handshake_completed = 1;

    // Configure connection for HTTP/3: no default stream, explicit stream management
    if (!SSL_set_default_stream_mode(ssl, SSL_DEFAULT_STREAM_MODE_NONE)) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_set_default_stream_mode failed on connection");
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Accept incoming streams so they're available via SSL_accept_stream()
    if (!SSL_set_incoming_stream_policy(ssl, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0)) {
        swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                        "SSL_set_incoming_stream_policy failed on connection");
        ERR_print_errors_fp(stderr);
        return false;
    }

    // TODO: Get remote address from SSL object if available

    swoole_trace_log(SW_TRACE_QUIC, "Connection initialized from SSL object with HTTP/3 configuration");
    return true;
}

Stream* Connection::create_stream(int64_t stream_id) {
    if (streams.find(stream_id) != streams.end()) {
        swoole_warning("Stream %ld already exists", stream_id);
        return streams[stream_id];
    }

    if (streams.size() >= max_streams) {
        swoole_warning("Maximum streams (%lu) reached", max_streams);
        return nullptr;
    }

    Stream *stream = new Stream(stream_id, this);
    stream->state = SW_QUIC_STREAM_OPEN;
    streams[stream_id] = stream;

    swoole_trace_log(SW_TRACE_QUIC, "Stream %ld created", stream_id);

    // Trigger callback if set
    if (on_stream_open) {
        on_stream_open(this, stream);
    }

    return stream;
}

Stream* Connection::get_stream(int64_t stream_id) {
    auto it = streams.find(stream_id);
    if (it == streams.end()) {
        return nullptr;
    }
    return it->second;
}

// Backward compatibility wrapper for HTTP/3 layer
Stream* Connection::open_stream(int64_t stream_id) {
    // If stream_id is -1 (default), allocate a new one
    if (stream_id == -1) {
        stream_id = next_stream_id;
        if (is_server) {
            // Server-initiated streams are odd-numbered (1, 3, 5, ...)
            // Make sure we start with 1 if next_stream_id is 0
            if (next_stream_id == 0) {
                next_stream_id = 1;
            }
            stream_id = next_stream_id;
            next_stream_id += 2;  // Skip to next odd number
        } else {
            // Client-initiated streams are even-numbered (0, 2, 4, ...)
            stream_id = next_stream_id;
            next_stream_id += 2;  // Skip to next even number
        }
    }

    // Create the stream
    return create_stream(stream_id);
}

bool Connection::close_stream(int64_t stream_id, uint64_t error_code) {
    Stream *stream = get_stream(stream_id);
    if (!stream) {
        return false;
    }

    stream->close(error_code);
    return true;
}

ssize_t Connection::read_stream(int64_t stream_id, uint8_t *buf, size_t len) {
    if (!ssl) {
        return -1;
    }

    size_t nread = 0;
    int ret = SSL_read_ex(ssl, buf, len, &nread);

    if (ret > 0) {
        swoole_trace_log(SW_TRACE_QUIC, "Read %zu bytes from stream %ld", nread, stream_id);
        return nread;
    }

    int ssl_error = SSL_get_error(ssl, ret);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        // Non-blocking I/O, retry later
        return 0;
    }

    // Error
    swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                    "SSL_read_ex failed: error=%d", ssl_error);
    ERR_print_errors_fp(stderr);
    return -1;
}

ssize_t Connection::write_stream(int64_t stream_id, const uint8_t *data, size_t len, bool fin) {
    if (!ssl) {
        return -1;
    }

    size_t nwritten = 0;
    int ret = SSL_write_ex(ssl, data, len, &nwritten);

    if (ret > 0) {
        swoole_trace_log(SW_TRACE_QUIC, "Wrote %zu bytes to stream %ld (fin=%d)",
                        nwritten, stream_id, fin);

        // If this is FIN, conclude the stream
        if (fin) {
            if (SSL_stream_conclude(ssl, 0) != 1) {
                swoole_warning("SSL_stream_conclude failed");
            }
        }

        return nwritten;
    }

    int ssl_error = SSL_get_error(ssl, ret);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        return 0;
    }

    swoole_error_log(SW_ERROR_SSL_BAD_PROTOCOL, SW_ERROR_SYSTEM_CALL_FAIL,
                    "SSL_write_ex failed: error=%d", ssl_error);
    ERR_print_errors_fp(stderr);
    return -1;
}

bool Connection::close(uint64_t error_code) {
    if (state == SW_QUIC_STATE_CLOSED) {
        return true;
    }

    state = SW_QUIC_STATE_CLOSING;

    // Close all streams
    for (auto &pair : streams) {
        Stream *stream = pair.second;
        if (ssl && stream->state != SW_QUIC_STREAM_CLOSED) {
            SSL_stream_conclude(ssl, 0);
        }
    }

    if (ssl) {
        // Shutdown connection (may need multiple calls)
        int shutdown_ret;
        do {
            shutdown_ret = SSL_shutdown(ssl);
        } while (shutdown_ret == 0);

        SSL_free(ssl);
        ssl = nullptr;
    }

    // Note: Don't free ssl_ctx, it's shared with Listener

    state = SW_QUIC_STATE_CLOSED;

    // Trigger callback if set
    if (on_connection_close) {
        on_connection_close(this, error_code);
    }

    swoole_trace_log(SW_TRACE_QUIC, "Connection closed with error code %lu", error_code);

    return true;
}

bool Connection::process_events() {
    if (!ssl) {
        return false;
    }

    // Pump I/O to process incoming data and make streams available
    // This is required for OpenSSL QUIC to process incoming packets
    char pump_buffer[1];
    size_t pump_bytes;
    SSL_peek_ex(ssl, pump_buffer, 0, &pump_bytes);  // Pump without reading

    // Try to accept new streams
    while (true) {
        SSL *stream_ssl = SSL_accept_stream(ssl, 0);  // Non-blocking
        if (!stream_ssl) {
            // No more streams available
            break;
        }

        // Get stream ID from the SSL object
        uint64_t stream_id = SSL_get_stream_id(stream_ssl);

        // Check stream type based on stream ID
        // Bit 0: 0=client-initiated, 1=server-initiated
        // Bit 1: 0=bidirectional, 1=unidirectional
        bool is_unidirectional = (stream_id & 0x2) != 0;
        bool is_client_initiated = (stream_id & 0x1) == 0;

        swoole_warning("[DEBUG] SSL_accept_stream: ID=%lu (uni=%d, client=%d)",
                        stream_id, is_unidirectional, is_client_initiated);

        // Get or create stream object
        Stream *stream = get_stream(stream_id);
        if (!stream) {
            // Create new stream object
            stream = create_stream(stream_id);
            if (!stream) {
                swoole_warning("Failed to create stream %lu", stream_id);
                SSL_free(stream_ssl);
                break;
            }
        }

        // Attach the SSL stream object if not already attached
        if (!stream->ssl_stream) {
            stream->ssl_stream = stream_ssl;
            swoole_warning("[DEBUG] Attached SSL stream to stream %lu", stream_id);
        } else {
            // Stream already has an SSL object (server-initiated stream)
            // Free the duplicate one from SSL_accept_stream
            swoole_warning("[DEBUG] Stream %lu already has SSL object, freeing duplicate", stream_id);
            SSL_free(stream_ssl);
            stream_ssl = stream->ssl_stream;  // Use the existing one
        }

        // Read data from the stream
        uint8_t buffer[8192];
        size_t nread = 0;
        size_t total_read = 0;

        while (SSL_read_ex(stream_ssl, buffer, sizeof(buffer), &nread) > 0) {
            total_read += nread;
            swoole_trace_log(SW_TRACE_QUIC, "Read %zu bytes from stream %lu (uni=%d)",
                            nread, stream_id, is_unidirectional);

            // Trigger callback with received data for ALL streams
            // nghttp3 needs to process:
            // - Bidirectional streams (0, 4, 8...): HTTP requests
            // - Unidirectional streams (2, 6, 10...): Control and QPACK streams from client
            if (on_stream_data && nread > 0) {
                on_stream_data(this, stream, buffer, nread);
            }

            if (is_unidirectional) {
                swoole_trace_log(SW_TRACE_QUIC, "Unidirectional stream %lu data (%zu bytes) sent to HTTP/3 layer",
                                stream_id, nread);
            }

            nread = 0;
        }

        if (total_read > 0) {
            swoole_trace_log(SW_TRACE_QUIC, "Total %zu bytes read from stream %lu", total_read, stream_id);
        }

        // Check if stream is finished
        if (SSL_get_stream_read_state(stream_ssl) == SSL_STREAM_STATE_FINISHED) {
            swoole_trace_log(SW_TRACE_QUIC, "Stream %lu finished (EOF)", stream_id);
            stream->fin_received = 1;
        }

        // Keep the stream SSL object alive - it's stored in stream->ssl_stream
        // and will be freed when the Stream is destroyed
    }

    return true;
}

const char* Connection::get_alpn_protocol() {
    if (!ssl) {
        return nullptr;
    }

    const unsigned char *alpn = nullptr;
    unsigned int alpnlen = 0;

    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);

    if (alpn && alpnlen > 0) {
        static char alpn_buf[256];
        memcpy(alpn_buf, alpn, std::min((unsigned int)sizeof(alpn_buf) - 1, alpnlen));
        alpn_buf[alpnlen] = '\0';
        return alpn_buf;
    }

    return nullptr;
}

}  // namespace quic
}  // namespace swoole

#endif  // SW_USE_QUIC
