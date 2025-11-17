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

#pragma once

#include "swoole.h"
#include "swoole_ssl.h"

#ifdef SW_USE_QUIC

#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <unordered_map>
#include <memory>

// QUIC Constants
#define SW_QUIC_MAX_PACKET_SIZE 1350
#define SW_QUIC_MAX_STREAMS 100
#define SW_QUIC_IDLE_TIMEOUT 30  // seconds
#define SW_QUIC_HANDSHAKE_TIMEOUT 10  // seconds
#define SW_QUIC_MAX_DATA 1048576  // 1MB
#define SW_QUIC_MAX_STREAM_DATA 524288  // 512KB

// QUIC Error Codes (RFC 9000)
enum swQuicErrorCode {
    SW_QUIC_NO_ERROR = 0x00,
    SW_QUIC_INTERNAL_ERROR = 0x01,
    SW_QUIC_CONNECTION_REFUSED = 0x02,
    SW_QUIC_FLOW_CONTROL_ERROR = 0x03,
    SW_QUIC_STREAM_LIMIT_ERROR = 0x04,
    SW_QUIC_STREAM_STATE_ERROR = 0x05,
    SW_QUIC_FINAL_SIZE_ERROR = 0x06,
    SW_QUIC_FRAME_ENCODING_ERROR = 0x07,
    SW_QUIC_TRANSPORT_PARAMETER_ERROR = 0x08,
    SW_QUIC_CONNECTION_ID_LIMIT_ERROR = 0x09,
    SW_QUIC_PROTOCOL_VIOLATION = 0x0A,
    SW_QUIC_INVALID_TOKEN = 0x0B,
    SW_QUIC_APPLICATION_ERROR = 0x0C,
    SW_QUIC_CRYPTO_BUFFER_EXCEEDED = 0x0D,
    SW_QUIC_KEY_UPDATE_ERROR = 0x0E,
    SW_QUIC_AEAD_LIMIT_REACHED = 0x0F,
    SW_QUIC_NO_VIABLE_PATH = 0x10,
};

// QUIC Connection State
enum swQuicConnectionState {
    SW_QUIC_STATE_INITIAL = 0,
    SW_QUIC_STATE_HANDSHAKE = 1,
    SW_QUIC_STATE_ESTABLISHED = 2,
    SW_QUIC_STATE_CLOSING = 3,
    SW_QUIC_STATE_DRAINING = 4,
    SW_QUIC_STATE_CLOSED = 5,
};

// QUIC Stream State
enum swQuicStreamState {
    SW_QUIC_STREAM_IDLE = 0,
    SW_QUIC_STREAM_OPEN = 1,
    SW_QUIC_STREAM_HALF_CLOSED_LOCAL = 2,
    SW_QUIC_STREAM_HALF_CLOSED_REMOTE = 3,
    SW_QUIC_STREAM_CLOSED = 4,
};

namespace swoole {
namespace quic {

// Forward declarations
struct Connection;
struct Stream;
struct Listener;

// QUIC Stream
struct Stream {
    int64_t stream_id;
    swQuicStreamState state;
    Connection *conn;

    // Buffer for received data
    String *recv_buffer;

    // Buffer for sending data
    String *send_buffer;

    // Stream flow control
    uint64_t rx_max_data;
    uint64_t rx_offset;
    uint64_t tx_max_data;
    uint64_t tx_offset;

    uchar fin_received : 1;
    uchar fin_sent : 1;
    uchar rst_received : 1;
    uchar rst_sent : 1;

    // User data
    void *user_data;

    Stream(int64_t id, Connection *c);
    ~Stream();

    bool send_data(const uint8_t *data, size_t len, bool fin);
    bool recv_data(const uint8_t *data, size_t len, bool fin);
    bool close(uint64_t error_code = SW_QUIC_NO_ERROR);
};

// QUIC Listener (Server-side only)
struct Listener {
    SSL_CTX *ssl_ctx;
    SSL *ssl_listener;  // OpenSSL QUIC listener object
    int udp_fd;

    // Local address
    ::sockaddr_storage local_addr;
    ::socklen_t local_addrlen;

    // Configuration
    const char *cert_file;
    const char *key_file;

    // Callbacks
    void (*on_connection)(Listener *listener, Connection *conn);
    void (*on_stream_open)(Connection *conn, Stream *stream);
    void (*on_stream_close)(Connection *conn, Stream *stream);
    void (*on_stream_data)(Connection *conn, Stream *stream, const uint8_t *data, size_t len);

    // User data
    void *user_data;

    Listener();
    ~Listener();

    // Initialize SSL_CTX with OpenSSL QUIC server method
    bool init(const char *cert, const char *key);

    // Bind to UDP socket and start listening (compatibility wrapper)
    bool bind(const char *host, int port);

    // Bind to UDP socket and start listening
    bool listen(const ::sockaddr *addr, ::socklen_t addrlen);

    // Accept incoming QUIC connection
    Connection* accept_connection();

    // Run event loop (compatibility with ngtcp2 API)
    void run();

    // Close listener
    bool close();
};

// QUIC Connection
struct Connection {
    // OpenSSL QUIC connection object
    SSL *ssl;
    SSL_CTX *ssl_ctx;  // Shared with Listener

    // Address information
    ::sockaddr_storage local_addr;
    ::socklen_t local_addrlen;
    ::sockaddr_storage remote_addr;
    ::socklen_t remote_addrlen;

    // State
    swQuicConnectionState state;

    // Streams
    std::unordered_map<int64_t, Stream*> streams;
    int64_t next_stream_id;
    uint64_t max_streams;

    // Send/Recv buffers
    uint8_t *send_buffer;
    size_t send_buffer_size;
    uint8_t *recv_buffer;
    size_t recv_buffer_size;

    // Timestamp
    uint64_t last_ts;

    // Callbacks
    void (*on_stream_open)(Connection *conn, Stream *stream);
    void (*on_stream_close)(Connection *conn, Stream *stream);
    void (*on_stream_data)(Connection *conn, Stream *stream, const uint8_t *data, size_t len);
    void (*on_connection_close)(Connection *conn, uint64_t error_code);

    // User data
    void *user_data;

    // Flags
    uchar is_server : 1;
    uchar handshake_completed : 1;
    uchar draining : 1;

    Connection();
    ~Connection();

    // Initialize from accepted SSL connection
    bool init_from_ssl(SSL *ssl_conn, SSL_CTX *ctx);

    // Stream management
    Stream* create_stream(int64_t stream_id);
    Stream* get_stream(int64_t stream_id);
    Stream* open_stream(int64_t stream_id = -1);  // Alias for create_stream (backward compatibility)
    bool close_stream(int64_t stream_id, uint64_t error_code);

    // I/O operations
    ssize_t read_stream(int64_t stream_id, uint8_t *buf, size_t len);
    ssize_t write_stream(int64_t stream_id, const uint8_t *data, size_t len, bool fin);

    // Connection management
    bool close(uint64_t error_code = SW_QUIC_NO_ERROR);
    bool process_events();  // Process I/O events

    // Get ALPN negotiated protocol
    const char* get_alpn_protocol();
};

// Backward compatibility: Server is an alias for Listener
// This allows HTTP/3 layer code to use swoole::quic::Server
typedef Listener Server;

// Helper functions
SSL_CTX* create_quic_server_context(const char *cert_file, const char *key_file);
int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *out_len,
                         const unsigned char *in, unsigned int in_len, void *arg);

}  // namespace quic
}  // namespace swoole

#endif  // SW_USE_QUIC
