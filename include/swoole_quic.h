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

#pragma once

#include "swoole.h"
#include "swoole_ssl.h"

#ifdef SW_USE_QUIC

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <unordered_map>
#include <memory>

// QUIC Constants
#define SW_QUIC_MAX_PACKET_SIZE 1350
#define SW_QUIC_MAX_STREAMS 100
#define SW_QUIC_IDLE_TIMEOUT 30  // seconds
#define SW_QUIC_HANDSHAKE_TIMEOUT 10  // seconds
#define SW_QUIC_MAX_DATA 1048576  // 1MB
#define SW_QUIC_MAX_STREAM_DATA 524288  // 512KB
#define SW_QUIC_MAX_ACK_DELAY 25  // milliseconds

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

// QUIC Stream
struct Stream {
    int64_t stream_id;
    swQuicStreamState state;
    Connection *conn;

    // Buffer for received data
    swString *recv_buffer;

    // Buffer for sending data
    swString *send_buffer;

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

// QUIC Connection
struct Connection {
    ngtcp2_conn *conn;
    SSL *ssl;
    SSL_CTX *ssl_ctx;

    // Connection ID
    ngtcp2_cid dcid;  // Destination Connection ID
    ngtcp2_cid scid;  // Source Connection ID

    // Address
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;

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

    // Timers
    ngtcp2_tstamp last_ts;
    ngtcp2_tstamp expiry;

    // Connection parameters
    ngtcp2_settings settings;
    ngtcp2_transport_params params;

    // Callbacks
    void (*on_stream_open)(Connection *conn, Stream *stream);
    void (*on_stream_close)(Connection *conn, Stream *stream);
    void (*on_stream_data)(Connection *conn, Stream *stream, const uint8_t *data, size_t len);
    void (*on_connection_close)(Connection *conn, uint64_t error_code);

    // User data
    void *user_data;

    // Server flag
    uchar is_server : 1;
    uchar handshake_completed : 1;
    uchar draining : 1;

    Connection();
    ~Connection();

    bool init_server(const struct sockaddr *local_addr, socklen_t local_addrlen,
                     const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                     const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                     SSL_CTX *ssl_ctx);

    bool init_client(const struct sockaddr *local_addr, socklen_t local_addrlen,
                     const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                     const char *server_name, SSL_CTX *ssl_ctx);

    Stream* open_stream(int64_t stream_id = -1);
    Stream* get_stream(int64_t stream_id);
    bool close_stream(int64_t stream_id, uint64_t error_code = SW_QUIC_NO_ERROR);

    ssize_t send_packet(uint8_t *dest, size_t destlen);
    ssize_t recv_packet(const uint8_t *data, size_t datalen);

    bool handle_expiry();
    ngtcp2_tstamp get_expiry();

    bool close(uint64_t error_code = SW_QUIC_NO_ERROR);

    static ngtcp2_callbacks create_callbacks();
    static void setup_transport_params(ngtcp2_transport_params *params);
    static void setup_settings(ngtcp2_settings *settings);
};

// QUIC Server
struct Server {
    int fd;
    SSL_CTX *ssl_ctx;

    // Active connections
    std::unordered_map<std::string, Connection*> connections;

    // Server callbacks
    void (*on_connection)(Server *server, Connection *conn);
    void (*on_stream_open)(Connection *conn, Stream *stream);
    void (*on_stream_close)(Connection *conn, Stream *stream);
    void (*on_stream_data)(Connection *conn, Stream *stream, const uint8_t *data, size_t len);

    // User data
    void *user_data;

    Server();
    ~Server();

    bool bind(const char *host, int port);
    Connection* accept_connection(const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                                   const uint8_t *data, size_t datalen);
    bool remove_connection(Connection *conn);

    void run();
};

// Helper functions
std::string cid_to_string(const ngtcp2_cid *cid);
ngtcp2_tstamp timestamp();
int generate_secure_random(uint8_t *data, size_t datalen);
bool generate_connection_id(ngtcp2_cid *cid);

} // namespace quic
} // namespace swoole

#endif // SW_USE_QUIC
