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

#include "swoole_quic.h"
#include "swoole_string.h"

#ifdef SW_USE_QUIC

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <vector>
#include <openssl/rand.h>

using namespace swoole;
using namespace swoole::quic;

// ==================== Helper Functions ====================

std::string swoole::quic::cid_to_string(const ngtcp2_cid *cid) {
    char buf[NGTCP2_MAX_CIDLEN * 2 + 1];
    for (size_t i = 0; i < cid->datalen; i++) {
        snprintf(buf + i * 2, 3, "%02x", cid->data[i]);
    }
    return std::string(buf, cid->datalen * 2);
}

ngtcp2_tstamp swoole::quic::timestamp() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (ngtcp2_tstamp) tv.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp) tv.tv_usec * NGTCP2_MICROSECONDS;
}

int swoole::quic::generate_secure_random(uint8_t *data, size_t datalen) {
    if (RAND_bytes(data, datalen) != 1) {
        return -1;
    }
    return 0;
}

bool swoole::quic::generate_connection_id(ngtcp2_cid *cid) {
    cid->datalen = NGTCP2_MIN_CIDLEN;
    if (generate_secure_random(cid->data, cid->datalen) != 0) {
        return false;
    }
    return true;
}

// ==================== QUIC Stream Implementation ====================

Stream::Stream(int64_t id, Connection *c)
    : stream_id(id),
      state(SW_QUIC_STREAM_IDLE),
      conn(c),
      recv_buffer(nullptr),
      send_buffer(nullptr),
      rx_max_data(SW_QUIC_MAX_STREAM_DATA),
      rx_offset(0),
      tx_max_data(SW_QUIC_MAX_STREAM_DATA),
      tx_offset(0),
      fin_received(0),
      fin_sent(0),
      rst_received(0),
      rst_sent(0),
      user_data(nullptr) {

    recv_buffer = new String(SW_BUFFER_SIZE_STD);
    send_buffer = new String(SW_BUFFER_SIZE_STD);

    if (id >= 0) {
        state = SW_QUIC_STREAM_OPEN;
    }
}

Stream::~Stream() {
    if (recv_buffer) {
        delete recv_buffer;
    }
    if (send_buffer) {
        delete send_buffer;
    }
}

bool Stream::send_data(const uint8_t *data, size_t len, bool fin) {
    if (state == SW_QUIC_STREAM_CLOSED || fin_sent) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_STREAM_CLOSED,
                         "Cannot send data on closed stream %ld", stream_id);
        return false;
    }

    if (len > 0) {
        send_buffer->append((const char *) data, len);
        tx_offset += len;
    }

    if (fin) {
        fin_sent = 1;
        if (state == SW_QUIC_STREAM_HALF_CLOSED_REMOTE) {
            state = SW_QUIC_STREAM_CLOSED;
        } else {
            state = SW_QUIC_STREAM_HALF_CLOSED_LOCAL;
        }
    }

    return true;
}

bool Stream::recv_data(const uint8_t *data, size_t len, bool fin) {
    if (state == SW_QUIC_STREAM_CLOSED || fin_received) {
        return false;
    }

    if (len > 0) {
        if (rx_offset + len > rx_max_data) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_FLOW_CONTROL,
                             "Stream %ld flow control exceeded", stream_id);
            return false;
        }

        recv_buffer->append((const char *) data, len);
        rx_offset += len;
    }

    if (fin) {
        fin_received = 1;
        if (state == SW_QUIC_STREAM_HALF_CLOSED_LOCAL) {
            state = SW_QUIC_STREAM_CLOSED;
        } else {
            state = SW_QUIC_STREAM_HALF_CLOSED_REMOTE;
        }
    }

    return true;
}

bool Stream::close(uint64_t error_code) {
    if (state == SW_QUIC_STREAM_CLOSED) {
        return true;
    }

    state = SW_QUIC_STREAM_CLOSED;

    if (conn && conn->conn) {
        ngtcp2_conn_shutdown_stream(conn->conn, 0, stream_id, error_code);
    }

    return true;
}

// ==================== QUIC Connection Callbacks ====================

static int on_client_initial(ngtcp2_conn *conn, void *user_data) {
    swoole_trace("QUIC: client_initial callback");
    return 0;
}

static int on_recv_crypto_data(ngtcp2_conn *conn,
                                ngtcp2_encryption_level encryption_level,
                                uint64_t offset,
                                const uint8_t *data,
                                size_t datalen,
                                void *user_data) {
    Connection *c = (Connection *) user_data;

    if (!c->ssl) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUIC_HANDSHAKE, "SSL not initialized");
        return NGTCP2_ERR_CRYPTO;
    }

    int rv = ngtcp2_crypto_read_write_crypto_data(
        conn, encryption_level, data, datalen);
    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUIC_HANDSHAKE,
                         "ngtcp2_crypto_read_write_crypto_data failed: %d", rv);
        return rv;
    }

    return 0;
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    Connection *c = (Connection *) user_data;

    swoole_trace("QUIC: handshake completed");
    c->handshake_completed = 1;
    c->state = SW_QUIC_STATE_ESTABLISHED;

    return 0;
}

static int on_recv_stream_data(ngtcp2_conn *conn,
                                 uint32_t flags,
                                 int64_t stream_id,
                                 uint64_t offset,
                                 const uint8_t *data,
                                 size_t datalen,
                                 void *user_data,
                                 void *stream_user_data) {
    Connection *c = (Connection *) user_data;

    Stream *stream = c->get_stream(stream_id);
    if (!stream) {
        // Create new stream for incoming data
        stream = c->open_stream(stream_id);
        if (!stream) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        if (c->on_stream_open) {
            c->on_stream_open(c, stream);
        }
    }

    bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;

    if (!stream->recv_data(data, datalen, fin)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    // Notify data callback
    if (c->on_stream_data && datalen > 0) {
        c->on_stream_data(c, stream, data, datalen);
    }

    // Notify close callback if fin received
    if (fin && c->on_stream_close) {
        c->on_stream_close(c, stream);
    }

    return 0;
}

static int on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    Connection *c = (Connection *) user_data;

    swoole_trace("QUIC: stream %ld opened", stream_id);

    Stream *stream = c->get_stream(stream_id);
    if (!stream) {
        stream = c->open_stream(stream_id);
        if (!stream) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (c->on_stream_open) {
        c->on_stream_open(c, stream);
    }

    return 0;
}

static int on_stream_close(ngtcp2_conn *conn,
                             uint32_t flags,
                             int64_t stream_id,
                             uint64_t app_error_code,
                             void *user_data,
                             void *stream_user_data) {
    Connection *c = (Connection *) user_data;

    swoole_trace("QUIC: stream %ld closed, error=%lu", stream_id, app_error_code);

    Stream *stream = c->get_stream(stream_id);
    if (stream) {
        if (c->on_stream_close) {
            c->on_stream_close(c, stream);
        }

        c->close_stream(stream_id, app_error_code);
    }

    return 0;
}

static int on_acked_stream_data_offset(ngtcp2_conn *conn,
                                         int64_t stream_id,
                                         uint64_t offset,
                                         uint64_t datalen,
                                         void *user_data,
                                         void *stream_user_data) {
    // Data acknowledged, can free buffer
    swoole_trace("QUIC: stream %ld data acked, offset=%lu, len=%zu", stream_id, offset, datalen);
    return 0;
}

static int on_extend_max_streams(ngtcp2_conn *conn,
                                   uint64_t max_streams,
                                   void *user_data) {
    Connection *c = (Connection *) user_data;
    c->max_streams = max_streams;
    swoole_trace("QUIC: max_streams extended to %lu", max_streams);
    return 0;
}

static void on_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
    generate_secure_random(dest, destlen);
}

static int on_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                      uint8_t *token, size_t cidlen,
                                      void *user_data) {
    if (generate_secure_random(cid->data, cidlen) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;

    if (generate_secure_random(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

// ==================== QUIC Connection Implementation ====================

Connection::Connection()
    : conn(nullptr),
      ssl(nullptr),
      ssl_ctx(nullptr),
      local_addrlen(0),
      remote_addrlen(0),
      state(SW_QUIC_STATE_INITIAL),
      next_stream_id(0),
      max_streams(SW_QUIC_MAX_STREAMS),
      send_buffer(nullptr),
      send_buffer_size(SW_QUIC_MAX_PACKET_SIZE),
      recv_buffer(nullptr),
      recv_buffer_size(SW_QUIC_MAX_PACKET_SIZE),
      last_ts(0),
      expiry(0),
      on_stream_open(nullptr),
      on_stream_close(nullptr),
      on_stream_data(nullptr),
      on_connection_close(nullptr),
      user_data(nullptr),
      is_server(0),
      handshake_completed(0),
      draining(0) {

    memset(&dcid, 0, sizeof(dcid));
    memset(&scid, 0, sizeof(scid));
    memset(&local_addr, 0, sizeof(local_addr));
    memset(&remote_addr, 0, sizeof(remote_addr));
    memset(&settings, 0, sizeof(settings));
    memset(&params, 0, sizeof(params));

    send_buffer = (uint8_t *) sw_malloc(send_buffer_size);
    recv_buffer = (uint8_t *) sw_malloc(recv_buffer_size);

    setup_settings(&settings);
    setup_transport_params(&params);
}

Connection::~Connection() {
    // Clean up streams
    for (auto &pair : streams) {
        delete pair.second;
    }
    streams.clear();

    if (conn) {
        ngtcp2_conn_del(conn);
        conn = nullptr;
    }

    if (ssl) {
        SSL_free(ssl);
        ssl = nullptr;
    }

    if (send_buffer) {
        sw_free(send_buffer);
        send_buffer = nullptr;
    }

    if (recv_buffer) {
        sw_free(recv_buffer);
        recv_buffer = nullptr;
    }
}

ngtcp2_callbacks Connection::create_callbacks() {
    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));

    // Client-side callback
    callbacks.client_initial = on_client_initial;

    // Server-side callback (required for server connections)
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

    // Crypto callbacks (required)
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.rand = on_rand;

    // Crypto data handling
    callbacks.recv_crypto_data = on_recv_crypto_data;

    // Stream callbacks
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.recv_stream_data = on_recv_stream_data;
    callbacks.stream_open = ::on_stream_open;
    callbacks.stream_close = ::on_stream_close;
    callbacks.acked_stream_data_offset = on_acked_stream_data_offset;
    callbacks.extend_max_local_streams_bidi = on_extend_max_streams;
    callbacks.extend_max_local_streams_uni = on_extend_max_streams;

    // Cleanup callbacks
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;

    // Connection ID callback
    callbacks.get_new_connection_id = on_get_new_connection_id;

    return callbacks;
}

void Connection::setup_settings(ngtcp2_settings *settings) {
    ngtcp2_settings_default(settings);
    settings->initial_ts = timestamp();
    settings->max_window = SW_QUIC_MAX_DATA;
    settings->max_stream_window = SW_QUIC_MAX_STREAM_DATA;
}

void Connection::setup_transport_params(ngtcp2_transport_params *params) {
    ngtcp2_transport_params_default(params);
    params->initial_max_stream_data_bidi_local = SW_QUIC_MAX_STREAM_DATA;
    params->initial_max_stream_data_bidi_remote = SW_QUIC_MAX_STREAM_DATA;
    params->initial_max_stream_data_uni = SW_QUIC_MAX_STREAM_DATA;
    params->initial_max_data = SW_QUIC_MAX_DATA;
    params->initial_max_streams_bidi = SW_QUIC_MAX_STREAMS;
    params->initial_max_streams_uni = SW_QUIC_MAX_STREAMS;
    params->max_idle_timeout = SW_QUIC_IDLE_TIMEOUT * NGTCP2_SECONDS;
    params->active_connection_id_limit = 7;
}

bool Connection::init_server(const struct sockaddr *local_addr, socklen_t local_addrlen,
                               const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                               const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                               SSL_CTX *ssl_ctx) {
    is_server = 1;
    this->ssl_ctx = ssl_ctx;

    memcpy(&this->local_addr, local_addr, local_addrlen);
    this->local_addrlen = local_addrlen;
    memcpy(&this->remote_addr, remote_addr, remote_addrlen);
    this->remote_addrlen = remote_addrlen;

    this->dcid = *dcid;
    this->scid = *scid;

    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(&path, (struct sockaddr *) &this->local_addr, local_addrlen,
                              (struct sockaddr *) &this->remote_addr, remote_addrlen, nullptr);

    ngtcp2_callbacks callbacks = create_callbacks();
    setup_settings(&settings);

    // Setup transport params for server
    setup_transport_params(&params);
    // Server must set original_dcid to the client's initial DCID
    params.original_dcid = *dcid;
    params.original_dcid_present = 1;

    last_ts = timestamp();
    settings.initial_ts = last_ts;

    int rv = ngtcp2_conn_server_new(&conn, &this->dcid, &this->scid, &path.path,
                                     NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);

    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUIC_INIT,
                         "ngtcp2_conn_server_new failed: %s", ngtcp2_strerror(rv));
        return false;
    }

    // Setup SSL
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SSL_CTX_INIT, "SSL_new failed");
        return false;
    }

    SSL_set_accept_state(ssl);
    SSL_set_quic_tls_early_data_enabled(ssl, 1);

    rv = ngtcp2_crypto_ossl_configure_server_session(ssl);
    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUIC_INIT,
                         "ngtcp2_crypto_ossl_configure_server_session failed: %d", rv);
        return false;
    }

    ngtcp2_conn_set_tls_native_handle(conn, ssl);

    state = SW_QUIC_STATE_HANDSHAKE;
    return true;
}

bool Connection::init_client(const struct sockaddr *local_addr, socklen_t local_addrlen,
                               const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                               const char *server_name, SSL_CTX *ssl_ctx) {
    is_server = 0;
    this->ssl_ctx = ssl_ctx;

    memcpy(&this->local_addr, local_addr, local_addrlen);
    this->local_addrlen = local_addrlen;
    memcpy(&this->remote_addr, remote_addr, remote_addrlen);
    this->remote_addrlen = remote_addrlen;

    if (!generate_connection_id(&scid)) {
        return false;
    }

    if (!generate_connection_id(&dcid)) {
        return false;
    }

    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(&path, (struct sockaddr *) &this->local_addr, local_addrlen,
                              (struct sockaddr *) &this->remote_addr, remote_addrlen, nullptr);

    ngtcp2_callbacks callbacks = create_callbacks();
    setup_settings(&settings);

    last_ts = timestamp();
    settings.initial_ts = last_ts;

    int rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &path.path,
                                     NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);

    if (rv != 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_QUIC_INIT,
                         "ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
        return false;
    }

    // Setup SSL
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SSL_CTX_INIT, "SSL_new failed");
        return false;
    }

    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, server_name);
    SSL_set_quic_tls_early_data_enabled(ssl, 1);

    ngtcp2_conn_set_tls_native_handle(conn, ssl);

    state = SW_QUIC_STATE_HANDSHAKE;
    return true;
}

Stream* Connection::open_stream(int64_t stream_id) {
    if (stream_id < 0) {
        // Generate new stream ID
        stream_id = next_stream_id;
        next_stream_id += 4;  // Bidirectional client/server initiated streams
    }

    if (streams.find(stream_id) != streams.end()) {
        return streams[stream_id];
    }

    Stream *stream = new Stream(stream_id, this);
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

bool Connection::close_stream(int64_t stream_id, uint64_t error_code) {
    auto it = streams.find(stream_id);
    if (it == streams.end()) {
        return false;
    }

    Stream *stream = it->second;
    stream->close(error_code);
    delete stream;
    streams.erase(it);

    return true;
}

ssize_t Connection::send_packet(uint8_t *dest, size_t destlen) {
    if (!conn || state == SW_QUIC_STATE_CLOSED) {
        return -1;
    }

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi;
    ngtcp2_tstamp ts = timestamp();

    ssize_t nwrite = ngtcp2_conn_write_pkt(conn, &ps.path, &pi, dest, destlen, ts);

    if (nwrite < 0) {
        if (nwrite != NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_SEND,
                             "ngtcp2_conn_write_pkt failed: %s", ngtcp2_strerror(nwrite));
        }
        return nwrite;
    }

    last_ts = ts;
    return nwrite;
}

ssize_t Connection::recv_packet(const uint8_t *data, size_t datalen) {
    if (!conn || state == SW_QUIC_STATE_CLOSED) {
        return -1;
    }

    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(&path, (struct sockaddr *) &local_addr, local_addrlen,
                              (struct sockaddr *) &remote_addr, remote_addrlen, nullptr);

    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));

    ngtcp2_tstamp ts = timestamp();

    int rv = ngtcp2_conn_read_pkt(conn, &path.path, &pi, data, datalen, ts);

    if (rv != 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_RECV,
                         "ngtcp2_conn_read_pkt failed: %s", ngtcp2_strerror(rv));
        return rv;
    }

    last_ts = ts;
    return datalen;
}

bool Connection::handle_expiry() {
    if (!conn) {
        return false;
    }

    ngtcp2_tstamp ts = timestamp();
    int rv = ngtcp2_conn_handle_expiry(conn, ts);

    if (rv != 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_TIMEOUT,
                         "ngtcp2_conn_handle_expiry failed: %s", ngtcp2_strerror(rv));
        return false;
    }

    last_ts = ts;
    return true;
}

ngtcp2_tstamp Connection::get_expiry() {
    if (!conn) {
        return 0;
    }
    return ngtcp2_conn_get_expiry(conn);
}

bool Connection::close(uint64_t error_code) {
    if (state == SW_QUIC_STATE_CLOSED || state == SW_QUIC_STATE_CLOSING) {
        return true;
    }

    state = SW_QUIC_STATE_CLOSING;

    if (conn) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);

        ngtcp2_pkt_info pi;
        ngtcp2_tstamp ts = timestamp();

        ngtcp2_ccerr ccerr;
        ngtcp2_ccerr_default(&ccerr);
        ngtcp2_ccerr_set_application_error(&ccerr, error_code, nullptr, 0);

        uint8_t buf[SW_QUIC_MAX_PACKET_SIZE];
        ssize_t nwrite = ngtcp2_conn_write_connection_close(conn, &ps.path, &pi,
                                                              buf, sizeof(buf), &ccerr, ts);

        // Connection close packet written (would need to be sent via socket)
    }

    state = SW_QUIC_STATE_CLOSED;

    if (on_connection_close) {
        on_connection_close(this, error_code);
    }

    return true;
}

// ==================== QUIC Server Implementation ====================

swoole::quic::Server::Server()
    : fd(-1),
      ssl_ctx(nullptr),
      on_connection(nullptr),
      on_stream_open(nullptr),
      on_stream_close(nullptr),
      on_stream_data(nullptr),
      user_data(nullptr) {
}

swoole::quic::Server::~Server() {
    for (auto &pair : connections) {
        delete pair.second;
    }
    connections.clear();

    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

bool swoole::quic::Server::bind(const char *host, int port) {
    // Create UDP socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        swoole_sys_error("socket() failed");
        return false;
    }

    // Set socket options
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        swoole_sys_error("setsockopt(SO_REUSEADDR) failed");
        return false;
    }

    // Bind address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_INVALID_PARAMS, "Invalid host address: %s", host);
        return false;
    }

    if (::bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        swoole_sys_error("bind() failed");
        return false;
    }

    swoole_trace("QUIC server listening on %s:%d", host, port);
    return true;
}

Connection* swoole::quic::Server::accept_connection(const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                                       const uint8_t *data, size_t datalen) {
    // Parse QUIC packet to extract connection IDs
    ngtcp2_pkt_hd hd;
    ngtcp2_version_cid version_cid;

    int rv = ngtcp2_pkt_decode_version_cid(&version_cid, data, datalen, NGTCP2_MIN_CIDLEN);
    if (rv != 0) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_PARSE,
                         "ngtcp2_pkt_decode_version_cid failed: %s", ngtcp2_strerror(rv));
        return nullptr;
    }

    // Convert version_cid to ngtcp2_cid
    ngtcp2_cid dcid;
    ngtcp2_cid_init(&dcid, version_cid.dcid, version_cid.dcidlen);

    // Check if connection already exists
    std::string cid_str = cid_to_string(&dcid);
    auto it = connections.find(cid_str);
    if (it != connections.end()) {
        return it->second;
    }

    // Create new connection
    Connection *conn = new Connection();

    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    getsockname(fd, (struct sockaddr *) &local_addr, &local_addrlen);

    ngtcp2_cid scid;
    if (!generate_connection_id(&scid)) {
        delete conn;
        return nullptr;
    }

    if (!conn->init_server((struct sockaddr *) &local_addr, local_addrlen,
                            remote_addr, remote_addrlen,
                            &dcid, &scid, ssl_ctx)) {
        delete conn;
        return nullptr;
    }

    // Set callbacks from server to connection
    if (on_stream_open) {
        conn->on_stream_open = on_stream_open;
    }
    if (on_stream_close) {
        conn->on_stream_close = on_stream_close;
    }
    if (on_stream_data) {
        conn->on_stream_data = on_stream_data;
    }

    connections[cid_str] = conn;

    if (on_connection) {
        on_connection(this, conn);
    }

    // Process initial packet
    conn->recv_packet(data, datalen);

    return conn;
}

bool swoole::quic::Server::remove_connection(Connection *conn) {
    std::string cid_str = cid_to_string(&conn->scid);
    auto it = connections.find(cid_str);
    if (it == connections.end()) {
        return false;
    }

    delete conn;
    connections.erase(it);
    return true;
}

void swoole::quic::Server::run() {
    if (fd < 0) {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "server not bound");
        return;
    }

    swoole_warning("QUIC server starting event loop on fd=%d", fd);

    // Event loop
    int loop_count = 0;
    while (true) {
        fd_set readfds;
        struct timeval tv;

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        // Set timeout to 1 second for processing timeouts
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            swoole_error_log(SW_LOG_ERROR, SW_ERROR_SYSTEM_CALL_FAIL, "select failed: %s", strerror(errno));
            break;
        }

        // Periodic debug output every 10 seconds
        if (++loop_count % 10 == 0) {
            swoole_warning("QUIC server loop iteration %d, active connections: %zu", loop_count, connections.size());
        }

        // Handle incoming packets
        if (ret > 0 && FD_ISSET(fd, &readfds)) {
            uint8_t buf[65536];
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);

            ssize_t nread = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &addrlen);
            if (nread < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    continue;
                }
                swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "recvfrom failed: %s", strerror(errno));
                continue;
            }

            if (nread == 0) {
                continue;
            }

            swoole_warning("QUIC server received %zd bytes from client", nread);

            // Try to parse packet header to get destination CID
            ngtcp2_version_cid version_cid;
            int rv = ngtcp2_pkt_decode_version_cid(&version_cid, buf, nread, NGTCP2_MIN_CIDLEN);

            Connection *conn = nullptr;
            if (rv == 0) {
                // Convert DCID to string and look up connection
                ngtcp2_cid dcid;
                ngtcp2_cid_init(&dcid, version_cid.dcid, version_cid.dcidlen);
                std::string cid_str = cid_to_string(&dcid);

                auto it = connections.find(cid_str);
                if (it != connections.end()) {
                    conn = it->second;
                    swoole_trace("Found existing connection for CID");
                } else {
                    // New connection - accept it
                    conn = accept_connection((struct sockaddr *) &addr, addrlen, buf, nread);
                    if (!conn) {
                        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_INIT, "Failed to accept connection");
                        continue;
                    }
                    swoole_warning("Accepted new QUIC connection, total connections: %zu", connections.size());
                    // First packet was already processed in accept_connection
                    goto send_packets;
                }
            }

            // Process packet for existing connection
            if (conn) {
                rv = conn->recv_packet(buf, nread);
                if (rv < 0) {
                    swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_RECV, "Failed to process packet");
                    // Don't remove connection yet, let it timeout
                }
            }

send_packets:
            // Send outgoing packets for this connection
            if (conn) {
                while (true) {
                    uint8_t sendbuf[65536];
                    ngtcp2_path_storage ps;
                    ngtcp2_pkt_info pi;

                    ngtcp2_path_storage_zero(&ps);

                    ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(conn->conn, &ps.path, &pi,
                                                                 sendbuf, sizeof(sendbuf),
                                                                 timestamp());
                    if (nwrite < 0) {
                        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_SEND,
                                        "ngtcp2_conn_write_pkt: %s", ngtcp2_strerror(nwrite));
                        break;
                    }

                    if (nwrite == 0) {
                        break;
                    }

                    // Send packet
                    ssize_t nsent = sendto(fd, sendbuf, nwrite, 0,
                                          ps.path.remote.addr, ps.path.remote.addrlen);
                    if (nsent < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // Would block, try again later
                            break;
                        }
                        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL,
                                        "sendto failed: %s", strerror(errno));
                        break;
                    }

                    swoole_warning("Sent %zd bytes to client", nsent);
                }
            }
        }

        // Process timeouts and idle connections
        ngtcp2_tstamp now = timestamp();
        std::vector<Connection*> to_remove;

        for (auto &pair : connections) {
            Connection *conn = pair.second;

            // Check expiry
            ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->conn);
            if (expiry != UINT64_MAX && expiry <= now) {
                swoole_trace("Connection expired, handling timeout");

                // Handle timeout
                int rv = ngtcp2_conn_handle_expiry(conn->conn, now);
                if (rv != 0) {
                    swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_TIMEOUT,
                                    "ngtcp2_conn_handle_expiry: %s", ngtcp2_strerror(rv));
                    to_remove.push_back(conn);
                    continue;
                }

                // Send packets after timeout handling
                while (true) {
                    uint8_t sendbuf[65536];
                    ngtcp2_path_storage ps;
                    ngtcp2_pkt_info pi;

                    ngtcp2_path_storage_zero(&ps);

                    ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(conn->conn, &ps.path, &pi,
                                                                 sendbuf, sizeof(sendbuf), now);
                    if (nwrite <= 0) {
                        break;
                    }

                    ssize_t nsent = sendto(fd, sendbuf, nwrite, 0,
                                          ps.path.remote.addr, ps.path.remote.addrlen);
                    if (nsent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL,
                                        "sendto failed: %s", strerror(errno));
                        break;
                    }
                }
            }

            // Check if connection should be closed
            if (ngtcp2_conn_in_closing_period(conn->conn) ||
                ngtcp2_conn_in_draining_period(conn->conn)) {
                swoole_trace("Connection in closing/draining period");
                to_remove.push_back(conn);
            }
        }

        // Remove closed connections
        for (Connection *conn : to_remove) {
            swoole_trace("Removing closed connection");
            remove_connection(conn);
        }
    }

    swoole_trace("QUIC server stopped");
}

#endif // SW_USE_QUIC
