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

#ifdef SW_USE_QUIC

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
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

    recv_buffer = swString_new(SW_BUFFER_SIZE_STD);
    send_buffer = swString_new(SW_BUFFER_SIZE_STD);

    if (id >= 0) {
        state = SW_QUIC_STREAM_OPEN;
    }
}

Stream::~Stream() {
    if (recv_buffer) {
        swString_free(recv_buffer);
    }
    if (send_buffer) {
        swString_free(send_buffer);
    }
}

bool Stream::send_data(const uint8_t *data, size_t len, bool fin) {
    if (state == SW_QUIC_STREAM_CLOSED || fin_sent) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_QUIC_STREAM_CLOSED,
                         "Cannot send data on closed stream %ld", stream_id);
        return false;
    }

    if (len > 0) {
        if (swString_append_ptr(send_buffer, (const char *) data, len) < 0) {
            return false;
        }
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

        if (swString_append_ptr(recv_buffer, (const char *) data, len) < 0) {
            return false;
        }
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

static int on_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
    return generate_secure_random(dest, destlen);
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

    callbacks.client_initial = on_client_initial;
    callbacks.recv_crypto_data = on_recv_crypto_data;
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.recv_stream_data = on_recv_stream_data;
    callbacks.stream_open = on_stream_open;
    callbacks.stream_close = on_stream_close;
    callbacks.acked_stream_data_offset = on_acked_stream_data_offset;
    callbacks.extend_max_streams_bidi = on_extend_max_streams;
    callbacks.extend_max_streams_uni = on_extend_max_streams;
    callbacks.rand = on_rand;
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

// Connection initialization methods will be implemented in next part...
// Due to size constraints, I'll create this in multiple parts

#endif // SW_USE_QUIC
