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
#include "swoole_quic.h"

#ifdef SW_USE_HTTP3

#include <nghttp3/nghttp3.h>

#include <unordered_map>
#include <string>
#include <vector>

// HTTP/3 Constants
#define SW_HTTP3_CONTROL_STREAM_TYPE 0x00
#define SW_HTTP3_PUSH_STREAM_TYPE 0x01
#define SW_HTTP3_QPACK_ENCODER_STREAM_TYPE 0x02
#define SW_HTTP3_QPACK_DECODER_STREAM_TYPE 0x03

#define SW_HTTP3_MAX_FIELD_SECTION_SIZE 65536
#define SW_HTTP3_MAX_TABLE_CAPACITY 4096
#define SW_HTTP3_MAX_BLOCKED_STREAMS 100

// HTTP/3 Error Codes (RFC 9114)
enum swHttp3ErrorCode {
    SW_HTTP3_NO_ERROR = 0x100,
    SW_HTTP3_GENERAL_PROTOCOL_ERROR = 0x101,
    SW_HTTP3_INTERNAL_ERROR = 0x102,
    SW_HTTP3_STREAM_CREATION_ERROR = 0x103,
    SW_HTTP3_CLOSED_CRITICAL_STREAM = 0x104,
    SW_HTTP3_FRAME_UNEXPECTED = 0x105,
    SW_HTTP3_FRAME_ERROR = 0x106,
    SW_HTTP3_EXCESSIVE_LOAD = 0x107,
    SW_HTTP3_ID_ERROR = 0x108,
    SW_HTTP3_SETTINGS_ERROR = 0x109,
    SW_HTTP3_MISSING_SETTINGS = 0x10A,
    SW_HTTP3_REQUEST_REJECTED = 0x10B,
    SW_HTTP3_REQUEST_CANCELLED = 0x10C,
    SW_HTTP3_REQUEST_INCOMPLETE = 0x10D,
    SW_HTTP3_MESSAGE_ERROR = 0x10E,
    SW_HTTP3_CONNECT_ERROR = 0x10F,
    SW_HTTP3_VERSION_FALLBACK = 0x110,
    SW_HTTP3_QPACK_DECOMPRESSION_FAILED = 0x200,
    SW_HTTP3_QPACK_ENCODER_STREAM_ERROR = 0x201,
    SW_HTTP3_QPACK_DECODER_STREAM_ERROR = 0x202,
};

// HTTP/3 Stream Types
enum swHttp3StreamType {
    SW_HTTP3_STREAM_TYPE_REQUEST = 0,
    SW_HTTP3_STREAM_TYPE_CONTROL = 1,
    SW_HTTP3_STREAM_TYPE_PUSH = 2,
    SW_HTTP3_STREAM_TYPE_QPACK_ENCODER = 3,
    SW_HTTP3_STREAM_TYPE_QPACK_DECODER = 4,
};

namespace swoole {
namespace http3 {

// Forward declarations
struct Connection;
struct Stream;
struct Server;

// HTTP/3 Header Field
struct HeaderField {
    std::string name;
    std::string value;
    bool never_index;

    HeaderField(const std::string &n, const std::string &v, bool ni = false)
        : name(n), value(v), never_index(ni) {}
};

// HTTP/3 Stream
struct Stream {
    int64_t stream_id;
    Connection *conn;
    swoole::quic::Stream *quic_stream;

    // HTTP/3 specific
    swHttp3StreamType type;
    nghttp3_conn *http3_conn;

    // Request/Response data
    std::vector<HeaderField> headers;
    String *body;

    // Status
    int status_code;
    std::string method;
    std::string path;
    std::string scheme;
    std::string authority;

    // Flags
    uchar headers_complete : 1;
    uchar body_complete : 1;
    uchar is_request : 1;
    uchar is_response : 1;

    // User data
    void *user_data;

    Stream(int64_t id, Connection *c, swoole::quic::Stream *qs);
    ~Stream();

    bool send_headers(const std::vector<HeaderField> &hdrs, bool fin = false);
    bool send_body(const uint8_t *data, size_t len, bool fin = true);
    bool send_response(int status, const std::vector<HeaderField> &hdrs,
                       const uint8_t *body_data = nullptr, size_t body_len = 0);

    bool recv_headers(const nghttp3_nv *nva, size_t nvlen);
    bool recv_body(const uint8_t *data, size_t len);

    void add_header(const std::string &name, const std::string &value, bool never_index = false);
    const char* get_header(const std::string &name);

    bool close();
};

// HTTP/3 Connection
struct Connection {
    swoole::quic::Connection *quic_conn;
    nghttp3_conn *conn;

    // Streams
    std::unordered_map<int64_t, Stream*> streams;
    int64_t next_stream_id;

    // Control streams
    int64_t control_stream_id;
    int64_t qpack_enc_stream_id;
    int64_t qpack_dec_stream_id;

    // QPACK encoder/decoder (managed by nghttp3_conn internally)
    // nghttp3_qpack_encoder *qpack_enc;
    // nghttp3_qpack_decoder *qpack_dec;

    // Settings
    nghttp3_settings settings;

    // Callbacks
    void (*on_stream_open)(Connection *conn, Stream *stream);
    void (*on_stream_close)(Connection *conn, Stream *stream);
    void (*on_recv_header)(Connection *conn, Stream *stream);
    void (*on_recv_body)(Connection *conn, Stream *stream, const uint8_t *data, size_t len);
    void (*on_recv_data_complete)(Connection *conn, Stream *stream);

    // User data
    void *user_data;

    // Server flag
    uchar is_server : 1;
    uchar control_stream_opened : 1;
    uchar qpack_streams_opened : 1;

    Connection(swoole::quic::Connection *qc);
    ~Connection();

    bool init_server();
    bool init_client();

    Stream* open_stream(int64_t stream_id = -1);
    Stream* get_stream(int64_t stream_id);
    bool close_stream(int64_t stream_id);

    bool open_control_streams();
    bool send_settings();

    ssize_t read_stream(int64_t stream_id, const uint8_t *data, size_t datalen, bool fin);
    ssize_t write_streams();

    bool close();

    static nghttp3_callbacks create_callbacks();
    static void setup_settings(nghttp3_settings *settings);
};

// HTTP/3 Server
struct Server {
    swoole::quic::Server *quic_server;

    // Active connections
    std::unordered_map<swoole::quic::Connection*, Connection*> connections;

    // Server settings
    nghttp3_settings settings;
    size_t max_field_section_size;
    size_t qpack_max_table_capacity;
    size_t qpack_blocked_streams;

    // Callbacks
    void (*on_connection)(Server *server, Connection *conn);
    void (*on_request)(Connection *conn, Stream *stream);
    void (*on_stream_close)(Connection *conn, Stream *stream);

    // User data
    void *user_data;

    Server();
    ~Server();

    bool bind(const char *host, int port, SSL_CTX *ssl_ctx);
    bool start();
    void stop();

    Connection* accept_connection(swoole::quic::Connection *quic_conn);
    bool remove_connection(Connection *conn);
};

// Helper functions
const char* get_error_string(uint64_t error_code);
nghttp3_nv make_nv(const char *name, const char *value, bool never_index = false);
nghttp3_nv make_nv(const std::string &name, const std::string &value, bool never_index = false);

// HTTP/3 Request/Response builder
struct RequestBuilder {
    std::string method;
    std::string scheme;
    std::string authority;
    std::string path;
    std::vector<HeaderField> headers;
    std::string body;

    RequestBuilder& set_method(const std::string &m);
    RequestBuilder& set_scheme(const std::string &s);
    RequestBuilder& set_authority(const std::string &a);
    RequestBuilder& set_path(const std::string &p);
    RequestBuilder& add_header(const std::string &name, const std::string &value);
    RequestBuilder& set_body(const std::string &b);

    std::vector<HeaderField> build_headers();
};

struct ResponseBuilder {
    int status;
    std::vector<HeaderField> headers;
    std::string body;

    ResponseBuilder& set_status(int s);
    ResponseBuilder& add_header(const std::string &name, const std::string &value);
    ResponseBuilder& set_body(const std::string &b);

    std::vector<HeaderField> build_headers();
};

} // namespace http3
} // namespace swoole

#endif // SW_USE_HTTP3
