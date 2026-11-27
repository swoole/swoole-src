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

#include "php_swoole_cxx.h"
#include "php_swoole_http.h"

#include "swoole_coroutine_channel.h"
#include "swoole_string.h"
#include "swoole_protocol.h"
#include "swoole_socket.h"
#include "swoole_util.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_http2_client_coro_arginfo.h"
END_EXTERN_C()

#include "swoole_http2.h"

#define HTTP2_CLIENT_HOST_HEADER_INDEX 3

using swoole::ReturnCode;
using swoole::SocketType;
using swoole::String;
using swoole::http2::get_default_setting;
using swoole::network::Address;
using swoole::network::Socket;

namespace Http2 = swoole::http2;

static zend_class_entry *swoole_http2_client_coro_ce;
static zend_object_handlers swoole_http2_client_coro_handlers;

static zend_class_entry *swoole_http2_client_coro_exception_ce;
static zend_object_handlers swoole_http2_client_coro_exception_handlers;

static zend_class_entry *swoole_http2_request_ce;
static zend_object_handlers swoole_http2_request_handlers;

static zend_class_entry *swoole_http2_response_ce;
static zend_object_handlers swoole_http2_response_handlers;

namespace swoole {
namespace coroutine {
namespace http2 {

struct Upload;

struct Stream {
    uint32_t stream_id;
    uint8_t gzip;
    uint8_t flags;
#ifdef SW_HAVE_ZLIB
    // Z_STREAM_END completes one gzip member, not necessarily the HTTP response.
    bool gzip_finished;
    bool request_is_head;
#endif

    // State of the current received header block, shared by its HEADERS and CONTINUATION frames.
    bool header_block_end_stream;
    bool header_block_is_trailers;
    bool response_ended;

    String *buffer;
    // The sending coroutine owns this state until send() or write() returns.
    Upload *upload;
#ifdef SW_HAVE_ZLIB
    z_stream gzip_stream;
#endif
    zval zresponse;
    size_t response_bytes;

    // flow control
    int32_t remote_window_size;  // A SETTINGS reduction may leave this stream in debt.
    uint32_t local_window_size;  // Remaining receive credit, checked before subtracting DATA.

    void release_receive_buffers() {
        delete buffer;
        buffer = nullptr;
#ifdef SW_HAVE_ZLIB
        if (gzip) {
            inflateEnd(&gzip_stream);
            gzip = 0;
        }
#endif
    }
};

class Client {
  public:
    SocketType socket_type;
    std::string host;
    int port;
    bool open_ssl;
    double timeout = NetSocket::default_read_timeout;

    uint32_t stream_id = 0;       // the next send stream id
    uint32_t last_stream_id = 0;  // the last received stream id
    uint32_t continuation_stream_id = 0;

    Http2::Settings local_settings = {};
    Http2::Settings remote_settings = {};

    // flow control
    uint32_t remote_window_size = 0;
    uint32_t local_window_size = 0;

    std::unordered_map<uint32_t, Stream *> streams;
    std::queue<zend_string *> send_queue;
    // The HEADERS frame being sent, which send() may still be writing while its coroutine waits.
    String header_frame;

    /* safety zval */
    zval _zobject;
    zval *zobject;
    SocketImpl *socket_ = nullptr;
    zval zsocket;

    Client(SocketType _socket_type, std::string &&_host, int _port, bool _ssl, const zval *zobj)
        : socket_type(_socket_type), host(std::move(_host)), open_ssl(_ssl) {
        if (_port == 0) {
            _port = _ssl ? 443 : 80;
        }
        port = _port;
        _zobject = *zobj;
        zobject = &_zobject;
        ZVAL_NULL(&zsocket);
        Http2::init_settings(&local_settings);
    }

    Stream *get_stream(uint32_t _stream_id) {
        auto i = streams.find(_stream_id);
        if (i == streams.end()) {
            return nullptr;
        } else {
            return i->second;
        }
    }

    void update_error_properties(int code, const char *msg) const {
        php_swoole_socket_set_error_properties(zobject, code, msg);
    }

    void io_error() const {
        update_error_properties(socket_->errCode, socket_->errMsg);
    }

    void nghttp2_error(int code, const char *msg) const {
        update_error_properties(code, std_string::format("%s with error: %s", msg, nghttp2_strerror(code)).c_str());
    }

    bool is_available() const {
        if (sw_unlikely(!socket_ || !socket_->is_connected())) {
            php_swoole_socket_set_error_properties(zobject, SW_ERROR_CLIENT_NO_CONNECTION);
            return false;
        }
        return true;
    }

    bool apply_setting(const zval *zset) try {
        if (!ZVAL_IS_ARRAY(zset)) {
            return true;
        }
        size_t limit = max_buffered_response_bytes;
        zval *value;
        if (php_swoole_array_get_value(Z_ARRVAL_P(zset), "http2_max_buffered_response_bytes", value)) {
            const auto size = zend::setting::get_size(value);
            if (size <= 0) {
                return php_swoole_throw_setting_exception("http2_max_buffered_response_bytes must be positive");
            }
            limit = size;
        }
        if (socket_ && !php_swoole_socket_set(socket_, zset)) {
            return false;
        }
        max_buffered_response_bytes = limit;
        return true;
    } catch (const zend::setting::ParseError &) {
        return false;
    }

    bool connect();
    Stream *create_stream(uint32_t _stream_id, uint8_t flags);
    void destroy_stream(Stream *stream);

    bool delete_stream(uint32_t _stream_id) {
        const auto i = streams.find(_stream_id);
        if (i == streams.end()) {
            return false;
        }

        destroy_stream(i->second);
        streams.erase(i);

        return true;
    }

    bool send_window_update(int _stream_id, uint32_t size);
    bool send_ping_frame();
    uint32_t send_request(zval *zrequest);
    bool write_data(uint32_t _stream_id, zval *zdata, bool end);
    bool send_goaway_frame(zend_long error_code, const char *debug_data, size_t debug_data_len);
    ReturnCode receive_frame(
        SocketImpl *socket, double timeout, zval *return_value, bool pipeline_read, uint32_t upload = 0);
    bool pop_pending_response(zval *return_value);
    void discard_pending_responses() {
        for (const auto &pending : pending_responses) {
            buffered_response_bytes -= pending.bytes;
        }
        pending_responses.clear();
        pending_upload_responses = 0;
        preserve_disconnect_error = false;
    }
    bool has_deferred_disconnect_error() const {
        return preserve_disconnect_error;
    }
    bool close() const;
    bool request_close();
    void socket_dtor();

    ~Client() {
        cancel_drain_timer();
        close();
    }

  private:
    struct PendingResponse {
        zend::Variable response;
        size_t bytes;
        bool buffered_by_upload;
    };
    static constexpr size_t MAX_PENDING_RESPONSES = 128;
    static constexpr size_t SEND_QUEUE_LIMIT = 128;
    size_t max_buffered_response_bytes = 64 * 1024 * 1024;
    // Track responses held by both open streams and the delivery queue. Only upload-driven reads enforce the limit.
    size_t buffered_response_bytes = 0;
    nghttp2_hd_inflater *inflater = nullptr;
    nghttp2_hd_deflater *deflater = nullptr;
    // The public receiver and writers waiting for credit share the frame reader.
    std::unique_ptr<Channel> read_lock;
#ifdef SW_HAVE_ZLIB
    // Frame decoding is serialized by read_lock, so streams share the decompression scratch space.
    std::unique_ptr<String> gzip_buffer;
#endif
    std::list<PendingResponse> pending_responses;
    size_t pending_upload_responses = 0;
    // GOAWAY carries a 31-bit ID. UINT32_MAX indicates that the peer has not sent one.
    uint32_t peer_last_stream_id = UINT32_MAX;
    long drain_timer = 0;
    bool buffered_pipeline_data = false;
    bool preserve_disconnect_error = false;
    bool drain_timed_out = false;

    bool is_draining() const {
        return peer_last_stream_id != UINT32_MAX;
    }
    bool can_open_stream() const {
        if (sw_unlikely(is_draining())) {
            return false;
        }
        if (sw_unlikely(streams.size() >= remote_settings.max_concurrent_streams)) {
            update_error_properties(SW_ERROR_HTTP2_TOO_MANY_STREAMS, "HTTP/2 peer concurrent stream limit reached");
            return false;
        }
        return true;
    }
    ssize_t build_header(zval *zrequest, SocketImpl *socket, String *&buffer);
    void cancel_drain_timer();
    void on_drain_timeout();
    bool close_if_drained();
    ReturnCode receive_goaway(const char *payload, size_t length, zval *return_value, bool upload_read);
    bool send_data(const Upload &upload, const char *p, size_t len, int flag);
    void finish_request(const Upload &upload);
    ReturnCode reset_stream(uint32_t id, uint32_t error, zval *return_value = nullptr, size_t *pending_bytes = nullptr);
    bool send_setting();
    ReturnCode parse_header(Stream *stream, int flags, char *in, size_t inlen, bool upload_read);
    ReturnCode parse_frame(zval *return_value, bool pipeline_read, size_t *pending_bytes = nullptr);
    ReturnCode reject_send_window(uint32_t error, const char *reason);
    ReturnCode reject_response_buffer();
#ifdef SW_HAVE_ZLIB
    ReturnCode reject_compressed_response();
#endif
    size_t remaining_response_bytes(bool upload_read) const;
    bool reserve_response_bytes(Stream *stream, size_t bytes, bool upload_read);
    void transfer_response(Stream *stream, zval *return_value, size_t *pending_bytes);
    void return_response(Stream *stream, zval *return_value, bool end, size_t *pending_bytes = nullptr);

    void clean_send_queue() {
        while (!send_queue.empty()) {
            zend_string *frame = send_queue.front();
            send_queue.pop();
            zend_string_release(frame);
        }
    }

    // Checked before a request or DATA write starts: dropping part of one would break the connection's HPACK state or
    // leave the stream unfinished.
    bool check_send_queue() const {
        if (socket_->has_bound(SW_EVENT_WRITE) && send_queue.size() >= SEND_QUEUE_LIMIT) {
            update_error_properties(SW_ERROR_QUEUE_FULL, "the send queue is full, try again later");
            return false;
        }
        return true;
    }

    // Part of a frame may already be on the wire, so the connection can't be used again.
    void send_error() {
        int code = socket_->errCode;
        std::string msg = socket_->errMsg;
        close();
        // close() resumes coroutines bound to the socket, and they record their own errors.
        update_error_properties(code, msg.c_str());
    }

    bool send(const char *buf, size_t len, bool flush = true) {
        if (socket_->has_bound(SW_EVENT_WRITE)) {
            send_queue.push(zend_string_init(buf, len, false));
            return true;
        }
        if (sw_unlikely(socket_->send_all(buf, len) != (ssize_t) len)) {
            send_error();
            return false;
        }
        while (flush && !send_queue.empty()) {
            zend_string *frame = send_queue.front();
            if (sw_unlikely(socket_->send_all(frame->val, frame->len) != (ssize_t) frame->len)) {
                send_error();
                zend_throw_exception(swoole_http2_client_coro_exception_ce,
                                     "failed to send control frame",
                                     SW_ERROR_HTTP2_SEND_CONTROL_FRAME_FAILED);
                return false;
            }
            send_queue.pop();
            zend_string_release(frame);
        }
        return true;
    }
};

struct Upload {
    Client &client;
    SocketImpl *const socket;
    const uint32_t stream_id;
    bool reset_received = false;
    bool completed_by_peer = false;
    bool refused_by_goaway = false;

    Upload(Client &client, Stream *stream) : client(client), socket(client.socket_), stream_id(stream->stream_id) {
        stream->upload = this;
    }

    Upload(const Upload &) = delete;
    Upload &operator=(const Upload &) = delete;

    ~Upload() {
        if (auto *stream = get_stream()) {
            stream->upload = nullptr;
        }
    }

    Stream *get_stream() const {
        return client.socket_ == socket ? client.get_stream(stream_id) : nullptr;
    }

    void report_reset() const {
        if (refused_by_goaway) {
            return;
        } else if (completed_by_peer) {
            client.update_error_properties(ECANCELED, "peer stopped the HTTP/2 upload after sending the response");
        } else {
            client.update_error_properties(SW_ERROR_HTTP2_STREAM_NOT_FOUND, "HTTP/2 upload stream is closed");
        }
    }
};

}  // namespace http2
}  // namespace coroutine
}  // namespace swoole

using swoole::coroutine::http2::Client;
using swoole::coroutine::http2::Stream;
using swoole::http2::HeaderSet;

struct Http2ClientObject {
    Client *client;
    zend_object std;
};

static sw_inline Http2ClientObject *http2_client_coro_fetch_object(zend_object *obj) {
    return reinterpret_cast<Http2ClientObject *>(reinterpret_cast<char *>(obj) -
                                                 swoole_http2_client_coro_handlers.offset);
}

static sw_inline Client *http2_client_coro_get_client(const zval *zobject) {
    return http2_client_coro_fetch_object(Z_OBJ_P(zobject))->client;
}

static void http2_client_coro_free_object(zend_object *object) {
    Http2ClientObject *h2o = http2_client_coro_fetch_object(object);
    if (h2o->client) {
        delete h2o->client;
        h2o->client = nullptr;
    }
    zend_object_std_dtor(&h2o->std);
}

static zend_object *http2_client_coro_create_object(zend_class_entry *ce) {
    auto *request = static_cast<Http2ClientObject *>(zend_object_alloc(sizeof(Http2ClientObject), ce));
    zend_object_std_init(&request->std, ce);
    object_properties_init(&request->std, ce);
    request->std.handlers = &swoole_http2_client_coro_handlers;
    return &request->std;
}

SW_EXTERN_C_BEGIN
static PHP_METHOD(swoole_http2_client_coro, __construct);
static PHP_METHOD(swoole_http2_client_coro, __destruct);
static PHP_METHOD(swoole_http2_client_coro, set);
static PHP_METHOD(swoole_http2_client_coro, connect);
static PHP_METHOD(swoole_http2_client_coro, stats);
static PHP_METHOD(swoole_http2_client_coro, isStreamExist);
static PHP_METHOD(swoole_http2_client_coro, send);
static PHP_METHOD(swoole_http2_client_coro, write);
static PHP_METHOD(swoole_http2_client_coro, recv);
static PHP_METHOD(swoole_http2_client_coro, read);
static PHP_METHOD(swoole_http2_client_coro, ping);
static PHP_METHOD(swoole_http2_client_coro, goaway);
static PHP_METHOD(swoole_http2_client_coro, close);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_http2_client_methods[] =
{
    PHP_ME(swoole_http2_client_coro, __construct,   arginfo_class_Swoole_Coroutine_Http2_Client___construct,    ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, __destruct,    arginfo_class_Swoole_Coroutine_Http2_Client___destruct,     ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, set,           arginfo_class_Swoole_Coroutine_Http2_Client_set,            ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, connect,       arginfo_class_Swoole_Coroutine_Http2_Client_connect,        ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, stats,         arginfo_class_Swoole_Coroutine_Http2_Client_stats,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, isStreamExist, arginfo_class_Swoole_Coroutine_Http2_Client_isStreamExist,  ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, send,          arginfo_class_Swoole_Coroutine_Http2_Client_send,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, write,         arginfo_class_Swoole_Coroutine_Http2_Client_write,          ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, recv,          arginfo_class_Swoole_Coroutine_Http2_Client_recv,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, read,          arginfo_class_Swoole_Coroutine_Http2_Client_read,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, goaway,        arginfo_class_Swoole_Coroutine_Http2_Client_goaway,         ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, ping,          arginfo_class_Swoole_Coroutine_Http2_Client_ping,           ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, close,         arginfo_class_Swoole_Coroutine_Http2_Client_close,          ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_http2_client_coro_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(
        swoole_http2_client_coro, "Swoole\\Coroutine\\Http2\\Client", "Co\\Http2\\Client", swoole_http2_client_methods);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http2_client_coro);
    SW_SET_CLASS_CLONEABLE(swoole_http2_client_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http2_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CUSTOM_OBJECT(swoole_http2_client_coro,
                               http2_client_coro_create_object,
                               http2_client_coro_free_object,
                               Http2ClientObject,
                               std);

    SW_INIT_CLASS_ENTRY_EX(swoole_http2_client_coro_exception,
                           "Swoole\\Coroutine\\Http2\\Client\\Exception",
                           "Co\\Http2\\Client\\Exception",
                           nullptr,
                           swoole_exception);

    SW_INIT_CLASS_ENTRY(swoole_http2_request, "Swoole\\Http2\\Request", nullptr, nullptr);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http2_request);
    SW_SET_CLASS_CLONEABLE(swoole_http2_request, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http2_request, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http2_request);

    SW_INIT_CLASS_ENTRY(swoole_http2_response, "Swoole\\Http2\\Response", nullptr, nullptr);
    SW_SET_CLASS_NOT_SERIALIZABLE(swoole_http2_response);
    SW_SET_CLASS_CLONEABLE(swoole_http2_response, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http2_response, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http2_response);

    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http2_client_coro_ce, ZEND_STRL("errMsg"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_client_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_client_coro_ce, ZEND_STRL("socket"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_client_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_client_coro_ce, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_client_coro_ce, ZEND_STRL("ssl"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("serverLastStreamId"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_string(swoole_http2_request_ce, ZEND_STRL("path"), "/", ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http2_request_ce, ZEND_STRL("method"), "GET", ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_request_ce, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_request_ce, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http2_request_ce, ZEND_STRL("data"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_request_ce, ZEND_STRL("pipeline"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_request_ce, ZEND_STRL("usePipelineRead"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_long(swoole_http2_response_ce, ZEND_STRL("streamId"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_response_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_response_ce, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_response_ce, ZEND_STRL("pipeline"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);
    /* Headers from trailing HEADERS frames, kept separate from the initial response "headers".
     * NULL when the peer sent no trailing HEADERS frame. Classification is by HTTP/2 receive
     * phase, independent of any application protocol (gRPC or otherwise). */
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("trailers"), ZEND_ACC_PUBLIC);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_DATA", SW_HTTP2_TYPE_DATA);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_HEADERS", SW_HTTP2_TYPE_HEADERS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_PRIORITY", SW_HTTP2_TYPE_PRIORITY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_RST_STREAM", SW_HTTP2_TYPE_RST_STREAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_SETTINGS", SW_HTTP2_TYPE_SETTINGS);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_PUSH_PROMISE", SW_HTTP2_TYPE_PUSH_PROMISE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_PING", SW_HTTP2_TYPE_PING);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_GOAWAY", SW_HTTP2_TYPE_GOAWAY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_WINDOW_UPDATE", SW_HTTP2_TYPE_WINDOW_UPDATE);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_TYPE_CONTINUATION", SW_HTTP2_TYPE_CONTINUATION);

    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_NO_ERROR", SW_HTTP2_ERROR_NO_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR", SW_HTTP2_ERROR_PROTOCOL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_INTERNAL_ERROR", SW_HTTP2_ERROR_INTERNAL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_FLOW_CONTROL_ERROR", SW_HTTP2_ERROR_FLOW_CONTROL_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_SETTINGS_TIMEOUT", SW_HTTP2_ERROR_SETTINGS_TIMEOUT);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_STREAM_CLOSED", SW_HTTP2_ERROR_STREAM_CLOSED);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_FRAME_SIZE_ERROR", SW_HTTP2_ERROR_FRAME_SIZE_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_REFUSED_STREAM", SW_HTTP2_ERROR_REFUSED_STREAM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_CANCEL", SW_HTTP2_ERROR_CANCEL);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_COMPRESSION_ERROR", SW_HTTP2_ERROR_COMPRESSION_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_CONNECT_ERROR", SW_HTTP2_ERROR_CONNECT_ERROR);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM", SW_HTTP2_ERROR_ENHANCE_YOUR_CALM);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_INADEQUATE_SECURITY", SW_HTTP2_ERROR_INADEQUATE_SECURITY);
    SW_REGISTER_LONG_CONSTANT("SWOOLE_HTTP2_ERROR_HTTP_1_1_REQUIRED", SW_HTTP2_ERROR_HTTP_1_1_REQUIRED);
}

void Client::socket_dtor() {
    cancel_drain_timer();
    socket_ = nullptr;
    clean_send_queue();
    // Responses already parsed by a writer belong to the application even after a transport failure.
    preserve_disconnect_error = is_draining() || !pending_responses.empty();
    buffered_pipeline_data = false;
#ifdef SW_HAVE_ZLIB
    gzip_buffer.reset();
#endif
    auto i = streams.begin();
    while (i != streams.end()) {
        destroy_stream(i->second);
        streams.erase(i++);
    }
    if (inflater) {
        nghttp2_hd_inflate_del(inflater);
        inflater = nullptr;
    }
    if (deflater) {
        nghttp2_hd_deflate_del(deflater);
        deflater = nullptr;
    }
    zend_update_property_bool(swoole_http2_client_coro_ce, Z_OBJ_P(zobject), ZEND_STRL("connected"), 0);
    zend_update_property_null(swoole_http2_client_coro_ce, Z_OBJ_P(zobject), ZEND_STRL("socket"));
    zval_ptr_dtor(&zsocket);
    ZVAL_NULL(&zsocket);
}

bool Client::connect() {
    if (sw_unlikely(socket_ != nullptr)) {
        update_error_properties(EISCONN, strerror(EISCONN));
        return false;
    }

    discard_pending_responses();
    peer_last_stream_id = UINT32_MAX;
    drain_timed_out = false;
    auto object = php_swoole_create_socket(socket_type);
    if (UNEXPECTED(!object)) {
        php_swoole_socket_set_error_properties(zobject, errno, strerror(errno));
        return false;
    }

    ZVAL_OBJ(&zsocket, object);
    socket_ = php_swoole_get_socket(&zsocket);
    socket_->set_dtor([this](Socket *_socket) { socket_dtor(); });
    socket_->set_zero_copy(true);
    if (open_ssl && !socket_->enable_ssl_encrypt()) {
        io_error();
        close();
        return false;
    }
    socket_->http2 = true;
    socket_->open_length_check = true;
    socket_->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
    socket_->protocol.package_length_offset = 0;
    socket_->protocol.package_body_offset = 0;
    socket_->protocol.get_package_length = Http2::get_frame_length;

    if (!apply_setting(
            sw_zend_read_property_ex(swoole_http2_client_coro_ce, zobject, SW_ZSTR_KNOWN(SW_ZEND_STR_SETTING), 0))) {
        close();
        return false;
    }

    if (!socket_->connect(host, port)) {
        io_error();
        close();
        return false;
    }

    stream_id = 1;
    continuation_stream_id = 0;
    // [init]: we must set default value, server is not always send all the settings
    Http2::init_settings(&remote_settings);
    // The peer's initial limit is unlimited until it advertises MAX_CONCURRENT_STREAMS.
    remote_settings.max_concurrent_streams = UINT32_MAX;
    remote_settings.init_window_size = SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;
    remote_settings.max_frame_size = SW_HTTP2_DEFAULT_MAX_FRAME_SIZE;
    remote_window_size = SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;
    local_window_size = SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;

    int ret = nghttp2_hd_inflate_new2(&inflater, php_nghttp2_mem());
    if (ret != 0) {
        nghttp2_error(ret, "nghttp2_hd_inflate_new2() failed");
        close();
        return false;
    }
    ret = nghttp2_hd_deflate_new2(&deflater, local_settings.header_table_size, php_nghttp2_mem());
    if (ret != 0) {
        nghttp2_error(ret, "nghttp2_hd_deflate_new2() failed");
        close();
        return false;
    }

    if (!send(ZEND_STRL(SW_HTTP2_PRI_STRING)) || !send_setting()) {
        return false;
    }

    zend_update_property(Z_OBJCE_P(zobject), Z_OBJ_P(zobject), ZEND_STRL("socket"), &zsocket);
    zend_update_property_bool(swoole_http2_client_coro_ce, Z_OBJ_P(zobject), ZEND_STRL("connected"), 1);

    return true;
}

bool Client::close() const {
    /*
     * The socket_ pointer MUST be staged,
     * when client close the member variable may be set to nullptr in socket dtor
     */
    SocketImpl *_socket = socket_;
    if (_socket == nullptr) {
        update_error_properties(EBADF, strerror(EBADF));
        return false;
    }
    zend_update_property_bool(Z_OBJCE_P(zobject), Z_OBJ_P(zobject), ZEND_STRL("connected"), 0);
    if (!_socket->close()) {
        update_error_properties(_socket->errCode, _socket->errMsg);
        return false;
    }
    return true;
}

void Client::cancel_drain_timer() {
    if (drain_timer > 0 && swoole_timer_is_available()) {
        swoole_timer_clear(drain_timer);
    }
    drain_timer = 0;
}

bool Client::request_close() {
    if (!drain_timed_out || !socket_) {
        discard_pending_responses();
        return close();
    }

    auto *socket = socket_;
    const bool ret = close();
    if (!socket_ || socket_ == socket) {
        update_error_properties(ETIMEDOUT, "HTTP/2 GOAWAY drain timed out");
    }
    return ret;
}

void Client::on_drain_timeout() {
    drain_timer = 0;
    drain_timed_out = true;
    update_error_properties(ETIMEDOUT, "HTTP/2 GOAWAY drain timed out");

    // A completion backend can suspend during close and needs a PHP coroutine to resume its I/O waiters.
    zend::Variable client(zobject);
    zend_fcall_info_cache fci{};
    fci.function_handler = static_cast<zend_function *>(
        zend_hash_str_find_ptr(&swoole_http2_client_coro_ce->function_table, ZEND_STRL("close")));
    fci.object = Z_OBJ_P(zobject);
    fci.called_scope = swoole_http2_client_coro_ce;
    if (swoole::PHPCoroutine::create(&fci, 0, nullptr, nullptr) < 0 && socket_) {
        if (socket_->has_bound()) {
            // Wake the existing I/O coroutine if we cannot create a separate closer.
            ::shutdown(socket_->get_socket()->fd, SHUT_RDWR);
        } else {
            request_close();
        }
    }
}

bool Client::close_if_drained() {
    if (!is_draining() || !streams.empty() || !socket_) {
        return false;
    }

    // Closing can wake other socket operations, which can overwrite the peer's GOAWAY diagnostic.
    auto *object = Z_OBJ_P(zobject);
    zval rv;
    zend::Variable error(zend_read_property(swoole_http2_client_coro_ce, object, ZEND_STRL("errCode"), 1, &rv));
    zend::Variable message(zend_read_property(swoole_http2_client_coro_ce, object, ZEND_STRL("errMsg"), 1, &rv));
    cancel_drain_timer();
    close();
    zend_update_property(swoole_http2_client_coro_ce, object, ZEND_STRL("errCode"), error.ptr());
    zend_update_property(swoole_http2_client_coro_ce, object, ZEND_STRL("errMsg"), message.ptr());
    return true;
}

ReturnCode Client::receive_goaway(const char *payload, size_t length, zval *return_value, bool upload_read) {
    uint32_t last, error;
    memcpy(&last, payload, sizeof(last));
    memcpy(&error, payload + sizeof(last), sizeof(error));
    last = std::min<uint32_t>(ntohl(last) & 0x7fffffffU, peer_last_stream_id);
    error = ntohl(error);
    zend::String message(payload + SW_HTTP2_GOAWAY_SIZE, length - SW_HTTP2_GOAWAY_SIZE);
    swoole_http2_recv_trace_log("GOAWAY length=%zu, last_stream_id=%u, error_code=%u, opaque_data=[%.*s]",
                                length,
                                last,
                                error,
                                static_cast<int>(message.len()),
                                message.val());

    bool closed = error != SW_HTTP2_ERROR_NO_ERROR;
    if (closed) {
        close();
    } else {
        const bool first_goaway = !is_draining();
        peer_last_stream_id = last;
        for (auto iter = streams.begin(); iter != streams.end();) {
            auto *stream = (iter++)->second;
            if (stream->stream_id <= last) {
                continue;
            }
            if (stream->upload) {
                stream->upload->refused_by_goaway = true;
            }
            zend::Variable response;
            size_t bytes = 0;
            if (reset_stream(stream->stream_id, SW_HTTP2_ERROR_REFUSED_STREAM, response.ptr(), &bytes) == SW_READY) {
                pending_responses.push_back({std::move(response), bytes, false});
            }
        }
        if (first_goaway && !streams.empty()) {
            double timeout = socket_->get_timeout(SW_TIMEOUT_READ);
            if (!(timeout > 0 && timeout < SW_SOCKET_DEFAULT_READ_TIMEOUT)) {
                timeout = SW_SOCKET_DEFAULT_READ_TIMEOUT;
            }
            drain_timer =
                swoole_timer_after(std::max(1L, static_cast<long>(timeout * 1000)), [this](Timer *, TimerNode *) {
                    on_drain_timeout();
                });
            if (drain_timer <= 0) {
                close();
                closed = true;
            }
        }
    }

    zend_update_property_long(swoole_http2_client_coro_ce, Z_OBJ_P(zobject), ZEND_STRL("errCode"), error);
    zend_update_property_str(swoole_http2_client_coro_ce, Z_OBJ_P(zobject), ZEND_STRL("errMsg"), message.get());
    zend_update_property_long(swoole_http2_client_coro_ce, Z_OBJ_P(zobject), ZEND_STRL("serverLastStreamId"), last);
    if (!upload_read && pop_pending_response(return_value)) {
        return SW_READY;
    }
    return closed ? SW_CLOSE : SW_CONTINUE;
}

static double http2_client_now() {
    return swoole::time<std::chrono::microseconds>(true) / 1000000.0;
}

ReturnCode Client::reject_send_window(uint32_t error, const char *reason) {
    auto *socket = socket_;
    // Try GOAWAY without interrupting a partially written frame or blocking on a stalled peer.
    if (!socket->has_bound(SW_EVENT_WRITE)) {
        SocketImpl::TimeoutSetter timeout(socket, 0.1, SW_TIMEOUT_WRITE);
        send_goaway_frame(error, reason, strlen(reason));
    }
    if (socket_ == socket) {
        close();
    }
    update_error_properties(error, reason);
    return SW_CLOSE;
}

bool Client::pop_pending_response(zval *return_value) {
    if (pending_responses.empty()) {
        return false;
    }
    auto &pending = pending_responses.front();
    ZVAL_COPY_VALUE(return_value, pending.response.ptr());
    pending.response.reset();
    buffered_response_bytes -= pending.bytes;
    pending_upload_responses -= pending.buffered_by_upload;
    pending_responses.pop_front();
    return true;
}

size_t Client::remaining_response_bytes(bool upload_read) const {
    const size_t limit = upload_read ? max_buffered_response_bytes : SIZE_MAX;
    return buffered_response_bytes < limit ? limit - buffered_response_bytes : 0;
}

bool Client::reserve_response_bytes(Stream *stream, size_t bytes, bool upload_read) {
    if (sw_unlikely(bytes > remaining_response_bytes(upload_read))) {
        return false;
    }
    buffered_response_bytes += bytes;
    stream->response_bytes += bytes;
    return true;
}

ReturnCode Client::reject_response_buffer() {
    close();
    update_error_properties(ENOBUFS, "HTTP/2 response buffering limit reached during upload");
    return SW_CLOSE;
}

#ifdef SW_HAVE_ZLIB
ReturnCode Client::reject_compressed_response() {
    // Do not retain a decoder or deliver buffered partial content after a corrupt representation.
    close();
    update_error_properties(SW_ERROR_HTTP_INVALID_PROTOCOL, "invalid or incomplete HTTP/2 gzip response");
    return SW_CLOSE;
}
#endif

ReturnCode Client::receive_frame(
    SocketImpl *socket, double timeout, zval *return_value, bool pipeline_read, uint32_t upload) {
    if (socket != socket_ || !socket->is_connected()) {
        return SW_CLOSE;
    }
    if (!read_lock) {
        read_lock = std::make_unique<Channel>();
    }
    if (timeout == 0) {
        timeout = socket->get_timeout(SW_TIMEOUT_READ);
    }
    const double deadline = timeout > 0 && read_lock->is_full() ? http2_client_now() + timeout : 0;
    if (!read_lock->push(nullptr, timeout)) {
        if (socket != socket_ || !socket->is_connected()) {
            return SW_CLOSE;
        }
        socket->set_err(read_lock->get_error() == Channel::ERROR_CANCELED ? ECANCELED : ETIMEDOUT);
        io_error();
        return SW_ERROR;
    }
    ON_SCOPE_EXIT {
        read_lock->pop();
    };

    if (upload == 0 && pop_pending_response(return_value)) {
        return SW_READY;
    }
    if (socket != socket_ || !socket->is_connected()) {
        return SW_CLOSE;
    }
    if (upload != 0) {
        auto *stream = get_stream(upload);
        if (!stream || (remote_window_size > 0 && stream->remote_window_size > 0)) {
            return SW_CONTINUE;
        }
    } else if (pipeline_read && buffered_pipeline_data) {
        for (const auto &entry : streams) {
            auto *stream = entry.second;
            if ((stream->flags & SW_HTTP2_STREAM_PIPELINE_RESPONSE) && stream->buffer && !stream->buffer->empty()) {
                return_response(stream, return_value, false);
                return SW_READY;
            }
        }
        buffered_pipeline_data = false;
    }
    if (deadline > 0) {
        timeout = deadline - http2_client_now();
        if (timeout <= 0) {
            socket->set_err(ETIMEDOUT);
            io_error();
            return SW_ERROR;
        }
    }
    const auto received = socket->recv_packet(timeout);
    if (received <= 0) {
        if (drain_timed_out) {
            close();
            update_error_properties(ETIMEDOUT, "HTTP/2 GOAWAY drain timed out");
            return SW_CLOSE;
        }
        if (upload != 0 && socket->errCode == 0) {
            socket->set_err(ECONNRESET);
        }
        io_error();
        if (socket->get_socket()->close_wait || (is_draining() && (received == 0 || socket->errCode != ECANCELED))) {
            close();
            return SW_CLOSE;
        }
        return SW_ERROR;
    }

    if (upload == 0) {
        const auto ret = parse_frame(return_value, pipeline_read);
        if (ret != SW_CLOSE && close_if_drained() && ret == SW_CONTINUE) {
            return SW_CLOSE;
        }
        return ret;
    }

    // Uploads may receive response frames before the application calls recv() or read().
    zend::Variable response;
    size_t bytes = 0;
    const bool data = socket->get_read_buffer()->str[3] == SW_HTTP2_TYPE_DATA;
    auto ret = parse_frame(response.ptr(), false, &bytes);
    if (ret == SW_READY) {
        if (sw_unlikely(pending_upload_responses >= MAX_PENDING_RESPONSES)) {
            buffered_response_bytes -= bytes;
            return reject_response_buffer();
        }
        pending_responses.push_back({std::move(response), bytes, true});
        ++pending_upload_responses;
        ret = SW_CONTINUE;
    } else if (ret == SW_CONTINUE && data) {
        buffered_pipeline_data = true;
    }
    if (ret != SW_CLOSE && close_if_drained() && ret == SW_CONTINUE) {
        return SW_CLOSE;
    }
    return ret;
}

#ifdef SW_HAVE_ZLIB
static ReturnCode http2_client_decompress(Stream *response, String *buffer, char *body, size_t length, size_t limit);
#endif

ReturnCode Client::parse_frame(zval *return_value, bool pipeline_read, size_t *pending_bytes) {
    const bool upload_read = pending_bytes != nullptr;
    char *buf = socket_->get_read_buffer()->str;
    uint8_t type = buf[3];
    uint8_t flags = buf[4];
    uint32_t _stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;
    ssize_t length = Http2::get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];

    if (_stream_id > last_stream_id) {
        last_stream_id = _stream_id;
    }

    // A header block's CONTINUATION frames must follow it with no other frames in between
    if (continuation_stream_id != 0 ? type != SW_HTTP2_TYPE_CONTINUATION || _stream_id != continuation_stream_id
                                    : type == SW_HTTP2_TYPE_CONTINUATION) {
        // close() records its own error when it has to wait for another coroutine
        close();
        update_error_properties(SW_HTTP2_ERROR_PROTOCOL_ERROR, "invalid CONTINUATION frame sequence");
        return SW_CLOSE;
    }

    switch (type) {
    case SW_HTTP2_TYPE_SETTINGS: {
        if (flags & SW_HTTP2_FLAG_ACK) {
            swoole_http2_frame_trace_log("ACK");
            return SW_CONTINUE;
        }

        auto rc = Http2::unpack_setting_data(buf, length, [&](uint16_t id, uint32_t value) -> ReturnCode {
            swoole_http2_frame_trace_log("id=%d, value=%d", id, value);
            switch (id) {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                if (value != remote_settings.header_table_size) {
                    remote_settings.header_table_size = value;
                    int ret = nghttp2_hd_deflate_change_table_size(deflater, value);
                    if (ret != 0) {
                        nghttp2_error(ret, "nghttp2_hd_deflate_change_table_size() failed");
                        return SW_ERROR;
                    }
                }
                swoole_trace_log(SW_TRACE_HTTP2, "setting: header_compression_table_max=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                remote_settings.max_concurrent_streams = value;
                swoole_trace_log(SW_TRACE_HTTP2, "setting: max_concurrent_streams=%u", value);
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE: {
                if (value > INT32_MAX) {
                    return reject_send_window(SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "invalid initial send window");
                }
                const int64_t delta = int64_t(value) - remote_settings.init_window_size;
                for (const auto &entry : streams) {
                    if (entry.second->remote_window_size + delta > INT32_MAX) {
                        return reject_send_window(SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "stream send window overflow");
                    }
                }
                for (const auto &entry : streams) {
                    entry.second->remote_window_size += delta;
                }
                remote_settings.init_window_size = value;
                swoole_trace_log(SW_TRACE_HTTP2, "setting: init_send_window=%u", value);
                break;
            }
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                if (value < SW_HTTP2_DEFAULT_MAX_FRAME_SIZE || value > SW_HTTP2_MAX_FRAME_SIZE) {
                    close();
                    update_error_properties(
                        SW_HTTP2_ERROR_PROTOCOL_ERROR,
                        std_string::format("invalid SETTINGS_MAX_FRAME_SIZE value %u", value).c_str());
                    return SW_CLOSE;
                }
                remote_settings.max_frame_size = value;
                swoole_trace_log(SW_TRACE_HTTP2, "setting: max_frame_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                if (value != remote_settings.max_header_list_size) {
                    remote_settings.max_header_list_size = value;
#if 0
                    int ret = nghttp2_hd_inflate_change_table_size(inflater, value);
                    if (ret != 0) {
                        nghttp2_error(ret, "nghttp2_hd_inflate_change_table_size() failed");
                        return SW_ERROR;
                    }
#endif
                }
                swoole_trace_log(SW_TRACE_HTTP2, "setting: max_header_list_size=%u", value);
                break;
            default:
                // disable warning and ignore it because some websites are not following http2 protocol totally
                // swoole_warning("unknown option[%d]: %d", id, value);
                break;
            }
            return SW_SUCCESS;
        });

        if (rc != SW_SUCCESS) {
            return rc;
        }

        Http2::set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 0, SW_HTTP2_FLAG_ACK, _stream_id);
        if (!send(frame, SW_HTTP2_FRAME_HEADER_SIZE)) {
            return SW_ERROR;
        }
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_WINDOW_UPDATE: {
        if (length != SW_HTTP2_WINDOW_UPDATE_SIZE) {
            // close() records its own error when it has to wait for another coroutine
            close();
            update_error_properties(SW_HTTP2_ERROR_FRAME_SIZE_ERROR, "invalid WINDOW_UPDATE frame length");
            return SW_CLOSE;
        }
        uint32_t value;
        memcpy(&value, buf, sizeof(value));
        value = ntohl(value) & 0x7fffffff;
        swoole_trace_log(
            SW_TRACE_HTTP2, "[" SW_ECHO_YELLOW "] stream_id=%u, size=%u", "WINDOW_UPDATE", _stream_id, value);
        if (_stream_id == 0) {
            if (value == 0 || int64_t(remote_window_size) + value > INT32_MAX) {
                return reject_send_window(
                    value == 0 ? SW_HTTP2_ERROR_PROTOCOL_ERROR : SW_HTTP2_ERROR_FLOW_CONTROL_ERROR,
                    "invalid connection WINDOW_UPDATE");
            }
            remote_window_size += value;
        } else if (auto *stream = get_stream(_stream_id)) {
            if (value == 0 || int64_t(stream->remote_window_size) + value > INT32_MAX) {
                const uint32_t error_code =
                    value == 0 ? SW_HTTP2_ERROR_PROTOCOL_ERROR : SW_HTTP2_ERROR_FLOW_CONTROL_ERROR;
                reset_stream(_stream_id, error_code);
                const uint32_t error = htonl(error_code);
                Http2::set_frame_header(frame, SW_HTTP2_TYPE_RST_STREAM, SW_HTTP2_RST_STREAM_SIZE, 0, _stream_id);
                memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE, &error, sizeof(error));
                if (!send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_RST_STREAM_SIZE)) {
                    return SW_ERROR;
                }
            } else {
                stream->remote_window_size += static_cast<int32_t>(value);
            }
        }
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_PING: {
        swoole_http2_frame_trace_log("ping");
        if (length != SW_HTTP2_FRAME_PING_PAYLOAD_SIZE) {
            // close() records its own error when it has to wait for another coroutine
            close();
            update_error_properties(SW_HTTP2_ERROR_FRAME_SIZE_ERROR, "invalid PING frame length");
            return SW_CLOSE;
        }
        if (!(flags & SW_HTTP2_FLAG_ACK)) {
            Http2::set_frame_header(
                frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_ACK, _stream_id);
            memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE, buf, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
            if (!send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE)) {
                return SW_ERROR;
            }
        }
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_GOAWAY: {
        if (length < SW_HTTP2_GOAWAY_SIZE) {
            // close() records its own error when it has to wait for another coroutine
            close();
            update_error_properties(SW_HTTP2_ERROR_FRAME_SIZE_ERROR, "invalid GOAWAY frame length");
            return SW_CLOSE;
        }
        if (_stream_id != 0) {
            close();
            update_error_properties(SW_HTTP2_ERROR_PROTOCOL_ERROR, "invalid GOAWAY stream ID");
            return SW_CLOSE;
        }
        return receive_goaway(buf, length, return_value, upload_read);
    }
    case SW_HTTP2_TYPE_RST_STREAM: {
        if (length != SW_HTTP2_RST_STREAM_SIZE) {
            // close() records its own error when it has to wait for another coroutine
            close();
            update_error_properties(SW_HTTP2_ERROR_FRAME_SIZE_ERROR, "invalid RST_STREAM frame length");
            return SW_CLOSE;
        }
        uint32_t error;
        memcpy(&error, buf, sizeof(error));
        error = ntohl(error);
        swoole_http2_frame_trace_log("error_code=%u", error);
        return reset_stream(_stream_id, error, return_value, pending_bytes);
    }
    /**
     * TODO not support push_promise
     */
    case SW_HTTP2_TYPE_PUSH_PROMISE: {
#ifdef SW_DEBUG
        uint32_t promise_stream_id = ntohl(*(uint32_t *) (buf)) & 0x7fffffff;
        swoole_http2_frame_trace_log("promise_stream_id=%d", promise_stream_id);
#endif
        // auto promise_stream = create_stream(promise_stream_id, false);
        // RETVAL_ZVAL(promise_stream->response_object, 0, 0);
        // return SW_READY;
        return SW_CONTINUE;
    }
    default: {
        swoole_http2_frame_trace_log("");
    }
    }

    Stream *stream = get_stream(_stream_id);
    // The stream is not found or has closed
    if (stream == nullptr) {
        swoole_notice("http2 stream#%d belongs to an unknown type or it never registered", _stream_id);
        return SW_CONTINUE;
    }
    if (stream->response_ended) {
        return SW_CONTINUE;
    }
    if (type == SW_HTTP2_TYPE_HEADERS || type == SW_HTTP2_TYPE_CONTINUATION) {
        if (type == SW_HTTP2_TYPE_HEADERS) {
            stream->header_block_end_stream = flags & SW_HTTP2_FLAG_END_STREAM;
            // CONTINUATION frames carry the rest of this field section, so they keep its classification
            stream->header_block_is_trailers = stream->flags & SW_HTTP2_STREAM_RESPONSE_HEADERS_RECEIVED;
            if (flags & SW_HTTP2_FLAG_PADDED) {
                if (length < 1 || (uint8_t) buf[0] >= length) {
                    close();
                    update_error_properties(SW_HTTP2_ERROR_PROTOCOL_ERROR, "invalid HEADERS frame padding");
                    return SW_CLOSE;
                }
                length -= 1 + (uint8_t) buf[0];
                buf++;
            }
            if (flags & SW_HTTP2_FLAG_PRIORITY) {
                if (length < SW_HTTP2_PRIORITY_SIZE) {
                    close();
                    update_error_properties(SW_HTTP2_ERROR_FRAME_SIZE_ERROR, "invalid HEADERS frame length");
                    return SW_CLOSE;
                }
                buf += SW_HTTP2_PRIORITY_SIZE;
                length -= SW_HTTP2_PRIORITY_SIZE;
            }
        }
        const auto ret = parse_header(stream, flags, buf, length, upload_read);
        if (ret != SW_SUCCESS) {
            return ret;
        }
        if (!(flags & SW_HTTP2_FLAG_END_HEADERS)) {
            continuation_stream_id = _stream_id;
            return SW_CONTINUE;
        }
        continuation_stream_id = 0;
    } else if (type == SW_HTTP2_TYPE_DATA) {
        if (!(flags & SW_HTTP2_FLAG_END_STREAM)) {
            stream->flags |= SW_HTTP2_STREAM_PIPELINE_RESPONSE;
        }
        if (length > local_window_size || length > stream->local_window_size) {
            close();
            update_error_properties(SW_HTTP2_ERROR_FLOW_CONTROL_ERROR, "response DATA exceeded receive window");
            return SW_CLOSE;
        }
        char *data = buf;
        ssize_t data_length = length;
        if (flags & SW_HTTP2_FLAG_PADDED) {
            if (length < 1 || (uint8_t) buf[0] >= length) {
                close();
                update_error_properties(SW_HTTP2_ERROR_PROTOCOL_ERROR, "invalid DATA frame padding");
                return SW_CLOSE;
            }
            data_length -= 1 + (uint8_t) buf[0];
            data++;
        }
        if (data_length > 0) {
#ifdef SW_HAVE_ZLIB
            if (stream->gzip) {
                if (!gzip_buffer) {
                    gzip_buffer.reset(make_string(SW_HTTP2_DATA_BUFFER_SIZE));
                }
                const auto ret = http2_client_decompress(
                    stream, gzip_buffer.get(), data, data_length, remaining_response_bytes(upload_read));
                if (ret == SW_CLOSE) {
                    return reject_response_buffer();
                }
                if (ret == SW_ERROR) {
                    return reject_compressed_response();
                }
                data = gzip_buffer->str;
                data_length = gzip_buffer->length;
            }
#endif
            if (!reserve_response_bytes(stream, data_length, upload_read)) {
                return reject_response_buffer();
            }
            if (data_length > 0) {
                if (!stream->buffer) {
                    stream->buffer = make_string(SW_HTTP2_DATA_BUFFER_SIZE);
                }
                stream->buffer->append(data, data_length);
            }
        }
        // The padding counts against the flow-control windows too
        if (length > 0) {
            local_window_size -= length;
            stream->local_window_size -= length;
            uint32_t connection_target =
                std::max(local_settings.init_window_size, uint32_t(SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE));
            if (local_window_size <= connection_target / 2) {
                if (!send_window_update(0, connection_target - local_window_size)) {
                    return SW_ERROR;
                }
                local_window_size = connection_target;
            }
            if (stream->local_window_size <= (local_settings.init_window_size / 2)) {
                if (!send_window_update(_stream_id, local_settings.init_window_size - stream->local_window_size)) {
                    return SW_ERROR;
                }
                stream->local_window_size = local_settings.init_window_size;
            }
        }
    }

    bool end =
        type == SW_HTTP2_TYPE_CONTINUATION ? stream->header_block_end_stream : (flags & SW_HTTP2_FLAG_END_STREAM);
    pipeline_read = ((pipeline_read || (stream->flags & SW_HTTP2_STREAM_USE_PIPELINE_READ)) &&
                     (stream->flags & SW_HTTP2_STREAM_PIPELINE_RESPONSE));
#ifdef SW_HAVE_ZLIB
    if (end && stream->gzip && !stream->gzip_finished && !stream->request_is_head) {
        const auto status = zend::object_get_long(&stream->zresponse, ZEND_STRL("statusCode"));
        // These responses can advertise an encoding without carrying the encoded representation.
        if (status != SW_HTTP_NO_CONTENT && status != SW_HTTP_NOT_MODIFIED) {
            return reject_compressed_response();
        }
    }
#endif
    if (end || pipeline_read) {
        return_response(stream, return_value, end, pending_bytes);
        return SW_READY;
    }

    return SW_CONTINUE;
}

void Client::transfer_response(Stream *stream, zval *return_value, size_t *pending_bytes) {
    zval *zresponse = &stream->zresponse;
    if (stream->buffer && !stream->buffer->empty()) {
        zend_update_property_stringl(swoole_http2_response_ce,
                                     Z_OBJ_P(zresponse),
                                     ZEND_STRL("data"),
                                     stream->buffer->str,
                                     stream->buffer->length);
        stream->buffer->clear();
    }
    if (pending_bytes) {
        *pending_bytes = stream->response_bytes;
        delete stream->buffer;
        stream->buffer = nullptr;
    } else {
        buffered_response_bytes -= stream->response_bytes;
    }
    stream->response_bytes = 0;
    ZVAL_COPY_VALUE(return_value, zresponse);
    ZVAL_UNDEF(zresponse);
}

void Client::return_response(Stream *stream, zval *return_value, bool end, size_t *pending_bytes) {
    transfer_response(stream, return_value, pending_bytes);
    if (end) {
        // The response can end before the request. Keep the send window alive until END_STREAM or RST_STREAM.
        stream->response_ended = true;
        if (stream->flags & SW_HTTP2_STREAM_REQUEST_END) {
            delete_stream(stream->stream_id);
        } else {
            stream->release_receive_buffers();
        }
    } else {
        zend_update_property_bool(swoole_http2_response_ce, Z_OBJ_P(return_value), ZEND_STRL("pipeline"), 1);
        object_init_ex(&stream->zresponse, swoole_http2_response_ce);
        zend_update_property_long(
            swoole_http2_response_ce, Z_OBJ_P(&stream->zresponse), ZEND_STRL("streamId"), stream->stream_id);
    }
}

#ifdef SW_HAVE_ZLIB
static ReturnCode http2_client_decompress(Stream *response, String *buffer, char *body, size_t length, size_t limit) {
    auto *stream = &response->gzip_stream;
    int status = 0;

    stream->avail_in = length;
    stream->next_in = (Bytef *) body;

    swoole_trace_log(SW_TRACE_ZLIB,
                     SW_START_LINE "\nstatus=%d\tavail_in=%u,\tavail_out=%u,\ttotal_in=%lu,\ttotal_out=%lu\n",
                     status,
                     stream->avail_in,
                     stream->avail_out,
                     stream->total_in,
                     stream->total_out);

    buffer->clear();

    // Allow one byte beyond the limit to detect when the decoded body needs more space.
    const size_t capacity = limit < SIZE_MAX ? limit + 1 : SIZE_MAX;
    while (true) {
        if (response->gzip_finished) {
            // A following member may start in this DATA frame or a later one. Preserve unconsumed input.
            auto *next_in = stream->next_in;
            const auto avail_in = stream->avail_in;
            if (inflateReset2(stream, MAX_WBITS + 16) != Z_OK) {
                return SW_ERROR;
            }
            stream->next_in = next_in;
            stream->avail_in = avail_in;
            response->gzip_finished = false;
        }
        const auto space = std::min({buffer->size - buffer->length, capacity - buffer->length, size_t(UINT_MAX)});
        stream->avail_out = space;
        stream->next_out = (Bytef *) (buffer->str + buffer->length);

        status = inflate(stream, Z_SYNC_FLUSH);

        swoole_trace_log(SW_TRACE_ZLIB,
                         "status=%d\tavail_in=%d,\tavail_out=%d,\ttotal_in=%lu,\ttotal_out=%lu,\tlength=%lu\n",
                         status,
                         stream->avail_in,
                         stream->avail_out,
                         stream->total_in,
                         stream->total_out,
                         buffer->length);

        buffer->length += space - stream->avail_out;
        if (buffer->length > limit) {
            return SW_CLOSE;
        }
        if (status == Z_STREAM_END) {
            response->gzip_finished = true;
            if (stream->avail_in == 0) {
                return SW_SUCCESS;
            }
            continue;
        }
        if (status == Z_BUF_ERROR && stream->avail_in == 0) {
            return SW_SUCCESS;
        }
        if (status != Z_OK) {
            return SW_ERROR;
        }
        if (stream->avail_in == 0 && stream->avail_out != 0) {
            return SW_SUCCESS;
        }
        if (buffer->length == buffer->size) {
            buffer->reserve(buffer->size + std::min(buffer->size, capacity - buffer->size));
        }
    }
}
#endif

static PHP_METHOD(swoole_http2_client_coro, __construct) {
    char *host;
    size_t host_len;
    zend_long port = 80;
    zend_bool ssl = false;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 3)
    Z_PARAM_STRING(host, host_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(port)
    Z_PARAM_BOOL(ssl)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (http2_client_coro_get_client(ZEND_THIS)) {
        zend_throw_error(nullptr, "Constructor of %s can only be called once", SW_Z_OBJCE_NAME_VAL_P(ZEND_THIS));
        RETURN_FALSE;
    }

    if (host_len == 0) {
        zend_throw_exception(swoole_http2_client_coro_exception_ce, "The host is empty", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }
    std::string host_string(host, host_len);
    auto type = Socket::convert_to_type(host_string);
    if (port != 0 && !Socket::is_local(type) && !Address::verify_port(port, true)) {
        zend_throw_exception(swoole_http2_client_coro_exception_ce, "The port is invalid", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    auto *client = new Client(type, std::move(host_string), port, ssl, ZEND_THIS);
    http2_client_coro_fetch_object(Z_OBJ_P(ZEND_THIS))->client = client;

    zend_update_property_stringl(swoole_http2_client_coro_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http2_client_coro_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("port"), client->port);
    zend_update_property_bool(swoole_http2_client_coro_ce, Z_OBJ_P(ZEND_THIS), ZEND_STRL("ssl"), ssl);
}

static PHP_METHOD(swoole_http2_client_coro, set) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!h2c->apply_setting(zset) || EG(exception)) {
        php_swoole_throw_setting_exception("failed to apply HTTP/2 client settings");
        RETURN_THROWS();
    }

    zval *zsetting =
        sw_zend_read_and_convert_property_array(swoole_http2_client_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    SEPARATE_ARRAY(zsetting);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    RETURN_TRUE;
}

/**
 * called in read channel
 */
bool Client::send_window_update(int _stream_id, uint32_t size) {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE];
    swoole_http2_send_trace_log("[" SW_ECHO_YELLOW "] stream_id=%d, size=%d", "WINDOW_UPDATE", stream_id, size);
    *(uint32_t *) ((char *) frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(size);
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_WINDOW_UPDATE, SW_HTTP2_WINDOW_UPDATE_SIZE, 0, _stream_id);
    return send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE);
}

/**
 * called on connect
 */
bool Client::send_setting() {
    char frame[SW_HTTP2_SETTING_FRAME_SIZE];
    size_t n = Http2::pack_setting_frame(frame, local_settings, false);
    swoole_http2_send_trace_log("[" SW_ECHO_MAGENTA
                                "] <header_table_size=%u, enable_push=%u, max_concurrent_streams=%u, "
                                "init_window_size=%u, max_frame_size=%u, max_header_list_size=%u>",
                                Http2::get_type(SW_HTTP2_TYPE_SETTINGS),
                                local_settings.header_table_size,
                                local_settings.enable_push,
                                local_settings.max_concurrent_streams,
                                local_settings.init_window_size,
                                local_settings.max_frame_size,
                                local_settings.max_header_list_size);
    if (!send(frame, n)) {
        return false;
    }
    // SETTINGS changes stream windows only. Advertise a larger connection window explicitly, and account for
    // that grant locally so later WINDOW_UPDATE increments describe the same credit at both endpoints.
    if (local_settings.init_window_size > SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE) {
        uint32_t increment = local_settings.init_window_size - SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE;
        if (!send_window_update(0, increment)) {
            return false;
        }
        local_window_size += increment;
    }
    return true;
}

void php_swoole_http_parse_set_cookies(const char *at, size_t length, zval *zcookies, zval *zset_cookie_headers);

ReturnCode Client::parse_header(Stream *stream, int flags, char *in, size_t inlen, bool upload_read) {
    zval *zresponse = &stream->zresponse;

    zval *zheaders =
        sw_zend_read_and_convert_property_array(swoole_http2_response_ce, zresponse, ZEND_STRL("headers"), 0);
    zval *zcookies =
        sw_zend_read_and_convert_property_array(swoole_http2_response_ce, zresponse, ZEND_STRL("cookies"), 0);
    zval *zset_cookie_headers = sw_zend_read_and_convert_property_array(
        swoole_http2_response_ce, zresponse, ZEND_STRL("set_cookie_headers"), 0);

    /* RFC 7540 sec 8.1: the initial response HEADERS frame carries the :status pseudo-header;
     * any later HEADERS frame on the same stream is a trailers frame and, per sec 8.1.2, MUST
     * NOT contain pseudo-headers. Classify by receive phase (a stream flag) plus the presence
     * of :status -- never by header names. This is a generic HTTP/2 facility, not gRPC-specific.
     * "headers" keeps receiving every header unchanged; "trailers" is only an additional view
     * of the trailing frame(s). */
    bool has_status_pseudo_header = false;
    zval *ztrailers = nullptr;

    for (;;) {
        nghttp2_nv nv;
        int inflate_flags = 0;

        ssize_t rv = nghttp2_hd_inflate_hd(
            inflater, &nv, &inflate_flags, (uchar *) in, inlen, (flags & SW_HTTP2_FLAG_END_HEADERS) != 0);
        if (rv < 0) {
            nghttp2_error(rv, "nghttp2_hd_inflate_hd failed");
            return SW_ERROR;
        }

        in += (size_t) rv;
        inlen -= (size_t) rv;

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            // Include per-field overhead so small, decoded headers count toward the buffering limit too.
            if (!reserve_response_bytes(stream, nv.namelen + nv.valuelen + 32, upload_read)) {
                return reject_response_buffer();
            }
            swoole_trace_log(SW_TRACE_HTTP2,
                             "[" SW_ECHO_GREEN "] %.*s[%lu]: %.*s[%lu]",
                             "HEADER",
                             (int) nv.namelen,
                             nv.name,
                             nv.namelen,
                             (int) nv.valuelen,
                             nv.value,
                             nv.valuelen);

            if (nv.name[0] == ':') {
                // Pseudo-headers only appear on the initial/informational response HEADERS
                // frame, never on a trailers frame. Encountering :status therefore proves this
                // frame is response headers, so its ordinary headers belong to "headers" only.
                if (SW_STRCASEEQ((char *) nv.name + 1, nv.namelen - 1, "status")) {
                    uint16_t status_code = 0;
                    if (!Http2::parse_status_code((char *) nv.value, nv.valuelen, &status_code)) {
                        return SW_ERROR;
                    }
                    zend::object_set(zresponse, ZEND_STRL("statusCode"), status_code);
                    has_status_pseudo_header = true;
                    stream->header_block_is_trailers = false;
                }
            } else {
#ifdef SW_HAVE_ZLIB
                if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "content-encoding") &&
                    SW_STR_ISTARTS_WITH((char *) nv.value, nv.valuelen, "gzip")) {
                    /**
                     * init zlib stream
                     */
                    stream->gzip = 1;
                    memset(&stream->gzip_stream, 0, sizeof(stream->gzip_stream));
                    stream->gzip_stream.zalloc = php_zlib_alloc;
                    stream->gzip_stream.zfree = php_zlib_free;
                    /**
                     * zlib decode
                     */
                    if (Z_OK != inflateInit2(&stream->gzip_stream, MAX_WBITS + 16)) {
                        swoole_warning("inflateInit2() failed");
                        return SW_ERROR;
                    }
                } else
#endif
                    if (SW_STRCASEEQ((char *) nv.name, nv.namelen, "set-cookie")) {
                    php_swoole_http_parse_set_cookies((char *) nv.value, nv.valuelen, zcookies, zset_cookie_headers);
                }
                add_assoc_stringl_ex(zheaders, (char *) nv.name, nv.namelen, (char *) nv.value, nv.valuelen);

                // "headers" still receives every header above (backward compatible). Only a
                // trailing HEADERS frame additionally feeds the separate "trailers" view.
                if (stream->header_block_is_trailers) {
                    if (ztrailers == nullptr) {
                        ztrailers = sw_zend_read_and_convert_property_array(
                            swoole_http2_response_ce, zresponse, ZEND_STRL("trailers"), 0);
                    }
                    add_assoc_stringl_ex(ztrailers, (char *) nv.name, nv.namelen, (char *) nv.value, nv.valuelen);
                }
            }
        }
        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }

        // Emitting the last field can consume all input before the inflater signals FINAL.
        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
            break;
        }
    }

    // Only a frame carrying :status marks the initial response headers as received. A trailers
    // frame has no pseudo-headers, so it leaves the flag untouched and is classified correctly
    // on the next HEADERS frame (if any).
    if (has_status_pseudo_header) {
        stream->flags |= SW_HTTP2_STREAM_RESPONSE_HEADERS_RECEIVED;
    }

    return SW_SUCCESS;
}

ssize_t Client::build_header(zval *zrequest, SocketImpl *socket, String *&buffer) {
    zval *zmethod = sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_METHOD), 0);
    zval *zpath = sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_PATH), 0);
    zval *zheaders = sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_HEADERS), 0);
    zval *zcookies = sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_COOKIES), 0);
    HeaderSet headers(8 + php_swoole_array_length_safe(zheaders) + php_swoole_array_length_safe(zcookies));
    bool find_host = false;

    if (Z_TYPE_P(zmethod) != IS_STRING || Z_STRLEN_P(zmethod) == 0) {
        headers.add(ZEND_STRL(":method"), ZEND_STRL("GET"));
    } else {
        headers.add(ZEND_STRL(":method"), Z_STRVAL_P(zmethod), Z_STRLEN_P(zmethod));
    }
    if (Z_TYPE_P(zpath) != IS_STRING || Z_STRLEN_P(zpath) == 0) {
        headers.add(ZEND_STRL(":path"), "/", 1);
    } else {
        headers.add(ZEND_STRL(":path"), Z_STRVAL_P(zpath), Z_STRLEN_P(zpath));
    }
    if (open_ssl) {
        headers.add(ZEND_STRL(":scheme"), ZEND_STRL("https"));
    } else {
        headers.add(ZEND_STRL(":scheme"), ZEND_STRL("http"));
    }
    // Host
    headers.reserve_one();

    if (ZVAL_IS_ARRAY(zheaders)) {
        zend_string *key;
        zval *zvalue;

        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zheaders), key, zvalue) {
            if (UNEXPECTED(!key || *ZSTR_VAL(key) == ':' || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            zend::String str_value(zvalue);
            if (SW_STRCASEEQ(ZSTR_VAL(key), ZSTR_LEN(key), "host")) {
                headers.add(HTTP2_CLIENT_HOST_HEADER_INDEX, ZEND_STRL(":authority"), str_value.val(), str_value.len());
                find_host = true;
            } else {
                headers.add(ZSTR_VAL(key), ZSTR_LEN(key), str_value.val(), str_value.len());
            }
        }
        ZEND_HASH_FOREACH_END();
    }
    if (!find_host) {
        const std::string *host_ptr;
        std::string _host;
        if (!open_ssl ? port != 80 : port != 443) {
            _host = std_string::format("%s:%d", host.c_str(), port);
            host_ptr = &_host;
        } else {
            host_ptr = &host;
        }
        headers.add(HTTP2_CLIENT_HOST_HEADER_INDEX, ZEND_STRL(":authority"), host_ptr->c_str(), host_ptr->length());
    }
    // http cookies
    if (ZVAL_IS_ARRAY(zcookies)) {
        zend_string *key;
        zval *zvalue;
        size_t encoded_value_len;
        String *header_buffer = sw_tg_buffer();

        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zcookies), key, zvalue) {
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue))) {
                continue;
            }
            zend::String str_value(zvalue);
            if (sw_unlikely(ZSTR_LEN(key) + str_value.len() + 1 > SW_HTTP_COOKIE_MAX_SIZE)) {
                zend_throw_exception_ex(
                    swoole_http2_client_coro_exception_ce, SW_ERROR_INVALID_PARAMS, "HTTP cookie header is too large");
                return -1;
            }
            header_buffer->clear();
            header_buffer->append(ZSTR_VAL(key), ZSTR_LEN(key));
            header_buffer->append("=", 1);
            char *encoded_value = php_swoole_url_encode(str_value.val(), str_value.len(), &encoded_value_len);
            if (encoded_value) {
                header_buffer->append(encoded_value, encoded_value_len);
                efree(encoded_value);
                headers.add(ZEND_STRL("cookie"), header_buffer->str, header_buffer->length);
            }
        }
        ZEND_HASH_FOREACH_END();
    }

    // PHP conversions above can run user code. Recheck admission before changing the HPACK state.
    if (sw_unlikely(EG(exception) || socket_ != socket || !socket->is_connected()) || !can_open_stream() ||
        !check_send_queue()) {
        return -1;
    }
    // send() copies queued frames. A direct write can yield, so keep its HEADERS frame in the client buffer.
    buffer = socket->has_bound(SW_EVENT_WRITE) ? sw_tg_buffer() : &header_frame;
    size_t buflen = nghttp2_hd_deflate_bound(deflater, headers.get(), headers.len());
    size_t buffer_size = SW_HTTP2_FRAME_HEADER_SIZE + buflen;
    // HeaderSet::add() copies cookie scratch values before this shared buffer is reused for encoding.
    buffer->clear();
    if (buffer_size > buffer->size) {
        buffer->reserve(buffer_size);
    }

    ssize_t rv = nghttp2_hd_deflate_hd(
        deflater, (uchar *) buffer->str + SW_HTTP2_FRAME_HEADER_SIZE, buflen, headers.get(), headers.len());
    if (rv < 0) {
        nghttp2_error(rv, "nghttp2_hd_deflate_hd() failed");
        close();
        return rv;
    }
    if ((uint64_t) rv > remote_settings.max_frame_size) {
        close();
        zend_throw_exception_ex(
            swoole_http2_client_coro_exception_ce, SW_ERROR_INVALID_PARAMS, "HTTP/2 header block is too large");
        return NGHTTP2_ERR_FRAME_SIZE_ERROR;
    }

    buffer->length = SW_HTTP2_FRAME_HEADER_SIZE + rv;
    return rv;
}

void Client::destroy_stream(Stream *stream) {
    buffered_response_bytes -= stream->response_bytes;
    stream->release_receive_buffers();
    zval_ptr_dtor(&stream->zresponse);
    efree(stream);
}

Stream *Client::create_stream(uint32_t _stream_id, uint8_t flags) {
    // malloc
    auto *stream = static_cast<Stream *>(ecalloc(1, sizeof(Stream)));
    // init
    stream->stream_id = _stream_id;
    stream->flags = flags;
    stream->remote_window_size = remote_settings.init_window_size;
    stream->local_window_size = local_settings.init_window_size;
    streams.emplace(_stream_id, stream);
    // create response object
    object_init_ex(&stream->zresponse, swoole_http2_response_ce);
    zend_update_property_long(swoole_http2_response_ce, Z_OBJ_P(&stream->zresponse), ZEND_STRL("streamId"), _stream_id);

    return stream;
}

/**
 * called in write channel
 */
bool Client::send_ping_frame() {
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE] = {};
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_NONE, 0);
    swoole_http2_send_trace_log("[" SW_ECHO_CYAN "]", "PING");
    return send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
}

ReturnCode Client::reset_stream(uint32_t id, uint32_t error, zval *return_value, size_t *pending_bytes) {
    auto *stream = get_stream(id);
    if (!stream) {
        return SW_CONTINUE;
    }
    if (auto *upload = stream->upload) {
        upload->reset_received = true;
        upload->completed_by_peer = stream->response_ended && error == SW_HTTP2_ERROR_NO_ERROR;
    }

    // An early complete response can be followed by a reset that stops the request body.
    const bool deliver_reset = return_value && !stream->response_ended;
    if (deliver_reset) {
        zend::object_set(&stream->zresponse, ZEND_STRL("statusCode"), HTTP_ESTATUS_SERVER_RESET);
        zend::object_set(&stream->zresponse, ZEND_STRL("errCode"), error);
        transfer_response(stream, return_value, pending_bytes);
    }
    delete_stream(id);
    return deliver_reset ? SW_READY : SW_CONTINUE;
}

void Client::finish_request(const Upload &upload) {
    if (auto *stream = upload.get_stream()) {
        stream->flags |= SW_HTTP2_STREAM_REQUEST_END;
        if (stream->response_ended) {
            delete_stream(stream->stream_id);
            close_if_drained();
        }
    }
}

bool Client::send_data(const Upload &upload, const char *p, size_t len, int flag) {
    auto *socket = upload.socket;
    const auto _stream_id = upload.stream_id;
    if (socket != socket_ || !socket->is_connected() || upload.reset_received) {
        return false;
    }

    char header[SW_HTTP2_FRAME_HEADER_SIZE];
    if (len == 0) {
        if (!(flag & SW_HTTP2_FLAG_END_STREAM)) {
            return true;
        }
        Http2::set_frame_header(header, SW_HTTP2_TYPE_DATA, 0, flag, _stream_id);
        swoole_trace_log(
            SW_TRACE_HTTP2, "send [" SW_ECHO_YELLOW "] stream_id=%u, flags=%d, send_n=0", "DATA", _stream_id, flag);
        return send(header, SW_HTTP2_FRAME_HEADER_SIZE) && !upload.reset_received;
    }
    double deadline = 0;
    while (len > 0) {
        if (socket != socket_ || !socket->is_connected() || upload.reset_received) {
            return false;
        }
        // A read can remove the stream while the frame write or flow-control wait is suspended.
        auto *stream = get_stream(_stream_id);
        if (!stream) {
            update_error_properties(SW_ERROR_HTTP2_STREAM_NOT_FOUND, "HTTP/2 upload stream is closed");
            return false;
        }
        const auto window = std::min(static_cast<int32_t>(remote_window_size), stream->remote_window_size);
        if (window <= 0) {
            const double now = http2_client_now();
            if (deadline == 0) {
                const double timeout = socket->get_timeout(SW_TIMEOUT_WRITE);
                deadline = now + (timeout > 0 ? timeout : SW_SOCKET_DEFAULT_WRITE_TIMEOUT);
            }
            if (deadline <= now) {
                socket->set_err(ETIMEDOUT);
                send_error();
                return false;
            }
            auto ret = receive_frame(socket, deadline - now, nullptr, false, _stream_id);
            if (ret == SW_ERROR && socket == socket_ && socket->is_connected()) {
                if (socket->errCode == 0) {
                    socket->set_err(SW_ERROR_HTTP2_INTERNAL_ERROR, "failed to receive HTTP/2 upload credit");
                }
                send_error();
            }
            if (ret != SW_CONTINUE) {
                return false;
            }
            continue;
        }
        const uint32_t send_len = std::min({len, size_t(remote_settings.max_frame_size), size_t(window)});
        const int send_flag = send_len == len ? flag : 0;
        // Reserve credit before send() can yield or queue DATA behind another frame.
        remote_window_size -= send_len;
        stream->remote_window_size -= static_cast<int32_t>(send_len);
        Http2::set_frame_header(header, SW_HTTP2_TYPE_DATA, send_len, send_flag, _stream_id);
        swoole_trace_log(SW_TRACE_HTTP2,
                         "send [" SW_ECHO_YELLOW "] stream_id=%u, flags=%d, send_n=%u",
                         "DATA",
                         _stream_id,
                         send_flag,
                         send_len);
        // Frames queued while the header waits must not be sent before its payload.
        if (!send(header, SW_HTTP2_FRAME_HEADER_SIZE, false)) {
            return false;
        }
        if (!send(p, send_len)) {
            return false;
        }
        len -= send_len;
        p += send_len;
    }
    return !upload.reset_received;
}

/**
 * called in write channel
 */
uint32_t Client::send_request(zval *zrequest) {
    if (!can_open_stream()) {
        return 0;
    }
    auto *socket = socket_;

    zval *zheaders =
        sw_zend_read_and_convert_property_array(swoole_http2_request_ce, zrequest, ZEND_STRL("headers"), 0);
    zval *zdata = sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_DATA), 0);
    zval *zpipeline =
        sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_PIPELINE), 0);
    zval ztmp, *zuse_pipeline_read = zend_read_property_ex(
                   Z_OBJCE_P(zrequest), Z_OBJ_P(zrequest), SW_ZSTR_KNOWN(SW_ZEND_STR_USE_PIPELINE_READ), true, &ztmp);
    bool is_data_empty = Z_TYPE_P(zdata) == IS_STRING ? Z_STRLEN_P(zdata) == 0 : !zval_is_true(zdata);

    if (ZVAL_IS_ARRAY(zdata)) {
        add_assoc_stringl_ex(
            zheaders, ZEND_STRL("content-type"), (char *) ZEND_STRL("application/x-www-form-urlencoded"));
    }

    uint8_t flags = 0;
    if (zval_is_true(zpipeline)) {
        flags |= SW_HTTP2_STREAM_PIPELINE_REQUEST;
    }
    if (zval_is_true(zuse_pipeline_read)) {
        flags |= SW_HTTP2_STREAM_USE_PIPELINE_READ;
    }

#ifdef SW_HAVE_ZLIB
    // Capture the method before header value conversions can run PHP code and mutate the request.
    zval *zmethod = sw_zend_read_property_ex(swoole_http2_request_ce, zrequest, SW_ZSTR_KNOWN(SW_ZEND_STR_METHOD), 0);
    const bool request_is_head = ZVAL_IS_STRING(zmethod) && SW_STREQ(Z_STRVAL_P(zmethod), Z_STRLEN_P(zmethod), "HEAD");
#endif
    String *buffer;
    ssize_t bytes = build_header(zrequest, socket, buffer);
    if (sw_unlikely(bytes < 0)) {
        return 0;
    }

    // Reserve the id before sending: other coroutines can send while send() waits. A concurrent recv() can also delete
    // the stream meanwhile, so only its id is used after this.
    uint32_t _stream_id = stream_id;
    bool pipeline = flags & SW_HTTP2_STREAM_PIPELINE_REQUEST;
    auto *stream = create_stream(_stream_id, flags);
#ifdef SW_HAVE_ZLIB
    stream->request_is_head = request_is_head;
#endif
    Upload upload(*this, stream);
    stream_id += 2;

    flags = SW_HTTP2_FLAG_END_HEADERS;

    if (is_data_empty && !pipeline) {
        flags |= SW_HTTP2_FLAG_END_STREAM;
    }

    Http2::set_frame_header(buffer->str, SW_HTTP2_TYPE_HEADERS, bytes, flags, _stream_id);

    swoole_http2_send_trace_log(
        "[" SW_ECHO_GREEN ", STREAM#%d] length=%zd", Http2::get_type(SW_HTTP2_TYPE_HEADERS), _stream_id, bytes);
    if (!send(buffer->str, buffer->length)) {
        return 0;
    }
    if (flags & SW_HTTP2_FLAG_END_STREAM) {
        finish_request(upload);
    }

    /**
     * send body
     */
    if (!is_data_empty) {
        char *p;
        size_t len;
        smart_str formstr_s = {};
        zend::String str_zpost_data;

        int flag = pipeline ? 0 : SW_HTTP2_FLAG_END_STREAM;
        if (ZVAL_IS_ARRAY(zdata)) {
            p = php_swoole_http_build_query(zdata, &len, &formstr_s);
            if (p == nullptr) {
                php_swoole_error(E_WARNING, "http_build_query failed");
                return 0;
            }
        } else {
            str_zpost_data = zdata;
            p = str_zpost_data.val();
            len = str_zpost_data.len();
        }

        swoole_http2_send_trace_log(
            "[" SW_ECHO_GREEN ", END, STREAM#%d] length=%zu", Http2::get_type(SW_HTTP2_TYPE_DATA), _stream_id, len);

        bool sent = send_data(upload, p, len, flag);
        smart_str_free(&formstr_s);
        if (!sent) {
            if (upload.completed_by_peer) {
                return _stream_id;
            }
            if (upload.reset_received) {
                upload.report_reset();
            }
            return 0;
        }
        if (flag & SW_HTTP2_FLAG_END_STREAM) {
            finish_request(upload);
        }
    }

    return _stream_id;
}

/**
 * called in write channel
 */
bool Client::write_data(uint32_t _stream_id, zval *zdata, bool end) {
    Stream *stream = get_stream(_stream_id);
    int flag = end ? SW_HTTP2_FLAG_END_STREAM : 0;

    if (stream == nullptr || !(stream->flags & SW_HTTP2_STREAM_PIPELINE_REQUEST) ||
        (stream->flags & SW_HTTP2_STREAM_REQUEST_END)) {
        update_error_properties(EINVAL,
                                std_string::format("unable to found active pipeline stream#%u", _stream_id).c_str());
        return false;
    }
    if (stream->upload) {
        update_error_properties(EBUSY, "another write is pending on this HTTP/2 stream");
        return false;
    }

    if (!check_send_queue()) {
        return false;
    }
    Upload upload(*this, stream);

    bool sent;
    if (ZVAL_IS_ARRAY(zdata)) {
        size_t len;
        smart_str formstr_s = {};
        char *formstr = php_swoole_http_build_query(zdata, &len, &formstr_s);
        if (formstr == nullptr) {
            php_swoole_error(E_WARNING, "http_build_query failed");
            return false;
        }
        swoole_trace_log(SW_TRACE_HTTP2,
                         "[" SW_ECHO_GREEN ",%s STREAM#%d] length=%zu",
                         Http2::get_type(SW_HTTP2_TYPE_DATA),
                         end ? " END," : "",
                         stream_id,
                         len);
        sent = send_data(upload, formstr, len, flag);
        smart_str_free(&formstr_s);
    } else {
        zend::String data(zdata);
        swoole_trace_log(SW_TRACE_HTTP2,
                         "[" SW_ECHO_GREEN ",%s STREAM#%d] length=%zu",
                         Http2::get_type(SW_HTTP2_TYPE_DATA),
                         end ? " END," : "",
                         stream_id,
                         data.len());
        sent = send_data(upload, data.val(), data.len(), flag);
    }

    if (!sent) {
        if (upload.reset_received) {
            upload.report_reset();
        }
        return false;
    }
    if (end) {
        finish_request(upload);
    }

    return true;
}

/**
 * called in write channel
 */
bool Client::send_goaway_frame(zend_long error_code, const char *debug_data, size_t debug_data_len) {
    // Validate before allocating or writing so a rejected call leaves the connection usable.
    if (debug_data_len > remote_settings.max_frame_size - SW_HTTP2_GOAWAY_SIZE) {
        php_swoole_error(E_WARNING, "GOAWAY debug data exceeds the peer's maximum frame size");
        return false;
    }
    size_t length = SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + debug_data_len;
    auto frame = (char *) ecalloc(1, length);
    Http2::set_frame_header(frame, SW_HTTP2_TYPE_GOAWAY, SW_HTTP2_GOAWAY_SIZE + debug_data_len, SW_HTTP2_FLAG_NONE, 0);
    *(uint32_t *) (frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(last_stream_id);
    *(uint32_t *) (frame + SW_HTTP2_FRAME_HEADER_SIZE + 4) = htonl(error_code);
    if (debug_data_len > 0) {
        memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE, debug_data, debug_data_len);
    }
    swoole_http2_send_trace_log("[" SW_ECHO_RED "] last-sid=%u, error-code=" ZEND_LONG_FMT,
                                Http2::get_type(SW_HTTP2_TYPE_GOAWAY),
                                last_stream_id,
                                error_code);
    bool ret = send(frame, length);
    efree(frame);
    return ret;
}

static PHP_METHOD(swoole_http2_client_coro, send) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);

    if (!h2c->is_available()) {
        RETURN_FALSE;
    }

    zval *zrequest;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_OBJECT_OF_CLASS(zrequest, swoole_http2_request_ce)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CLIENT_PRESERVE_SOCKET(&h2c->zsocket);

    uint32_t stream_id = h2c->send_request(zrequest);
    if (stream_id == 0) {
        RETURN_FALSE;
    } else {
        RETURN_LONG(stream_id);
    }
}

static void http2_client_coro_recv(INTERNAL_FUNCTION_PARAMETERS, bool pipeline_read) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (h2c->pop_pending_response(return_value)) {
        return;
    }
    // Preserve the disconnect error once the queued responses have been delivered.
    if (h2c->has_deferred_disconnect_error() || !h2c->is_available()) {
        RETURN_FALSE;
    }
    auto *socket = h2c->socket_;
    SW_CLIENT_PRESERVE_SOCKET(&h2c->zsocket);

    while (true) {
        ReturnCode ret = h2c->receive_frame(socket, timeout, return_value, pipeline_read);
        if (ret == SW_CONTINUE) {
            continue;
        } else if (ret == SW_READY) {
            break;
        } else {
            RETURN_FALSE;
        }
    }
}

static PHP_METHOD(swoole_http2_client_coro, recv) {
    http2_client_coro_recv(INTERNAL_FUNCTION_PARAM_PASSTHRU, false);
}

static PHP_METHOD(swoole_http2_client_coro, __destruct) {}

static PHP_METHOD(swoole_http2_client_coro, close) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    SW_CLIENT_PRESERVE_SOCKET(&h2c->zsocket);
    RETURN_BOOL(h2c->request_close());
}

static PHP_METHOD(swoole_http2_client_coro, connect) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    RETURN_BOOL(h2c->connect());
}

static sw_inline void http2_client_settings_to_array(const Http2::Settings *settings, zval *zarray) {
    array_init(zarray);
    add_assoc_long_ex(zarray, ZEND_STRL("header_table_size"), settings->header_table_size);
    add_assoc_long_ex(zarray, ZEND_STRL("init_window_size"), settings->init_window_size);
    add_assoc_long_ex(zarray, ZEND_STRL("max_concurrent_streams"), settings->max_concurrent_streams);
    add_assoc_long_ex(zarray, ZEND_STRL("max_frame_size"), settings->max_frame_size);
    add_assoc_long_ex(zarray, ZEND_STRL("max_header_list_size"), settings->max_header_list_size);
}

static PHP_METHOD(swoole_http2_client_coro, stats) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    zval _zarray, *zarray = &_zarray;
    String key = {};

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(key.str, key.length);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (key.length > 0) {
        if (SW_STREQ(key.str, key.length, "current_stream_id")) {
            RETURN_LONG(h2c->stream_id);
        } else if (SW_STREQ(key.str, key.length, "last_stream_id")) {
            RETURN_LONG(h2c->last_stream_id);
        } else if (SW_STREQ(key.str, key.length, "local_settings")) {
            http2_client_settings_to_array(&h2c->local_settings, zarray);
            RETURN_ZVAL(zarray, 0, 0);
        } else if (SW_STREQ(key.str, key.length, "remote_settings")) {
            http2_client_settings_to_array(&h2c->remote_settings, zarray);
            RETURN_ZVAL(zarray, 0, 0);
        } else if (SW_STREQ(key.str, key.length, "active_stream_num")) {
            RETURN_LONG(h2c->streams.size());
        }
    } else {
        array_init(return_value);
        add_assoc_long_ex(return_value, ZEND_STRL("current_stream_id"), h2c->stream_id);
        add_assoc_long_ex(return_value, ZEND_STRL("last_stream_id"), h2c->last_stream_id);
        http2_client_settings_to_array(&h2c->local_settings, zarray);
        add_assoc_zval_ex(return_value, ZEND_STRL("local_settings"), zarray);
        http2_client_settings_to_array(&h2c->remote_settings, zarray);
        add_assoc_zval_ex(return_value, ZEND_STRL("remote_settings"), zarray);
        add_assoc_long_ex(return_value, ZEND_STRL("active_stream_num"), h2c->streams.size());
    }
}

static PHP_METHOD(swoole_http2_client_coro, isStreamExist) {
    zend_long stream_id = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(stream_id)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (stream_id < 0) {
        RETURN_FALSE;
    }

    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    if (!h2c->socket_) {
        RETURN_FALSE;
    } else if (stream_id == 0) {
        RETURN_TRUE;
    }
    Stream *stream = h2c->get_stream(stream_id);
    RETURN_BOOL(stream ? 1 : 0);
}

static PHP_METHOD(swoole_http2_client_coro, write) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);

    if (!h2c->is_available()) {
        RETURN_FALSE;
    }

    zend_long stream_id;
    zval *data;
    zend_bool end = false;

    ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_LONG(stream_id);
    Z_PARAM_ZVAL(data);
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(end);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (stream_id < 0) {
        RETURN_FALSE;
    }

    SW_CLIENT_PRESERVE_SOCKET(&h2c->zsocket);

    RETURN_BOOL(h2c->write_data(stream_id, data, end));
}

static PHP_METHOD(swoole_http2_client_coro, read) {
    http2_client_coro_recv(INTERNAL_FUNCTION_PARAM_PASSTHRU, true);
}

static PHP_METHOD(swoole_http2_client_coro, ping) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);

    if (!h2c->is_available()) {
        RETURN_FALSE;
    }

    SW_CLIENT_PRESERVE_SOCKET(&h2c->zsocket);
    RETURN_BOOL(h2c->send_ping_frame());
}

/**
 * +-+-------------------------------------------------------------+
 * |R|                  Last-Stream-ID (31)                        |
 * +-+-------------------------------------------------------------+
 * |                      Error Code (32)                          |
 * +---------------------------------------------------------------+
 * |                  Additional Debug Data (*)                    |
 * +---------------------------------------------------------------+
 */
static PHP_METHOD(swoole_http2_client_coro, goaway) {
    Client *h2c = http2_client_coro_get_client(ZEND_THIS);
    zend_long error_code = SW_HTTP2_ERROR_NO_ERROR;
    char *debug_data = nullptr;
    size_t debug_data_len = 0;

    if (!h2c->is_available()) {
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(error_code);
    Z_PARAM_STRING(debug_data, debug_data_len);
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    SW_CLIENT_PRESERVE_SOCKET(&h2c->zsocket);
    RETURN_BOOL(h2c->send_goaway_frame(error_code, debug_data, debug_data_len));
}
