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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"
#include "swoole_http.h"

#ifdef SW_USE_HTTP2

#include "http.h"
#include "http2.h"

#define HTTP2_CLIENT_HOST_HEADER_INDEX   3

#include <vector>

using namespace swoole;
using swoole::coroutine::Socket;

static zend_class_entry *swoole_http2_client_coro_ce;
static zend_object_handlers swoole_http2_client_coro_handlers;

static zend_class_entry *swoole_http2_client_coro_exception_ce;
static zend_object_handlers swoole_http2_client_coro_exception_handlers;

static zend_class_entry *swoole_http2_request_ce;
static zend_object_handlers swoole_http2_request_handlers;

static zend_class_entry *swoole_http2_response_ce;
static zend_object_handlers swoole_http2_response_handlers;

struct http2_client_stream
{
    uint32_t stream_id;
    uint8_t gzip;
    uint8_t type;
    swString *buffer;
#ifdef SW_HAVE_ZLIB
    z_stream gzip_stream;
    swString *gzip_buffer;
#endif
    zval *zresponse;
    zval _zresponse;

    // flow control
    uint32_t remote_window_size;
    uint32_t local_window_size;
};

class http2_client
{
public:
    std::string host;
    int port;
    bool ssl;
    double timeout = Socket::default_read_timeout;

    Socket *client = nullptr;

    nghttp2_hd_inflater *inflater = nullptr;
    nghttp2_hd_deflater *deflater = nullptr;

    uint32_t stream_id = 0; // the next send stream id
    uint32_t last_stream_id = 0; // the last received stream id

    swHttp2_settings local_settings = {0};
    swHttp2_settings remote_settings = {0};

    swHashMap *streams = nullptr;

    /* safety zval */
    zval _zobject;
    zval *zobject;

    http2_client(const char *_host, size_t _host_len, int _port, bool _ssl, zval *__zobject)
    {
        host = std::string(_host, _host_len);
        port = _port;
        ssl = _ssl;
        _zobject = *__zobject;
        zobject = &_zobject;
    }

    inline http2_client_stream* get_stream(uint32_t stream_id)
    {
        return (http2_client_stream*) swHashMap_find_int(streams, stream_id);
    }

    inline void update_error_properties(int code, const char *msg)
    {
        zend_update_property_long(swoole_http2_client_coro_ce, zobject, ZEND_STRL("errCode"), code);
        zend_update_property_string(swoole_http2_client_coro_ce, zobject, ZEND_STRL("errMsg"), msg);
    }

    inline void io_error()
    {
        update_error_properties(client->errCode, client->errMsg);
    }

    inline void nghttp2_error(int code, const char *msg)
    {
        update_error_properties(code, cpp_string::format("%s with error: %s", msg, nghttp2_strerror(code)).c_str());
    }

    inline bool is_available()
    {
        if (sw_unlikely(!client))
        {
            SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
            zend_update_property_long(swoole_http2_client_coro_ce, zobject, ZEND_STRL("errCode"), ECONNRESET);
            zend_update_property_string(swoole_http2_client_coro_ce, zobject, ZEND_STRL("errMsg"), "client is not connected to server");
            return false;
        }
        return true;
    }

    inline void apply_setting(zval *zset)
    {
        if (client && ZVAL_IS_ARRAY(zset))
        {
            php_swoole_client_set(client, zset);
        }
    }

    inline bool recv_packet(double timeout)
    {
        if (sw_unlikely(client->recv_packet(timeout) <= 0))
        {
            io_error();
            return false;
        }
        return true;
    }

    bool connect();
    http2_client_stream* create_stream(uint32_t stream_id, bool pipeline);
    bool send_window_update(int stream_id, uint32_t size);
    bool send_ping_frame();
    bool send_data(uint32_t stream_id, zval *data, bool end);
    uint32_t send_request(zval *req);
    bool send_goaway_frame(zend_long error_code, const char *debug_data, size_t debug_data_len);
    enum swReturn_code parse_frame(zval *return_value);
    bool close();

    ~http2_client()
    {
        close();
    }
private:
    bool send_setting();
    int parse_header(http2_client_stream *stream , int flags, char *in, size_t inlen);

    inline bool send(const char *buf, size_t len)
    {
        if (sw_unlikely(client->send_all(buf, len) != (ssize_t )len))
        {
            io_error();
            return false;
        }
        return true;
    }
};

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_stats, 0, 0, 0)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_isStreamExist, 0, 0, 1)
    ZEND_ARG_INFO(0, stream_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_send, 0, 0, 1)
    ZEND_ARG_INFO(0, request)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_write, 0, 0, 2)
    ZEND_ARG_INFO(0, stream_id)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, end_stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http2_client_coro_goaway, 0, 0, 0)
    ZEND_ARG_INFO(0, error_code)
    ZEND_ARG_INFO(0, debug_data)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_http2_client_coro, __construct);
static PHP_METHOD(swoole_http2_client_coro, __destruct);
static PHP_METHOD(swoole_http2_client_coro, set);
static PHP_METHOD(swoole_http2_client_coro, connect);
static PHP_METHOD(swoole_http2_client_coro, stats);
static PHP_METHOD(swoole_http2_client_coro, isStreamExist);
static PHP_METHOD(swoole_http2_client_coro, send);
static PHP_METHOD(swoole_http2_client_coro, write);
static PHP_METHOD(swoole_http2_client_coro, recv);
static PHP_METHOD(swoole_http2_client_coro, ping);
static PHP_METHOD(swoole_http2_client_coro, goaway);
static PHP_METHOD(swoole_http2_client_coro, close);

static void http2_client_stream_free(void *ptr);

static const zend_function_entry swoole_http2_client_methods[] =
{
    PHP_ME(swoole_http2_client_coro, __construct,   arginfo_swoole_http2_client_coro_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, __destruct,    arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, set,           arginfo_swoole_http2_client_coro_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, connect,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, stats,         arginfo_swoole_http2_client_coro_stats, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, isStreamExist, arginfo_swoole_http2_client_coro_isStreamExist, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, send,          arginfo_swoole_http2_client_coro_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, write,         arginfo_swoole_http2_client_coro_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, recv,          arginfo_swoole_http2_client_coro_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, goaway,        arginfo_swoole_http2_client_coro_goaway, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, ping,          arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http2_client_coro, close,         arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_http2_client_coro_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_http2_client_coro, "Swoole\\Coroutine\\Http2\\Client", NULL, "Co\\Http2\\Client", swoole_http2_client_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_http2_client_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http2_client_coro, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http2_client_coro, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http2_client_coro);

    SW_INIT_CLASS_ENTRY_EX(swoole_http2_client_coro_exception, "Swoole\\Coroutine\\Http2\\Client\\Exception", NULL, "Co\\Http2\\Client\\Exception", NULL, swoole_exception);

    SW_INIT_CLASS_ENTRY(swoole_http2_request, "Swoole\\Http2\\Request", "swoole_http2_request", NULL, NULL);
    SW_SET_CLASS_SERIALIZABLE(swoole_http2_request, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http2_request, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http2_request, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http2_request);

    SW_INIT_CLASS_ENTRY(swoole_http2_response, "Swoole\\Http2\\Response", "swoole_http2_response", NULL, NULL);
    SW_SET_CLASS_SERIALIZABLE(swoole_http2_response, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_http2_response, sw_zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_http2_response, sw_zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_WITH_ITS_OWN_HANDLERS(swoole_http2_response);

    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("errMsg"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("type"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_client_coro_ce, ZEND_STRL("setting"), ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_client_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_client_coro_ce, ZEND_STRL("host"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_client_coro_ce, ZEND_STRL("port"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_client_coro_ce, ZEND_STRL("ssl"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_string(swoole_http2_request_ce, ZEND_STRL("path"), "/", ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http2_request_ce, ZEND_STRL("method"), "GET", ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_request_ce, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_request_ce, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_http2_request_ce, ZEND_STRL("data"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_request_ce, ZEND_STRL("pipeline"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_long(swoole_http2_response_ce, ZEND_STRL("streamId"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_response_ce, ZEND_STRL("errCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_http2_response_ce, ZEND_STRL("statusCode"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_http2_response_ce, ZEND_STRL("pipeline"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("set_cookie_headers"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("cookies"), ZEND_ACC_PUBLIC);
    zend_declare_property_null(swoole_http2_response_ce, ZEND_STRL("data"), ZEND_ACC_PUBLIC);

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
}

bool http2_client::connect()
{
    if (sw_unlikely(client != nullptr))
    {
        return false;
    }

    client = new Socket(SW_SOCK_TCP);

    client->http2 = 1;
    client->open_length_check = 1;
    client->protocol.get_package_length = swHttp2_get_frame_length;
    client->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
    client->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;

    apply_setting(sw_zend_read_property(swoole_http2_client_coro_ce, zobject, ZEND_STRL("setting"), 0));

#ifdef SW_USE_OPENSSL
    client->open_ssl = ssl;
#endif
    if (!client->connect(host, port))
    {
        io_error();
        close();
        return false;
    }

    stream_id = 1;
    streams = swHashMap_new(8, http2_client_stream_free);
    // [init]: we must set default value, server is not always send all the settings
    swHttp2_init_settings(&local_settings);
    swHttp2_init_settings(&remote_settings);
    int ret = nghttp2_hd_inflate_new(&inflater);
    if (ret != 0)
    {
        nghttp2_error(ret, "nghttp2_hd_inflate_new() failed");
        close();
        return false;
    }
    ret = nghttp2_hd_deflate_new(&deflater, local_settings.header_table_size);
    if (ret != 0)
    {
        nghttp2_error(ret, "nghttp2_hd_deflate_new() failed");
        close();
        return false;
    }

    if (!send(ZEND_STRL(SW_HTTP2_PRI_STRING)))
    {
        close();
        return false;
    }

    if (!send_setting())
    {
        close();
        return false;
    }

    zend_update_property_bool(swoole_http2_client_coro_ce, zobject, ZEND_STRL("connected"), 1);

    return true;
}

bool http2_client::close()
{
    Socket *_client = client;
    if (!_client)
    {
        return false;
    }
    zend_update_property_bool(swoole_http2_client_coro_ce, zobject, ZEND_STRL("connected"), 0);
    if (!_client->has_bound())
    {
        if (streams)
        {
            swHashMap_free(streams);
            streams = NULL;
        }
        if (inflater)
        {
            nghttp2_hd_inflate_del(inflater);
            inflater = NULL;
        }
        if (deflater)
        {
            nghttp2_hd_deflate_del(deflater);
            deflater = NULL;
        }
        client = nullptr;
    }
    if (_client->close())
    {
        delete _client;
    }
    return true;
}

enum swReturn_code http2_client::parse_frame(zval *return_value)
{
    char *buf = client->get_read_buffer()->str;
    uint8_t type = buf[3];
    uint8_t flags = buf[4];
    uint32_t stream_id = ntohl((*(int *) (buf + 5))) & 0x7fffffff;
    ssize_t length = swHttp2_get_length(buf);
    buf += SW_HTTP2_FRAME_HEADER_SIZE;

    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];

    if (stream_id > last_stream_id)
    {
        last_stream_id = stream_id;
    }

    uint16_t id = 0;
    uint32_t value = 0;

    switch (type)
    {
    case SW_HTTP2_TYPE_SETTINGS:
    {
        if (flags & SW_HTTP2_FLAG_ACK)
        {
            swHttp2FrameTraceLog(recv, "ACK");
            return SW_CONTINUE;
        }

        while (length > 0)
        {
            id = ntohs(*(uint16_t *) (buf));
            value = ntohl(*(uint32_t *) (buf + sizeof(uint16_t)));
            swHttp2FrameTraceLog(recv, "id=%d, value=%d", id, value);
            switch (id)
            {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                if (value != remote_settings.header_table_size)
                {
                    remote_settings.header_table_size = value;
                    int ret = nghttp2_hd_deflate_change_table_size(deflater, value);
                    if (ret != 0)
                    {
                        nghttp2_error(ret, "nghttp2_hd_deflate_change_table_size() failed");
                        return SW_ERROR;
                    }
                }
                swTraceLog(SW_TRACE_HTTP2, "setting: header_compression_table_max=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                remote_settings.max_concurrent_streams = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_concurrent_streams=%u", value);
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                remote_settings.window_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: init_send_window=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                remote_settings.max_frame_size = value;
                swTraceLog(SW_TRACE_HTTP2, "setting: max_frame_size=%u", value);
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                if (value != remote_settings.max_header_list_size)
                {
                    remote_settings.max_header_list_size = value;
                    int ret = nghttp2_hd_inflate_change_table_size(inflater, value);
                    if (ret != 0)
                    {
                        nghttp2_error(ret, "nghttp2_hd_inflate_change_table_size() failed");
                        return SW_ERROR;
                    }
                }
                swTraceLog(SW_TRACE_HTTP2, "setting: max_header_list_size=%u", value);
                break;
            default:
                // disable warning and ignore it because some websites are not following http2 protocol totally
                // swWarn("unknown option[%d]: %d", id, value);
                break;
            }
            buf += sizeof(id) + sizeof(value);
            length -= sizeof(id) + sizeof(value);
        }

        swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 0, SW_HTTP2_FLAG_ACK, stream_id);
        if (!send(frame, SW_HTTP2_FRAME_HEADER_SIZE))
        {
            return SW_ERROR;
        }
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_WINDOW_UPDATE:
    {
        value = ntohl(*(uint32_t *) buf);
        swHttp2FrameTraceLog(recv, "window_size_increment=%d", value);
        if (stream_id == 0)
        {
            remote_settings.window_size += value;
        }
        else
        {
            http2_client_stream *stream = get_stream(stream_id);
            if (stream)
            {
                stream->remote_window_size += value;
            }
        }
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_PING:
    {
        swHttp2FrameTraceLog(recv, "ping");
        if (!(flags & SW_HTTP2_FLAG_ACK))
        {
            swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_ACK, stream_id);
            memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE, buf + SW_HTTP2_FRAME_HEADER_SIZE, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
            if (!send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE))
            {
                return SW_ERROR;
            }
        }
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_GOAWAY:
    {
        uint32_t server_last_stream_id = ntohl(*(uint32_t *) (buf));
        buf += 4;
        value = ntohl(*(uint32_t *) (buf));
        buf += 4;
        swHttp2FrameTraceLog(recv, "last_stream_id=%d, error_code=%d, opaque_data=[%.*s]", server_last_stream_id, value, (int) (length - SW_HTTP2_GOAWAY_SIZE), buf);

        // update goaway error code and error msg
        zend_update_property_long(swoole_http2_client_coro_ce, zobject, ZEND_STRL("errCode"), value);
        zend_update_property_stringl(swoole_http2_client_coro_ce, zobject, ZEND_STRL("errMsg"), buf, length - SW_HTTP2_GOAWAY_SIZE);
        zend_update_property_long(swoole_http2_client_coro_ce, zobject, ZEND_STRL("serverLastStreamId"), server_last_stream_id);
        close();
        return SW_CONTINUE;
    }
    case SW_HTTP2_TYPE_RST_STREAM:
    {
        value = ntohl(*(uint32_t *) (buf));
        swHttp2FrameTraceLog(recv, "error_code=%d", value);

        // delete and free quietly
        swHashMap_del_int(streams, stream_id);
        return SW_CONTINUE;
    }
    /**
     * TODO not support push_promise
     */
    case SW_HTTP2_TYPE_PUSH_PROMISE:
    {
#ifdef SW_DEBUG
        uint32_t promise_stream_id = ntohl(*(uint32_t *) (buf)) & 0x7fffffff;
        swHttp2FrameTraceLog(recv, "promise_stream_id=%d", promise_stream_id);
#endif
        // auto promise_stream = create_stream(promise_stream_id, false);
        // RETVAL_ZVAL(promise_stream->response_object, 0, 0);
        // return SW_READY;
        return SW_CONTINUE;
    }
    default:
    {
        swHttp2FrameTraceLog(recv, "");
    }
    }

    http2_client_stream *stream = get_stream(stream_id);
    // The stream is not found or has closed
    if (stream == NULL)
    {
        swNotice("http2 stream#%d belongs to an unknown type or it never registered", stream_id);
        return SW_CONTINUE;
    }
    if (type == SW_HTTP2_TYPE_HEADERS)
    {
        parse_header(stream, flags, buf, length);
    }
    else if (type == SW_HTTP2_TYPE_DATA)
    {
        if (length > 0)
        {
            if (!stream->buffer)
            {
                stream->buffer = swString_new(SW_HTTP2_DATA_BUFFER_SIZE);
            }
#ifdef SW_HAVE_ZLIB
            if (stream->gzip)
            {
                if (php_swoole_zlib_uncompress(&stream->gzip_stream, stream->gzip_buffer, buf, length) == SW_ERR)
                {
                    swWarn("uncompress failed");
                    return SW_ERROR;
                }
                swString_append_ptr(stream->buffer, stream->gzip_buffer->str, stream->gzip_buffer->length);
            }
            else
#endif
            {
                swString_append_ptr(stream->buffer, buf, length);
            }

            // now we control the connection flow only (not stream)
            // our window size is unlimited, so we don't worry about subtraction overflow
            local_settings.window_size -= length;
            stream->local_window_size -= length;
            if (local_settings.window_size < (SW_HTTP2_MAX_WINDOW_SIZE / 4))
            {
                if (!send_window_update(0, SW_HTTP2_MAX_WINDOW_SIZE - local_settings.window_size))
                {
                    return SW_ERROR;
                }
                local_settings.window_size = SW_HTTP2_MAX_WINDOW_SIZE;
            }
            if (stream->local_window_size < (SW_HTTP2_MAX_WINDOW_SIZE / 4))
            {
                if (!send_window_update(stream_id, SW_HTTP2_MAX_WINDOW_SIZE - stream->local_window_size))
                {
                    return SW_ERROR;
                }
                stream->local_window_size = SW_HTTP2_MAX_WINDOW_SIZE;
            }
        }
    }

    uint8_t stream_type = stream->type;
    if (
        (type == SW_HTTP2_TYPE_DATA && stream_type == SW_HTTP2_STREAM_PIPELINE) ||       // pipeline data frame
        (stream_type == SW_HTTP2_STREAM_NORMAL && (flags & SW_HTTP2_FLAG_END_STREAM)) || // normal end frame
        type == SW_HTTP2_TYPE_RST_STREAM || type == SW_HTTP2_TYPE_GOAWAY                 // rst or goaway frame
    )
    {
        zval zresponse = *stream->zresponse;

        if (type == SW_HTTP2_TYPE_RST_STREAM)
        {
            zend_update_property_long(swoole_http2_response_ce, &zresponse, ZEND_STRL("statusCode"), -3);
            zend_update_property_long(swoole_http2_response_ce, &zresponse, ZEND_STRL("errCode"), value);
        }
        else if (stream_type == SW_HTTP2_STREAM_PIPELINE && !(flags & SW_HTTP2_FLAG_END_STREAM))
        {
            zend_update_property_bool(swoole_http2_response_ce, &zresponse, ZEND_STRL("pipeline"), 1);
        }

        if (stream->buffer)
        {
            zend_update_property_stringl(swoole_http2_response_ce, stream->zresponse, ZEND_STRL("data"), stream->buffer->str, stream->buffer->length);
            swString_clear(stream->buffer);
        }

        Z_ADDREF_P(&zresponse);
        swHashMap_del_int(streams, stream_id);
        RETVAL_ZVAL(&zresponse, 0, 0);
        return SW_READY;
    }

    return SW_CONTINUE;
}

#ifdef SW_HAVE_ZLIB
int php_swoole_zlib_uncompress(z_stream *stream, swString *buffer, char *body, int length)
{
    int status = 0;

    stream->avail_in = length;
    stream->next_in = (Bytef *) body;
    stream->total_in = 0;
    stream->total_out = 0;

#if 0
    printf(SW_START_LINE"\nstatus=%d\tavail_in=%ld,\tavail_out=%ld,\ttotal_in=%ld,\ttotal_out=%ld\n", status,
            stream->avail_in, stream->avail_out, stream->total_in, stream->total_out);
#endif

    swString_clear(buffer);

    while (1)
    {
        stream->avail_out = buffer->size - buffer->length;
        stream->next_out = (Bytef *) (buffer->str + buffer->length);

        status = inflate(stream, Z_SYNC_FLUSH);

#if 0
        printf("status=%d\tavail_in=%ld,\tavail_out=%ld,\ttotal_in=%ld,\ttotal_out=%ld,\tlength=%ld\n", status,
                stream->avail_in, stream->avail_out, stream->total_in, stream->total_out, buffer->length);
#endif
        if (status >= 0)
        {
            buffer->length = stream->total_out;
        }
        if (status == Z_STREAM_END)
        {
            return SW_OK;
        }
        else if (status == Z_OK)
        {
            if (buffer->length + 4096 >= buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    return SW_ERR;
                }
            }
            if (stream->avail_in == 0)
            {
                return SW_OK;
            }
        }
        else
        {
            return SW_ERR;
        }
    }
    return SW_ERR;
}
#endif

static PHP_METHOD(swoole_http2_client_coro, __construct)
{
    char *host;
    size_t host_len;
    zend_long port = 80;
    zend_bool ssl = SW_FALSE;

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 3)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(port)
        Z_PARAM_BOOL(ssl)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (host_len == 0)
    {
        zend_throw_exception(swoole_http2_client_coro_exception_ce, "host is empty", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }

    http2_client *h2c = new http2_client(host, host_len, port, ssl, ZEND_THIS);
    if (ssl)
    {
#ifndef SW_USE_OPENSSL
        zend_throw_exception_ex(
            swoole_http2_client_coro_exception_ce,
            EPROTONOSUPPORT, "you must configure with `enable-openssl` to support ssl connection"
        );
        delete h2c;
        RETURN_FALSE;
#endif
    }

    swoole_set_object(ZEND_THIS, h2c);

    zend_update_property_stringl(swoole_http2_client_coro_ce, ZEND_THIS, ZEND_STRL("host"), host, host_len);
    zend_update_property_long(swoole_http2_client_coro_ce, ZEND_THIS, ZEND_STRL("port"), port);
    zend_update_property_bool(swoole_http2_client_coro_ce, ZEND_THIS, ZEND_STRL("ssl"), ssl);
}

static PHP_METHOD(swoole_http2_client_coro, set)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    zval *zset;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval *zsetting = sw_zend_read_and_convert_property_array(swoole_http2_client_coro_ce, ZEND_THIS, ZEND_STRL("setting"), 0);
    php_array_merge(Z_ARRVAL_P(zsetting), Z_ARRVAL_P(zset));

    h2c->apply_setting(zset);

    RETURN_TRUE;
}

bool http2_client::send_window_update(int stream_id, uint32_t size)
{
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE];
    swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_YELLOW "] stream_id=%d, size=%d", "WINDOW_UPDATE", stream_id, size);
    *(uint32_t*) ((char *)frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(size);
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_WINDOW_UPDATE, SW_HTTP2_WINDOW_UPDATE_SIZE, 0, stream_id);
    return send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_WINDOW_UPDATE_SIZE);
}

bool http2_client::send_setting()
{
    swHttp2_settings *settings = &local_settings;
    uint16_t id = 0;
    uint32_t value = 0;

    char frame[SW_HTTP2_FRAME_HEADER_SIZE + 18];
    memset(frame, 0, sizeof(frame));
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_SETTINGS, 18, 0, 0);

    char *p = frame + SW_HTTP2_FRAME_HEADER_SIZE;
    /**
     * MAX_CONCURRENT_STREAMS
     */
    id = htons(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(settings->max_concurrent_streams);
    memcpy(p, &value, sizeof(value));
    p += 4;
    /**
     * MAX_FRAME_SIZE
     */
    id = htons(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(settings->max_frame_size);
    memcpy(p, &value, sizeof(value));
    p += 4;
    /**
     * INIT_WINDOW_SIZE
     */
    id = htons(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE);
    memcpy(p, &id, sizeof(id));
    p += 2;
    value = htonl(settings->window_size);
    memcpy(p, &value, sizeof(value));
    p += 4;

    swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN "]\t[length=%d]", swHttp2_get_type(SW_HTTP2_TYPE_SETTINGS), 18);
    return send(frame, SW_HTTP2_FRAME_HEADER_SIZE + 18);
}

int http2_client::parse_header(http2_client_stream *stream, int flags, char *in, size_t inlen)
{
    zval *zresponse = stream->zresponse;

    if (flags & SW_HTTP2_FLAG_PRIORITY)
    {
        //int stream_deps = ntohl(*(int *) (in));
        //uint8_t weight = in[4];
        in += 5;
        inlen -= 5;
    }

    zval *zheaders = sw_zend_read_and_convert_property_array(swoole_http2_response_ce, zresponse, ZEND_STRL("headers"), 0);
    zval *zcookies = sw_zend_read_and_convert_property_array(swoole_http2_response_ce, zresponse, ZEND_STRL("cookies"), 0);
    zval *zset_cookie_headers = sw_zend_read_and_convert_property_array(swoole_http2_response_ce, zresponse, ZEND_STRL("set_cookie_headers"), 0);

    ssize_t rv;
    while (true)
    {
        nghttp2_nv nv;
        int inflate_flags = 0;
        size_t proclen;

        rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, (uchar *) in, inlen, 1);
        if (rv < 0)
        {
            nghttp2_error(rv, "nghttp2_hd_inflate_hd failed");
            return SW_ERR;
        }

        proclen = (size_t) rv;
        in += proclen;
        inlen -= proclen;

        //swTraceLog(SW_TRACE_HTTP2, "Header: %s[%d]: %s[%d]", nv.name, nv.namelen, nv.value, nv.valuelen);

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT)
        {
            if (nv.name[0] == ':')
            {
                if (strncasecmp((char *) nv.name + 1, "status", nv.namelen -1) == 0)
                {
                    zend_update_property_long(swoole_http2_response_ce, zresponse, ZEND_STRL("statusCode"), atoi((char *) nv.value));
                    continue;
                }
            }
#ifdef SW_HAVE_ZLIB
            else if (strncasecmp((char *) nv.name, "content-encoding", nv.namelen) == 0 && strncasecmp((char *) nv.value, "gzip", nv.valuelen) == 0)
            {
                /**
                 * init zlib stream
                 */
                stream->gzip = 1;
                memset(&stream->gzip_stream, 0, sizeof(stream->gzip_stream));
                stream->gzip_buffer = swString_new(8192);
                stream->gzip_stream.zalloc = php_zlib_alloc;
                stream->gzip_stream.zfree = php_zlib_free;
                /**
                 * zlib decode
                 */
                if (Z_OK != inflateInit2(&stream->gzip_stream, MAX_WBITS + 16))
                {
                    swWarn("inflateInit2() failed");
                    return SW_ERR;
                }
            }
#endif
            else if (strncasecmp((char *) nv.name, "set-cookie", nv.namelen) == 0)
            {
                if (SW_OK != http_parse_set_cookies((char *) nv.value, nv.valuelen, zcookies, zset_cookie_headers))
                {
                    return SW_ERR;
                }
            }
            add_assoc_stringl_ex(zheaders, (char *) nv.name, nv.namelen, (char *) nv.value, nv.valuelen);
        }

        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL)
        {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }

        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0)
        {
            break;
        }
    }

    return SW_OK;
}

static ssize_t http2_client_build_header(zval *zobject, zval *zrequest, char *buffer)
{
    http2_client *h2c = (http2_client *) swoole_get_object(zobject);
    zval *zmethod = sw_zend_read_property(swoole_http2_request_ce, zrequest, ZEND_STRL("method"), 0);
    zval *zpath = sw_zend_read_property(swoole_http2_request_ce, zrequest, ZEND_STRL("path"), 0);
    zval *zheaders = sw_zend_read_property(swoole_http2_request_ce, zrequest, ZEND_STRL("headers"), 0);
    zval *zcookies = sw_zend_read_property(swoole_http2_request_ce, zrequest, ZEND_STRL("cookies"), 0);
    http2::headers headers(8 + php_swoole_array_length_safe(zheaders) + php_swoole_array_length_safe(zcookies));
    bool find_host = 0;

    if (Z_TYPE_P(zmethod) != IS_STRING || Z_STRLEN_P(zmethod) == 0)
    {
        headers.add(ZEND_STRL(":method"), ZEND_STRL("GET"));
    }
    else
    {
        headers.add(ZEND_STRL(":method"), Z_STRVAL_P(zmethod), Z_STRLEN_P(zmethod));
    }
    if (Z_TYPE_P(zpath) != IS_STRING || Z_STRLEN_P(zpath) == 0)
    {
        headers.add(ZEND_STRL(":path"), "/", 1);
    }
    else
    {
        headers.add(ZEND_STRL(":path"), Z_STRVAL_P(zpath), Z_STRLEN_P(zpath));
    }
    if (h2c->ssl)
    {
        headers.add(ZEND_STRL(":scheme"), ZEND_STRL("https"));
    }
    else
    {
        headers.add(ZEND_STRL(":scheme"), ZEND_STRL("http"));
    }
    // Host
    headers.reserve_one();

    if (ZVAL_IS_ARRAY(zheaders))
    {
        zend_string *key;
        zval *zvalue;

        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zheaders), key, zvalue)
        {
            if (UNEXPECTED(!key || *ZSTR_VAL(key) == ':' || ZVAL_IS_NULL(zvalue)))
            {
                continue;
            }
            zend::string str_value(zvalue);
            if (strncasecmp("host", ZSTR_VAL(key), ZSTR_LEN(key)) == 0)
            {
                headers.add(HTTP2_CLIENT_HOST_HEADER_INDEX, ZEND_STRL(":authority"), str_value.val(), str_value.len());
                find_host = true;
            }
            else
            {
                headers.add(ZSTR_VAL(key), ZSTR_LEN(key), str_value.val(), str_value.len());
            }
        }
        ZEND_HASH_FOREACH_END();
    }
    if (!find_host)
    {
        headers.add(HTTP2_CLIENT_HOST_HEADER_INDEX,ZEND_STRL(":authority"), h2c->host.c_str(), h2c->host.length());
    }
    // http cookies
    if (ZVAL_IS_ARRAY(zcookies))
    {
        zend_string *key;
        zval *zvalue;
        char *encoded_value;
        int encoded_value_len;
        swString *buffer = SwooleTG.buffer_stack;

        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zcookies), key, zvalue)
        {
            if (UNEXPECTED(!key || ZVAL_IS_NULL(zvalue)))
            {
                continue;
            }
            zend::string str_value(zvalue);
            swString_clear(buffer);
            swString_append_ptr(buffer, ZSTR_VAL(key), ZSTR_LEN(key));
            swString_append_ptr(buffer, "=", 1);
            encoded_value = php_swoole_url_encode(str_value.val(), str_value.len(), &encoded_value_len);
            if (encoded_value)
            {
                swString_append_ptr(buffer, encoded_value, encoded_value_len);
                efree(encoded_value);
                headers.add(ZEND_STRL("cookie"), buffer->str, buffer->length);
            }
        }
        ZEND_HASH_FOREACH_END();
    }

    size_t buflen = nghttp2_hd_deflate_bound(h2c->deflater, headers.get(), headers.len());
    if (buflen > h2c->remote_settings.max_header_list_size)
    {
        php_swoole_error(E_WARNING, "header cannot bigger than remote max_header_list_size %u", h2c->remote_settings.max_header_list_size);
        return -1;
    }
    ssize_t rv = nghttp2_hd_deflate_hd(h2c->deflater, (uchar *) buffer, buflen, headers.get(), headers.len());
    if (rv < 0)
    {
        h2c->nghttp2_error(rv, "nghttp2_hd_deflate_hd() failed");
        return -1;
    }
    return rv;
}


static void http2_client_stream_free(void *ptr)
{
    http2_client_stream *stream = (http2_client_stream *) ptr;
    if (stream->buffer)
    {
        swString_free(stream->buffer);
    }
#ifdef SW_HAVE_ZLIB
    if (stream->gzip)
    {
        inflateEnd(&stream->gzip_stream);
        swString_free(stream->gzip_buffer);
    }
#endif
    if (stream->zresponse)
    {
        zval_ptr_dtor(stream->zresponse);
        stream->zresponse = NULL;
    }
    efree(stream);
}

http2_client_stream* http2_client::create_stream(uint32_t stream_id, bool pipeline)
{
    // malloc
    http2_client_stream *stream = (http2_client_stream *) ecalloc(1, sizeof(http2_client_stream));
    // init
    stream->zresponse = &stream->_zresponse;
    object_init_ex(stream->zresponse, swoole_http2_response_ce);
    stream->stream_id = stream_id;
    stream->type = pipeline ? SW_HTTP2_STREAM_PIPELINE : SW_HTTP2_STREAM_NORMAL;
    stream->remote_window_size = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    stream->local_window_size = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    // add to map
    swHashMap_add_int(streams, stream_id, stream);
    // set property
    zend_update_property_long(swoole_http2_response_ce, stream->zresponse, ZEND_STRL("streamId"), stream_id);

    return stream;
}

bool http2_client::send_ping_frame()
{
    char frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE];
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_PING, SW_HTTP2_FRAME_PING_PAYLOAD_SIZE, SW_HTTP2_FLAG_NONE, 0);
    return send(frame, SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_FRAME_PING_PAYLOAD_SIZE);
}

uint32_t http2_client::send_request(zval *req)
{
    ssize_t length;

    zval *zheaders = sw_zend_read_and_convert_property_array(swoole_http2_request_ce, req, ZEND_STRL("headers"), 0);
    zval *zdata = sw_zend_read_property(swoole_http2_request_ce, req, ZEND_STRL("data"), 0);
    zval *zpipeline = sw_zend_read_property(swoole_http2_request_ce, req, ZEND_STRL("pipeline"), 0);
    bool is_data_empty = !zend_is_true(zdata);

    if (ZVAL_IS_ARRAY(zdata))
    {
        add_assoc_stringl_ex(zheaders, ZEND_STRL("content-type"), (char *) ZEND_STRL("application/x-www-form-urlencoded"));
    }

    /**
     * send header
     */
    char* buffer = SwooleTG.buffer_stack->str;
    length = http2_client_build_header(zobject, req, buffer + SW_HTTP2_FRAME_HEADER_SIZE);
    if (length <= 0)
    {
        return 0;
    }

    auto stream = create_stream(stream_id, Z_BVAL_P(zpipeline));

    if (is_data_empty)
    {
        //pipeline
        if (stream->type == SW_HTTP2_STREAM_PIPELINE)
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, length, SW_HTTP2_FLAG_END_HEADERS, stream->stream_id);
        }
        else
        {
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, length, SW_HTTP2_FLAG_END_STREAM | SW_HTTP2_FLAG_END_HEADERS, stream->stream_id);
        }
    }
    else
    {
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_HEADERS, length, SW_HTTP2_FLAG_END_HEADERS, stream->stream_id);
    }

    swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN ", STREAM#%d] length=%zd", swHttp2_get_type(SW_HTTP2_TYPE_HEADERS), stream->stream_id, length);
    if (!send(buffer, length + SW_HTTP2_FRAME_HEADER_SIZE))
    {
        return 0;
    }

    /**
     * send body
     */
    if (!is_data_empty)
    {
        char *p;
        size_t len;
        smart_str formstr_s = { NULL, 0 };
        uint8_t send_flag;
        uint32_t send_len;
        zend::string str_zpost_data;

        int flag = stream->type == SW_HTTP2_STREAM_PIPELINE ? 0 : SW_HTTP2_FLAG_END_STREAM;
        if (ZVAL_IS_ARRAY(zdata))
        {
            p = php_swoole_http_build_query(zdata, &len, &formstr_s);
            if (p == NULL)
            {
                php_swoole_error(E_WARNING, "http_build_query failed");
                return 0;
            }
        }
        else
        {
            str_zpost_data = zdata;
            p = str_zpost_data.val();
            len = str_zpost_data.len();
        }

        swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN ", END, STREAM#%d] length=%zu", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream->stream_id, len);

        while (len > 0)
        {
            if (len > remote_settings.max_frame_size)
            {
                send_len = remote_settings.max_frame_size;
                send_flag = 0;
            }
            else
            {
                send_len = len;
                send_flag = flag;
            }
            swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, send_len, send_flag, stream->stream_id);
            if (!send(buffer, SW_HTTP2_FRAME_HEADER_SIZE))
            {
                return 0;
            }
            if (!send(p, send_len))
            {
                return 0;
            }
            len -= send_len;
            p += send_len;
        }

        if (formstr_s.s)
        {
            smart_str_free(&formstr_s);
        }
    }

    stream_id += 2;

    return stream->stream_id;
}

bool http2_client::send_data(uint32_t stream_id, zval *data, bool end)
{
    char buffer[SW_HTTP2_FRAME_HEADER_SIZE];
    http2_client_stream *stream = get_stream(stream_id);

    if (stream == NULL || stream->type != SW_HTTP2_STREAM_PIPELINE)
    {
        update_error_properties(EINVAL, cpp_string::format("can not found stream#%u", stream_id).c_str());
        return false;
    }

    int flag = end ? SW_HTTP2_FLAG_END_STREAM : 0;

    if (ZVAL_IS_ARRAY(data))
    {
        size_t len;
        smart_str formstr_s = { 0 };
        char *formstr = php_swoole_http_build_query(data, &len, &formstr_s);
        if (formstr == NULL)
        {
            php_swoole_error(E_WARNING, "http_build_query failed");
            return false;
        }
        memset(buffer, 0, SW_HTTP2_FRAME_HEADER_SIZE);
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, len, flag, stream_id);
        swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN ", END, STREAM#%d] length=%zu", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream_id, len);
        if (!send(buffer, SW_HTTP2_FRAME_HEADER_SIZE) || !send(formstr, len))
        {
            return false;
        }
        smart_str_free(&formstr_s);
    }
    else if (Z_TYPE_P(data) == IS_STRING)
    {
        swHttp2_set_frame_header(buffer, SW_HTTP2_TYPE_DATA, Z_STRLEN_P(data), flag, stream_id);
        swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN ", END, STREAM#%d] length=%zu", swHttp2_get_type(SW_HTTP2_TYPE_DATA), stream_id, Z_STRLEN_P(data));
        if (!send(buffer, SW_HTTP2_FRAME_HEADER_SIZE) || !send(Z_STRVAL_P(data), Z_STRLEN_P(data)))
        {
            return false;
        }
    }
    else
    {
        php_swoole_error(E_WARNING, "unknown data type[%d]", Z_TYPE_P(data) );
        return false;
    }
    return true;
}

bool http2_client::send_goaway_frame(zend_long error_code, const char *debug_data, size_t debug_data_len)
{
    size_t length = SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE + debug_data_len;
    char *frame = (char *) ecalloc(1, length);
    bool ret;
    swHttp2_set_frame_header(frame, SW_HTTP2_TYPE_GOAWAY, SW_HTTP2_GOAWAY_SIZE + debug_data_len, error_code, 0);
    *(uint32_t*) (frame + SW_HTTP2_FRAME_HEADER_SIZE) = htonl(last_stream_id);
    *(uint32_t*) (frame + SW_HTTP2_FRAME_HEADER_SIZE + 4) = htonl(error_code);
    if (debug_data_len > 0)
    {
        memcpy(frame + SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_GOAWAY_SIZE, debug_data, debug_data_len);
    }
    swTraceLog(SW_TRACE_HTTP2, "[" SW_ECHO_GREEN "] Send: last-sid=%d, error-code=%d", swHttp2_get_type(SW_HTTP2_TYPE_GOAWAY), last_stream_id, error_code);
    ret = send(frame, length);
    efree(frame);
    return ret;
}

static PHP_METHOD(swoole_http2_client_coro, send)
{
    zval *request;
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);

    if (!h2c->is_available())
    {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &request) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (Z_TYPE_P(request) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(request), swoole_http2_request_ce))
    {
        php_swoole_fatal_error(E_ERROR, "object is not instanceof swoole_http2_request");
        RETURN_FALSE;
    }

    uint32_t stream_id = h2c->send_request(request);
    if (stream_id == 0)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(stream_id);
    }
}

static PHP_METHOD(swoole_http2_client_coro, recv)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);

    if (!h2c->is_available())
    {
        RETURN_FALSE;
    }

    double timeout = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|d", &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    while (true)
    {
        if (!h2c->recv_packet(timeout))
        {
            RETURN_FALSE;
        }

        enum swReturn_code ret = h2c->parse_frame(return_value);
        if (ret == SW_CONTINUE)
        {
            continue;
        }
        else if (ret == SW_READY)
        {
            break;
        }
        else
        {
            RETURN_FALSE;
        }
    }
}

static PHP_METHOD(swoole_http2_client_coro, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    if (!h2c)
    {
        return;
    }
    delete h2c;
    swoole_set_object(ZEND_THIS, nullptr);
}

static PHP_METHOD(swoole_http2_client_coro, close)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    RETURN_BOOL(h2c->close());
}

static PHP_METHOD(swoole_http2_client_coro, connect)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    RETURN_BOOL(h2c->connect());
}

static sw_inline void http2_settings_to_array(swHttp2_settings *settings, zval* zarray)
{
    array_init(zarray);
    add_assoc_long_ex(zarray, ZEND_STRL("header_table_size"), settings->header_table_size);
    add_assoc_long_ex(zarray, ZEND_STRL("window_size"), settings->window_size);
    add_assoc_long_ex(zarray, ZEND_STRL("max_concurrent_streams"), settings->max_concurrent_streams);
    add_assoc_long_ex(zarray, ZEND_STRL("max_frame_size"), settings->max_frame_size);
    add_assoc_long_ex(zarray, ZEND_STRL("max_header_list_size"), settings->max_header_list_size);
}

static PHP_METHOD(swoole_http2_client_coro, stats)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    zval _zarray, *zarray = &_zarray;
    swString key = {0};
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|s", &key.str, &key.length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (key.length > 0)
    {
        if (strcmp(key.str, "current_stream_id") == 0)
        {
            RETURN_LONG(h2c->stream_id);
        }
        else if (strcmp(key.str, "last_stream_id") == 0)
        {
            RETURN_LONG(h2c->last_stream_id);
        }
        else if (strcmp(key.str, "local_settings") == 0)
        {
            http2_settings_to_array(&h2c->local_settings, zarray);
            RETURN_ZVAL(zarray, 0, 0);
        }
        else if (strcmp(key.str, "remote_settings") == 0)
        {
            http2_settings_to_array(&h2c->remote_settings, zarray);
            RETURN_ZVAL(zarray, 0, 0);
        }
        else if (strcmp(key.str, "active_stream_num") == 0)
        {
            RETURN_LONG(h2c->streams ? swHashMap_count(h2c->streams) : 0);
        }
    }
    else
    {
        array_init(return_value);
        add_assoc_long_ex(return_value, ZEND_STRL("current_stream_id"), h2c->stream_id);
        add_assoc_long_ex(return_value, ZEND_STRL("last_stream_id"), h2c->last_stream_id);
        http2_settings_to_array(&h2c->local_settings, zarray);
        add_assoc_zval_ex(return_value, ZEND_STRL("local_settings"), zarray);
        http2_settings_to_array(&h2c->remote_settings, zarray);
        add_assoc_zval_ex(return_value, ZEND_STRL("remote_settings"), zarray);
        add_assoc_long_ex(return_value, ZEND_STRL("active_stream_num"), h2c->streams ? swHashMap_count(h2c->streams) : 0);
    }
}

static PHP_METHOD(swoole_http2_client_coro, isStreamExist)
{
    zend_long stream_id = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &stream_id) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (stream_id < 0)
    {
        RETURN_FALSE;
    }

    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    if (!h2c->client)
    {
        RETURN_FALSE;
    }
    else
    {
        if (stream_id == 0)
        {
            RETURN_TRUE;
        }
        if (!h2c->streams)
        {
            RETURN_FALSE;
        }
    }
    http2_client_stream *stream = h2c->get_stream(stream_id);
    RETURN_BOOL(stream ? 1 : 0);
}

static PHP_METHOD(swoole_http2_client_coro, write)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);

    if (!h2c->is_available())
    {
        RETURN_FALSE;
    }

    long stream_id;
    zval *data;
    zend_bool end = 0;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lz|b", &stream_id, &data, &end) == FAILURE)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(h2c->send_data(stream_id, data, end));
}

static PHP_METHOD(swoole_http2_client_coro, ping)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);

    if (!h2c->is_available())
    {
        RETURN_FALSE;
    }

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
static PHP_METHOD(swoole_http2_client_coro, goaway)
{
    http2_client *h2c = (http2_client *) swoole_get_object(ZEND_THIS);
    zend_long error_code = SW_HTTP2_ERROR_NO_ERROR;
    char* debug_data = NULL;
    size_t debug_data_len = 0;

    if (!h2c->is_available())
    {
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ls", &error_code, &debug_data, &debug_data_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(h2c->send_goaway_frame(error_code, debug_data, debug_data_len));
}

#endif
