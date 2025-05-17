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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "test_coroutine.h"
#include "redis_client.h"
#include "swoole_server.h"
#include "swoole_http.h"
#include "swoole_http2.h"

#include <nghttp2/nghttp2.h>
#include <nghttp2/nghttp2ver.h>

using namespace swoole;
using namespace std;
using http_server::Context;
using network::Client;
using network::SyncClient;
using swoole::network::AsyncClient;

const std::string REDIS_TEST_KEY = "key-swoole";
const std::string REDIS_TEST_VALUE = "value-swoole";

TEST(http2, default_settings) {
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE), SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH), SW_HTTP2_DEFAULT_ENABLE_PUSH);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS),
              SW_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMS);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE), SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE), SW_HTTP2_DEFAULT_MAX_FRAME_SIZE);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE),
              SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE);

    http2::Settings _settings = {
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
    };

    http2::put_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE, _settings.header_table_size);
    http2::put_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH, _settings.enable_push);
    http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, _settings.max_concurrent_streams);
    http2::put_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE, _settings.init_window_size);
    http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE, _settings.max_frame_size);
    http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, _settings.max_header_list_size);

    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE), _settings.header_table_size);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH), _settings.enable_push);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), _settings.max_concurrent_streams);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE), _settings.init_window_size);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE), _settings.max_frame_size);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE), _settings.max_header_list_size);
}

TEST(http2, pack_setting_frame) {
    char frame[SW_HTTP2_SETTING_FRAME_SIZE];
    http2::Settings settings_1{};
    http2::init_settings(&settings_1);
    size_t n = http2::pack_setting_frame(frame, settings_1, false);

    ASSERT_GT(n, 16);

    http2::Settings settings_2{};
    http2::unpack_setting_data(
        frame + SW_HTTP2_FRAME_HEADER_SIZE, n, [&settings_2](uint16_t id, uint32_t value) -> ReturnCode {
            switch (id) {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                settings_2.header_table_size = value;
                break;
            case SW_HTTP2_SETTINGS_ENABLE_PUSH:
                settings_2.enable_push = value;
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                settings_2.max_concurrent_streams = value;
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                settings_2.init_window_size = value;
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                settings_2.max_frame_size = value;
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                settings_2.max_header_list_size = value;
                break;
            default:
                return SW_ERROR;
            }
            return SW_SUCCESS;
        });

    ASSERT_MEMEQ(&settings_1, &settings_2, sizeof(settings_2));
}

#define HTTP2_GET_TYPE_TEST(t) ASSERT_STREQ(http2::get_type(SW_HTTP2_TYPE_##t), #t)

TEST(http2, get_type) {
    HTTP2_GET_TYPE_TEST(DATA);
    HTTP2_GET_TYPE_TEST(HEADERS);
    HTTP2_GET_TYPE_TEST(PRIORITY);
    HTTP2_GET_TYPE_TEST(RST_STREAM);
    HTTP2_GET_TYPE_TEST(SETTINGS);
    HTTP2_GET_TYPE_TEST(PUSH_PROMISE);
    HTTP2_GET_TYPE_TEST(PING);
    HTTP2_GET_TYPE_TEST(GOAWAY);
    HTTP2_GET_TYPE_TEST(WINDOW_UPDATE);
    HTTP2_GET_TYPE_TEST(CONTINUATION);
}

TEST(http2, get_type_color) {
    SW_LOOP_N(SW_HTTP2_TYPE_GOAWAY + 2) {
        ASSERT_GE(http2::get_type_color(i), 0);
    }
}

struct Http2Session {
    SessionId fd;
    nghttp2_session *session;
    Server *server;
    std::unordered_map<int32_t, std::string> stream_paths;
    std::unordered_map<int32_t, std::string> stream_data;

    Http2Session(SessionId _fd, Server *_serv) : fd(_fd), session(nullptr), server(_serv) {}
    ~Http2Session() {
        if (session) {
            nghttp2_session_del(session);
            session = nullptr;
        }
    }
};

#define CHECK_NGHTTP2(expr, error_msg)                                                                                 \
    do {                                                                                                               \
        int rv = (expr);                                                                                               \
        if (rv != 0) {                                                                                                 \
            swoole_error_log(SW_LOG_ERROR, "%s: %s", error_msg, nghttp2_strerror(rv));                                 \
            return -1;                                                                                                 \
        }                                                                                                              \
    } while (0)

std::unordered_map<SessionId, std::shared_ptr<Http2Session>> sessions;

static nghttp2_settings_entry default_settings[] = {
    {
        NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
        SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE,
    },
    {
        NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
        SW_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMS,
    },
    {
        NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
        SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE,
    },
    {
        NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
        SW_HTTP2_DEFAULT_MAX_FRAME_SIZE,
    },
    {
        NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
        SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE,
    },
};

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    auto http2_session = static_cast<Http2Session *>(user_data);
    Server *server = static_cast<Server *>(http2_session->server);

    bool ret = server->send(http2_session->fd, reinterpret_cast<const char *>(data), length);
    if (!ret) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return length;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    return 0;
}

// 处理头部回调
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name,
                              size_t namelen,
                              const uint8_t *value,
                              size_t valuelen,
                              uint8_t flags,
                              void *user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    DEBUG() << "Header: " << std::string(reinterpret_cast<const char *>(name), namelen) << ": "
            << std::string(reinterpret_cast<const char *>(value), valuelen) << std::endl;

    return 0;
}

// 处理请求开始回调
static int on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    DEBUG() << "New request started on stream ID: " << frame->hd.stream_id << std::endl;

    return 0;
}

static void handle_request(nghttp2_session *session, int32_t stream_id, Http2Session *http2_session);

static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    auto http2_session = static_cast<Http2Session *>(user_data);

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            swoole_trace_log(SW_TRACE_HTTP2, "Received HEADERS frame for stream %d", frame->hd.stream_id);

            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                handle_request(session, frame->hd.stream_id, http2_session);
            }
        }
        break;
    case NGHTTP2_DATA:
        swoole_trace_log(SW_TRACE_HTTP2, "Received DATA frame for stream %d", frame->hd.stream_id);

        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            handle_request(session, frame->hd.stream_id, http2_session);
        }
        break;
    }

    return 0;
}

static int on_data_chunk_recv_callback(
    nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    auto http2_session = static_cast<Http2Session *>(user_data);

    // 将数据块添加到对应流的数据中
    http2_session->stream_data[stream_id].append(reinterpret_cast<const char *>(data), len);

    swoole_trace_log(SW_TRACE_HTTP2, "Received %zu bytes of DATA for stream %d", len, stream_id);

    return 0;
}

static int on_frame_not_send_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      int lib_error_code,
                                      void *user_data) {
    // 处理帧发送失败
    std::cerr << "Failed to send frame type: " << frame->hd.type << std::endl;
    return 0;
}

static int on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    if (frame->hd.type == NGHTTP2_WINDOW_UPDATE) {
        DEBUG() << "Window update sent: stream=" << frame->hd.stream_id
                << ", increment=" << frame->window_update.window_size_increment << std::endl;
    }
    return 0;
}

static ssize_t string_read_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint8_t *buf,
                                    size_t length,
                                    uint32_t *data_flags,
                                    nghttp2_data_source *source,
                                    void *user_data) {
    const char *data = static_cast<const char *>(source->ptr);
    size_t datalen = strlen(data);

    if (datalen <= length) {
        memcpy(buf, data, datalen);
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return datalen;
    } else {
        memcpy(buf, data, length);
        return length;
    }
}

static void handle_request(nghttp2_session *session, int32_t stream_id, Http2Session *http2_session) {
    // 获取路径
    std::string path = "/";
    auto path_it = http2_session->stream_paths.find(stream_id);
    if (path_it != http2_session->stream_paths.end()) {
        path = path_it->second;
    }

    // 获取请求体
    std::string request_body;
    auto body_it = http2_session->stream_data.find(stream_id);
    if (body_it != http2_session->stream_data.end()) {
        request_body = body_it->second;
    }

    swoole_trace_log(SW_TRACE_HTTP2,
                     "Request fully received on stream %d, path: %s, body length: %zu",
                     stream_id,
                     path.c_str(),
                     request_body.length());

    auto header_server = "nghttp2-server/" NGHTTP2_VERSION;
    // 准备响应头
    nghttp2_nv hdrs[] = {
        {(uint8_t *) ":status", (uint8_t *) "200", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) "content-type", (uint8_t *) "text/html", 12, 9, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) "server", (uint8_t *) header_server, 6, strlen(header_server), NGHTTP2_NV_FLAG_NONE}};

    if (path == "/" || path == "/index.html") {
        const char *body = "<html><body><h1>Welcome to HTTP/2 Server</h1>"
                           "<p>This is a simple HTTP/2 server implementation.</p>"
                           "</body></html>";

        nghttp2_data_provider data_prd;
        data_prd.source.ptr = (void *) body;
        data_prd.read_callback = string_read_callback;

        // 提交响应
        int rv = nghttp2_submit_response(session, stream_id, hdrs, sizeof(hdrs) / sizeof(hdrs[0]), &data_prd);
        if (rv != 0) {
            swoole_error_log(
                SW_LOG_ERROR, SW_ERROR_HTTP2_INTERNAL_ERROR, "Failed to submit response: %s", nghttp2_strerror(rv));
            return;
        }
    } else {
        // 404 Not Found
        nghttp2_nv error_hdrs[] = {{(uint8_t *) ":status", (uint8_t *) "404", 7, 3, NGHTTP2_NV_FLAG_NONE},
                                   {(uint8_t *) "content-type", (uint8_t *) "text/html", 12, 9, NGHTTP2_NV_FLAG_NONE},
                                   {(uint8_t *) "server", (uint8_t *) header_server, 6, 17, NGHTTP2_NV_FLAG_NONE}};

        const char *body = "<html><body><h1>404 Not Found</h1>"
                           "<p>The requested resource was not found on this server.</p>"
                           "</body></html>";

        nghttp2_data_provider data_prd;
        data_prd.source.ptr = (void *) body;
        data_prd.read_callback = string_read_callback;

        nghttp2_submit_response(session, stream_id, error_hdrs, sizeof(error_hdrs) / sizeof(error_hdrs[0]), &data_prd);
    }

    nghttp2_session_send(session);
}

static void http2_send_settings(Http2Session *session_data, const nghttp2_settings_entry *settings, size_t num) {
    auto rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, settings, num);
    if (rv != 0) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_HTTP2_INTERNAL_ERROR, "Failed to submit settings: %s", nghttp2_strerror(rv));
        return;
    }
    nghttp2_session_send(session_data->session);
}

static std::shared_ptr<Http2Session> create_http2_session(Server *serv, SessionId fd) {
    auto session_data = std::make_shared<Http2Session>(fd, serv);

    nghttp2_session_callbacks *callbacks;
    int rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        swoole_warning("Failed to create nghttp2 callbacks: %s", nghttp2_strerror(rv));
        return nullptr;
    }

    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks, on_frame_not_send_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks, on_frame_not_send_callback);

    rv = nghttp2_session_server_new(&session_data->session, callbacks, session_data.get());
    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0) {
        swoole_error_log(
            SW_LOG_ERROR, SW_ERROR_HTTP2_INTERNAL_ERROR, "Failed to create nghttp2 session: %s", nghttp2_strerror(rv));
        return nullptr;
    }

    nghttp2_session_set_user_data(session_data->session, session_data.get());

    return session_data;
}

static void test_ssl_http2(Server::Mode mode) {
    Server serv(mode);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_INFO);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    const int server_port = __LINE__ + TEST_PORT;
    ListenPort *port = serv.add_port((enum swSocketType)(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, server_port);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->open_http2_protocol = 1;
    port->open_http_protocol = 1;
    port->open_websocket_protocol = 1;
    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port->ssl_context->http = 1;
    port->ssl_context->http_v2 = 1;
    port->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);
    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();
            lock->lock();

            auto cmd = "nghttp -v -y https://127.0.0.1:" + std::to_string(server_port) + "/";
            pid_t pid;
            auto _pipe = swoole_shell_exec(cmd.c_str(), &pid, 1);
            String buf(1024);
            while (1) {
                auto n = read(_pipe, buf.str + buf.length, buf.size - buf.length);
                if (n > 0) {
                    buf.grow(n);
                    continue;
                }
                break;
            }

            int status;
            ASSERT_EQ(waitpid(pid, &status, 0), pid);
            close(_pipe);

            usleep(10000);

            DEBUG() << buf.to_std_string();

            EXPECT_TRUE(buf.contains("user-agent: nghttp2/" NGHTTP2_VERSION));
            // FIXME There is a bug in nghttp's processing of settings frames,
            // so it can only give up detecting response content.
            // EXPECT_TRUE(buf.contains("Welcome to HTTP/2 Server"));

            serv->shutdown();
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onConnect = [](Server *serv, DataHead *ev) {
        SessionId fd = ev->fd;
        DEBUG() << "New connection: " << fd << std::endl;

        auto session = create_http2_session(serv, fd);
        if (!session) {
            serv->close(fd);
            return;
        }

        sessions[fd] = session;
        ssize_t consumed = nghttp2_session_mem_recv(
            session->session, (uint8_t *) SW_HTTP2_PRI_STRING, sizeof(SW_HTTP2_PRI_STRING) - 1);
        if (consumed < 0) {
            swoole_error_log(SW_LOG_ERROR,
                             SW_ERROR_HTTP2_INTERNAL_ERROR,
                             "nghttp2_session_mem_recv() error: %s",
                             nghttp2_strerror((int) consumed));
            serv->close(fd);
            return;
        }
         http2_send_settings(session.get(), default_settings, sizeof(default_settings) / sizeof(default_settings[0]));
    };

    serv.onClose = [](Server *serv, DataHead *ev) {
        SessionId fd = ev->fd;
        DEBUG() << "Close connection: " << fd << std::endl;
        sessions.erase(fd);
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        SessionId fd = req->info.fd;
        std::shared_ptr<Http2Session> session;
        if (sessions.find(fd) == sessions.end()) {
            serv->close(fd);
            return SW_ERR;
        }

        session = sessions[fd];
        const uint8_t *data_ptr = reinterpret_cast<const uint8_t *>(req->data);
        size_t data_len = req->info.len;

        ssize_t consumed = nghttp2_session_mem_recv(session->session, data_ptr, data_len);
        if (consumed < 0) {
            swoole_error_log(SW_LOG_ERROR,
                             SW_ERROR_HTTP2_INTERNAL_ERROR,
                             "nghttp2_session_mem_recv() error: %s",
                             nghttp2_strerror((int) consumed));
            serv->close(fd);
            return SW_ERR;
        }

        if (nghttp2_session_want_write(session->session)) {
            nghttp2_session_send(session->session);
        }

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;
}

TEST(http2, ssl) {
    test_ssl_http2(Server::MODE_BASE);
}
