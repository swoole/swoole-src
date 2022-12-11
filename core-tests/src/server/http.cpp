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

#include "httplib_client.h"
#include "llhttp.h"
#include "swoole_server.h"
#include "swoole_file.h"
#include "swoole_http.h"
#include "swoole_util.h"

using namespace swoole;
using namespace std;
using swoole::http_server::Context;
using swoole::network::Client;
using swoole::network::SyncClient;

SessionId session_id = 0;
Connection *conn = nullptr;
Session *session = nullptr;

struct http_context {
    unordered_map<string, string> headers;
    unordered_map<string, string> response_headers;
    string url;
    string current_key;
    Server *server;
    int fd;
    bool completed;

    void setHeader(string key, string value) {
        response_headers[key] = value;
    }

    void response(enum swHttpStatusCode code, string body) {
        response_headers["Content-Length"] = to_string(body.length());
        response(code);
        server->send(fd, body.c_str(), body.length());
    }

    void response(int code) {
        swString *buf = swoole::make_string(1024);
        buf->length = sw_snprintf(buf->str, buf->size, "HTTP/1.1 %s\r\n", http_server::get_status_message(code));
        for (auto &kv : response_headers) {
            buf->append(kv.first.c_str(), kv.first.length());
            buf->append(SW_STRL(": "));
            buf->append(kv.second.c_str(), kv.second.length());
            buf->append(SW_STRL("\r\n"));
        }
        buf->append(SW_STRL("\r\n"));
        server->send(fd, buf->str, buf->length);
        delete buf;
    }
};

static int handle_on_message_complete(llhttp_t *parser) {
    http_context *ctx = reinterpret_cast<http_context *>(parser->data);
    ctx->completed = true;
    return 0;
}

static int handle_on_header_field(llhttp_t *parser, const char *at, size_t length) {
    http_context *ctx = reinterpret_cast<http_context *>(parser->data);
    ctx->current_key = string(at, length);
    return 0;
}

static int handle_on_header_value(llhttp_t *parser, const char *at, size_t length) {
    http_context *ctx = reinterpret_cast<http_context *>(parser->data);
    ctx->headers[ctx->current_key] = string(at, length);
    return 0;
}

static int handle_on_url(llhttp_t *parser, const char *at, size_t length) {
    http_context *ctx = reinterpret_cast<http_context *>(parser->data);
    ctx->url = std::string(at, length);
    return 0;
}

static void test_base_server(function<void(Server *)> fn) {
    thread child_thread;
    Server serv(swoole::Server::MODE_BASE);
    serv.worker_num = 1;
    serv.enable_reuse_port = true;
    serv.heartbeat_check_interval = 1;
    serv.private_data_2 = (void *) &fn;

    serv.enable_static_handler = true;
    serv.set_document_root(test::get_root_path());
    serv.add_static_handler_location("/examples");

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_http_protocol = 1;
    port->open_websocket_protocol = 1;

    serv.create();

    serv.onWorkerStart = [&child_thread](Server *serv, int worker_id) {
        function<void(Server *)> fn = *(function<void(Server *)> *) serv->private_data_2;
        child_thread = thread(fn, serv);
    };

    serv.onClose = [](Server *serv, DataHead *info) -> void {
        if (conn) {
            if (conn->close_actively) {
                EXPECT_EQ(info->reactor_id, -1);
            } else {
                EXPECT_GE(info->reactor_id, 0);
            }
        }
    };

    serv.onReceive = [](Server *serv, swRecvData *req) -> int {
        session_id = req->info.fd;
        conn = serv->get_connection_by_session_id(session_id);

        if (conn->websocket_status == swoole::websocket::STATUS_ACTIVE) {
            sw_tg_buffer()->clear();
            std::string resp = "Swoole: " + string(req->data, req->info.len);
            swoole::websocket::encode(sw_tg_buffer(),
                                      resp.c_str(),
                                      resp.length(),
                                      swoole::websocket::OPCODE_TEXT,
                                      swoole::websocket::FLAG_FIN);
            serv->send(session_id, sw_tg_buffer()->str, sw_tg_buffer()->length);
            return SW_OK;
        }

        llhttp_t parser = {};
        llhttp_settings_t settings = {};
        llhttp_init(&parser, HTTP_REQUEST, &settings);

        http_context ctx = {};
        parser.data = &ctx;
        ctx.server = serv;
        ctx.fd = session_id;

        settings.on_url = handle_on_url;
        settings.on_header_field = handle_on_header_field;
        settings.on_header_value = handle_on_header_value;
        settings.on_message_complete = handle_on_message_complete;

        enum llhttp_errno err = llhttp_execute(&parser, req->data, req->info.len);

        if (err == HPE_PAUSED_UPGRADE) {
            ctx.setHeader("Connection", "Upgrade");
            ctx.setHeader("Sec-WebSocket-Accept", "IIRiohCjop4iJrmvySrFcwcXpHo=");
            ctx.setHeader("Sec-WebSocket-Version", "13");
            ctx.setHeader("Upgrade", "websocket");
            ctx.setHeader("Content-Length", "0");

            ctx.response(SW_HTTP_SWITCHING_PROTOCOLS);

            conn->websocket_status = swoole::websocket::STATUS_ACTIVE;

            return SW_OK;
        }

        if (err != HPE_OK) {
            fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), parser.reason);
            return SW_ERR;
        }
        EXPECT_EQ(err, HPE_OK);

        if (ctx.url == "/just/get/file") {
            std::string filename = test::get_root_path() + "/examples/test.jpg";
            serv->sendfile(session_id, filename.c_str(), filename.length(), 0, 0);
        } else {
            ctx.response(SW_HTTP_OK, "hello world");
        }

        EXPECT_EQ(ctx.headers["User-Agent"], httplib::USER_AGENT);

        return SW_OK;
    };

    serv.start();
    child_thread.join();
}

static Server *test_process_server(Server::DispatchMode dispatch_mode = Server::DISPATCH_FDMOD, bool is_ssl = false) {
    Server *server = new Server(swoole::Server::MODE_PROCESS);
    server->user_ = std::string("root");
    server->group_ = std::string("root");
    server->chroot_ = std::string("/");
    server->worker_num = 2;
    server->dispatch_mode = dispatch_mode;
    server->open_cpu_affinity = true;
    sw_logger()->set_level(SW_LOG_WARNING);

    conn = nullptr;
    session = nullptr;
    ListenPort *port = is_ssl ? server->add_port((enum swSocketType)(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0)
                              : server->add_port(SW_SOCK_TCP, TEST_HOST, 0);

    port->open_http_protocol = 1;
    port->open_websocket_protocol = 1;
    port->open_tcp_keepalive = 1;

    server->enable_static_handler = true;
    server->set_document_root(test::get_root_path());
    server->add_static_handler_location("/examples");

    server->create();

    server->onClose = [](Server *serv, DataHead *info) -> void {
        if (conn) {
            if (conn->close_actively) {
                ASSERT_EQ(info->reactor_id, -1);
            } else {
                ASSERT_GE(info->reactor_id, 0);
            }
        }
    };

    server->onReceive = [&](Server *serv, swRecvData *req) -> int {
        session_id = req->info.fd;
        conn = serv->get_connection_by_session_id(session_id);
        session = serv->get_session(session_id);

        EXPECT_LE(serv->get_idle_worker_num(), serv->worker_num);
        EXPECT_TRUE(serv->is_healthy_connection(microtime(), conn));

        llhttp_t parser = {};
        llhttp_settings_t settings = {};
        llhttp_init(&parser, HTTP_REQUEST, &settings);

        http_context ctx = {};
        parser.data = &ctx;
        ctx.server = serv;
        ctx.fd = session_id;

        settings.on_url = handle_on_url;
        settings.on_header_field = handle_on_header_field;
        settings.on_header_value = handle_on_header_value;
        settings.on_message_complete = handle_on_message_complete;

        enum llhttp_errno err = llhttp_execute(&parser, req->data, req->info.len);
        if (err != HPE_OK) {
            fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), parser.reason);
            return SW_ERR;
        }

        if (ctx.url == "/overflow") {
            conn->overflow = 1;
        }

        if (ctx.url == "/pause") {
            serv->feedback(conn, SW_SERVER_EVENT_PAUSE_RECV);
        }

        EXPECT_EQ(err, HPE_OK);
        ctx.response(SW_HTTP_OK, "hello world");

        return SW_OK;
    };

    return server;
}

static Server *test_proxy_server() {
    Server *server = new Server(swoole::Server::MODE_BASE);
    server->worker_num = 1;

    ListenPort *port = server->add_port(SW_SOCK_TCP, TEST_HOST, 0);
    port->kernel_socket_send_buffer_size = INT_MAX;
    port->kernel_socket_recv_buffer_size = INT_MAX;
    port->open_tcp_nodelay = true;
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    server->enable_static_handler = true;
    server->set_document_root(test::get_root_path());
    server->add_static_handler_location("/examples");

    server->get_primary_port()->set_package_max_length(64 * 1024);
    port->open_http_protocol = 1;
    port->open_websocket_protocol = 1;

    server->create();

    server->onReceive = [&](Server *server, swRecvData *req) -> int {
        session_id = req->info.fd;
        conn = server->get_connection_by_session_id(session_id);

        SwooleG.process_id = server->worker_num;

        llhttp_t parser = {};
        llhttp_settings_t settings = {};
        llhttp_init(&parser, HTTP_REQUEST, &settings);

        http_context ctx = {};
        parser.data = &ctx;
        ctx.server = server;
        ctx.fd = session_id;

        settings.on_url = handle_on_url;
        settings.on_header_field = handle_on_header_field;
        settings.on_header_value = handle_on_header_value;
        settings.on_message_complete = handle_on_message_complete;

        enum llhttp_errno err = llhttp_execute(&parser, req->data, req->info.len);

        if (err != HPE_OK) {
            fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), parser.reason);
            return SW_ERR;
        }

        if (ctx.url == "/just/get/file") {
            std::string filename = test::get_root_path() + "/examples/test.jpg";
            server->sendfile(session_id, filename.c_str(), filename.length(), 0, 0);
        } else {
            ctx.response(SW_HTTP_OK, "hello world");
        }

        EXPECT_EQ(err, HPE_OK);
        EXPECT_EQ(ctx.headers["User-Agent"], httplib::USER_AGENT);
        return SW_OK;
    };

    return server;
}

TEST(http_server, get) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp->status, 200);
        EXPECT_EQ(resp->body, string("hello world"));

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, heartbeat_check_interval) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp->status, 200);
        EXPECT_EQ(resp->body, string("hello world"));
        sleep(3);

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, not_active) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();
        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        cli.Get("/index.html");

        conn->active = 0;
        cli.set_read_timeout(0, 100);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp, nullptr);
        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, has_closed) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();
        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        cli.Get("/index.html");

        conn->closed = 1;
        cli.set_read_timeout(0, 100);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp, nullptr);
        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, idle_time) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();
        auto port = serv->get_primary_port();
        port->max_idle_time = 1;

        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp->status, 200);

        sleep(2);
        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, post) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        httplib::Params params;
        params.emplace("name", "john");
        params.emplace("note", "coder");
        auto resp = cli.Post("/index.html", params);
        EXPECT_EQ(resp->status, 200);
        EXPECT_EQ(resp->body, string("hello world"));

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, static_get) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/examples/test.jpg");
        EXPECT_EQ(resp->status, 200);

        string file = test::get_root_path() + "/examples/test.jpg";
        File fp(file, O_RDONLY);
        EXPECT_TRUE(fp.ready());

        auto str = fp.read_content();

        EXPECT_EQ(resp->body, str->to_std_string());

        resp = cli.Get("/just/get/file");
        EXPECT_EQ(resp, nullptr);
        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, static_files) {
    test_base_server([](Server *serv) {
        serv->http_autoindex = true;
        serv->add_static_handler_location("");

        swoole_signal_block_all();
        auto port = serv->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);

        auto resp = cli.Get("/");
        EXPECT_EQ(resp->status, 200);
        std::string::size_type postion = resp->body.find("Index of");
        EXPECT_TRUE(postion != std::string::npos);

        // directory not exists
        resp = cli.Get("/test/../");
        EXPECT_EQ(resp->status, 404);

        // must be document_root
        resp = cli.Get("//tests/../");
        EXPECT_EQ(resp->status, 200);

        resp = cli.Get("/tests/../README.md");
        EXPECT_EQ(resp->status, 200);

        // file not exists
        resp = cli.Get("/not-exists.jpg");
        EXPECT_EQ(resp->status, 404);

        // try again
        serv->add_static_handler_index_files("README.md");
        resp = cli.Get("/");
        postion = resp->body.find("<h2 align=center>");
        EXPECT_TRUE(postion != std::string::npos);

        kill(getpid(), SIGTERM);
    });
}

static void request_with_header(const char *date_format, httplib::Client *cli) {
    char temp[128] = {0};
    time_t raw_time = time(NULL) + 7 * 24 * 60 * 60;
    tm *time_info = gmtime(&raw_time);

    strftime(temp, sizeof(temp), date_format, time_info);
    httplib::Headers headers = {{"If-Modified-Since", temp}};
    auto resp = cli->Get("/", headers);
    EXPECT_EQ(resp, nullptr);
}

TEST(http_server, not_modify) {
    test_base_server([](Server *serv) {
        serv->http_autoindex = true;
        serv->add_static_handler_location("");

        swoole_signal_block_all();
        auto port = serv->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);

        serv->add_static_handler_index_files("swoole-logo.svg");
        auto resp = cli.Get("/");
        EXPECT_EQ(resp->status, 200);

        // 304 not modified
        cli.set_read_timeout(0, 100);
        request_with_header(SW_HTTP_RFC1123_DATE_GMT, &cli);
        request_with_header(SW_HTTP_RFC1123_DATE_UTC, &cli);
        request_with_header(SW_HTTP_RFC850_DATE, &cli);
        request_with_header(SW_HTTP_ASCTIME_DATE, &cli);
        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, proxy_file) {
    Server *server = test_proxy_server();
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);

        auto resp = cli.Get("/just/get/file");
        ASSERT_EQ(resp, nullptr);
    }
}

// need fix
TEST(http_server, proxy_response) {
    Server *server = test_proxy_server();
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };
        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/");
        ASSERT_EQ(resp, nullptr);
        //        ASSERT_EQ(resp->body, string("hello world"));
    }
}

static void websocket_test(int server_port, const char *data, size_t length) {
    httplib::Client cli(TEST_HOST, server_port);

    httplib::Headers headers;
    EXPECT_TRUE(cli.Upgrade("/websocket", headers));
    EXPECT_TRUE(cli.Push(data, length));

    auto msg = cli.Recv();
    EXPECT_EQ(string(msg->payload, msg->payload_length), string("Swoole: ") + string(data, length));
}

TEST(http_server, websocket_small) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();
        websocket_test(serv->get_primary_port()->get_port(), SW_STRL("hello world, swoole is best!"));
        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, websocket_medium) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();

        swString str(8192);
        str.repeat("A", 1, 8192);
        websocket_test(serv->get_primary_port()->get_port(), str.value(), str.get_length());

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, websocket_big) {
    test_base_server([](Server *serv) {
        swoole_signal_block_all();

        swString str(128 * 1024);
        str.repeat("A", 1, str.capacity() - 1);
        websocket_test(serv->get_primary_port()->get_port(), str.value(), str.get_length());

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, parser1) {
    std::thread t;
    auto server = swoole::http_server::listen(":0", [](Context &ctx) {
        EXPECT_EQ(ctx.form_data.size(), 3);
        ctx.end("DONE");
    });
    server->worker_num = 1;
    server->onWorkerStart = [&t](Server *server, uint32_t worker_id) {
        t = std::thread([server]() {
            swoole_signal_block_all();
            string file = test::get_root_path() + "/core-tests/fuzz/cases/req1.bin";
            File fp(file, O_RDONLY);
            EXPECT_TRUE(fp.ready());
            auto str = fp.read_content();
            SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, server->get_primary_port()->port);
            c.send(str->value(), str->get_length());
            char buf[1024];
            auto n = c.recv(buf, sizeof(buf));
            c.close();
            std::string resp(buf, n);

            EXPECT_TRUE(resp.find("200 OK") != resp.npos);

            kill(server->get_master_pid(), SIGTERM);
        });
    };
    server->start();
    t.join();
}

TEST(http_server, parser2) {
    std::thread t;
    auto server = swoole::http_server::listen(":0", [](Context &ctx) {
        EXPECT_EQ(ctx.form_data.size(), 3);
        ctx.end("DONE");
    });
    server->worker_num = 1;
    server->get_primary_port()->set_package_max_length(64 * 1024);
    server->upload_max_filesize = 1024 * 1024;
    server->onWorkerStart = [&t](Server *server, uint32_t worker_id) {
        t = std::thread([server]() {
            swoole_signal_block_all();
            string file = test::get_root_path() + "/core-tests/fuzz/cases/req2.bin";
            File fp(file, O_RDONLY);
            EXPECT_TRUE(fp.ready());
            auto str = fp.read_content();
            SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, server->get_primary_port()->port);
            c.send(str->value(), str->get_length());
            char buf[1024];
            auto n = c.recv(buf, sizeof(buf));
            c.close();
            std::string resp(buf, n);

            EXPECT_TRUE(resp.find("200 OK") != resp.npos);

            kill(server->get_master_pid(), SIGTERM);
        });
    };
    server->start();
    t.join();
}

TEST(http_server, heartbeat) {
    Server *server = test_process_server();
    server->heartbeat_check_interval = 0;
    auto port = server->get_primary_port();
    port->set_package_max_length(1024);
    port->heartbeat_idle_time = 2;

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        sleep(1);
        port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/");
        ASSERT_EQ(resp->status, 200);
        ASSERT_EQ(resp->body, string("hello world"));
        sleep(10);
        resp = cli.Get("/");
        ASSERT_EQ(resp, nullptr);
    }
}

TEST(http_server, overflow) {
    Server *server = test_process_server();
    auto port = server->get_primary_port();

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        sleep(1);
        port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/");
        ASSERT_EQ(resp->status, 200);
        ASSERT_EQ(resp->body, string("hello world"));
        resp = cli.Get("/overflow");
        ASSERT_EQ(resp, nullptr);
    }
}

TEST(http_server, process) {
    Server *server = test_process_server();
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/");
        ASSERT_EQ(resp->status, 200);
        ASSERT_EQ(resp->body, string("hello world"));

        resp = cli.Get("/");
        ASSERT_EQ(resp->status, 200);
        ASSERT_EQ(resp->body, string("hello world"));
    }
}

TEST(http_server, process1) {
    Server *server = test_process_server();
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };
        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/index.html");
        ASSERT_EQ(resp->status, 200);
        ASSERT_EQ(resp->body, string("hello world"));

        sleep(1);
        resp = cli.Get("/examples/test.jpg");
        ASSERT_EQ(resp->status, 200);
    }
}

TEST(http_server, stream_mode) {
    Server *server = test_process_server(Server::DISPATCH_STREAM);
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };
        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/");
        ASSERT_EQ(resp->status, 200);
    }
}

TEST(http_server, redundant_callback) {
    Server *server = test_process_server(Server::DISPATCH_STREAM);
    server->onConnect = [](Server *serv, DataHead *info) -> int { return 0; };
    server->onClose = [](Server *serv, DataHead *info) -> int { return 0; };
    server->onBufferFull = [](Server *serv, DataHead *info) -> int { return 0; };
    server->onBufferEmpty = [](Server *serv, DataHead *info) -> int { return 0; };

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        ASSERT_EQ(server->onConnect, nullptr);
        ASSERT_EQ(server->onClose, nullptr);
        ASSERT_EQ(server->onBufferFull, nullptr);
        ASSERT_EQ(server->onBufferEmpty, nullptr);
        exit(0);
    }

    if (pid > 0) {
        sleep(2);
        kill(server->get_master_pid(), SIGTERM);
    }
}

TEST(http_server, pause) {
    Server *server = test_process_server();
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        cli.set_keep_alive(true);
        auto resp = cli.Get("/pause");
        ASSERT_EQ(resp->status, 200);
        ASSERT_EQ(resp->body, string("hello world"));

        resp = cli.Get("/");
        ASSERT_EQ(resp, nullptr);
    }
}

TEST(http_server, sni) {
    Server *server = test_process_server(Server::DISPATCH_FDMOD, true);
    ListenPort *port = server->get_primary_port();
    port->ssl_set_cert_file(test::get_root_path() + "/tests/include/ssl_certs/server.crt");
    port->ssl_set_key_file(test::get_root_path() + "/tests/include/ssl_certs/server.key");
    SSLContext *context = new SSLContext();
    *context = *port->ssl_context;
    context->cert_file = test::get_root_path() + "/tests/include/ssl_certs/sni_server_cs_cert.pem";
    context->key_file = test::get_root_path() + "/tests/include/ssl_certs/sni_server_cs_key.pem";
    port->ssl_add_sni_cert("localhost", context);
    port->ssl_context->protocols = 0;
    port->ssl_init();

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        string port_num = to_string(server->get_primary_port()->port);

        sleep(1);
        pid_t pid2;
        string command = "curl https://localhost:" + port_num + " -k -vvv --stderr /tmp/wwwsnitestcom.txt";
        swoole_shell_exec(command.c_str(), &pid2, 0);
        sleep(1);

        stringstream buffer;
        ifstream wwwsnitestcom;
        wwwsnitestcom.open("/tmp/wwwsnitestcom.txt");
        ASSERT_TRUE(wwwsnitestcom.is_open());
        buffer << wwwsnitestcom.rdbuf();
        wwwsnitestcom.close();
        string response(buffer.str());
        ASSERT_TRUE(response.find("CN=cs.php.net") != string::npos);

        string command2 = "curl https://127.0.0.1:" + port_num + " -k -vvv --stderr /tmp/wwwsnitest2com.txt";
        swoole_shell_exec(command2.c_str(), &pid2, 0);
        sleep(1);

        stringstream buffer2;
        ifstream wwwsnitest2com;
        wwwsnitest2com.open("/tmp/wwwsnitest2com.txt");
        ASSERT_TRUE(wwwsnitest2com.is_open());
        buffer2 << wwwsnitest2com.rdbuf();
        string response2(buffer2.str());
        wwwsnitest2com.close();
        ASSERT_TRUE(response2.find("CN=127.0.0.1") != string::npos);
    }
}

TEST(http_server, bad_request) {
    Server *server = test_process_server();

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };
        sleep(1);

        string str_1 = "curl -X UNKNOWN http://";
        string str_2 = ":";
        string str_3 = " -k -vvv --stderr /tmp/bad_request.txt";
        string host = TEST_HOST;
        string port = to_string(server->get_primary_port()->port);
        string command = str_1 + host + str_2 + port + str_3;

        pid_t pid2;
        swoole_shell_exec(command.c_str(), &pid2, 0);
        sleep(1);

        stringstream buffer;
        ifstream bad_request;
        bad_request.open("/tmp/bad_request.txt");
        ASSERT_TRUE(bad_request.is_open());
        buffer << bad_request.rdbuf();
        string response(buffer.str());
        bad_request.close();
        ASSERT_TRUE(response.find("400 Bad Request") != string::npos);
    }
}

TEST(http_server, chunked) {
    Server *server = test_process_server();

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };
        sleep(1);

        string jpg_path = swoole::test::get_jpg_file();
        string str_1 = "curl -H 'Transfer-Encoding: chunked' -F \"file=@" + jpg_path + "\" http://";
        string str_2 = ":";
        string host = TEST_HOST;
        string port = to_string(server->get_primary_port()->port);
        string command = str_1 + host + str_2 + port;

        pid_t pid2;
        int pipe = swoole_shell_exec(command.c_str(), &pid2, 0);
        sleep(1);

        char buf[1024] = {};
        read(pipe, buf, sizeof(buf) - 1);
        ASSERT_STREQ(buf, "hello world");
    }
}

TEST(http_server, max_queued_bytes) {
    Server *server = test_process_server();
    server->max_queued_bytes = 100;

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        sleep(1);

        string jpg_path = swoole::test::get_jpg_file();
        string str_1 = "curl -H 'Transfer-Encoding: chunked' -F \"file=@" + jpg_path + "\" http://";
        string str_2 = ":";
        string host = TEST_HOST;
        string port = to_string(server->get_primary_port()->port);
        string command = str_1 + host + str_2 + port;

        pid_t pid2;
        int pipe = swoole_shell_exec(command.c_str(), &pid2, 0);
        sleep(1);

        char buf[1024] = {};
        read(pipe, buf, sizeof(buf) - 1);
        ASSERT_STREQ(buf, "hello world");
    }
}

TEST(http_server, dispatch_func_return_error_worker_id) {
    Server *server = test_process_server();
    server->dispatch_func = [](Server *serv, Connection *conn, SendData *data) -> int {
        return data->info.fd % 2 == 0 ? Server::DISPATCH_RESULT_DISCARD_PACKET
                                      : Server::DISPATCH_RESULT_CLOSE_CONNECTION;
    };
    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    };

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };
        sleep(1);
        auto port = server->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        cli.set_read_timeout(1, 0);
        auto resp = cli.Get("/");
        ASSERT_EQ(resp, nullptr);
        resp = cli.Get("/");
        ASSERT_EQ(resp, nullptr);
    }
}

TEST(http_server, client_ca) {
    Server *server = test_process_server(Server::DISPATCH_FDMOD, true);
    ListenPort *port = server->get_primary_port();
    port->ssl_set_cert_file(test::get_root_path() + "/tests/include/api/ssl-ca/server-cert.pem");
    port->ssl_set_key_file(test::get_root_path() + "/tests/include/api/ssl-ca/server-key.pem");
    port->ssl_context->verify_peer = true;
    port->ssl_context->allow_self_signed = true;
    port->ssl_context->client_cert_file = test::get_root_path() + "/tests/include/api/ssl-ca/ca-cert.pem";
    port->ssl_init();

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        string port_num = to_string(server->get_primary_port()->port);

        sleep(1);
        pid_t pid2;
        string client_cert = " --cert " + test::get_root_path() + "/tests/include/api/ssl-ca/client-cert.pem ";
        string client_key = "--key " + test::get_root_path() + "/tests/include/api/ssl-ca/client-key.pem";
        string command = "curl https://127.0.0.1:" + port_num + " " + client_cert + client_key +
                         " -k -vvv --stderr /tmp/client_ca.txt";
        swoole_shell_exec(command.c_str(), &pid2, 0);
        sleep(1);

        stringstream buffer;
        ifstream client_ca;
        client_ca.open("/tmp/client_ca.txt");
        ASSERT_TRUE(client_ca.is_open());
        buffer << client_ca.rdbuf();
        client_ca.close();
        string response(buffer.str());
        ASSERT_TRUE(response.find("200 OK") != response.npos);
    }
}

static bool request_with_if_range_header(const char *date_format, std::string port) {
    struct stat file_stat;
    std::string file_path = test::get_root_path() + "/docs/swoole-logo.svg";
    stat(file_path.c_str(), &file_stat);
    time_t file_mtime = file_stat.st_mtim.tv_sec;
    struct tm *time_info = gmtime(&file_mtime);

    char temp[128] = {0};
    strftime(temp, sizeof(temp), date_format, time_info);

    string str_1 = "curl http://";
    string host = TEST_HOST;
    string str_2 = ":";
    string str_3 = "/docs/swoole-logo.svg -k -vvv --stderr /tmp/http_range.txt ";
    string headers = "-H 'Range: bytes=0-500' -H 'If-Range: ";
    string command = str_1 + host + str_2 + port + str_3 + headers + string(temp) + "'";

    pid_t pid;
    close(swoole_shell_exec(command.c_str(), &pid, 0));
    sleep(2);

    stringstream buffer;
    ifstream http_range;
    http_range.open("/tmp/http_range.txt");
    if (!http_range.is_open()) {
        return false;
    }

    buffer << http_range.rdbuf();
    string response(buffer.str());
    http_range.close();
    return response.find("206 Partial Content") != string::npos && response.find("Content-Length: 501") != string::npos;
}

TEST(http_server, http_range) {
    Server *server = test_process_server();
    server->http_autoindex = true;
    server->add_static_handler_location("/docs");

    pid_t pid = fork();

    if (pid == 0) {
        server->start();
        exit(0);
    }

    if (pid > 0) {
        sleep(1);
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        string port = to_string(server->get_primary_port()->port);
        ASSERT_TRUE(request_with_if_range_header(SW_HTTP_RFC1123_DATE_GMT, port));
        ASSERT_TRUE(request_with_if_range_header(SW_HTTP_RFC1123_DATE_UTC, port));
        ASSERT_TRUE(request_with_if_range_header(SW_HTTP_RFC850_DATE, port));
        ASSERT_TRUE(request_with_if_range_header(SW_HTTP_ASCTIME_DATE, port));
    }
}

static bool request_with_diff_range(std::string port, std::string range) {
    string str_1 = "curl -X GET http://";
    string host = TEST_HOST;
    string str_2 = ":";
    string str_3 = "/docs/swoole-logo.svg -k -vvv --stderr /tmp/http_range.txt ";
    string headers = "-H 'Range: bytes=" + range;
    string command = str_1 + host + str_2 + port + str_3 + headers + "'";

    pid_t pid;
    close(swoole_shell_exec(command.c_str(), &pid, 0));

    sleep(2);
    stringstream buffer;
    ifstream http_range;
    http_range.open("/tmp/http_range.txt");
    if (!http_range.is_open()) {
        return false;
    }

    buffer << http_range.rdbuf();
    string response(buffer.str());
    http_range.close();
    return response.find("206 Partial Content") != string::npos;
}

TEST(http_server, http_range2) {
    Server *server = test_process_server();
    server->add_static_handler_location("/docs");
    server->add_static_handler_index_files("swoole-logo.svg");

    pid_t pid = fork();

    if (pid > 0) {
        server->start();
        exit(0);
    }

    if (pid == 0) {
        sleep(1);
        ON_SCOPE_EXIT {
            kill(server->get_master_pid(), SIGTERM);
        };

        ASSERT_TRUE(request_with_diff_range(to_string(server->get_primary_port()->port), "0-15"));
        ASSERT_TRUE(request_with_diff_range(to_string(server->get_primary_port()->port), "16-31"));
        ASSERT_TRUE(request_with_diff_range(to_string(server->get_primary_port()->port), "-16"));
        ASSERT_TRUE(request_with_diff_range(to_string(server->get_primary_port()->port), "128-"));
        ASSERT_TRUE(request_with_diff_range(to_string(server->get_primary_port()->port), "0-0,-1"));

    }
}

// it is always last test
TEST(http_server, abort_connection) {
    Server serv(swoole::Server::MODE_PROCESS);
    serv.worker_num = 2;
    SwooleG.max_sockets = 2;
    serv.set_max_connection(1);
    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_http_protocol = 1;
    serv.create();

    serv.onWorkerStart = [](Server *serv, int worker_id) {
        auto port = serv->get_primary_port();
        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/");
        EXPECT_EQ(resp, nullptr);

        if (worker_id == 0) {
            sleep(1);
            kill(serv->get_master_pid(), SIGTERM);
        }
    };

    serv.onReceive = [&](Server *server, swRecvData *req) -> int { return SW_OK; };
    serv.start();
}
