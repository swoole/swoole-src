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
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "tests.h"
#include "httplib_client.h"
#include "llhttp.h"
#include "http.h"
#include "wrapper/client.hpp"
#include "swoole_log.h"

using namespace swoole;
using namespace std;

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

    void response(int code, string body) {
        response_headers["Content-Length"] = to_string(body.length());
        response(code);
        server->send(server, fd, body.c_str(), body.length());
    }

    void response(int code) {
        swString *buf = swoole::make_string(1024);
        buf->length = sw_snprintf(buf->str, buf->size, "HTTP/1.1 %s\r\n", swHttp_get_status_message(code));
        for (auto &kv : response_headers) {
            swString_append_ptr(buf, kv.first.c_str(), kv.first.length());
            swString_append_ptr(buf, SW_STRL(": "));
            swString_append_ptr(buf, kv.second.c_str(), kv.second.length());
            swString_append_ptr(buf, SW_STRL("\r\n"));
        }
        swString_append_ptr(buf, SW_STRL("\r\n"));
        server->send(server, fd, buf->str, buf->length);
        swString_free(buf);
    }
};

static int handle_on_message_complete(llhttp_t* parser) {
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

static void test_run_server(function<void(swServer *)> fn) {
    thread child_thread;
    swServer serv(SW_MODE_BASE);
    serv.worker_num = 1;
    serv.ptr2 = (void *) &fn;

    serv.enable_static_handler = true;
    serv.set_document_root(test::get_root_path());
    serv.add_static_handler_location("/examples");

    sw_logger()->set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_http_protocol = 1;
    port->open_websocket_protocol = 1;

    serv.create();

    serv.onWorkerStart = [&child_thread](swServer *serv, int worker_id) {
        function<void(swServer *)> fn = *(function<void(swServer *)> *) serv->ptr2;
        child_thread = thread(fn, serv);
    };

    serv.onReceive = [](swServer *serv, swEventData *task) -> int {
        char *data = nullptr;
        size_t length = serv->get_packet(serv, task, &data);

        llhttp_t parser = {};
        llhttp_settings_t settings = {};
        llhttp_init(&parser, HTTP_REQUEST, &settings);

        http_context ctx = {};
        parser.data = &ctx;

        settings.on_url = handle_on_url;
        settings.on_header_field = handle_on_header_field;
        settings.on_header_value = handle_on_header_value;
        settings.on_message_complete = handle_on_message_complete;

        enum llhttp_errno err = llhttp_execute(&parser, data, length);

        if (err == HPE_PAUSED_UPGRADE) {
            ctx.server = serv;
            ctx.fd = task->info.fd;

            ctx.setHeader("Connection", "Upgrade");
            ctx.setHeader("Sec-WebSocket-Accept", "IIRiohCjop4iJrmvySrFcwcXpHo=");
            ctx.setHeader("Sec-WebSocket-Version", "13");
            ctx.setHeader("Upgrade", "websocket");
            ctx.setHeader("Content-Length", "0");

            ctx.response(101);

            return SW_OK;
        }

        if (err != HPE_OK) {
            fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
                    parser.reason);
            return SW_ERR;
        }
        EXPECT_EQ(err, HPE_OK);

        ctx.server = serv;
        ctx.fd = task->info.fd;
        ctx.response(200, "hello world");

        EXPECT_EQ(ctx.headers["User-Agent"], httplib::USER_AGENT);

        return SW_OK;
    };

    serv.start();
    child_thread.join();
}

TEST(http_server, get) {
    test_run_server([](swServer *serv) {
        swSignal_none();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp->status, 200);
        EXPECT_EQ(resp->body, string("hello world"));

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, post) {
    test_run_server([](swServer *serv) {
        swSignal_none();

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
    test_run_server([](swServer *serv) {
        swSignal_none();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/examples/test.jpg");
        EXPECT_EQ(resp->status, 200);

        string file = test::get_root_path() + "/examples/test.jpg";
        int fd = open(file.c_str(), O_RDONLY);
        EXPECT_GT(fd, 0);

        String str(swoole_sync_readfile_eof(fd));

        EXPECT_EQ(resp->body, str.to_std_string());

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, websocket) {
    test_run_server([](swServer *serv) {
        swSignal_none();

        auto port = serv->get_primary_port();

        httplib::Headers headers;

        headers.emplace("Connection", "Upgrade");
        headers.emplace("Upgrade", "websocket");
        headers.emplace("Sec-Websocket-Key", "sN9cRrP/n9NdMgdcy2VJFQ==");
        headers.emplace("Sec-WebSocket-Version", "13");

        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/websocket", headers);
        EXPECT_EQ(resp->status, 101);

        kill(getpid(), SIGTERM);
    });
}
