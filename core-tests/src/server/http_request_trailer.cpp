#include "test_core.h"
#include "swoole_http.h"
#include "swoole_server.h"

using namespace swoole;

TEST(http_server, ignore_http1_request_trailers) {
    std::unique_ptr<network::AsyncClient> client;
    std::string response;
    bool completed = false;
    auto server = http_server::listen(":0", [](http_server::Context &ctx) {
        EXPECT_EQ(ctx.headers["Content-Type"], "text/plain");
        EXPECT_EQ(ctx.headers["Cookie"], "initial=yes");
        EXPECT_EQ(ctx.headers.count("X-Trailer"), 0);
        ctx.end("DONE");
    });
    ASSERT_NE(server, nullptr);
    server->worker_num = 1;
    server->onStart = [&](Server *server) {
        client.reset(new network::AsyncClient(SW_SOCK_TCP));
        client->on_connect([](network::AsyncClient *client) {
            const std::string request = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                                        "Content-Type: text/plain\r\nCookie: initial=yes\r\n"
                                        "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n"
                                        "Content-Type: multipart/form-data\r\nCookie: extra=no\r\n"
                                        "X-Trailer: ignored\r\n\r\n";
            EXPECT_EQ(client->send(request), (ssize_t) request.size());
        });
        client->on_receive(
            [&](network::AsyncClient *, const char *data, size_t length) { response.append(data, length); });
        client->on_close([&, server](network::AsyncClient *) {
            EXPECT_NE(response.find("200 OK"), std::string::npos);
            EXPECT_NE(response.find("\r\n\r\nDONE"), std::string::npos);
            completed = true;
            server->shutdown();
        });
        client->on_error([server](network::AsyncClient *) {
            ADD_FAILURE() << "HTTP test client failed to connect";
            server->shutdown();
        });
        EXPECT_TRUE(client->connect(TEST_HOST, server->get_primary_port()->port, 3));
    };
    ASSERT_EQ(server->start(), SW_OK);
    EXPECT_TRUE(completed);
}
