#include "test_core.h"
#include "swoole_proxy.h"

using namespace swoole;

namespace {
class Socks5ProtocolTest : public testing::Test {
  protected:
    void SetUp() override {
        saved_error = swoole_get_last_error();
        proxy.socket_type = SW_SOCK_TCP;
        proxy.target_host = "example.test";
        proxy.target_port = 443;
        proxy.dns_tunnel = true;
        proxy.state = SW_SOCKS5_STATE_HANDSHAKE;
    }

    void TearDown() override {
        swoole_set_last_error(saved_error);
    }

    bool reply(const std::string &response) {
        return proxy.handshake(response.data(), response.size(), [&](const char *data, size_t length) -> ssize_t {
            sent.emplace_back(data, length);
            return length;
        });
    }

    std::string connect_request() const {
        return std::string("\x05\x01\x00\x03\x0c", 5) + "example.test" + std::string("\x01\xbb", 2);
    }

    Socks5Proxy proxy{};
    std::vector<std::string> sent;
    int saved_error = 0;
};
}  // namespace

TEST_F(Socks5ProtocolTest, no_authentication) {
    ASSERT_EQ(proxy.pack_negotiate_request(), 3);
    EXPECT_EQ(std::string(proxy.buf, 3), std::string("\x05\x01\x00", 3));
    ASSERT_TRUE(reply(std::string("\x05\x00", 2)));
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0], connect_request());
    EXPECT_EQ(proxy.state, SW_SOCKS5_STATE_CONNECT);
    ASSERT_TRUE(reply(std::string("\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb", 10)));
    EXPECT_EQ(proxy.state, SW_SOCKS5_STATE_READY);
    EXPECT_EQ(sent.size(), 1u);
}

TEST_F(Socks5ProtocolTest, username_password_authentication) {
    proxy.username = "user";
    proxy.password = "pass";
    ASSERT_EQ(proxy.pack_negotiate_request(), 3);
    EXPECT_EQ(std::string(proxy.buf, 3), std::string("\x05\x01\x02", 3));
    ASSERT_TRUE(reply(std::string("\x05\x02", 2)));
    EXPECT_EQ(proxy.state, SW_SOCKS5_STATE_AUTH);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0], std::string("\x01\x04", 2) + "user" + std::string("\x04", 1) + "pass");
    ASSERT_TRUE(reply(std::string("\x01\x00", 2)));
    EXPECT_EQ(proxy.state, SW_SOCKS5_STATE_CONNECT);
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[1], connect_request());
    ASSERT_TRUE(reply(std::string("\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb", 10)));
    EXPECT_EQ(proxy.state, SW_SOCKS5_STATE_READY);
}

TEST_F(Socks5ProtocolTest, rejects_invalid_replies_without_sending) {
    struct Case {
        uint8_t state;
        std::string response;
        int error;
    };
    const Case cases[] = {
        {SW_SOCKS5_STATE_HANDSHAKE, std::string("\x04\x00", 2), SW_ERROR_SOCKS5_UNSUPPORT_VERSION},
        {SW_SOCKS5_STATE_HANDSHAKE, std::string("\x05\xff", 2), SW_ERROR_SOCKS5_UNSUPPORT_METHOD},
        {SW_SOCKS5_STATE_AUTH, std::string("\x05\x00", 2), SW_ERROR_SOCKS5_UNSUPPORT_VERSION},
        {SW_SOCKS5_STATE_AUTH, std::string("\x01\x01", 2), SW_ERROR_SOCKS5_AUTH_FAILED},
        {SW_SOCKS5_STATE_CONNECT, std::string("\x04\x00", 2), SW_ERROR_SOCKS5_UNSUPPORT_VERSION},
        {SW_SOCKS5_STATE_CONNECT, std::string("\x05\x05", 2), SW_ERROR_SOCKS5_SERVER_ERROR},
        {SW_SOCKS5_STATE_CONNECT, std::string("\x05\x00\x00\xff", 4), SW_ERROR_SOCKS5_HANDSHAKE_FAILED},
        {SW_SOCKS5_STATE_CONNECT, std::string("\x05\x05\x00\xff", 4), SW_ERROR_SOCKS5_SERVER_ERROR},
    };
    for (const auto &item : cases) {
        SCOPED_TRACE(testing::PrintToString(item.response));
        proxy.response.clear();
        proxy.state = item.state;
        proxy.method = SW_SOCKS5_METHOD_NO_AUTH;
        EXPECT_FALSE(reply(item.response));
        EXPECT_ERREQ(item.error);
        EXPECT_EQ(proxy.state, item.state);
        EXPECT_TRUE(sent.empty());
    }
}

TEST_F(Socks5ProtocolTest, rejects_failed_or_partial_writes) {
    for (const auto state : {SW_SOCKS5_STATE_HANDSHAKE, SW_SOCKS5_STATE_AUTH}) {
        for (const bool partial : {false, true}) {
            SCOPED_TRACE(state);
            SCOPED_TRACE(partial);
            proxy.state = state;
            proxy.method = SW_SOCKS5_METHOD_AUTH;
            proxy.username = "user";
            proxy.password = "pass";
            const auto response =
                state == SW_SOCKS5_STATE_AUTH ? std::string("\x01\x00", 2) : std::string("\x05\x02", 2);
            size_t sends = 0;
            EXPECT_FALSE(proxy.handshake(response.data(), response.size(), [&](const char *, size_t length) -> ssize_t {
                sends++;
                return partial ? static_cast<ssize_t>(length) - 1 : -1;
            }));
            EXPECT_EQ(sends, 1u);
            EXPECT_NE(proxy.state, SW_SOCKS5_STATE_READY);
        }
    }
}

TEST_F(Socks5ProtocolTest, credential_length_boundaries) {
    std::unique_ptr<Socks5Proxy> accepted(
        Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, std::string(250, 'u'), std::string(250, 'p')));
    ASSERT_NE(accepted, nullptr);
    ASSERT_EQ(accepted->pack_auth_request(), 503);
    const auto expected =
        std::string("\x01\xfa", 2) + std::string(250, 'u') + std::string("\xfa", 1) + std::string(250, 'p');
    EXPECT_EQ(std::string(accepted->buf, expected.size()), expected);
    for (const bool long_username : {false, true}) {
        std::unique_ptr<Socks5Proxy> rejected(Socks5Proxy::create(SW_SOCK_TCP,
                                                                  "127.0.0.1",
                                                                  1080,
                                                                  std::string(long_username ? 251 : 1, 'u'),
                                                                  std::string(long_username ? 1 : 251, 'p')));
        EXPECT_EQ(rejected, nullptr);
        EXPECT_ERREQ(SW_ERROR_SOCKS5_AUTH_FAILED);
    }
}

TEST_F(Socks5ProtocolTest, domain_length_boundaries) {
    proxy.target_host.assign(255, 'h');
    proxy.target_port = 65535;
    ASSERT_EQ(proxy.pack_connect_request(), 262);
    EXPECT_EQ(std::string(proxy.buf, 262),
              std::string("\x05\x01\x00\x03\xff", 5) + std::string(255, 'h') + std::string("\xff\xff", 2));
    proxy.target_host.push_back('h');
    EXPECT_EQ(proxy.pack_connect_request(), SW_ERR);
    EXPECT_ERREQ(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
    proxy.method = SW_SOCKS5_METHOD_NO_AUTH;
    EXPECT_FALSE(reply(std::string("\x05\x00", 2)));
    EXPECT_TRUE(sent.empty());
}

TEST_F(Socks5ProtocolTest, packs_ipv4_and_ipv6_without_remote_dns) {
    proxy.dns_tunnel = false;
    proxy.target_host = "127.0.0.1";
    ASSERT_EQ(proxy.pack_connect_request(), 10);
    EXPECT_EQ(std::string(proxy.buf, 10), std::string("\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb", 10));
    proxy.socket_type = SW_SOCK_TCP6;
    proxy.target_host = "::1";
    ASSERT_EQ(proxy.pack_connect_request(), 22);
    EXPECT_EQ(std::string(proxy.buf, 22),
              std::string("\x05\x01\x00\x04", 4) + std::string(15, '\0') + std::string("\x01\x01\xbb", 3));
}

TEST_F(Socks5ProtocolTest, rejects_non_ip_and_unsupported_socket_types_without_remote_dns) {
    proxy.dns_tunnel = false;
    proxy.target_host = "example.test";
    EXPECT_EQ(proxy.pack_connect_request(), SW_ERR);
    EXPECT_ERREQ(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
    proxy.socket_type = SW_SOCK_UNIX_STREAM;
    proxy.target_host = "/tmp/swoole-socks5-test.sock";
    EXPECT_EQ(proxy.pack_connect_request(), SW_ERR);
    EXPECT_ERREQ(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);
}
