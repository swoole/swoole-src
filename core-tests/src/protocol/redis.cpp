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
#include "swoole_redis.h"

using namespace swoole;
using namespace std;

const std::string REDIS_TEST_KEY = "key-swoole";
const std::string REDIS_TEST_VALUE = "value-swoole";

TEST(redis, get) {
    test::coroutine::run([](void *arg) {
        RedisClient redis;
        ASSERT_TRUE(redis.Connect("127.0.0.1", 6379));
        ASSERT_TRUE(redis.Set(REDIS_TEST_KEY, REDIS_TEST_VALUE));
        ASSERT_EQ(redis.Get(REDIS_TEST_KEY), REDIS_TEST_VALUE);
    });
}

TEST(redis, server) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.enable_static_handler = true;

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->open_redis_protocol = true;

    serv.create();
    std::unordered_map<std::string, std::string> redis_data;

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id != 0) {
            return;
        }
        swoole::Coroutine::create(
            [](void *arg) {
                Server *serv = reinterpret_cast<Server *>(arg);
                RedisClient redis;
                ASSERT_TRUE(redis.Connect("127.0.0.1", serv->get_primary_port()->port));
                ASSERT_TRUE(redis.Set(REDIS_TEST_KEY, REDIS_TEST_VALUE));
                ASSERT_EQ(redis.Get(REDIS_TEST_KEY), REDIS_TEST_VALUE);

                ASSERT_EQ(redis.Get(REDIS_TEST_KEY + "-not-exists"), "");

                String rdata;
                rdata.append_random_bytes(128 * 1024, true);
                auto data = rdata.to_std_string();

                ASSERT_TRUE(redis.Set(REDIS_TEST_KEY + "-big-key", data));
                ASSERT_EQ(redis.Get(REDIS_TEST_KEY + "-big-key"), data);
                ASSERT_EQ(redis.Ttl(REDIS_TEST_KEY), -1);
                ASSERT_FALSE(redis.Select(1));
                ASSERT_EQ(redis.Role(), "master");

                kill(serv->gs->master_pid, SIGTERM);
            },
            serv);
    };

    serv.onReceive = [&redis_data](Server *serv, RecvData *req) -> int {
        int session_id = req->info.fd;
        auto list = redis::parse(req->data, req->info.len);

        String *buffer = sw_tg_buffer();
        buffer->clear();

        if (strcasecmp(list[0].c_str(), "GET") == 0) {
            auto result = redis_data.find(list[1]);
            if (result == redis_data.end()) {
                redis::format_nil(buffer);
            } else {
                char buf[64];
                auto n = snprintf(buf, sizeof(buf), "$%zu\r\n", result->second.length());
                serv->send(session_id, buf, n);
                serv->send(session_id, result->second.c_str(), result->second.length());
                serv->send(session_id, SW_CRLF, SW_CRLF_LEN);
                return SW_OK;
            }
        } else if (strcasecmp(list[0].c_str(), "SET") == 0) {
            redis::format(buffer, redis::REPLY_STATUS, "OK");
            redis_data[list[1]] = list[2];
        } else if (strcasecmp(list[0].c_str(), "TTL") == 0) {
            redis::format(buffer, redis::REPLY_INT, -1);
        } else if (strcasecmp(list[0].c_str(), "ROLE") == 0) {
            redis::format(buffer, redis::REPLY_STRING, "master");
        } else {
            redis::format(buffer, redis::REPLY_ERROR, "Not Suppport");
        }

        serv->send(session_id, buffer->str, buffer->length);
        return SW_OK;
    };

    serv.start();
}

TEST(redis, format) {
    auto buf = sw_tg_buffer();

    buf->clear();
    redis::format(buf, redis::REPLY_STATUS, "");
    ASSERT_EQ(std::string(buf->str, buf->length), "+OK\r\n");

    buf->clear();
    redis::format(buf, redis::REPLY_ERROR, "");
    ASSERT_EQ(std::string(buf->str, buf->length), "-ERR\r\n");
}

TEST(redis, parse) {
    auto buf = sw_tg_buffer();

    buf->clear();
    auto rs = redis::parse(SW_STRL(":3\r\n"));
    ASSERT_EQ(rs.size(), 1u);
    ASSERT_EQ(rs[0], "3");
}

TEST(redis, parse_incomplete) {
    auto rs = redis::parse(SW_STRL("*1\r\n$3\r\n"));
    ASSERT_TRUE(rs.empty());
}

TEST(redis, recv_packet_with_partially_filled_buffer) {
    int pairs[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, pairs), 0);
    ASSERT_EQ(send(pairs[0], "*", 1, 0), 1);
    close(pairs[0]);

    network::Socket socket{};
    socket.fd = pairs[1];
    socket.socket_type = SW_SOCK_UNIX_STREAM;

    Connection conn{};
    conn.fd = pairs[1];
    conn.socket = &socket;

    Protocol protocol{};
    protocol.package_max_length = SW_BUFFER_SIZE_BIG * 2;

    String buffer(SW_BUFFER_SIZE_BIG);
    size_t buffer_size = buffer.size;

    ASSERT_EQ(redis::recv_packet(&protocol, &conn, &buffer), SW_ERR);
    ASSERT_EQ(buffer.length, 1);
    ASSERT_EQ(buffer.size, buffer_size);

    sw_free(conn.object);
    close(pairs[1]);
}

TEST(redis, format_empty_bulk_string) {
    String buffer;
    redis::format(&buffer, redis::REPLY_STRING, std::string{});
    EXPECT_EQ(buffer.to_std_string(), "$0\r\n\r\n");
}

TEST(redis, format_binary_bulk_and_signed_integer) {
    String buffer;
    redis::format(&buffer, redis::REPLY_STRING, std::string("a\0b", 3));
    EXPECT_EQ(buffer.to_std_string(), std::string("$3\r\na\0b\r\n", 9));
    buffer.clear();
    redis::format_nil(&buffer);
    EXPECT_EQ(buffer.to_std_string(), "$-1\r\n");
    buffer.clear();
    redis::format(&buffer, redis::REPLY_INT, LONG_MIN);
    EXPECT_EQ(buffer.to_std_string(), ":" + std::to_string(LONG_MIN) + "\r\n");
    buffer.clear();
    redis::format(&buffer, redis::REPLY_INT, LONG_MAX);
    EXPECT_EQ(buffer.to_std_string(), ":" + std::to_string(LONG_MAX) + "\r\n");
}

TEST(redis, parse_binary_empty_and_nil_bulk_strings) {
    const std::string packet = std::string("*4\r\n$3\r\na\0b\r\n", 13) + "$0\r\n\r\n$-1\r\n:-42\r\n";
    const auto parsed = redis::parse(packet.data(), packet.size());
    const std::vector<std::string> expected = {std::string("a\0b", 3), "", "-42"};
    EXPECT_EQ(parsed, expected);
}

TEST(redis, parse_preserves_complete_arguments_before_incomplete_bulk) {
    const std::string packet = "*2\r\n$3\r\nGET\r\n$5\r\nhel";
    EXPECT_EQ(redis::parse(packet.data(), packet.size()), std::vector<std::string>{"GET"});
}

#ifndef _WIN32
namespace {
class RedisProtocolTest : public testing::Test {
  protected:
    void SetUp() override {
        saved_error = swoole_get_last_error();
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        socket.fd = fds[1];
        socket.socket_type = SW_SOCK_UNIX_STREAM;
        ASSERT_TRUE(socket.set_nonblock());
        conn.fd = fds[1];
        conn.socket = &socket;
        protocol.package_max_length = 256;
        protocol.private_data_1 = this;
        protocol.onPackage = [](const Protocol *protocol, network::Socket *socket, const RecvData *data) {
            auto *test = static_cast<RedisProtocolTest *>(protocol->private_data_1);
            test->packets.emplace_back(data->data, data->info.len);
            if (test->remove_on_package) {
                socket->removed = true;
            }
            return test->callback_result;
        };
    }

    void TearDown() override {
        sw_free(conn.object);
        for (int fd : fds) {
            if (fd >= 0) {
                close(fd);
            }
        }
        swoole_set_last_error(saved_error);
    }

    int receive() {
        return redis::recv_packet(&protocol, &conn, &buffer);
    }

    void send(const std::string &packet) {
        ASSERT_EQ(::send(fds[0], packet.data(), packet.size(), 0), static_cast<ssize_t>(packet.size()));
    }

    int fds[2] = {-1, -1};
    int saved_error = 0;
    network::Socket socket{};
    Connection conn{};
    Protocol protocol{};
    String buffer{16};
    std::vector<std::string> packets;
    int callback_result = SW_OK;
    bool remove_on_package = false;
};
}  // namespace

TEST_F(RedisProtocolTest, empty_nonblocking_socket_waits_for_data) {
    EXPECT_EQ(receive(), SW_OK);
    EXPECT_TRUE(packets.empty());
    EXPECT_EQ(buffer.length, 0u);
}

TEST_F(RedisProtocolTest, reuses_request_after_complete_packet) {
    const std::string packet = "*1\r\n$3\r\nfoo\r\n";
    for (size_t i = 0; i < 2; i++) {
        send(packet);
        ASSERT_EQ(receive(), SW_OK);
        ASSERT_EQ(packets.size(), i + 1);
        EXPECT_EQ(packets.back(), packet);
        EXPECT_EQ(buffer.length, 0u);
    }
}

TEST_F(RedisProtocolTest, fragmented_bulk_waits_for_final_crlf) {
    const std::string packet = "*1\r\n$5\r\nhello\r\n";
    send(packet.substr(0, packet.size() - 3));
    ASSERT_EQ(receive(), SW_OK);
    EXPECT_TRUE(packets.empty());
    EXPECT_EQ(buffer.length, packet.size() - 3);
    send(packet.substr(packet.size() - 3));
    ASSERT_EQ(receive(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], packet);
    EXPECT_EQ(buffer.length, 0u);
}

TEST_F(RedisProtocolTest, crlf_inside_fragmented_bulk_is_not_a_packet_boundary) {
    const std::string packet = "*1\r\n$6\r\nab\r\ncd\r\n";
    send(packet.substr(0, 12));
    ASSERT_EQ(receive(), SW_OK);
    EXPECT_TRUE(packets.empty());
    send(packet.substr(12));
    ASSERT_EQ(receive(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], packet);
    EXPECT_EQ(buffer.length, 0u);
}

TEST_F(RedisProtocolTest, buffer_growth_stops_at_package_limit) {
    protocol.package_max_length = 24;
    const std::string packet = "*1\r\n$12\r\n" + std::string(12, 'x') + "\r\n";
    send(packet);
    ASSERT_EQ(receive(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], packet);
    EXPECT_EQ(buffer.size, protocol.package_max_length);
}

TEST_F(RedisProtocolTest, buffer_growth_clamps_page_alignment_to_package_limit) {
    const std::string packet = "*1\r\n$128\r\n" + std::string(128, 'x') + "\r\n";
    send(packet);
    ASSERT_EQ(receive(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], packet);
    EXPECT_EQ(buffer.size, protocol.package_max_length);
}

TEST_F(RedisProtocolTest, rejects_oversized_declared_bulk) {
    send("*1\r\n$1000\r\n");
    EXPECT_EQ(receive(), SW_ERR);
    EXPECT_TRUE(packets.empty());
}

TEST_F(RedisProtocolTest, rejects_unterminated_packet_at_buffer_limit) {
    send(std::string(protocol.package_max_length, 'x'));
    EXPECT_EQ(receive(), SW_ERR);
    EXPECT_EQ(buffer.length, protocol.package_max_length);
    EXPECT_EQ(buffer.size, protocol.package_max_length);
    EXPECT_TRUE(packets.empty());
}

TEST_F(RedisProtocolTest, rejects_malformed_array_length) {
    send("*x\r\n");
    EXPECT_EQ(receive(), SW_ERR);
    EXPECT_TRUE(packets.empty());
}

TEST_F(RedisProtocolTest, rejects_malformed_bulk_length) {
    send("*1\r\n$x\r\n");
    EXPECT_EQ(receive(), SW_ERR);
    EXPECT_TRUE(packets.empty());
}

TEST_F(RedisProtocolTest, rejects_malformed_integer) {
    send("*1\r\n:x\r\n");
    EXPECT_EQ(receive(), SW_ERR);
    EXPECT_TRUE(packets.empty());
}

TEST_F(RedisProtocolTest, propagates_callback_failure) {
    callback_result = SW_ERR;
    const std::string packet = "*1\r\n$3\r\nfoo\r\n";
    send(packet);
    EXPECT_EQ(receive(), SW_ERR);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], packet);
}

TEST_F(RedisProtocolTest, callback_may_remove_socket) {
    remove_on_package = true;
    const std::string packet = "*1\r\n$3\r\nfoo\r\n";
    send(packet);
    EXPECT_EQ(receive(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], packet);
    EXPECT_TRUE(socket.removed);
}
#endif
