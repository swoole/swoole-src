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
#include "swoole_protocol.h"

using namespace swoole;

TEST(protocol, default_length_requires_complete_field_at_offset) {
    Protocol protocol{};
    protocol.package_length_type = 'N';
    protocol.package_length_size = 4;
    protocol.package_length_offset = 2;
    protocol.package_body_offset = 6;
    const char header[] = {'x', 'y', 0, 0, 0, 9};
    for (uint32_t length = 0; length < sizeof(header); ++length) {
        PacketLength pl{header, length, 0};
        EXPECT_EQ(Protocol::default_length_func(&protocol, nullptr, &pl), 0);
        EXPECT_EQ(pl.header_len, sizeof(header));
    }
    PacketLength pl{header, sizeof(header), 0};
    EXPECT_EQ(Protocol::default_length_func(&protocol, nullptr, &pl), 15);
    EXPECT_EQ(pl.header_len, 4u);
}

TEST(protocol, default_length_rejects_zero_field_width_and_negative_lengths) {
    Protocol protocol{};
    const char header[] = {static_cast<char>(0xff)};
    PacketLength pl{header, sizeof(header), 0};
    EXPECT_EQ(Protocol::default_length_func(&protocol, nullptr, &pl), SW_ERR);
    protocol.package_length_size = 1;
    protocol.package_length_type = 'c';
    EXPECT_EQ(Protocol::default_length_func(&protocol, nullptr, &pl), SW_ERR);
    protocol.package_length_type = 'C';
    EXPECT_EQ(Protocol::default_length_func(&protocol, nullptr, &pl), 255);
    protocol.get_package_length_size = [](network::Socket *) -> uint8_t { return 0; };
    EXPECT_EQ(Protocol::default_length_func(&protocol, nullptr, &pl), SW_ERR);
}

#ifndef _WIN32
namespace {
class ProtocolFramingTest : public testing::Test {
  protected:
    void SetUp() override {
        saved_error = swoole_get_last_error();
        saved_errno = errno;
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        socket.fd = fds[1];
        socket.socket_type = SW_SOCK_UNIX_STREAM;
        ASSERT_TRUE(socket.set_nonblock());
        protocol.package_length_type = 'N';
        protocol.package_length_size = 4;
        protocol.package_body_offset = 4;
        protocol.package_max_length = 64;
        protocol.get_package_length = Protocol::default_length_func;
        protocol.package_eof_len = 2;
        memcpy(protocol.package_eof, "\r\n", 2);
        protocol.private_data_1 = this;
        protocol.onPackage = [](const Protocol *protocol, network::Socket *socket, const RecvData *data) {
            auto *test = static_cast<ProtocolFramingTest *>(protocol->private_data_1);
            test->packets.emplace_back(data->data, data->info.len);
            socket->removed = test->remove_on_package;
            return test->callback_result;
        };
    }

    void TearDown() override {
        for (const int fd : fds) {
            if (fd >= 0) {
                close(fd);
            }
        }
        swoole_set_last_error(saved_error);
        errno = saved_errno;
    }

    static std::string length_packet(const std::string &payload) {
        const uint32_t length = htonl(payload.size());
        return std::string(reinterpret_cast<const char *>(&length), sizeof(length)) + payload;
    }

    void send(const std::string &data) {
        ASSERT_EQ(::send(fds[0], data.data(), data.size(), 0), static_cast<ssize_t>(data.size()));
    }

    int receive_length() {
        return protocol.recv_with_length_protocol(&socket, &buffer);
    }

    int receive_eof() {
        return protocol.recv_with_eof_protocol(&socket, &buffer);
    }

    void close_peer() {
        ASSERT_EQ(close(fds[0]), 0);
        fds[0] = -1;
    }

    int fds[2] = {-1, -1};
    int saved_error = 0;
    int saved_errno = 0;
    network::Socket socket{};
    Protocol protocol{};
    String buffer{16};
    std::vector<std::string> packets;
    bool remove_on_package = false;
    int callback_result = SW_OK;
};
}  // namespace

TEST_F(ProtocolFramingTest, length_waits_for_header_and_body_fragments) {
    EXPECT_EQ(receive_length(), SW_OK);  // EAGAIN must leave the buffer untouched.
    const auto packet = length_packet(std::string("a\0bc", 4));
    send(packet.substr(0, 2));
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(buffer.length, 2u);
    EXPECT_TRUE(packets.empty());
    send(packet.substr(2, 3));
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_TRUE(socket.recv_wait);
    EXPECT_EQ(buffer.offset, packet.size());
    EXPECT_TRUE(packets.empty());
    send(packet.substr(5));
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{packet});
    EXPECT_FALSE(socket.recv_wait);
    EXPECT_EQ(buffer.length, 0u);
    EXPECT_EQ(buffer.offset, 0);
}

TEST_F(ProtocolFramingTest, length_grows_buffer_and_accepts_exact_limit) {
    const auto packet = length_packet(std::string(60, 'x'));
    send(packet);
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{packet});
    EXPECT_GE(buffer.size, packet.size());
}

TEST_F(ProtocolFramingTest, length_rejects_oversized_and_malformed_packets) {
    send(length_packet(std::string(61, 'x')));
    EXPECT_EQ(receive_length(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    EXPECT_TRUE(packets.empty());
    buffer.clear();
    protocol.get_package_length = [](const Protocol *, network::Socket *, PacketLength *) -> ssize_t { return -1; };
    socket.skip_recv = true;
    EXPECT_EQ(receive_length(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_MALFORMED_DATA);
}

TEST_F(ProtocolFramingTest, length_rejects_missing_length_in_complete_header) {
    protocol.get_package_length = [](const Protocol *, network::Socket *, PacketLength *) -> ssize_t { return 0; };
    send("abcd");
    EXPECT_EQ(receive_length(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_NOT_FOUND);
    EXPECT_TRUE(packets.empty());
}

TEST_F(ProtocolFramingTest, length_rejects_dynamic_zero_width_without_receiving) {
    protocol.get_package_length_size = [](network::Socket *) -> uint8_t { return 0; };
    send(length_packet("x"));
    EXPECT_EQ(receive_length(), SW_ERR);
    EXPECT_EQ(buffer.length, 0u);
}

TEST_F(ProtocolFramingTest, length_dispatches_coalesced_buffered_packets_before_reading) {
    const auto first = length_packet("first");
    const auto second = length_packet("second");
    buffer.append(first + second);
    socket.skip_recv = true;
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_FALSE(socket.skip_recv);
    EXPECT_EQ(packets, (std::vector<std::string>{first, second}));
    EXPECT_EQ(buffer.length, 0u);
}

TEST_F(ProtocolFramingTest, length_stops_after_callback_removes_socket) {
    buffer.append(length_packet("first") + length_packet("second"));
    socket.skip_recv = true;
    remove_on_package = true;
    EXPECT_EQ(receive_length(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0], length_packet("first"));
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets.size(), 1u);
}

TEST_F(ProtocolFramingTest, length_propagates_callback_failure) {
    callback_result = SW_ERR;
    send(length_packet("x"));
    EXPECT_EQ(receive_length(), SW_ERR);
    EXPECT_EQ(packets.size(), 1u);
}

TEST_F(ProtocolFramingTest, length_detects_peer_close_during_partial_body) {
    send(length_packet("body").substr(0, 6));
    close_peer();
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_TRUE(packets.empty());
    EXPECT_EQ(receive_length(), SW_ERR);
    EXPECT_TRUE(packets.empty());
}

TEST_F(ProtocolFramingTest, split_retains_partial_delimiter_and_dispatches_binary_packets) {
    buffer.append("x");
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_CONTINUE);
    buffer.append("\r");
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_CONTINUE);
    buffer.append(std::string("\na\0b\r\nt", 7));
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"x\r\n", std::string("a\0b\r\n", 5)}));
    EXPECT_EQ(buffer.to_std_string(), "t");
    EXPECT_EQ(buffer.offset, 0);
    buffer.append("\r\n");
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_OK);
    EXPECT_EQ(buffer.length, 0u);
    ASSERT_EQ(packets.size(), 3u);
    EXPECT_EQ(packets.back(), "t\r\n");
}

TEST_F(ProtocolFramingTest, split_stops_on_callback_failure_or_removal) {
    buffer.append("a\r\nb\r\n");
    callback_result = SW_ERR;
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_CLOSE);
    EXPECT_EQ(packets, std::vector<std::string>{"a\r\n"});
    buffer.offset = 0;
    packets.clear();
    callback_result = SW_OK;
    remove_on_package = true;
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_CLOSE);
    EXPECT_EQ(packets, std::vector<std::string>{"a\r\n"});
}

TEST_F(ProtocolFramingTest, eof_waits_for_fragments_then_reuses_buffer) {
    EXPECT_EQ(receive_eof(), SW_OK);
    send("a");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_TRUE(packets.empty());
    send("\r");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_TRUE(packets.empty());
    send("\n");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{"a\r\n"});
    EXPECT_EQ(buffer.length, 0u);
    send("b\r\n");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"a\r\n", "b\r\n"}));
}

TEST_F(ProtocolFramingTest, eof_splits_coalesced_packets_and_retains_tail) {
    protocol.split_by_eof = true;
    send("a\r\nb\r\ntail\r");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"a\r\n", "b\r\n"}));
    EXPECT_EQ(buffer.to_std_string(), "tail\r");
    send("\n");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets.back(), "tail\r\n");
}

TEST_F(ProtocolFramingTest, eof_grows_buffer_and_clamps_to_packet_limit) {
    send(std::string(40, 'x'));
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(buffer.size, protocol.package_max_length);
    EXPECT_EQ(buffer.length, 40u);
    send("\r\n");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{std::string(40, 'x') + "\r\n"});
}

TEST_F(ProtocolFramingTest, eof_rejects_unterminated_packet_at_limit) {
    send(std::string(protocol.package_max_length, 'x'));
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    EXPECT_EQ(buffer.length, protocol.package_max_length);
    EXPECT_TRUE(packets.empty());
}

TEST_F(ProtocolFramingTest, eof_accepts_terminated_packet_at_limit) {
    send(std::string(protocol.package_max_length - 2, 'x') + "\r\n");
    EXPECT_EQ(receive_eof(), SW_OK);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0].size(), protocol.package_max_length);
}

TEST_F(ProtocolFramingTest, eof_stops_when_callback_removes_socket) {
    remove_on_package = true;
    send("a\r\n");
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets.size(), 1u);
}

TEST_F(ProtocolFramingTest, eof_propagates_callback_failure) {
    callback_result = SW_ERR;
    send("a\r\n");
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_EQ(packets.size(), 1u);
}

TEST_F(ProtocolFramingTest, eof_split_propagates_callback_failure) {
    protocol.split_by_eof = true;
    callback_result = SW_ERR;
    send("a\r\n");
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_EQ(packets.size(), 1u);
}

TEST_F(ProtocolFramingTest, eof_detects_peer_close) {
    close_peer();
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_TRUE(packets.empty());
}

TEST_F(ProtocolFramingTest, receive_reports_nonfatal_socket_errors_without_dispatch) {
    ASSERT_EQ(close(fds[1]), 0);
    fds[1] = -1;
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_TRUE(packets.empty());
}
#endif
