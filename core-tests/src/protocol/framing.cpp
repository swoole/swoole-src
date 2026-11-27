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

TEST(protocol, resolve_package_length_status) {
    Protocol protocol{};
    protocol.package_length_type = 'N';
    protocol.package_length_size = 4;
    protocol.package_body_offset = 4;
    protocol.package_max_length = 64;
    protocol.get_package_length = Protocol::default_length_func;
    const char header[] = {0, 0, 0, 10, 'x'};
    ssize_t length = -1;
    uint32_t header_len = 99;

    EXPECT_EQ(protocol.resolve_package_length(nullptr, header, 3, &length, &header_len),
              PackageLengthStatus::NEED_MORE);
    EXPECT_EQ(length, 0);
    EXPECT_EQ(header_len, 4u);  // updated from the length function
    EXPECT_EQ(protocol.resolve_package_length(nullptr, header, 5, &length), PackageLengthStatus::OK);
    EXPECT_EQ(length, 14);

    const char big[] = {0, 0, 1, 0};
    EXPECT_EQ(protocol.resolve_package_length(nullptr, big, 4, &length), PackageLengthStatus::TOO_LARGE);
    EXPECT_EQ(length, 260);

    const char negative[] = {
        static_cast<char>(0xff), static_cast<char>(0xff), static_cast<char>(0xff), static_cast<char>(0xff)};
    protocol.package_length_type = 'l';
    EXPECT_EQ(protocol.resolve_package_length(nullptr, negative, 4, &length), PackageLengthStatus::MALFORMED);
}

TEST(protocol, resolve_package_length_uses_limit_from_before_callback) {
    Protocol protocol{};
    protocol.package_max_length = 8;
    protocol.get_package_length = [](const Protocol *current, network::Socket *, PacketLength *) -> ssize_t {
        const_cast<Protocol *>(current)->package_max_length = 16;
        return 12;
    };

    ssize_t length = 0;
    EXPECT_EQ(protocol.resolve_package_length(nullptr, "x", 1, &length), PackageLengthStatus::TOO_LARGE);
    EXPECT_EQ(length, 12);
}

TEST(protocol, set_package_eof) {
    Protocol protocol{};
    std::string eof(sizeof(protocol.package_eof), 'x');
    eof[0] = '\0';
    ASSERT_TRUE(protocol.set_package_eof(eof.data(), eof.size()));

    EXPECT_FALSE(protocol.set_package_eof("", 0));
    const std::string oversized(eof.size() + 1, 'y');
    EXPECT_FALSE(protocol.set_package_eof(oversized.data(), oversized.size()));
    EXPECT_EQ(protocol.package_eof_len, eof.size());
    EXPECT_MEMEQ(protocol.package_eof, eof.data(), eof.size());
}

TEST(protocol, find_eof_end_and_growth) {
    Protocol protocol{};
    protocol.package_eof_len = 2;
    memcpy(protocol.package_eof, "\r\n", 2);
    EXPECT_EQ(protocol.find_eof_end("ab\r", 3), -1);
    EXPECT_EQ(protocol.find_eof_end("ab\r\ncd", 7), 4);
    EXPECT_EQ(protocol.find_eof_end("\r\n", 2), 2);
    EXPECT_EQ(protocol.find_eof_end("", 0), -1);

    protocol.package_max_length = 10000;
    EXPECT_EQ(protocol.next_eof_buffer_size(16),
              static_cast<size_t>(swoole_size_align(32, swoole_pagesize())) > 10000
                  ? 10000u
                  : swoole_size_align(32, swoole_pagesize()));
    protocol.package_max_length = 100;
    EXPECT_EQ(protocol.next_eof_buffer_size(80), 100u);
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
            if (test->pause_on_package) {
                socket->recv_paused = 1;
                socket->events = SW_EVENT_WRITE;
            }
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
    bool pause_on_package = false;
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
    EXPECT_EQ(protocol.recv_split_by_eof(&socket, &buffer), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{"a\r\n"});
    EXPECT_EQ(buffer.to_std_string(), "b\r\n");
}

TEST_F(ProtocolFramingTest, length_pause_with_write_retains_undelivered_packets) {
    pause_on_package = true;
    const auto first = length_packet("first");
    const auto second = length_packet("second");
    buffer.append(first + second);
    socket.skip_recv = true;
    ASSERT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{first});
    EXPECT_FALSE(socket.removed);
    EXPECT_EQ(socket.events, SW_EVENT_WRITE);
    EXPECT_EQ(buffer.to_std_string(), second);
    EXPECT_TRUE(socket.skip_recv);
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets.size(), 1u);

    pause_on_package = false;
    socket.recv_paused = 0;
    ASSERT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{first, second}));
    EXPECT_EQ(buffer.length, 0u);
    EXPECT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets.size(), 2u);
}

TEST_F(ProtocolFramingTest, eof_pause_with_write_retains_undelivered_packets) {
    protocol.split_by_eof = true;
    pause_on_package = true;
    buffer.append("a\r\nb\r\n");
    socket.skip_recv = true;
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{"a\r\n"});
    EXPECT_FALSE(socket.removed);
    EXPECT_EQ(socket.events, SW_EVENT_WRITE);
    EXPECT_EQ(buffer.to_std_string(), "b\r\n");
    EXPECT_TRUE(socket.skip_recv);
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets.size(), 1u);

    pause_on_package = false;
    socket.recv_paused = 0;
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"a\r\n", "b\r\n"}));
    EXPECT_EQ(buffer.length, 0u);
    EXPECT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets.size(), 2u);
}

TEST_F(ProtocolFramingTest, length_resume_uses_packet_length_cached_before_pause) {
    int length_calls = 0;
    protocol.private_data_2 = &length_calls;
    protocol.get_package_length = [](const Protocol *protocol, network::Socket *socket, PacketLength *length) {
        ++*static_cast<int *>(protocol->private_data_2);
        socket->recv_paused = 1;
        return Protocol::default_length_func(protocol, socket, length);
    };
    const auto packet = length_packet("first");
    buffer.append(packet);
    socket.skip_recv = true;
    ASSERT_EQ(receive_length(), SW_OK);
    EXPECT_TRUE(packets.empty());
    EXPECT_TRUE(socket.skip_recv);
    EXPECT_EQ(length_calls, 1);

    socket.recv_paused = 0;
    ASSERT_EQ(receive_length(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{packet});
    EXPECT_EQ(length_calls, 1);
}

TEST_F(ProtocolFramingTest, eof_without_split_clears_delivered_packet_when_paused) {
    pause_on_package = true;
    send("a\r\n");
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(buffer.length, 0u);
    pause_on_package = false;
    socket.recv_paused = 0;
    send("b\r\n");
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"a\r\n", "b\r\n"}));
}

TEST_F(ProtocolFramingTest, eof_resume_reads_after_buffered_partial_packet) {
    protocol.split_by_eof = true;
    buffer.append("part\r");
    socket.skip_recv = true;
    send("\n");
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, std::vector<std::string>{"part\r\n"});
    EXPECT_EQ(buffer.length, 0u);
}

TEST_F(ProtocolFramingTest, closed_callback_may_destroy_its_separate_receive_buffer) {
    for (int mode : {0, 1, 2}) {
        SCOPED_TRACE(mode);
        auto owned_buffer = std::make_unique<String>(64);
        protocol.private_data_2 = &owned_buffer;
        protocol.split_by_eof = mode == 1;
        socket.close_wait = 0;
        socket.skip_recv = mode != 2;
        protocol.onPackage = [](const Protocol *protocol, network::Socket *socket, const RecvData *) -> int {
            socket->close_wait = 1;
            static_cast<std::unique_ptr<String> *>(protocol->private_data_2)->reset();
            return SW_OK;
        };
        if (mode == 0) {
            owned_buffer->append(length_packet("first") + length_packet("second"));
        } else if (mode == 1) {
            owned_buffer->append("a\r\nb\r\n");
        } else {
            send("a\r\n");
        }
        const int result = mode == 0 ? protocol.recv_with_length_protocol(&socket, owned_buffer.get())
                                     : protocol.recv_with_eof_protocol(&socket, owned_buffer.get());
        EXPECT_EQ(result, SW_ERR);
        EXPECT_EQ(owned_buffer, nullptr);
    }
}

TEST_F(ProtocolFramingTest, client_resumes_buffered_packets_without_peer_data) {
    for (bool length_protocol : {false, true}) {
        for (bool keep_write : {false, true}) {
            SCOPED_TRACE(length_protocol ? "length" : "eof");
            SCOPED_TRACE(keep_write);
            ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
            network::Client cli(SW_SOCK_UNIX_STREAM, true);
            ON_SCOPE_EXIT {
                cli.close();
                if (sw_reactor()) {
                    swoole_event_free();
                }
            };
            ASSERT_TRUE(cli.ready());
            cli.socket->close_fd();
            cli.socket->fd = dup(fds[1]);
            ASSERT_GE(cli.socket->fd, 0);
            cli.active = true;
            cli.open_eof_check = !length_protocol;
            cli.open_length_check = length_protocol;
            cli.protocol.get_package_length = Protocol::default_length_func;
            cli.protocol.package_body_offset = 4;
            cli.protocol.split_by_eof = true;
            ASSERT_TRUE(cli.protocol.set_package_eof("\r\n", 2));
            cli.buffer = new String(64);
            const auto first = length_protocol ? length_packet("first") : "a\r\n";
            const auto second = length_protocol ? length_packet("second") : "b\r\n";
            cli.buffer->append(first + second);
            cli.socket->skip_recv = true;
            std::vector<std::string> received;
            TimerNode *watchdog = nullptr;
            cli.onClose = [](network::Client *) {};
            cli.onReceive = [&](network::Client *client, const char *data, size_t length) {
                received.emplace_back(data, length);
                if (received.size() == 1) {
                    EXPECT_EQ(client->sleep(), SW_OK);
                } else {
                    if (watchdog) {
                        swoole_timer_del(watchdog);
                        watchdog = nullptr;
                    }
                    client->close();
                }
            };
            ASSERT_EQ(swoole_event_add(cli.socket, SW_EVENT_READ | (keep_write ? SW_EVENT_WRITE : 0)), SW_OK);
            Event event{};
            event.fd = cli.socket->fd;
            event.socket = cli.socket;
            auto *reactor = sw_reactor();
            reactor->get_handler(cli.fd_type, SW_EVENT_READ)(reactor, &event);
            ASSERT_FALSE(cli.closed);
            ASSERT_EQ(received, std::vector<std::string>{first});
            ASSERT_EQ(cli.socket->events, keep_write ? SW_EVENT_WRITE : 0);
            watchdog = swoole_timer_add(1000L, false, [&](Timer *, TimerNode *) {
                watchdog = nullptr;
                ADD_FAILURE() << "buffered packet was not delivered after wakeup";
                cli.close();
            });
            ASSERT_NE(watchdog, nullptr);
            ASSERT_EQ(cli.wakeup(), SW_OK);
            ASSERT_EQ(swoole_event_wait(), SW_OK);
            EXPECT_EQ(received, (std::vector<std::string>{first, second}));
        }
    }
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

TEST_F(ProtocolFramingTest, eof_rejects_oversized_complete_packet_in_large_buffer) {
    protocol.package_max_length = 8;
    ASSERT_GT(buffer.size, protocol.package_max_length);
    send("1234567\r\n");
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    EXPECT_TRUE(packets.empty());
}

TEST_F(ProtocolFramingTest, eof_split_limits_each_packet_after_fragmented_delimiter) {
    protocol.split_by_eof = true;
    protocol.package_max_length = 8;
    buffer.reserve(64);
    send("123456\r");
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_TRUE(packets.empty());

    send("\nabcdef\r\ntail\r");
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"123456\r\n", "abcdef\r\n"}));
    EXPECT_EQ(buffer.to_std_string(), "tail\r");

    send("\n");
    ASSERT_EQ(receive_eof(), SW_OK);
    EXPECT_EQ(packets, (std::vector<std::string>{"123456\r\n", "abcdef\r\n", "tail\r\n"}));
}

TEST_F(ProtocolFramingTest, eof_split_stops_at_oversized_complete_packet) {
    protocol.split_by_eof = true;
    protocol.package_max_length = 8;
    buffer.reserve(64);
    send("valid\r\n1234567\r\nlater\r\n");
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    EXPECT_EQ(packets, std::vector<std::string>{"valid\r\n"});
}

TEST_F(ProtocolFramingTest, eof_split_rejects_unterminated_tail_at_or_above_limit) {
    protocol.split_by_eof = true;
    protocol.package_max_length = 8;
    buffer.reserve(64);
    for (size_t length : {8u, 9u}) {
        buffer.clear();
        packets.clear();
        send("valid\r\n" + std::string(length, 'x'));
        EXPECT_EQ(receive_eof(), SW_ERR);
        EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
        EXPECT_EQ(packets, std::vector<std::string>{"valid\r\n"});
    }
}

TEST_F(ProtocolFramingTest, eof_split_checks_buffered_packets_on_resume) {
    protocol.split_by_eof = true;
    protocol.package_max_length = 8;
    socket.skip_recv = true;
    buffer.append("1234567\r\n");
    EXPECT_EQ(receive_eof(), SW_ERR);
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    EXPECT_TRUE(packets.empty());
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
