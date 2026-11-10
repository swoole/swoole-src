#include "test_core.h"
#include "swoole_pipe.h"

using namespace swoole;

TEST(socket_recv_eof, only_a_positive_length_stream_read_observes_eof) {
    UnixSocket sockets(false, SOCK_STREAM);
    ASSERT_TRUE(sockets.ready());
    auto *reader = sockets.get_socket(false);
    auto *writer = sockets.get_socket(true);
    reader->socket_type = SW_SOCK_UNIX_STREAM;
    ASSERT_EQ(writer->send("x", 1, 0), 1);
    char byte;
    EXPECT_EQ(reader->recv(&byte, 0, 0), 0);
    EXPECT_FALSE(reader->recv_eof);
    EXPECT_EQ(reader->recv(&byte, 1, 0), 1);
    EXPECT_FALSE(reader->recv_eof);
    ASSERT_EQ(::shutdown(writer->fd, SHUT_WR), 0);
    ASSERT_EQ(reader->wait_event(1000, SW_EVENT_READ), SW_OK);
    EXPECT_EQ(reader->recv(&byte, 1, 0), 0);
    EXPECT_TRUE(reader->recv_eof);
}

TEST(socket_recv_eof, synthetic_hangup_does_not_count_as_observed_eof) {
    UnixSocket sockets(false, SOCK_STREAM);
    ASSERT_TRUE(sockets.ready());
    auto *reader = sockets.get_socket(false);
    reader->socket_type = SW_SOCK_UNIX_STREAM;
    reader->event_hup = 1;
    char byte;
    EXPECT_EQ(reader->recv(&byte, 1, MSG_DONTWAIT), 0);
    EXPECT_FALSE(reader->recv_eof);
}

TEST(socket_recv_eof, empty_datagram_does_not_count_as_stream_eof) {
    UnixSocket sockets(false, SOCK_DGRAM);
    ASSERT_TRUE(sockets.ready());
    auto *reader = sockets.get_socket(false);
    reader->socket_type = SW_SOCK_UNIX_DGRAM;
    ASSERT_EQ(sockets.get_socket(true)->send("", 0, 0), 0);
    char byte;
    EXPECT_EQ(reader->recv(&byte, 1, 0), 0);
    EXPECT_FALSE(reader->recv_eof);
}
