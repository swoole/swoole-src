#include "test_core.h"
#include "swoole_pipe.h"

#include <type_traits>

using namespace swoole;

TEST(pipe, virtual_destructor) {
    // AsyncThreads deletes its platform-specific pipe through SocketPair *.
    ASSERT_TRUE(std::has_virtual_destructor<SocketPair>::value);
}

TEST(pipe, unixsock) {
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    char buf[1024];

    int ret = p.write((void *) SW_STRS("hello world1"));
    ASSERT_GT(ret, 0);
    ret = p.write((void *) SW_STRS("hello world2"));
    ASSERT_GT(ret, 0);
    ret = p.write((void *) SW_STRS("hello world3"));
    ASSERT_GT(ret, 0);

    // 1
    ret = p.read(buf, sizeof(buf));
    if (ret < 0) {
        swoole_sys_warning("read() failed.");
    }
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world1", buf), 0);
    // 2
    ret = p.read(buf, sizeof(buf));
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world2", buf), 0);
    // 3
    ret = p.read(buf, sizeof(buf));
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world3", buf), 0);
}

TEST(pipe, base) {
    int ret;
    char data[256];

    Pipe p(true);
    ASSERT_TRUE(p.ready());

    ret = p.write((void *) SW_STRL("hello world\n"));
    ASSERT_GT(ret, 0);
    ret = p.write((void *) SW_STRL("你好中国。\n"));
    ASSERT_GT(ret, 0);

    sw_memset_zero(data, 256);
    ret = p.read(data, 255);
    ASSERT_GT(ret, 0);
    ASSERT_EQ(strcmp("hello world\n你好中国。\n", data), 0);
}

TEST(pipe, nonblocking_empty_read_and_binary_transfer) {
    Pipe pipe(false);
    ASSERT_TRUE(pipe.ready());
    char buffer[16]{};
    EXPECT_EQ(pipe.read(buffer, sizeof(buffer)), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
    const std::string payload("a\0b\xff", 4);
    ASSERT_EQ(pipe.write(payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));
    ASSERT_EQ(pipe.read(buffer, sizeof(buffer)), static_cast<ssize_t>(payload.size()));
    EXPECT_EQ(std::string(buffer, payload.size()), payload);
}

TEST(pipe, blocking_mode_can_be_changed_on_both_ends) {
    Pipe pipe(false);
    ASSERT_TRUE(pipe.ready());
    pipe.set_timeout(0.1);
    for (const bool blocking : {true, false, true}) {
        pipe.set_blocking(blocking);
#ifndef _WIN32
        for (const bool master : {true, false}) {
            const int flags = fcntl(pipe.get_socket(master)->fd, F_GETFL);
            ASSERT_GE(flags, 0);
            EXPECT_EQ((flags & O_NONBLOCK) == 0, blocking);
        }
#endif
        ASSERT_EQ(pipe.write("data", 4), 4);
        char buffer[4];
        ASSERT_EQ(pipe.read(buffer, sizeof(buffer)), 4);
        EXPECT_EQ(std::string(buffer, sizeof(buffer)), "data");
    }
}

TEST(pipe, clean_drains_multiple_chunks_without_closing_pipe) {
    Pipe pipe(false);
    ASSERT_TRUE(pipe.ready());
    const std::string payload(2048, 'x');
    ASSERT_EQ(pipe.write(payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));
    pipe.clean();
    char buffer[8];
    EXPECT_EQ(pipe.read(buffer, sizeof(buffer)), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
    ASSERT_EQ(pipe.write("next", 4), 4);
    ASSERT_EQ(pipe.read(buffer, sizeof(buffer)), 4);
    EXPECT_EQ(std::string(buffer, 4), "next");
}

TEST(pipe, clean_stops_at_eof_after_writer_is_closed) {
    Pipe pipe(false);
    ASSERT_TRUE(pipe.ready());
    ASSERT_EQ(pipe.write("pending", 7), 7);
    ASSERT_TRUE(pipe.close(SW_PIPE_CLOSE_MASTER));
    EXPECT_FALSE(pipe.ready());
    pipe.clean();
    char buffer;
    EXPECT_EQ(pipe.read(&buffer, 1), 0);
    EXPECT_FALSE(pipe.close(SW_PIPE_CLOSE_MASTER));
    EXPECT_TRUE(pipe.close(SW_PIPE_CLOSE_WORKER));
    EXPECT_FALSE(pipe.close(SW_PIPE_CLOSE_WORKER));
}

TEST(pipe, closing_reader_preserves_writer_until_closed) {
    Pipe pipe(false);
    ASSERT_TRUE(pipe.ready());
    ASSERT_TRUE(pipe.close(SW_PIPE_CLOSE_WORKER));
    EXPECT_FALSE(pipe.ready());
    EXPECT_EQ(pipe.get_socket(false), nullptr);
    EXPECT_NE(pipe.get_socket(true), nullptr);
    EXPECT_FALSE(pipe.close(SW_PIPE_CLOSE_WORKER));
    EXPECT_TRUE(pipe.close());
    EXPECT_EQ(pipe.get_socket(true), nullptr);
    EXPECT_TRUE(pipe.close());
}

#ifndef _WIN32
TEST(pipe, destructor_closes_both_descriptors) {
    int reader, writer;
    {
        Pipe pipe(false);
        ASSERT_TRUE(pipe.ready());
        reader = pipe.get_socket(false)->fd;
        writer = pipe.get_socket(true)->fd;
    }
    EXPECT_EQ(fcntl(reader, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(fcntl(writer, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST(pipe, nonblocking_unix_socket_preserves_datagram_boundaries) {
    UnixSocket pipe(false, SOCK_DGRAM);
    ASSERT_TRUE(pipe.ready());
    ASSERT_TRUE(pipe.set_buffer_size(4096));
    const std::string first("a\0b", 3);
    ASSERT_EQ(pipe.write(first.data(), first.size()), static_cast<ssize_t>(first.size()));
    ASSERT_EQ(pipe.write("second", 6), 6);
    char buffer[16];
    ASSERT_EQ(pipe.read(buffer, sizeof(buffer)), 3);
    EXPECT_EQ(std::string(buffer, 3), first);
    ASSERT_EQ(pipe.read(buffer, sizeof(buffer)), 6);
    EXPECT_EQ(std::string(buffer, 6), "second");
    EXPECT_EQ(pipe.read(buffer, sizeof(buffer)), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
}

TEST(pipe, invalid_unix_socket_type_is_not_ready) {
    UnixSocket pipe(false, -1);
    EXPECT_FALSE(pipe.ready());
    EXPECT_EQ(pipe.get_socket(true), nullptr);
    EXPECT_EQ(pipe.get_socket(false), nullptr);
}
#endif
