#include "test_core.h"
#include "swoole_file.h"

#include <limits>

namespace swoole {
namespace detail {
extern ssize_t sendfile_with_retry(
    int out_fd, int in_fd, off_t *offset, size_t size, int (*sendfile)(int, int, off_t, size_t, off_t *));
}  // namespace detail
}  // namespace swoole

namespace {
using Sendfile = std::function<int(off_t, size_t, off_t *)>;
thread_local const Sendfile *active_sendfile = nullptr;

ssize_t sendfile_with_retry(off_t *offset, size_t size, const Sendfile &sendfile) {
    active_sendfile = &sendfile;
    ON_SCOPE_EXIT {
        active_sendfile = nullptr;
    };
    return swoole::detail::sendfile_with_retry(
        -1, -1, offset, size, [](int, int, off_t begin, size_t count, off_t *bytes) {
            return (*active_sendfile)(begin, count, bytes);
        });
}
}  // namespace

TEST(os_sendfile, zero_progress_eintr_preserves_range) {
    off_t offset = 7;
    int calls = 0;
    const auto sent = sendfile_with_retry(&offset, 9, [&](off_t begin, size_t count, off_t *bytes) {
        EXPECT_EQ(begin, 7);
        EXPECT_EQ(count, 9);
        if (++calls == 1) {
            *bytes = 0;
            errno = EINTR;
            return -1;
        }
        *bytes = 4;
        return 0;
    });
    EXPECT_EQ(sent, 4);
    EXPECT_EQ(offset, 11);
    EXPECT_EQ(calls, 2);
}

TEST(os_sendfile, interrupted_partial_send_returns_progress) {
    off_t offset = 7;
    int calls = 0;
    const auto sent = sendfile_with_retry(&offset, 9, [&](off_t begin, size_t count, off_t *bytes) {
        EXPECT_EQ(begin, 7);
        EXPECT_EQ(count, 9);
        ++calls;
        *bytes = 3;
        errno = EINTR;
        return -1;
    });
    EXPECT_EQ(sent, 3);
    EXPECT_EQ(offset, 10);
    EXPECT_EQ(calls, 1);
}

TEST(os_sendfile, would_block_preserves_progress) {
    for (off_t bytes : {off_t(0), off_t(3)}) {
        off_t offset = 7;
        const auto sent = sendfile_with_retry(&offset, 9, [&](off_t, size_t, off_t *output) {
            *output = bytes;
            errno = EAGAIN;
            return -1;
        });
        EXPECT_EQ(sent, bytes ? bytes : -1);
        EXPECT_EQ(offset, 7 + bytes);
        EXPECT_EQ(errno, EAGAIN);
    }
}

TEST(os_sendfile, hard_failure_ignores_unchanged_output_length) {
    off_t offset = 7;
    const auto sent = sendfile_with_retry(&offset, 9, [](off_t, size_t count, off_t *bytes) {
        // Darwin initializes len with the requested count, and an early EBADF may leave it unchanged.
        *bytes = count;
        errno = EBADF;
        return -1;
    });
    EXPECT_EQ(sent, -1);
    EXPECT_EQ(offset, 7);
    EXPECT_EQ(errno, EBADF);
}

TEST(os_sendfile, zero_count_does_not_call_native_sendfile) {
    off_t offset = 7;
    bool called = false;
    const auto sent = sendfile_with_retry(&offset, 0, [&](off_t, size_t, off_t *) {
        called = true;
        return 0;
    });
    EXPECT_EQ(sent, 0);
    EXPECT_EQ(offset, 7);
    EXPECT_FALSE(called);
}

TEST(os_sendfile, successful_eof_does_not_advance_offset) {
    off_t offset = 7;
    const auto sent = sendfile_with_retry(&offset, 9, [](off_t, size_t, off_t *) { return 0; });
    EXPECT_EQ(sent, 0);
    EXPECT_EQ(offset, 7);
}

TEST(os_sendfile, count_fits_signed_result) {
    off_t offset = 7;
    const auto sent = sendfile_with_retry(&offset, SIZE_MAX, [](off_t, size_t count, off_t *) {
        EXPECT_EQ(count, static_cast<size_t>(std::numeric_limits<ssize_t>::max()));
        return 0;
    });
    EXPECT_EQ(sent, 0);
    EXPECT_EQ(offset, 7);
}

#ifndef _WIN32
TEST(os_sendfile, native_range_and_zero_count) {
    swoole::network::Address address;
    ASSERT_TRUE(address.assign(SW_SOCK_TCP, "127.0.0.1", 0));
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    ON_SCOPE_EXIT {
        ::close(listener);
    };
    ASSERT_EQ(::bind(listener, &address.addr.ss, address.len), 0);
    ASSERT_EQ(::listen(listener, 1), 0);
    ASSERT_EQ(::getsockname(listener, &address.addr.ss, &address.len), 0);
    const int sender = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(sender, 0);
    ON_SCOPE_EXIT {
        ::close(sender);
    };
    ASSERT_EQ(::connect(sender, &address.addr.ss, address.len), 0);
    const int receiver = ::accept(listener, nullptr, nullptr);
    ASSERT_GE(receiver, 0);
    ON_SCOPE_EXIT {
        ::close(receiver);
    };
    timeval timeout{2, 0};
    ASSERT_EQ(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);

    auto file = swoole::make_tmpfile();
    ASSERT_TRUE(file.ready());
    ON_SCOPE_EXIT {
        swoole::File::remove(file.get_path());
    };
    const std::string data = "prefix-wanted-suffix";
    ASSERT_EQ(file.write(data.data(), data.length()), static_cast<ssize_t>(data.length()));
    off_t offset = 7;
    EXPECT_EQ(swoole_sendfile(sender, file.get_fd(), &offset, 0), 0);
    EXPECT_EQ(offset, 7);
    char received[32];
    EXPECT_EQ(::recv(receiver, received, sizeof(received), MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EAGAIN);
    const auto sent = swoole_sendfile(sender, file.get_fd(), &offset, 6);
    ASSERT_EQ(sent, 6);
    EXPECT_EQ(offset, 13);
    ASSERT_EQ(::recv(receiver, received, 6, MSG_WAITALL), 6);
    EXPECT_EQ(std::string(received, 6), "wanted");
}
#endif
