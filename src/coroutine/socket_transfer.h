#pragma once

#include "swoole_coroutine_socket.h"

#include <chrono>

namespace swoole {
namespace coroutine {

template <typename Buffer, typename Transfer, typename TimedTransfer>
ssize_t transfer_all(
    Socket &socket, Buffer *buffer, size_t length, double timeout, Transfer transfer, TimedTransfer timed_transfer) {
    using Clock = std::chrono::steady_clock;
    const auto start = timeout > 0 ? Clock::now() : Clock::time_point{};
    size_t transferred = 0;

    do {
        ssize_t n;
        if (transferred > 0 && timeout > 0) {
            const double remaining = timeout - std::chrono::duration<double>(Clock::now() - start).count();
            if (remaining <= 0) {
                socket.set_err(ETIMEDOUT);
                return transferred;
            }
            n = timed_transfer(buffer + transferred, length - transferred, remaining);
        } else {
            n = transfer(buffer + transferred, length - transferred);
        }
        if (n <= 0) {
            return transferred > 0 ? static_cast<ssize_t>(transferred) : n;
        }
        transferred += n;
    } while (transferred < length);

    return transferred;
}

}  // namespace coroutine
}  // namespace swoole
