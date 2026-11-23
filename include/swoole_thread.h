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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_lock.h"
#include "swoole_signal.h"
#include "swoole_util.h"

#include <atomic>
#include <thread>
#include <string>

long swoole_thread_get_native_id();
bool swoole_thread_set_name(const char *name);
bool swoole_thread_get_name(char *buf, size_t len);
std::string swoole_thread_id_to_str(std::thread::id id);

#ifdef HAVE_CPU_AFFINITY
int swoole_thread_set_cpu_affinity(cpu_set_t *set);
int swoole_thread_get_cpu_affinity(cpu_set_t *set);
#endif

namespace swoole {
class Thread {
    std::atomic<int> exit_status{0};
    std::atomic<bool> living{false};
    std::thread thread;

  public:
    bool is_alive() const {
        return living.load(std::memory_order_acquire);
    }

    bool joinable() const {
        return thread.joinable();
    }

    void join() {
        thread.join();
    }

    void detach() {
        thread.detach();
    }

    int get_exit_status() const {
        return exit_status.load(std::memory_order_relaxed);
    }

    pthread_t get_id() {
        return thread.native_handle();
    }

    template <typename Callable>
    void start(Callable fn) {
        const bool restore_signal_mask = swoole_signal_block_all();
        ON_SCOPE_EXIT {
            if (restore_signal_mask) {
                swoole_signal_unblock_all();
            }
        };
        exit_status.store(0, std::memory_order_relaxed);
        living.store(true, std::memory_order_release);
        try {
            thread = std::thread(fn);
        } catch (...) {
            living.store(false, std::memory_order_release);
            throw;
        }
    }

    void enter() {
        exit_status.store(0, std::memory_order_relaxed);
        living.store(true, std::memory_order_release);
    }

    void exit(const int status) {
        exit_status.store(status, std::memory_order_relaxed);
        living.store(false, std::memory_order_release);
    }
};
}  // namespace swoole
