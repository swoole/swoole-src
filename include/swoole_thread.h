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

#include "swoole.h"
#include "swoole_lock.h"

#include <thread>
#include <string>

long swoole_thread_get_native_id(void);
bool swoole_thread_set_name(const char *name);
bool swoole_thread_get_name(char *buf, size_t len);
std::string swoole_thread_id_to_str(std::thread::id id);

namespace swoole {
class Thread {
  private:
    int exit_status;
    bool living;
    std::thread thread;

  public:
    bool is_alive() {
        return living;
    }

    bool joinable() {
        return thread.joinable();
    }

    void join() {
        thread.join();
    }

    void detach() {
        thread.detach();
    }

    int get_exit_status() {
        return exit_status;
    }

    pthread_t get_id() {
        return thread.native_handle();
    }

    template <typename _Callable>
    void start(_Callable fn) {
        thread = std::thread(fn);
    }

    void enter() {
        exit_status = 0;
        living = true;
    }

    void exit(int status) {
        exit_status = status;
        living = false;
    }
};
}  // namespace swoole
