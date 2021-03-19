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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#pragma once

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
#include "swoole_util.h"

SW_EXTERN_C_BEGIN
#include <curl/curl.h>
#include <curl/multi.h>
#include "thirdparty/php/curl/curl_private.h"
SW_EXTERN_C_END

namespace swoole {

using network::Socket;

namespace curl {

struct Handle {
    CURL *cp;
    Socket *socket;
    int fd;
    int bitmask;
    int action;
    bool listening;
};

struct Selector {
    bool defer_callback = false;
    std::set<int> active_handles;
};

class Multi {
    CURLM *multi_handle_;
    TimerNode *timer = nullptr;
    bool timedout = false;
    Coroutine *co = nullptr;
    int running_handles_ = 0;
    int last_sockfd;
    std::unique_ptr<Selector> selector;
    std::unordered_map<int, Handle *> handles;

    CURLcode read_info();

    Socket *create_socket(CURL *cp, curl_socket_t sockfd);

    Handle *get_handle(CURL *cp) {
        Handle *handle;
        curl_easy_getinfo(cp, CURLINFO_PRIVATE, &handle);
        return handle;
    }

    Handle *get_handle(int fd) {
        auto iter = handles.find(fd);
        if (iter == handles.end()) {
            return nullptr;
        }
        return iter->second;
    }

    void set_event(CURL *easy, void *socket_ptr, curl_socket_t sockfd, int action);
    void del_event(CURL *easy, void *socket_ptr, curl_socket_t sockfd);

    void add_timer(long timeout_ms) {
        if (timer && swoole_timer_is_available()) {
            swoole_timer_del(timer);
        }

        timer = swoole_timer_add(
            timeout_ms, false, [this](Timer *timer, TimerNode *tnode) {
            callback(nullptr, 0);
            this->timer = nullptr;
        });
    }

    void del_timer() {
        if (timer && swoole_timer_is_available()) {
            swoole_timer_del(timer);
            timer = nullptr;
        }
    }

  public:
    Multi() {
        multi_handle_ = curl_multi_init();
        co = nullptr;
        curl_multi_setopt(multi_handle_, CURLMOPT_SOCKETFUNCTION, handle_socket);
        curl_multi_setopt(multi_handle_, CURLMOPT_TIMERFUNCTION, handle_timeout);
        curl_multi_setopt(multi_handle_, CURLMOPT_SOCKETDATA, this);
        curl_multi_setopt(multi_handle_, CURLMOPT_TIMERDATA, this);
    }

    CURLM *get_multi_handle() {
        return multi_handle_;
    }

    int get_running_handles() {
        return running_handles_;
    }

    void set_selector(Selector *_selector) {
        selector.reset(_selector);
    }

    CURLMcode add_handle(CURL *cp) {
        auto handle = new Handle{};
        handle->cp = cp;
        curl_easy_setopt(cp, CURLOPT_PRIVATE, handle);
        return curl_multi_add_handle(multi_handle_, cp);
    }

    CURLMcode remove_handle(CURL *cp) {
        auto retval = curl_multi_remove_handle(multi_handle_, cp);
        auto handle = get_handle(cp);
        delete handle;
        curl_easy_setopt(cp, CURLOPT_PRIVATE, nullptr);
        return retval;
    }

    CURLMcode perform() {
        auto retval = curl_multi_perform(multi_handle_, &running_handles_);
        return retval;
    }

    CURLcode exec(php_curl *ch);
    long select(php_curlm *mh);
    void callback(Socket *sock, int event_bitmask);

    static int cb_readable(Reactor *reactor, Event *event);
    static int cb_writable(Reactor *reactor, Event *event);
    static int cb_error(Reactor *reactor, Event *event);
    static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp);
    static int handle_timeout(CURLM *multi, long timeout_ms, void *userp);
};
};
}  // namespace swoole
#endif
