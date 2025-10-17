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

#include "php_swoole_cxx.h"

#ifdef SW_USE_CURL
#include "swoole_util.h"

SW_EXTERN_C_BEGIN
#include <curl/curl.h>
#include <curl/multi.h>
#if PHP_VERSION_ID >= 80400
#include "thirdparty/php84/curl/curl_private.h"
#else
#include "thirdparty/php/curl/curl_private.h"
#endif
SW_EXTERN_C_END

#if LIBCURL_VERSION_NUM < 0x073800
#error "require cURL version 7.56.0 or later"
#endif

#include <unordered_set>

CURLcode swoole_curl_easy_perform(CURL *cp);
php_curl *swoole_curl_get_handle(zval *zid, bool exclusive = true, bool required = true);
void swoole_curl_easy_reset(CURL *curl);

namespace swoole {
namespace curl {

class Multi;

struct Socket {
    Multi *multi;
    network::Socket *socket;
    int bitmask;
    int sockfd;
    int action;
};

struct Handle {
    CURL *cp;
    Multi *multi;
    /**
     * This is only for the swoole_curl_easy_perform function,
     * and it has a one-to-one relationship with the curl handle.
     * It must be destroyed when the curl handle is released.
     */
    Multi *easy_multi;

    Handle(CURL *_cp) {
        cp = _cp;
        multi = nullptr;
        easy_multi = nullptr;
    }
};

Handle *get_handle(CURL *cp);
Handle *create_handle(CURL *ch);
void destroy_handle(CURL *ch);

struct Selector {
    bool timer_callback = false;
    std::unordered_set<Socket *> active_sockets;
};

class Multi {
    CURLM *multi_handle_;
    TimerNode *timer = nullptr;
    long timeout_ms_ = 0;
    Coroutine *co = nullptr;
    int running_handles_ = 0;
    bool defer_callback = false;
    Selector selector;
    std::unordered_map<curl_socket_t, Socket *> sockets;

    CURLcode read_info() const;

    Socket *create_socket(curl_socket_t sockfd, CURL *cp);
    void destroy_socket(curl_socket_t sockfd, CURL *cp);

    int set_event(void *socket_ptr, curl_socket_t sockfd, int action);
    int del_event(void *socket_ptr, curl_socket_t sockfd);
    void selector_finish();
    void selector_prepare();

    bool wait_event() {
        return timer || !sockets.empty();
    }

    void add_timer(long timeout_ms) {
        if (timer && swoole_timer_is_available()) {
            swoole_timer_del(timer);
        }
        timeout_ms_ = timeout_ms;
        timer = swoole_timer_add(timeout_ms, false, [this](Timer *timer, TimerNode *tnode) {
            this->timer = nullptr;
            callback(nullptr, 0);
        });
    }

    void del_timer() {
        if (timer && swoole_timer_is_available()) {
            swoole_timer_del(timer);
            timeout_ms_ = -1;
            timer = nullptr;
        }
    }

    void set_timer() {
        long _timeout_ms = 0;
        curl_multi_timeout(multi_handle_, &_timeout_ms);
        handle_timeout(multi_handle_, _timeout_ms, this);
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

    ~Multi() {
        del_timer();
        curl_multi_cleanup(multi_handle_);
    }

    CURLM *get_multi_handle() {
        return multi_handle_;
    }

    int get_running_handles() {
        return running_handles_;
    }

    CURLMcode add_handle(Handle *handle);
    CURLMcode remove_handle(Handle *handle) const;

    CURLMcode perform() {
        return curl_multi_perform(multi_handle_, &running_handles_);
    }

    int get_event(int action) {
        return action == CURL_POLL_IN ? SW_EVENT_READ : SW_EVENT_WRITE;
    }

    Coroutine *check_bound_co() {
        if (co) {
            swoole_fatal_error(SW_ERROR_CO_HAS_BEEN_BOUND, "cURL is executing, cannot be operated");
            return nullptr;
        }
        return Coroutine::get_current_safe();
    }

    CURLcode exec(Handle *handle);
    long select(php_curlm *mh, double timeout = -1);
    void callback(Socket *curl_socket, int bitmask, int sockfd = -1);

    static int cb_readable(Reactor *reactor, Event *event);
    static int cb_writable(Reactor *reactor, Event *event);
    static int cb_error(Reactor *reactor, Event *event);
    static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp);
    static int handle_timeout(CURLM *multi, long timeout_ms, void *userp);
};
};  // namespace curl
}  // namespace swoole
#endif
