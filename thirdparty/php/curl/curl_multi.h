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
#include "swoole_util.h"

SW_EXTERN_C_BEGIN

#include <curl/curl.h>

#include "curl_private.h"

SW_EXTERN_C_END


#define CALL_FN_BEGIN    std::function<bool(void)> fn = [&]() -> bool {
#define CALL_FN_END      return true;\
            };\
            zval result; \
            ZVAL_NULL(&result); \
            ch->callback = &fn; \
            PHPCoroutine::resume_m(ch->context, &result); \
            break;

using swoole::network::Socket;

namespace swoole {
class cURLMulti {
    CURLM *handle;
    TimerNode *timer = nullptr;

    void read_info();

    Socket *create_socket(curl_socket_t sockfd) {
        if (!swoole_event_isset_handler(PHP_SWOOLE_FD_CO_CURL)) {
            swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_READ, cb_readable);
            swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_WRITE, cb_writable);
            swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_ERROR, cb_error);
        }
        Socket *socket = new Socket();
        socket->fd = sockfd;
        socket->removed = 1;
        socket->fd_type = (enum swFd_type) PHP_SWOOLE_FD_CO_CURL;
        curl_multi_assign(handle, sockfd, (void*) socket);
        return socket;
    }

    bool add(CURL *cp) {
        return curl_multi_add_handle(handle, cp) == CURLM_OK;
    }

    void set_event(void *socket_ptr, curl_socket_t sockfd, int action) {
        Socket *socket = socket_ptr ? (Socket*) socket_ptr : create_socket(sockfd);
        int events = 0;
        if (action != CURL_POLL_IN) {
            events |= SW_EVENT_WRITE;
        }
        if (action != CURL_POLL_OUT) {
            events |= SW_EVENT_READ;
        }
        if (socket->events) {
            swoole_event_set(socket, events);
        } else {
            swoole_event_add(socket, events);
        }
    }

    void del_event(void *socket_ptr, curl_socket_t sockfd) {
        Socket *socket = (Socket*) socket_ptr;
        socket->silent_remove = 1;
        if (socket->events && swoole_event_is_available()) {
            swoole_event_del(socket);
        }
        socket->fd = -1;
        socket->free();
        curl_multi_assign(handle, sockfd, NULL);
    }

    void add_timer(long timeout_ms) {
        if (timer) {
            swoole_timer_del(timer);
        }

        timer = swoole_timer_add(timeout_ms, false, [this](Timer *timer, TimerNode *tnode) {
            socket_action(CURL_SOCKET_TIMEOUT, 0);
        });
    }

    void del_timer() {
        if (timer && swoole_event_is_available()) {
            swoole_timer_del(timer);
        }
    }

 public:
    cURLMulti() {
        handle = curl_multi_init();
        curl_multi_setopt(handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
        curl_multi_setopt(handle, CURLMOPT_TIMERFUNCTION, handle_timeout);
    }

    CURLcode exec(php_curl *ch) {
        if (!add(ch->cp)) {
            return CURLE_FAILED_INIT;
        }

        zval _return_value;
        zval *return_value = &_return_value;

        FutureTask *context = (FutureTask*) emalloc(sizeof(FutureTask));
        ON_SCOPE_EXIT {
            efree(context);
        };
        ch->context = context;

        do {
            PHPCoroutine::yield_m(return_value, context);
        } while(ZVAL_IS_NULL(return_value) && ch->callback && (*ch->callback)());

        ch->context = nullptr;

        return (CURLcode) Z_LVAL_P(return_value);
    }

    void socket_action(int fd, int event_bitmask) {
        int running_handles;
        curl_multi_socket_action(handle, fd, event_bitmask, &running_handles);
        read_info();
    }

    static int cb_readable(Reactor *reactor, Event *event);
    static int cb_writable(Reactor *reactor, Event *event);
    static int cb_error(Reactor *reactor, Event *event);
    static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp);
    static int handle_timeout(CURLM *multi, long timeout_ms, void *userp);
};
}
