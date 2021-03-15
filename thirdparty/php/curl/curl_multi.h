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
#include <curl/multi.h>

#include "curl_private.h"

SW_EXTERN_C_END

namespace swoole {

using network::Socket;

struct MultiSelector {
    bool defer_callback = false;
    std::set<int> active_handles;
    FutureTask *context;
};

class cURLMulti {
    CURLM *handle;
    TimerNode *timer = nullptr;
    std::unique_ptr<MultiSelector> selector;

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
        socket->object = this;
        socket->fd_type = (enum swFd_type) PHP_SWOOLE_FD_CO_CURL;
        curl_multi_assign(handle, sockfd, (void *) socket);
        return socket;
    }

    bool add(CURL *cp) {
        return curl_multi_add_handle(handle, cp) == CURLM_OK;
    }

    void set_event(void *socket_ptr, curl_socket_t sockfd, int action) {
        Socket *socket = socket_ptr ? (Socket *) socket_ptr : create_socket(sockfd);
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
        Socket *socket = (Socket *) socket_ptr;
        socket->silent_remove = 1;
        if (socket->events && swoole_event_is_available()) {
            swoole_event_del(socket);
        }
        socket->fd = -1;
        socket->free();
        curl_multi_assign(handle, sockfd, NULL);
    }

    void add_timer(long timeout_ms) {
        if (timer && swoole_timer_is_available()) {
            swoole_timer_del(timer);
        }

        timer = swoole_timer_add(
            timeout_ms, false, [this](Timer *timer, TimerNode *tnode) { socket_action(CURL_SOCKET_TIMEOUT, 0); });
    }

    void del_timer() {
        if (timer && swoole_timer_is_available()) {
            swoole_timer_del(timer);
        }
    }

  public:
    cURLMulti() {
        handle = curl_multi_init();
        curl_multi_setopt(handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
        curl_multi_setopt(handle, CURLMOPT_TIMERFUNCTION, handle_timeout);
        curl_multi_setopt(handle, CURLMOPT_SOCKETDATA, this);
        curl_multi_setopt(handle, CURLMOPT_TIMERDATA, this);
    }

    CURLM *get_multi_handle() {
        return handle;
    }

    void set_selector(MultiSelector *_selector) {
        selector.reset(_selector);
    }

    CURLcode exec(php_curl *ch) {
        Coroutine::get_current_safe();

        if (!add(ch->cp)) {
            return CURLE_FAILED_INIT;
        }

        zval _return_value;
        zval *return_value = &_return_value;

        FutureTask *context = (FutureTask *) emalloc(sizeof(FutureTask));
        ON_SCOPE_EXIT {
            efree(context);
        };
        ch->context = context;
        PHPCoroutine::yield_m(return_value, context);
        ch->context = nullptr;

        return (CURLcode) Z_LVAL_P(return_value);
    }

    long select(php_curlm *mh) {
        Coroutine::get_current_safe();

        if (selector->context) {
            swFatalError(SW_ERROR_CO_HAS_BEEN_BOUND, "cURL is already waiting, cannot be operated");
            return -1;
        }

        if (selector->active_handles.size() > 0) {
            auto count = selector->active_handles.size();
            selector->active_handles.clear();
            return count;
        }

        zval _return_value;
        zval *return_value = &_return_value;

        FutureTask context{};

        auto set_context_fn = [this, mh](FutureTask *ctx) {
            for (zend_llist_element *element = mh->easyh.head; element; element = element->next) {
                zval *z_ch = (zval *) element->data;
                php_curl *ch;
                if ((ch = _php_curl_get_handle(z_ch, false)) == NULL) {
                    continue;
                }
                ch->context = ctx;
            }
            selector->context = ctx;
        };

        set_context_fn(&context);
        PHPCoroutine::yield_m(return_value, &context);
        set_context_fn(nullptr);

        return Z_LVAL_P(return_value);
    }

    void socket_action(int fd, int event_bitmask) {
        int running_handles;
        curl_multi_socket_action(handle, fd, event_bitmask, &running_handles);

        // for curl_multi_select
        if (selector) {
            selector->active_handles.insert(fd);
            if (!selector->context || selector->defer_callback) {
                return;
            }
            selector->defer_callback = true;
            swoole_event_defer(
                [this](void *data) {
                    zval result;
                    ZVAL_LONG(&result, selector->active_handles.size());
                    selector->active_handles.clear();
                    PHPCoroutine::resume_m(selector->context, &result);
                },
                nullptr);
        } else {
            read_info();
        }
    }

    static int cb_readable(Reactor *reactor, Event *event);
    static int cb_writable(Reactor *reactor, Event *event);
    static int cb_error(Reactor *reactor, Event *event);
    static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp);
    static int handle_timeout(CURLM *multi, long timeout_ms, void *userp);
};
}  // namespace swoole
