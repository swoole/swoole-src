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

#include "php_swoole_curl.h"
#include "swoole_socket.h"

#ifdef SW_USE_CURL

namespace swoole {
namespace curl {

Handle *get_handle(CURL *cp) {
    Handle *handle;
    if (curl_easy_getinfo(cp, CURLINFO_PRIVATE, (void *) &handle) == CURLE_OK) {
        return handle;
    } else {
        return nullptr;
    }
}

Handle *create_handle(CURL *cp) {
    auto *handle = new Handle(cp);
    curl_easy_setopt(cp, CURLOPT_PRIVATE, handle);
    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_MAGENTA " handle=%p, curl=%p", "[CREATE]", handle, cp);
    return handle;
}

void destroy_handle(CURL *cp) {
    auto handle = get_handle(cp);
    if (!handle) {
        return;
    }
    delete handle->easy_multi;
    curl_easy_setopt(cp, CURLOPT_PRIVATE, nullptr);
    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_RED " handle=%p, curl=%p", "[DESTROY]", handle, cp);
    delete handle;
}

static int execute_callback(Event *event, int bitmask) {
    auto curl_socket = static_cast<Socket *>(event->socket->object);
    curl_socket->bitmask |= bitmask;
    curl_socket->multi->callback(curl_socket, bitmask, event->fd);
    return 0;
}

Multi::Multi() {
	multi_handle_ = curl_multi_init();
	co = nullptr;
	curl_multi_setopt(multi_handle_, CURLMOPT_SOCKETFUNCTION, handle_socket);
	curl_multi_setopt(multi_handle_, CURLMOPT_TIMERFUNCTION, handle_timeout);
	curl_multi_setopt(multi_handle_, CURLMOPT_SOCKETDATA, this);
	curl_multi_setopt(multi_handle_, CURLMOPT_TIMERDATA, this);
}

Multi::~Multi() {
    del_timer();
    curl_multi_cleanup(multi_handle_);
}

int Multi::cb_readable(Reactor *reactor, Event *event) {
    return execute_callback(event, CURL_CSELECT_IN);
}

int Multi::cb_writable(Reactor *reactor, Event *event) {
    return execute_callback(event, CURL_CSELECT_OUT);
}

int Multi::cb_error(Reactor *reactor, Event *event) {
    return execute_callback(event, CURL_CSELECT_ERR);
}

int Multi::handle_socket(CURL *cp, curl_socket_t sockfd, int action, void *userp, void *socketp) {
    auto *multi = static_cast<Multi *>(userp);
    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_CYAN "curl=%p, sockfd=%d, action=%d, userp=%p, socketp=%p",
                     "[HANDLE_SOCKET]",
                     cp,
                     sockfd,
                     action,
                     userp,
                     socketp);
    switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
        return multi->set_event(socketp, sockfd, action);
    case CURL_POLL_REMOVE:
        return multi->del_event(socketp, sockfd);
    default:
        abort();
    }
    return 0;
}

int Multi::del_event(void *socket_ptr, curl_socket_t sockfd) {
    sockets.erase(sockfd);
    curl_multi_assign(multi_handle_, sockfd, nullptr);

    if (sw_unlikely(!socket_ptr)) {
        return SW_ERR;
    }

    auto curl_socket = static_cast<Socket *>(socket_ptr);
    if (curl_socket->socket->events && sw_likely(swoole_event_is_available())) {
        curl_socket->socket->silent_remove = 1;
        swoole_event_del(curl_socket->socket);
    }

    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_RED " socket_ptr=%p, fd=%d", "[DEL_EVENT]", socket_ptr, sockfd);

    curl_socket->socket->fd = -1;
    curl_socket->socket->free();

    if (selector.executing) {
        curl_socket->deleted = true;
        selector.release_sockets.insert(curl_socket);
    } else {
        delete curl_socket;
    }

    return SW_OK;
}

int Multi::set_event(void *socket_ptr, curl_socket_t sockfd, int action) {
    if (sw_unlikely(!swoole_event_is_available())) {
        return -1;
    }

    if (sw_unlikely(!swoole_event_isset_handler(PHP_SWOOLE_FD_CO_CURL, SW_EVENT_READ))) {
        swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL, SW_EVENT_READ, cb_readable);
        swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL, SW_EVENT_WRITE, cb_writable);
        swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL, SW_EVENT_ERROR, cb_error);
    }

    Socket *curl_socket;

    if (socket_ptr) {
        curl_socket = (Socket *) socket_ptr;
    } else {
        curl_socket = new Socket();
        if (sw_unlikely(curl_multi_assign(multi_handle_, sockfd, curl_socket) != CURLM_OK)) {
            delete curl_socket;
            return -1;
        }

        curl_socket->socket = new network::Socket();
        curl_socket->socket->fd = sockfd;
        curl_socket->socket->removed = 1;
        curl_socket->socket->fd_type = static_cast<FdType>(PHP_SWOOLE_FD_CO_CURL);
        curl_socket->socket->object = curl_socket;
        curl_socket->multi = this;

        sockets[sockfd] = curl_socket;
    }

    curl_socket->sockfd = sockfd;
    curl_socket->action = action;

    int events = 0;
    if (action != CURL_POLL_IN) {
        events |= SW_EVENT_WRITE;
    }
    if (action != CURL_POLL_OUT) {
        events |= SW_EVENT_READ;
    }

    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_GREEN " curl_socket=%p, fd=%d, events=%d",
                     "[ADD_EVENT]",
                     curl_socket,
                     sockfd,
                     events);

    if (curl_socket->socket->events) {
        return swoole_event_set(curl_socket->socket, events);
    } else {
        return swoole_event_add(curl_socket->socket, events);
    }
}

CURLMcode Multi::add_handle(Handle *handle) {
    auto retval = curl_multi_add_handle(multi_handle_, handle->cp);
    if (retval == CURLM_OK) {
        handle->multi = this;
        swoole_trace_log(SW_TRACE_CO_CURL,
                         SW_ECHO_GREEN " handle=%p, curl=%p, multi=%p, running_handles=%d",
                         "[ADD_HANDLE]",
                         handle,
                         handle->cp,
                         this,
                         running_handles_);
    }
    return retval;
}

CURLMcode Multi::remove_handle(Handle *handle) const {
    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_RED " handle=%p, curl=%p, multi=%p, running_handles=%d",
                     "[REMOVE_HANDLE]",
                     handle,
                     handle->cp,
                     handle->multi,
                     handle->multi->running_handles_);

    const auto rc = curl_multi_remove_handle(multi_handle_, handle->cp);
    handle->multi = nullptr;
    return rc;
}

void Multi::selector_prepare() {
    for (auto it : sockets) {
        Socket *curl_socket = it.second;
        if (curl_socket->socket->removed) {
            swoole_event_add(curl_socket->socket, get_event(curl_socket->action));
            swoole_trace_log(SW_TRACE_CO_CURL,
                             "resume, curl_socket=%p, fd=%d, action=%d",
                             curl_socket,
                             curl_socket->socket->get_fd(),
                             curl_socket->action);
        }
    }
}

CURLcode Multi::exec(Handle *handle) {
    if (add_handle(handle) != CURLM_OK) {
        return CURLE_FAILED_INIT;
    }

    bool is_canceled = false;

    SW_LOOP {
        selector_prepare();

        if (wait_event()) {
            co = check_bound_co();
            co->yield_ex(-1);
            is_canceled = co->is_canceled();
            co = nullptr;

            if (is_canceled) {
                swoole_set_last_error(SW_ERROR_CO_CANCELED);
                break;
            }
        }

        selector_finish();
        if (running_handles_ == 0) {
            break;
        }
        set_timer();
    }

    del_timer();

    CURLcode retval = read_info();
    remove_handle(handle);
    return is_canceled ? CURLE_ABORTED_BY_CALLBACK : retval;
}

CURLcode Multi::read_info() const {
    CURLMsg *message;
    int pending;

    while ((message = curl_multi_info_read(multi_handle_, &pending))) {
        switch (message->msg) {
        case CURLMSG_DONE:
            /* Do not use message data after calling curl_multi_remove_handle() and
             curl_easy_cleanup(). As per curl_multi_info_read() docs:
             "WARNING: The data the returned pointer points to will not survive
             calling curl_multi_cleanup, curl_multi_remove_handle or
             curl_easy_cleanup." */
            return message->data.result;
        default:
            swoole_warning("CURLMSG default");
            break;
        }
    }
    return CURLE_OK;
}

int Multi::handle_timeout(CURLM *mh, long timeout_ms, void *userp) {
    auto *multi = static_cast<Multi *>(userp);
    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_BLUE " timeout_ms=%ld", "[HANDLE_TIMEOUT]", timeout_ms);
    if (sw_unlikely(!swoole_event_is_available())) {
        return -1;
    }
    if (timeout_ms < 0) {
        if (multi->timer) {
            multi->del_timer();
        } else {
            multi->add_timer(1000);
        }
    } else {
        if (timeout_ms == 0) {
            timeout_ms = 1; /* 0 means directly call socket_action, but we'll do it in a bit */
        }
        multi->add_timer(timeout_ms);
    }
    return 0;
}

void Multi::selector_finish() {
    del_timer();

    selector.executing = true;

    if (selector.timer_callback) {
        selector.timer_callback = false;
        curl_multi_socket_action(multi_handle_, CURL_SOCKET_TIMEOUT, 0, &running_handles_);
        swoole_trace_log(SW_TRACE_CO_CURL, "socket_action[timer], running_handles=%d", running_handles_);
    }

    while (!selector.active_sockets.empty()) {
        auto active_sockets = selector.active_sockets;
        selector.active_sockets.clear();

        for (auto curl_socket : active_sockets) {
            /**
             * In `curl_multi_socket_action`, `Handle::destroy_socket()` may be invoked,
             * which will remove entries from the `unordered_map`.
             * In C++, removing elements during iteration can render the iterator invalid; hence,
             * it's necessary to copy `handle->sockets` into a new `unordered_map`.
             */
            swoole_trace_log(SW_TRACE_CO_CURL,
                             "curl_multi_socket_action(): sockfd=%d, bitmask=%d, running_handles_=%d",
                             curl_socket->sockfd,
                             curl_socket->bitmask,
                             running_handles_);

            if (!curl_socket->deleted) {
                int bitmask = curl_socket->bitmask;
                curl_socket->bitmask = 0;
                curl_multi_socket_action(multi_handle_, curl_socket->sockfd, bitmask, &running_handles_);
            }
        }
    }

    selector.executing = false;
    for (auto curl_socket : selector.release_sockets) {
        delete curl_socket;
    }
    selector.release_sockets.clear();
}

long Multi::select(php_curlm *mh, double timeout) {
    if (zend_llist_count(&mh->easyh) == 0) {
        return 0;
    }

    if (curl_multi_socket_all(multi_handle_, &running_handles_) != CURLM_OK) {
        return CURLE_FAILED_INIT;
    }

    selector_prepare();
    set_timer();

    // no events and timers, should not be suspended
    if (!wait_event()) {
        return 0;
    }

    co = check_bound_co();
    co->yield_ex(timeout);
    co = nullptr;

    swoole_trace_log(SW_TRACE_CO_CURL, "yield timeout, count=%lu", zend_llist_count(&mh->easyh));

    const auto count = selector.active_sockets.size();
    selector_finish();

    return static_cast<long>(count);
}

void Multi::callback(Socket *curl_socket, int bitmask, int sockfd) {
    swoole_trace_log(
        SW_TRACE_CO_CURL, "curl_socket=%p, bitmask=%d, co=%p, sockfd=%d", curl_socket, bitmask, co, sockfd);
    if (!curl_socket) {
        selector.timer_callback = true;
    }
    if (!co) {
        if (curl_socket) {
            swoole_event_del(curl_socket->socket);
        } else {
            del_timer();
        }
        return;
    }
    if (curl_socket) {
        selector.active_sockets.insert(curl_socket);
    }
    if (defer_callback) {
        return;
    }
    defer_callback = true;
    swoole_event_defer(
        [this](void *data) {
            defer_callback = false;
            if (co) {
                co->resume();
            }
        },
        nullptr);
}
}  // namespace curl
}  // namespace swoole

CURLcode swoole_curl_easy_perform(CURL *cp) {
    auto handle = swoole::curl::get_handle(cp);
    if (!handle->easy_multi) {
        handle->easy_multi = new Multi();
    }
    return handle->easy_multi->exec(handle);
}

void swoole_curl_easy_reset(CURL *cp) {
    auto handle = swoole::curl::get_handle(cp);
    curl_easy_reset(cp);
    curl_easy_setopt(cp, CURLOPT_PRIVATE, handle);
}

php_curl *swoole_curl_get_handle(zval *zid, bool exclusive, bool required) {
    php_curl *ch = Z_CURL_P(zid);
    if (SWOOLE_G(req_status) == PHP_SWOOLE_RSHUTDOWN_END) {
        exclusive = false;
    }
    if (exclusive && swoole_coroutine_is_in()) {
        auto handle = swoole::curl::get_handle(ch->cp);
        if (required && !handle) {
            php_swoole_fatal_error(E_WARNING, "The given handle is not initialized in coroutine");
            return nullptr;
        }
        if (handle && handle->multi && handle->multi->check_bound_co() == nullptr) {
            return nullptr;
        }
    }
    return ch;
}

#endif
