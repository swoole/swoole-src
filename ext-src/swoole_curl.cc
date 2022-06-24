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

static int execute_callback(Event *event, int bitmask) {
    Handle *handle = (Handle *) event->socket->object;
    handle->event_bitmask |= bitmask;
    handle->event_fd = event->fd;
    handle->multi->callback(handle, bitmask);
    return 0;
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

int Multi::handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
    Multi *multi = (Multi *) userp;
    swoole_trace_log(
        SW_TRACE_CO_CURL, SW_ECHO_CYAN "action=%d, userp=%p, socketp=%p", "[HANDLE_SOCKET]", action, userp, socketp);
    switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
        multi->set_event(easy, socketp, s, action);
        break;
    case CURL_POLL_REMOVE:
        if (socketp) {
            multi->del_event(easy, socketp, s);
        }
        break;
    default:
        abort();
    }
    return 0;
}

Socket *Multi::create_socket(CURL *cp, curl_socket_t sockfd) {
    if (!swoole_event_isset_handler(PHP_SWOOLE_FD_CO_CURL)) {
        swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_READ, cb_readable);
        swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_WRITE, cb_writable);
        swoole_event_set_handler(PHP_SWOOLE_FD_CO_CURL | SW_EVENT_ERROR, cb_error);
    }
    Socket *socket = new Socket();
    socket->fd = sockfd;
    socket->removed = 1;
    socket->fd_type = (FdType) PHP_SWOOLE_FD_CO_CURL;
    curl_multi_assign(multi_handle_, sockfd, (void *) socket);

    Handle *handle = get_handle(cp);
    handle->socket = socket;
    handle->cp = cp;
    socket->object = handle;

    return socket;
}

void Multi::del_event(CURL *cp, void *socket_ptr, curl_socket_t sockfd) {
    Socket *socket = (Socket *) socket_ptr;
    socket->silent_remove = 1;
    if (socket->events && swoole_event_is_available() && swoole_event_del(socket) == SW_OK) {
        event_count_--;
    }
    socket->fd = -1;
    socket->free();
    curl_multi_assign(multi_handle_, sockfd, NULL);

    Handle *handle = get_handle(cp);
    if (handle) {
        handle->socket = nullptr;
    }

    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_RED " handle=%p, curl=%p, fd=%d", "[DEL_EVENT]", handle, cp, sockfd);
}

void Multi::set_event(CURL *cp, void *socket_ptr, curl_socket_t sockfd, int action) {
    Socket *socket = socket_ptr ? (Socket *) socket_ptr : create_socket(cp, sockfd);
    int events = 0;
    if (action != CURL_POLL_IN) {
        events |= SW_EVENT_WRITE;
    }
    if (action != CURL_POLL_OUT) {
        events |= SW_EVENT_READ;
    }
    assert(socket->fd > 0);
    socket->fd = sockfd;
    if (socket->events) {
        swoole_event_set(socket, events);
    } else {
        if (swoole_event_add(socket, events) == SW_OK) {
            event_count_++;
        }
    }
    Handle *handle = get_handle(cp);
    handle->action = action;

    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_GREEN " handle=%p, curl=%p, fd=%d, events=%d",
                     "[ADD_EVENT]",
                     handle,
                     cp,
                     sockfd,
                     events);
}

CURLMcode Multi::add_handle(CURL *cp) {
    auto retval = curl_multi_add_handle(multi_handle_, cp);
    if (retval == CURLM_OK) {
        auto handle = get_handle(cp);
        if (handle == nullptr) {
            handle = new Handle{};
            handle->cp = cp;
            curl_easy_setopt(cp, CURLOPT_PRIVATE, handle);
        }
        handle->multi = this;
        swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_GREEN " handle=%p, curl=%p", "[ADD_HANDLE]", handle, cp);
    }
    return retval;
}

CURLMcode Multi::remove_handle(CURL *cp) {
    auto retval = curl_multi_remove_handle(multi_handle_, cp);
    if (retval == CURLM_OK) {
        auto handle = get_handle(cp);
        if (handle) {
            handle->multi = nullptr;
        }
        swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_RED " handle=%p, curl=%p", "[REMOVE_HANDLE]", handle, cp);
    }
    return retval;
}

CURLcode Multi::exec(php_curl *ch) {
    if (add_handle(ch->cp) != CURLM_OK) {
        return CURLE_FAILED_INIT;
    }

    Handle *handle = get_handle(ch->cp);
    bool is_canceled = false;

    SW_LOOP {
        if (handle->socket && handle->socket->removed) {
            if (swoole_event_add(handle->socket, get_event(handle->action)) == SW_OK) {
                event_count_++;
            }
            swoole_trace_log(
                SW_TRACE_CO_CURL, "resume, handle=%p, curl=%p, fd=%d", handle, ch->cp, handle->socket->get_fd());
        }

        co = check_bound_co();
        co->yield_ex(-1);
        is_canceled = co->is_canceled();
        co = nullptr;

        if (is_canceled) {
            swoole_set_last_error(SW_ERROR_CO_CANCELED);
            break;
        }

        int sockfd = last_sockfd;
        int bitmask = 0;
        if (sockfd >= 0) {
            bitmask = handle->event_bitmask;
            if (handle->socket && !handle->socket->removed && swoole_event_del(handle->socket) == SW_OK) {
                event_count_--;
            }
        }
        del_timer();

        curl_multi_socket_action(multi_handle_, sockfd, bitmask, &running_handles_);
        swoole_trace_log(SW_TRACE_CO_CURL,
                         "curl_multi_socket_action: handle=%p, sockfd=%d, bitmask=%d, running_handles_=%d",
                         handle,
                         sockfd,
                         bitmask,
                         running_handles_);
        if (running_handles_ == 0) {
            break;
        }
        set_timer();
        if (sockfd >= 0 && handle->socket && handle->socket->removed) {
            if (swoole_event_add(handle->socket, get_event(handle->action)) == SW_OK) {
                event_count_++;
            }
        }
        if (!timer && handle->socket->removed) {
            break;
        }
    }

    CURLcode retval = read_info();
    remove_handle(ch->cp);
    return is_canceled ? CURLE_ABORTED_BY_CALLBACK : retval;
}

CURLcode Multi::read_info() {
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
    Multi *multi = (Multi *) userp;
    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_BLUE "timeout_ms=%ld", "[HANDLE_TIMEOUT]", timeout_ms);
    if (!swoole_event_is_available()) {
        return 0;
    }
    if (timeout_ms < 0) {
        multi->del_timer();
    } else {
        if (timeout_ms == 0) {
            timeout_ms = 1; /* 0 means directly call socket_action, but we'll do it in a bit */
        }
        multi->add_timer(timeout_ms);
    }
    return 0;
}

long Multi::select(php_curlm *mh, double timeout) {
    if (zend_llist_count(&mh->easyh) == 0) {
        return 0;
    }

    if (curl_multi_socket_all(multi_handle_, &running_handles_) != CURLM_OK) {
        return CURLE_FAILED_INIT;
    }

    for (zend_llist_element *element = mh->easyh.head; element; element = element->next) {
        zval *z_ch = (zval *) element->data;
        php_curl *ch;
        if ((ch = swoole_curl_get_handle(z_ch, false)) == NULL) {
            continue;
        }
        Handle *handle = get_handle(ch->cp);

        swoole_trace_log(SW_TRACE_CO_CURL,
                         "handle=%p, handle->socket=%p, handle->socket->removed=%d",
                         handle,
                         handle ? handle->socket : nullptr,
                         handle ? (handle->socket ? handle->socket->removed : 1) : 1);

        if (handle && handle->socket && handle->socket->removed) {
            if (swoole_event_add(handle->socket, get_event(handle->action)) == SW_OK) {
                event_count_++;
            }
            swoole_trace_log(
                SW_TRACE_CO_CURL, "resume, handle=%p, curl=%p, fd=%d", handle, ch->cp, handle->socket->get_fd());
        }
    }
    set_timer();

    // no events and timers, should not be suspended
    if (!timer && event_count_ == 0) {
        return 0;
    }

    co = check_bound_co();
    co->yield_ex(timeout);
    co = nullptr;

    swoole_trace_log(SW_TRACE_CO_CURL, "yield timeout, count=%lu", zend_llist_count(&mh->easyh));

    auto count = selector->active_handles.size();

    for (zend_llist_element *element = mh->easyh.head; element; element = element->next) {
        zval *z_ch = (zval *) element->data;
        php_curl *ch;
        if ((ch = swoole_curl_get_handle(z_ch, false)) == NULL) {
            continue;
        }
        Handle *handle = get_handle(ch->cp);
        if (handle && handle->socket && !handle->socket->removed && swoole_event_del(handle->socket) == SW_OK) {
            swoole_trace_log(
                SW_TRACE_CO_CURL, "suspend, handle=%p, curl=%p, fd=%d", handle, ch->cp, handle->socket->get_fd());
            event_count_--;
        }
    }
    del_timer();

    if (selector->timer_callback) {
        selector->timer_callback = false;
        curl_multi_socket_action(multi_handle_, CURL_SOCKET_TIMEOUT, 0, &running_handles_);
        swoole_trace_log(SW_TRACE_CO_CURL, "socket_action[timer], running_handles=%d", running_handles_);
    }

    for (auto iter = selector->active_handles.begin(); iter != selector->active_handles.end(); iter++) {
        Handle *handle = *iter;
        curl_multi_socket_action(multi_handle_, handle->event_fd, handle->event_bitmask, &running_handles_);
        swoole_trace_log(SW_TRACE_CO_CURL, "socket_action[socket], running_handles=%d", running_handles_);
    }

    selector->active_handles.clear();

    return count;
}

void Multi::callback(Handle *handle, int event_bitmask) {
    swoole_trace_log(SW_TRACE_CO_CURL, "handle=%p, event_bitmask=%d, co=%p", handle, event_bitmask, co);
    if (handle) {
        last_sockfd = handle->event_fd;
    } else {
        last_sockfd = -1;
    }
    if (selector.get()) {
        if (!handle) {
            selector->timer_callback = true;
        }
    }
    if (!co) {
        if (handle) {
            if (swoole_event_del(handle->socket) == SW_OK) {
                event_count_--;
            }
        } else {
            del_timer();
        }
        return;
    }
    if (selector.get() && handle) {
        selector->active_handles.insert(handle);
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
#endif
