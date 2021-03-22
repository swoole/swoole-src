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

#include "php_swoole_curl.h"

#ifdef SW_USE_CURL

namespace swoole {
namespace curl {

int Multi::cb_readable(Reactor *reactor, Event *event) {
    Handle *handle = (Handle *) event->socket->object;
    handle->multi->callback(handle, CURL_CSELECT_IN);
    return 0;
}

int Multi::cb_writable(Reactor *reactor, Event *event) {
    Handle *handle = (Handle *) event->socket->object;
    handle->multi->callback(handle, CURL_CSELECT_OUT);
    return 0;
}

int Multi::cb_error(Reactor *reactor, Event *event) {
    Handle *handle = (Handle *) event->socket->object;
    handle->multi->callback(handle, CURL_CSELECT_ERR);
    return 0;
}

int Multi::handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
    Multi *multi = (Multi *) userp;
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
    socket->fd_type = (enum swFd_type) PHP_SWOOLE_FD_CO_CURL;
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
    if (socket->events && swoole_event_is_available()) {
        swoole_event_del(socket);
    }
    socket->fd = -1;
    socket->free();
    curl_multi_assign(multi_handle_, sockfd, NULL);

    Handle *handle = get_handle(cp);
    handle->socket = nullptr;

    swTraceLog(SW_TRACE_CO_CURL, SW_ECHO_RED " handle=%p, curl=%p, fd=%d", "[DEL]", handle, cp, sockfd);
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
        swoole_event_add(socket, events);
    }
    Handle *handle = get_handle(cp);
    handle->action = action;
    handle->removed = false;

    swTraceLog(SW_TRACE_CO_CURL, SW_ECHO_GREEN " handle=%p, curl=%p, fd=%d, events=%d", "[ADD]", handle, cp, sockfd, events);
}

CURLcode Multi::exec(php_curl *ch) {
    if (co) {
        swFatalError(SW_ERROR_CO_HAS_BEEN_BOUND, "cURL is already waiting, cannot be operated");
        return CURLE_FAILED_INIT;
    }

    co = Coroutine::get_current_safe();
    ON_SCOPE_EXIT {
        co = nullptr;
    };

    if (add_handle(ch->cp) != CURLM_OK) {
        return CURLE_FAILED_INIT;
    }

    Handle *handle = get_handle(ch->cp);

    SW_LOOP {
        co->yield();
        int sockfd = last_sockfd;
        int bitmask = 0;
        if (sockfd >= 0) {
            bitmask = handle->bitmask;
            swoole_event_del(handle->socket);
            handle->removed = true;
        }
        del_timer();
        curl_multi_socket_action(multi_handle_, sockfd, bitmask, &running_handles_);
        if (running_handles_ == 0) {
            break;
        }
        long _timeout_ms = 0;
        curl_multi_timeout(multi_handle_, &_timeout_ms);
        add_timer(_timeout_ms == 0 ? 1: _timeout_ms);
        if (sockfd >= 0 && handle->socket && handle->removed) {
            swoole_event_add(handle->socket, get_event(handle->action));
            handle->removed = false;
        }
    }

    CURLcode retval = read_info();
    remove_handle(ch->cp);
    return retval;
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
            swWarn("CURLMSG default");
            break;
        }
    }
    return CURLE_OK;
}

int Multi::handle_timeout(CURLM *mh, long timeout_ms, void *userp) {
    Multi *multi = (Multi *) userp;
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

long Multi::select(php_curlm *mh) {
    if (co) {
        swFatalError(SW_ERROR_CO_HAS_BEEN_BOUND, "cURL is already waiting, cannot be operated");
        return CURLE_FAILED_INIT;
    }

    co = Coroutine::get_current_safe();
    ON_SCOPE_EXIT {
        co = nullptr;
    };

    long _timeout_ms = 0;
    curl_multi_timeout(multi_handle_, &_timeout_ms);
    add_timer(_timeout_ms == 0 ? 1: _timeout_ms);

    for (zend_llist_element *element = mh->easyh.head; element; element = element->next) {
        zval *z_ch = (zval *) element->data;
        php_curl *ch;
        if ((ch = _php_curl_get_handle(z_ch, false)) == NULL) {
            continue;
        }
        Handle *handle = get_handle(ch->cp);
        if (handle && handle->socket && handle->removed) {
            swoole_event_add(handle->socket, get_event(handle->action));
            handle->removed = false;
            swTraceLog(SW_TRACE_CO_CURL, "resume, handle=%p, curl=%p, fd=%d", handle, ch->cp, handle->socket->get_fd());
        }
    }

    co->yield();
    auto count = selector->active_handles.size();

    for (zend_llist_element *element = mh->easyh.head; element; element = element->next) {
        zval *z_ch = (zval *) element->data;
        php_curl *ch;
        if ((ch = _php_curl_get_handle(z_ch, false)) == NULL) {
            continue;
        }
        Handle *handle = get_handle(ch->cp);
        if (handle && handle->socket) {
            swTraceLog(SW_TRACE_CO_CURL, "suspend, handle=%p, curl=%p, fd=%d", handle, ch->cp, handle->socket->get_fd());
            swoole_event_del(handle->socket);
            handle->removed = true;
        }
    }
    del_timer();

    for (auto iter = selector->active_handles.begin(); iter != selector->active_handles.end(); iter++) {
        Handle *handle = *iter;
        int bitmask = 0;
        int sockfd = -1;
        if (handle) {
            bitmask = handle->bitmask;
            sockfd = handle->socket->fd;
        }
        curl_multi_socket_action(multi_handle_, sockfd, bitmask, &running_handles_);
        swTraceLog(SW_TRACE_CO_CURL, "socket_action, running_handles=%d", running_handles_);
    }
    selector->active_handles.clear();

    return count;
}

void Multi::callback(Handle *handle, int event_bitmask) {
    if (handle) {
        last_sockfd = handle->socket->fd;
        handle->bitmask = event_bitmask;
    } else {
        last_sockfd = -1;
    }
    // for curl_multi_select
    if (selector.get()) {
        if (!co) {
            if (handle) {
                swoole_event_del(handle->socket);
                handle->removed = true;
            } else {
                del_timer();
            }
            return;
        }
        selector->active_handles.insert(handle);
        if (selector->defer_callback) {
            return;
        }
        selector->defer_callback = true;
        swoole_event_defer(
            [this](void *data) {
                selector->defer_callback = false;
                co->resume();
            },
            nullptr);
    } else {
        co->resume();
    }
}
}  // namespace curl
}  // namespace swoole
#endif
