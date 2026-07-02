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
#include "swoole_afd.h"
#include "swoole_coroutine_system.h"
#include "swoole_socket.h"

#ifdef SW_USE_CURL

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef SW_CURL_USE_IOCP
static bool curl_iocp_debug_enabled() {
    static int enabled = -1;
    if (enabled < 0) {
        const char *value = getenv("SWOOLE_CURL_IOCP_DEBUG");
        enabled = value && value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
    }
    return enabled != 0;
}

#define CURL_IOCP_DEBUG(fmt, ...)                                                                                     \
    do {                                                                                                              \
        if (curl_iocp_debug_enabled()) {                                                                              \
            fprintf(stderr, "[swoole-curl-iocp] " fmt "\n", ##__VA_ARGS__);                                         \
            fflush(stderr);                                                                                           \
        }                                                                                                             \
    } while (0)
#else
#define CURL_IOCP_DEBUG(fmt, ...)
#endif

SW_EXTERN_C_BEGIN
zend_class_entry *php_curl_ce = NULL;
zend_class_entry *php_curl_multi_ce = NULL;
zend_class_entry *php_curl_share_ce = NULL;
#if PHP_VERSION_ID >= 80500
zend_class_entry *php_curl_share_persistent_ce = NULL;
#endif
zend_class_entry *php_curl_CURLFile_ce = NULL;
zend_class_entry *php_curl_CURLStringFile_ce = NULL;

zend_class_entry *swoole_coroutine_curl_handle_ce;
zend_class_entry *swoole_coroutine_curl_multi_handle_ce;
SW_EXTERN_C_END

namespace swoole {
namespace curl {

void minit() {
    php_curl_ce = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("curlhandle"));
    php_curl_multi_ce = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("curlmultihandle"));
    php_curl_share_ce = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("curlsharehandle"));
#if PHP_VERSION_ID >= 80500
    php_curl_share_persistent_ce = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("curlsharepersistenthandle"));
#endif
    php_curl_CURLFile_ce = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("curlfile"));
    php_curl_CURLStringFile_ce = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("curlstringfile"));
}

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

#ifdef SW_CURL_USE_IOCP
static bool is_ip_address(const char *host) {
    in_addr ipv4 {};
    in6_addr ipv6 {};
    return InetPtonA(AF_INET, host, &ipv4) == 1 || InetPtonA(AF_INET6, host, &ipv6) == 1;
}
#endif

void prepare_resolve(Handle *handle) {
#ifdef SW_CURL_USE_IOCP
    handle->clear_resolve();

    char *effective_url = nullptr;
    if (curl_easy_getinfo(handle->cp, CURLINFO_EFFECTIVE_URL, &effective_url) != CURLE_OK || !effective_url ||
        !effective_url[0]) {
        return;
    }

    CURLU *url = curl_url();
    if (!url) {
        return;
    }

    char *scheme = nullptr;
    char *host = nullptr;
    char *port = nullptr;
    std::string port_string;

    if (curl_url_set(url, CURLUPART_URL, effective_url, 0) != CURLUE_OK ||
        curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK || !host || !host[0] ||
        is_ip_address(host)) {
        goto cleanup;
    }

    if (curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) == CURLUE_OK && port && port[0]) {
        port_string = port;
    } else {
        if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK || !scheme) {
            goto cleanup;
        }
        if (std::strcmp(scheme, "https") == 0) {
            port_string = "443";
        } else if (std::strcmp(scheme, "http") == 0) {
            port_string = "80";
        } else {
            goto cleanup;
        }
    }

    {
        std::string ip = coroutine::System::gethostbyname(host, AF_INET);
        if (ip.empty()) {
            goto cleanup;
        }

        std::string resolve = std::string(host) + ":" + port_string + ":" + ip;
        curl_slist *resolve_list = curl_slist_append(nullptr, resolve.c_str());
        if (resolve_list) {
            handle->set_resolve(resolve_list);
            CURL_IOCP_DEBUG("resolve host=%s port=%s ip=%s", host, port_string.c_str(), ip.c_str());
        }
    }

cleanup:
    if (scheme) {
        curl_free(scheme);
    }
    if (host) {
        curl_free(host);
    }
    if (port) {
        curl_free(port);
    }
    curl_url_cleanup(url);
#else
    (void) handle;
#endif
}

#ifdef SW_CURL_USE_IOCP
static ULONG curl_action_to_afd_events(int action) {
    ULONG events = afd::POLL_DISCONNECT | afd::POLL_ABORT | afd::POLL_LOCAL_CLOSE | afd::POLL_CONNECT_FAIL;

    if (action != CURL_POLL_OUT) {
        events |= afd::POLL_RECEIVE | afd::POLL_RECEIVE_EXPEDITED;
    }
    if (action != CURL_POLL_IN) {
        events |= afd::POLL_SEND;
    }

    return events;
}

static int afd_events_to_curl_bitmask(ULONG events, LONG status) {
    int bitmask = 0;

    if (events & (afd::POLL_RECEIVE | afd::POLL_RECEIVE_EXPEDITED | afd::POLL_DISCONNECT | afd::POLL_ABORT |
                  afd::POLL_LOCAL_CLOSE)) {
        bitmask |= CURL_CSELECT_IN;
    }
    if (events & afd::POLL_SEND) {
        bitmask |= CURL_CSELECT_OUT;
    }
    if (status != 0 || (events & (afd::POLL_CONNECT_FAIL | afd::POLL_ABORT | afd::POLL_LOCAL_CLOSE))) {
        bitmask |= CURL_CSELECT_ERR;
    }

    return bitmask;
}

struct IocpOperation {
    IocpEvent event;
    Socket *curl_socket;
    afd::PollInfo poll_info;

    explicit IocpOperation(Socket *curl_socket_)
        : event(SW_IOCP_CUSTOM, curl_socket_->sockfd), curl_socket(curl_socket_) {
        event.callback = on_complete;
        event.private_data = this;

        afd::init_poll_info(&poll_info, curl_socket_->sockfd, curl_action_to_afd_events(curl_socket_->action));
    }

    static void on_complete(IocpEvent *event, DWORD transferred, DWORD error) {
        (void) transferred;
        auto *operation = static_cast<IocpOperation *>(event->private_data);
        Socket *curl_socket = operation->curl_socket;
        const ULONG afd_events = operation->poll_info.handles[0].events;
        const LONG afd_status = operation->poll_info.handles[0].status;
        const int bitmask =
            error == ERROR_SUCCESS ? afd_events_to_curl_bitmask(afd_events, afd_status) : CURL_CSELECT_ERR;

        CURL_IOCP_DEBUG("complete fd=%d afd_events=0x%lx afd_status=%ld bitmask=%d transferred=%lu error=%lu orphaned=%d socket=%p",
                        (int) event->fd,
                        (unsigned long) afd_events,
                        (long) afd_status,
                        bitmask,
                        (unsigned long) transferred,
                        (unsigned long) error,
                        event->orphaned,
                        curl_socket);

        if (curl_socket) {
            if (operation == curl_socket->operation) {
                curl_socket->operation = nullptr;
            }

            if (!curl_socket->deleted && !event->orphaned) {
                curl_socket->multi->callback(curl_socket, bitmask, curl_socket->sockfd);
            }

            if (curl_socket->deleted && !curl_socket->operation) {
                delete curl_socket;
            }
        }

        delete operation;
    }
};
#else
static int execute_callback(Event *event, int bitmask) {
    auto curl_socket = static_cast<Socket *>(event->socket->object);
    curl_socket->bitmask |= bitmask;
    curl_socket->multi->callback(curl_socket, bitmask, event->fd);
    return 0;
}
#endif

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
#ifdef SW_CURL_USE_IOCP
    for (auto it : sockets) {
        release_socket(it.second);
    }
    sockets.clear();
#endif
    curl_multi_cleanup(multi_handle_);
}

#ifndef SW_CURL_USE_IOCP
int Multi::cb_readable(Reactor *reactor, Event *event) {
    return execute_callback(event, CURL_CSELECT_IN);
}

int Multi::cb_writable(Reactor *reactor, Event *event) {
    return execute_callback(event, CURL_CSELECT_OUT);
}

int Multi::cb_error(Reactor *reactor, Event *event) {
    return execute_callback(event, CURL_CSELECT_ERR);
}
#endif

int Multi::handle_socket(CURL *cp, curl_socket_t sockfd, int action, void *userp, void *socketp) {
    auto *multi = static_cast<Multi *>(userp);
    CURL_IOCP_DEBUG("handle_socket curl=%p fd=%d action=%d socketp=%p", cp, (int) sockfd, action, socketp);
    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_CYAN "curl=%p, sockfd=%d, action=%d, userp=%p, socketp=%p",
                     "[HANDLE_SOCKET]",
                     cp,
                     (int) sockfd,
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
        swoole_warning("unexpected curl socket action[%d]", action);
        return 0;
    }
}

#ifdef SW_CURL_USE_IOCP
int Multi::post_event(Socket *curl_socket, int bitmask) {
    if (curl_socket->deleted) {
        CURL_IOCP_DEBUG("post_event skip deleted socket=%p fd=%d bitmask=%d",
                        curl_socket,
                        (int) curl_socket->sockfd,
                        bitmask);
        return SW_ERR;
    }

    if (curl_socket->operation) {
        CURL_IOCP_DEBUG("post_event skip pending socket=%p fd=%d bitmask=%d",
                        curl_socket,
                        (int) curl_socket->sockfd,
                        bitmask);
        return SW_OK;
    }

    if (sw_unlikely(!Iocp::init(sw_reactor()))) {
        CURL_IOCP_DEBUG("post_event init iocp failed fd=%d bitmask=%d", (int) curl_socket->sockfd, bitmask);
        return SW_ERR;
    }

    auto iocp = SwooleTG.iocp;
    if (sw_unlikely(!iocp->associate_socket(curl_socket->sockfd))) {
        CURL_IOCP_DEBUG("post_event associate failed fd=%d bitmask=%d", (int) curl_socket->sockfd, bitmask);
        return SW_ERR;
    }

    auto *operation = new IocpOperation(curl_socket);
    curl_socket->operation = operation;
    iocp->submit(&operation->event);

    DWORD bytes = 0;
    BOOL retval = DeviceIoControl(reinterpret_cast<HANDLE>(curl_socket->sockfd),
                                  afd::IOCTL_POLL,
                                  &operation->poll_info,
                                  sizeof(operation->poll_info),
                                  &operation->poll_info,
                                  sizeof(operation->poll_info),
                                  &bytes,
                                  &operation->event.overlapped);

    int error = retval ? ERROR_SUCCESS : GetLastError();
    CURL_IOCP_DEBUG("post_event fd=%d action=%d afd_events=0x%lx retval=%d error=%d",
                    (int) curl_socket->sockfd,
                    curl_socket->action,
                    (unsigned long) operation->poll_info.handles[0].events,
                    retval,
                    error);

    if (!retval) {
        if (error != WSA_IO_PENDING) {
            iocp->cancel_submission(&operation->event);
            curl_socket->operation = nullptr;
            delete operation;
            Iocp::set_error(error);
            return SW_ERR;
        }
    }

    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_GREEN " curl_socket=%p, fd=%d, bitmask=%d",
                     "[IOCP_POST]",
                     curl_socket,
                     (int) curl_socket->sockfd,
                     bitmask);
    return SW_OK;
}

void Multi::cancel_event(IocpOperation *operation) {
    if (!operation || operation->event.completed) {
        return;
    }
    CURL_IOCP_DEBUG("cancel_event fd=%d", (int) operation->event.fd);
    if (SwooleTG.iocp) {
        SwooleTG.iocp->cancel_submission(&operation->event);
    } else {
        operation->event.orphaned = true;
    }
    CancelIoEx(reinterpret_cast<HANDLE>(operation->event.fd), &operation->event.overlapped);
}

void Multi::try_free_socket(Socket *curl_socket) {
    if (!curl_socket || curl_socket->operation) {
        return;
    }
    delete curl_socket;
}

void Multi::release_socket(Socket *curl_socket) {
    if (!curl_socket || curl_socket->deleted) {
        return;
    }
    CURL_IOCP_DEBUG("release_socket socket=%p fd=%d operation=%p",
                    curl_socket,
                    (int) curl_socket->sockfd,
                    curl_socket->operation);
    curl_socket->deleted = true;
    cancel_event(curl_socket->operation);
    if (selector.executing && !curl_socket->operation) {
        selector.release_sockets.insert(curl_socket);
    } else {
        try_free_socket(curl_socket);
    }
}

int Multi::del_event(void *socket_ptr, curl_socket_t sockfd) {
    sockets.erase(sockfd);
    curl_multi_assign(multi_handle_, sockfd, nullptr);
    CURL_IOCP_DEBUG("del_event fd=%d socketp=%p sockets=%zu", (int) sockfd, socket_ptr, sockets.size());

    if (sw_unlikely(!socket_ptr)) {
        return SW_ERR;
    }

    auto curl_socket = static_cast<Socket *>(socket_ptr);
    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_RED " socket_ptr=%p, fd=%d", "[IOCP_DEL]", socket_ptr, (int) sockfd);
    release_socket(curl_socket);
    return SW_OK;
}

int Multi::set_event(void *socket_ptr, curl_socket_t sockfd, int action) {
    Socket *curl_socket;

    if (socket_ptr) {
        curl_socket = static_cast<Socket *>(socket_ptr);
    } else {
        curl_socket = new Socket();
        curl_socket->sockfd = sockfd;
        curl_socket->multi = this;

        if (sw_unlikely(curl_multi_assign(multi_handle_, sockfd, curl_socket) != CURLM_OK)) {
            delete curl_socket;
            return SW_ERR;
        }
        sockets[sockfd] = curl_socket;
        CURL_IOCP_DEBUG("set_event new socket=%p fd=%d sockets=%zu", curl_socket, (int) sockfd, sockets.size());
    }

    curl_socket->sockfd = sockfd;
    curl_socket->action = action;
    curl_socket->multi = this;

    cancel_event(curl_socket->operation);

    CURL_IOCP_DEBUG("set_event socket=%p fd=%d action=%d operation=%p",
                    curl_socket,
                    (int) sockfd,
                    action,
                    curl_socket->operation);
    swoole_trace_log(SW_TRACE_CO_CURL,
                     SW_ECHO_GREEN " curl_socket=%p, fd=%d, action=%d",
                     "[IOCP_SET]",
                     curl_socket,
                     (int) sockfd,
                     action);
    return SW_OK;
}
#else
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

    int events = get_event(action);

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
#endif

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
#ifdef SW_CURL_USE_IOCP
        if (curl_socket->deleted) {
            continue;
        }
        post_event(curl_socket,
                   curl_socket->action == CURL_POLL_IN     ? CURL_CSELECT_IN
                   : curl_socket->action == CURL_POLL_OUT  ? CURL_CSELECT_OUT
                                                            : (CURL_CSELECT_IN | CURL_CSELECT_OUT));
#else
        if (curl_socket->socket->removed) {
            swoole_event_add(curl_socket->socket, get_event(curl_socket->action));
            swoole_trace_log(SW_TRACE_CO_CURL,
                             "resume, curl_socket=%p, fd=%d, action=%d",
                             curl_socket,
                             curl_socket->socket->get_fd(),
                             curl_socket->action);
        }
#endif
    }
}

CURLcode Multi::exec(Handle *handle) {
    prepare_resolve(handle);
    if (add_handle(handle) != CURLM_OK) {
        return CURLE_FAILED_INIT;
    }

    bool is_canceled = false;
    CURL_IOCP_DEBUG("exec begin handle=%p curl=%p running=%d sockets=%zu",
                    handle,
                    handle->cp,
                    running_handles_,
                    sockets.size());

    SW_LOOP {
        CURL_IOCP_DEBUG("exec loop before_prepare running=%d sockets=%zu timer=%p",
                        running_handles_,
                        sockets.size(),
                        timer);
        selector_prepare();

        if (selector.active_sockets.empty() && wait_event()) {
            co = check_bound_co();
            CURL_IOCP_DEBUG("exec yield cid=%ld running=%d sockets=%zu timer=%p",
                            co ? co->get_cid() : -1,
                            running_handles_,
                            sockets.size(),
                            timer);
            co->yield_ex(-1);
            is_canceled = co->is_canceled();
            CURL_IOCP_DEBUG("exec resume canceled=%d running=%d sockets=%zu timer=%p",
                            is_canceled,
                            running_handles_,
                            sockets.size(),
                            timer);
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
    CURL_IOCP_DEBUG("exec end retval=%d canceled=%d running=%d sockets=%zu",
                    retval,
                    is_canceled,
                    running_handles_,
                    sockets.size());
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
    CURL_IOCP_DEBUG("handle_timeout timeout_ms=%ld timer=%p sockets=%zu",
                    timeout_ms,
                    multi->timer,
                    multi->sockets.size());
    swoole_trace_log(SW_TRACE_CO_CURL, SW_ECHO_BLUE " timeout_ms=%ld", "[HANDLE_TIMEOUT]", timeout_ms);
    if (sw_unlikely(!swoole_event_is_available())) {
        return -1;
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

void Multi::selector_finish() {
    del_timer();

    selector.executing = true;

    if (selector.timer_callback) {
        selector.timer_callback = false;
        auto rc = curl_multi_socket_action(multi_handle_, CURL_SOCKET_TIMEOUT, 0, &running_handles_);
        CURL_IOCP_DEBUG("socket_action timer rc=%d running=%d sockets=%zu", rc, running_handles_, sockets.size());
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
                             (int) curl_socket->sockfd,
                             curl_socket->bitmask,
                             running_handles_);

            if (!curl_socket->deleted) {
                int bitmask = curl_socket->bitmask;
                curl_socket->bitmask = 0;
                auto rc = curl_multi_socket_action(multi_handle_, curl_socket->sockfd, bitmask, &running_handles_);
                CURL_IOCP_DEBUG("socket_action fd=%d bitmask=%d rc=%d running=%d sockets=%zu",
                                (int) curl_socket->sockfd,
                                bitmask,
                                rc,
                                running_handles_,
                                sockets.size());
            }
        }
    }

    selector.executing = false;
    for (auto curl_socket : selector.release_sockets) {
#ifdef SW_CURL_USE_IOCP
        try_free_socket(curl_socket);
#else
        delete curl_socket;
#endif
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
    CURL_IOCP_DEBUG("callback socket=%p fd=%d bitmask=%d co=%p defer=%d",
                    curl_socket,
                    sockfd,
                    bitmask,
                    co,
                    defer_callback);
    swoole_trace_log(
        SW_TRACE_CO_CURL, "curl_socket=%p, bitmask=%d, co=%p, sockfd=%d", curl_socket, bitmask, co, sockfd);
    if (!curl_socket) {
        selector.timer_callback = true;
    }
    if (!co) {
        if (curl_socket) {
#ifndef SW_CURL_USE_IOCP
            swoole_event_del(curl_socket->socket);
#endif
        } else {
            del_timer();
        }
        return;
    }
    if (curl_socket) {
        curl_socket->bitmask |= bitmask;
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
