/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#include "php_swoole_cxx.h"
#include "swoole_server.h"
#include "swoole_signal.h"

BEGIN_EXTERN_C()
#include "stubs/php_swoole_event_arginfo.h"
END_EXTERN_C()

using namespace swoole;
using swoole::network::Socket;

static std::unordered_map<int, Socket *> event_socket_map;

zend_class_entry *swoole_event_ce;
static zend_object_handlers swoole_event_handlers;

struct EventObject {
    zval zsocket;
    zend::Callable *readable_callback;
    zend::Callable *writable_callback;
};

static int event_readable_callback(Reactor *reactor, Event *event);
static int event_writable_callback(Reactor *reactor, Event *event);
static int event_error_callback(Reactor *reactor, Event *event);
static void event_defer_callback(void *data);
static void event_end_callback(void *data);

SW_EXTERN_C_BEGIN
static PHP_FUNCTION(swoole_event_add);
static PHP_FUNCTION(swoole_event_set);
static PHP_FUNCTION(swoole_event_del);
static PHP_FUNCTION(swoole_event_write);
static PHP_FUNCTION(swoole_event_wait);
static PHP_FUNCTION(swoole_event_rshutdown);
static PHP_FUNCTION(swoole_event_exit);
static PHP_FUNCTION(swoole_event_defer);
static PHP_FUNCTION(swoole_event_cycle);
static PHP_FUNCTION(swoole_event_dispatch);
static PHP_FUNCTION(swoole_event_isset);
SW_EXTERN_C_END

// clang-format off
static const zend_function_entry swoole_event_methods[] =
{
    ZEND_FENTRY(add,       ZEND_FN(swoole_event_add),       arginfo_swoole_event_add,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(del,       ZEND_FN(swoole_event_del),       arginfo_swoole_event_del,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(set,       ZEND_FN(swoole_event_set),       arginfo_swoole_event_set,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(isset,     ZEND_FN(swoole_event_isset),     arginfo_swoole_event_isset,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dispatch,  ZEND_FN(swoole_event_dispatch),  arginfo_swoole_event_dispatch,  ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(defer,     ZEND_FN(swoole_event_defer),     arginfo_swoole_event_defer,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(cycle,     ZEND_FN(swoole_event_cycle),     arginfo_swoole_event_cycle,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(write,     ZEND_FN(swoole_event_write),     arginfo_swoole_event_write,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(wait,      ZEND_FN(swoole_event_wait),      arginfo_swoole_event_wait,      ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(rshutdown, ZEND_FN(swoole_event_rshutdown), arginfo_swoole_event_rshutdown, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exit,      ZEND_FN(swoole_event_exit),      arginfo_swoole_event_exit,      ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
// clang-format on

void php_swoole_event_minit(int module_number) {
    SW_INIT_CLASS_ENTRY(swoole_event, "Swoole\\Event", nullptr, swoole_event_methods);
    SW_SET_CLASS_CREATE(swoole_event, sw_zend_create_object_deny);

    SW_FUNCTION_ALIAS(
        &swoole_event_ce->function_table, "add", CG(function_table), "swoole_event_add", arginfo_swoole_event_add);
    SW_FUNCTION_ALIAS(
        &swoole_event_ce->function_table, "del", CG(function_table), "swoole_event_del", arginfo_swoole_event_del);
    SW_FUNCTION_ALIAS(
        &swoole_event_ce->function_table, "set", CG(function_table), "swoole_event_set", arginfo_swoole_event_set);
    SW_FUNCTION_ALIAS(
        &swoole_event_ce->function_table, "wait", CG(function_table), "swoole_event_wait", arginfo_swoole_event_wait);

    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table,
                      "isset",
                      CG(function_table),
                      "swoole_event_isset",
                      arginfo_swoole_event_isset);
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table,
                      "dispatch",
                      CG(function_table),
                      "swoole_event_dispatch",
                      arginfo_swoole_event_dispatch);
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table,
                      "defer",
                      CG(function_table),
                      "swoole_event_defer",
                      arginfo_swoole_event_defer);
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table,
                      "cycle",
                      CG(function_table),
                      "swoole_event_cycle",
                      arginfo_swoole_event_cycle);
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table,
                      "write",
                      CG(function_table),
                      "swoole_event_write",
                      arginfo_swoole_event_write);
    SW_FUNCTION_ALIAS(&swoole_event_ce->function_table,
                      "exit",
                      CG(function_table),
                      "swoole_event_exit",
                      arginfo_swoole_event_rshutdown);
}

static void event_object_free(void *data) {
    EventObject *peo = (EventObject *) data;
    if (peo->readable_callback) {
        delete peo->readable_callback;
    }
    if (peo->writable_callback) {
        delete peo->writable_callback;
    }
    zval_ptr_dtor((&peo->zsocket));
    efree(peo);
}

static int event_readable_callback(Reactor *reactor, Event *event) {
    EventObject *peo = (EventObject *) event->socket->object;

    zval argv[1];
    argv[0] = peo->zsocket;
    auto fcc = peo->readable_callback->ptr();

    if (UNEXPECTED(!zend::function::call(fcc, 1, argv, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_fatal_error(E_WARNING,
                               "%s: readable callback handler error, fd [%d] will be removed from reactor",
                               ZSTR_VAL(swoole_event_ce->name),
                               php_swoole_convert_to_fd(&peo->zsocket));
        event->socket->object = nullptr;
        swoole_event_defer(event_object_free, peo);
        swoole_event_del(event->socket);
        return SW_ERR;
    }

    return SW_OK;
}

static int event_writable_callback(Reactor *reactor, Event *event) {
    EventObject *peo = (EventObject *) event->socket->object;

    zval argv[1];
    argv[0] = peo->zsocket;
    auto fcc = peo->writable_callback->ptr();

    if (UNEXPECTED(!zend::function::call(fcc, 1, argv, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_fatal_error(E_WARNING,
                               "%s: writable callback handler error, fd [%d] will be removed from reactor",
                               ZSTR_VAL(swoole_event_ce->name),
                               php_swoole_convert_to_fd(&peo->zsocket));
        event->socket->object = nullptr;
        swoole_event_defer(event_object_free, peo);
        swoole_event_del(event->socket);
        return SW_ERR;
    }

    return SW_OK;
}

static int event_error_callback(Reactor *reactor, Event *event) {
    if (!(event->socket->events & SW_EVENT_ERROR)) {
        if (event->socket->events & SW_EVENT_READ) {
            return reactor->get_handler(SW_EVENT_READ, event->socket->fd_type)(reactor, event);
        } else {
            return reactor->get_handler(SW_EVENT_WRITE, event->socket->fd_type)(reactor, event);
        }
    }

    int error;
    if (event->socket->get_option(SOL_SOCKET, SO_ERROR, &error) < 0) {
        php_swoole_sys_error(E_WARNING, "swoole_event->onError[1]: getsockopt[sock=%d] failed", event->fd);
    }

    if (error != 0) {
        php_swoole_fatal_error(
            E_WARNING, "swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    event_object_free(event->socket->object);
    swoole_event_del(event->socket);

    return SW_OK;
}

static void event_defer_callback(void *data) {
    zend::Callable *cb = (zend::Callable *) data;
    if (UNEXPECTED(!zend::function::call(cb, 0, nullptr, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s::defer callback handler error", ZSTR_VAL(swoole_event_ce->name));
    }
    delete cb;
}

static void event_end_callback(void *data) {
    zend::Callable *cb = (zend::Callable *) data;
    if (UNEXPECTED(!zend::function::call(cb, 0, nullptr, nullptr, php_swoole_is_enable_coroutine()))) {
        php_swoole_error(E_WARNING, "%s::end callback handler error", ZSTR_VAL(swoole_event_ce->name));
    }
}

int php_swoole_reactor_init() {
    if (!SWOOLE_G(cli)) {
        php_swoole_fatal_error(E_ERROR, "async-io must be used in PHP CLI mode");
        return SW_ERR;
    }

    if (sw_server()) {
        if (sw_server()->is_task_worker() && !sw_server()->task_enable_coroutine) {
            php_swoole_fatal_error(
                E_ERROR, "Unable to use async-io in task processes, please set `task_enable_coroutine` to true");
            return SW_ERR;
        }
        if (sw_server()->is_manager()) {
            php_swoole_fatal_error(E_ERROR, "Unable to use async-io in manager process");
            return SW_ERR;
        }
    }
    if (!sw_reactor()) {
        swoole_trace_log(SW_TRACE_PHP, "init reactor");

        if (swoole_event_init(SW_EVENTLOOP_WAIT_EXIT) < 0) {
            php_swoole_fatal_error(E_ERROR, "Unable to create event-loop reactor");
            return SW_ERR;
        }

        php_swoole_register_shutdown_function("Swoole\\Event::rshutdown");
    }

    if (sw_reactor() && SwooleG.user_exit_condition &&
        !sw_reactor()->isset_exit_condition(Reactor::EXIT_CONDITION_USER_AFTER_DEFAULT)) {
        sw_reactor()->set_exit_condition(Reactor::EXIT_CONDITION_USER_AFTER_DEFAULT, SwooleG.user_exit_condition);
    }

    return SW_OK;
}

void php_swoole_event_wait() {
    if (php_swoole_is_fatal_error() || !sw_reactor()) {
        return;
    }
    if (swoole_coroutine_is_in()) {
        php_swoole_fatal_error(E_ERROR, "Unable to call Event::wait() in coroutine");
        return;
    }
    if (!sw_reactor()->if_exit() && !sw_reactor()->bailout) {
        // Don't disable object slot reuse while running shutdown functions:
        // https://github.com/php/php-src/commit/bd6eabd6591ae5a7c9ad75dfbe7cc575fa907eac
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
        zend_bool in_shutdown = EG(flags) & EG_FLAGS_IN_SHUTDOWN;
        EG(flags) &= ~EG_FLAGS_IN_SHUTDOWN;
#endif
        if (sw_reactor()->wait(nullptr) < 0) {
            php_swoole_sys_error(E_ERROR, "reactor wait failed");
        }
#if defined(EG_FLAGS_IN_SHUTDOWN) && !defined(EG_FLAGS_OBJECT_STORE_NO_REUSE)
        if (in_shutdown) {
            EG(flags) |= EG_FLAGS_IN_SHUTDOWN;
        }
#endif
    }
    swoole_event_free();
}

void php_swoole_event_exit() {
    if (sw_reactor()) {
        php_swoole_timer_clear_all();
        sw_reactor()->running = false;
    }
}

int php_swoole_convert_to_fd(zval *zsocket) {
    int fd = -1;

    switch (Z_TYPE_P(zsocket)) {
    case IS_RESOURCE: {
        php_stream *stream;
        if ((php_stream_from_zval_no_verify(stream, zsocket))) {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void **) &fd, 1) ==
                    SUCCESS &&
                fd >= 0) {
                return fd;
            }
        }
        php_swoole_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
        return SW_ERR;
    }
    case IS_LONG: {
        fd = Z_LVAL_P(zsocket);
        if (fd < 0) {
            php_swoole_fatal_error(E_WARNING, "invalid file descriptor#%d passed", fd);
            return SW_ERR;
        }
        return fd;
    }
    case IS_OBJECT: {
        zval *zfd = nullptr;
        if (sw_zval_is_co_socket(zsocket)) {
            zfd = sw_zend_read_property_ex(Z_OBJCE_P(zsocket), zsocket, SW_ZSTR_KNOWN(SW_ZEND_STR_FD), 0);
        } else if (sw_zval_is_client(zsocket)) {
            zfd = sw_zend_read_property_ex(Z_OBJCE_P(zsocket), zsocket, SW_ZSTR_KNOWN(SW_ZEND_STR_SOCK), 0);
        } else if (sw_zval_is_process(zsocket)) {
            zfd = sw_zend_read_property_ex(Z_OBJCE_P(zsocket), zsocket, SW_ZSTR_KNOWN(SW_ZEND_STR_PIPE), 0);
#ifdef SWOOLE_SOCKETS_SUPPORT
        } else if (sw_zval_is_php_socket(zsocket)) {
            php_socket *php_sock = SW_Z_SOCKET_P(zsocket);
            if (IS_INVALID_SOCKET(php_sock)) {
                php_swoole_fatal_error(E_WARNING, "contains a closed socket");
                return SW_ERR;
            }
            return php_sock->bsd_socket;
#endif
        }
        if (zfd == nullptr || Z_TYPE_P(zfd) != IS_LONG) {
            return SW_ERR;
        }
        return Z_LVAL_P(zfd);
    }
    default:
        php_swoole_fatal_error(E_WARNING, "invalid file descriptor passed");
        return SW_ERR;
    }
}

int php_swoole_convert_to_fd_ex(zval *zsocket, int *async) {
    int fd;

    *async = 0;
    if (Z_TYPE_P(zsocket) == IS_RESOURCE) {
        php_stream *stream;
        if ((php_stream_from_zval_no_verify(stream, zsocket))) {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void **) &fd, 1) ==
                    SUCCESS &&
                fd >= 0) {
                *async = (stream->wrapper && (stream->wrapper->wops == php_plain_files_wrapper.wops)) ? 0 : 1;
                return fd;
            }
        }
#ifdef SWOOLE_SOCKETS_SUPPORT
        else {
            php_socket *php_sock;
            if ((php_sock = SW_Z_SOCKET_P(zsocket))) {
                fd = php_sock->bsd_socket;
                *async = 1;
                return fd;
            }
        }
#endif
    }
    php_swoole_fatal_error(E_WARNING, "fd argument must be either valid PHP stream or valid PHP socket resource");
    return SW_ERR;
}

#ifdef SWOOLE_SOCKETS_SUPPORT
php_socket *php_swoole_convert_to_socket(int sock) {
    php_socket *socket_object;
    zval zsocket;
    object_init_ex(&zsocket, socket_ce);
    socket_object = Z_SOCKET_P(&zsocket);
    socket_import_file_descriptor(sock, socket_object);
    return socket_object;
}
#endif

static void event_check_reactor() {
    php_swoole_check_reactor();

    if (!swoole_event_isset_handler(SW_FD_USER)) {
        swoole_event_set_handler(SW_FD_USER | SW_EVENT_READ, event_readable_callback);
        swoole_event_set_handler(SW_FD_USER | SW_EVENT_WRITE, event_writable_callback);
        swoole_event_set_handler(SW_FD_USER | SW_EVENT_ERROR, event_error_callback);
    }
}

static Socket *event_get_socket(int socket_fd) {
    auto i = event_socket_map.find(socket_fd);
    if (i == event_socket_map.end()) {
        return nullptr;
    }
    return i->second;
}

static PHP_FUNCTION(swoole_event_add) {
    zval *zfd;
    zend_long events = SW_EVENT_READ;
    zval *zreadable_callback = nullptr;
    zval *zwritable_callback = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(zreadable_callback)
    Z_PARAM_ZVAL(zwritable_callback)
    Z_PARAM_LONG(events)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    event_check_reactor();

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        php_swoole_fatal_error(E_WARNING, "unknown fd type");
        RETURN_FALSE;
    }
    if (socket_fd == 0 && (events & SW_EVENT_WRITE)) {
        php_swoole_fatal_error(E_WARNING, "invalid socket fd [%d]", socket_fd);
        RETURN_FALSE;
    }
    if (event_socket_map.find(socket_fd) != event_socket_map.end()) {
        php_swoole_fatal_error(E_WARNING, "already exist");
        RETURN_FALSE;
    }
    if (!(events & (SW_EVENT_WRITE | SW_EVENT_READ))) {
        php_swoole_fatal_error(E_WARNING, "invalid events");
        RETURN_FALSE;
    }
    Socket *socket = swoole::make_socket(socket_fd, SW_FD_USER);
    if (!socket) {
        RETURN_FALSE;
    }

    auto readable_callback = sw_callable_create_ex(zreadable_callback, "readable_callback", true);
    if ((events & SW_EVENT_READ) && readable_callback == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "%s: unable to find readable callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }

    auto writable_callback = sw_callable_create_ex(zwritable_callback, "writable_callback", true);
    if ((events & SW_EVENT_WRITE) && writable_callback == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "%s: unable to find writable callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        if (readable_callback) {
            delete readable_callback;
        }
        RETURN_FALSE;
    }

    EventObject *peo = (EventObject *) ecalloc(1, sizeof(*peo));

    Z_TRY_ADDREF_P(zfd);
    peo->zsocket = *zfd;
    peo->readable_callback = readable_callback;
    peo->writable_callback = writable_callback;

    socket->set_nonblock();
    socket->object = peo;

    if (swoole_event_add(socket, events) < 0) {
        php_swoole_fatal_error(E_WARNING, "swoole_event_add failed");
        socket->free();
        event_object_free(peo);
        RETURN_FALSE;
    }

    event_socket_map[socket_fd] = socket;

    RETURN_LONG(socket_fd);
}

static PHP_FUNCTION(swoole_event_write) {
    zval *zfd;
    char *data;
    size_t len;

    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_STRING(data, len)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (len == 0) {
        php_swoole_fatal_error(E_WARNING, "data empty");
        RETURN_FALSE;
    }

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        php_swoole_fatal_error(E_WARNING, "unknown type");
        RETURN_FALSE;
    }

    Socket *socket = event_get_socket(socket_fd);
    if (socket == nullptr) {
        php_swoole_fatal_error(E_WARNING, "socket[%d] is not found in the reactor", socket_fd);
        RETURN_FALSE;
    }

    event_check_reactor();
    if (swoole_event_write(socket, data, len) < 0) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_FUNCTION(swoole_event_set) {
    if (!sw_reactor()) {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_set");
        RETURN_FALSE;
    }

    zval *zfd;
    zend_long events = 0;
    zval *zreadable_callback = nullptr;
    zval *zwritable_callback = nullptr;

    ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(zreadable_callback)
    Z_PARAM_ZVAL(zwritable_callback)
    Z_PARAM_LONG(events)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        RETURN_FALSE;
    }

    Socket *socket = event_get_socket(socket_fd);
    if (socket == nullptr) {
        php_swoole_fatal_error(E_WARNING, "socket[%d] is not found in the reactor", socket_fd);
        RETURN_FALSE;
    }

    EventObject *peo = (EventObject *) socket->object;
    auto readable_callback = sw_callable_create_ex(zreadable_callback, "readable_callback");
    auto writable_callback = sw_callable_create_ex(zwritable_callback, "writable_callback");
    if (readable_callback) {
        if (peo->readable_callback) {
            swoole_event_defer(sw_callable_free, peo->readable_callback);
        }
        peo->readable_callback = readable_callback;
    }
    if (writable_callback) {
        if (peo->writable_callback) {
            swoole_event_defer(sw_callable_free, peo->writable_callback);
        }
        peo->writable_callback = writable_callback;
    }
    if ((events & SW_EVENT_READ) && peo->readable_callback == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "%s: unable to find readable callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }
    if ((events & SW_EVENT_WRITE) && peo->writable_callback == nullptr) {
        php_swoole_fatal_error(
            E_WARNING, "%s: unable to find writable callback of fd [%d]", ZSTR_VAL(swoole_event_ce->name), socket_fd);
        RETURN_FALSE;
    }
    if (swoole_event_set(socket, events) < 0) {
        php_swoole_fatal_error(E_WARNING, "%s::set failed", ZSTR_VAL(swoole_event_ce->name));
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_del) {
    zval *zfd;

    if (!sw_reactor()) {
        php_swoole_fatal_error(E_WARNING, "reactor is not ready, cannot call swoole_event_del");
        RETURN_FALSE;
    }

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zfd)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        php_swoole_fatal_error(E_WARNING, "unknown type");
        RETURN_FALSE;
    }

    Socket *socket = event_get_socket(socket_fd);
    if (!socket) {
        RETURN_FALSE;
    }
    swoole_event_defer(event_object_free, socket->object);
    int retval = swoole_event_del(socket);
    event_socket_map.erase(socket_fd);
    socket->fd = -1;
    socket->free();
    RETURN_BOOL(retval == SW_OK);
}

static PHP_FUNCTION(swoole_event_defer) {
    zval *zfn;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ZVAL(zfn)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    php_swoole_check_reactor();
    auto fn = sw_callable_create(zfn);
    swoole_event_defer(event_defer_callback, fn);

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_cycle) {
    zval *zcallback;
    zend_bool before = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(zcallback)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(before)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    event_check_reactor();

    if (ZVAL_IS_NULL(zcallback)) {
        if (sw_reactor()->idle_task.callback == nullptr) {
            RETURN_FALSE;
        } else {
            swoole_event_defer(sw_callable_free, sw_reactor()->idle_task.data);
            sw_reactor()->idle_task.callback = nullptr;
            sw_reactor()->idle_task.data = nullptr;
            RETURN_TRUE;
        }
    }

    auto callback = sw_callable_create(zcallback);
    if (!before) {
        if (sw_reactor()->idle_task.data != nullptr) {
            swoole_event_defer(sw_callable_free, sw_reactor()->idle_task.data);
        }

        sw_reactor()->idle_task.callback = event_end_callback;
        sw_reactor()->idle_task.data = callback;
    } else {
        if (sw_reactor()->future_task.data != nullptr) {
            swoole_event_defer(sw_callable_free, sw_reactor()->future_task.data);
        }

        sw_reactor()->future_task.callback = event_end_callback;
        sw_reactor()->future_task.data = callback;
        // Registration onBegin callback function
        sw_reactor()->activate_future_task();
    }

    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_exit) {
    php_swoole_event_exit();
}

static PHP_FUNCTION(swoole_event_wait) {
    if (!sw_reactor()) {
        return;
    }
    php_swoole_event_wait();
}

static PHP_FUNCTION(swoole_event_rshutdown) {
    /* prevent the program from jumping out of the rshutdown */
    zend_try {
        // when throw Exception, do not show the info
        if (!php_swoole_is_fatal_error() && sw_reactor()) {
            if (!sw_reactor()->bailout) {
                php_swoole_fatal_error(E_DEPRECATED, "Event::wait() in shutdown function is deprecated");
            }
            php_swoole_event_wait();
        }
    }
    zend_end_try();
}

static PHP_FUNCTION(swoole_event_dispatch) {
    if (!sw_reactor()) {
        RETURN_FALSE;
    }
    sw_reactor()->once = true;
    if (sw_reactor()->wait(nullptr) < 0) {
        php_swoole_sys_error(E_ERROR, "reactor wait failed");
    }
    sw_reactor()->once = false;
    RETURN_TRUE;
}

static PHP_FUNCTION(swoole_event_isset) {
    if (!sw_reactor()) {
        RETURN_FALSE;
    }

    zval *zfd;
    zend_long events = SW_EVENT_READ | SW_EVENT_WRITE;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|l", &zfd, &events) == FAILURE) {
        RETURN_FALSE;
    }

    int socket_fd = php_swoole_convert_to_fd(zfd);
    if (socket_fd < 0) {
        php_swoole_fatal_error(E_WARNING, "unknown type");
        RETURN_FALSE;
    }

    Socket *_socket = event_get_socket(socket_fd);
    if (_socket == nullptr || _socket->removed) {
        RETURN_FALSE;
    }
    if (_socket->events & events) {
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
}
